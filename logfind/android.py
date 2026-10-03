"""Android / 面具（Magisk）模块的开机日志：

* 生成 post-fs-data 阶段启动的常驻 logcat 脚本（早于 zygote/system_server，能完整记录
  含框架侧装钩在内的开机窗口；logcat 自带 -r/-n 轮转，防止写爆 /data）；
* 把脚本写入/合并进模块的 post-fs-data.sh（用标记包裹，重复执行原地更新）；
* 通过 adb 查看状态、把设备上的日志（含轮转出的 boot.log.1 ...）拉回本地检索。
"""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Tuple

from .parsing import parse_size
from .textio import atomic_write

MARK_BEGIN = "# >>> logfind bootlog >>>"
MARK_END = "# <<< logfind bootlog <<<"

_SAFE_PATH = re.compile(r"^/[A-Za-z0-9._/-]+$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
_SAFE_WORD = re.compile(r"^[a-z]+$")
_EXIT_LINE = re.compile(r"^\s*exit(\s+\d+)?\s*$")


@dataclass
class BootLogSpec:
    """常驻 logcat 的参数，默认值与 ven11 的 post-fs-data.sh 一致。"""
    log_dir: str = "/data/local/tmp/ven11/log"
    name: str = "boot.log"
    rotate_kb: int = 16384          # logcat -r，单位 KB
    count: int = 3                  # logcat -n，保留的轮转文件数
    fmt: str = "time"               # logcat -v
    buffers: List[str] = field(default_factory=list)  # 空 = logcat 默认（main/system/crash）

    def validate(self) -> "BootLogSpec":
        self.log_dir = self.log_dir.rstrip("/") or "/"
        if not _SAFE_PATH.match(self.log_dir):
            raise ValueError("设备目录必须是绝对路径，且只含字母数字和 ._-/: %r" % self.log_dir)
        if not _SAFE_NAME.match(self.name):
            raise ValueError("日志文件名只能含字母数字和 ._-: %r" % self.name)
        if not _SAFE_WORD.match(self.fmt):
            raise ValueError("logcat 格式不合法: %r（常用 time / threadtime）" % self.fmt)
        for b in self.buffers:
            if not _SAFE_WORD.match(b):
                raise ValueError("logcat 缓冲区名不合法: %r（main/system/crash/events/kernel/all）" % b)
        if self.rotate_kb <= 0 or self.count <= 0:
            raise ValueError("轮转大小和个数必须大于 0")
        return self

    @property
    def remote_path(self) -> str:
        return "%s/%s" % (self.log_dir, self.name)


def size_to_kb(spec) -> int:
    """'16M' / '16MB' / '512K' -> KB；纯数字按 KB 处理（与 logcat -r 一致）。"""
    if isinstance(spec, int) or str(spec).strip().isdigit():
        return int(spec)
    return max(1, parse_size(spec) // 1024)


def _human_kb(kb: int) -> str:
    return "%gM" % (kb / 1024) if kb % 1024 == 0 else "%dK" % kb


def render_block(spec: BootLogSpec) -> str:
    spec.validate()
    extra = "".join(" -b %s" % b for b in spec.buffers)
    lines = [
        MARK_BEGIN,
        "# 由 logfind android script 生成，重复执行会原地更新这一段。",
        "# 常驻 logcat，post-fs-data 阶段启动（早于 zygote/system_server），",
        "# 完整记录含框架侧装钩在内的开机窗口；%s×%d 轮转防写爆 /data。" % (_human_kb(spec.rotate_kb), spec.count),
        "BOOTLOG_DIR=%s" % spec.log_dir,
        'mkdir -p "$BOOTLOG_DIR"',
        'chmod 777 "$BOOTLOG_DIR"',
        'if ! pgrep -f "$BOOTLOG_DIR/%s" >/dev/null 2>&1; then' % spec.name,
        '  /system/bin/logcat -v %s%s -f "$BOOTLOG_DIR/%s" -r %d -n %d >/dev/null 2>&1 &' % (
            spec.fmt, extra, spec.name, spec.rotate_kb, spec.count),
        "fi",
        MARK_END,
    ]
    return "\n".join(lines) + "\n"


def render_script(spec: BootLogSpec) -> str:
    return "#!/system/bin/sh\n" + render_block(spec) + "exit 0\n"


def merge_into_script(existing: str, spec: BootLogSpec) -> Tuple[str, str]:
    """把开机日志段合并进已有脚本，返回 (新内容, 动作说明)。

    已有标记段 -> 原地替换；否则插到末尾的 exit 之前（放在 exit 之后永远不会执行）。
    """
    block = render_block(spec)
    text = existing.lstrip("﻿").replace("\r\n", "\n").replace("\r", "\n")
    begin, end = text.find(MARK_BEGIN), text.find(MARK_END)
    if begin != -1 and end > begin:
        end += len(MARK_END)
        if text[end:end + 1] == "\n":
            end += 1
        return text[:begin] + block + text[end:], "updated"
    if not text.strip():
        return render_script(spec), "created"
    lines = text.rstrip("\n").split("\n")
    idx = len(lines)
    for i in range(len(lines) - 1, -1, -1):
        s = lines[i].strip()
        if not s or s.startswith("#"):
            continue
        if _EXIT_LINE.match(lines[i]):
            idx = i
        break
    head = "\n".join(lines[:idx])
    tail = "\n".join(lines[idx:])
    out = (head + "\n\n" if head else "") + block + ("\n" + tail if tail else "")
    return out.rstrip("\n") + "\n", "inserted"


def install_script(target: str, spec: BootLogSpec) -> Tuple[str, str]:
    """写入脚本。target 是目录（如模块根目录）时写入其中的 post-fs-data.sh。

    返回 (路径, 动作)。改动已有文件前会保留一份 .bak；统一写 LF 换行、无 BOM
    （CRLF 的脚本在设备上会因为 'exit 0\\r' 之类的问题静默失败）。
    """
    path = os.path.join(target, "post-fs-data.sh") if os.path.isdir(target) else target
    if os.path.exists(path):
        with open(path, "rb") as fh:
            raw = fh.read()
        old = raw.decode("utf-8", errors="surrogateescape")
        new, action = merge_into_script(old, spec)
        if new == old:
            return path, "unchanged"
        shutil.copy2(path, path + ".bak")
    else:
        new, action = render_script(spec), "created"
    atomic_write(path, new.encode("utf-8", errors="surrogateescape"))
    if os.name != "nt":
        os.chmod(path, 0o755)
    return path, action


# ---------- adb ----------
class Adb:
    def __init__(self, serial: Optional[str] = None, adb: str = "adb", timeout: float = 120):
        exe = shutil.which(adb) if not os.path.isabs(adb) else adb
        if not exe or not os.path.exists(exe):
            raise RuntimeError("找不到 adb（%s）；请安装 platform-tools 并加入 PATH，或用 --adb 指定路径" % adb)
        self.exe = exe
        self.serial = serial
        self.timeout = timeout

    def _cmd(self, *args: str) -> List[str]:
        return [self.exe] + (["-s", self.serial] if self.serial else []) + list(args)

    def run(self, *args: str) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(self._cmd(*args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=self.timeout)
        except subprocess.TimeoutExpired:
            raise RuntimeError("adb %s 超时（%ss）" % (" ".join(args[:2]), self.timeout))

    def shell(self, script: str, su: bool = False) -> Tuple[int, str]:
        """在设备上执行 sh 脚本。su=True 时以 root 执行（Magisk: su -c）。"""
        if su:
            script = "su -c %s" % shlex.quote(script)
        p = self.run("shell", script)
        return p.returncode, p.stdout.decode("utf-8", errors="replace").replace("\r\n", "\n")

    def read_file(self, remote: str) -> bytes:
        """以 root 读取设备文件（logcat 以 root 创建的文件，shell 用户通常没有读权限）。"""
        p = self.run("exec-out", "su -c %s" % shlex.quote("cat %s" % shlex.quote(remote)))
        if p.returncode != 0:
            raise RuntimeError("读取 %s 失败: %s" % (
                remote, p.stderr.decode("utf-8", errors="replace").strip() or "rc=%d" % p.returncode))
        return p.stdout

    def check_device(self) -> None:
        p = self.run("get-state")
        state = p.stdout.decode(errors="replace").strip()
        if p.returncode != 0 or state != "device":
            msg = p.stderr.decode("utf-8", errors="replace").strip() or state or "未知"
            raise RuntimeError("adb 设备不可用: %s（多台设备时用 -s 指定序列号）" % msg)


@dataclass
class RemoteFile:
    name: str
    size: int
    mtime: int


_STAT_LINE = re.compile(r"^(\d+) (\d+) (.+)$")


def list_remote(adb: Adb, spec: BootLogSpec) -> List[RemoteFile]:
    """列出 boot.log 及其轮转文件 boot.log.1 ...（新的在前）。"""
    spec.validate()
    script = "cd %s 2>/dev/null && stat -c '%%Y %%s %%n' %s %s.* 2>/dev/null" % (
        spec.log_dir, spec.name, spec.name)
    files: List[RemoteFile] = []
    for su in (False, True):  # 目录是 777，一般不需要 root；失败再用 su 试一次
        _, out = adb.shell(script, su=su)
        for line in out.splitlines():
            m = _STAT_LINE.match(line.strip())
            if m and (m.group(3) == spec.name or re.match(re.escape(spec.name) + r"\.\d+$", m.group(3))):
                files.append(RemoteFile(m.group(3), int(m.group(2)), int(m.group(1))))
        if files:
            break

    def order(f: RemoteFile) -> int:
        suffix = f.name[len(spec.name) + 1:]
        return int(suffix) if suffix.isdigit() else 0
    return sorted(files, key=order)


def logcat_pids(adb: Adb, spec: BootLogSpec) -> List[int]:
    # Android 7+ 的 /proc 带 hidepid，shell 可能看不到 root 进程，先用 su。
    # 写成 .../[b]oot.log：仍匹配 logcat 的命令行，但不会匹配 adb 在设备上
    # 包出来的 sh -c / su -c 进程（它们的命令行里是字面的 "[b]oot.log"）。
    pat = shlex.quote("%s/[%s]%s" % (spec.log_dir, spec.name[0], spec.name[1:]))
    for su in (True, False):
        rc, out = adb.shell("pgrep -f %s" % pat, su=su)
        pids = [int(x) for x in out.split() if x.isdigit()]
        if pids:
            return pids
    return []


def pull_dir(home: str) -> str:
    return os.path.join(home, "android")


def list_pulls(home: str) -> List[str]:
    d = pull_dir(home)
    try:
        names = sorted(n for n in os.listdir(d) if os.path.isdir(os.path.join(d, n)))
    except OSError:
        return []
    return [os.path.join(d, n) for n in names]


def resolve_pull(home: str, ref: str = "latest") -> str:
    pulls = list_pulls(home)
    if not pulls:
        raise LookupError("%s 下还没有拉取过的设备日志（先运行 logfind android pull）" % pull_dir(home))
    if ref in ("latest", "last", ""):
        return pulls[-1]
    if ref == "prev":
        ref = "-2"
    if re.match(r"^-\d+$", ref):
        idx = int(ref)
        if -len(pulls) <= idx:
            return pulls[idx]
        raise LookupError("只拉取过 %d 次" % len(pulls))
    ids = [os.path.basename(p) for p in pulls]
    matches = [p for p, i in zip(pulls, ids) if i.startswith(ref)] or [p for p, i in zip(pulls, ids) if ref in i]
    if not matches:
        raise LookupError("找不到拉取记录: %s" % ref)
    return matches[-1]


def pull_files(pull_path: str) -> List[str]:
    """拉取目录中的日志文件，按时间先后（最旧的轮转文件在前）。"""
    try:
        with open(os.path.join(pull_path, "meta.json"), encoding="utf-8") as fh:
            meta = json.load(fh)
        names = [f["name"] for f in reversed(meta.get("files", []))]
    except (OSError, ValueError):
        names = sorted((n for n in os.listdir(pull_path) if n != "meta.json"),
                       key=lambda n: os.path.getmtime(os.path.join(pull_path, n)))
    return [os.path.join(pull_path, n) for n in names if os.path.isfile(os.path.join(pull_path, n))]


def pull(adb: Adb, spec: BootLogSpec, home: str, out_dir: Optional[str] = None,
         log=None) -> Tuple[str, List[dict]]:
    """把设备日志拉到本地（默认 <home>/android/<时间>_<设备>/），并恢复设备上的 mtime。

    先尝试 adb pull；logcat 以 root 创建的文件 shell 通常读不了，失败时改用 su 读取。
    """
    adb.check_device()
    remote = list_remote(adb, spec)
    if not remote:
        raise LookupError("设备上没有 %s*（脚本是否已生效？可用 logfind android status 检查）" % spec.remote_path)
    if out_dir is None:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        tag = re.sub(r"[^\w.-]+", "_", adb.serial or "")
        out_dir = os.path.join(pull_dir(home), stamp + ("_" + tag if tag else ""))
    os.makedirs(out_dir, exist_ok=True)
    results = []
    for f in remote:
        rpath = "%s/%s" % (spec.log_dir, f.name)
        local = os.path.join(out_dir, f.name)
        method = "pull"
        p = adb.run("pull", rpath, local)
        if p.returncode != 0 or not os.path.exists(local) or (os.path.getsize(local) == 0 and f.size > 0):
            method = "su"
            atomic_write(local, adb.read_file(rpath))
        os.utime(local, (f.mtime, f.mtime))
        info = {"name": f.name, "remote": rpath, "size": os.path.getsize(local),
                "remote_size": f.size, "mtime": f.mtime, "method": method}
        results.append(info)
        if log:
            log(info)
    meta = {"serial": adb.serial, "remote_dir": spec.log_dir, "name": spec.name,
            "pulled_at": datetime.now().isoformat(timespec="seconds"), "files": results}
    atomic_write(os.path.join(out_dir, "meta.json"),
                 json.dumps(meta, ensure_ascii=False, indent=2).encode("utf-8"))
    return out_dir, results

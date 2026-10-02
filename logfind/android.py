"""Android 设备日志：开机即落盘、跨重启续抓、绕过 SELinux 上下文问题拉文件。

对应几个常见的抓取失败：

- 开机洪峰冲掉环形缓冲 / ``logcat -G`` 重启失效：``bootlog`` 在 post-fs-data 阶段
  （zygote、system_server 启动之前）每次开机重新执行 ``logcat -G``，并启动一个常驻 logcat
  把日志持续写到文件，开机头几十秒的内容在被冲掉之前就已经落盘。
- 重启时 adbd 掉线、主机侧 ``adb logcat`` 退出（exit 255）：``LogcatStreamer`` 断开后
  等待设备重新上线，按 boot_id 判断是否重启——重启了就从新缓冲开头抓，没重启就从断点续接。
- SELinux 拒绝 / ``cp`` 保留 root 上下文导致 pull 被拒：``pull_paths`` 用
  ``adb exec-out su -c 'tar -cf - ...'`` 直接把内容流回主机，设备上不落中间文件。
- 设备时钟跳变：定期写入 ``logfind_clock`` 时钟锚点，检索时用 ``--fix-clock`` / ``--uptime``
  按“开机后秒数”过滤（见 timeline.py）。
"""
from __future__ import annotations

import os
import posixpath
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from .archive import Session, TriggerRecorder, stderr_hit_printer
from .timeline import ANCHOR_TAG, BOOT_MARK


class AdbError(RuntimeError):
    pass


def q(s: str) -> str:
    """设备 shell（mksh / toybox sh）用的 POSIX 引号。"""
    return shlex.quote(s)


_TEXT_FIXUP = re.compile(r"\r+\n")


def _text(data: bytes) -> str:
    return _TEXT_FIXUP.sub("\n", data.decode("utf-8", errors="replace"))


class Adb:
    """对 adb 命令的薄封装。serial 为空时使用 $ANDROID_SERIAL 或唯一连接的设备。"""

    def __init__(self, serial: Optional[str] = None, adb: Optional[str] = None,
                 su_cmd: Optional[str] = "su -c"):
        exe = adb or os.environ.get("ADB") or shutil.which("adb")
        if not exe:
            raise AdbError("找不到 adb：请安装 Android platform-tools 并加入 PATH，或用 --adb / 环境变量 ADB 指定")
        self.exe = exe
        self.serial = serial or os.environ.get("ANDROID_SERIAL") or None
        self.su_cmd = su_cmd or None

    def base(self) -> List[str]:
        return [self.exe] + (["-s", self.serial] if self.serial else [])

    def wrap(self, cmd: str, su: bool) -> str:
        if su and self.su_cmd:
            return "%s %s" % (self.su_cmd, q(cmd))
        return cmd

    def run(self, args: Sequence[str], timeout: Optional[float] = 60) -> Tuple[int, str, str]:
        try:
            p = subprocess.run(self.base() + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               stdin=subprocess.DEVNULL, timeout=timeout)
        except subprocess.TimeoutExpired:
            return 124, "", "adb %s 超时" % " ".join(args[:1])
        except OSError as e:
            raise AdbError("无法运行 adb (%s): %s" % (self.exe, e))
        return p.returncode, _text(p.stdout), _text(p.stderr)

    def shell(self, cmd: str, su: bool = False, timeout: Optional[float] = 60) -> Tuple[int, str, str]:
        return self.run(["shell", self.wrap(cmd, su)], timeout)

    def popen_exec_out(self, cmd: str, su: bool = False) -> subprocess.Popen:
        """exec-out 不分配 pty、不做换行转换，二进制安全。外层 stderr 丢弃，避免混进数据流。"""
        remote = self.wrap(cmd, su)
        if su and self.su_cmd:
            remote += " 2>/dev/null"
        try:
            return subprocess.Popen(self.base() + ["exec-out", remote], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, bufsize=0)
        except OSError as e:
            raise AdbError("无法运行 adb (%s): %s" % (self.exe, e))

    def push(self, local: str, remote: str) -> None:
        code, out, err = self.run(["push", local, remote], timeout=120)
        if code != 0:
            raise AdbError("adb push 失败: %s" % (err or out).strip())

    def wait_for_device(self) -> int:
        proc = subprocess.Popen(self.base() + ["wait-for-device"], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            proc.wait()
        except BaseException:
            proc.kill()
            raise
        return proc.returncode

    def boot_id(self) -> Optional[str]:
        code, out, _ = self.shell("cat /proc/sys/kernel/random/boot_id", timeout=15)
        bid = out.strip().lower()
        return bid if code == 0 and re.match(r"^[0-9a-f-]{8,}$", bid) else None

    def serialno(self) -> str:
        if self.serial:
            return self.serial
        code, out, _ = self.run(["get-serialno"], timeout=15)
        s = out.strip()
        return s if code == 0 and s and s != "unknown" else "device"

    def require_root(self) -> None:
        if not self.su_cmd:
            return
        code, out, err = self.shell("id -u", su=True, timeout=30)
        if code != 0 or out.strip().splitlines()[-1:] != ["0"]:
            raise AdbError("无法通过 `%s` 获得 root（输出: %s）。设备需要已 root（Magisk / KernelSU / APatch），"
                           "并在管理器里允许 Shell 的超级用户请求；su 用法不同时用 --su-cmd 指定"
                           % (self.su_cmd, (out + err).strip()[:200] or "空"))


# ---------------------------------------------------------------------------
# bootlog：开机即落盘
# ---------------------------------------------------------------------------
SCRIPT_NAME = "logfind_bootlog.sh"
DEFAULT_SCRIPT_DIR = "/data/adb/post-fs-data.d"   # Magisk / KernelSU / APatch 通用
DEFAULT_BOOTLOG_DIR = "/data/local/tmp/logfind"


@dataclass
class BootlogOptions:
    directory: str = DEFAULT_BOOTLOG_DIR
    buffer_size: str = "16M"   # 每次开机执行 logcat -G；"0" 表示不改
    buffers: str = "all"
    keep: int = 5              # 设备上保留最近几次开机
    rotate_kb: int = 8192      # logcat -r：单个文件 KB
    rotate_count: int = 8      # logcat -n：每次开机最多几个文件
    anchor: int = 10           # 时钟锚点间隔（秒）；开机头 2 分钟每 2 秒一次
    extra: str = ""            # 额外的 logcat 参数，例如 "*:V"


_SIZE_RE = re.compile(r"^\d+[KkMm]?$")


def check_buffer_size(size: str) -> str:
    if size != "0" and not _SIZE_RE.match(size):
        raise ValueError("缓冲大小格式应为 16M / 4096K / 0（不修改）: %r" % size)
    return size.upper()


_SCRIPT = r'''#!/system/bin/sh
# logfind bootlog —— 由 `logfind adb bootlog install` 生成；删除: `logfind adb bootlog uninstall`
#
# 在 post-fs-data 阶段（zygote / system_server 启动之前）运行：
#   1. 每次开机重新执行 logcat -G，缓冲扩容不会因为重启失效
#   2. 启动常驻 logcat，从 logd 缓冲开头读并持续写文件，开机洪峰冲不掉已落盘的内容
#   3. 每次开机一个目录 boot-NNNN（含 boot_id、开机原因、上次开机的 pstore），只保留最近 KEEP 个
#   4. 定期写入 logfind_clock 时钟锚点（uptime ↔ 墙钟），RTC 跳变后仍能按开机后秒数切窗口
DIR=__DIR__
SIZE=__SIZE__
BUFFERS=__BUFFERS__
KEEP=__KEEP__
ROTATE_KB=__ROTATE_KB__
ROTATE_N=__ROTATE_N__
ANCHOR=__ANCHOR__
EXTRA=__EXTRA__
LOGD_SOCKET=${LOGFIND_LOGD_SOCKET:-/dev/socket/logdr}

up() { cut -d' ' -f1 /proc/uptime; }

main() {
  i=0
  while [ ! -d "${DIR%/*}" ] && [ $i -lt 600 ]; do sleep 0.1; i=$((i + 1)); done
  i=0
  while [ ! -S "$LOGD_SOCKET" ] && [ $i -lt 600 ]; do sleep 0.1; i=$((i + 1)); done
  mkdir -p "$DIR" || exit 1
  BID=$(cat /proc/sys/kernel/random/boot_id)
  if [ -f "$DIR/current" ]; then
    read cur_bid cur_lpid cur_apid cur_seq < "$DIR/current"
    if [ "$cur_bid" = "$BID" ] && kill -0 "$cur_lpid" 2>/dev/null; then
      exit 0  # 本次开机已经在抓
    fi
  fi
  if [ "$SIZE" != "0" ]; then
    logcat -b "$BUFFERS" -G "$SIZE" >/dev/null 2>&1 || logcat -G "$SIZE" >/dev/null 2>&1
  fi
  SEQ=$(cat "$DIR/seq" 2>/dev/null)
  case "$SEQ" in ''|*[!0-9]*) SEQ=0 ;; esac
  SEQ=$((SEQ + 1))
  echo "$SEQ" > "$DIR/seq"
  B="$DIR/boot-$(printf %04d "$SEQ")"
  mkdir -p "$B"
  {
    echo "seq=$SEQ"
    echo "boot_id=$BID"
    echo "uptime=$(up)"
    echo "date=$(date '+%Y-%m-%d %H:%M:%S %z')"
    echo "bootreason=$(getprop ro.boot.bootreason)"
    echo "fingerprint=$(getprop ro.build.fingerprint)"
    echo "buffer_size=$SIZE"
    echo "persist_logd_size=$(getprop persist.logd.size)"
  } > "$B/boot.txt"
  if [ -d /sys/fs/pstore ] && [ -n "$(ls /sys/fs/pstore 2>/dev/null)" ]; then
    mkdir -p "$B/pstore" && cp /sys/fs/pstore/* "$B/pstore/" 2>/dev/null
  fi
  dmesg > "$B/dmesg-early.txt" 2>/dev/null
  n=$(ls -d "$DIR"/boot-* 2>/dev/null | wc -l)
  if [ "$n" -gt "$KEEP" ]; then
    ls -d "$DIR"/boot-* | sort | head -n $((n - KEEP)) | while read d; do rm -rf "$d"; done
  fi
  FMT="-v threadtime -v year"
  logcat -v year -d -t 1 >/dev/null 2>&1 || FMT="-v threadtime"
  log -t __TAG__ "boot_id=$BID seq=$SEQ up=$(up)"
  set -f  # $EXTRA 里的 *:V 之类不做通配展开
  logcat -b "$BUFFERS" $FMT $EXTRA -f "$B/logcat.txt" -r "$ROTATE_KB" -n "$ROTATE_N" &
  LPID=$!
  set +f
  (
    k=0
    while kill -0 $LPID 2>/dev/null; do
      if [ $k -lt 60 ]; then sleep 2; else sleep "$ANCHOR"; fi
      k=$((k + 1))
      log -t __TAG__ "boot_id=$BID up=$(up)"
    done
  ) &
  APID=$!
  echo "$BID $LPID $APID $SEQ" > "$DIR/current"
}

( main ) </dev/null >/dev/null 2>&1 &
'''


def bootlog_script(opts: BootlogOptions) -> str:
    values = {
        "__DIR__": q(opts.directory.rstrip("/")),
        "__SIZE__": q(check_buffer_size(opts.buffer_size)),
        "__BUFFERS__": q(opts.buffers),
        "__KEEP__": str(max(1, int(opts.keep))),
        "__ROTATE_KB__": str(max(64, int(opts.rotate_kb))),
        "__ROTATE_N__": str(max(1, int(opts.rotate_count))),
        "__ANCHOR__": str(max(1, int(opts.anchor))),
        "__EXTRA__": q(opts.extra),
        "__TAG__": ANCHOR_TAG,
    }
    s = _SCRIPT
    for k, v in values.items():
        s = s.replace(k, v)
    return s


def install_bootlog(adb: Adb, opts: BootlogOptions, script_dir: str = DEFAULT_SCRIPT_DIR,
                    persist_size: bool = True, start_now: bool = True,
                    log: Callable[[str], None] = print) -> str:
    adb.require_root()
    script = bootlog_script(opts)
    dest = "%s/%s" % (script_dir.rstrip("/"), SCRIPT_NAME)
    staging = "/data/local/tmp/.%s" % SCRIPT_NAME
    fd, local = tempfile.mkstemp(suffix=".sh")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(script)
        adb.push(local, staging)
    finally:
        os.unlink(local)
    # 用 cat 重定向生成新文件（继承目标目录的 SELinux 上下文），而不是 cp
    code, out, err = adb.shell("mkdir -p %s && cat %s > %s && chmod 0755 %s; r=$?; rm -f %s; exit $r"
                               % (q(script_dir), q(staging), q(dest), q(dest), q(staging)), su=True)
    if code != 0:
        raise AdbError("写入 %s 失败: %s\n  可用 --script-dir 换一个开机脚本目录（如 /data/adb/service.d）"
                       % (dest, (err or out).strip()))
    log("已安装开机脚本: %s" % dest)
    if persist_size and opts.buffer_size != "0":
        size = check_buffer_size(opts.buffer_size)
        code, out, err = adb.shell("setprop persist.logd.size %s" % q(size), su=True)
        if code == 0:
            log("已设置 persist.logd.size=%s（logd 下次启动起即使用该大小，比脚本里的 -G 更早生效）" % size)
        else:
            log("设置 persist.logd.size 失败（不影响脚本里的 -G）: %s" % (err or out).strip())
    if start_now:
        code, out, err = adb.shell("sh %s" % q(dest), su=True)
        time.sleep(1.0)
        st = bootlog_status(adb, opts.directory)
        if st.get("running"):
            log("本次开机已开始抓取 -> %s" % st.get("current_dir", opts.directory))
        else:
            log("立即启动失败（重启后仍会生效）: %s" % (err or out).strip())
    return dest


def uninstall_bootlog(adb: Adb, directory: str = DEFAULT_BOOTLOG_DIR, script_dir: str = DEFAULT_SCRIPT_DIR,
                      purge: bool = False, reset_size: bool = False,
                      log: Callable[[str], None] = print) -> None:
    adb.require_root()
    d = q(directory.rstrip("/"))
    cmd = ("rm -f %s; if [ -f %s/current ]; then read b l a s < %s/current; kill $l $a 2>/dev/null; "
           "rm -f %s/current; fi" % (q("%s/%s" % (script_dir.rstrip("/"), SCRIPT_NAME)), d, d, d))
    if purge:
        cmd += "; rm -rf %s" % d
    if reset_size:
        cmd += "; setprop persist.logd.size ''"
    code, out, err = adb.shell(cmd, su=True)
    if code != 0:
        raise AdbError("卸载失败: %s" % (err or out).strip())
    log("已删除开机脚本并停止抓取%s%s" % ("，已删除 %s" % directory if purge else "",
                                 "，已清除 persist.logd.size" if reset_size else ""))


def _parse_kv(text: str) -> Dict[str, str]:
    out = {}
    for line in text.splitlines():
        k, sep, v = line.partition("=")
        if sep:
            out[k.strip()] = v.strip()
    return out


def bootlog_status(adb: Adb, directory: str = DEFAULT_BOOTLOG_DIR,
                   script_dir: str = DEFAULT_SCRIPT_DIR) -> dict:
    d = q(directory.rstrip("/"))
    script = q("%s/%s" % (script_dir.rstrip("/"), SCRIPT_NAME))
    cmd = ("echo \"@script=$([ -f %s ] && echo yes || echo no)\"; "
           "echo \"@boot_id=$(cat /proc/sys/kernel/random/boot_id)\"; "
           "echo \"@persist=$(getprop persist.logd.size)\"; "
           "if [ -f %s/current ]; then read b l a s < %s/current; "
           "echo \"@current=$b $s\"; kill -0 $l 2>/dev/null && echo @running=yes; fi; "
           "for b in %s/boot-*; do [ -d \"$b\" ] || continue; "
           "echo \"@@ $b $(du -sk \"$b\" | cut -f1)\"; cat \"$b/boot.txt\" 2>/dev/null; done"
           % (script, d, d, d))
    code, out, err = adb.shell(cmd, su=True)
    if code != 0 and "@boot_id" not in out:
        raise AdbError("读取状态失败: %s" % (err or out).strip())
    st: dict = {"boots": [], "running": False}
    cur_boot: Optional[dict] = None
    for line in out.splitlines():
        if line.startswith("@@ "):
            parts = line[3:].split()
            cur_boot = {"path": parts[0], "name": os.path.basename(parts[0]),
                        "kb": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0}
            st["boots"].append(cur_boot)
        elif line.startswith("@"):
            k, _, v = line[1:].partition("=")
            if k == "running":
                st["running"] = True
            elif k == "current":
                bid, _, seq = v.partition(" ")
                st["current_boot_id"] = bid
                if seq.strip().isdigit():
                    st["current_dir"] = "%s/boot-%04d" % (directory.rstrip("/"), int(seq))
            else:
                st[k] = v.strip()
        elif cur_boot is not None:
            cur_boot.update(_parse_kv(line))
    code, out, _ = adb.shell("logcat -g", timeout=20)
    if code == 0:
        st["buffers"] = out.strip()
    return st


def select_boots(boots: List[dict], refs: Sequence[str]) -> List[dict]:
    """all / latest / prev / -N / 序号（3 或 0003）。"""
    if not refs or "all" in refs:
        return list(boots)
    out: List[dict] = []
    for ref in refs:
        if ref in ("latest", "last"):
            ref = "-1"
        elif ref == "prev":
            ref = "-2"
        if re.match(r"^-\d+$", ref):
            idx = int(ref)
            if -len(boots) <= idx:
                b = boots[idx]
            else:
                raise LookupError("设备上只有 %d 次开机记录" % len(boots))
        else:
            want = "boot-%04d" % int(ref) if ref.isdigit() else ref
            found = [b for b in boots if b["name"] == want]
            if not found:
                raise LookupError("找不到开机记录 %s（有: %s）" % (ref, ", ".join(b["name"] for b in boots)))
            b = found[0]
        if b not in out:
            out.append(b)
    return out


def host_boot_name(boot: dict) -> str:
    bid = (boot.get("boot_id") or "")[:8]
    return "%s_%s" % (boot["name"], bid) if bid else boot["name"]


# ---------------------------------------------------------------------------
# pull：绕过 SELinux 上下文问题拉文件
# ---------------------------------------------------------------------------
@dataclass
class PullResult:
    files: List[str]
    bytes: int
    errors: str


def _safe_member(name: str) -> Optional[str]:
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None
    return os.path.join(*parts)


def _extract_stream(stream, dest: str) -> Tuple[List[str], int]:
    """流式解包，只接受普通文件和目录（拒绝绝对路径、..、链接、设备文件）。"""
    files: List[str] = []
    total = 0
    try:
        tf = tarfile.open(fileobj=stream, mode="r|*")
    except (tarfile.ReadError, EOFError):
        return files, total
    try:
        for m in tf:
            rel = _safe_member(m.name)
            if rel is None:
                continue
            target = os.path.join(dest, rel)
            if m.isdir():
                os.makedirs(target, exist_ok=True)
            elif m.isfile():
                os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
                src = tf.extractfile(m)
                with open(target, "wb") as out:
                    if src is not None:
                        shutil.copyfileobj(src, out, 1 << 20)
                try:
                    os.utime(target, (m.mtime, m.mtime))
                except (OSError, OverflowError):
                    pass
                files.append(target)
                total += m.size
    except (tarfile.ReadError, EOFError) as e:
        raise AdbError("tar 数据流中断: %s（设备断开或 su 被拒？）" % e)
    finally:
        tf.close()
    return files, total


def selinux_diagnose(adb: Adb) -> List[str]:
    """拉取失败时给出 su 进程的 SELinux 上下文和最近的 avc 拒绝记录。"""
    lines = []
    _, ctx, _ = adb.shell("id -Z 2>/dev/null || cat /proc/self/attr/current", su=True, timeout=20)
    _, mode, _ = adb.shell("getenforce", timeout=20)
    lines.append("su 进程上下文: %s，SELinux: %s" % (ctx.strip() or "?", mode.strip() or "?"))
    _, avc, _ = adb.shell("(dmesg 2>/dev/null; logcat -b all -d 2>/dev/null) | grep 'avc: *denied' | tail -n 6",
                          su=True, timeout=30)
    for l in avc.strip().splitlines():
        lines.append("  " + l.strip()[:300])
    return lines


def pull_paths(adb: Adb, remote_paths: Sequence[str], dest: str, su: bool = True,
               setenforce0: bool = False) -> PullResult:
    """``adb exec-out su -c 'tar -cf - -C 父目录 名字'`` 流回主机后解包到 dest/<名字>。

    数据不经过设备上的临时文件，不存在 “cp 保留 root SELinux 上下文导致 adb pull 被拒” 的问题。
    """
    os.makedirs(dest, exist_ok=True)
    groups: Dict[str, List[str]] = {}
    for p in remote_paths:
        p = p.rstrip("/") or "/"
        parent, name = p.rsplit("/", 1) if "/" in p else (".", p)
        groups.setdefault(parent or "/", []).append(name)
    errfile = "/data/local/tmp/.logfind_pull_%d.err" % os.getpid()
    restore = None
    if setenforce0:
        _, mode, _ = adb.shell("getenforce")
        if mode.strip().lower() == "enforcing":
            code, out, err = adb.shell("setenforce 0", su=True)
            if code != 0:
                raise AdbError("setenforce 0 失败: %s" % (err or out).strip())
            restore = "setenforce 1"
    files: List[str] = []
    total = 0
    errors = []
    try:
        for parent, names in groups.items():
            cmd = "tar -cf - -C %s %s 2>%s" % (q(parent), " ".join(q(n) for n in names), errfile)
            proc = adb.popen_exec_out(cmd, su=su)
            try:
                got, size = _extract_stream(proc.stdout, dest)
            finally:
                proc.stdout.close()
                proc.wait()
                proc.stderr.close()
            _, err, _ = adb.shell("cat %s 2>/dev/null; rm -f %s" % (errfile, errfile), su=su)
            err = err.strip()
            if not got and re.search(r"not found|inaccessible|No such", err or "") and "tar" in err:
                got, size, err = _pull_by_cat(adb, parent, names, dest, su)
            files += got
            total += size
            if err:
                errors.append(err)
    finally:
        if restore:
            adb.shell(restore, su=True)
    return PullResult(files, total, "\n".join(errors))


def _pull_by_cat(adb: Adb, parent: str, names: Sequence[str], dest: str, su: bool) -> Tuple[List[str], int, str]:
    """设备上没有 tar 时逐个文件 cat。"""
    files, total, errs = [], 0, []
    for name in names:
        root = "%s/%s" % (parent.rstrip("/"), name)
        _, out, err = adb.shell("find %s -type f 2>/dev/null || ls %s" % (q(root), q(root)), su=su)
        for remote in [l.strip() for l in out.splitlines() if l.strip()]:
            rel = _safe_member(posixpath.relpath(remote, parent) if remote.startswith("/") else remote)
            if rel is None:
                continue
            proc = adb.popen_exec_out("cat %s" % q(remote), su=su)
            data, _ = proc.communicate()  # communicate 会关闭管道
            if proc.returncode not in (0, None):
                errs.append("%s: adb 退出码 %s" % (remote, proc.returncode))
                continue
            target = os.path.join(dest, rel)
            os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
            with open(target, "wb") as fh:
                fh.write(data)
            files.append(target)
            total += len(data)
    return files, total, "\n".join(errs)


# ---------------------------------------------------------------------------
# logcat 流式抓取：跨重启自动重连
# ---------------------------------------------------------------------------
_LOGCAT_TS = re.compile(r"^(?:\d{4}-)?\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+")


class LogcatStreamer:
    """``adb logcat`` 断开（设备重启、USB 抖动、adbd 重启）后自动等待并重连。

    - 每次连接前读取 boot_id：变了 = 设备重启过，从新缓冲开头抓（尽量多拿开机日志），
      并重新执行 ``logcat -G``（扩容不跨重启）；没变 = 同一次开机，用 ``-T`` 从断点续接并去重。
    - 每次连接写入 ``#logfind-boot boot_id=...`` 标记，周期写入时钟锚点，供 ``grep --fix-clock`` 使用。
    """

    def __init__(self, adb: Adb, session: Session, *, buffers: str = "all", buffer_size: Optional[str] = None,
                 logcat_args: Sequence[str] = (), reconnect: bool = True, max_connects: int = 0,
                 anchor_interval: float = 10.0, echo: bool = True, triggers: Sequence[str] = (),
                 trigger_before: int = 50, trigger_after: int = 30, size_with_su: bool = False,
                 out=None):
        self.adb = adb
        self.session = session
        self.archive = session.archive
        self.buffers = buffers
        self.buffer_size = check_buffer_size(buffer_size) if buffer_size else None
        self.logcat_args = list(logcat_args)
        self.reconnect = reconnect
        self.max_connects = max_connects
        self.anchor_interval = anchor_interval
        self.echo = echo
        self.size_with_su = size_with_su
        self.out = out or sys.stdout
        self.recorder = TriggerRecorder(triggers, session.hits_dir, trigger_before, trigger_after,
                                        on_hit=stderr_hit_printer() if echo else None)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._proc: Optional[subprocess.Popen] = None
        self.connects = 0
        self.boots = 0
        self.lines = 0

    def stop(self) -> None:
        self._stop.set()
        p = self._proc
        if p is not None and p.poll() is None:
            try:
                p.terminate()
            except OSError:
                pass

    def _note(self, text: str) -> None:
        with self._lock:
            self.archive.note(text)
        if self.echo:
            try:
                sys.stderr.write("[logfind] %s\n" % text)
                sys.stderr.flush()
            except Exception:
                pass

    def _emit(self, line: str) -> None:
        ts = time.time()
        with self._lock:
            self.archive.write("logcat", line, ts)
            self.recorder.feed("logcat", line, ts)
        self.lines += 1
        if self.echo and ANCHOR_TAG not in line:
            try:
                self.out.write(line + "\n")
                self.out.flush()
            except (OSError, ValueError):
                pass

    def _anchor_loop(self, bid: str, done: threading.Event) -> None:
        cmd = 'log -t %s "boot_id=%s up=$(cut -d\' \' -f1 /proc/uptime)"' % (ANCHOR_TAG, bid)
        while not done.is_set() and not self._stop.is_set():
            try:
                self.adb.shell(cmd, timeout=10)
            except AdbError:
                pass
            done.wait(self.anchor_interval)

    def _logcat_cmd(self, since: Optional[str], year: bool) -> str:
        parts = ["logcat", "-b", self.buffers, "-v", "threadtime"]
        if year:
            parts += ["-v", "year"]
        if since:
            parts += ["-T", since]
        parts += self.logcat_args
        return " ".join(q(p) for p in parts)

    def run(self) -> int:
        last_bid: Optional[str] = None
        last_ts: Optional[str] = None
        seen_at_last: set = set()
        year_ok: Optional[bool] = None
        failures = 0
        self.session.update_meta(status="running", serial=self.adb.serial, buffers=self.buffers)
        try:
            while not self._stop.is_set():
                if self.max_connects and self.connects >= self.max_connects:
                    break
                if self.connects:
                    self._note("等待设备重新上线（adb wait-for-device）...")
                if self.adb.wait_for_device() != 0:
                    failures += 1
                    if failures > 30:
                        self._note("adb wait-for-device 连续失败，放弃")
                        break
                    self._stop.wait(min(2.0 * failures, 10.0))
                    continue
                bid = None
                for _ in range(10):
                    bid = self.adb.boot_id()
                    if bid or self._stop.is_set():
                        break
                    self._stop.wait(1.0)
                self.connects += 1
                failures = 0
                since = None
                if bid is None or bid != last_bid:
                    self.boots += 1
                    if last_bid:
                        self._note("检测到设备重启（boot_id %s -> %s），从新缓冲开头抓取" % (last_bid[:8], (bid or "?")[:8]))
                    self._note("%s boot_id=%s connect=%d" % (BOOT_MARK, bid or "unknown", self.connects))
                    last_ts, seen_at_last, year_ok = None, set(), None
                    if self.buffer_size:
                        code, out, err = self.adb.shell("logcat -b %s -G %s" % (q(self.buffers), self.buffer_size),
                                                        su=self.size_with_su, timeout=20)
                        self._note("logcat -G %s：%s" % (self.buffer_size, "成功" if code == 0 else
                                                         "失败 %s" % (err or out).strip()[:200]))
                else:
                    since = last_ts
                    self._note("%s boot_id=%s connect=%d 同一次开机重连，从 %s 续接"
                               % (BOOT_MARK, bid, self.connects, since or "缓冲开头"))
                if year_ok is None:
                    code, out, _ = self.adb.shell("logcat -v year -d -t 1 >/dev/null 2>&1 && echo year-ok", timeout=20)
                    year_ok = "year-ok" in out
                done = threading.Event()
                if self.anchor_interval > 0 and bid:
                    threading.Thread(target=self._anchor_loop, args=(bid, done), daemon=True).start()
                self._proc = proc = self.adb.popen_exec_out(self._logcat_cmd(since, year_ok))
                try:
                    for raw in iter(proc.stdout.readline, b""):
                        line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                        m = _LOGCAT_TS.match(line)
                        if m:
                            t = m.group(0)
                            if since is not None:
                                if t == since and line in seen_at_last:
                                    continue
                                if t != since:
                                    since = None
                            if t != last_ts:
                                last_ts, seen_at_last = t, set()
                            seen_at_last.add(line)
                        self._emit(line)
                except BaseException:
                    if proc.poll() is None:
                        proc.terminate()
                    raise
                finally:
                    done.set()
                    code = proc.wait()
                    self._proc = None
                    err = proc.stderr.read().decode("utf-8", errors="replace").strip() if proc.stderr else ""
                    proc.stdout.close()
                    if proc.stderr:
                        proc.stderr.close()
                last_bid = bid or last_bid
                if self._stop.is_set():
                    break
                self._note("adb logcat 断开（退出码 %s%s）" % (code, "：" + err[:200] if err else ""))
                if not self.reconnect:
                    break
                self._stop.wait(1.0)
        except KeyboardInterrupt:
            self.stop()
        finally:
            self.recorder.flush()
            self._note("结束：共连接 %d 次、经历 %d 次开机、%d 行" % (self.connects, self.boots, self.lines))
            self.session.update_meta(status="ok", connects=self.connects, boots=self.boots,
                                     lines={"logcat": self.lines}, hits=len(self.recorder.files),
                                     hit_matches=self.recorder.hit_count)
            self.session.close()
        return 0


def install_signal_stop(streamer: LogcatStreamer) -> None:
    if hasattr(signal, "SIGTERM"):
        try:
            signal.signal(signal.SIGTERM, lambda *a: streamer.stop())
        except ValueError:  # 非主线程
            pass

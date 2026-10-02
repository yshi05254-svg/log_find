"""包装运行任意命令：stdout/stderr 实时显示的同时完整落盘，崩溃/信号退出也能留下现场。"""
from __future__ import annotations

import collections
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from typing import Deque, Dict, List, Optional, Sequence

from .archive import Session, TriggerRecorder, stderr_hit_printer
from .textio import LineSplitter, strip_ansi


def _signal_name(num: int) -> str:
    try:
        return signal.Signals(num).name
    except (ValueError, AttributeError):
        return "signal %d" % num


def _windows_status(code: int) -> Optional[str]:
    known = {0xC0000005: "ACCESS_VIOLATION", 0xC00000FD: "STACK_OVERFLOW",
             0xC0000409: "STACK_BUFFER_OVERRUN", 0xC0000374: "HEAP_CORRUPTION",
             0xC000001D: "ILLEGAL_INSTRUCTION", 0xC0000094: "INTEGER_DIVIDE_BY_ZERO",
             0x40010004: "DEBUGGER_TERMINATED / killed", 0xC000013A: "CONTROL_C_EXIT"}
    return known.get(code & 0xFFFFFFFF)


def describe_exit(code: Optional[int]) -> str:
    if code is None:
        return "未知"
    if code < 0:
        return "被信号终止: %s" % _signal_name(-code)
    if os.name == "nt":
        name = _windows_status(code)
        if name:
            return "退出码 0x%08X (%s)" % (code & 0xFFFFFFFF, name)
    if code > 128 and os.name != "nt":
        return "退出码 %d (可能是 %s)" % (code, _signal_name(code - 128))
    return "退出码 %d" % code


def build_env(unbuffer: bool = True, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    env = dict(os.environ)
    if unbuffer:
        # Python 子进程：关闭缓冲，并在段错误等致命错误时打印所有线程的调用栈
        env["PYTHONUNBUFFERED"] = "1"
        env.setdefault("PYTHONFAULTHANDLER", "1")
        # 只改错误处理方式，不改编码：管道下遇到无法编码的字符时不让子进程崩溃
        env.setdefault("PYTHONIOENCODING", ":backslashreplace")
    if extra:
        env.update(extra)
    return env


def maybe_stdbuf(cmd: Sequence[str]) -> List[str]:
    """Linux 上用 stdbuf 让 C/C++ 程序按行刷新，避免进程崩溃时缓冲区里的日志丢失。"""
    if os.name == "nt" or not cmd:
        return list(cmd)
    stdbuf = shutil.which("stdbuf")
    if stdbuf and shutil.which(cmd[0]):
        return [stdbuf, "-oL", "-eL"] + list(cmd)
    return list(cmd)


class _StreamPump(threading.Thread):
    def __init__(self, fd: int, name: str, sink, echo_to, encoding: str, keep_ansi: bool):
        super().__init__(daemon=True, name="logfind-%s" % name)
        self.fd = fd
        self.stream_name = name
        self.sink = sink
        self.echo_to = echo_to
        self.splitter = LineSplitter(encoding)
        self.keep_ansi = keep_ansi
        self.lines = 0
        self.tail: Deque[str] = collections.deque(maxlen=200)

    def _emit(self, line: str) -> None:
        if not self.keep_ansi:
            line = strip_ansi(line)
        self.lines += 1
        self.tail.append(line)
        self.sink(self.stream_name, line)

    def run(self) -> None:
        while True:
            try:
                data = os.read(self.fd, 65536)
            except OSError:  # pty 在子进程退出后返回 EIO
                data = b""
            if not data:
                break
            if self.echo_to is not None:
                try:
                    self.echo_to.write(data)
                    self.echo_to.flush()
                except (OSError, ValueError):
                    pass
            for line in self.splitter.feed(data):
                self._emit(line)
        rest = self.splitter.flush()
        if rest:
            self._emit(rest)


def run_command(cmd: Sequence[str], session: Session, *, echo: bool = True,
                triggers: Sequence[str] = (), trigger_before: int = 50, trigger_after: int = 30,
                unbuffer: bool = True, use_stdbuf: bool = True, use_pty: bool = False,
                encoding: str = "auto", keep_ansi: bool = False, cwd: Optional[str] = None,
                env: Optional[Dict[str, str]] = None, tail_on_fail: int = 30,
                merge_streams: bool = False) -> int:
    """运行命令并捕获全部输出，返回退出码。"""
    archive = session.archive
    recorder = TriggerRecorder(triggers, session.hits_dir, trigger_before, trigger_after,
                               on_hit=stderr_hit_printer() if echo else None)
    lock = threading.Lock()

    def sink(stream: str, line: str) -> None:
        ts = time.time()
        with lock:
            archive.write(stream, line, ts)
            recorder.feed(stream, line, ts)

    full_cmd = list(cmd)
    if unbuffer and use_stdbuf and not use_pty:
        full_cmd = maybe_stdbuf(full_cmd)
    environ = build_env(unbuffer, env)
    out_echo = getattr(sys.stdout, "buffer", None) if echo else None
    err_echo = getattr(sys.stderr, "buffer", None) if echo else None

    started = time.time()
    session.update_meta(command=list(cmd), cwd=os.path.abspath(cwd or os.getcwd()),
                        triggers=list(triggers), status="running")
    archive.note("启动: %s" % subprocess.list2cmdline(list(cmd)))

    master = slave = None
    if use_pty and os.name != "nt":
        import pty
        master, slave = pty.openpty()
        stdout_target = slave
    else:
        stdout_target = subprocess.PIPE
    stderr_target = subprocess.STDOUT if merge_streams else subprocess.PIPE

    try:
        proc = subprocess.Popen(full_cmd, stdout=stdout_target, stderr=stderr_target,
                                cwd=cwd, env=environ, bufsize=0)
    except OSError as e:
        archive.note("启动失败: %s" % e)
        session.update_meta(status="failed-to-start", error=str(e))
        session.close()
        raise
    finally:
        if slave is not None:
            os.close(slave)

    pumps = []
    out_fd = master if master is not None else proc.stdout.fileno()
    pumps.append(_StreamPump(out_fd, "stdout", sink, out_echo, encoding, keep_ansi))
    if proc.stderr is not None:
        pumps.append(_StreamPump(proc.stderr.fileno(), "stderr", sink, err_echo, encoding, keep_ansi))
    session.update_meta(child_pid=proc.pid)
    for p in pumps:
        p.start()

    interrupted = False
    try:
        while True:
            try:
                code = proc.wait()
                break
            except KeyboardInterrupt:
                # 子进程同样收到了 Ctrl+C；给它时间自己收尾并把日志写完
                interrupted = True
                archive.note("收到 Ctrl+C，等待子进程退出")
                try:
                    code = proc.wait(timeout=10)
                    break
                except (subprocess.TimeoutExpired, KeyboardInterrupt):
                    archive.note("子进程未退出，强制终止")
                    proc.kill()
    finally:
        for p in pumps:
            p.join(timeout=10)
        if master is not None:
            try:
                os.close(master)
            except OSError:
                pass
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

    recorder.flush()
    desc = describe_exit(code)
    duration = time.time() - started
    archive.note("结束: %s，耗时 %.1fs" % (desc, duration))
    stream_lines = {p.stream_name: p.lines for p in pumps}
    session.update_meta(status="interrupted" if interrupted else ("ok" if code == 0 else "failed"),
                        returncode=code, exit=desc, duration=round(duration, 3),
                        lines=stream_lines, hits=len(recorder.files), hit_matches=recorder.hit_count,
                        dropped_segments=archive.dropped_segments)
    session.close()

    if echo:
        _print_summary(session, code, desc, pumps, recorder, tail_on_fail)
    return code


def _print_summary(session, code, desc, pumps, recorder, tail_on_fail) -> None:
    w = sys.stderr.write
    w("\n[logfind] %s | 输出已保存: %s\n" % (desc, session.directory))
    if recorder.files:
        w("[logfind] 触发 %d 次，现场保存在 %d 个文件: %s\n"
          % (recorder.hit_count, len(recorder.files), session.hits_dir))
    if code != 0 and tail_on_fail > 0:
        err = next((p for p in pumps if p.stream_name == "stderr"), None)
        tail = list(err.tail)[-tail_on_fail:] if err and err.tail else []
        if not tail:
            tail = list(pumps[0].tail)[-tail_on_fail:]
        if tail:
            w("[logfind] ---- 最后 %d 行%s（防止被刷屏淹没）----\n"
              % (len(tail), " stderr" if err and err.tail else ""))
            for line in tail:
                w("  %s\n" % line)
            w("[logfind] ---- 结束 ----\n")
    try:
        sys.stderr.flush()
    except Exception:
        pass

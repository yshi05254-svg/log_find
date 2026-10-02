"""在 Python 进程内部抓取所有输出，专治“日志被吞”。

- fd 级重定向：连 C/C++ 扩展、printf、第三方库直接写 fd 1/2 的输出都能抓到
- 退出前调用 libc fflush，避免 C 层缓冲区里的日志随进程消失
- logging：临时把 root 降到 DEBUG 采集所有记录，但保持原有控制台输出级别不变；
  propagate=False 的 logger 也会被挂上采集 handler
- 未捕获异常（含子线程）写入归档；faulthandler 把段错误调用栈写到独立文件
"""
from __future__ import annotations

import ctypes
import ctypes.util
import faulthandler
import logging
import os
import sys
import threading
import time
import traceback
from typing import List, Optional, Tuple

from .archive import Session
from .textio import LineSplitter, strip_ansi


def flush_c_stdio() -> None:
    try:
        if os.name == "nt":
            libc = ctypes.cdll.msvcrt
        else:
            libc = ctypes.CDLL(ctypes.util.find_library("c") or None)
        libc.fflush(None)
    except Exception:
        pass


def _flush_py() -> None:
    for s in (sys.stdout, sys.stderr, sys.__stdout__, sys.__stderr__):
        try:
            if s is not None:
                s.flush()
        except Exception:
            pass


class _FdTee:
    def __init__(self, fd: int, name: str, session: Session, echo: bool, lock: threading.Lock):
        self.fd = fd
        self.name = name
        self.session = session
        self.echo = echo
        self.lock = lock
        self.saved: Optional[int] = None
        self.thread: Optional[threading.Thread] = None

    def start(self) -> None:
        _flush_py()
        flush_c_stdio()
        self.saved = os.dup(self.fd)
        r, w = os.pipe()
        os.dup2(w, self.fd)
        os.close(w)
        self.thread = threading.Thread(target=self._pump, args=(r,), daemon=True,
                                       name="logfind-fd%d" % self.fd)
        self.thread.start()

    def _pump(self, r: int) -> None:
        splitter = LineSplitter("auto")
        archive = self.session.archive
        try:
            while True:
                try:
                    data = os.read(r, 65536)
                except OSError:
                    break
                if not data:
                    break
                if self.echo and self.saved is not None:
                    try:
                        os.write(self.saved, data)
                    except OSError:
                        pass
                for line in splitter.feed(data):
                    with self.lock:
                        archive.write(self.name, strip_ansi(line))
            rest = splitter.flush()
            if rest:
                with self.lock:
                    archive.write(self.name, strip_ansi(rest))
        finally:
            os.close(r)

    def stop(self) -> None:
        if self.saved is None:
            return
        _flush_py()
        flush_c_stdio()
        os.dup2(self.saved, self.fd)  # 管道唯一的写端被替换掉，读线程会读到 EOF
        if self.thread is not None:
            self.thread.join(timeout=5)
        os.close(self.saved)
        self.saved = None


class ArchiveHandler(logging.Handler):
    def __init__(self, session: Session, level: int = logging.NOTSET):
        super().__init__(level)
        self.session = session
        self.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            self.session.archive.write("log", msg, record.created)
        except Exception:
            self.handleError(record)


class capture:
    """上下文管理器 / 手动 start()/stop()。

    用法::

        import logfind
        with logfind.capture(name="mask"):
            run_my_module()

    所有输出写入 ``<home>/sessions/<时间>_<name>/``，之后可用 ``logfind show`` / ``logfind grep --session`` 查看。
    """

    def __init__(self, name: str = "inproc", home: Optional[str] = None,
                 session: Optional[Session] = None, fds: bool = True, echo: bool = True,
                 logging_level: Optional[int] = logging.DEBUG, catch_hidden_loggers: bool = True,
                 hooks: bool = True, **archive_kw):
        from .config import default_home
        self.session = session or Session.create(home or default_home(), name,
                                                 {"kind": "inproc", "argv": list(sys.argv)}, **archive_kw)
        self.fds = fds
        self.echo = echo
        self.logging_level = logging_level
        self.catch_hidden_loggers = catch_hidden_loggers
        self.hooks = hooks
        self._lock = threading.Lock()
        self._tees: List[_FdTee] = []
        self._handler: Optional[ArchiveHandler] = None
        self._restore: List[Tuple] = []
        self._fault_fh = None
        self._old_hooks = None
        self._active = False

    @property
    def directory(self) -> str:
        return self.session.directory

    def start(self) -> "capture":
        if self._active:
            return self
        self._active = True
        if self.hooks:
            self._install_hooks()
        if self.logging_level is not None:
            self._install_logging()
        if self.fds:
            for fd, name in ((1, "stdout"), (2, "stderr")):
                tee = _FdTee(fd, name, self.session, self.echo, self._lock)
                try:
                    tee.start()
                    self._tees.append(tee)
                except OSError as e:
                    self.session.archive.note("无法重定向 fd %d: %s" % (fd, e))
        self.session.archive.note("开始进程内捕获 pid=%d" % os.getpid())
        return self

    def stop(self, exc_info=None) -> None:
        if not self._active:
            return
        self._active = False
        if exc_info and exc_info[0] is not None and not issubclass(exc_info[0], (SystemExit, GeneratorExit)):
            self.session.archive.write("exception", "".join(traceback.format_exception(*exc_info)).rstrip())
        for tee in reversed(self._tees):
            tee.stop()
        self._tees.clear()
        self._uninstall_logging()
        self._uninstall_hooks()
        self.session.archive.note("结束进程内捕获")
        self.session.update_meta(ended=time.strftime("%Y-%m-%dT%H:%M:%S"),
                                 status="exception" if exc_info and exc_info[0] else "ok")
        self.session.close()

    def __enter__(self) -> "capture":
        return self.start()

    def __exit__(self, *exc) -> bool:
        self.stop(exc)
        return False

    # ---- logging ----
    def _install_logging(self) -> None:
        root = logging.getLogger()
        self._handler = ArchiveHandler(self.session)
        old_level = root.level
        if self.logging_level < root.getEffectiveLevel():
            # 原有 handler 保持原来的过滤级别，控制台不会突然被 DEBUG 刷屏
            for h in root.handlers:
                if h.level == logging.NOTSET:
                    self._restore.append(("hlevel", h, h.level))
                    h.setLevel(old_level)
            self._restore.append(("rlevel", root, old_level))
            root.setLevel(self.logging_level)
        root.addHandler(self._handler)
        if self.catch_hidden_loggers:
            for lg in list(logging.root.manager.loggerDict.values()):
                if isinstance(lg, logging.Logger) and not lg.propagate:
                    lg.addHandler(self._handler)
                    self._restore.append(("handler", lg, None))

    def _uninstall_logging(self) -> None:
        if self._handler is None:
            return
        logging.getLogger().removeHandler(self._handler)
        for kind, obj, val in reversed(self._restore):
            if kind == "hlevel":
                obj.setLevel(val)
            elif kind == "rlevel":
                obj.setLevel(val)
            elif kind == "handler":
                obj.removeHandler(self._handler)
        self._restore.clear()
        self._handler = None

    # ---- 崩溃钩子 ----
    def _install_hooks(self) -> None:
        archive = self.session.archive
        self._old_hooks = (sys.excepthook, getattr(threading, "excepthook", None),
                           faulthandler.is_enabled())
        old_sys, old_thr, _ = self._old_hooks

        def sys_hook(tp, val, tb):
            try:
                archive.write("exception", "".join(traceback.format_exception(tp, val, tb)).rstrip())
            except Exception:
                pass
            old_sys(tp, val, tb)

        sys.excepthook = sys_hook
        if old_thr is not None:
            def thr_hook(args):
                try:
                    text = "".join(traceback.format_exception(args.exc_type, args.exc_value,
                                                              args.exc_traceback)).rstrip()
                    archive.write("exception", "线程 %s 未捕获异常:\n%s"
                                  % (getattr(args.thread, "name", "?"), text))
                except Exception:
                    pass
                old_thr(args)
            threading.excepthook = thr_hook
        # 段错误时 Python 线程已经无法工作，必须直接写到真实文件
        try:
            self._fault_fh = open(os.path.join(self.session.directory, "crash-faulthandler.log"), "w")
            faulthandler.enable(file=self._fault_fh, all_threads=True)
        except (OSError, RuntimeError, ValueError):
            self._fault_fh = None

    def _uninstall_hooks(self) -> None:
        if self._old_hooks is None:
            return
        old_sys, old_thr, fh_enabled = self._old_hooks
        sys.excepthook = old_sys
        if old_thr is not None:
            threading.excepthook = old_thr
        if self._fault_fh is not None:
            faulthandler.disable()
            if fh_enabled:
                try:
                    faulthandler.enable(file=sys.__stderr__)
                except Exception:
                    pass
            self._fault_fh.close()
            path = self._fault_fh.name
            try:
                if os.path.getsize(path) == 0:
                    os.remove(path)
            except OSError:
                pass
            self._fault_fh = None
        self._old_hooks = None

"""logfind —— 健壮的日志/快照捕获、跟踪、检索与对比工具。

Python 中直接使用::

    import logfind

    with logfind.capture(name="mask"):          # 抓取本进程全部输出（含 C 扩展）、logging、崩溃栈
        run()

    logfind.snap({"step": 3, "vec": v}, label="vector")   # 原子地保存对象快照
    logfind.snap_files(["out/*.json"], label="mask")       # 稳定拷贝文件快照
"""
from __future__ import annotations

__version__ = "0.1.0"

from typing import Any, Iterable, Optional

from .archive import Archive, Session, TriggerRecorder, list_sessions, resolve_session
from .follow import Follower
from .inproc import capture, flush_c_stdio
from .search import Filters, Matcher, iter_records, search
from .snapshot import Snapshot, SnapshotStore, diff_snapshots
from .textio import atomic_write, read_stable, read_text


def _store(home: Optional[str]) -> SnapshotStore:
    import os
    from .config import default_home
    return SnapshotStore(os.path.join(home or default_home(), "snapshots"))


def snap(obj: Any, label: str = "", name: str = "object", note: str = "",
         home: Optional[str] = None) -> Snapshot:
    """保存内存对象快照（dict/list/numpy 数组/任意可 pickle 对象）。"""
    return _store(home).save_object(obj, label=label, name=name, note=note)


def snap_files(paths: Iterable[str], label: str = "", note: str = "",
               home: Optional[str] = None) -> Snapshot:
    """对文件/目录/glob 拍快照，会等待正在写入的文件写完。"""
    return _store(home).take(list(paths), label=label, note=note)


__all__ = [
    "Archive", "Session", "TriggerRecorder", "list_sessions", "resolve_session", "Follower",
    "capture", "flush_c_stdio", "Filters", "Matcher", "iter_records", "search", "Snapshot",
    "SnapshotStore", "diff_snapshots", "atomic_write", "read_stable", "read_text", "snap",
    "snap_files", "__version__",
]

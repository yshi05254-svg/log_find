"""持久化归档：把所有捕获到的行带时间戳落盘，分段滚动，并支持触发器保存上下文。"""
from __future__ import annotations

import collections
import json
import os
import re
import sys
import threading
import time
from datetime import datetime
from typing import Callable, Deque, Dict, Iterable, List, Optional, Tuple

from .parsing import parse_size
from .textio import atomic_write

ARCHIVE_LINE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}) \[([^\]]*)\] ?(.*)$")
NOTE_SOURCE = "logfind"


def _fmt_ts(ts: float) -> str:
    dt = datetime.fromtimestamp(ts)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03d" % (dt.microsecond // 1000)


def _safe_source(source: str) -> str:
    return source.replace("]", ")").replace("\n", " ") or "-"


def _slug(text: str, n: int = 40) -> str:
    s = re.sub(r"[^\w.-]+", "_", text, flags=re.UNICODE).strip("_")
    return s[:n] or "x"


class Archive:
    """线程安全的分段日志归档。

    每行格式: ``2026-10-02T20:22:01.123 [source] 文本``，可直接用任何文本工具查看。
    每行写入后立即 flush 到操作系统，进程被 kill 也不会丢失已写入的行。
    """

    def __init__(self, directory: str, max_segment_bytes="16MB", max_total_bytes="1GB",
                 fsync_interval: float = 2.0):
        self.directory = directory
        os.makedirs(directory, exist_ok=True)
        self.max_segment_bytes = parse_size(max_segment_bytes)
        self.max_total_bytes = parse_size(max_total_bytes)
        self.fsync_interval = fsync_interval
        self._lock = threading.RLock()
        self._fh = None
        self._seg_index = 0
        self._seg_size = 0
        self._last_fsync = time.time()
        self.lines_written = 0
        self.dropped_segments = 0
        existing = self.segments()
        if existing:
            self._seg_index = int(re.findall(r"\d+", os.path.basename(existing[-1]))[0])
        self._open_next()

    def segments(self) -> List[str]:
        return sorted(
            os.path.join(self.directory, n) for n in os.listdir(self.directory)
            if re.match(r"^seg-\d+\.log$", n)
        )

    def _open_next(self) -> None:
        if self._fh is not None:
            self._fh.close()
        self._seg_index += 1
        path = os.path.join(self.directory, "seg-%06d.log" % self._seg_index)
        self._fh = open(path, "a", encoding="utf-8", errors="replace", newline="\n")
        self._seg_size = self._fh.tell()
        self._enforce_total()

    def _enforce_total(self) -> None:
        segs = self.segments()
        total = sum(os.path.getsize(s) for s in segs)
        while total > self.max_total_bytes and len(segs) > 1:
            victim = segs.pop(0)
            total -= os.path.getsize(victim)
            os.remove(victim)
            self.dropped_segments += 1

    def write(self, source: str, text: str, ts: Optional[float] = None) -> None:
        ts = time.time() if ts is None else ts
        prefix = "%s [%s] " % (_fmt_ts(ts), _safe_source(source))
        payload = "".join(prefix + part + "\n" for part in text.split("\n"))
        with self._lock:
            if self._fh is None:
                return
            self._fh.write(payload)
            self._fh.flush()
            self._seg_size += len(payload.encode("utf-8", errors="replace"))
            self.lines_written += payload.count("\n")
            now = time.time()
            if self.fsync_interval >= 0 and now - self._last_fsync >= self.fsync_interval:
                try:
                    os.fsync(self._fh.fileno())
                except OSError:
                    pass
                self._last_fsync = now
            if self._seg_size >= self.max_segment_bytes:
                self._open_next()

    def note(self, text: str) -> None:
        self.write(NOTE_SOURCE, text)

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                try:
                    self._fh.flush()
                    os.fsync(self._fh.fileno())
                except OSError:
                    pass
                self._fh.close()
                self._fh = None


def parse_archive_line(line: str) -> Optional[Tuple[str, str, str]]:
    """返回 (时间戳, 来源, 文本)。"""
    m = ARCHIVE_LINE.match(line)
    return (m.group(1), m.group(2), m.group(3)) if m else None


class Session:
    """一次捕获会话：<home>/sessions/<id>/{meta.json, seg-*.log, hits/}"""

    def __init__(self, directory: str):
        self.directory = directory
        self.id = os.path.basename(directory.rstrip("/\\"))
        self._archive: Optional[Archive] = None

    @classmethod
    def create(cls, home: str, name: str = "session", meta: Optional[dict] = None,
               **archive_kw) -> "Session":
        base = os.path.join(home, "sessions")
        os.makedirs(base, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        sid = "%s_%s" % (stamp, _slug(name, 30))
        path = os.path.join(base, sid)
        n = 1
        while os.path.exists(path):
            n += 1
            path = os.path.join(base, "%s-%d" % (sid, n))
        os.makedirs(path)
        s = cls(path)
        info = {"id": s.id, "name": name, "started": datetime.now().isoformat(timespec="seconds"),
                "pid": os.getpid(), "cwd": os.getcwd()}
        info.update(meta or {})
        s.write_meta(info)
        s._archive = Archive(path, **archive_kw)
        return s

    @property
    def archive(self) -> Archive:
        if self._archive is None:
            self._archive = Archive(self.directory)
        return self._archive

    @property
    def hits_dir(self) -> str:
        return os.path.join(self.directory, "hits")

    @property
    def meta_path(self) -> str:
        return os.path.join(self.directory, "meta.json")

    def read_meta(self) -> dict:
        try:
            with open(self.meta_path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {"id": self.id}

    def write_meta(self, meta: dict) -> None:
        atomic_write(self.meta_path, json.dumps(meta, ensure_ascii=False, indent=2).encode("utf-8"))

    def update_meta(self, **kw) -> None:
        meta = self.read_meta()
        meta.update(kw)
        self.write_meta(meta)

    def segments(self) -> List[str]:
        if not os.path.isdir(self.directory):
            return []
        return sorted(
            os.path.join(self.directory, n) for n in os.listdir(self.directory)
            if re.match(r"^seg-\d+\.log$", n)
        )

    def hit_files(self) -> List[str]:
        if not os.path.isdir(self.hits_dir):
            return []
        return sorted(os.path.join(self.hits_dir, n) for n in os.listdir(self.hits_dir))

    def iter_lines(self) -> Iterable[str]:
        for seg in self.segments():
            with open(seg, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    yield line.rstrip("\n")

    def close(self) -> None:
        if self._archive is not None:
            self._archive.close()


def list_sessions(home: str) -> List[Session]:
    base = os.path.join(home, "sessions")
    if not os.path.isdir(base):
        return []
    return [Session(os.path.join(base, n)) for n in sorted(os.listdir(base))
            if os.path.isdir(os.path.join(base, n))]


def resolve_session(home: str, ref: str = "latest") -> Session:
    sessions = list_sessions(home)
    if not sessions:
        raise LookupError("%s 下还没有任何会话" % os.path.join(home, "sessions"))
    if ref in ("latest", "last", ""):
        return sessions[-1]
    if ref == "prev":
        ref = "-2"
    if re.match(r"^-\d+$", ref):
        idx = int(ref)
        if -len(sessions) <= idx:
            return sessions[idx]
        raise LookupError("只有 %d 个会话" % len(sessions))
    matches = [s for s in sessions if s.id.startswith(ref)] or [s for s in sessions if ref in s.id]
    if not matches:
        raise LookupError("找不到会话: %s" % ref)
    return matches[-1]


def prune_sessions(home: str, keep: int) -> List[str]:
    removed = []
    import shutil
    for s in list_sessions(home)[:-keep] if keep > 0 else []:
        shutil.rmtree(s.directory, ignore_errors=True)
        removed.append(s.id)
    return removed


Entry = Tuple[float, str, str]  # (时间, 来源, 文本)


class TriggerRecorder:
    """关键字/正则命中时，把命中前 `before` 行和命中后 `after` 行保存成单独的文件。

    即使终端被刷屏、日志文件被滚动覆盖，命中现场依然完整保留。
    """

    def __init__(self, patterns: Iterable[str], out_dir: str, before: int = 50, after: int = 30,
                 ignore_case: bool = False, on_hit: Optional[Callable[[str, Entry], None]] = None,
                 max_hits: int = 200):
        flags = re.IGNORECASE if ignore_case else 0
        self.patterns = [re.compile(p, flags) for p in patterns if p]
        self.out_dir = out_dir
        self.before = before
        self.after = after
        self.on_hit = on_hit
        self.max_hits = max_hits
        self.ring: Deque[Entry] = collections.deque(maxlen=max(before, 1))
        self._lock = threading.Lock()
        self._pending: Optional[dict] = None
        self.hit_count = 0
        self.files: List[str] = []

    @property
    def enabled(self) -> bool:
        return bool(self.patterns)

    def _match(self, text: str) -> Optional[str]:
        for rx in self.patterns:
            if rx.search(text):
                return rx.pattern
        return None

    def feed(self, source: str, text: str, ts: Optional[float] = None) -> None:
        if not self.patterns:
            return
        entry = (time.time() if ts is None else ts, source, text)
        with self._lock:
            pat = self._match(text)
            if self._pending is not None:
                self._pending["lines"].append(("hit" if pat else "", entry))
                if pat:
                    self._pending["remaining"] = self.after
                    self._pending["patterns"].add(pat)
                    self.hit_count += 1
                else:
                    self._pending["remaining"] -= 1
                if self._pending["remaining"] <= 0:
                    self._write_pending()
            elif pat:
                self.hit_count += 1
                self._pending = {
                    "first": entry, "patterns": {pat}, "remaining": self.after,
                    "lines": [("", e) for e in self.ring] + [("hit", entry)],
                }
                if self.after <= 0:
                    self._write_pending()
            self.ring.append(entry)
        if pat and self.on_hit:
            self.on_hit(pat, entry)

    def _write_pending(self) -> None:
        p, self._pending = self._pending, None
        if p is None or len(self.files) >= self.max_hits:
            return
        os.makedirs(self.out_dir, exist_ok=True)
        ts, source, text = p["first"]
        name = "%s_%03d_%s.txt" % (datetime.fromtimestamp(ts).strftime("%Y%m%d-%H%M%S"),
                                   len(self.files) + 1, _slug(text, 40))
        path = os.path.join(self.out_dir, name)
        out = ["# logfind 触发记录", "# 匹配规则: %s" % ", ".join(sorted(p["patterns"])),
               "# 首次命中: %s [%s]" % (_fmt_ts(ts), source), ""]
        for mark, (t, src, txt) in p["lines"]:
            out.append("%s %s [%s] %s" % (">>" if mark else "  ", _fmt_ts(t), src, txt))
        atomic_write(path, ("\n".join(out) + "\n").encode("utf-8", errors="replace"))
        self.files.append(path)

    def flush(self) -> None:
        with self._lock:
            if self._pending is not None:
                self._write_pending()


def stderr_hit_printer(prefix: str = "[logfind] 命中") -> Callable[[str, Entry], None]:
    def _p(pattern: str, entry: Entry) -> None:
        try:
            sys.stderr.write("\x1b[1;33m%s /%s/: %s\x1b[0m\n" % (prefix, pattern, entry[2][:200])
                             if sys.stderr.isatty() else "%s /%s/: %s\n" % (prefix, pattern, entry[2][:200]))
            sys.stderr.flush()
        except Exception:
            pass
    return _p


def tail_entries(lines: Iterable[str], n: int) -> List[str]:
    return list(collections.deque(lines, maxlen=n))


def summarize_sources(session: Session) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for line in session.iter_lines():
        p = parse_archive_line(line)
        if p:
            counts[p[1]] = counts.get(p[1], 0) + 1
    return counts

"""健壮地实时跟踪日志文件（类似 tail -F，但不丢行）。

处理的情况：
- 文件还不存在 / 被删除后重建
- 日志滚动（rename 方式）：先把旧文件剩余内容读完，再从新文件开头读
- copytruncate 方式滚动 / 文件被清空：检测到变小后从头读
- 写了一半的行：等待换行，超过 partial_timeout 仍没有换行则直接输出
- glob 模式下新出现的文件（例如按时间命名的新日志）
- Windows 下不长期占用文件句柄，避免阻碍写入方滚动日志
"""
from __future__ import annotations

import glob
import os
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List, Optional

from .textio import LineSplitter, is_wide, open_any, sniff_encoding

CHUNK = 1 << 20
MAX_PER_POLL = 16 << 20
HEAD_BYTES = 64


@dataclass
class FollowEvent:
    kind: str  # line / partial / appeared / rotated / truncated / vanished / error
    path: str
    text: str = ""
    ts: float = field(default_factory=time.time)


class _Tracked:
    def __init__(self, path: str, encoding: str):
        self.path = path
        self.encoding_opt = encoding
        self.key = None  # (dev, ino)
        self.offset = 0
        self.fh = None
        self.splitter: Optional[LineSplitter] = None
        self.last_data = time.time()
        self.vanished = False
        self.head = b""  # 文件开头的指纹，用于识别“清空后又写入更多内容”的截断
        self.mtime_ns = 0

    def bind(self, st: os.stat_result, offset: int) -> None:
        self.key = (st.st_dev, st.st_ino)
        self.offset = offset
        self.vanished = False
        self.mtime_ns = st.st_mtime_ns
        self.head = self.read_head()
        enc = self.encoding_opt
        if enc in (None, "", "auto"):
            enc = sniff_encoding(self.path)
        self.splitter = LineSplitter(enc)

    def read_head(self, n: int = HEAD_BYTES) -> bytes:
        n = min(n, self.offset) if self.offset else 0
        if n <= 0:
            return b""
        try:
            with open(self.path, "rb") as fh:
                return fh.read(n)
        except OSError:
            return b""

    def close(self) -> None:
        if self.fh is not None:
            try:
                self.fh.close()
            except OSError:
                pass
            self.fh = None


def expand(patterns: Iterable[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for pat in patterns:
        pat = os.path.expanduser(pat)
        if glob.has_magic(pat):
            matches = sorted(glob.glob(pat, recursive=True))
        else:
            matches = [pat] if os.path.exists(pat) else []
        for m in matches:
            if os.path.isfile(m):
                key = os.path.abspath(m)
                if key not in seen:
                    seen.add(key)
                    out.append(m)
    return out


def _offset_for_last_lines(path: str, size: int, n: int) -> int:
    if n <= 0 or size == 0:
        return size
    with open(path, "rb") as fh:
        pos = size
        found = 0
        block = 8192
        # 文件最后一个字符是换行时不计入
        fh.seek(size - 1)
        if fh.read(1) == b"\n":
            pos -= 1
        while pos > 0:
            step = min(block, pos)
            pos -= step
            fh.seek(pos)
            data = fh.read(step)
            idx = len(data)
            while True:
                idx = data.rfind(b"\n", 0, idx)
                if idx < 0:
                    break
                found += 1
                if found >= n:
                    return pos + idx + 1
    return 0


class Follower:
    def __init__(self, patterns: Iterable[str], from_start: bool = False, tail_lines: int = 0,
                 encoding: str = "auto", keep_open: Optional[bool] = None,
                 partial_timeout: float = 1.0, poll_interval: float = 0.2,
                 rescan_interval: float = 0.5):
        self.patterns = list(patterns)
        self.encoding = encoding
        self.keep_open = (os.name != "nt") if keep_open is None else keep_open
        self.partial_timeout = partial_timeout
        self.poll_interval = poll_interval
        self.rescan_interval = rescan_interval
        self.files: Dict[str, _Tracked] = {}
        self._last_scan = 0.0
        self._start_time = time.time()
        self._seen_keys = set()  # 读过的 (dev, ino)，避免重复读取
        for path in expand(self.patterns):
            t = _Tracked(path, encoding)
            try:
                st = os.stat(path)
            except OSError:
                continue
            if from_start:
                off = 0
            elif tail_lines > 0:
                enc = encoding if encoding not in (None, "", "auto") else sniff_encoding(path)
                off = 0 if is_wide(enc) else _offset_for_last_lines(path, st.st_size, tail_lines)
            else:
                off = st.st_size
            t.bind(st, off)
            self._seen_keys.add(t.key)
            self.files[os.path.abspath(path)] = t
        # 明确指定但暂不存在的文件也跟踪，出现后从头读
        for pat in self.patterns:
            p = os.path.expanduser(pat)
            if not glob.has_magic(p) and os.path.abspath(p) not in self.files:
                t = _Tracked(p, encoding)
                t.vanished = True
                self.files[os.path.abspath(p)] = t
        self._last_scan = time.time()

    # ---- 读取 ----
    def _open(self, t: _Tracked):
        if t.fh is not None:
            return t.fh
        fh = open(t.path, "rb")
        st = os.fstat(fh.fileno())
        if (st.st_dev, st.st_ino) != t.key:
            fh.close()
            return None
        fh.seek(t.offset)
        if self.keep_open:
            t.fh = fh
        return fh

    def _read_from(self, t: _Tracked, fh, events: List[FollowEvent], limit: int = MAX_PER_POLL) -> None:
        total = 0
        while total < limit:
            data = fh.read(CHUNK)
            if not data:
                break
            total += len(data)
            t.offset += len(data)
            t.last_data = time.time()
            for line in t.splitter.feed(data):
                events.append(FollowEvent("line", t.path, line))

    def _read_new(self, t: _Tracked, events: List[FollowEvent]) -> None:
        try:
            fh = self._open(t)
        except FileNotFoundError:
            return
        except OSError as e:
            events.append(FollowEvent("error", t.path, str(e)))
            return
        if fh is None:
            return
        try:
            fh.seek(t.offset)
            self._read_from(t, fh, events)
        finally:
            if not self.keep_open:
                fh.close()

    def _find_rotated(self, t: _Tracked) -> Optional[str]:
        """旧文件已被改名：在同目录下按 inode 找到它（app.log -> app.log.1 等）。"""
        d = os.path.dirname(os.path.abspath(t.path)) or "."
        try:
            names = os.listdir(d)
        except OSError:
            return None
        base = os.path.basename(t.path)
        stem = os.path.splitext(base)[0]
        for n in sorted(names, key=lambda x: (not x.startswith(stem), x)):
            p = os.path.join(d, n)
            try:
                st = os.stat(p)
            except OSError:
                continue
            if (st.st_dev, st.st_ino) == t.key:
                return p
        return None

    def _drain_old(self, t: _Tracked, events: List[FollowEvent]) -> None:
        """在切换到新文件之前，把旧文件里还没读到的内容读完。"""
        if t.key is None or t.splitter is None:
            return
        try:
            if t.fh is not None:
                self._read_from(t, t.fh, events, limit=1 << 62)
            else:
                rotated = self._find_rotated(t)
                if rotated and not rotated.endswith((".gz", ".bz2", ".xz")):
                    with open(rotated, "rb") as fh:
                        fh.seek(t.offset)
                        self._read_from(t, fh, events, limit=1 << 62)
        except OSError as e:
            events.append(FollowEvent("error", t.path, "读取旧文件失败: %s" % e))
        rest = t.splitter.flush()
        if rest:
            events.append(FollowEvent("partial", t.path, rest))
        t.close()

    def _rescan(self, events: List[FollowEvent]) -> None:
        for path in expand(self.patterns):
            key = os.path.abspath(path)
            if key in self.files:
                continue
            try:
                st = os.stat(path)
            except OSError:
                continue
            self._recover_siblings(path, events)
            t = _Tracked(path, self.encoding)
            t.bind(st, 0)
            self._seen_keys.add(t.key)
            self.files[key] = t
            events.append(FollowEvent("appeared", path))

    def _recover_siblings(self, path: str, events: List[FollowEvent]) -> None:
        """新文件在两次扫描之间出现又被滚动走：把开始跟踪之后才产生的滚动文件补读回来。"""
        from .search import rotated_siblings
        cands = []
        for sib in rotated_siblings(path):
            try:
                st = os.stat(sib)
            except OSError:
                continue
            key = (st.st_dev, st.st_ino)
            if key in self._seen_keys or st.st_mtime < self._start_time - 1:
                continue
            cands.append((st.st_mtime, sib, st))
        for _, sib, st in sorted(cands):
            t = _Tracked(sib, self.encoding)
            t.bind(st, 0)
            self._seen_keys.add(t.key)
            events.append(FollowEvent("recovered", sib))
            try:
                with open_any(sib) as fh:
                    self._read_from(t, fh, events, limit=1 << 62)
            except (OSError, EOFError) as e:
                events.append(FollowEvent("error", sib, str(e)))
            rest = t.splitter.flush()
            if rest:
                events.append(FollowEvent("partial", sib, rest))

    def poll(self) -> List[FollowEvent]:
        events: List[FollowEvent] = []
        now = time.time()
        if now - self._last_scan >= self.rescan_interval:
            self._rescan(events)
            self._last_scan = now
        for t in list(self.files.values()):
            try:
                st = os.stat(t.path)
            except OSError:
                st = None
            if st is None:
                if not t.vanished:
                    self._drain_old(t, events)
                    t.vanished = True
                    events.append(FollowEvent("vanished", t.path))
                continue
            key = (st.st_dev, st.st_ino)
            if t.vanished or key != t.key:
                if not t.vanished and t.key is not None:
                    self._drain_old(t, events)
                    events.append(FollowEvent("rotated", t.path))
                elif t.key is None or t.vanished:
                    events.append(FollowEvent("appeared", t.path))
                # 两次轮询之间可能已经滚动了不止一次
                self._recover_siblings(t.path, events)
                t.close()
                t.bind(st, 0)
                self._seen_keys.add(t.key)
            elif st.st_size < t.offset or (st.st_mtime_ns != t.mtime_ns and t.head
                                           and t.read_head(len(t.head)) != t.head):
                t.close()
                t.splitter.reset()
                t.offset = 0
                events.append(FollowEvent("truncated", t.path))
            t.mtime_ns = st.st_mtime_ns
            if st.st_size > t.offset:
                self._read_new(t, events)
                if len(t.head) < HEAD_BYTES:
                    t.head = t.read_head()
            if t.splitter is not None and t.splitter.pending and \
                    time.time() - t.last_data >= self.partial_timeout:
                rest = t.splitter.flush()
                if rest:
                    events.append(FollowEvent("partial", t.path, rest))
        return events

    def follow(self, should_stop=None) -> Iterator[FollowEvent]:
        while True:
            events = self.poll()
            for ev in events:
                yield ev
            if should_stop is not None and should_stop():
                return
            if not events:
                time.sleep(self.poll_interval)

    def close(self) -> List[FollowEvent]:
        events: List[FollowEvent] = []
        for t in self.files.values():
            if t.splitter is not None:
                rest = t.splitter.flush()
                if rest:
                    events.append(FollowEvent("partial", t.path, rest))
            t.close()
        return events

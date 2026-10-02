"""跨文件检索：多行记录（异常栈不被拆散）、时间/级别过滤、上下文、自动包含滚动后的旧文件和压缩文件。"""
from __future__ import annotations

import collections
import glob
import os
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Deque, Iterable, Iterator, List, Optional, Sequence

from .parsing import parse_level, parse_timestamp
from .textio import LineSplitter, detect_encoding, looks_binary, open_any

# 常见“崩溃/被吞掉的错误”特征
PRESETS = {
    "crash": [
        r"Traceback \(most recent call last\)", r"Segmentation fault", r"core dumped", r"\bSIGSEGV\b",
        r"\bSIGABRT\b", r"\bSIGBUS\b", r"\bSIGFPE\b", r"\bSIGILL\b", r"\bpanic(ked)?\b", r"Assertion .*failed",
        r"\bAborted\b", r"terminate called", r"std::bad_alloc", r"\bOOM\b", r"[Oo]ut of memory",
        r"\bKilled\b", r"Fatal Python error", r"CUDA error", r"cudaError", r"illegal memory access",
        r"ACCESS_VIOLATION", r"stack overflow", r"double free", r"heap-use-after-free",
        r"AddressSanitizer", r"\b(nan|NaN)\b", r"\b\w*(Error|Exception)\b:", r"unhandled exception",
    ],
    "error": [r"(?i)\b(error|err|fatal|critical|fail(ed|ure)?|exception)\b"],
    "warn": [r"(?i)\b(warn(ing)?|deprecated)\b"],
}

LOG_EXTS = (".log", ".txt", ".out", ".err", ".jsonl", ".gz", ".bz2", ".xz", ".csv", ".trace")
_ROTATED_TAIL = re.compile(r"^[.\-_](\d+|\d{4}-?\d{2}-?\d{2}[\w.-]*|old|bak)(\.(gz|bz2|xz|zip))?$")


@dataclass
class Record:
    path: str
    lineno: int
    lines: List[str]
    ts: Optional[datetime] = None
    level: Optional[int] = None

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


@dataclass
class Hit:
    record: Record
    is_match: bool
    index: int  # 在该文件中的记录序号，用于判断是否连续


def rotated_siblings(path: str) -> List[str]:
    """app.log -> app.log.1, app.log.2.gz, app.1.log, app-20261001.log ..."""
    d = os.path.dirname(path) or "."
    base = os.path.basename(path)
    stem, ext = os.path.splitext(base)
    out = []
    try:
        names = os.listdir(d)
    except OSError:
        return out
    for n in names:
        if n == base:
            continue
        tail = None
        if n.startswith(base):
            tail = n[len(base):]
        elif ext and n.startswith(stem) and (n.endswith(ext) or ext + "." in n):
            mid = n[len(stem):]
            tail = mid.replace(ext, "", 1)
        if tail is not None and _ROTATED_TAIL.match(tail):
            out.append(os.path.join(d, n))
    return out


def expand_paths(patterns: Iterable[str], rotated: bool = False) -> List[str]:
    files, seen = [], set()

    def add(p: str) -> None:
        k = os.path.abspath(p)
        if k not in seen and os.path.isfile(p):
            seen.add(k)
            files.append(p)

    for pat in patterns:
        pat = os.path.expanduser(pat)
        cands = sorted(glob.glob(pat, recursive=True)) if glob.has_magic(pat) else [pat]
        for c in cands:
            if os.path.isdir(c):
                for root, dirs, names in os.walk(c):
                    dirs[:] = sorted(x for x in dirs if not x.startswith("."))
                    for n in sorted(names):
                        if n.lower().endswith(LOG_EXTS) or re.search(r"\.log[.\-_]", n):
                            add(os.path.join(root, n))
            else:
                add(c)
                if rotated:
                    for s in rotated_siblings(c):
                        add(s)
    # 旧文件在前，按时间顺序阅读
    def mtime(p):
        try:
            return os.path.getmtime(p)
        except OSError:
            return 0
    files.sort(key=mtime)
    return files


_CONT_RE = re.compile(r"^(\s|Traceback |Caused by|During handling|The above exception|\.\.\. \d+ more|"
                      r"#\d+\s+0x|\s*at\s|\s*File \")")


def iter_lines(path: str, encoding: str = "auto") -> Iterator[str]:
    with open_any(path) as fh:
        head = fh.read(65536)
        if encoding in (None, "", "auto"):
            enc = detect_encoding(head)
        else:
            enc = encoding
        sp = LineSplitter(enc)
        data = head
        while data:
            for line in sp.feed(data):
                yield line
            data = fh.read(1 << 20)
        rest = sp.flush()
        if rest:
            yield rest


def iter_records(path: str, encoding: str = "auto", multiline: bool = True,
                 max_record_lines: int = 400) -> Iterator[Record]:
    """把行组合成记录：带时间戳的行开始新记录，无时间戳的后续行（如异常栈）归入上一条。"""
    try:
        ref = datetime.fromtimestamp(os.path.getmtime(path))
    except OSError:
        ref = datetime.now()
    try:
        with open_any(path) as fh:
            if looks_binary(fh.read(8192)):
                return
    except (OSError, EOFError):
        return
    cur: Optional[Record] = None
    seen_ts = False
    try:
        for lineno, line in enumerate(iter_lines(path, encoding), 1):
            ts = parse_timestamp(line, ref)
            if ts is not None:
                seen_ts = True
            starts_new = (not multiline or cur is None or ts is not None
                          or len(cur.lines) >= max_record_lines
                          or (not seen_ts and not _CONT_RE.match(line)))
            if starts_new:
                if cur is not None:
                    yield cur
                cur = Record(path, lineno, [line], ts, parse_level(line))
            else:
                cur.lines.append(line)
                if cur.level is None:
                    cur.level = parse_level(line)
    except (OSError, EOFError) as e:
        if cur is not None:
            cur.lines.append("[logfind] 读取中断: %s" % e)
    if cur is not None:
        yield cur


class Matcher:
    def __init__(self, patterns: Sequence[str], fixed: bool = False, ignore_case: bool = False,
                 invert: bool = False, all_of: bool = False):
        flags = re.IGNORECASE if ignore_case else 0
        self.regexes = [re.compile(re.escape(p) if fixed else p, flags) for p in patterns]
        self.invert = invert
        self.all_of = all_of

    def __call__(self, text: str) -> bool:
        if not self.regexes:
            ok = True
        elif self.all_of:
            ok = all(r.search(text) for r in self.regexes)
        else:
            ok = any(r.search(text) for r in self.regexes)
        return ok != self.invert

    def highlight(self, text: str, start: str, end: str) -> str:
        if self.invert or not self.regexes:
            return text
        for r in self.regexes:
            text = r.sub(lambda m: start + m.group(0) + end if m.group(0) else "", text)
        return text


@dataclass
class Filters:
    since: Optional[datetime] = None
    until: Optional[datetime] = None
    min_level: Optional[int] = None
    max_level: Optional[int] = None

    def accept(self, r: Record) -> bool:
        if self.since or self.until:
            if r.ts is None:
                return False
            if self.since and r.ts < self.since:
                return False
            if self.until and r.ts > self.until:
                return False
        if self.min_level is not None and (r.level is None or r.level < self.min_level):
            return False
        if self.max_level is not None and (r.level is None or r.level > self.max_level):
            return False
        return True


def search_records(records: Iterable[Record], matcher: Matcher, filters: Optional[Filters] = None,
                   before: int = 0, after: int = 0, max_count: int = 0) -> Iterator[Hit]:
    filters = filters or Filters()
    ring: Deque = collections.deque(maxlen=before or 1)
    remaining_after = 0
    matches = 0
    last_emitted = -1
    for i, rec in enumerate(records):
        is_match = filters.accept(rec) and matcher(rec.text)
        if is_match:
            if before:
                for j, r in ring:
                    if j > last_emitted:
                        yield Hit(r, False, j)
            yield Hit(rec, True, i)
            last_emitted = i
            matches += 1
            remaining_after = after
            ring.clear()
            if max_count and matches >= max_count and not after:
                return
        elif remaining_after > 0:
            yield Hit(rec, False, i)
            last_emitted = i
            remaining_after -= 1
            if max_count and matches >= max_count and remaining_after == 0:
                return
        else:
            if max_count and matches >= max_count:
                return
            if before:
                ring.append((i, rec))


def search(paths: Sequence[str], matcher: Matcher, filters: Optional[Filters] = None,
           before: int = 0, after: int = 0, max_count: int = 0, encoding: str = "auto",
           multiline: bool = True) -> Iterator[Hit]:
    for p in paths:
        yield from search_records(iter_records(p, encoding, multiline), matcher, filters,
                                  before, after, max_count)

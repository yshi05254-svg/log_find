"""设备时钟跳变校正与开机分段。

Android 设备 RTC 未同步时，开机阶段的 logcat 时间可能是 06-05 这类“纪元”时间，联网后
又突然跳到真实时间；按墙钟时间过滤就会切错窗口。这里把每一行换算成“开机后经过的秒数”
（uptime），它不受时钟跳变影响，再用本次开机最后一次已知的墙钟偏移推出“校正后的墙钟时间”。

换算依据（按可靠程度）：

1. 时钟锚点：``logfind adb bootlog`` / ``logfind adb logcat`` 会定期往设备日志里写
   ``logfind_clock: boot_id=<id> up=<秒>``。锚点行的 logcat 时间戳与 up 之差就是当时的
   “墙钟 - uptime”偏移。两个锚点之间偏移变了，说明中间发生了跳变，跳变点取相邻两行时间差
   最符合跳变方向的位置。
2. 没有锚点时退化为启发式：相邻两行时间倒退超过 2 秒或前跳超过 10 分钟，视为时钟跳变，
   把这段差值剔除；uptime 此时表示“距本次开机第一行日志的秒数”（近似值）。

开机分段依据 ``#logfind-boot boot_id=...`` 标记（``logfind adb logcat`` 每次连接时写入
会话归档）、锚点里的 boot_id 变化，或锚点 up 值变小。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable, List, Optional, Tuple

from .parsing import parse_timestamp, strip_archive_prefix

ANCHOR_TAG = "logfind_clock"
BOOT_MARK = "#logfind-boot"

_ANCHOR_RE = re.compile(r"\blogfind_clock\b[^:\n]{0,40}:\s*(?P<body>.*)$")
_KV_BOOT = re.compile(r"\bboot_id=(?P<bid>[0-9A-Fa-f][0-9A-Fa-f-]{7,})")
_KV_UP = re.compile(r"\bup=(?P<up>\d+(?:\.\d+)?)")
_BOOT_MARK_RE = re.compile(re.escape(BOOT_MARK) + r"\s+boot_id=(?P<bid>[0-9A-Fa-f][0-9A-Fa-f-]{7,})")

ANCHOR_TOLERANCE = 1.0     # 两个锚点之间偏移变化超过 1 秒才算跳变
HEURISTIC_BACK = 2.0       # 无锚点：时间倒退超过 2 秒视为跳变
HEURISTIC_FORWARD = 600.0  # 无锚点：前跳超过 10 分钟视为跳变

_EPOCH = datetime(1970, 1, 1)


def to_seconds(dt: datetime) -> float:
    return (dt - _EPOCH).total_seconds()


def from_seconds(s: float) -> datetime:
    return _EPOCH + timedelta(seconds=s)


def parse_anchor(text: str) -> Optional[Tuple[float, Optional[str]]]:
    """从一行（logcat 行）里解析时钟锚点，返回 (uptime, boot_id)。"""
    m = _ANCHOR_RE.search(text)
    if not m:
        return None
    up = _KV_UP.search(m["body"])
    if not up:
        return None
    bid = _KV_BOOT.search(m["body"])
    return float(up["up"]), (bid["bid"].lower() if bid else None)


def parse_boot_mark(line: str) -> Optional[str]:
    m = _BOOT_MARK_RE.search(line)
    return m["bid"].lower() if m else None


@dataclass
class Boot:
    index: int                  # 文件内第几次开机，从 1 开始
    start: int                  # 起始行号
    boot_id: Optional[str]
    anchored: bool              # True: uptime 来自锚点（精确）；False: 启发式近似
    changes: List[Tuple[int, float]] = field(default_factory=list)  # (从该行起, 墙钟-uptime 偏移)
    final_offset: Optional[float] = None
    jumps: int = 0              # 检测到的时钟跳变次数


class _BootBuilder:
    def __init__(self, index: int, start: int, boot_id: Optional[str]):
        self.boot = Boot(index, start, boot_id, anchored=False)
        self.prev: Optional[float] = None
        self.win_max: Optional[Tuple[float, int]] = None  # 当前锚点窗口内最大的正向时间差
        self.win_min: Optional[Tuple[float, int]] = None  # 最大的反向时间差
        self.anchor_changes: List[Tuple[int, float]] = []
        self.anchor_jumps = 0
        self.last_off: Optional[float] = None
        self.last_up: Optional[float] = None
        self.h_off: Optional[float] = None
        self.h_changes: List[Tuple[int, float]] = []
        self.h_jumps = 0

    def observe(self, lineno: int, t: float) -> None:
        if self.prev is None:
            self.h_off = t
            self.h_changes.append((lineno, t))
        else:
            d = t - self.prev
            if self.win_max is None or d > self.win_max[0]:
                self.win_max = (d, lineno)
            if self.win_min is None or d < self.win_min[0]:
                self.win_min = (d, lineno)
            if d < -HEURISTIC_BACK or d > HEURISTIC_FORWARD:
                self.h_off += d
                self.h_changes.append((lineno, self.h_off))
                self.h_jumps += 1
        self.prev = t

    def anchor(self, lineno: int, offset: float, up: float) -> None:
        if self.last_off is None:
            # 第一个锚点之前的行（开机最早期）沿用第一个锚点的偏移
            self.anchor_changes.append((self.boot.start, offset))
        elif abs(offset - self.last_off) > ANCHOR_TOLERANCE:
            best = self.win_max if offset > self.last_off else self.win_min
            split = best[1] if best is not None else lineno
            self.anchor_changes.append((split, offset))
            self.anchor_jumps += 1
        self.last_off = offset
        self.last_up = up
        self.win_max = self.win_min = None

    def finish(self) -> Boot:
        b = self.boot
        if self.anchor_changes:
            b.anchored = True
            b.changes = self.anchor_changes
            b.final_offset = self.last_off
            b.jumps = self.anchor_jumps
        else:
            b.changes = self.h_changes
            b.final_offset = self.h_off
            b.jumps = self.h_jumps
        return b


class Timeline:
    def __init__(self, boots: List[Boot]):
        self.boots = boots

    @property
    def total(self) -> int:
        return len(self.boots)

    def cursor(self) -> "TimelineCursor":
        return TimelineCursor(self)


class TimelineCursor:
    """按行号递增的顺序查询每行的 (第几次开机, uptime, 校正后的墙钟时间)。"""

    def __init__(self, tl: Timeline):
        self.boots = tl.boots
        self.total = tl.total
        self.bi = 0
        self.ci = -1

    def resolve(self, lineno: int, ts: Optional[datetime]) -> Tuple[Optional[int], Optional[float], Optional[datetime]]:
        if not self.boots:
            return None, None, None
        while self.bi + 1 < len(self.boots) and self.boots[self.bi + 1].start <= lineno:
            self.bi += 1
            self.ci = -1
        boot = self.boots[self.bi]
        while self.ci + 1 < len(boot.changes) and boot.changes[self.ci + 1][0] <= lineno:
            self.ci += 1
        if ts is None or self.ci < 0:
            return boot.index, None, None
        up = to_seconds(ts) - boot.changes[self.ci][1]
        fixed = from_seconds(up + boot.final_offset) if boot.final_offset is not None else None
        return boot.index, up, fixed


def build_timeline(lines: Iterable[str], ref: Optional[datetime] = None) -> Timeline:
    """第一遍扫描：找出开机分段、时钟锚点与跳变点。只保存少量状态，大文件也不占内存。"""
    boots: List[Boot] = []
    cur: Optional[_BootBuilder] = None

    def new_boot(lineno: int, bid: Optional[str]) -> _BootBuilder:
        if cur is not None:
            boots.append(cur.finish())
        return _BootBuilder(len(boots) + 1, lineno, bid)

    for lineno, line in enumerate(lines, 1):
        mark = parse_boot_mark(line)
        if mark is not None:
            if cur is None:
                cur = new_boot(lineno, mark)
            elif cur.boot.boot_id is None:
                cur.boot.boot_id = mark
            elif cur.boot.boot_id != mark:
                cur = new_boot(lineno, mark)
            continue
        if cur is None:
            cur = new_boot(lineno, None)
        text = strip_archive_prefix(line)
        ts = parse_timestamp(text, ref)
        if ts is None:
            continue
        a = parse_anchor(text)
        if a is not None:
            up, bid = a
            if bid and cur.boot.boot_id and bid != cur.boot.boot_id:
                cur = new_boot(lineno, bid)
            elif cur.last_up is not None and up < cur.last_up - 1.0:
                cur = new_boot(lineno, bid)
            elif bid and cur.boot.boot_id is None:
                cur.boot.boot_id = bid
        t = to_seconds(ts)
        cur.observe(lineno, t)
        if a is not None:
            cur.anchor(lineno, t - a[0], a[0])
    if cur is not None:
        boots.append(cur.finish())
    return Timeline(boots)


_RANGE_UNIT = {"": 1.0, "s": 1.0, "ms": 0.001, "m": 60.0, "min": 60.0, "h": 3600.0}
_RANGE_PART = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(ms|min|s|m|h)?\s*$", re.IGNORECASE)


def _range_value(text: str) -> float:
    m = _RANGE_PART.match(text)
    if not m:
        raise ValueError("无法解析时长: %r（例: 20、20s、1.5m、500ms）" % text)
    return float(m.group(1)) * _RANGE_UNIT[(m.group(2) or "").lower()]


def parse_uptime_range(spec: str) -> Tuple[Optional[float], Optional[float]]:
    """'0-20s' / '20s'（等同 0-20s）/ '30-' / '-1m' / '10s..2m' → (下限, 上限) 秒。"""
    s = spec.strip().replace("..", "-")
    if "-" not in s:
        return 0.0, _range_value(s)
    lo, _, hi = s.partition("-")
    return (_range_value(lo) if lo.strip() else None), (_range_value(hi) if hi.strip() else None)


def format_uptime(up: Optional[float]) -> str:
    return "?" if up is None else "%.3fs" % up

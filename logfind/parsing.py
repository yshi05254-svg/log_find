"""从日志行里解析时间戳、日志级别，以及命令行里的时间表达式。"""
from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Optional

LEVELS = {
    "TRACE": 5, "VERBOSE": 5,
    "DEBUG": 10,
    "INFO": 20,
    "NOTICE": 25,
    "WARN": 30, "WARNING": 30,
    "ERROR": 40, "ERR": 40,
    "CRITICAL": 50, "CRIT": 50, "FATAL": 50, "PANIC": 50, "ALERT": 50, "EMERG": 50,
}
_LETTER = {"V": 5, "T": 5, "D": 10, "I": 20, "W": 30, "E": 40, "F": 50, "A": 50, "C": 50}
LEVEL_NAMES = {5: "TRACE", 10: "DEBUG", 20: "INFO", 25: "NOTICE", 30: "WARN", 40: "ERROR", 50: "FATAL"}

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

_HEAD = 48  # 时间戳只在行首附近查找，避免把正文里的时间当成新记录

_TS_FULL = re.compile(
    r"(?<!\d)(?P<y>\d{4})[-/.](?P<mo>\d{1,2})[-/.](?P<d>\d{1,2})[T _]+"
    r"(?P<h>\d{1,2}):(?P<mi>\d{2}):(?P<s>\d{2})(?:[.,:](?P<f>\d{1,9}))?"
)
# 2026-10-02 无时分秒的日期不作为记录起点
_TS_NOYEAR = re.compile(  # logcat: 10-02 20:22:01.123
    r"^\W{0,2}(?P<mo>\d{2})-(?P<d>\d{2})\s+(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})(?:\.(?P<f>\d{1,9}))?"
)
_TS_GLOG = re.compile(  # glog: E1002 20:22:01.123456 1234 file.cc:12]
    r"^(?P<lv>[IWEF])(?P<mo>\d{2})(?P<d>\d{2})\s+(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})(?:\.(?P<f>\d{1,9}))?"
)
_TS_SYSLOG = re.compile(  # Oct  2 20:22:01
    r"^\W{0,2}(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(?P<d>\d{1,2})\s+"
    r"(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})"
)
_TS_TIMEONLY = re.compile(  # [20:22:01.123] 只有时分秒
    r"^\W{0,2}(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})(?:[.,:](?P<f>\d{1,6}))?(?!\d)"
)

_LEVEL_WORD = re.compile(
    r"(?<![A-Za-z])(TRACE|VERBOSE|DEBUG|INFO|NOTICE|WARNING|WARN|ERROR|ERR|CRITICAL|CRIT|FATAL|PANIC|ALERT|EMERG)(?![A-Za-z])",
    re.IGNORECASE,
)
_LEVEL_LOGCAT = re.compile(r"^\S+\s+\S+\s+\d+\s+\d+\s+([VDIWEFA])\s")
_LEVEL_LOGCAT_BRIEF = re.compile(r"^([VDIWEFA])/[^\s(]+\s*\(")


def _frac(f: Optional[str]) -> int:
    if not f:
        return 0
    return int((f + "000000")[:6])


def _mk(y, mo, d, h, mi, s, f=None) -> Optional[datetime]:
    try:
        return datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), _frac(f))
    except ValueError:
        return None


def parse_timestamp(line: str, ref: Optional[datetime] = None) -> Optional[datetime]:
    """识别行首的时间戳。缺少年份/日期时用 ref（默认当前时间）补全。"""
    head = line[:_HEAD]
    m = _TS_FULL.search(head)
    if m:
        return _mk(m["y"], m["mo"], m["d"], m["h"], m["mi"], m["s"], m["f"])
    ref = ref or datetime.now()
    for rx in (_TS_GLOG, _TS_NOYEAR):
        m = rx.match(head)
        if m:
            return _mk(ref.year, m["mo"], m["d"], m["h"], m["mi"], m["s"], m["f"])
    m = _TS_SYSLOG.match(head)
    if m:
        return _mk(ref.year, _MONTHS[m["mon"]], m["d"], m["h"], m["mi"], m["s"])
    m = _TS_TIMEONLY.match(head)
    if m:
        return _mk(ref.year, ref.month, ref.day, m["h"], m["mi"], m["s"], m["f"])
    return None


def parse_level(line: str) -> Optional[int]:
    m = _TS_GLOG.match(line)
    if m:
        return _LETTER[m["lv"]]
    m = _LEVEL_LOGCAT.match(line) or _LEVEL_LOGCAT_BRIEF.match(line)
    if m:
        return _LETTER[m.group(1)]
    m = _LEVEL_WORD.search(line[:96])
    if m:
        return LEVELS[m.group(1).upper()]
    return None


def level_from_name(name: str) -> int:
    key = name.strip().upper()
    if key.isdigit():
        return int(key)
    if key in LEVELS:
        return LEVELS[key]
    if len(key) == 1 and key in _LETTER:
        return _LETTER[key]
    raise ValueError("未知日志级别: %r（可用: %s）" % (name, ", ".join(sorted(LEVELS))))


_REL = re.compile(r"^(\d+(?:\.\d+)?)\s*(s|sec|m|min|h|hour|d|day|w|week)s?$", re.IGNORECASE)
_REL_UNIT = {"s": 1, "sec": 1, "m": 60, "min": 60, "h": 3600, "hour": 3600,
             "d": 86400, "day": 86400, "w": 604800, "week": 604800}


def parse_time_spec(spec: str, now: Optional[datetime] = None) -> datetime:
    """支持: 10m / 2h / 1d（相对现在）、today、yesterday、HH:MM[:SS]、完整日期时间。"""
    now = now or datetime.now()
    s = spec.strip()
    m = _REL.match(s)
    if m:
        return now - timedelta(seconds=float(m.group(1)) * _REL_UNIT[m.group(2).lower()])
    low = s.lower()
    if low == "today":
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    if low == "yesterday":
        return (now - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    m = re.match(r"^(\d{1,2}):(\d{2})(?::(\d{2}))?$", s)
    if m:
        return now.replace(hour=int(m.group(1)), minute=int(m.group(2)),
                           second=int(m.group(3) or 0), microsecond=0)
    m = re.match(r"^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})$", s)
    if m:
        return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    ts = parse_timestamp(s, now)
    if ts is None:
        raise ValueError("无法解析时间: %r" % spec)
    return ts


def parse_size(spec) -> int:
    if isinstance(spec, int):
        return spec
    m = re.match(r"^\s*(\d+(?:\.\d+)?)\s*([kmgt]?)i?b?\s*$", str(spec), re.IGNORECASE)
    if not m:
        raise ValueError("无法解析大小: %r" % spec)
    mult = {"": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30, "t": 1 << 40}[m.group(2).lower()]
    return int(float(m.group(1)) * mult)

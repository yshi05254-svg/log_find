"""健壮的底层文件读取：编码探测、压缩文件透明读取、被占用重试、稳定读取、原子写入。"""
from __future__ import annotations

import bz2
import codecs
import gzip
import json
import lzma
import os
import re
import tempfile
import time
from typing import IO, Callable, List, Optional, Tuple

# 逐行解码时依次尝试的编码；gb18030 是 GBK/GB2312 的超集，覆盖 Windows 中文环境的输出
FALLBACK_ENCODINGS = ("utf-8", "gb18030")

_MAGIC = (
    (b"\x1f\x8b", gzip.open),
    (b"BZh", bz2.open),
    (b"\xfd7zXZ\x00", lzma.open),
)
_SUFFIX = {".gz": gzip.open, ".bz2": bz2.open, ".xz": lzma.open, ".lzma": lzma.open}

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][A-Z0-9]")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def _normalize(enc: str) -> str:
    return codecs.lookup(enc).name


def is_wide(encoding: str) -> bool:
    """utf-16/utf-32 不能按 b'\\n' 切分字节，需要先解码再切行。"""
    name = _normalize(encoding)
    return name.startswith("utf-16") or name.startswith("utf-32")


def detect_encoding(sample: bytes) -> str:
    """根据文件开头的字节猜测编码。"""
    if sample.startswith(codecs.BOM_UTF8):
        return "utf-8"
    if sample.startswith(codecs.BOM_UTF32_LE):
        return "utf-32-le"
    if sample.startswith(codecs.BOM_UTF32_BE):
        return "utf-32-be"
    if sample.startswith(codecs.BOM_UTF16_LE):
        return "utf-16-le"
    if sample.startswith(codecs.BOM_UTF16_BE):
        return "utf-16-be"
    if len(sample) >= 8:
        half = len(sample) // 2
        even_nul = sample[0::2].count(0)
        odd_nul = sample[1::2].count(0)
        if odd_nul > half * 0.4 and even_nul < half * 0.05:
            return "utf-16-le"
        if even_nul > half * 0.4 and odd_nul < half * 0.05:
            return "utf-16-be"
    for enc in FALLBACK_ENCODINGS:
        # 采样末尾可能截断了一个多字节字符，允许去掉最多 3 个尾字节
        for cut in range(4):
            chunk = sample[: len(sample) - cut] if cut else sample
            try:
                chunk.decode(enc)
                return enc
            except UnicodeDecodeError:
                continue
    return "latin-1"


def looks_binary(sample: bytes) -> bool:
    if not sample:
        return False
    if is_wide(detect_encoding(sample)):
        return False
    return b"\x00" in sample[:8192]


def decode_bytes(raw: bytes, preferred: str = "utf-8") -> str:
    """解码一行字节；首选编码失败时逐个回退，最后用替换字符兜底，永不抛异常。"""
    tried = []
    for enc in (preferred,) + FALLBACK_ENCODINGS:
        if enc in tried:
            continue
        tried.append(enc)
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")


class LineSplitter:
    """把任意切分的字节块还原成完整的文本行，保留未结束的半行。"""

    def __init__(self, encoding: Optional[str] = "auto"):
        self.encoding = None if encoding in (None, "", "auto") else _normalize(encoding)
        self._buf = b""
        self._tbuf = ""
        self._decoder = None
        self._ready = False

    def _setup(self, data: bytes) -> None:
        if self.encoding is None:
            self.encoding = detect_encoding(data[:65536])
        if is_wide(self.encoding):
            self._decoder = codecs.getincrementaldecoder(self.encoding)(errors="replace")
        self._ready = True

    @staticmethod
    def _clean(line: str) -> str:
        if line.endswith("\r"):
            line = line[:-1]
        return line.lstrip("﻿")

    def feed(self, data: bytes) -> List[str]:
        if not data:
            return []
        if not self._ready:
            self._setup(data)
        if self._decoder is not None:
            self._tbuf += self._decoder.decode(data)
            parts = self._tbuf.split("\n")
            self._tbuf = parts.pop()
            return [self._clean(p) for p in parts]
        self._buf += data
        parts = self._buf.split(b"\n")
        self._buf = parts.pop()
        return [self._clean(decode_bytes(p, self.encoding)) for p in parts]

    @property
    def pending(self) -> bool:
        return bool(self._buf or self._tbuf)

    def flush(self) -> Optional[str]:
        """取出未以换行结束的残留内容（程序崩溃前最后半行往往在这里）。"""
        if self._decoder is not None:
            self._tbuf += self._decoder.decode(b"", final=True)
            text, self._tbuf = self._tbuf, ""
        else:
            text = decode_bytes(self._buf, self.encoding or "utf-8") if self._buf else ""
            self._buf = b""
        return self._clean(text) if text else None

    def reset(self) -> None:
        self._buf = b""
        self._tbuf = ""
        if self._decoder is not None:
            self._decoder.reset()


def _retry(fn: Callable, retries: int = 8, delay: float = 0.05):
    """Windows 下文件被写入进程独占时会短暂 PermissionError，退避重试。"""
    last = None
    for i in range(retries):
        try:
            return fn()
        except FileNotFoundError:
            raise
        except (PermissionError, BlockingIOError, InterruptedError) as e:
            last = e
            time.sleep(delay * (2 ** min(i, 5)))
    raise last  # type: ignore[misc]


def open_any(path: str, retries: int = 8) -> IO[bytes]:
    """以二进制方式打开，自动识别 gz/bz2/xz（按后缀或文件头）。"""
    def _open():
        fh = open(path, "rb")
        try:
            head = fh.read(6)
        except Exception:
            fh.close()
            raise
        opener = _SUFFIX.get(os.path.splitext(path)[1].lower())
        if opener is None:
            for magic, op in _MAGIC:
                if head.startswith(magic):
                    opener = op
                    break
        if opener is None:
            fh.seek(0)
            return fh
        fh.close()
        return opener(path, "rb")
    return _retry(_open, retries)


def is_compressed(path: str) -> bool:
    if os.path.splitext(path)[1].lower() in _SUFFIX:
        return True
    try:
        with open(path, "rb") as fh:
            head = fh.read(6)
    except OSError:
        return False
    return any(head.startswith(m) for m, _ in _MAGIC)


def sniff_encoding(path: str, size: int = 65536) -> str:
    try:
        with open_any(path) as fh:
            return detect_encoding(fh.read(size))
    except (OSError, EOFError):
        return "utf-8"


def read_text(path: str, encoding: str = "auto") -> str:
    with open_any(path) as fh:
        data = fh.read()
    enc = detect_encoding(data[:65536]) if encoding in (None, "", "auto") else encoding
    if is_wide(enc):
        return data.decode(enc, errors="replace").lstrip("﻿")
    return "\n".join(decode_bytes(line, enc) for line in data.split(b"\n")).lstrip("﻿")


def _sig(path: str) -> Tuple[int, int]:
    st = os.stat(path)
    return st.st_size, st.st_mtime_ns


def json_validator(data: bytes) -> bool:
    try:
        json.loads(read_bytes_as_text(data))
        return True
    except ValueError:
        return False


def read_bytes_as_text(data: bytes) -> str:
    enc = detect_encoding(data[:65536])
    if is_wide(enc):
        return data.decode(enc, errors="replace").lstrip("﻿")
    return decode_bytes(data, enc).lstrip("﻿")


def default_validator(path: str) -> Optional[Callable[[bytes], bool]]:
    if path.lower().endswith(".json"):
        return json_validator
    return None


def read_stable(
    path: str,
    settle: float = 0.05,
    attempts: int = 40,
    quiet: float = 1.0,
    validator: Optional[Callable[[bytes], bool]] = None,
) -> Tuple[bytes, bool]:
    """读取一个可能正在被写入的文件。

    只有当 (大小, mtime) 连续两次一致、读到的长度与文件大小一致、并且 validator 通过时
    才认为读到的是完整内容。最近 `quiet` 秒内都没修改过的文件只需读一次。
    返回 (内容, 是否稳定)；多次尝试仍不稳定时返回最后一次读到的内容。
    """
    compressed = is_compressed(path)
    prev = None
    data = b""
    for _ in range(max(1, attempts)):
        try:
            before = _sig(path)
            with open_any(path) as fh:
                data = fh.read()
            after = _sig(path)
        except FileNotFoundError:
            raise
        except (OSError, EOFError):
            # 压缩文件写了一半会 EOFError
            time.sleep(settle)
            prev = None
            continue
        consistent = before == after and (compressed or before[0] == len(data))
        valid = consistent and (validator is None or validator(data))
        if valid:
            idle = time.time() - after[1] / 1e9
            if after == prev or idle >= quiet:
                return data, True
        prev = after if consistent else None
        time.sleep(settle)
    return data, False


def atomic_write(path: str, data: bytes) -> None:
    """先写临时文件再 rename，读者永远不会看到写了一半的文件。"""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        _retry(lambda: os.replace(tmp, path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

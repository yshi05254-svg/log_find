"""快照：稳定地拷贝文件（不会读到写了一半的内容）、保存 Python 对象、对比差异、监视变化自动留档。"""
from __future__ import annotations

import difflib
import glob
import hashlib
import json
import math
import os
import pickle
import re
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from .textio import (atomic_write, default_validator, is_access_denied, is_source_unavailable,
                     looks_binary, read_bytes_as_text, read_stable)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _slug(text: str) -> str:
    return re.sub(r"[^\w.-]+", "_", text, flags=re.UNICODE).strip("_")[:40]


def _rel_for(path: str) -> str:
    ap = os.path.abspath(path)
    try:
        rel = os.path.relpath(ap, os.getcwd())
    except ValueError:  # Windows 下不同盘符
        rel = ".." + os.sep
    if rel.startswith(".."):
        drive, tail = os.path.splitdrive(ap)
        rel = os.path.join("_abs", drive.replace(":", ""), tail.lstrip("/\\"))
    return rel.replace("\\", "/")


def expand_inputs(patterns: Iterable[str]) -> List[str]:
    out, seen = [], set()
    for pat in patterns:
        pat = os.path.expanduser(pat)
        if glob.has_magic(pat):
            cands = sorted(glob.glob(pat, recursive=True))
        else:
            cands = [pat]
        for c in cands:
            if os.path.isdir(c):
                for root, dirs, files in os.walk(c):
                    dirs[:] = sorted(d for d in dirs if not d.startswith(".logfind"))
                    for f in sorted(files):
                        p = os.path.join(root, f)
                        if os.path.abspath(p) not in seen:
                            seen.add(os.path.abspath(p))
                            out.append(p)
            elif os.path.isfile(c) and os.path.abspath(c) not in seen:
                seen.add(os.path.abspath(c))
                out.append(c)
    return out


@dataclass
class Snapshot:
    directory: str
    manifest: Dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return os.path.basename(self.directory)

    @property
    def label(self) -> str:
        return self.manifest.get("label", "")

    @property
    def files(self) -> Dict[str, Dict[str, Any]]:
        return self.manifest.get("files", {})

    def path_of(self, rel: str) -> str:
        return os.path.join(self.directory, "files", rel)

    def read(self, rel: str) -> bytes:
        with open(self.path_of(rel), "rb") as fh:
            return fh.read()

    def find(self, name: str) -> Optional[str]:
        if name in self.files:
            return name
        norm = name.replace("\\", "/")
        cands = [r for r in self.files if r.endswith("/" + norm) or r == norm
                 or os.path.basename(r) == os.path.basename(norm)]
        return cands[0] if len(cands) == 1 else (norm if norm in self.files else None)


class SnapshotStore:
    def __init__(self, root: str):
        self.root = root

    # ---- 创建 ----
    def _new_dir(self, label: str) -> str:
        os.makedirs(self.root, exist_ok=True)
        now = datetime.now()
        base = now.strftime("%Y%m%d-%H%M%S-") + "%03d" % (now.microsecond // 1000)
        if label:
            base += "_" + _slug(label)
        path = os.path.join(self.root, base)
        n = 1
        while os.path.exists(path):
            n += 1
            path = os.path.join(self.root, "%s-%d" % (base, n))
        os.makedirs(os.path.join(path, "files"))
        return path

    def _store_file(self, snap_dir: str, rel: str, data: bytes, sha: str,
                    prev: Optional[Snapshot]) -> None:
        dest = os.path.join(snap_dir, "files", rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        # 内容和上一个快照相同则硬链接，长期 watch 也不会占用大量磁盘
        if prev is not None and prev.files.get(rel, {}).get("sha256") == sha:
            try:
                os.link(prev.path_of(rel), dest)
                return
            except OSError:
                pass
        with open(dest, "wb") as fh:
            fh.write(data)

    def take(self, patterns: Iterable[str], label: str = "", note: str = "",
             settle: float = 0.05, attempts: int = 40,
             validator: Optional[Callable[[str], Optional[Callable[[bytes], bool]]]] = None) -> Snapshot:
        paths = expand_inputs(patterns)
        prev = self.latest(label) if label else self.latest()
        snap_dir = self._new_dir(label)
        files: Dict[str, Dict[str, Any]] = {}
        errors = []
        dead_devs: Dict[int, str] = {}  # 已确认整体不可用的设备 -> 首个错误
        for p in paths:
            rel = _rel_for(p)
            st = None
            try:
                st = os.stat(p)
                if st.st_dev in dead_devs:
                    errors.append({"src": os.path.abspath(p), "rel": rel, "kind": "unavailable",
                                   "error": "所在设备不可用，已跳过（%s）" % dead_devs[st.st_dev]})
                    continue
                data, stable = read_stable(p, settle=settle, attempts=attempts,
                                           validator=(validator or default_validator)(p))
            except OSError as e:
                kind = _error_kind(e)
                if kind == "unavailable" and st is not None:
                    dead_devs[st.st_dev] = str(e)
                errors.append({"src": os.path.abspath(p), "rel": rel, "kind": kind, "error": str(e)})
                continue
            sha = _sha(data)
            self._store_file(snap_dir, rel, data, sha, prev)
            files[rel] = {"src": os.path.abspath(p), "size": len(data), "sha256": sha,
                          "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="milliseconds"),
                          "stable": stable}
        coverage = {"total": len(paths), "read": len(files)}
        for e in errors:
            coverage[e["kind"]] = coverage.get(e["kind"], 0) + 1
        manifest = {"label": label, "note": note, "created": datetime.now().isoformat(timespec="milliseconds"),
                    "patterns": list(patterns), "files": files, "errors": errors,
                    "coverage": coverage, "cwd": os.getcwd()}
        atomic_write(os.path.join(snap_dir, "manifest.json"),
                     json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"))
        return Snapshot(snap_dir, manifest)

    def save_object(self, obj: Any, label: str = "", name: str = "object", note: str = "") -> Snapshot:
        """把内存中的对象存成快照：JSON 可序列化的存 .json，numpy 数组存 .npy，其余 pickle + repr。"""
        prev = self.latest(label) if label else self.latest()
        snap_dir = self._new_dir(label)
        blobs: List[Tuple[str, bytes]] = []
        np = _numpy()
        if np is not None and isinstance(obj, np.ndarray):
            import io
            buf = io.BytesIO()
            np.save(buf, obj, allow_pickle=False)
            blobs.append((name + ".npy", buf.getvalue()))
        else:
            try:
                blobs.append((name + ".json", json.dumps(obj, ensure_ascii=False, indent=2,
                                                        default=_json_default).encode("utf-8")))
            except (TypeError, ValueError):
                blobs.append((name + ".pkl", pickle.dumps(obj)))
                blobs.append((name + ".repr.txt", repr(obj).encode("utf-8", errors="replace")))
        files = {}
        for rel, data in blobs:
            sha = _sha(data)
            self._store_file(snap_dir, rel, data, sha, prev)
            files[rel] = {"src": None, "size": len(data), "sha256": sha, "stable": True}
        manifest = {"label": label, "note": note, "created": datetime.now().isoformat(timespec="milliseconds"),
                    "object": True, "type": type(obj).__name__, "files": files, "errors": []}
        atomic_write(os.path.join(snap_dir, "manifest.json"),
                     json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"))
        return Snapshot(snap_dir, manifest)

    # ---- 查询 ----
    def list(self, label: Optional[str] = None) -> List[Snapshot]:
        if not os.path.isdir(self.root):
            return []
        out = []
        for n in sorted(os.listdir(self.root)):
            mpath = os.path.join(self.root, n, "manifest.json")
            if not os.path.isfile(mpath):
                continue  # 正在写入或被中断的快照
            try:
                with open(mpath, encoding="utf-8") as fh:
                    m = json.load(fh)
            except (OSError, ValueError):
                continue
            if label is None or m.get("label") == label:
                out.append(Snapshot(os.path.join(self.root, n), m))
        return out

    def latest(self, label: Optional[str] = None) -> Optional[Snapshot]:
        snaps = self.list(label)
        return snaps[-1] if snaps else None

    def resolve(self, ref: str, label: Optional[str] = None) -> Snapshot:
        snaps = self.list(label)
        if not snaps:
            raise LookupError("没有快照" + ("（标签 %s）" % label if label else ""))
        if ref in ("latest", "last", ""):
            return snaps[-1]
        if ref == "prev":
            ref = "-2"
        if re.match(r"^-\d+$", ref):
            idx = int(ref)
            if -len(snaps) <= idx:
                return snaps[idx]
            raise LookupError("只有 %d 个快照" % len(snaps))
        if re.match(r"^\d+$", ref) and int(ref) < len(snaps) and len(ref) < 6:
            return snaps[int(ref)]
        m = [s for s in snaps if s.id.startswith(ref)] or [s for s in snaps if ref in s.id]
        if not m:
            raise LookupError("找不到快照: %s" % ref)
        return m[-1]

    def prune(self, keep: int, label: Optional[str] = None) -> List[str]:
        snaps = self.list(label)
        removed = []
        for s in snaps[:-keep] if keep > 0 else snaps:
            shutil.rmtree(s.directory, ignore_errors=True)
            removed.append(s.id)
        return removed

    # ---- 监视 ----
    def watch(self, patterns: List[str], interval: float = 1.0, label: str = "watch",
              keep: int = 0, on_snapshot: Optional[Callable[[Snapshot, List[str]], None]] = None,
              should_stop: Optional[Callable[[], bool]] = None, debounce: float = 0.3) -> None:
        """文件内容变化时自动拍快照；同一次写入过程只拍一张（debounce）。"""
        last: Dict[str, Tuple[int, int]] = {}
        first = True
        while not (should_stop and should_stop()):
            cur = {}
            for p in expand_inputs(patterns):
                try:
                    st = os.stat(p)
                    cur[os.path.abspath(p)] = (st.st_size, st.st_mtime_ns)
                except OSError:
                    pass
            if cur != last:
                if not first:
                    time.sleep(debounce)
                changed = sorted(set(k for k in set(cur) | set(last) if cur.get(k) != last.get(k)))
                snap = self.take(patterns, label=label, note="watch: %d 个文件变化" % len(changed))
                if on_snapshot:
                    on_snapshot(snap, changed if not first else [])
                if keep > 0:
                    self.prune(keep, label)
                # 用拍摄后的状态作为基准，避免 debounce 期间的写入重复触发
                last = {}
                for p in expand_inputs(patterns):
                    try:
                        st = os.stat(p)
                        last[os.path.abspath(p)] = (st.st_size, st.st_mtime_ns)
                    except OSError:
                        pass
                first = False
            time.sleep(interval)


def _error_kind(e: OSError) -> str:
    if is_access_denied(e):
        return "denied"
    if is_source_unavailable(e):
        return "unavailable"
    return "failed"


def _numpy():
    try:
        import numpy  # noqa
        return numpy
    except Exception:
        return None


def _json_default(o):
    np = _numpy()
    if np is not None:
        if isinstance(o, np.ndarray):
            return o.tolist()
        if isinstance(o, np.generic):
            return o.item()
    if isinstance(o, (set, frozenset, tuple)):
        return list(o)
    if isinstance(o, bytes):
        return o.decode("utf-8", errors="replace")
    if hasattr(o, "__dict__"):
        return {"__type__": type(o).__name__, **{k: v for k, v in vars(o).items() if not k.startswith("_")}}
    raise TypeError("not serializable")


# ================= 差异对比 =================

@dataclass
class FileDiff:
    rel: str
    status: str  # added / removed / changed / same / unreadable
    details: List[str] = field(default_factory=list)


def _unread_map(snap: Snapshot) -> Dict[str, str]:
    """快照拍摄时读取失败的文件：rel -> 错误信息。"""
    return {e["rel"]: e.get("error", "") for e in snap.manifest.get("errors", []) if e.get("rel")}


def _is_num(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _num_equal(a, b, tol: float) -> bool:
    if isinstance(a, float) and isinstance(b, float) and math.isnan(a) and math.isnan(b):
        return True
    if tol > 0:
        return abs(a - b) <= tol * max(1.0, abs(a), abs(b))
    return a == b


def json_diff(a: Any, b: Any, tol: float = 0.0, path: str = "$", out: Optional[List[str]] = None,
              limit: int = 200) -> List[str]:
    """结构化 JSON 对比；长数值数组（向量）给出汇总而不是逐元素刷屏。"""
    out = [] if out is None else out
    if len(out) >= limit:
        return out
    if _is_num(a) and _is_num(b):
        if not _num_equal(a, b, tol):
            out.append("%s: %r -> %r" % (path, a, b))
        return out
    if type(a) != type(b):
        out.append("%s: 类型 %s -> %s (%s -> %s)" % (path, type(a).__name__, type(b).__name__,
                                                   _short(a), _short(b)))
        return out
    if isinstance(a, dict):
        for k in a:
            if k not in b:
                out.append("%s.%s: 被删除 (原值 %s)" % (path, k, _short(a[k])))
        for k in b:
            if k not in a:
                out.append("%s.%s: 新增 = %s" % (path, k, _short(b[k])))
        for k in a:
            if k in b:
                json_diff(a[k], b[k], tol, "%s.%s" % (path, k), out, limit)
        return out
    if isinstance(a, list):
        if a and b and all(_is_num(x) for x in a) and all(_is_num(x) for x in b) and \
                (len(a) > 16 or len(b) > 16):
            out.extend(_vector_summary(path, a, b, tol))
            return out
        if len(a) != len(b):
            out.append("%s: 长度 %d -> %d" % (path, len(a), len(b)))
        for i in range(min(len(a), len(b))):
            json_diff(a[i], b[i], tol, "%s[%d]" % (path, i), out, limit)
        return out
    if a != b:
        out.append("%s: %s -> %s" % (path, _short(a), _short(b)))
    return out


def _vector_summary(path: str, a: list, b: list, tol: float) -> List[str]:
    out = []
    if len(a) != len(b):
        out.append("%s: 向量长度 %d -> %d" % (path, len(a), len(b)))
    n = min(len(a), len(b))
    diffs = [(i, a[i], b[i]) for i in range(n) if not _num_equal(a[i], b[i], tol)]
    if diffs:
        def _absd(x, y):
            try:
                return abs(float(x) - float(y))
            except (OverflowError, ValueError):
                return float("inf")
        max_i, max_a, max_b = max(diffs, key=lambda t: _absd(t[1], t[2]))
        nan_a = sum(1 for x in b if isinstance(x, float) and math.isnan(x))
        out.append("%s: %d/%d 个元素不同, 最大差 %.6g @[%d] (%r -> %r)%s" % (
            path, len(diffs), n, _absd(max_a, max_b), max_i, max_a, max_b,
            ", 新值含 %d 个 NaN" % nan_a if nan_a else ""))
        shown = ", ".join("[%d] %r->%r" % d for d in diffs[:5])
        out.append("%s: 前几处: %s%s" % (path, shown, " ..." if len(diffs) > 5 else ""))
    return out


def _short(v: Any, n: int = 80) -> str:
    s = json.dumps(v, ensure_ascii=False, default=str) if not isinstance(v, str) else repr(v)
    return s if len(s) <= n else s[: n - 3] + "..."


def _npy_diff(da: bytes, db: bytes, tol: float) -> Optional[List[str]]:
    np = _numpy()
    if np is None:
        return None
    import io
    try:
        a = np.load(io.BytesIO(da), allow_pickle=False)
        b = np.load(io.BytesIO(db), allow_pickle=False)
    except Exception:
        return None
    out = []
    if a.shape != b.shape:
        return ["shape %s -> %s" % (a.shape, b.shape), "dtype %s -> %s" % (a.dtype, b.dtype)]
    if a.dtype != b.dtype:
        out.append("dtype %s -> %s" % (a.dtype, b.dtype))
    if a.dtype.kind in "fciub" and b.dtype.kind in "fciub":
        fa, fb = a.astype("float64"), b.astype("float64")
        close = np.isclose(fa, fb, rtol=tol, atol=tol, equal_nan=True) if tol > 0 else \
            ((fa == fb) | (np.isnan(fa) & np.isnan(fb)))
        n_diff = int((~close).sum())
        if n_diff:
            d = np.abs(fa - fb)
            d[np.isnan(d)] = np.inf
            idx = np.unravel_index(int(np.argmax(d)), d.shape)
            out.append("%d/%d 个元素不同, 最大差 %.6g @%s" % (n_diff, fa.size, float(d[idx]), tuple(int(i) for i in idx)))
            out.append("新数组: NaN=%d Inf=%d min=%.6g max=%.6g mean=%.6g" % (
                int(np.isnan(fb).sum()), int(np.isinf(fb).sum()),
                float(np.nanmin(fb)) if fb.size else 0, float(np.nanmax(fb)) if fb.size else 0,
                float(np.nanmean(fb)) if fb.size else 0))
    elif not np.array_equal(a, b):
        out.append("数组内容不同")
    return out


def diff_bytes(rel: str, da: bytes, db: bytes, tol: float = 0.0, context: int = 3,
               max_lines: int = 400, names: Tuple[str, str] = ("a", "b")) -> List[str]:
    low = rel.lower()
    if low.endswith(".npy"):
        r = _npy_diff(da, db, tol)
        if r is not None:
            return r
    if low.endswith((".json", ".jsonl")) or low.endswith(".json.txt"):
        try:
            if low.endswith(".jsonl"):
                ja = [json.loads(x) for x in read_bytes_as_text(da).splitlines() if x.strip()]
                jb = [json.loads(x) for x in read_bytes_as_text(db).splitlines() if x.strip()]
            else:
                ja, jb = json.loads(read_bytes_as_text(da)), json.loads(read_bytes_as_text(db))
            res = json_diff(ja, jb, tol)
            return res or ["(JSON 语义相同，仅格式/空白不同%s)" % ("，或差异在容差内" if tol else "")]
        except ValueError as e:
            prefix = ["(JSON 解析失败: %s，按文本对比)" % e]
        else:
            prefix = []
    else:
        prefix = []
    if looks_binary(da[:8192]) or looks_binary(db[:8192]):
        n = min(len(da), len(db))
        first = next((i for i in range(n) if da[i] != db[i]), n)
        return prefix + ["二进制文件: 大小 %d -> %d，首个不同字节偏移 %d" % (len(da), len(db), first)]
    ta = read_bytes_as_text(da).splitlines()
    tb = read_bytes_as_text(db).splitlines()
    lines = list(difflib.unified_diff(ta, tb, names[0], names[1], n=context, lineterm=""))
    if len(lines) > max_lines:
        lines = lines[:max_lines] + ["... (还有 %d 行差异未显示)" % (len(lines) - max_lines)]
    return prefix + (lines or ["(仅换行符/编码不同)"])


def diff_snapshots(a: Snapshot, b: Optional[Snapshot], tol: float = 0.0, context: int = 3,
                   only: Optional[List[str]] = None) -> List[FileDiff]:
    """对比两个快照；b 为 None 时与磁盘上的当前文件（live）对比。"""
    result: List[FileDiff] = []
    a_err = _unread_map(a)
    if b is None:
        b_files = {}
        for rel, info in a.files.items():
            src = info.get("src")
            if src and os.path.isfile(src):
                b_files[rel] = src
        get_b = lambda rel: read_stable(b_files[rel], validator=default_validator(rel))[0]  # noqa: E731
        b_keys = set(b_files)
        b_name = "live"
        b_err: Dict[str, str] = {}
    else:
        get_b = b.read
        b_keys = set(b.files)
        b_name = b.id
        b_err = _unread_map(b)
    keys = sorted(set(a.files) | b_keys)
    if only:
        keys = [k for k in keys if any(o.replace("\\", "/") in k for o in only)]
    for rel in keys:
        # 某一侧拍摄时没读到（权限被拒、设备不可用），不能当成新增/删除
        if rel not in b_keys:
            if rel in b_err:
                result.append(FileDiff(rel, "unreadable", ["%s 中未能读取: %s" % (b_name, b_err[rel])]))
            else:
                result.append(FileDiff(rel, "removed"))
            continue
        if rel not in a.files:
            if rel in a_err:
                result.append(FileDiff(rel, "unreadable", ["%s 中未能读取: %s" % (a.id, a_err[rel])]))
            else:
                result.append(FileDiff(rel, "added"))
            continue
        da = a.read(rel)
        try:
            db = get_b(rel)
        except OSError as e:
            result.append(FileDiff(rel, "unreadable", ["%s 中未能读取: %s" % (b_name, e)]))
            continue
        if b is not None and a.files[rel].get("sha256") == b.files[rel].get("sha256"):
            result.append(FileDiff(rel, "same"))
            continue
        if da == db:
            result.append(FileDiff(rel, "same"))
            continue
        details = diff_bytes(rel, da, db, tol, context, names=("%s/%s" % (a.id, rel), "%s/%s" % (b_name, rel)))
        status = "same" if tol and details and details[0].startswith("(JSON 语义相同") else "changed"
        result.append(FileDiff(rel, status, details))
    return result

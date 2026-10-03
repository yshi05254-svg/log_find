import gzip
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from contextlib import redirect_stdout
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from logfind import textio  # noqa: E402
from logfind.archive import Session, TriggerRecorder, parse_archive_line, resolve_session  # noqa: E402
from logfind.cli import main as cli_main  # noqa: E402
from logfind.follow import Follower  # noqa: E402
from logfind.parsing import parse_level, parse_time_spec, parse_timestamp  # noqa: E402
from logfind.runner import run_command  # noqa: E402
from logfind.search import Filters, Matcher, expand_paths, iter_records, search  # noqa: E402
from logfind.snapshot import SnapshotStore, diff_snapshots, json_diff  # noqa: E402


class TmpDir(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="logfind-test-")
        self.home = os.path.join(self.tmp, ".logfind")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def p(self, *parts):
        return os.path.join(self.tmp, *parts)

    def write(self, name, data, mode="w", **kw):
        path = self.p(name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, mode, **kw) as fh:
            fh.write(data)
        return path


class TextIOTests(TmpDir):
    def test_detect_encodings(self):
        self.assertEqual(textio.detect_encoding("你好 world".encode("utf-8")), "utf-8")
        self.assertEqual(textio.detect_encoding("错误：向量维度不匹配".encode("gbk")), "gb18030")
        self.assertEqual(textio.detect_encoding("﻿hello".encode("utf-16-le")), "utf-16-le")
        self.assertEqual(textio.detect_encoding("hello world".encode("utf-16-le")), "utf-16-le")
        # 采样在多字节字符中间被截断
        self.assertEqual(textio.detect_encoding("你好".encode("utf-8")[:-1]), "utf-8")

    def test_splitter_partial_and_mixed(self):
        sp = textio.LineSplitter("utf-8")
        data = "第一行\r\n第二".encode("utf-8")
        self.assertEqual(sp.feed(data[:4]), [])
        self.assertEqual(sp.feed(data[4:]), ["第一行"])
        self.assertEqual(sp.feed("行\n".encode("utf-8") + "中文GBK\n".encode("gbk")), ["第二行", "中文GBK"])
        self.assertEqual(sp.feed(b"tail"), [])
        self.assertEqual(sp.flush(), "tail")

    def test_splitter_utf16(self):
        sp = textio.LineSplitter("auto")
        data = "﻿a\nb行\nc".encode("utf-16-le")
        out = []
        for i in range(0, len(data), 3):
            out += sp.feed(data[i:i + 3])
        self.assertEqual(out, ["a", "b行"])
        self.assertEqual(sp.flush(), "c")

    def test_open_any_gzip_without_suffix(self):
        path = self.p("app.log.1")
        with gzip.open(path, "wb") as fh:
            fh.write(b"zipped line\n")
        with textio.open_any(path) as fh:
            self.assertEqual(fh.read(), b"zipped line\n")

    def test_read_stable_waits_for_valid_json(self):
        path = self.write("state.json", '{"a": [1, 2')

        def finish():
            time.sleep(0.3)
            with open(path, "w") as fh:
                fh.write('{"a": [1, 2, 3]}')
        t = threading.Thread(target=finish)
        t.start()
        data, stable = textio.read_stable(path, settle=0.05, attempts=40,
                                          validator=textio.default_validator(path))
        t.join()
        self.assertTrue(stable)
        self.assertEqual(json.loads(data), {"a": [1, 2, 3]})

    def test_atomic_write(self):
        path = self.p("sub", "x.bin")
        textio.atomic_write(path, b"abc")
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), b"abc")
        self.assertEqual([n for n in os.listdir(self.p("sub")) if n.startswith(".tmp")], [])


class ParsingTests(unittest.TestCase):
    def test_timestamps(self):
        ref = datetime(2026, 10, 2, 12, 0, 0)
        self.assertEqual(parse_timestamp("2026-10-02 20:22:01,123 INFO x"), datetime(2026, 10, 2, 20, 22, 1, 123000))
        self.assertEqual(parse_timestamp("[2026/10/02T20:22:01.5] x"), datetime(2026, 10, 2, 20, 22, 1, 500000))
        self.assertEqual(parse_timestamp("10-01 08:00:00.001  12  34 E Tag: x", ref), datetime(2026, 10, 1, 8, 0, 0, 1000))
        self.assertEqual(parse_timestamp("E1001 08:00:00.000100 12 a.cc:3] boom", ref), datetime(2026, 10, 1, 8, 0, 0, 100))
        self.assertEqual(parse_timestamp("Oct  2 20:22:01 host x", ref), datetime(2026, 10, 2, 20, 22, 1))
        self.assertEqual(parse_timestamp("[20:22:01] x", ref), datetime(2026, 10, 2, 20, 22, 1))
        self.assertIsNone(parse_timestamp("    at foo.bar(Baz.java:3)"))
        self.assertIsNone(parse_timestamp("value 2026-10-02 20:22:01" .rjust(80)))

    def test_levels(self):
        self.assertEqual(parse_level("2026-10-02 20:22:01 ERROR boom"), 40)
        self.assertEqual(parse_level("[warning] careful"), 30)
        self.assertEqual(parse_level("E1001 08:00:00.000100 12 a.cc:3] boom"), 40)
        self.assertEqual(parse_level("10-01 08:00:00.001  12  34 W Tag: x"), 30)
        self.assertEqual(parse_level("I/Mask( 123): hi"), 20)
        # logcat -v time：级别字母在时间之后，正文里的 Error 不能把 I 级别误判成 ERROR
        self.assertEqual(parse_level("10-01 08:00:00.001 E/Zygote( 123): boom"), 40)
        self.assertEqual(parse_level("10-01 08:00:00.001 I/Zygote( 123): Error-free"), 20)
        self.assertIsNone(parse_level("plain text"))

    def test_time_spec(self):
        now = datetime(2026, 10, 2, 12, 0, 0)
        self.assertEqual(parse_time_spec("30m", now), datetime(2026, 10, 2, 11, 30))
        self.assertEqual(parse_time_spec("14:30", now), datetime(2026, 10, 2, 14, 30))
        self.assertEqual(parse_time_spec("2026-10-01", now), datetime(2026, 10, 1))
        self.assertEqual(parse_time_spec("2026-10-01 08:00:00", now), datetime(2026, 10, 1, 8))


class FollowTests(TmpDir):
    def collect(self, fol, rounds=3):
        out = []
        for _ in range(rounds):
            out += fol.poll()
        return out

    def lines(self, events):
        return [e.text for e in events if e.kind in ("line", "partial")]

    def test_rotation_by_rename_keeps_tail_of_old_file(self):
        for keep_open in (True, False):
            with self.subTest(keep_open=keep_open):
                path = self.write("r%d/app.log" % keep_open, "old-1\n")
                fol = Follower([path], tail_lines=10, keep_open=keep_open, rescan_interval=0)
                self.assertEqual(self.lines(fol.poll()), ["old-1"])
                with open(path, "a") as fh:
                    fh.write("old-2\n")
                os.rename(path, path + ".1")  # 滚动前最后写入的行还没被读
                with open(path, "w") as fh:
                    fh.write("new-1\n")
                ev = self.collect(fol)
                self.assertEqual(self.lines(ev), ["old-2", "new-1"])
                self.assertIn("rotated", [e.kind for e in ev])
                fol.close()

    def test_truncate_and_partial_line(self):
        path = self.write("app.log", "a\nb\n")
        fol = Follower([path], from_start=True, partial_timeout=0.1)
        self.assertEqual(self.lines(fol.poll()), ["a", "b"])
        with open(path, "w") as fh:
            fh.write("c\n")
        ev = fol.poll()
        self.assertIn("truncated", [e.kind for e in ev])
        self.assertEqual(self.lines(ev), ["c"])
        with open(path, "a") as fh:
            fh.write("half")
        self.assertEqual(self.lines(fol.poll()), [])
        time.sleep(0.15)
        self.assertEqual(self.lines(fol.poll()), ["half"])
        # 清空后立刻写入比原来更多的内容（大小没有变小）也要识别为截断
        time.sleep(0.01)
        with open(path, "w") as fh:
            fh.write("xyz-much-longer-content\n")
        ev = fol.poll()
        self.assertIn("truncated", [e.kind for e in ev])
        self.assertEqual(self.lines(ev), ["xyz-much-longer-content"])
        fol.close()

    def test_missing_file_and_glob_new_files(self):
        later = self.p("logs", "later.log")
        fol = Follower([later, self.p("logs", "*.txt")], rescan_interval=0)
        self.assertEqual(fol.poll(), [])
        self.write("logs/later.log", "hello\n")
        self.write("logs/x.txt", "glob\n")
        self.assertEqual(sorted(self.lines(self.collect(fol))), ["glob", "hello"])
        fol.close()

    def test_fast_double_rotation_is_recovered(self):
        path = self.p("fast", "app.log")
        os.makedirs(self.p("fast"))
        fol = Follower([self.p("fast", "*.log")], rescan_interval=0)
        for gen in range(3):
            with open(path, "a") as fh:
                fh.write("gen %d\n" % gen)
            if gen < 2:
                os.rename(path, path + ".%d" % (gen + 1))  # 在任何轮询之前连续滚动
        ev = self.collect(fol)
        self.assertEqual(self.lines(ev), ["gen 0", "gen 1", "gen 2"])
        with open(path, "a") as fh:
            fh.write("gen 2b\n")
        os.rename(path, path + ".9")
        with open(path, "w") as fh:
            fh.write("gen 3\n")
        self.assertEqual(self.lines(self.collect(fol)), ["gen 2b", "gen 3"])
        fol.close()

    def test_gbk_file(self):
        path = self.write("gbk.log", "启动\n".encode("gbk"), mode="wb")
        fol = Follower([path], from_start=True)
        self.assertEqual(self.lines(fol.poll()), ["启动"])
        fol.close()


class SearchTests(TmpDir):
    LOG = textwrap.dedent("""\
        2026-10-02 10:00:00 INFO start mask
        2026-10-02 10:00:01 DEBUG step 1
        2026-10-02 10:00:02 ERROR failed to load
        Traceback (most recent call last):
          File "a.py", line 1, in <module>
        ValueError: dimension mismatch 128 != 256
        2026-10-02 10:05:00 WARN slow
        2026-10-02 11:00:00 INFO done
        """)

    def test_multiline_record_and_filters(self):
        path = self.write("app.log", self.LOG)
        recs = list(iter_records(path))
        self.assertEqual(len(recs), 5)
        self.assertEqual(len(recs[2].lines), 4)
        hits = list(search([path], Matcher(["dimension"])))
        self.assertEqual(len(hits), 1)
        self.assertIn("ERROR failed", hits[0].record.text)
        hits = list(search([path], Matcher([]), Filters(min_level=30)))
        self.assertEqual([h.record.lineno for h in hits], [3, 7])
        f = Filters(since=datetime(2026, 10, 2, 10, 4), until=datetime(2026, 10, 2, 10, 30))
        self.assertEqual([h.record.lineno for h in search([path], Matcher([]), f)], [7])

    def test_context(self):
        path = self.write("app.log", self.LOG)
        hits = list(search([path], Matcher(["WARN"]), before=1, after=1))
        self.assertEqual([(h.record.lineno, h.is_match) for h in hits], [(3, False), (7, True), (8, False)])

    def test_rotated_and_compressed(self):
        path = self.write("svc.log", "2026-10-02 12:00:00 ERROR current\n")
        with gzip.open(self.p("svc.log.2.gz"), "wt") as fh:
            fh.write("2026-10-01 12:00:00 ERROR oldest\n")
        self.write("svc.log.1", "2026-10-02 08:00:00 ERROR older\n")
        os.utime(self.p("svc.log.2.gz"), (1, 1))
        os.utime(self.p("svc.log.1"), (2, 2))
        files = expand_paths([path], rotated=True)
        texts = [h.record.text for h in search(files, Matcher(["ERROR"]))]
        self.assertEqual([t.split()[-1] for t in texts], ["oldest", "older", "current"])

    def test_plain_log_indented_continuation(self):
        path = self.write("plain.log", "error: boom\n  detail 1\nnext\n")
        recs = list(iter_records(path))
        self.assertEqual([r.lines for r in recs], [["error: boom", "  detail 1"], ["next"]])


class ArchiveTests(TmpDir):
    def test_session_and_segments(self):
        s = Session.create(self.home, "unit", max_segment_bytes=200, max_total_bytes=10000)
        for i in range(30):
            s.archive.write("stdout", "line %d" % i)
        s.archive.write("stderr", "multi\nline")
        s.close()
        self.assertGreater(len(s.segments()), 1)
        lines = list(s.iter_lines())
        self.assertEqual(len(lines), 32)
        self.assertEqual(parse_archive_line(lines[-1])[1:], ("stderr", "line"))
        self.assertEqual(resolve_session(self.home, "latest").id, s.id)

    def test_total_cap_drops_oldest(self):
        s = Session.create(self.home, "cap", max_segment_bytes=100, max_total_bytes=400)
        for i in range(100):
            s.archive.write("x", "line %03d" % i)
        s.close()
        self.assertLessEqual(sum(os.path.getsize(x) for x in s.segments()), 600)
        self.assertGreater(s.archive.dropped_segments, 0)

    def test_trigger_context(self):
        out = self.p("hits")
        rec = TriggerRecorder(["ERROR"], out, before=3, after=2)
        for i in range(10):
            rec.feed("s", "line %d" % i)
        rec.feed("s", "ERROR here")
        rec.feed("s", "after 1")
        rec.feed("s", "ERROR again")  # 在 after 窗口内再次命中：合并、延长
        for i in range(5):
            rec.feed("s", "tail %d" % i)
        rec.flush()
        self.assertEqual(len(rec.files), 1)
        with open(rec.files[0], encoding="utf-8") as fh:
            body = fh.read()
        for want in ("line 7", "line 9", ">> ", "ERROR again", "tail 1"):
            self.assertIn(want, body)
        self.assertNotIn("line 6", body)
        self.assertNotIn("tail 2", body)


class RunnerTests(TmpDir):
    def run_py(self, code, **kw):
        s = Session.create(self.home, "t")
        rc = run_command([sys.executable, "-c", code], s, echo=False, **kw)
        return rc, s

    def test_captures_both_streams_and_crash(self):
        code = textwrap.dedent("""\
            import sys, os
            print("hello stdout")
            sys.stdout.write("no newline before crash")
            print("to stderr", file=sys.stderr)
            os.abort() if hasattr(os, "abort") else sys.exit(3)
            """)
        rc, s = self.run_py(code, triggers=["stderr"])
        lines = [parse_archive_line(l) for l in s.iter_lines()]
        texts = [(src, txt) for _, src, txt in lines]
        self.assertIn(("stdout", "hello stdout"), texts)
        self.assertIn(("stdout", "no newline before crash"), texts)
        self.assertIn(("stderr", "to stderr"), texts)
        self.assertNotEqual(rc, 0)
        meta = s.read_meta()
        self.assertEqual(meta["returncode"], rc)
        if os.name != "nt":
            self.assertIn("SIGABRT", meta["exit"])
        self.assertEqual(len(s.hit_files()), 1)

    def test_unbuffered_python_output_survives_hard_kill(self):
        # 不设置 PYTHONUNBUFFERED 时，管道下 print 的内容在 os._exit 时会丢失
        code = "import os\nprint('must not be lost')\nos._exit(1)"
        rc, s = self.run_py(code)
        self.assertIn("[stdout] must not be lost", "\n".join(s.iter_lines()))
        saved = os.environ.pop("PYTHONUNBUFFERED", None)
        try:
            rc2, s2 = self.run_py(code, unbuffer=False)
        finally:
            if saved is not None:
                os.environ["PYTHONUNBUFFERED"] = saved
        self.assertNotIn("[stdout] must not be lost", "\n".join(s2.iter_lines()))

    def test_gbk_output(self):
        code = "import sys\nsys.stdout.buffer.write('中文输出\\n'.encode('gbk'))"
        rc, s = self.run_py(code)
        self.assertIn("中文输出", "\n".join(s.iter_lines()))


class InprocTests(TmpDir):
    def test_capture_subprocess_isolated(self):
        # fd 重定向会影响整个进程，放在子进程中测试
        script = textwrap.dedent("""\
            import logging, os, sys, ctypes, ctypes.util
            sys.path.insert(0, %r)
            import logfind
            hidden = logging.getLogger("hidden")
            hidden.propagate = False
            with logfind.capture(name="inproc", home=%r, echo=False) as cap:
                print("py print")
                os.write(1, b"raw fd write\\n")
                libc = ctypes.CDLL(ctypes.util.find_library("c"))
                libc.printf(b"c printf without flush\\n")
                logging.getLogger("mask").debug("debug record")
                hidden.warning("hidden logger")
            print(cap.directory)
            """) % (ROOT, self.home)
        if os.name == "nt":
            self.skipTest("printf via libc 仅在 POSIX 上测试")
        out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        s = Session(out.stdout.strip().splitlines()[-1])
        body = "\n".join(s.iter_lines())
        for want in ("py print", "raw fd write", "c printf without flush",
                     "DEBUG mask: debug record", "hidden logger"):
            self.assertIn(want, body)


class SnapshotTests(TmpDir):
    def setUp(self):
        super().setUp()
        self.cwd = os.getcwd()
        os.chdir(self.tmp)
        self.store = SnapshotStore(os.path.join(self.home, "snapshots"))

    def tearDown(self):
        os.chdir(self.cwd)
        super().tearDown()

    def test_take_diff_live_and_hardlink(self):
        self.write("out/state.json", json.dumps({"step": 1, "vec": [0.0] * 32, "name": "m"}))
        self.write("out/log.txt", "a\nb\n")
        a = self.store.take(["out"], label="mask")
        self.assertEqual(sorted(a.files), ["out/log.txt", "out/state.json"])
        vec = [0.0] * 32
        vec[5] = 0.5
        vec[7] = float("nan")
        self.write("out/state.json", json.dumps({"step": 2, "vec": vec, "extra": True}))
        b = self.store.take(["out"], label="mask")
        # 未变化的文件使用硬链接
        if hasattr(os, "link"):
            self.assertEqual(os.stat(a.path_of("out/log.txt")).st_ino, os.stat(b.path_of("out/log.txt")).st_ino)
        diffs = {d.rel: d for d in diff_snapshots(a, b)}
        self.assertEqual(diffs["out/log.txt"].status, "same")
        detail = "\n".join(diffs["out/state.json"].details)
        self.assertIn("$.step: 1 -> 2", detail)
        self.assertIn("$.name: 被删除", detail)
        self.assertIn("$.extra: 新增", detail)
        self.assertIn("2/32 个元素不同", detail)
        self.write("out/log.txt", "a\nc\n")
        live = {d.rel: d for d in diff_snapshots(b, None)}
        self.assertEqual(live["out/log.txt"].status, "changed")
        self.assertIn("+c", live["out/log.txt"].details)
        self.assertEqual(self.store.resolve("prev", "mask").id, a.id)

    def test_tolerance(self):
        self.assertEqual(json_diff([1.0] * 20, [1.0 + 1e-9] * 20, tol=1e-6), [])
        self.assertTrue(json_diff([1.0] * 20, [1.0 + 1e-3] * 20, tol=1e-6))

    def test_save_object_and_prune(self):
        for i in range(3):
            self.store.save_object({"i": i, "s": {1, 2}}, label="obj")
        self.store.save_object(object(), label="obj", name="weird")
        snaps = self.store.list("obj")
        self.assertEqual(len(snaps), 4)
        self.assertIn("weird.pkl", snaps[-1].files)
        self.assertEqual(len(self.store.prune(2, "obj")), 2)
        self.assertEqual(len(self.store.list("obj")), 2)

    def test_watch(self):
        path = self.write("w/data.json", '{"v": 1}')

        def writer():
            time.sleep(0.3)
            with open(path, "w") as fh:
                fh.write('{"v": 2}')
        t = threading.Thread(target=writer)
        t.start()
        seen = []
        deadline = time.time() + 5
        self.store.watch(["w"], interval=0.05, label="w", debounce=0.05,
                         on_snapshot=lambda s, c: seen.append(s),
                         should_stop=lambda: len(seen) >= 2 or time.time() > deadline)
        t.join()
        self.assertEqual(len(seen), 2)
        self.assertIn('"v": 2', seen[-1].read("w/data.json").decode())


class CliTests(TmpDir):
    def cli(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(list(argv))
        return rc, buf.getvalue()

    def test_grep_cli(self):
        path = self.write("a.log", SearchTests.LOG)
        rc, out = self.cli("grep", "--color", "never", "-C", "1", "dimension", path)
        self.assertEqual(rc, 0)
        self.assertIn("ValueError: dimension mismatch", out)
        self.assertIn("DEBUG step 1", out)
        rc, out = self.cli("grep", "--color", "never", "-c", "--level", "warn", path)
        self.assertEqual(out.strip(), "2")
        rc, out = self.cli("grep", "--color", "never", "--preset", "crash", "--json", path)
        self.assertEqual(json.loads(out.splitlines()[0])["line"], 3)

    def test_run_show_grep_session(self):
        rc, _ = self.cli("run", "--home", self.home, "-q", "--", sys.executable, "-c",
                         "import sys; print('alpha'); print('beta-err', file=sys.stderr); sys.exit(4)")
        self.assertEqual(rc, 4)
        rc, out = self.cli("show", "--home", self.home, "--color", "never", "--stream", "stderr")
        self.assertIn("beta-err", out)
        self.assertNotIn("alpha", out)
        rc, out = self.cli("grep", "--home", self.home, "--color", "never", "-s", "latest", "alpha")
        self.assertEqual(rc, 0)
        self.assertIn("[stdout] alpha", out)
        rc, out = self.cli("sessions", "--home", self.home)
        self.assertIn("退出码 4", out)

    def test_snap_cli(self):
        cwd = os.getcwd()
        os.chdir(self.tmp)
        try:
            self.write("s/x.json", '{"a": 1}')
            self.cli("snap", "take", "--home", self.home, "s")
            self.write("s/x.json", '{"a": 2}')
            self.cli("snap", "take", "--home", self.home, "s")
            rc, out = self.cli("snap", "diff", "--home", self.home, "--color", "never")
            self.assertEqual(rc, 1)
            self.assertIn("$.a: 1 -> 2", out)
            rc, out = self.cli("snap", "show", "--home", self.home, "prev", "x.json")
            self.assertEqual(json.loads(out), {"a": 1})
        finally:
            os.chdir(cwd)

    def test_profile_config(self):
        cfg = self.write("logfind.toml", textwrap.dedent("""\
            home = "data"
            [profiles.vector]
            logs = ["logs/*.log"]
            """))
        self.write("logs/v.log", "2026-10-02 10:00:00 ERROR vector nan\n")
        rc, out = self.cli("grep", "--config", cfg, "--color", "never", "-p", "vector", "nan")
        self.assertEqual(rc, 0)
        self.assertIn("vector nan", out)


FAKE_ADB = r"""#!/usr/bin/env python3
import os, shutil, subprocess, sys
a = sys.argv[1:]
if a[:1] == ["-s"]:
    a = a[2:]
if a[0] == "get-state":
    print("device"); sys.exit(0)
if a[0] in ("shell", "exec-out"):
    p = subprocess.run(["sh", "-c", a[1]])
    sys.exit(p.returncode)
if a[0] == "pull":
    if os.environ.get("FAKE_PULL_DENIED"):
        print("adb: error: failed to stat remote object: Permission denied", file=sys.stderr); sys.exit(1)
    shutil.copy(a[1], a[2]); sys.exit(0)
sys.exit(1)
"""


@unittest.skipIf(os.name == "nt", "需要 POSIX sh")
class AndroidTests(TmpDir):
    def setUp(self):
        super().setUp()
        from logfind import android
        self.android = android
        self.bin = self.p("bin")
        os.makedirs(self.bin)
        for name, body in (("adb", FAKE_ADB), ("su", '#!/bin/sh\n[ "$1" = "-c" ] && shift\nexec sh -c "$1"\n'),
                           ("getprop", "#!/bin/sh\necho 1\n")):
            path = os.path.join(self.bin, name)
            with open(path, "w") as fh:
                fh.write(body)
            os.chmod(path, 0o755)
        self.old_path = os.environ["PATH"]
        os.environ["PATH"] = self.bin + os.pathsep + self.old_path
        self.dev = self.p("dev", "log")
        os.makedirs(self.dev)

    def tearDown(self):
        os.environ["PATH"] = self.old_path
        os.environ.pop("FAKE_PULL_DENIED", None)
        super().tearDown()

    def test_script_matches_and_is_valid_sh(self):
        spec = self.android.BootLogSpec()
        text = self.android.render_script(spec)
        self.assertIn('/system/bin/logcat -v time -f "$BOOTLOG_DIR/boot.log" -r 16384 -n 3', text)
        self.assertIn("BOOTLOG_DIR=/data/local/tmp/ven11/log", text)
        self.assertIn("16M×3", text)
        path = self.write("s.sh", text)
        self.assertEqual(subprocess.run(["sh", "-n", path]).returncode, 0)
        spec = self.android.BootLogSpec(rotate_kb=self.android.size_to_kb("8M"), count=5, buffers=["all"])
        self.assertIn("-v time -b all -f", self.android.render_block(spec))
        self.assertIn("-r 8192 -n 5", self.android.render_block(spec))
        for bad in (dict(log_dir="data/x"), dict(log_dir="/data/x'; rm -rf /"), dict(name="a b"),
                    dict(fmt="time;id")):
            with self.assertRaises(ValueError):
                self.android.BootLogSpec(**bad).validate()

    def test_install_merges_into_existing_module_script(self):
        mod = self.p("module")
        os.makedirs(mod)
        orig = "\ufeff#!/system/bin/sh\r\nMODDIR=${0%/*}\r\necho hi > /dev/null\r\n\r\nexit 0\r\n"
        self.write("module/post-fs-data.sh", orig, newline="")
        path, action = self.android.install_script(mod, self.android.BootLogSpec())
        self.assertEqual(action, "inserted")
        with open(path, "rb") as fh:
            data = fh.read().decode("utf-8")
        self.assertNotIn("\r", data)
        self.assertTrue(data.startswith("#!/system/bin/sh\nMODDIR"))
        self.assertLess(data.index(self.android.MARK_END), data.rindex("exit 0"))  # 在 exit 之前才会执行
        self.assertTrue(os.path.exists(path + ".bak"))
        # 重复执行：原地更新，不会重复插入
        path, action = self.android.install_script(mod, self.android.BootLogSpec(count=5))
        self.assertEqual(action, "updated")
        with open(path, encoding="utf-8") as fh:
            data = fh.read()
        self.assertEqual(data.count(self.android.MARK_BEGIN), 1)
        self.assertIn("-n 5", data)
        self.assertEqual(self.android.install_script(mod, self.android.BootLogSpec(count=5))[1], "unchanged")
        # 新文件
        path, action = self.android.install_script(self.p("new.sh"), self.android.BootLogSpec())
        self.assertEqual(action, "created")
        self.assertEqual(subprocess.run(["sh", "-n", path]).returncode, 0)

    def _device_logs(self):
        self.write("dev/log/boot.log.2", "10-03 08:00:00.000 I/init(    1): old boot\n")
        self.write("dev/log/boot.log.1", "10-03 08:00:01.000 E/AndroidRuntime( 99): FATAL EXCEPTION: main\n")
        self.write("dev/log/boot.log", "10-03 08:00:02.000 I/Zygote( 77): Error-free line\n")
        self.write("dev/log/unrelated.txt", "x\n")
        for i, n in enumerate(("boot.log.2", "boot.log.1", "boot.log")):
            t = datetime(2026, 10, 3, 8, 0, i).timestamp()
            os.utime(os.path.join(self.dev, n), (t, t))

    def test_pull_with_su_fallback_and_grep(self):
        self._device_logs()
        os.environ["FAKE_PULL_DENIED"] = "1"
        rc, out = CliTests.cli(self, "android", "pull", "--home", self.home, "--dir", self.dev, "-s", "emu-1")
        self.assertEqual(rc, 0)
        out_dir = out.strip()
        self.assertTrue(os.path.basename(out_dir).endswith("_emu-1"))
        self.assertEqual(sorted(os.listdir(out_dir)), ["boot.log", "boot.log.1", "boot.log.2", "meta.json"])
        with open(os.path.join(out_dir, "meta.json"), encoding="utf-8") as fh:
            meta = json.load(fh)
        self.assertEqual({f["method"] for f in meta["files"]}, {"su"})
        self.assertEqual(int(os.path.getmtime(os.path.join(out_dir, "boot.log.2"))),
                         int(datetime(2026, 10, 3, 8, 0, 0).timestamp()))
        # 检索：最旧的轮转文件在前；级别过滤不会把 I 级别里的 Error 算进去
        rc, out = CliTests.cli(self, "grep", "--home", self.home, "--color", "never", "--android", "latest",
                               "-l", "error", ".")
        self.assertEqual(rc, 0)
        self.assertIn("FATAL EXCEPTION", out)
        self.assertNotIn("Error-free", out)
        rc, out = CliTests.cli(self, "grep", "--home", self.home, "--color", "never", "--android", "latest",
                               "--json", "boot|FATAL|Error")
        self.assertEqual([json.loads(l)["path"].rsplit(os.sep, 1)[1] for l in out.splitlines()],
                         ["boot.log.2", "boot.log.1", "boot.log"])
        rc, out = CliTests.cli(self, "android", "list", "--home", self.home)
        self.assertIn("3 文件", out)

    def test_status(self):
        self._device_logs()
        rc, out = CliTests.cli(self, "android", "status", "--home", self.home, "--color", "never",
                               "--dir", self.dev)
        self.assertEqual(rc, 1)  # 没有常驻 logcat
        self.assertIn("未运行", out)
        self.assertIn("boot.log.2", out)
        self.assertNotIn("unrelated", out)
        holder = subprocess.Popen(["sh", "-c", "sleep 30 # %s/boot.log" % self.dev])
        try:
            rc, out = CliTests.cli(self, "android", "status", "--home", self.home, "--color", "never",
                                   "--dir", self.dev)
            self.assertEqual(rc, 0)
            self.assertIn("运行中", out)
        finally:
            holder.kill()
            holder.wait()


if __name__ == "__main__":
    unittest.main()

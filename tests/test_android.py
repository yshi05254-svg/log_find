"""Android 相关功能测试：用一个模拟设备的假 adb，以及在 dash/sh 下真实执行生成的开机脚本。"""
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time
import unittest
from contextlib import redirect_stdout
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from logfind import android  # noqa: E402
from logfind.archive import Session  # noqa: E402
from logfind.cli import main as cli_main  # noqa: E402
from logfind.search import Filters, Matcher, iter_records, search  # noqa: E402
from logfind.timeline import build_timeline, parse_uptime_range  # noqa: E402

POSIX = os.name != "nt"

FAKE_ADB = r'''
import json, os, shlex, sys, tarfile

state_path = os.environ["FAKE_ADB_STATE"]
with open(state_path) as fh:
    st = json.load(fh)
args = sys.argv[1:]
if args[:1] == ["-s"]:
    args = args[2:]

def save():
    with open(state_path, "w") as fh:
        json.dump(st, fh)

def unwrap(cmd):
    """去掉 su -c '...' 2>/dev/null 外壳。"""
    parts = shlex.split(cmd)
    if parts[:2] == ["su", "-c"]:
        return parts[2], True
    return cmd, False

def conn():
    return st["connections"][min(st["idx"], len(st["connections"]) - 1)]

verb = args[0]
if verb == "wait-for-device":
    sys.exit(0)
if verb == "get-serialno":
    print("FAKE123")
    sys.exit(0)
if verb == "push":
    with open(args[1], "rb") as src:
        st["pushed"][args[2]] = src.read().decode()
    save()
    sys.exit(0)
cmd = args[1]
inner, su = unwrap(cmd)
st["calls"].append({"verb": verb, "cmd": inner, "su": su})
save()
if verb == "shell":
    if "boot_id" in inner and inner.startswith("cat /proc"):
        print(conn()["boot_id"])
    elif "id -u" == inner:
        print("0")
    elif "logcat -v year -d" in inner:
        print("year-ok")
    elif inner.startswith("echo \"@script"):
        sys.stdout.write(st.get("status_out", ""))
    elif inner.startswith("cat /data/local/tmp/.logfind_pull_"):
        sys.stdout.write(st.get("pull_err", ""))
    sys.exit(0)
if verb == "exec-out":
    if inner.startswith("logcat"):
        c = conn()
        st["idx"] += 1
        save()
        for line in c["lines"]:
            sys.stdout.write(line + "\n")
        sys.stdout.flush()
        sys.exit(c.get("exit", 0))
    toks = shlex.split(inner)
    if toks[:3] == ["tar", "-cf", "-"]:
        parent = toks[4]
        names = [t for t in toks[5:] if not t.startswith("2>")]
        base = os.path.join(st["root"], parent.lstrip("/"))
        with tarfile.open(fileobj=sys.stdout.buffer, mode="w|") as tf:
            for n in names:
                if os.path.exists(os.path.join(base, n)):
                    tf.add(os.path.join(base, n), arcname=n)
        sys.exit(0)
sys.exit(1)
'''


def logcat_line(ts, tag, msg, level="I", pid=100):
    return "%s  1000 %5d %5d %s %s: %s" % (ts, pid, pid, level, tag, msg)


BID_A = "aaaa1111-2222-3333-4444-555566667777"
BID_B = "bbbb1111-2222-3333-4444-555566667777"

# 开机时 RTC 是 06-05，up=16s 时联网对时跳到 10-02 20:00:00
JUMP_LOG = [
    logcat_line("2026-06-05 08:00:00.000", "init", "starting service zygote"),           # up 3
    logcat_line("2026-06-05 08:00:00.500", "logfind_clock", "boot_id=%s seq=1 up=3.5" % BID_A),
    logcat_line("2026-06-05 08:00:05.000", "LSPosed", "hook installed"),                  # up 8
    logcat_line("2026-06-05 08:00:10.000", "logfind_clock", "boot_id=%s up=13.0" % BID_A),
    logcat_line("2026-06-05 08:00:12.000", "Zygote", "preload done"),                     # up 15
    logcat_line("2026-10-02 20:00:00.000", "NetworkTime", "synced"),                      # up 16
    logcat_line("2026-10-02 20:00:04.000", "logfind_clock", "boot_id=%s up=20.0" % BID_A),
    logcat_line("2026-10-02 20:00:10.000", "LSPosed", "late hook", level="E"),            # up 26
]


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="logfind-android-")
        self.home = os.path.join(self.tmp, ".logfind")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, name, text):
        path = os.path.join(self.tmp, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def cli(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(list(argv))
        return rc, buf.getvalue()


class TimelineTests(Tmp):
    def records(self, path, **kw):
        return list(iter_records(path, clock_fix=True, **kw))

    def test_anchors_fix_rtc_jump(self):
        path = self.write("boot/logcat.txt", "\n".join(JUMP_LOG) + "\n")
        recs = {r.text.split(": ", 1)[1]: r for r in self.records(path)}
        self.assertAlmostEqual(recs["starting service zygote"].uptime, 3.0, places=3)
        self.assertAlmostEqual(recs["hook installed"].uptime, 8.0, places=3)
        self.assertAlmostEqual(recs["preload done"].uptime, 15.0, places=3)
        self.assertAlmostEqual(recs["synced"].uptime, 16.0, places=3)
        self.assertAlmostEqual(recs["late hook"].uptime, 26.0, places=3)
        # 校正后的墙钟：开机阶段的 06-05 被换算到对时后的真实时间
        self.assertEqual(recs["hook installed"].ts, datetime(2026, 10, 2, 19, 59, 52))
        self.assertEqual({r.boot for r in recs.values()}, {1})

        hits = [h.record.text for h in search([path], Matcher(["LSPosed"]),
                                              Filters(uptime_min=0, uptime_max=20), clock_fix=True)]
        self.assertEqual(len(hits), 1)
        self.assertIn("hook installed", hits[0])
        # 按墙钟过滤：不校正时 06-05 的行会被 --since 10-02 19:59 漏掉
        since = datetime(2026, 10, 2, 19, 59, 0)
        plain = [h for h in search([path], Matcher(["hook installed"]), Filters(since=since))]
        fixed = [h for h in search([path], Matcher(["hook installed"]), Filters(since=since), clock_fix=True)]
        self.assertEqual((len(plain), len(fixed)), (0, 1))

    def test_heuristic_without_anchors(self):
        lines = [l for l in JUMP_LOG if "logfind_clock" not in l]
        path = self.write("plain.txt", "\n".join(lines) + "\n")
        recs = {r.text.split(": ", 1)[1]: r for r in self.records(path)}
        self.assertAlmostEqual(recs["starting service zygote"].uptime, 0.0)
        self.assertAlmostEqual(recs["hook installed"].uptime, 5.0)
        self.assertAlmostEqual(recs["synced"].uptime, 12.0)   # 跳变被剔除
        self.assertAlmostEqual(recs["late hook"].uptime, 22.0)

    def test_logcat_without_year_uses_reference(self):
        lines = [l[5:] for l in JUMP_LOG]  # 默认 threadtime：06-05 08:00:00.000
        tl = build_timeline(lines, datetime(2026, 10, 3))
        self.assertEqual(len(tl.boots), 1)
        self.assertTrue(tl.boots[0].anchored)
        self.assertEqual(tl.boots[0].jumps, 1)

    def test_boot_split_by_anchor_boot_id(self):
        second = [
            logcat_line("2026-06-05 08:00:00.000", "init", "second boot"),
            logcat_line("2026-06-05 08:00:00.100", "logfind_clock", "boot_id=%s up=2.1" % BID_B),
            logcat_line("2026-06-05 08:00:03.000", "LSPosed", "hook again"),
        ]
        path = self.write("two.txt", "\n".join(JUMP_LOG + second) + "\n")
        hits = list(search([path], Matcher(["LSPosed"]), Filters(boot=-1), clock_fix=True))
        self.assertEqual([h.record.boot for h in hits], [2])
        self.assertAlmostEqual(hits[0].record.uptime, 5.0, places=3)

    def test_parse_uptime_range(self):
        self.assertEqual(parse_uptime_range("0-20s"), (0, 20))
        self.assertEqual(parse_uptime_range("20"), (0, 20))
        self.assertEqual(parse_uptime_range("1m-2m"), (60, 120))
        self.assertEqual(parse_uptime_range("30-"), (30, None))
        self.assertEqual(parse_uptime_range("500ms..2s"), (0.5, 2))
        with self.assertRaises(ValueError):
            parse_uptime_range("abc")

    def test_grep_cli_uptime(self):
        path = self.write("boot/logcat.txt", "\n".join(JUMP_LOG) + "\n")
        rc, out = self.cli("grep", "--color", "never", "--uptime", "0-20s", "LSPosed", path)
        self.assertEqual(rc, 0)
        self.assertIn("[b1 +8.000s]", out)
        self.assertNotIn("late hook", out)
        rc, out = self.cli("grep", "--color", "never", "--json", "--fix-clock", "-l", "error", path)
        rec = json.loads(out.splitlines()[0])
        self.assertEqual((rec["boot"], rec["uptime"], rec["level"]), (1, 26.0, "ERROR"))

    def test_safe_extract_rejects_traversal_and_links(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for name, data in (("ok/a.log", b"hello"), ("../evil", b"x"), ("/abs", b"y")):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            link = tarfile.TarInfo("ok/link")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            tf.addfile(link)
        buf.seek(0)
        dest = os.path.join(self.tmp, "x")
        files, size = android._extract_stream(buf, dest)
        self.assertEqual([os.path.relpath(f, dest) for f in files], [os.path.join("ok", "a.log"), "abs"])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "evil")))
        self.assertFalse(os.path.lexists(os.path.join(dest, "ok", "link")))


@unittest.skipUnless(POSIX, "假 adb 依赖 shebang")
class FakeAdbTests(Tmp):
    def setUp(self):
        super().setUp()
        self.adb_path = os.path.join(self.tmp, "fake_adb")
        with open(self.adb_path, "w") as fh:
            fh.write("#!%s\n%s" % (sys.executable, FAKE_ADB))
        os.chmod(self.adb_path, 0o755)
        self.state_path = os.path.join(self.tmp, "state.json")
        self.root = os.path.join(self.tmp, "device")
        os.environ["FAKE_ADB_STATE"] = self.state_path
        self.set_state(connections=[{"boot_id": BID_A, "lines": []}])

    def tearDown(self):
        os.environ.pop("FAKE_ADB_STATE", None)
        super().tearDown()

    def set_state(self, **kw):
        st = {"idx": 0, "calls": [], "pushed": {}, "root": self.root}
        st.update(kw)
        with open(self.state_path, "w") as fh:
            json.dump(st, fh)

    def state(self):
        with open(self.state_path) as fh:
            return json.load(fh)

    def adb(self):
        return android.Adb(adb=self.adb_path)

    def test_logcat_reconnects_across_reboot(self):
        a = [logcat_line("2026-06-05 08:00:0%d.000" % i, "LSPosed", "a%d" % i) for i in range(4)]
        b = [logcat_line("2026-06-05 08:00:0%d.000" % i, "LSPosed", "b%d" % i) for i in range(2)]
        self.set_state(connections=[
            {"boot_id": BID_A, "lines": a[:3], "exit": 255},       # USB 抖动断开
            {"boot_id": BID_A, "lines": a[2:], "exit": 255},       # 同一次开机重连：-T 续接，a2 重复
            {"boot_id": BID_B, "lines": b, "exit": 0},             # 重启后
        ])
        session = Session.create(self.home, "t")
        s = android.LogcatStreamer(self.adb(), session, buffer_size="16M", max_connects=3,
                                   anchor_interval=0, echo=False)
        s.run()
        text = "\n".join(session.iter_lines())
        for i in range(4):
            self.assertEqual(text.count("LSPosed: a%d" % i), 1, "a%d" % i)
        self.assertIn("LSPosed: b1", text)
        self.assertIn("检测到设备重启", text)
        self.assertIn("同一次开机重连", text)
        self.assertEqual((s.connects, s.boots), (3, 2))
        calls = [c["cmd"] for c in self.state()["calls"]]
        logcats = [c["cmd"] for c in self.state()["calls"] if c["verb"] == "exec-out"]
        self.assertEqual(len(logcats), 3)
        self.assertNotIn("-T", logcats[0])
        self.assertIn("-T '2026-06-05 08:00:02.000'", logcats[1])
        self.assertIn("-v year", logcats[0])
        self.assertEqual(sum("-G 16M" in c for c in calls), 2)  # 每次开机重做一次，重连不重复
        # 会话归档按开机分段，boot 2 的行用设备时间算 uptime
        hits = list(search(session.segments(), Matcher(["LSPosed: b"]), Filters(boot=2), clock_fix=True))
        self.assertEqual(len(hits), 2)
        self.assertAlmostEqual(hits[1].record.uptime, 1.0)

    def test_pull_streams_tar(self):
        log_dir = os.path.join(self.root, "data", "adb", "lspd", "log")
        os.makedirs(os.path.join(log_dir, "old"))
        with open(os.path.join(log_dir, "verbose.log"), "w") as fh:
            fh.write("hooked\n")
        with open(os.path.join(log_dir, "old", "x.log"), "w") as fh:
            fh.write("old\n")
        self.set_state(connections=[{"boot_id": BID_A, "lines": []}],
                       pull_err="tar: /data/adb/lspd/log/secret: Permission denied\n")
        dest = os.path.join(self.tmp, "out")
        res = android.pull_paths(self.adb(), ["/data/adb/lspd/log/"], dest)
        with open(os.path.join(dest, "log", "verbose.log")) as fh:
            self.assertEqual(fh.read(), "hooked\n")
        self.assertTrue(os.path.isfile(os.path.join(dest, "log", "old", "x.log")))
        self.assertIn("Permission denied", res.errors)
        tar_call = [c for c in self.state()["calls"] if c["cmd"].startswith("tar")][0]
        self.assertTrue(tar_call["su"])
        self.assertIn("-C /data/adb/lspd log", tar_call["cmd"])

    def test_bootlog_install_status_pull(self):
        boot_dir = os.path.join(self.root, "data", "local", "tmp", "logfind", "boot-0003")
        os.makedirs(boot_dir)
        with open(os.path.join(boot_dir, "logcat.txt"), "w") as fh:
            fh.write("\n".join(JUMP_LOG) + "\n")
        status = textwrap.dedent("""\
            @script=yes
            @boot_id=%s
            @persist=16M
            @current=%s 3
            @running=yes
            @@ /data/local/tmp/logfind/boot-0003 120
            seq=3
            boot_id=%s
            date=2026-06-05 08:00:00 +0800
            bootreason=reboot
            """) % (BID_B, BID_A, BID_A)
        self.set_state(connections=[{"boot_id": BID_A, "lines": []}], status_out=status)
        rc, out = self.cli("adb", "bootlog", "install", "--adb", self.adb_path, "--home", self.home)
        self.assertEqual(rc, 0)
        st = self.state()
        script = st["pushed"]["/data/local/tmp/.logfind_bootlog.sh"]
        self.assertIn("logcat -b \"$BUFFERS\" -G \"$SIZE\"", script)
        cmds = [c["cmd"] for c in st["calls"] if c["su"]]
        self.assertTrue(any("cat /data/local/tmp/.logfind_bootlog.sh > /data/adb/post-fs-data.d/logfind_bootlog.sh"
                            in c for c in cmds), cmds)
        self.assertIn("setprop persist.logd.size 16M", cmds)
        self.assertIn("sh /data/adb/post-fs-data.d/logfind_bootlog.sh", cmds)

        rc, out = self.cli("adb", "bootlog", "status", "--adb", self.adb_path, "--home", self.home)
        self.assertIn("boot-0003", out)
        self.assertIn("reason=reboot", out)

        rc, out = self.cli("adb", "bootlog", "pull", "--adb", self.adb_path, "--home", self.home)
        self.assertEqual(rc, 0, out)
        dest = os.path.join(self.home, "android", "FAKE123", "boot-0003_aaaa1111")
        self.assertTrue(os.path.isfile(os.path.join(dest, "logcat.txt")), out)
        rc, out = self.cli("adb", "bootlog", "pull", "--adb", self.adb_path, "--home", self.home)
        self.assertIn("跳过", out)
        rc, out = self.cli("grep", "--color", "never", "--uptime", "0-20", "LSPosed", dest)
        self.assertIn("hook installed", out)
        self.assertNotIn("late hook", out)


@unittest.skipUnless(POSIX and shutil.which("sh"), "需要 POSIX sh")
class BootScriptTests(Tmp):
    """在主机 sh 下真实执行生成的开机脚本，logcat / log / getprop 用假的。"""

    def setUp(self):
        super().setUp()
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin)
        self.calls = os.path.join(self.tmp, "calls.txt")
        fakes = {
            "logcat": 'echo "logcat $*" >> "$CALLS"\n'
                      'case "$*" in *" -f "*) exec sleep 30 ;; esac\nexit 0\n',
            "log": 'echo "log $*" >> "$CALLS"\n',
            "getprop": 'echo "fake-$1"\n',
        }
        for name, body in fakes.items():
            p = os.path.join(self.bin, name)
            with open(p, "w") as fh:
                fh.write("#!/bin/sh\n" + body)
            os.chmod(p, 0o755)
        self.sock_path = os.path.join(self.tmp, "logdr")
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.bind(self.sock_path)
        self.pids = []

    def tearDown(self):
        for pid in self.pids:
            try:
                os.kill(pid, 9)
            except OSError:
                pass
        self.sock.close()
        super().tearDown()

    def run_script(self, script_path, devdir):
        env = dict(os.environ, PATH=self.bin + os.pathsep + os.environ.get("PATH", ""),
                   CALLS=self.calls, LOGFIND_LOGD_SOCKET=self.sock_path)
        subprocess.run(["sh", script_path], env=env, check=True, timeout=10)

    def wait_current(self, devdir, seq):
        deadline = time.time() + 10
        cur = os.path.join(devdir, "current")
        while time.time() < deadline:
            if os.path.exists(cur):
                with open(cur) as fh:
                    parts = fh.read().split()
                if len(parts) == 4 and parts[3] == str(seq):
                    self.pids += [int(parts[1]), int(parts[2])]
                    return parts
            time.sleep(0.05)
        self.fail("脚本没有写出 current")

    def test_script_runs_and_guards_double_start(self):
        devdir = os.path.join(self.tmp, "dev", "logfind")
        os.makedirs(os.path.dirname(devdir))
        script = android.bootlog_script(android.BootlogOptions(directory=devdir, keep=2, extra="*:V"))
        path = self.write("bootlog.sh", script)
        self.run_script(path, devdir)
        parts = self.wait_current(devdir, 1)
        with open("/proc/sys/kernel/random/boot_id") as fh:
            bid = fh.read().strip()
        self.assertEqual(parts[0], bid)
        with open(os.path.join(devdir, "boot-0001", "boot.txt")) as fh:
            info = fh.read()
        self.assertIn("boot_id=%s" % bid, info)
        self.assertIn("bootreason=fake-ro.boot.bootreason", info)
        time.sleep(0.3)
        with open(self.calls) as fh:
            calls = fh.read()
        self.assertIn("logcat -b all -G 16M", calls)
        self.assertIn("-v threadtime -v year *:V -f %s/boot-0001/logcat.txt -r 8192 -n 8" % devdir, calls)
        self.assertIn("log -t logfind_clock boot_id=%s seq=1 up=" % bid, calls)

        # 同一次开机再次执行（例如 install 后立即启动）：不重复抓
        self.run_script(path, devdir)
        time.sleep(0.5)
        self.assertEqual(sorted(n for n in os.listdir(devdir) if n.startswith("boot-")), ["boot-0001"])

        # 模拟重启：current 里记录的是上一次开机的 boot_id，脚本应开新目录，并按 keep=2 清理
        for seq in (2, 3):
            with open(os.path.join(devdir, "current"), "w") as fh:
                fh.write("previous-boot 1 1 %d\n" % (seq - 1))
            self.run_script(path, devdir)
            self.wait_current(devdir, seq)
        time.sleep(0.2)
        self.assertEqual(sorted(n for n in os.listdir(devdir) if n.startswith("boot-")),
                         ["boot-0002", "boot-0003"])


if __name__ == "__main__":
    unittest.main()

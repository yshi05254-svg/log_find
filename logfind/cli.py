"""命令行入口: logfind <子命令>。运行 `logfind -h` 或 `logfind <子命令> -h` 查看帮助。"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
from typing import List, Optional

from . import __version__
from .archive import (Session, TriggerRecorder, list_sessions, parse_archive_line, prune_sessions,
                      resolve_session, stderr_hit_printer)
from .config import EXAMPLE, Config, load_config
from .follow import Follower
from .parsing import LEVEL_NAMES, level_from_name, parse_time_spec
from .search import PRESETS, Filters, Matcher, expand_paths, search
from .timeline import format_uptime, parse_uptime_range
from .snapshot import SnapshotStore, diff_snapshots
from .textio import read_bytes_as_text


# ---------- 输出辅助 ----------
class Color:
    def __init__(self, enabled: bool):
        self.on = enabled

    def __call__(self, code: str, text: str) -> str:
        return "\x1b[%sm%s\x1b[0m" % (code, text) if self.on else text


def _color_enabled(mode: str) -> bool:
    if mode == "always":
        return True
    if mode == "never" or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _level_color(level: Optional[int]) -> str:
    if level is None:
        return "0"
    if level >= 40:
        return "1;31"
    if level >= 30:
        return "33"
    if level <= 10:
        return "2"
    return "0"


def _out(text: str = "") -> None:
    sys.stdout.write(text + "\n")


def _fix_stdio() -> None:
    # Windows 控制台遇到无法编码的字符时不要崩溃
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


def _cfg(args) -> Config:
    cfg = load_config(getattr(args, "config", None))
    if getattr(args, "home", None):
        cfg.home = args.home
    return cfg


def _profile(args, cfg: Config):
    return cfg.profile(getattr(args, "profile", None))


# ---------- run ----------
def cmd_run(args) -> int:
    from .runner import run_command
    cfg = _cfg(args)
    prof = _profile(args, cfg)
    cmd = list(args.cmd)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd and prof and prof.command:
        cmd = prof.command
    if not cmd:
        print("logfind run: 需要要运行的命令，例如: logfind run -- python train.py", file=sys.stderr)
        return 2
    triggers = list(args.trigger or []) + (prof.triggers if prof else [])
    for p in args.preset or []:
        triggers += PRESETS[p]
    name = args.name or (prof.name if prof else os.path.basename(cmd[0]))
    session = Session.create(cfg.home, name, {"kind": "run", "profile": prof.name if prof else None},
                             max_segment_bytes=cfg.max_segment, max_total_bytes=cfg.max_total)
    prune_sessions(cfg.home, cfg.keep_sessions)
    env = dict(prof.env) if prof else {}
    for kv in args.env or []:
        k, _, v = kv.partition("=")
        env[k] = v
    try:
        code = run_command(
            cmd, session, echo=not args.quiet, triggers=triggers,
            trigger_before=args.before if args.before is not None else (prof.trigger_before if prof else 50),
            trigger_after=args.after if args.after is not None else (prof.trigger_after if prof else 30),
            unbuffer=not args.no_unbuffer, use_stdbuf=not args.no_stdbuf, use_pty=args.pty,
            encoding=args.encoding or (prof.encoding if prof else "auto"), keep_ansi=args.keep_ansi,
            cwd=args.cwd or (prof.cwd if prof else None), env=env, tail_on_fail=args.tail_on_fail,
            merge_streams=args.merge)
    except OSError as e:
        print("logfind run: 无法启动 %s: %s" % (cmd[0], e), file=sys.stderr)
        return 127
    if code < 0:
        return 128 + (-code)
    return code & 0xFF if os.name != "nt" else code


# ---------- tail ----------
def cmd_tail(args) -> int:
    cfg = _cfg(args)
    prof = _profile(args, cfg)
    patterns = list(args.paths) or (prof.logs if prof else [])
    if not patterns:
        print("logfind tail: 请指定文件/glob，或用 -p 指定配置中的 profile", file=sys.stderr)
        return 2
    color = Color(_color_enabled(args.color))
    matcher = Matcher(args.grep or [], ignore_case=args.ignore_case) if args.grep else None
    min_level = level_from_name(args.level) if args.level else None
    triggers = list(args.trigger or []) + (prof.triggers if prof else [])
    for p in args.preset or []:
        triggers += PRESETS[p]

    session = None
    if args.record or triggers:
        session = Session.create(cfg.home, "tail-" + (prof.name if prof else "files"),
                                 {"kind": "tail", "patterns": patterns},
                                 max_segment_bytes=cfg.max_segment, max_total_bytes=cfg.max_total)
        print(color("2", "[logfind] 记录到 %s" % session.directory), file=sys.stderr)
    recorder = TriggerRecorder(triggers, session.hits_dir, args.before, args.after,
                               on_hit=stderr_hit_printer()) if session and triggers else None

    fol = Follower(patterns, from_start=args.from_start, tail_lines=args.lines,
                   encoding=args.encoding or (prof.encoding if prof else "auto"),
                   poll_interval=args.interval, rescan_interval=max(args.interval, 0.25))
    tracked = [t.path for t in fol.files.values() if not t.vanished]
    print(color("2", "[logfind] 跟踪 %d 个文件%s" % (len(tracked), "（等待文件出现）" if not tracked else "")),
          file=sys.stderr)
    multi = len(fol.files) > 1 or any(any(c in p for c in "*?[") for p in patterns)
    from .parsing import parse_level
    stop = {"flag": False}
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, lambda *a: stop.__setitem__("flag", True))

    def handle(ev) -> None:
        if ev.kind in ("line", "partial"):
            if session:
                session.archive.write(os.path.basename(ev.path), ev.text, ev.ts)
            if recorder:
                recorder.feed(os.path.basename(ev.path), ev.text, ev.ts)
            if matcher and not matcher(ev.text):
                return
            lv = parse_level(ev.text)
            if min_level is not None and (lv is None or lv < min_level):
                return
            prefix = color("36", "%s: " % os.path.basename(ev.path)) if multi else ""
            body = ev.text
            if matcher:
                body = matcher.highlight(body, "\x1b[1;31m", "\x1b[0m") if color.on else body
            elif color.on:
                body = color(_level_color(lv), body)
            _out(prefix + body)
            sys.stdout.flush()
        else:
            msg = {"appeared": "文件出现", "recovered": "补读已被滚动走的新文件", "rotated": "检测到日志滚动（旧文件剩余内容已读完）",
                   "truncated": "文件被截断/清空，从头读取", "vanished": "文件被删除，等待重建",
                   "error": "读取错误"}.get(ev.kind, ev.kind)
            line = "[logfind] %s: %s %s" % (msg, ev.path, ev.text)
            print(color("35", line), file=sys.stderr)
            if session:
                session.archive.note(line)

    try:
        for ev in fol.follow(should_stop=lambda: stop["flag"]):
            handle(ev)
    except KeyboardInterrupt:
        pass
    finally:
        for ev in fol.close():
            handle(ev)
        if recorder:
            recorder.flush()
            if recorder.files:
                print("[logfind] 触发 %d 次，现场: %s" % (recorder.hit_count, session.hits_dir), file=sys.stderr)
        if session:
            session.update_meta(status="ok")
            session.close()
    return 0


# ---------- grep ----------
def cmd_grep(args) -> int:
    cfg = _cfg(args)
    prof = _profile(args, cfg)
    pos = list(args.args)
    patterns = list(args.regexp or [])
    for p in args.preset or []:
        patterns += PRESETS[p]
    if not patterns and not args.level and not args.since and not args.until:
        if not pos:
            print("logfind grep: 需要 PATTERN（或 -e / --preset / --level / --since）", file=sys.stderr)
            return 2
        patterns.append(pos.pop(0))
    elif not patterns and pos and not _exists_any(pos[0]):
        patterns.append(pos.pop(0))

    files: List[str] = []
    if args.session:
        for ref in args.session:
            files += resolve_session(cfg.home, ref).segments()
    files += expand_paths(pos or ([] if args.session else (prof.logs if prof else [])),
                          rotated=not args.no_rotated)
    if not files:
        print("logfind grep: 没有可搜索的文件（指定路径、-p profile 或 --session）", file=sys.stderr)
        return 2

    matcher = Matcher(patterns, fixed=args.fixed, ignore_case=args.ignore_case, invert=args.invert,
                      all_of=args.all)
    up_lo, up_hi = parse_uptime_range(args.uptime) if args.uptime else (None, None)
    boot = None
    if args.boot:
        boot = {"latest": -1, "last": -1, "prev": -2}.get(args.boot)
        if boot is None:
            boot = int(args.boot)
            if boot == 0:
                raise ValueError("--boot 从 1 开始（-1 表示最后一次开机）")
    clock_fix = bool(args.fix_clock or args.uptime or args.boot)
    filt = Filters(since=parse_time_spec(args.since) if args.since else None,
                   until=parse_time_spec(args.until) if args.until else None,
                   min_level=level_from_name(args.level) if args.level else None,
                   uptime_min=up_lo, uptime_max=up_hi, boot=boot)
    before = args.before if args.before is not None else args.context
    after = args.after if args.after is not None else args.context
    color = Color(_color_enabled(args.color))
    show_name = len(files) > 1 or bool(args.session)
    count = 0
    last_key = None
    per_file = {}
    for hit in search(files, matcher, filt, before, after, args.max_count,
                      encoding=args.encoding or "auto", multiline=not args.single_line,
                      clock_fix=clock_fix):
        rec = hit.record
        if hit.is_match:
            count += 1
            per_file[rec.path] = per_file.get(rec.path, 0) + 1
        if args.count or args.files_with_matches:
            continue
        if args.json:
            _out(json.dumps({"path": rec.path, "line": rec.lineno, "match": hit.is_match,
                             "ts": rec.ts.isoformat() if rec.ts else None,
                             "level": LEVEL_NAMES.get(rec.level) if rec.level else None,
                             "uptime": rec.uptime, "boot": rec.boot,
                             "text": rec.text}, ensure_ascii=False))
            continue
        key = (rec.path, hit.index)
        if (before or after) and last_key is not None and \
                (last_key[0] != rec.path or hit.index != last_key[1] + 1):
            _out(color("2", "--"))
        last_key = key
        sep = ":" if hit.is_match else "-"
        loc = color("35", rec.path) + sep if show_name else ""
        loc += color("32", str(rec.lineno)) + sep
        if clock_fix:
            loc += color("33", "[b%s +%s]" % (rec.boot or "?", format_uptime(rec.uptime))) + " "
        lines = rec.lines
        if args.max_lines and len(lines) > args.max_lines:
            lines = lines[: args.max_lines] + ["... (记录共 %d 行)" % len(rec.lines)]
        for i, line in enumerate(lines):
            text = matcher.highlight(line, "\x1b[1;31m", "\x1b[0m") if (color.on and hit.is_match) else line
            if hit.is_match and color.on and i == 0 and not matcher.regexes:
                text = color(_level_color(rec.level), text)
            _out((loc if i == 0 else " " * len(_strip(loc))) + text)
    if args.files_with_matches:
        for f in per_file:
            _out(f)
    elif args.count:
        for f in files:
            if per_file.get(f) or len(files) == 1:
                _out("%s:%d" % (f, per_file.get(f, 0)) if show_name else str(per_file.get(f, 0)))
    return 0 if count else 1


def _strip(s: str) -> str:
    from .textio import strip_ansi
    return strip_ansi(s)


def _exists_any(p: str) -> bool:
    import glob
    return os.path.exists(p) or bool(glob.has_magic(p) and glob.glob(p, recursive=True))


# ---------- sessions / show / hits ----------
def cmd_sessions(args) -> int:
    cfg = _cfg(args)
    sessions = list_sessions(cfg.home)
    if args.prune is not None:
        removed = prune_sessions(cfg.home, args.prune)
        print("已删除 %d 个旧会话" % len(removed))
        return 0
    if not sessions:
        print("还没有会话（%s）" % os.path.join(cfg.home, "sessions"))
        return 0
    for s in sessions[-args.limit:] if args.limit else sessions:
        m = s.read_meta()
        size = sum(os.path.getsize(x) for x in s.segments())
        cmd = m.get("command")
        _out("%-40s %-12s %-24s %8s  hits=%-3s %s" % (
            s.id, m.get("status", "?"), m.get("exit", ""), _human(size), len(s.hit_files()),
            " ".join(cmd)[:60] if isinstance(cmd, list) else (m.get("kind") or "")))
    return 0


def _human(n: float) -> str:
    for unit in ("B", "K", "M", "G"):
        if n < 1024:
            return ("%d%s" if unit == "B" else "%.1f%s") % (n, unit)
        n /= 1024
    return "%.1fT" % n


def cmd_show(args) -> int:
    cfg = _cfg(args)
    s = resolve_session(cfg.home, args.ref)
    color = Color(_color_enabled(args.color))
    if args.meta:
        _out(json.dumps(s.read_meta(), ensure_ascii=False, indent=2))
        return 0
    from collections import deque
    lines = s.iter_lines()
    if args.stream:
        lines = (l for l in lines if (parse_archive_line(l) or ("", "", ""))[1] in args.stream)
    if args.tail:
        lines = deque(lines, maxlen=args.tail)
    for line in lines:
        p = parse_archive_line(line)
        if args.raw or not p:
            _out(line)
            continue
        ts, src, text = p
        code = {"stderr": "31", "logfind": "35", "exception": "1;31"}.get(src, "36")
        ts_part = ts[11:] if not args.full_time else ts
        _out("%s %s %s" % (color("2", ts_part), color(code, "%-6s" % src), text))
    return 0


def cmd_hits(args) -> int:
    cfg = _cfg(args)
    sessions = [resolve_session(cfg.home, args.ref)] if args.ref else list_sessions(cfg.home)
    any_hit = False
    for s in sessions:
        for f in s.hit_files():
            any_hit = True
            if args.cat:
                _out("==> %s <==" % f)
                with open(f, encoding="utf-8", errors="replace") as fh:
                    sys.stdout.write(fh.read())
            else:
                _out(f)
    if not any_hit:
        print("没有触发记录", file=sys.stderr)
    return 0


# ---------- snap ----------
def _store(cfg: Config) -> SnapshotStore:
    return SnapshotStore(os.path.join(cfg.home, "snapshots"))


def cmd_snap(args) -> int:
    cfg = _cfg(args)
    prof = _profile(args, cfg)
    store = _store(cfg)
    color = Color(_color_enabled(getattr(args, "color", "auto")))
    act = args.snap_cmd
    label = getattr(args, "label", None)
    if label is None and prof is not None and act in ("take", "watch", "list", "diff", "prune"):
        label = prof.name

    if act == "take":
        paths = list(args.paths) or (prof.snapshots if prof else [])
        if not paths:
            print("logfind snap take: 请指定文件/目录/glob，或 -p profile", file=sys.stderr)
            return 2
        snap = store.take(paths, label=label or "", note=args.note or "")
        _print_snap_summary(snap, color)
        return 0 if snap.files else 1

    if act == "list":
        snaps = store.list(label)
        for i, s in enumerate(snaps):
            unstable = sum(1 for f in s.files.values() if not f.get("stable", True))
            _out("%3d  %-44s %4d 文件 %8s%s%s" % (
                i, s.id, len(s.files), _human(sum(f.get("size", 0) for f in s.files.values())),
                color("33", "  不稳定:%d" % unstable) if unstable else "",
                "  " + s.manifest.get("note", "") if s.manifest.get("note") else ""))
        if not snaps:
            print("没有快照", file=sys.stderr)
        return 0

    if act == "show":
        snap = store.resolve(args.ref, label)
        if not args.file:
            _out(json.dumps(snap.manifest, ensure_ascii=False, indent=2))
            return 0
        rel = snap.find(args.file)
        if rel is None:
            print("快照 %s 中没有 %s；包含: %s" % (snap.id, args.file, ", ".join(list(snap.files)[:20])),
                  file=sys.stderr)
            return 1
        data = snap.read(rel)
        try:
            sys.stdout.write(read_bytes_as_text(data))
        except Exception:
            sys.stdout.buffer.write(data)
        return 0

    if act == "diff":
        refs = list(args.refs)
        if args.live:
            a = store.resolve(refs[0] if refs else "latest", label)
            b = None
        else:
            if len(refs) == 0:
                refs = ["prev", "latest"]
            elif len(refs) == 1:
                refs = [refs[0], "latest"]
            a = store.resolve(refs[0], label)
            b = store.resolve(refs[1], label)
        diffs = diff_snapshots(a, b, tol=args.tol, context=args.context, only=args.only)
        _out(color("1", "对比 %s -> %s" % (a.id, b.id if b else "当前文件(live)")))
        changed = 0
        for d in diffs:
            if d.status == "same":
                if args.all:
                    _out("  = %s" % d.rel)
                continue
            changed += 1
            mark = {"added": color("32", "+ 新增"), "removed": color("31", "- 删除"),
                    "changed": color("33", "~ 修改")}[d.status]
            _out("%s %s" % (mark, d.rel))
            for line in d.details:
                if line.startswith("+") and not line.startswith("+++"):
                    line = color("32", line)
                elif line.startswith("-") and not line.startswith("---"):
                    line = color("31", line)
                elif line.startswith("@@"):
                    line = color("36", line)
                _out("    " + line)
        if not changed:
            _out("没有差异")
        return 1 if changed else 0

    if act == "watch":
        paths = list(args.paths) or (prof.snapshots if prof else [])
        if not paths:
            print("logfind snap watch: 请指定文件/目录/glob，或 -p profile", file=sys.stderr)
            return 2
        print("[logfind] 监视 %s，变化时自动快照（Ctrl+C 结束）" % ", ".join(paths), file=sys.stderr)

        def on_snap(s, changed):
            what = ("变化: " + ", ".join(os.path.relpath(c) for c in changed[:5])) if changed else "初始快照"
            print("[logfind] %s  %s" % (s.id, what), file=sys.stderr)

        try:
            store.watch(paths, interval=args.interval, label=label or "watch", keep=args.keep,
                        on_snapshot=on_snap)
        except KeyboardInterrupt:
            pass
        return 0

    if act == "prune":
        removed = store.prune(args.keep, label)
        print("已删除 %d 个快照" % len(removed))
        return 0
    return 2


def _print_snap_summary(snap, color) -> None:
    _out("快照 %s  (%d 个文件) -> %s" % (snap.id, len(snap.files), snap.directory))
    for rel, info in snap.files.items():
        flag = "" if info.get("stable", True) else color("33", "  [不稳定：文件一直在变化，内容可能不完整]")
        _out("  %-60s %8s%s" % (rel, _human(info["size"]), flag))
    for e in snap.manifest.get("errors", []):
        _out(color("31", "  失败 %s: %s" % (e["src"], e["error"])))


# ---------- adb ----------
def _adb(args):
    from .android import Adb
    su_cmd = None if getattr(args, "no_su", False) else args.su_cmd
    return Adb(serial=args.serial, adb=args.adb, su_cmd=su_cmd)


def cmd_adb(args) -> int:
    from . import android
    cfg = _cfg(args)
    act = args.adb_cmd
    if act == "bootlog" and args.action == "script":
        opts = android.BootlogOptions(directory=args.dir, buffer_size=args.size, buffers=args.buffers,
                                      keep=args.keep, rotate_kb=args.rotate_kb, rotate_count=args.rotate_count,
                                      anchor=args.anchor, extra=" ".join(args.logcat_arg or []))
        sys.stdout.write(android.bootlog_script(opts))
        return 0
    adb = _adb(args)

    if act == "logcat":
        extra = list(args.logcat_args)
        if extra and extra[0] == "--":
            extra = extra[1:]
        triggers = list(args.trigger or [])
        for p in args.preset or []:
            triggers += PRESETS[p]
        session = Session.create(cfg.home, args.name or "adb-logcat-%s" % (adb.serial or "device"),
                                 {"kind": "adb-logcat", "command": ["adb", "logcat"] + extra},
                                 max_segment_bytes=cfg.max_segment, max_total_bytes=cfg.max_total)
        prune_sessions(cfg.home, cfg.keep_sessions)
        print("[logfind] 记录到 %s（Ctrl+C 结束；设备重启后自动重连）" % session.directory, file=sys.stderr)
        streamer = android.LogcatStreamer(
            adb, session, buffers=args.buffers, buffer_size=args.buffer_size, logcat_args=extra,
            reconnect=not args.no_reconnect, max_connects=args.max_connects, anchor_interval=args.anchor,
            echo=not args.quiet, triggers=triggers,
            trigger_before=args.before if args.before is not None else 50,
            trigger_after=args.after if args.after is not None else 30,
            size_with_su=args.size_with_su)
        android.install_signal_stop(streamer)
        streamer.run()
        print("[logfind] 会话 %s：连接 %d 次，经历 %d 次开机，%d 行；"
              "按开机后时间检索: logfind grep --session %s --uptime 0-20s PATTERN"
              % (session.id, streamer.connects, streamer.boots, streamer.lines, session.id), file=sys.stderr)
        return 0

    if act == "pull":
        dest = args.output or os.path.join(cfg.home, "android", _slug_serial(adb.serialno()), "pull")
        if not args.no_su:
            adb.require_root()
        res = android.pull_paths(adb, args.remote, dest, su=not args.no_su, setenforce0=args.setenforce0)
        for f in res.files:
            _out(f)
        print("[logfind] 拉取 %d 个文件，%s -> %s" % (len(res.files), _human(res.bytes), dest), file=sys.stderr)
        if res.errors:
            print("[logfind] 设备端报错:\n  " + res.errors.replace("\n", "\n  "), file=sys.stderr)
            if "denied" in res.errors.lower():
                for line in android.selinux_diagnose(adb):
                    print("[logfind] " + line, file=sys.stderr)
                print("[logfind] 提示: 被 SELinux 拦截时可加 --setenforce0（拉取期间临时宽容模式，结束后恢复）",
                      file=sys.stderr)
        return 0 if res.files and not res.errors else 1

    # bootlog
    opts = android.BootlogOptions(directory=args.dir, buffer_size=args.size, buffers=args.buffers,
                                  keep=args.keep, rotate_kb=args.rotate_kb, rotate_count=args.rotate_count,
                                  anchor=args.anchor, extra=" ".join(args.logcat_arg or []))
    action = args.action
    if action == "install":
        android.install_bootlog(adb, opts, script_dir=args.script_dir, persist_size=not args.no_persist_size,
                                start_now=not args.no_start, log=_out)
        _out("之后每次开机都会自动落盘到 %s；拉取: logfind adb bootlog pull" % opts.directory)
        return 0
    if action == "uninstall":
        android.uninstall_bootlog(adb, args.dir, args.script_dir, purge=args.purge, reset_size=args.reset_size,
                                  log=_out)
        return 0
    adb.require_root()
    st = android.bootlog_status(adb, args.dir, args.script_dir)
    if action == "status":
        _out("开机脚本: %s    本次开机抓取中: %s    persist.logd.size=%s" % (
            "已安装" if st.get("script") == "yes" else "未安装", "是" if st.get("running") else "否",
            st.get("persist") or "(未设置)"))
        _out("当前 boot_id: %s" % st.get("boot_id", "?"))
        if st.get("buffers"):
            _out(st["buffers"])
        for b in st["boots"]:
            mark = " *" if b.get("boot_id") and b.get("boot_id") == st.get("boot_id") else ""
            _out("  %-10s %8s  %s  boot_id=%s  reason=%s%s" % (
                b["name"], _human(b["kb"] * 1024), b.get("date", "?"), (b.get("boot_id") or "?")[:8],
                b.get("bootreason") or "?", mark))
        if not st["boots"]:
            _out("  （设备上还没有开机记录；安装后重启一次即可）")
        return 0
    # pull
    boots = android.select_boots(st["boots"], args.boot or ["all"])
    dest_root = args.output or os.path.join(cfg.home, "android", _slug_serial(adb.serialno()))
    pulled = 0
    for b in boots:
        name = android.host_boot_name(b)
        dest = os.path.join(dest_root, name)
        live = b.get("boot_id") == st.get("boot_id")
        if os.path.isdir(dest) and not live and not args.force:
            _out("跳过 %s（已拉取过，--force 重新拉取）" % name)
            continue
        tmp = dest + ".partial"
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
        res = android.pull_paths(adb, [b["path"]], tmp, su=True)
        src = os.path.join(tmp, b["name"])
        if not os.path.isdir(src):
            print("拉取 %s 失败: %s" % (b["name"], res.errors or "没有数据"), file=sys.stderr)
            shutil.rmtree(tmp, ignore_errors=True)
            continue
        shutil.rmtree(dest, ignore_errors=True)
        os.replace(src, dest)
        shutil.rmtree(tmp, ignore_errors=True)
        pulled += 1
        _out("%s -> %s  (%d 个文件, %s)%s" % (b["name"], dest, len(res.files), _human(res.bytes),
                                          "  [本次开机，仍在写入]" if live else ""))
    if pulled:
        _out("检索开机头 20 秒: logfind grep --uptime 0-20s PATTERN %s" % os.path.join(dest_root, "<boot目录>"))
    return 0 if pulled or boots else 1


def _slug_serial(serial: str) -> str:
    import re
    return re.sub(r"[^\w.-]+", "_", serial) or "device"


# ---------- init ----------
def cmd_init(args) -> int:
    path = args.output
    if os.path.exists(path) and not args.force:
        print("%s 已存在（--force 覆盖）" % path, file=sys.stderr)
        return 1
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(EXAMPLE)
    print("已生成 %s，请按实际路径修改 profiles" % path)
    return 0


# ---------- 参数定义 ----------
def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", help="配置文件路径（默认向上查找 logfind.toml）")
    common.add_argument("--home", help="数据目录（默认 .logfind，或配置中的 home）")
    common.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    prof = argparse.ArgumentParser(add_help=False)
    prof.add_argument("-p", "--profile", help="使用配置中的 profile（如 mask / vector）")
    trig = argparse.ArgumentParser(add_help=False)
    trig.add_argument("-t", "--trigger", action="append", metavar="REGEX",
                      help="命中时保存前后上下文到 hits/（可多次指定）")
    trig.add_argument("--preset", action="append", choices=sorted(PRESETS),
                      help="内置规则集：crash=崩溃/异常/段错误/NaN 等")
    trig.add_argument("-B", "--before", type=int, default=None, help="命中前保留行数")
    trig.add_argument("-A", "--after", type=int, default=None, help="命中后保留行数")

    ap = argparse.ArgumentParser(prog="logfind", description="健壮的日志/快照捕获、跟踪、检索与对比工具")
    ap.add_argument("-V", "--version", action="version", version="logfind " + __version__)
    sub = ap.add_subparsers(dest="command", metavar="<子命令>")

    p = sub.add_parser("run", parents=[common, prof, trig],
                       help="运行命令并完整记录 stdout/stderr（防止被吞、被刷屏）",
                       description="例: logfind run -t ERROR -- python mask_main.py --cfg a.yaml")
    p.add_argument("--name", help="会话名")
    p.add_argument("-q", "--quiet", action="store_true", help="不在终端回显，只落盘")
    p.add_argument("--pty", action="store_true", help="(Linux/macOS) 用伪终端运行，程序会认为输出到终端而逐行刷新")
    p.add_argument("--merge", action="store_true", help="把 stderr 合并进 stdout（保证两者先后顺序）")
    p.add_argument("--no-unbuffer", action="store_true", help="不设置 PYTHONUNBUFFERED 等去缓冲环境变量")
    p.add_argument("--no-stdbuf", action="store_true", help="Linux 下不使用 stdbuf 包装")
    p.add_argument("--keep-ansi", action="store_true", help="归档中保留颜色控制符")
    p.add_argument("--encoding", help="子进程输出编码（默认自动识别 utf-8/gbk/utf-16）")
    p.add_argument("--cwd", help="工作目录")
    p.add_argument("--env", action="append", metavar="K=V", help="额外环境变量")
    p.add_argument("--tail-on-fail", type=int, default=30, help="失败时在末尾重新打印最后 N 行 stderr")
    p.add_argument("cmd", nargs=argparse.REMAINDER, help="要运行的命令（建议放在 -- 之后）")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("tail", parents=[common, prof, trig], help="实时跟踪日志文件（抗滚动/截断/重建）")
    p.add_argument("paths", nargs="*", help="文件或 glob（如 'logs/**/*.log'，记得加引号）")
    p.add_argument("-n", "--lines", type=int, default=10, help="开始时先显示最后 N 行")
    p.add_argument("-f", "--from-start", action="store_true", help="从文件开头读")
    p.add_argument("-g", "--grep", action="append", metavar="REGEX", help="只显示匹配的行（不影响记录）")
    p.add_argument("-i", "--ignore-case", action="store_true")
    p.add_argument("-l", "--level", help="只显示该级别及以上（debug/info/warn/error）")
    p.add_argument("-r", "--record", action="store_true", help="同时把所有行记录到会话归档")
    p.add_argument("--encoding", help="文件编码（默认自动识别）")
    p.add_argument("--interval", type=float, default=0.2, help="轮询间隔秒")
    p.set_defaults(func=cmd_tail, before=50, after=30)

    p = sub.add_parser("grep", parents=[common, prof],
                       help="检索日志（多行记录、时间/级别过滤、含滚动与压缩文件）",
                       description="例: logfind grep -C 3 --since 30m 'dimension' logs/  |  "
                                   "logfind grep --preset crash --session latest")
    p.add_argument("args", nargs="*", metavar="[PATTERN] [PATH]", help="正则和要搜索的文件/目录/glob")
    p.add_argument("-e", "--regexp", action="append", help="匹配规则（可多次，任一命中即可）")
    p.add_argument("--all", action="store_true", help="多个 -e 时要求全部命中")
    p.add_argument("--preset", action="append", choices=sorted(PRESETS))
    p.add_argument("-F", "--fixed", action="store_true", help="按普通字符串匹配")
    p.add_argument("-i", "--ignore-case", action="store_true")
    p.add_argument("-v", "--invert", action="store_true")
    p.add_argument("-C", "--context", type=int, default=0, help="前后各显示 N 条记录")
    p.add_argument("-B", "--before", type=int)
    p.add_argument("-A", "--after", type=int)
    p.add_argument("-m", "--max-count", type=int, default=0, help="每个文件最多 N 条匹配")
    p.add_argument("--since", help="起始时间: 30m / 2h / today / 14:30 / 2026-10-02 14:30:00")
    p.add_argument("--until", help="结束时间")
    p.add_argument("-l", "--level", help="最低级别 debug/info/warn/error/fatal")
    p.add_argument("-s", "--session", action="append", metavar="REF",
                   help="搜索 logfind 会话归档（latest / prev / -3 / ID 前缀）")
    p.add_argument("--no-rotated", action="store_true", help="不自动包含 app.log.1 / .gz 等滚动文件")
    p.add_argument("--single-line", action="store_true", help="不合并多行记录")
    p.add_argument("--max-lines", type=int, default=60, help="单条记录最多显示行数（0 不限）")
    p.add_argument("-c", "--count", action="store_true", help="只输出匹配数")
    p.add_argument("-L", "--files-with-matches", action="store_true", help="只输出有匹配的文件名")
    p.add_argument("--json", action="store_true", help="以 JSON Lines 输出")
    p.add_argument("--encoding")
    p.add_argument("--fix-clock", action="store_true",
                   help="校正设备时钟跳变（RTC 未同步、联网对时），--since/--until 按校正后的时间比较，"
                        "并显示 [第几次开机 +开机后秒数]")
    p.add_argument("--uptime", metavar="RANGE",
                   help="按开机后秒数过滤（不受时钟跳变影响）: 0-20s / 20s / 1m-2m / 30-；隐含 --fix-clock")
    p.add_argument("--boot", metavar="N",
                   help="只看文件内第 N 次开机（1 起；-1 / latest 为最后一次，prev 为倒数第二次）；隐含 --fix-clock")
    p.set_defaults(func=cmd_grep)

    p = sub.add_parser("sessions", parents=[common], help="列出捕获会话")
    p.add_argument("-n", "--limit", type=int, default=30)
    p.add_argument("--prune", type=int, metavar="KEEP", help="只保留最近 KEEP 个会话")
    p.set_defaults(func=cmd_sessions)

    p = sub.add_parser("show", parents=[common], help="查看某个会话的完整输出")
    p.add_argument("ref", nargs="?", default="latest", help="latest / prev / -2 / ID 前缀")
    p.add_argument("-n", "--tail", type=int, help="只看最后 N 行")
    p.add_argument("--stream", action="append", help="只看某个来源: stdout / stderr / log / exception / logfind")
    p.add_argument("--raw", action="store_true", help="原样输出归档行")
    p.add_argument("--full-time", action="store_true", help="显示完整日期")
    p.add_argument("--meta", action="store_true", help="显示会话元信息（命令、退出码、耗时等）")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("hits", parents=[common], help="列出/查看触发器保存的现场")
    p.add_argument("ref", nargs="?", help="会话（默认全部）")
    p.add_argument("--cat", action="store_true", help="直接输出内容")
    p.set_defaults(func=cmd_hits)

    p = sub.add_parser("snap", help="快照：稳定拷贝、列表、查看、对比、监视")
    ss = p.add_subparsers(dest="snap_cmd", metavar="<动作>")
    q = ss.add_parser("take", parents=[common, prof], help="拍快照（等待文件写完、校验 JSON 完整性）")
    q.add_argument("paths", nargs="*")
    q.add_argument("-L", "--label", help="标签，用于分组（默认 profile 名）")
    q.add_argument("-m", "--note", help="备注")
    q = ss.add_parser("list", parents=[common, prof], help="列出快照")
    q.add_argument("-L", "--label")
    q = ss.add_parser("show", parents=[common, prof], help="查看快照清单或其中某个文件")
    q.add_argument("ref", nargs="?", default="latest")
    q.add_argument("file", nargs="?")
    q.add_argument("-L", "--label")
    q = ss.add_parser("diff", parents=[common, prof], help="对比快照（默认 prev 对 latest）")
    q.add_argument("refs", nargs="*", help="A B；只给一个时与 latest 对比")
    q.add_argument("--live", action="store_true", help="与磁盘上当前文件对比")
    q.add_argument("--tol", type=float, default=0.0, help="数值相对容差（浮点向量对比用，如 1e-6）")
    q.add_argument("-U", "--context", type=int, default=3)
    q.add_argument("--only", action="append", help="只对比路径包含该字符串的文件")
    q.add_argument("--all", action="store_true", help="也列出未变化的文件")
    q.add_argument("-L", "--label")
    q = ss.add_parser("watch", parents=[common, prof], help="监视文件，变化时自动快照")
    q.add_argument("paths", nargs="*")
    q.add_argument("-i", "--interval", type=float, default=1.0)
    q.add_argument("-k", "--keep", type=int, default=200, help="最多保留快照数（0 不限）")
    q.add_argument("-L", "--label")
    q = ss.add_parser("prune", parents=[common, prof], help="清理旧快照")
    q.add_argument("-k", "--keep", type=int, required=True)
    q.add_argument("-L", "--label")
    p.set_defaults(func=cmd_snap)

    adbopt = argparse.ArgumentParser(add_help=False)
    adbopt.add_argument("-s", "--serial", help="设备序列号（默认 $ANDROID_SERIAL 或唯一连接的设备）")
    adbopt.add_argument("--adb", help="adb 可执行文件路径（默认 PATH 中的 adb 或 $ADB）")
    adbopt.add_argument("--su-cmd", default="su -c",
                        help="设备上以 root 执行命令的写法（默认 'su -c'；如 'su 0 -c'）")
    p = sub.add_parser("adb", help="Android：开机日志落盘、跨重启自动重连 logcat、绕过 SELinux 拉文件",
                       description="logfind adb logcat | logfind adb bootlog install/status/pull/uninstall | "
                                   "logfind adb pull /data/adb/lspd/log")
    asub = p.add_subparsers(dest="adb_cmd", metavar="<动作>")
    q = asub.add_parser("logcat", parents=[common, trig, adbopt],
                        help="流式抓 logcat；设备重启 / adb 断开（exit 255）后自动等待并重连",
                        description="例: logfind adb logcat -G 16M --preset android -- '*:V'")
    q.add_argument("-b", "--buffers", default="all", help="logcat -b（默认 all）")
    q.add_argument("-G", "--buffer-size", help="每次开机连上后执行 logcat -G（扩容不跨重启，这里每次重做）")
    q.add_argument("--size-with-su", action="store_true", help="用 su 执行 -G（部分机型 shell 无权修改）")
    q.add_argument("--no-reconnect", action="store_true", help="断开后不重连")
    q.add_argument("--max-connects", type=int, default=0, help="最多连接 N 次后结束（0 不限）")
    q.add_argument("--anchor", type=float, default=10.0, help="时钟锚点间隔秒（0 关闭）")
    q.add_argument("-q", "--quiet", action="store_true", help="不在终端回显")
    q.add_argument("--name", help="会话名")
    q.add_argument("logcat_args", nargs=argparse.REMAINDER, help="传给 logcat 的额外参数（放在 -- 之后）")
    q = asub.add_parser("bootlog", parents=[common, adbopt],
                        help="开机即落盘：post-fs-data 阶段启动 logcat 写文件，每次开机重做 -G（需要 root）",
                        description="install: 安装开机脚本 | status: 查看 | pull: 拉回主机 | "
                                    "uninstall: 删除 | script: 只打印脚本内容")
    q.add_argument("action", choices=("install", "status", "pull", "uninstall", "script"))
    q.add_argument("--dir", default="/data/local/tmp/logfind", help="设备上的落盘目录")
    q.add_argument("--script-dir", default="/data/adb/post-fs-data.d",
                   help="开机脚本目录（Magisk / KernelSU / APatch 通用，默认 post-fs-data.d）")
    q.add_argument("-G", "--size", default="16M", help="每次开机执行的 logcat -G 大小（0 不修改）")
    q.add_argument("-b", "--buffers", default="all")
    q.add_argument("--keep", type=int, default=5, help="设备上保留最近几次开机")
    q.add_argument("--rotate-kb", type=int, default=8192, help="单个日志文件大小（KB）")
    q.add_argument("--rotate-count", type=int, default=8, help="每次开机最多几个日志文件")
    q.add_argument("--anchor", type=int, default=10, help="时钟锚点间隔秒（开机头 2 分钟固定 2 秒）")
    q.add_argument("--logcat-arg", action="append", help="额外 logcat 参数（如 '*:V'，可多次）")
    q.add_argument("--no-persist-size", action="store_true", help="不设置 persist.logd.size")
    q.add_argument("--no-start", action="store_true", help="安装后不立即开始抓本次开机")
    q.add_argument("--boot", action="append", help="pull: all / latest / prev / -N / 序号（可多次，默认 all）")
    q.add_argument("-o", "--output", help="pull: 主机目录（默认 <home>/android/<序列号>/）")
    q.add_argument("--force", action="store_true", help="pull: 已拉取过的也重新拉")
    q.add_argument("--purge", action="store_true", help="uninstall: 同时删除设备上的落盘目录")
    q.add_argument("--reset-size", action="store_true", help="uninstall: 同时清除 persist.logd.size")
    q = asub.add_parser("pull", parents=[common, adbopt],
                        help="用 exec-out + su + tar 把受限目录流回主机（不落中间文件，避开 SELinux 上下文问题）",
                        description="例: logfind adb pull /data/adb/lspd/log /data/system/packages.xml")
    q.add_argument("remote", nargs="+", help="设备上的文件或目录")
    q.add_argument("-o", "--output", help="主机目录（默认 <home>/android/<序列号>/pull）")
    q.add_argument("--no-su", action="store_true", help="不使用 su")
    q.add_argument("--setenforce0", action="store_true",
                   help="拉取期间临时 setenforce 0，结束后恢复 Enforcing（仅在确认被 SELinux 拦截时使用）")
    p.set_defaults(func=cmd_adb)

    p = sub.add_parser("init", help="在当前目录生成 logfind.toml 示例配置")
    p.add_argument("-o", "--output", default="logfind.toml")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    _fix_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None) or (args.command == "snap" and not args.snap_cmd):
        parser.print_help() if not getattr(args, "func", None) else \
            parser.parse_args(["snap", "-h"])
        return 2
    if args.command == "adb" and not args.adb_cmd:
        parser.parse_args(["adb", "-h"])
        return 2
    try:
        return args.func(args)
    except (LookupError, ValueError, RuntimeError) as e:
        print("logfind: %s" % e, file=sys.stderr)
        return 2
    except BrokenPipeError:
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        return 0


if __name__ == "__main__":
    sys.exit(main())

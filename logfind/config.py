"""项目配置：在当前目录或上级目录查找 logfind.toml / .logfind.toml / logfind.json。

示例见 logfind.example.toml，可以为“面具模块”“Vector 模块”等分别定义 profile。
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

CONFIG_NAMES = ("logfind.toml", ".logfind.toml", "logfind.json", ".logfind.json")
ENV_HOME = "LOGFIND_HOME"
ENV_CONFIG = "LOGFIND_CONFIG"


def _load_toml(path: str) -> Dict[str, Any]:
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore
        except ImportError:
            raise RuntimeError("读取 %s 需要 Python 3.11+ 或安装 tomli；也可以改用 logfind.json" % path)
    with open(path, "rb") as fh:
        return tomllib.load(fh)


def find_config(start: Optional[str] = None) -> Optional[str]:
    env = os.environ.get(ENV_CONFIG)
    if env:
        return env
    d = os.path.abspath(start or os.getcwd())
    while True:
        for n in CONFIG_NAMES:
            p = os.path.join(d, n)
            if os.path.isfile(p):
                return p
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


@dataclass
class Profile:
    name: str
    logs: List[str] = field(default_factory=list)
    snapshots: List[str] = field(default_factory=list)
    triggers: List[str] = field(default_factory=list)
    command: List[str] = field(default_factory=list)
    encoding: str = "auto"
    env: Dict[str, str] = field(default_factory=dict)
    cwd: Optional[str] = None
    trigger_before: int = 50
    trigger_after: int = 30


@dataclass
class Config:
    path: Optional[str] = None
    home: str = ".logfind"
    profiles: Dict[str, Profile] = field(default_factory=dict)
    max_segment: str = "16MB"
    max_total: str = "1GB"
    keep_sessions: int = 100

    def profile(self, name: Optional[str]) -> Optional[Profile]:
        if not name:
            return None
        if name not in self.profiles:
            raise KeyError("配置中没有 profile %r（可用: %s）%s" % (
                name, ", ".join(sorted(self.profiles)) or "无",
                "" if self.path else "；未找到配置文件，可运行 `logfind init` 生成"))
        return self.profiles[name]


def _as_list(v) -> List[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    return [str(x) for x in v]


def load_config(path: Optional[str] = None) -> Config:
    path = path or find_config()
    if not path:
        return Config(home=os.environ.get(ENV_HOME, ".logfind"))
    raw = _load_toml(path) if path.endswith(".toml") else json.load(open(path, encoding="utf-8"))
    base = os.path.dirname(os.path.abspath(path))

    def rel(p: str) -> str:
        p = os.path.expanduser(os.path.expandvars(p))
        return p if os.path.isabs(p) else os.path.join(base, p)

    cfg = Config(path=path)
    cfg.home = os.environ.get(ENV_HOME) or rel(raw.get("home", ".logfind"))
    cfg.max_segment = raw.get("max_segment", cfg.max_segment)
    cfg.max_total = raw.get("max_total", cfg.max_total)
    cfg.keep_sessions = int(raw.get("keep_sessions", cfg.keep_sessions))
    for name, p in (raw.get("profiles") or {}).items():
        cfg.profiles[name] = Profile(
            name=name,
            logs=[rel(x) for x in _as_list(p.get("logs"))],
            snapshots=[rel(x) for x in _as_list(p.get("snapshots"))],
            triggers=_as_list(p.get("triggers")),
            command=_as_list(p.get("command")),
            encoding=p.get("encoding", "auto"),
            env={str(k): str(v) for k, v in (p.get("env") or {}).items()},
            cwd=rel(p["cwd"]) if p.get("cwd") else None,
            trigger_before=int(p.get("trigger_before", 50)),
            trigger_after=int(p.get("trigger_after", 30)),
        )
    return cfg


def default_home() -> str:
    try:
        return load_config().home
    except Exception:
        return os.environ.get(ENV_HOME, ".logfind")


EXAMPLE = '''# logfind 配置文件。路径相对于本文件所在目录，支持 glob（** 递归）与 ~ / $ENV。
home = ".logfind"          # 归档、快照、触发记录的存放目录
max_segment = "16MB"       # 单个归档分段大小
max_total = "1GB"          # 单个会话归档总上限（超出后删除最旧分段）
keep_sessions = 100        # 最多保留多少个会话

[profiles.mask]            # 面具模块
logs = ["logs/mask/**/*.log", "/tmp/mask_*.log"]
snapshots = ["out/mask/snapshots/*.json", "out/mask/*.npy"]
triggers = ["ERROR", "Traceback", "Segmentation fault", "NaN"]
command = ["python", "-m", "mask.main"]
encoding = "auto"          # auto / utf-8 / gbk / utf-16 ...

[profiles.vector]          # Vector 模块
logs = ["logs/vector/*.log"]
snapshots = ["out/vector/state/**/*"]
triggers = ["(?i)error", "dimension mismatch", "nan"]
trigger_before = 100
trigger_after = 40

[profiles.vector.env]
RUST_BACKTRACE = "1"
'''

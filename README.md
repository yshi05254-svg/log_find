# logfind — 健壮的日志 / 快照读取工具

开发面具模块、Vector 模块这类程序时，常见的问题有：

| 问题 | 典型原因 | logfind 的做法 |
| --- | --- | --- |
| 日志**被吞** | stdout 被管道全缓冲，进程崩溃/被 kill 时缓冲区丢失；C 扩展直接写 fd；logger 级别过高或 `propagate=False` | `run` 自动去缓冲（`PYTHONUNBUFFERED`、`stdbuf`、可选 `--pty`）；`capture()` 在 fd 层重定向并在退出前 `fflush`；临时把 logging 降到 DEBUG 采集但不改变控制台输出 |
| 日志**被刷掉** | 终端滚屏、日志滚动/覆盖（rename、copytruncate）、新文件替换旧文件 | 所有输出带时间戳落盘归档；`tail` 先读完旧文件再切到新文件，并补读来不及跟踪就被滚动走的文件；触发器把命中前后的上下文单独存档 |
| 崩溃**没留现场** | 段错误、abort、OOM 被杀 | 识别信号/Windows 异常码；`PYTHONFAULTHANDLER` 打出 C 层崩溃栈；失败时在末尾重印最后 N 行 stderr；`--preset crash` 一键检索崩溃特征 |
| 快照**读到一半** | 读的时候对方还在写 | 等文件大小/mtime 稳定、并校验 JSON 完整性后再拷贝；写快照用临时文件加 rename，保证原子性 |
| 快照**难对比** | JSON 结构大、浮点向量逐元素对比会刷屏 | 结构化 JSON diff；长数值数组给出汇总（不同元素个数、最大差、NaN 个数）；支持容差 `--tol`；`.npy` 对比（需要 numpy） |
| 编码乱码 | Windows 工具输出 GBK、UTF-16 | 自动识别 UTF-8 / GBK(GB18030) / UTF-16 / UTF-32，逐行回退解码，永不因编码报错 |

纯 Python 标准库实现，无第三方依赖，支持 Python 3.8+，兼容 Linux / macOS / Windows。被监控的程序可以用任何语言编写（C++、Python、Rust 等都行）。

## 安装

```bash
pip install -e .          # 安装后得到 logfind 命令
# 或不安装，直接：python -m logfind ...
```

## 快速上手

```bash
# 1. 运行程序，输出照常显示，同时完整落盘；遇到崩溃特征时自动保存上下文
logfind run --preset crash -t "dimension mismatch" -- python mask_main.py --cfg a.yaml

# 2. 回看：会话列表 / 完整输出 / 只看 stderr / 触发现场
logfind sessions
logfind show                    # 最新会话
logfind show prev --stream stderr -n 50
logfind hits --cat

# 3. 实时跟踪日志文件（抗滚动、截断、删除重建、GBK/UTF-16）
logfind tail 'logs/**/*.log' -l warn -t ERROR -r

# 4. 检索：异常栈作为一条记录，支持时间/级别过滤，自动包含 app.log.1、app.log.2.gz
logfind grep -C 2 --since 30m "nan|inf" logs/
logfind grep --preset crash --session latest
logfind grep -l error --since today -c logs/

# 5. 快照：拍摄、对比、监视
logfind snap take out/vector/state.json out/mask/ -L vector -m "调参前"
logfind snap diff                     # prev 对 latest
logfind snap diff --tol 1e-6 -L vector
logfind snap diff --live              # 最新快照 对 磁盘上当前文件
logfind snap watch out/vector/ -i 0.5 # 文件一变化就自动快照（未变的文件用硬链接，不占空间）
logfind snap show prev state.json
```

## 面具模块：开机日志（post-fs-data 常驻 logcat）

开机早期（zygote / system_server 起来之前、框架侧装钩的那段时间）的日志，等开机后再 `adb logcat` 往往已经被环形缓冲区冲掉了。
`logfind android` 把“post-fs-data 阶段启动常驻 logcat 写文件”这一套做成了命令：

```bash
# 1. 生成脚本并写进模块：没有 post-fs-data.sh 就新建；已有的话只插入/更新一段带标记的代码
#    （插在末尾 exit 之前，原文件备份为 .bak，统一转成 LF 换行，重复执行不会重复插入）
logfind android script -o my_module/
logfind android script                       # 只打印脚本
logfind android script -o my_module/ --size 32M --count 5 -b all   # 调整轮转/缓冲区

# 2. 刷入模块、重启后检查：常驻 logcat 是否在跑、日志文件大小
logfind android status

# 3. 拉回本地（含 boot.log.1、boot.log.2 等轮转文件，保留设备上的修改时间）
#    logcat 以 root 创建的文件 shell 用户读不了，adb pull 失败时会自动改用 su 读取
logfind android pull                         # -> .logfind/android/<时间>_<设备>/
logfind android list

# 4. 检索（最旧的轮转文件排在前面，按时间顺序阅读）
logfind grep --android latest --preset android          # Java 崩溃 / native tombstone / ANR / avc denied ...
logfind grep --android latest -l error "MyHook|LSPosed"
logfind grep --android prev -C 5 "Fatal signal"
```

生成的脚本（默认值与原来手写的 ven11 脚本一致）：

```sh
#!/system/bin/sh
# >>> logfind bootlog >>>
# 由 logfind android script 生成，重复执行会原地更新这一段。
# 常驻 logcat，post-fs-data 阶段启动（早于 zygote/system_server），
# 完整记录含框架侧装钩在内的开机窗口；16M×3 轮转防写爆 /data。
BOOTLOG_DIR=/data/local/tmp/ven11/log
mkdir -p "$BOOTLOG_DIR"
chmod 777 "$BOOTLOG_DIR"
if ! pgrep -f "$BOOTLOG_DIR/boot.log" >/dev/null 2>&1; then
  /system/bin/logcat -v time -f "$BOOTLOG_DIR/boot.log" -r 16384 -n 3 >/dev/null 2>&1 &
fi
# <<< logfind bootlog <<<
exit 0
```

目录、文件名、轮转大小/个数、格式、缓冲区、设备序列号都可以在命令行（`--dir --log-name --size --count --format -b -s`）或配置文件的 `[android]` 段里改。
`-v time` 和 `-v threadtime` 格式的级别、时间都能识别，`-l error` 不会把正文里含 “Error” 的 I 级别日志误算进来。

## 配置文件（按模块分 profile）

运行 `logfind init` 生成 `logfind.toml`（完整示例见 [logfind.example.toml](logfind.example.toml)）：

```toml
home = ".logfind"

[profiles.mask]
logs = ["logs/mask/**/*.log"]
snapshots = ["out/mask/snapshots/*.json"]
triggers = ["ERROR", "Traceback", "Segmentation fault", "NaN"]
command = ["python", "-m", "mask.main"]

[profiles.vector]
logs = ["logs/vector/*.log"]
snapshots = ["out/vector/state/**/*"]
triggers = ["(?i)error", "dimension mismatch"]
```

之后就可以：

```bash
logfind run -p mask             # 运行 profile 中的 command，并使用其中的 triggers
logfind tail -p vector
logfind grep -p mask --preset crash
logfind snap take -p vector && logfind snap diff -p vector
```

配置文件会从当前目录向上查找，也可以用 `--config` 或环境变量 `LOGFIND_CONFIG` 指定，数据目录可以用 `--home` 或 `LOGFIND_HOME` 指定。

## 在 Python 代码中使用

```python
import logfind

# 抓取本进程全部输出：print、logging（含 DEBUG、propagate=False 的 logger）、
# C/C++ 扩展的 printf、未捕获异常（含子线程）；段错误调用栈写入 crash-faulthandler.log
with logfind.capture(name="mask"):
    run_mask_pipeline()

# 原子地保存内存对象快照：dict/list → .json，numpy 数组 → .npy，其它对象 → .pkl + repr
logfind.snap({"step": step, "vec": vec, "mask": mask}, label="vector")

# 对文件拍快照（等待写完再拷贝）
logfind.snap_files(["out/vector/*.json"], label="vector")

# 安全地写自己的快照文件，读者永远不会读到写了一半的内容
logfind.atomic_write("out/state.json", json.dumps(state).encode())

# 读取可能正在被写入的文件
data, stable = logfind.read_stable("out/state.json", validator=logfind.textio.json_validator)

# 程序化检索
from logfind.search import Matcher, Filters, expand_paths, search
for hit in search(expand_paths(["logs/"], rotated=True), Matcher(["dimension"]), Filters(min_level=40)):
    print(hit.record.path, hit.record.lineno, hit.record.text)
```

之后用 `logfind show` / `logfind grep --session latest ...` 查看捕获的内容。

## 数据目录结构

```
.logfind/
├── android/<时间>_<设备>/          # logfind android pull：boot.log、boot.log.1 ... 和 meta.json
├── sessions/<时间>_<名字>/
│   ├── meta.json                 # 命令、工作目录、退出码/信号、耗时、各流行数
│   ├── seg-000001.log            # 归档：2026-10-02T20:22:01.123 [stderr] 文本
│   ├── hits/*.txt                # 触发器保存的上下文（>> 标记命中行）
│   └── crash-faulthandler.log    # capture() 模式下的段错误调用栈
└── snapshots/<时间>_<标签>/
    ├── manifest.json             # 源路径、大小、sha256、mtime、是否稳定
    └── files/...                 # 文件副本（保留相对路径）
```

归档是普通文本，任何编辑器、`grep`、`less` 都能直接打开。单个会话默认最多 1GB（按 16MB 分段滚动），默认保留最近 100 个会话，可在配置中调整。

## 命令速查

| 命令 | 作用 |
| --- | --- |
| `run [-t RE] [--preset crash] [--pty] [--merge] -- CMD...` | 运行并记录；`--merge` 合并 stdout 和 stderr，保证两者的先后顺序；`--pty` 让 C 程序以为输出到终端而逐行刷新 |
| `tail PATHS [-n N] [-f] [-g RE] [-l LEVEL] [-t RE] [-r]` | 实时跟踪；`-r` 同时归档，`-t` 触发存档 |
| `grep [PATTERN] [PATHS] [-e RE] [-C N] [--since] [--until] [-l LEVEL] [-s SESSION] [--json]` | 检索 |
| `sessions [--prune KEEP]` / `show [REF] [--stream] [-n] [--meta]` / `hits [REF] [--cat]` | 会话管理 |
| `snap take/list/show/diff/watch/prune` | 快照 |
| `android script/status/pull/list` | 面具模块开机日志：生成/合并 post-fs-data 常驻 logcat 脚本，查看状态，拉回本地；`grep --android REF` 检索 |
| `init` | 生成示例配置 |

会话和快照的引用写法：`latest`、`prev`、`-3`（倒数第 3 个）、ID 前缀。

## 注意事项

- stdout 和 stderr 是两根独立的管道，归档里两者的交错顺序以到达时间为准。需要严格的先后顺序时用 `--merge`。
- copytruncate 方式的滚动，如果在“复制”和“清空”之间又有写入，这部分内容本身就会丢失（这是该滚动方式的固有缺陷）。logfind 能识别出截断（包括清空后马上写入更多内容的情况），并从头重新读取。
- Windows 下 `tail` 不会长期占用文件句柄（否则写入方无法滚动日志），改为通过文件 ID 找到被改名的旧文件补读。

## 测试

```bash
python -m unittest discover -s tests -v
```

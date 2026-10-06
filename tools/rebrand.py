#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rebrand.py -- 把项目从旧名 (RegGuard / global-inject-demo / global-inject-lib)
              整体改名为新名 (R3 ShieldCore / R3ShieldCore)。

为什么要有这个工具
==================
改名的影响面是 370+ 个文件，而其中一批名字是**运行期承重**的：

  · `global-inject-lib.dll`  —— 引擎 exe 按**固定路径**去找注入 DLL
                                (app.cpp 拼 `<部署根>\\32|64\\global-inject-lib.dll`，
                                 ark_actions.cpp 还用 _wcsicmp 比这个名字)
  · `regguard.ini`           —— 引擎会**写回**它 (app.cpp)，配置文件
  · `regguard-events.log`    —— 拦截事件落盘
  · `engine-console.log`     —— printf 重定向目标 (app.cpp RedirectDiagnosticsToFile)
  · `REGGUARD_*`             —— 4 个环境变量开关
  · `RegGuardKernel`         —— 内核驱动服务名 / 设备名

**改漏任何一处都不是"报错"，而是静默失效** —— 引擎找不到 DLL 就不注入，
找不到 ini 就用默认值，日志写到另一个文件里去。所以改名必须**可验证**：
`--check` 就是那条断言 —— 改完之后全仓**必须**再找不到任何一个旧 token。

设计要点
========
1. **逐文件编码保真**：仓库里混着 UTF-8（源码/文档）、GBK+CRLF（.bat）、
   UTF-8+BOM（.ps1）。本工具先探测每个文件的编码，解码成 str 再替换，
   最后**按原编码原 BOM 状态写回**。绝不整仓按一种编码读写。

   （不直接做 bytes 级替换的原因：GBK 的双字节序列的**尾字节**落在
     0x40-0x7E，也就是 ASCII 字母区，理论上旧 token 可能从某个汉字的
     第二个字节开始"撞"上。解码成 str 就完全没这个问题。）

2. **映射表有序**：长 token 在前。`global-inject-demo-x64.exe` 必须先于
   `global-inject-demo` 被替换，否则会被切碎成 `R3ShieldCore-x64.exe`。

3. **include / exclude 是白名单制**：只动源码、脚本、文档、当前发布目录；
   历史证据（旧版本快照 dist/*-vNN、构建产物 obj/Release/Debug、
   _probe_results、.log、.zip、.exe）一律不碰 —— 那些是**当时的实测记录**，
   改了就等于篡改证据。

用法
====
    python tools/rebrand.py --check     # 只报告：还有哪些文件含旧 token（改完必须是 0）
    python tools/rebrand.py --apply     # 执行替换
    python tools/rebrand.py --check --verbose

退出码：--check 发现残留 => 1；干净 => 0。
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# 备份目录（放在 .workbuddy-ai/backup 下，那个前缀本身在扫描排除表里，
# 所以备份不会被再次改名）
BACKUP_ROOT = REPO / ".workbuddy-ai" / "backup"

# ---------------------------------------------------------------------------
# 映射表（有序！长 token 在前）
# ---------------------------------------------------------------------------
# 每一项: (旧, 新, 说明)
# 说明只用于报告，不参与替换。
MAPPING: list[tuple[str, str, str]] = [
    # --- 主程序 exe（必须最先，否则被 global-inject-demo 规则切碎） ---
    ("global-inject-demo-x64.exe", "R3 ShieldCore.exe",
     "x64 主程序（发布用的那个）"),
    ("global-inject-demo.exe",     "R3 ShieldCore-x86.exe",
     "x86 主程序"),
    # 探针用 Get-Process -Name / tasklist imagename（不带扩展名）
    ("global-inject-demo-x64",     "R3 ShieldCore",
     "探针按进程名找/杀主程序"),

    # --- 注入 DLL（运行期固定名，硬耦合） ---
    ("global-inject-lib.dll",      "r3shieldcore-lib.dll",
     "注入 DLL 固定名（app.cpp / ark_actions.cpp 硬编码）"),
    ("global-inject-lib",          "R3ShieldCoreLib",
     "DLL 工程目录名"),

    # --- 解决方案 / 工程目录 ---
    ("global-inject.sln",          "R3ShieldCore.sln",
     "解决方案文件"),
    ("global-inject-demo",         "R3ShieldCore",
     "工程根目录 / exe 工程目录 / 各处路径引用"),

    # --- 构建期专用开关（注意：这是单 G 的 REGUARD，不是 REGGUARD） ---
    ("REGUARD_NO_UAC",             "R3SHIELDCORE_NO_UAC",
     "build.sh 的免提权验证开关（原名单 G，grep REGGUARD 找不到它）"),

    # --- 环境变量开关（4 个，前缀一起换） ---
    ("REGGUARD_",                  "R3SHIELDCORE_",
     "环境变量开关前缀（ARK_ACTION / EXIT_AFTER_MS / START_TAB / START_TOPMOST）"),

    # --- C++ 标识符 / 显示名 / 服务名 / 窗口类名 ---
    ("RegGuard",                   "R3ShieldCore",
     "类名、命名空间、服务名、设备名、界面标题"),

    # --- 文件名（小写形式）：ini / log / 源码文件 / 清单 / 驱动 ---
    ("regguard",                   "r3shieldcore",
     "regguard.ini / regguard-events.log / regguard_*.cpp / regguard-uac.manifest / regguard_kernel.c"),

    # --- 无品牌但属承重的运行期文件名 ---
    ("engine-console.log",         "r3shieldcore-console.log",
     "printf 重定向目标（app.cpp RedirectDiagnosticsToFile）"),
    ("engine-startup-error.log",   "r3shieldcore-startup-error.log",
     "启动失败日志（start.bat 引用）"),

    # --- 蛇形命名（和 camelCase 的 RegGuard 是两套写法，别漏） ---
    #     reg_guard_channel.h / reg_guard_rules.cpp / reg_guard_shared.h /
    #     reg_guard_prompt_ui.cpp —— 共 130 个文件里出现，主要在 #include 里。
    ("reg_guard_",                 "r3shieldcore_",
     "蛇形命名的源码文件名与 #include 路径"),

    # --- ★ 大小写变体（v65 实测漏网过） ---
    #
    # 教训：映射表是**大小写敏感**的，所以 `RegGuard` / `regguard` / `REGGUARD_`
    # 这三条**覆盖不到** `GLOBAL-INJECT-LOG` 这种全大写写法。
    # 漏掉的后果：DLL 的日志前缀还是旧名，`strings -el` 一扫就能看见，
    # 而 `--check` 却是绿的（因为它只查映射表里那几个精确 token）。
    #
    # 所以这里补上大小写变体，并且给 `--check` 加一条**大小写不敏感**的残留扫描
    # （见 check_case_insensitive_residue），让这类漏洞不再靠"碰巧想起来"。
    ("GLOBAL-INJECT-VERBOSE",      "R3SHIELDCORE-VERBOSE",
     "DLL 日志前缀（logger.h，大写变体）"),
    ("GLOBAL-INJECT-LOG",          "R3SHIELDCORE-LOG",
     "DLL 日志前缀（logger.h，大写变体）"),
    ("GLOBAL-INJECT",              "R3SHIELDCORE",
     "大写变体兜底"),
    # 注意：**不能**加 `("Global-Injection", ...)` —— 外部博客 URL
    #       m417z.com/Implementing-Global-Injection-and-Hooking-in-Windows/
    #       里就是这个词，改了链接就废了。
    ("global-inject",              "r3shieldcore",
     "小写变体兜底（URL 里的 Global-Injection 首字母大写，不会被这条命中）"),
    ("Reguard",                    "R3ShieldCore",
     "旧名的手误变体（原 netcheck-diag.bat 里的 findstr 关键字）"),
]

# 这些子串**永远不要改**（外部 URL / 第三方标识）。
KEEP_SUBSTRINGS = (
    "m417z.com/Implementing-Global-Injection-and-Hooking-in-Windows",
)

# ---------------------------------------------------------------------------
# 大小写不敏感的残留词根
# ---------------------------------------------------------------------------
# `--check` 除了比对 MAPPING 里的精确 token，还会用这组**词根**做
# 大小写不敏感的扫描。任何命中（扣掉 KEEP_SUBSTRINGS 之后）都算残留。
#
# 这一条是为了堵住"映射表大小写敏感"造成的盲区 —— 真实案例：
# `[GLOBAL-INJECT-LOG]` 逃过了 `RegGuard`/`regguard`/`REGGUARD_` 三条规则。
RESIDUE_STEMS = ("global-inject", "regguard", "reg_guard")

# 允许"故意保留旧名"的行：行内出现这个标记就跳过该行的替换。
KEEP_MARKER = "rebrand-keep"

# ★ 块级标记（v65 新增）：`rebrand-keep:start` … `rebrand-keep:end` 之间**整段**跳过。
#   为什么需要它：memory 里有"改名映射表""版本记录"这类**成段的历史**，
#   旧名必须逐条列出来。只支持行级标记的话，就得给 14 行连续加 `<!-- rebrand-keep -->`，
#   把一张本来给人读的表格毁成噪音。
#   ★ 注意 KEEP_BLOCK_START 里**包含** KEEP_MARKER 子串，所以判定顺序不能反：
#     先判 end、再判 start、最后才判行级 marker。
KEEP_BLOCK_START = "rebrand-keep:start"
KEEP_BLOCK_END = "rebrand-keep:end"


def keep_mask(lines: list[str]) -> list[bool]:
    """逐行判定"是否属于故意保留旧名的范围"（行级标记 ∪ 块级标记）。"""
    mask: list[bool] = []
    in_block = False
    for ln in lines:
        if KEEP_BLOCK_END in ln:
            in_block = False
            mask.append(True)
        elif KEEP_BLOCK_START in ln:
            in_block = True
            mask.append(True)
        elif in_block or KEEP_MARKER in ln:
            mask.append(True)
        else:
            mask.append(False)
    return mask

# ---------------------------------------------------------------------------
# 扫描范围
# ---------------------------------------------------------------------------
# 只扫这些**根**（相对仓库根）。
#
# ★★★【坑】这些根**必须跟着改名一起改**（v65 实测踩到）：
#   改名把 `global-inject-demo/` 变成了 `R3ShieldCore/`，而这里还写着旧路径
#   ⇒ os.walk 找不到目录就**静默跳过** ⇒ 扫描文件数从 367 掉到 243，
#     整个源码树根本没被扫，而 `--check` 照样报"✓ 干净"。
#     结果：`logger.h` 的 `[GLOBAL-INJECT-LOG]` 一直没改，直到用
#     `strings -el` 扫二进制才发现。
#   ⇒ 所以下面有 ROOT_ASSERT 断言：声明的根**必须存在**，否则直接 FAIL。
INCLUDE_ROOTS = [
    "R3ShieldCore",                # 源码树（内部再按 EXCLUDE_DIRS 过滤）
    "driver",                      # R0 内核组件
    "tools",                       # 探针 / 测试 / 闸门脚本
    "docs",                        # 文档
    "dist/R3ShieldCore-x64",       # 当前发布目录（手写脚本 + 配置 + 文档）
    ".workbuddy-ai/memory",        # 项目记忆
]

# 仓库根目录下的散文件（用 glob，避免漏掉新加的 build_*.sh）
INCLUDE_ROOT_GLOBS = [
    "*.sh", "*.bat", "*.cmd", "*.md", "*.py", "*.xml", "*.ini",
]

# 目录名命中即整棵子树跳过
#
# ★ `verification` 必须排除：那底下是**当时的实测证据**
#   （*.out / *.err / *.diff / *.patch / *.recipe / *.tlog /
#     *.lastbuildstate / *.before / *.original），
#   记录的是"某次跑出来是什么"。改名工具去改它 = 篡改证据。
EXCLUDE_DIRS = {
    "obj", "_t", "verdir", ".git", ".svn", ".vs",
    "Debug", "Release", "RelV53", "RelV53x64", "x64", "Win32",
    "libraries", "build", "backup", "verification",
    "BuildCheck", "ArkTest",
    "_probe_results", "_zip_tmp", "node_modules", "__pycache__",
}

# 相对仓库根的路径前缀命中即跳过（历史快照 / 旧发布物）
EXCLUDE_PATH_PREFIXES = [
    "dist/RegGuard-x64-v",
    "dist/build",
    ".workbuddy-ai/backup",
]

# 按扩展名跳过（二进制 / 证据 / 快照）
EXCLUDE_EXT = {
    ".exe", ".dll", ".lib", ".obj", ".sys", ".pdb", ".ilk", ".exp",
    ".zip", ".7z", ".rar", ".gz", ".tar",
    ".png", ".jpg", ".jpeg", ".bmp", ".ico", ".gif", ".webp",
    ".log", ".etl", ".dmp", ".map", ".res", ".tlb", ".cache",
    ".pdf", ".docx", ".xlsx", ".pptx",
    # --- 探针输出转储（tools/*.txt、tools/logrun/*）也是证据 ---
    ".txt",
    # --- 历史证据 / 构建中间态（这些是"当时跑出来是什么"的记录） ---
    ".out", ".err", ".diff", ".patch", ".recipe", ".tlog",
    ".lastbuildstate", ".test", ".before", ".original", ".highbak",
    ".bak", ".tmp", ".suo", ".user",
}

# 文件名里含这些片段就跳过（备份文件）
EXCLUDE_NAME_PARTS = (".bak", "~", ".orig")

# 扩展名在黑名单里、但**路径**落在这里面时仍然要改。
# 当前发布目录 dist/RegGuard-x64/ 里的 .txt 是随包文档（预设说明.txt），
# 不是探针输出，必须跟着改名。
ALLOW_EXT_PATHS = ("dist/R3ShieldCore-x64/",)
# ★ 但只放行这几个扩展名 —— 那个目录里还有 *.log（跑出来的事件日志），
#   那是证据，不能碰。
ALLOW_EXT_ONLY = {".txt"}

# ★ 本工具自己的文件名 —— 必须排除！
#   它的 MAPPING 表里写满了旧 token（"RegGuard" / "regguard" / …），
#   一旦被自己扫到，映射表会被替换成 ("R3ShieldCore", "R3ShieldCore")，
#   整个工具当场失效。
SELF_EXCLUDE = ("tools/rebrand.py",)

# 超过这个大小就不扫（正常文本文件不会这么大）
MAX_SIZE = 8 * 1024 * 1024


# ---------------------------------------------------------------------------
# 编码探测
# ---------------------------------------------------------------------------
def decode_text(raw: bytes) -> tuple[str, str, bool] | None:
    """返回 (文本, 编码, 是否带 BOM)；无法解码则返回 None（当作二进制跳过）。"""
    if raw.startswith(b"\xef\xbb\xbf"):
        try:
            return raw.decode("utf-8-sig"), "utf-8", True
        except UnicodeDecodeError:
            return None
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return None  # UTF-16 的 .bat/.ps1 在本项目里是错误状态，不动它
    # 含 NUL 的按二进制处理
    if b"\x00" in raw[:4096]:
        return None
    try:
        return raw.decode("utf-8"), "utf-8", False
    except UnicodeDecodeError:
        pass
    try:
        return raw.decode("gbk"), "gbk", False
    except UnicodeDecodeError:
        return None


def encode_text(text: str, encoding: str, bom: bool) -> bytes:
    out = text.encode(encoding)
    if bom:
        out = b"\xef\xbb\xbf" + out
    return out


# ---------------------------------------------------------------------------
# 扫描
# ---------------------------------------------------------------------------
def is_excluded(path: Path) -> bool:
    rel = path.relative_to(REPO)
    relposix = rel.as_posix()

    for prefix in EXCLUDE_PATH_PREFIXES:
        if relposix.startswith(prefix):
            return True
    if relposix in SELF_EXCLUDE:
        return True
    if path.suffix.lower() in EXCLUDE_EXT:
        if not (path.suffix.lower() in ALLOW_EXT_ONLY
                and relposix.startswith(ALLOW_EXT_PATHS)):
            return True
    for part in EXCLUDE_NAME_PARTS:
        if part in path.name:
            return True
    for part in rel.parts[:-1]:
        if part in EXCLUDE_DIRS:
            return True
    return False


def iter_files() -> list[Path]:
    """返回要扫描的文件。

    ★ 正向对照：INCLUDE_ROOTS 里声明的根**必须存在**。
      不存在就说明根路径写错了（改名后没跟着改），此时**绝不能**静默返回空集
      —— 那会让 --check 假绿。所以直接抛异常，调用方报错退出。
    """
    missing = [r for r in INCLUDE_ROOTS if not (REPO / r).is_dir()]
    if missing:
        raise SystemExit(
            "!!! rebrand.py 扫描根不存在：" + ", ".join(missing) + "\n"
            "    这通常意味着项目刚改过名，而 INCLUDE_ROOTS 还指着旧路径。\n"
            "    修好根路径再跑 —— 否则 --check 会在'什么都没扫'的情况下报绿。")

    out: list[Path] = []
    for root in INCLUDE_ROOTS:
        base = REPO / root
        for dirpath, dirnames, filenames in os.walk(base):
            d = Path(dirpath)
            # 原地裁掉被排除的子目录，避免白走
            dirnames[:] = [
                n for n in dirnames
                if n not in EXCLUDE_DIRS
                and not (d / n).relative_to(REPO).as_posix().startswith(tuple(EXCLUDE_PATH_PREFIXES))
            ]
            for name in filenames:
                p = d / name
                if is_excluded(p):
                    continue
                out.append(p)
    for pattern in INCLUDE_ROOT_GLOBS:
        for p in sorted(REPO.glob(pattern)):
            if p.is_file() and not is_excluded(p):
                out.append(p)
    return sorted(set(out))


def read_text(path: Path) -> tuple[str, str, bool] | None:
    """读文件并解码；失败返回 None。"""
    try:
        if path.stat().st_size > MAX_SIZE:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    return decode_text(raw)


def count_hits(text: str) -> int:
    return sum(text.count(old) for old, _, _ in MAPPING)


# ---------------------------------------------------------------------------
# KEEP_SUBSTRINGS 的掩码保护
# ---------------------------------------------------------------------------
# 替换前先把"绝不能改"的子串换成占位符，替换完再换回来。
# 这样即使以后有人加了一条更宽的映射规则，也不会把外部 URL 改坏。
_KEEP_OPEN = "\x01"
_KEEP_CLOSE = "\x02"


def mask_keeps(text: str) -> tuple[str, list[str]]:
    saved: list[str] = []
    for sub in KEEP_SUBSTRINGS:
        while sub in text:
            idx = text.index(sub)
            ph = f"{_KEEP_OPEN}{len(saved)}{_KEEP_CLOSE}"
            saved.append(sub)
            text = text[:idx] + ph + text[idx + len(sub):]
    return text, saved


def unmask_keeps(text: str, saved: list[str]) -> str:
    for i, sub in enumerate(saved):
        text = text.replace(f"{_KEEP_OPEN}{i}{_KEEP_CLOSE}", sub)
    return text


def case_insensitive_residue(text: str) -> list[str]:
    """返回大小写不敏感扫描命中的残留（已扣掉 KEEP_SUBSTRINGS）。"""
    masked, _ = mask_keeps(text)
    low = masked.lower()
    out: list[str] = []
    for stem in RESIDUE_STEMS:
        if stem in low:
            out.append(stem)
    return out


# ---------------------------------------------------------------------------
# 单文件处理
# ---------------------------------------------------------------------------
def process_file(path: Path, apply: bool, verbose: bool) -> tuple[int, int, int, list[str]]:
    """返回 (旧token命中次数, 改动行数, 替换次数, 大小写不敏感残留词根)。"""
    dec = read_text(path)
    if dec is None:
        return (0, 0, 0, [])
    text, encoding, bom = dec
    lines = text.splitlines(keepends=True)

    # ★ hits 必须**只统计没标 rebrand-keep 的行**（行级 + 块级，见 keep_mask）。
    #   否则：标了 keep 的历史行被正确跳过（不替换），但 count_hits 仍然
    #   把它们算进去 ⇒ --check 永远报残留 ⇒ 假警报，闸门失去意义。
    #   （实测踩过：tools/check_env_switch_names.py 的 3 处历史引用。）
    mask = keep_mask(lines)
    hits = sum(count_hits(ln) for ln, kept in zip(lines, mask) if not kept)

    # 大小写不敏感的残留：同样跳过 keep 范围
    residue: set[str] = set()
    for line, kept in zip(lines, mask):
        if kept:
            continue
        residue.update(case_insensitive_residue(line))

    if hits == 0 and not residue:
        return (0, 0, 0, [])

    new_lines: list[str] = []
    changed_lines = 0
    replaced = 0

    for line, kept in zip(lines, mask):
        if kept:
            new_lines.append(line)
            continue
        new_line = line
        # 先保护"绝不能改"的子串
        masked, saved = mask_keeps(new_line)
        for old, new, _ in MAPPING:
            n = masked.count(old)
            if n:
                masked = masked.replace(old, new)
                replaced += n
        new_line = unmask_keeps(masked, saved)
        if new_line != line:
            changed_lines += 1
        new_lines.append(new_line)

    new_text = "".join(new_lines)
    if new_text != text and apply:
        path.write_bytes(encode_text(new_text, encoding, bom))

    if verbose or not apply:
        rel = path.relative_to(REPO).as_posix()
        kinds = sorted({note for old, _, note in MAPPING if old in text})
        tag = f"{hits} 处" + (f" + 残留 {sorted(residue)}" if residue else "")
        print(f"  {'[改]' if apply else '[留]'} {rel}  ({tag} / {changed_lines} 行)")
        for k in kinds:
            print(f"        - {k}")

    return (hits, changed_lines, replaced, sorted(residue))


def new_name(name: str) -> str:
    """把 MAPPING 作用到**文件名/目录名**上。"""
    out = name
    for old, new, _ in MAPPING:
        out = out.replace(old, new)
    return out


def collect_rename_targets() -> list[Path]:
    """找出所有"名字里还含旧 token"的文件和目录（排除证据/产物）。"""
    found: list[Path] = []
    prefixes = tuple(EXCLUDE_PATH_PREFIXES)
    # 当前发布目录：这里面的**二进制**也要跟着改名（exe / dll）
    LIVE_DIST = "dist/R3ShieldCore-x64/"
    LIVE_DIST_BIN_EXT = {".exe", ".dll"}

    def walk(d: Path) -> None:
        try:
            entries = sorted(d.iterdir(), key=lambda p: p.name)
        except OSError:
            return
        for e in entries:
            rel = e.relative_to(REPO).as_posix()
            renamed = new_name(e.name) != e.name
            if e.is_dir():
                if e.name in EXCLUDE_DIRS:
                    continue
                if rel.startswith(prefixes):
                    continue
                if e.name.startswith(".backup"):
                    continue
                if renamed:
                    found.append(e)
                walk(e)
                continue

            if not renamed:
                continue
            if rel.startswith(prefixes):
                continue
            ext = e.suffix.lower()
            if ext in EXCLUDE_EXT:
                # 二进制只在当前发布目录里改（旧快照 / 日志 / zip 一律不动）
                if not (rel.startswith(LIVE_DIST) and ext in LIVE_DIST_BIN_EXT):
                    continue
            found.append(e)

    walk(REPO)
    # 深度倒序：先改深层的文件，再改它们的父目录，避免路径失效
    found.sort(key=lambda p: len(p.relative_to(REPO).parts), reverse=True)
    return found


def do_rename(apply: bool) -> int:
    targets = collect_rename_targets()
    print(f"[改名] 待改名条目 {len(targets)} 个")
    if not targets:
        return 0

    if apply:
        stamp = time.strftime("%Y-%m-%d-%H%M%S")
        log = BACKUP_ROOT / f"{stamp}-rename.tsv"
        log.parent.mkdir(parents=True, exist_ok=True)
        lines: list[str] = []

    done = 0
    for p in targets:
        rel = p.relative_to(REPO)
        nn = new_name(p.name)
        dst = p.with_name(nn)
        if apply:
            if not p.exists():
                print(f"  [跳] {rel} —— 已不存在（父目录先被改了？）")
                continue
            try:
                p.rename(dst)
            except OSError as ex:
                print(f"  [败] {rel} -> {nn}  ({ex})")
                continue
            lines.append(f"{rel}\t{dst.relative_to(REPO).as_posix()}")
            print(f"  [改] {rel}  ->  {dst.relative_to(REPO).as_posix()}")
        else:
            print(f"  [留] {rel}  ->  {dst.relative_to(REPO).as_posix()}")
        done += 1

    if apply:
        log.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"[改名] {done} 个条目已改名；清单 -> {log}")
    else:
        print(f"[改名] 将改 {done} 个条目（--check 模式，未落盘）")
    return done


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="项目整体改名工具")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true", help="只检查残留（改完必须是 0 命中）")
    g.add_argument("--apply", action="store_true", help="执行文本替换")
    g.add_argument("--rename-check", action="store_true",
                   help='列出「名字里还含旧 token」的文件/目录（不改）')
    g.add_argument("--rename", action="store_true",
                   help="执行文件/目录改名（按深度倒序）")
    ap.add_argument("--verbose", "-v", action="store_true", help="逐文件打印")
    args = ap.parse_args()

    if args.rename_check:
        return 1 if do_rename(apply=False) else 0
    if args.rename:
        do_rename(apply=True)
        return 0

    files = iter_files()

    # ---- 执行前先备份（本仓库没有 git，改名不可逆） ----
    if args.apply:
        stamp = time.strftime("%Y-%m-%d-%H%M%S")
        backup_dir = BACKUP_ROOT / f"{stamp}-rebrand"
        n = 0
        for p in files:
            dec = read_text(p)
            if dec is None or count_hits(dec[0]) == 0:
                continue
            dst = backup_dir / p.relative_to(REPO)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, dst)
            n += 1
        print(f"[备份] {n} 个待改文件 -> {backup_dir}")

    total_hits = 0
    total_changed = 0
    total_replaced = 0
    touched: list[str] = []
    residue_files: list[str] = []

    for p in files:
        h, c, r, res = process_file(p, apply=args.apply, verbose=args.verbose)
        total_hits += h
        total_changed += c
        total_replaced += r
        if c:
            touched.append(p.relative_to(REPO).as_posix())
        if res:
            residue_files.append(
                f"{p.relative_to(REPO).as_posix()}  ->  {', '.join(res)}")

    mode = "APPLY" if args.apply else "CHECK"
    print()
    print(f"=== rebrand.py {mode} ===")
    print(f"  扫描文件数      : {len(files)}")
    print(f"  命中旧 token 数 : {total_hits}")
    print(f"  涉及文件数      : {len(touched)}")
    print(f"  改动行数        : {total_changed}")
    if args.apply:
        print(f"  替换次数        : {total_replaced}")
        print()
        print("  下一步：再跑一次 --check，必须是 0 命中、0 残留。")
        return 0

    fail = False
    if total_hits:
        print()
        print("  ✗ 还有精确 token 残留 —— 改名没完成，或又有人把旧名写回来了。")
        print("    （若某行确实要保留旧名，在该行加 rebrand-keep 标记。）")
        fail = True
    if residue_files:
        print()
        print(f"  ✗ {len(residue_files)} 个文件有**大小写不敏感**残留"
              f"（词根 {', '.join(RESIDUE_STEMS)}）：")
        for r in residue_files:
            print(f"    {r}")
        print()
        print("  这一类是映射表大小写敏感造成的盲区（真实案例：[GLOBAL-INJECT-LOG]）。")
        print("  要么补一条映射，要么在那一行加 rebrand-keep（历史记录/外部 URL）。")
        fail = True

    if fail:
        return 1
    print()
    print("  ✓ 干净：精确 token 0 命中，大小写不敏感扫描 0 残留。")
    return 0


if __name__ == "__main__":
    sys.exit(main())

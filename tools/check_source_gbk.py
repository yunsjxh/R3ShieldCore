#!/usr/bin/env python3
"""
check_source_gbk.py —— 找出 MSVC 在中文代码页(936)下**放不下**的字符。

为什么需要这个闸门（铁律 46 的检测器）：

    MSVC 在中文系统上默认用 CP936 生成"执行字符集"。源文件里如果出现一个
    GBK **编不出**的字符（例如 U+26A0 警告三角、U+21D2 推出箭头），
    编译器只会给一条 **warning C4566**，然后**把这个字符直接丢掉** ——
    于是窄字符串字面量被静默改写：

        printf("⚠ 校验失败\\n");   →  实际输出  " 校验失败\\n"

    没有 error、没有乱码、没有异常，只是那句话里少了一个字。
    本仓库已经因为这一类问题栽过（见铁律 46）。

    注意：`-source-charset:utf-8` **挡不住**它 —— 那个开关管的是"怎么读源文件"，
    而 C4566 管的是"能不能写进执行字符集"。两个问题不同。

================================================================================
★ v66 修正一：只扫**字面量**，不扫注释（这条改动本身就是铁律 142 的实例）
================================================================================

    C4566 是**字面量**的警告。注释里的 `⇒` / emoji **不会**产生 C4566，
    编译器连看都不看。而本脚本 v65 之前是**整份文件逐字符扫**的 ——
    于是全仓 5700+ 个"问题"里绝大多数是注释，闸门**恒红**。
    恒红的闸门等于**没有闸门**：谁都不看它，真出事也照样绿。

================================================================================
★ v66 修正二：区分**窄**与**宽/UTF-8** 字面量（实测，不是查文档）
================================================================================

    v66 之前本脚本把 `L"⚠ %s 想要启动高危程序"` 也报成问题 —— 那是**假 FAIL**。
    铁律 127：假 FAIL 比漏报更贵（它会让整个闸门被无视）。

    实测口径（探针 `_t/gbkprobe/p2.cpp`，cl.exe -std:c++20 -source-charset:utf-8
    -W3，中文系统 CP936；下面每行都是**真跑出来**的，不是查文档抄的）：

        行 3   const char*    a = "narrow ⚠";        → warning C4566  ★会丢字
        行 4   const wchar_t* b = L"wide ⚠";         → 无
        行 5   const char8_t* c = u8"u8 ⚠";          → 无（u8 = UTF-8 执行字符集）
        行 6   const char16_t* d = u"u16 ⚠";         → 无
        行 7   const char32_t* e = U"u32 ⚠";         → 无
        行 11  char           i = '⚠';               → warning C4566  ★会丢字
        行 12  wchar_t        j = L'⚠';              → 无
        （另测 `R"(raw ⚠)"` 窄原始串 → warning C4566）

    ⇒ 只有**窄**字面量会被 C4566 丢字：
        会丢：`"..."`  `'...'`  `R"(...)"`
        安全：`L` / `u` / `U` / `u8` 前缀（含它们的 `R` 变体 `LR` `uR` `UR` `u8R`）

    ★ 还有一个**只按源文本扫就整类漏掉**的写法 —— `\\uXXXX` 转义：
        行 3   const char* a = "A \\u26A0 B";   → **warning C4566**
      源文本里全是 ASCII，但编译器先把 `\\u26A0` 还原成 U+26A0，
      再往 CP936 执行字符集里塞 ⇒ 塞不进去照样丢字。
      ⇒ 本脚本在**窄**字面量里单独解析 `\\uXXXX` / `\\UXXXXXXXX` 并按码点查。
        （`\\xNN` / 八进制 `\\NNN` 产生的是**字节**而非码点，不经过这层转换，不查。）

================================================================================
★ v66 修正三：允许行内豁免（否则一条合法假阳性就能让闸门再次恒红）
================================================================================

    已知假阳性：`TEXT("⚠")` / `_T("⚠")` 这类**宏**。宏展开后是 `L"⚠"`（安全），
    但本脚本只看源文本，看到的窄字面量 ⇒ 会误报。
    遇到这种，在**该行**加 `// gbk-ok` 即可豁免（行尾标记，grep 得到、审得动）。

================================================================================
★ v66 修正四：本闸门自带负对照（铁律 128）
================================================================================

    `tools/gbk_gate_fixture.txt` 是**故意的**坏夹具（含窄字面量 / `\\u` 转义 /
    宽字面量 / u8 字面量 / 注释 / 豁免行 六种情况），
    `tools/selftest_gbk_gate.py` 断言它被检出**恰好**该检出的那几处。

    ★ 为什么必须有：本脚本在 v65 是**恒红**的（全仓 5700+ 处，绝大多数是注释）
      —— 一个恒红的闸门和一个恒绿的闸门一样没用。
      没有负对照，"我修好了"就只是一句话；有了负对照，
      "它会红、而且只在真该红的时候红"才是被证明过的事实。

用法：
    python tools/check_source_gbk.py driver/r3shieldcore_kernel.c driver/driver_probe.c
    python tools/check_source_gbk.py --all                # 扫全仓 .c/.cpp/.h（仅字面量）
    python tools/check_source_gbk.py --all --comments     # 连注释一起查（严格模式）
退出码：0 = 全部安全；1 = 有不安全字符
"""

import os
import sys

# 内核/驱动源码目录：这些文件的字符串都用中文，最容易被 C4566 咬到
DEFAULT_TARGETS = [
    "driver/r3shieldcore_kernel.c",
    "driver/driver_probe.c",
    "service/r3shieldcore_svc.c",
]

SCAN_EXTS = (".c", ".cpp", ".h", ".hpp")

# ★ 实测：这些前缀的执行字符集**一定**能表示任意 Unicode ⇒ 不会 C4566。
#   见文件头"修正二"的探针结果。其余（含空前缀）都按**窄**字面量处理。
SAFE_PREFIXES = {"L", "u", "U", "u8", "LR", "uR", "UR", "u8R"}

# 行内豁免标记。
SUPPRESS_MARK = "gbk-ok"

# 目录黑名单：这些目录里的源文件**不参与构建**，扫它们只会制造噪声。
SKIP_DIRS = {"obj", "_t", "build", "dist", ".git", "libraries", "verdir", "demo",
             "backup", "verification"}


def scan(path, include_comments=False):
    """返回 (bad, err)。

    bad = [(行号, 列号, 字符, 码点, 位置, 字面量前缀)]
    err = None 或错误串。

    ★ 实现是一个**极简 C/C++ 词法器**，只为回答一个问题：
      "这个字符在不在**窄**字面量里？"
      它不追求完备（不展开宏、不解析原始字符串的精确边界、不处理预处理分支），
      只要求**在"把注释或宽字面量误判成窄字面量"这件事上不犯错** ——
      因为误判会直接制造假 FAIL（铁律 127）。
    """
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        return None, str(e)

    # 源文件按 UTF-8 读（本仓约定）；带 BOM 也认
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        return None, "不是合法 UTF-8: %s" % e

    # 预先切行，供行内豁免判断。
    lines = text.split("\n")

    bad = []
    n = len(text)
    i = 0
    line = 1
    col = 1
    state = "code"          # code | line_comment | block_comment | string | char
    narrow = True           # 当前字面量是否是"窄"的（会被 C4566 丢字）
    prefix = ""             # 当前字面量的前缀，用于诊断输出

    def bump(ch):
        nonlocal line, col
        if ch == "\n":
            line += 1
            col = 1
        else:
            col += 1

    def suppressed(lineno):
        """该行是否带 `// gbk-ok` 豁免标记。"""
        if 1 <= lineno <= len(lines):
            return SUPPRESS_MARK in lines[lineno - 1]
        return False

    def prefix_before(idx):
        """取 `idx` 前紧邻的标识符（字面量前缀），如 `L` / `u8R` / `R`。"""
        j = idx - 1
        while j >= 0 and (text[j].isalnum() or text[j] == "_"):
            j -= 1
        return text[j + 1:idx]

    while i < n:
        ch = text[i]

        # ---------------- 代码态 ----------------
        if state == "code":
            if text.startswith("//", i):
                state = "line_comment"
                bump("/"); bump("/")
                i += 2
                continue
            if text.startswith("/*", i):
                state = "block_comment"
                bump("/"); bump("*")
                i += 2
                continue
            if ch == '"' or ch == "'":
                prefix = prefix_before(i)
                narrow = prefix not in SAFE_PREFIXES
                state = "string" if ch == '"' else "char"
                bump(ch)
                i += 1
                continue
            bump(ch)
            i += 1
            continue

        # ---------------- 行注释 ----------------
        if state == "line_comment":
            if include_comments and ord(ch) >= 128 and not suppressed(line):
                _check_gbk(ch, line, col, "comment", "", bad)
            if ch == "\n":
                state = "code"
            bump(ch)
            i += 1
            continue

        # ---------------- 块注释 ----------------
        if state == "block_comment":
            if text.startswith("*/", i):
                state = "code"
                bump("*"); bump("/")
                i += 2
                continue
            if include_comments and ord(ch) >= 128 and not suppressed(line):
                _check_gbk(ch, line, col, "comment", "", bad)
            bump(ch)
            i += 1
            continue

        # ---------------- 字符串 / 字符字面量 ----------------
        if state in ("string", "char"):
            if ch == "\\":
                # ★ 转义里有一类**必须单独查**：`\uXXXX` / `\UXXXXXXXX`。
                #
                #   为什么（实测，见文件头探针 p.cpp 第 3 行）：
                #     `const char* a = "A \u26A0 B";`  → **warning C4566**
                #   源文本里全是 ASCII，但编译器先把它还原成 U+26A0，
                #   再往 CP936 执行字符集里塞 —— 塞不进去就丢字。
                #   只按"源文本里的非 ASCII 字符"扫会**整类漏掉**这种写法。
                #
                #   注：`\xNN` / `\NNN`（八进制）产生的是**字节**而不是码点，
                #   不经过码点→执行字符集的转换 ⇒ 不会 C4566，不查。
                esc = text[i + 1] if i + 1 < n else ""
                if esc in ("u", "U"):
                    hexlen = 4 if esc == "u" else 8
                    hexs = text[i + 2:i + 2 + hexlen]
                    if len(hexs) == hexlen and all(
                            c in "0123456789abcdefABCDEF" for c in hexs):
                        cp = int(hexs, 16)
                        if narrow and not (0xD800 <= cp <= 0xDFFF) and cp <= 0x10FFFF \
                                and not suppressed(line):
                            _check_gbk(chr(cp), line, col, state,
                                       prefix + "\\" + esc, bad)
                        for k in range(2 + hexlen):
                            if i + k < n:
                                bump(text[i + k])
                        i += 2 + hexlen
                        continue

                # 其余转义：跳过下一个字符（它可能是 `\"` / `\\` / `\n`）。
                bump(ch)
                i += 1
                if i < n:
                    bump(text[i])
                    i += 1
                continue
            if (state == "string" and ch == '"') or (state == "char" and ch == "'"):
                state = "code"
                narrow = True
                prefix = ""
                bump(ch)
                i += 1
                continue
            # ★ 只查**窄**字面量 —— 宽/UTF-8 字面量不会 C4566（见文件头探针）。
            if narrow and ord(ch) >= 128 and not suppressed(line):
                _check_gbk(ch, line, col, state, prefix, bad)
            bump(ch)
            i += 1
            continue

    return bad, None


def _check_gbk(ch, line, col, where, prefix, bad):
    try:
        ch.encode("gbk")
    except UnicodeEncodeError:
        bad.append((line, col, ch, ord(ch), where, prefix))


def gather_all(root):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        # 跳过产物/第三方/临时/快照目录
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn.lower().endswith(SCAN_EXTS):
                out.append(os.path.join(dirpath, fn))
    return sorted(out)


def main():
    argv = sys.argv[1:]
    include_comments = "--comments" in argv
    want_all = "--all" in argv
    args = [a for a in argv if not a.startswith("--")]

    if want_all:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        targets = gather_all(root)
        print("扫描全仓 %d 个源文件（范围：%s）..."
              % (len(targets), "窄字面量 + 注释" if include_comments else "仅窄字面量"))
    elif args:
        targets = args
    else:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        targets = [os.path.join(root, t) for t in DEFAULT_TARGETS]

    total_bad = 0
    files_bad = 0
    missing = []

    for path in targets:
        bad, err = scan(path, include_comments)
        if bad is None:
            if "No such file" in err or not os.path.exists(path):
                missing.append(path)
            else:
                print("[FAIL] %s —— %s" % (path, err))
                total_bad += 1
                files_bad += 1
            continue
        if bad:
            total_bad += len(bad)
            files_bad += 1
            print("[FAIL] %s —— %d 个字符在 CP936 下编不出（会被 C4566 静默丢掉）:"
                  % (path, len(bad)))
            for line, col, ch, cp, where, prefix in bad[:40]:
                print("        行 %d 列 %d  %r  U+%04X  [%s%s]"
                      % (line, col, ch, cp, where,
                         (" 前缀=" + prefix) if prefix else ""))
            if len(bad) > 40:
                print("        ...（还有 %d 处）" % (len(bad) - 40))
            print("       修法：换成 ASCII 写法（例如 ⚠ → [!]、⇒ → ->），"
                  "或把该字面量改成宽字面量 L\"...\"（宽字面量不受 C4566 影响）；"
                  "确属合法假阳性（如 TEXT(\"...\") 宏）可在该行加 `// %s` 豁免。"
                  % SUPPRESS_MARK)

    for path in missing:
        print("[INFO] 跳过不存在的文件: %s" % path)

    print()
    if total_bad == 0:
        print("PASS: 所有窄字面量在 CP936 执行字符集下都能完整表示。")
        return 0
    print("FAIL: %d 个文件、共 %d 个字符会被静默丢弃 —— 先修掉再编译。"
          % (files_bad, total_bad))
    return 1


if __name__ == "__main__":
    sys.exit(main())

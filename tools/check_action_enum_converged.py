#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_action_enum_converged.py -- 决策档位 `Action` 必须是**共享的那一个**。

为什么需要这个闸门
==================
v74 之前，**17 个 guard 各自在 .cpp 里定义了一份一模一样**的

    enum class Action { Pass, Record, Block };

（例：`file_guard.cpp:130-135`）。多写几份的代价不是重复几行，而是
**同一个概念在 17 处独立演化** —— 事实也正是如此：

  · v67 只给 `screen_guard` 加了 `Spoof`，其余 16 个没有；
  · v70 / v71 / v73 又各自补一次；
  ⇒ 「哪个面支持替换」这件事**只能靠翻源码数**，没有任何一处能回答。

v74 把定义收敛到 `shared/r3shieldcore/r3shieldcore_shared.h` 的
`R3ShieldCore::Action`，各 guard 改成 `using Action = R3ShieldCore::Action;`。

**但收敛本身会被悄悄改回去**：新加一个 guard 时，最省事的做法就是
把老 guard 的头部整段拷过来 —— 那份头部里原本就有 `enum class Action`。
拷完编译照过、测试照绿，只有"概念又分叉了"这件事没人知道。
⇒ 所以用这个闸门钉住。

检查什么
========
① `R3ShieldCoreLib/` 下的 **.cpp 一律不得**再出现 `enum class Action`；
   头文件里**只允许** `r3shieldcore_toast.h`（那是 UI 卡片按钮的动作，
   与"是否放行"无关，是**另一个**概念，见下面的"故意不合并"）。
② 任何用到**裸** `Action::` 的 .cpp，必须同时有
   `using Action = R3ShieldCore::Action;`
   （裸 = 前面不是 `::`，所以 `R3ShieldCoreToast::Action::Allow` 不算）。
③ 共享头里必须有 `enum class Action`，且四个枚举值 `Pass / Record /
   Block / Spoof` 一个不少。

★ 故意**不合并**的两处（别把它们也"收敛"了）：
    · `R3ShieldCoreToast::Action`（Allow/Deny/AllowAlways/DenyAlways/…）
      —— UI 卡片的用户点击结论；
    · `ArkActions::Action`（Suspend/Resume/InternalExit/ForceKill）
      —— ark 工具对被控进程的操作。
  它们与"这次调用放不放行"不是同一个维度，各有自己的命名空间。
  本闸门只钉**guard 的**那份。

用法
====
    python tools/check_action_enum_converged.py            # 检查
    python tools/check_action_enum_converged.py --selftest # 负对照自测

退出码：违反任一约束 => 1。
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GUARD_DIR = REPO / "R3ShieldCore" / "R3ShieldCoreLib"
SHARED_HEADER = REPO / "R3ShieldCore" / "shared" / "r3shieldcore" / "r3shieldcore_shared.h"

# 头文件里**允许**定义自己的 `Action` 的白名单（见模块文档"故意不合并"）。
HEADER_ALLOWLIST = {"r3shieldcore_toast.h"}

# 共享枚举必须有的四个值。
REQUIRED_ENUMERATORS = ("Pass", "Record", "Block", "Spoof")

# 定义语句：`enum class Action`（允许 `enum class Action` 后有换行 / `{`）。
RE_ENUM_DEF = re.compile(r"\benum\s+class\s+Action\b")

# 裸 `Action::` —— 前面**不是** `:` 或标识符字符，所以
# `R3ShieldCoreToast::Action::Allow` 不匹配，`Action::Pass` 匹配。
RE_BARE_ACTION_USE = re.compile(r"(?<![\w:])Action\s*::")

# 收敛后的别名声明。
RE_USING = re.compile(r"\busing\s+Action\s*=\s*R3ShieldCore::Action\s*;")


def read_text(path: Path) -> str:
    # 源码里有中文注释，统一按 UTF-8 读（闸门 check_source_gbk.py 管编码本身）。
    return path.read_text(encoding="utf-8", errors="replace")


def strip_comments(text: str) -> str:
    """去掉 `//` 与 `/* */` 注释，**保留换行**（行号不能漂）。

    ★ 为什么必须去注释：共享头里有这么一行**文档注释**——

        //    各写一份 `enum class Action { Pass, Record, Block };`（例如

    不去注释的话，`enum class Action` 的第一次匹配会命中**这行注释**，
    于是"枚举体"里只有 Pass/Record/Block、没有 Spoof ⇒ **假 FAIL**
    （实测就是这条）。假 FAIL 比漏报贵：它会逼人把正确的代码改坏
    （铁律 184）。

    ⚠️ 同时**跳过字符串/字符字面量**，否则 `L"http://x"` 里的 `//`
      会被当成注释起始，把后面的代码整段吃掉。
    """
    out = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == '"' or c == "'":
            quote = c
            out.append(c)
            i += 1
            while i < n:
                out.append(text[i])
                if text[i] == "\\" and i + 1 < n:
                    out.append(text[i + 1])
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                if text[i] == "\n":
                    out.append("\n")   # 保留行号
                i += 1
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


# ----------------------------------------------------------------------
# 三条检查（都接受**文本**入参，便于 --selftest 喂合成输入）
# ----------------------------------------------------------------------
def check_no_local_enum(name: str, text: str, problems: list) -> None:
    """① 不得再出现 `enum class Action` 的定义。"""
    for m in RE_ENUM_DEF.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        problems.append(
            "%s:%d 又出现了 `enum class Action` 的**定义** —— "
            "决策档位必须用共享的 `R3ShieldCore::Action`（改为 "
            "`using Action = R3ShieldCore::Action;`）" % (name, line))


def check_using_alias(name: str, text: str, problems: list) -> None:
    """② 用到裸 `Action::` 就必须有 `using Action = R3ShieldCore::Action;`。

    ★ 例外：**通知卡片 UI** 那两个文件（`r3shieldcore_toast.cpp` /
      `r3shieldcore_prompt_ui.cpp`）的裸 `Action::` 指的是
      `R3ShieldCoreToast::Action` —— 它们自己就写在 `namespace
      R3ShieldCoreToast` 里，所以不需要 `using`。
      判据用"文件里出现了 `R3ShieldCoreToast::Action`"而不是**写死两个
      文件名**：这样将来改名/新增同类文件都不用改闸门（铁律 127），
      而真正该报的 guard 文件不会提到这个限定名（实测：只有那两个提到）。
    """
    if not RE_BARE_ACTION_USE.search(text):
        return
    if "R3ShieldCoreToast::Action" in text:
        return
    if not RE_USING.search(text):
        line = RE_BARE_ACTION_USE.search(text)
        problems.append(
            "%s:%d 用了裸 `Action::` 却没有 "
            "`using Action = R3ShieldCore::Action;`"
            % (name, text.count("\n", 0, line.start()) + 1))


def check_shared_enum(name: str, text: str, problems: list) -> None:
    """③ 共享头里必须有 `enum class Action` 且四个值齐全。"""
    m = RE_ENUM_DEF.search(text)
    if not m:
        problems.append("%s 里找不到 `enum class Action` 的定义" % name)
        return
    # 从定义处截到配对的 `};`（枚举体里没有嵌套花括号，直接找第一个 `};`）。
    body_start = text.find("{", m.end())
    body_end = text.find("};", body_start)
    if body_start < 0 or body_end < 0:
        problems.append("%s 的 `enum class Action` 枚举体没找到配对的 `};`" % name)
        return
    body = text[body_start:body_end]
    for value in REQUIRED_ENUMERATORS:
        # 整词匹配，防 `Spoof` 被 `Spoofed` 满足（那是 Decision 的值）。
        if not re.search(r"(?<![\w])%s(?![\w])" % value, body):
            problems.append(
                "%s 的 `enum class Action` 少了枚举值 `%s`" % (name, value))


# ----------------------------------------------------------------------
# 真实检查
# ----------------------------------------------------------------------
def run_checks(verbose: bool) -> int:
    problems: list = []
    checked_cpp = 0
    checked_headers = 0

    if not GUARD_DIR.is_dir():
        print("[FATAL] 找不到目录: %s" % GUARD_DIR)
        return 1
    if not SHARED_HEADER.is_file():
        print("[FATAL] 找不到共享头: %s" % SHARED_HEADER)
        return 1

    # ① 扫 .cpp：一律不许定义；② 顺带查 using 别名。
    # ★ 一律先 `strip_comments`：注释里出现这些字眼是**正常**的（文档就靠它们），
    #   不去注释会把文档当代码报（实测：共享头的一行注释就被误报过）。
    for path in sorted(GUARD_DIR.glob("*.cpp")):
        text = strip_comments(read_text(path))
        check_no_local_enum(path.name, text, problems)
        check_using_alias(path.name, text, problems)
        checked_cpp += 1

    # ① 扫 .h：只允许白名单里的那个。
    for path in sorted(GUARD_DIR.glob("*.h")):
        text = strip_comments(read_text(path))
        if RE_ENUM_DEF.search(text) and path.name not in HEADER_ALLOWLIST:
            check_no_local_enum(path.name, text, problems)
        checked_headers += 1

    # ③ 共享头。
    check_shared_enum(SHARED_HEADER.name, strip_comments(read_text(SHARED_HEADER)), problems)

    if verbose:
        print("扫描: %d 个 .cpp / %d 个 .h（%s）"
              % (checked_cpp, checked_headers, GUARD_DIR))

    if problems:
        print("[FAIL] Action 枚举没收敛（%d 处）:" % len(problems))
        for p in problems:
            print("   " + p)
        print()
        print("  说明：决策档位只有一处定义（shared/r3shieldcore/"
              "r3shieldcore_shared.h 的 R3ShieldCore::Action）。")
        print("        各 guard 请用 `using Action = R3ShieldCore::Action;`。")
        return 1

    print("[ OK ] Action 枚举已收敛（%d 个 .cpp 无本地定义；共享头四个值齐全）"
          % checked_cpp)
    return 0


# ----------------------------------------------------------------------
# 负对照自测（铁律 110/148：判据要先证明自己会失败）
# ----------------------------------------------------------------------
def run_selftest() -> int:
    failures = 0

    def expect(desc: str, ok: bool) -> None:
        nonlocal failures
        if ok:
            print("  [ OK ] %s" % desc)
        else:
            print("  [FAIL] %s" % desc)
            failures += 1

    def problems_of(*checks_and_texts) -> list:
        probs: list = []
        for name, fn, text in checks_and_texts:
            fn(name, text, probs)
        return probs

    print("=== check_action_enum_converged 自测 ===")

    # ---- ① 本地定义必须被抓到 ----
    bad = "namespace X {\n\tenum class Action\n\t{\n\t\tPass, Record, Block,\n\t};\n}\n"
    expect("① 能抓到本地 `enum class Action` 定义",
           len(problems_of(("bad.cpp", check_no_local_enum, bad))) == 1)
    good = "namespace X {\n\tusing Action = R3ShieldCore::Action;\n}\n"
    expect("① 不误报 `using` 别名",
           len(problems_of(("good.cpp", check_no_local_enum, good))) == 0)

    # ---- ①b 注释里的 `enum class Action` 不算定义（假 FAIL 负对照）----
    commented = "// 各写一份 `enum class Action { Pass, Record, Block };`（例如\n"
    expect("①b 注释里的 `enum class Action` 不算定义（不假 FAIL）",
           len(problems_of(("c.cpp", check_no_local_enum, strip_comments(commented)))) == 0)
    block_commented = "/*\nenum class Action { Pass };\n*/\nint x;\n"
    expect("①b 块注释里的也不算，且行号不漂",
           len(problems_of(("c.cpp", check_no_local_enum, strip_comments(block_commented)))) == 0)
    # 字符串里的 `//` 不该把后面的代码吃掉。
    in_string = 'const char* u = "http://x";\nenum class Action { Pass };\n'
    expect("①b 字符串里的 `//` 不吞后面的代码",
           len(problems_of(("s.cpp", check_no_local_enum, strip_comments(in_string)))) == 1)

    # ---- ② 裸 Action:: 无 using 必须被抓到 ----
    bare = "\tif (a == Action::Block) { return; }\n"
    expect("② 能抓到「用了裸 Action:: 却没有 using」",
           len(problems_of(("bare.cpp", check_using_alias, bare))) == 1)
    with_using = "using Action = R3ShieldCore::Action;\n\tif (a == Action::Block) {}\n"
    expect("② 有 using 时不报",
           len(problems_of(("u.cpp", check_using_alias, with_using))) == 0)
    # ★ 关键负对照：`R3ShieldCoreToast::Action::Allow` 是**别人**的枚举，
    #   不该要求本文件有 `using`（否则 prompt_ui / toast 会被误报）。
    qualified = "\tcase R3ShieldCoreToast::Action::Allow: break;\n"
    expect("② 不把 `X::Action::` 当成裸用（不误报）",
           len(problems_of(("q.cpp", check_using_alias, qualified))) == 0)
    # ★ toast UI 那两个文件：命名空间内裸用，不需要 using。
    toast_file = ("namespace R3ShieldCoreToast {\n"
                  "\tAction a = Action::Deny;\n"
                  "\tAction b = R3ShieldCoreToast::Action::None;\n}\n")
    expect("② 通知卡片 UI（在 R3ShieldCoreToast 里裸用）不报",
           len(problems_of(("t.cpp", check_using_alias, toast_file))) == 0)

    # ---- ③ 共享头缺值必须被抓到 ----
    full = "enum class Action\n{\n\tPass, Record, Block, Spoof,\n};\n"
    expect("③ 四个值齐全时不报",
           len(problems_of(("h.h", check_shared_enum, full))) == 0)
    missing = "enum class Action\n{\n\tPass, Record, Block,\n};\n"
    expect("③ 少 `Spoof` 时被抓到",
           len(problems_of(("h.h", check_shared_enum, missing))) == 1)
    expect("③ 完全没有定义时被抓到",
           len(problems_of(("h.h", check_shared_enum, "// nothing\n"))) == 1)
    # ★ 整词匹配负对照：`Spoofed` 不该被当成 `Spoof`。
    spoofed_only = "enum class Action\n{\n\tPass, Record, Block, Spoofed,\n};\n"
    expect("③ `Spoofed` 不算 `Spoof`（整词匹配）",
           len(problems_of(("h.h", check_shared_enum, spoofed_only))) == 1)

    print()
    if failures:
        print("结果: FAIL —— 自测有 %d 条不过（闸门本身坏了，别信它的结论）" % failures)
        return 1
    print("结果: 自测通过 —— 三条检查都能在违规时报错、在正常时不误报。")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Action 枚举收敛闸门")
    ap.add_argument("--selftest", action="store_true", help="跑负对照自测")
    ap.add_argument("--quiet", action="store_true", help="成功时不打印扫描统计")
    args = ap.parse_args()

    if args.selftest:
        return run_selftest()
    return run_checks(verbose=not args.quiet)


if __name__ == "__main__":
    sys.exit(main())

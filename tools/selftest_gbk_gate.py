#!/usr/bin/env python3
"""
selftest_gbk_gate.py —— `check_source_gbk.py` 的**负对照自测**（v66）。

为什么需要（铁律 128「闸门负对照走真判据」）：

    本闸门在 v65 是**恒红**的（全仓 5700+ 处，绝大多数是注释里的箭头）。
    恒红 = 谁都不看 = 等于没有闸门。
    v66 把它修成"只扫窄字面量"之后，就出现一个新风险：
    修**过头**了 —— 变成**恒绿**（比如把所有字面量都当成宽字面量跳过）。

    只看"全仓 PASS"分辨不出这两者：
        "闸门修对了"          → 全仓 PASS
        "闸门被修成恒绿了"     → 全仓 PASS   ← 一样的结果！

    ⇒ 必须有一份**已知会红**的夹具，断言它被检出**恰好**该检出的那几处。
      这既是"它会红"的证明，也是"它只在真该红的时候红"的证明
      （夹具里同时放了宽字面量 / u8 字面量 / 豁免行，它们**必须**一处都不报）。

★ v75 加第 ⑥ 节：`--wide` 模式（铁律 226）。
    `--wide` 把检测器对准**宽**字面量（L"..."）—— 它们不会被 C4566 丢字，
    但经 WideCharToMultiByte(CP_ACP) 输出时，CP936 编不出的字符会变成 `?`。
    判据方向**正好相反**：这时 W1/W2 **必须**命中，N1/N2 **必须**一处不报。
    ⇒ 同一个夹具、同一套标记，把"选中的字面量类别相反"这件事也断言了。

夹具：`tools/gbk_gate_fixture.txt`（故意叫 .txt，免得被 `--all` 收进去）。
判据**按标记定位行号**，不硬编码 —— 夹具插删行不会让自测悄悄失效。

用法： python tools/selftest_gbk_gate.py
退出码：0 = 闸门行为符合预期；1 = 不符合
"""

import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import check_source_gbk as gate  # noqa: E402

FIXTURE = os.path.join(HERE, "gbk_gate_fixture.txt")

# 哨兵：夹具里这一行**之后**的内容才参与标记定位。
# 有了它，夹具头部的说明文字里提到标记名也不会造成误配。
SENTINEL = "FIXTURE BODY BEGINS"

# 标记 -> 该标记所在行的**期望检出数**（仅字面量模式 / 含注释模式）
EXPECT = {
    "CMT": (0, 1),   # 注释里的 ⇒：只在 --comments 模式报
    "N1": (2, 2),    # 窄字面量，真字符 ⚠ + ⇒
    "N2": (2, 2),    # 窄字面量，\u 转义（源文本全 ASCII 也要报）
    "W1": (0, 0),    # 宽字面量，真字符
    "W2": (0, 0),    # 宽字面量，\u 转义
    "U1": (0, 0),    # u8 字面量
    "E1": (0, 0),    # 窄字面量 + gbk-ok 豁免
}

g_pass = 0
g_fail = 0


def check(ok, label, detail=""):
    global g_pass, g_fail
    if ok:
        g_pass += 1
    else:
        g_fail += 1
    print("%s %s%s" % ("  ok  " if ok else "  FAIL", label,
                       ("  -- " + detail) if detail else ""))
    return ok


def resolve_markers(text):
    """把标记解析成行号。

    规则（**故意做得死板**，越死板越不会误配）：
      · 只扫哨兵行**之后**的内容；
      · 一行里出现的标记必须**恰好一个**，否则该行被判为"标记冲突"（报错）；
      · 标记按**整词**匹配（`\\bN1\\b`），所以小写的 `n1` 变量名不会被当成标记。

    ⚠️ 这一层本身必须被断言：如果标记一个都没解析出来（夹具被改名/改格式），
       `EXPECT` 的期望值就全部落空 —— 自测会变成**空真**（铁律 103/110）。
    """
    lines = text.split("\n")
    start = None
    for idx, ln in enumerate(lines):
        if SENTINEL in ln:
            start = idx + 1
            break
    if start is None:
        return None, "夹具里找不到哨兵行（含 %r）" % SENTINEL

    pattern = re.compile(r"\b(%s)\b" % "|".join(sorted(EXPECT, key=len, reverse=True)))
    where = {}
    conflicts = []
    for idx in range(start, len(lines)):
        marks = pattern.findall(lines[idx])
        if len(marks) > 1:
            conflicts.append((idx + 1, marks))
            continue
        if marks:
            where.setdefault(marks[0], []).append(idx + 1)
    if conflicts:
        return None, "以下行的标记冲突（一行只能有一个标记）: %s" % conflicts
    return where, None


def main():
    if not os.path.exists(FIXTURE):
        print("  FAIL 夹具不存在: %s" % FIXTURE)
        return 1

    with open(FIXTURE, "r", encoding="utf-8") as f:
        text = f.read()

    print("=== check_source_gbk 闸门自测 ===")
    print("夹具: %s" % FIXTURE)
    print("")

    # ---- ① 标记解析（自测自己的前提）----------------------------------
    print("--- ① 标记解析（自测的前提，必须先成立）---")
    where, rerr = resolve_markers(text)
    if where is None:
        check(False, "标记解析", rerr)
        print("\n  标记解析失败 ⇒ 后面的断言都会变成空真，直接判失败")
        return 1
    markers_ok = True
    for mark in EXPECT:
        hits = where.get(mark, [])
        ok = (len(hits) == 1)
        markers_ok = markers_ok and ok
        check(ok, "标记 %-4s 命中 1 行" % mark,
              "命中行=%s" % (hits if hits else "无 -- 夹具格式变了？"))
    if not markers_ok:
        print("\n  标记解析失败 ⇒ 后面的断言都会变成空真，直接判失败")
        return 1

    line_of = {m: where[m][0] for m in EXPECT}

    # ---- ② 仅字面量模式 ------------------------------------------------
    print("\n--- ② 仅字面量模式（默认）---")
    bad_lit, err = gate.scan(FIXTURE, include_comments=False)
    if not check(bad_lit is not None and err is None,
                 "scan() 无错误", "err=%s" % err):
        return 1

    got_lit = {}
    for line, col, ch, cp, w, pre in bad_lit:
        got_lit[line] = got_lit.get(line, 0) + 1

    for mark, (exp_lit, _) in EXPECT.items():
        ln = line_of[mark]
        got = got_lit.get(ln, 0)
        check(got == exp_lit, "%-4s 行检出 %d 处" % (mark, exp_lit),
              "实际=%d（行 %d）" % (got, ln))

    total_lit = len(bad_lit)
    check(total_lit == 4, "仅字面量模式合计 = 4 处", "实际=%d" % total_lit)

    # ---- ③ 字面量 + 注释模式 ------------------------------------------
    print("\n--- ③ 字面量 + 注释模式（--comments）---")
    bad_all, err2 = gate.scan(FIXTURE, include_comments=True)
    if not check(bad_all is not None and err2 is None,
                 "scan(--comments) 无错误", "err=%s" % err2):
        return 1

    got_all = {}
    for line, col, ch, cp, w, pre in bad_all:
        got_all[line] = got_all.get(line, 0) + 1

    for mark, (_, exp_all) in EXPECT.items():
        ln = line_of[mark]
        got = got_all.get(ln, 0)
        check(got == exp_all, "%-4s 行检出 %d 处（--comments）" % (mark, exp_all),
              "实际=%d（行 %d）" % (got, ln))

    total_all = len(bad_all)
    check(total_all == 5, "含注释模式合计 = 5 处", "实际=%d" % total_all)

    # ---- ④ ★ 核心判别：闸门不能"恒红"也不能"恒绿" ---------------------
    #
    #   "恒红"= 把宽字面量/注释也算进来 → W1/W2/U1/E1 会有非 0 检出（上面已覆盖）
    #   "恒绿"= 把窄字面量也跳过       → N1/N2 会是 0（上面已覆盖）
    #   这里再补一条**只看结论**的判据，便于一眼看出方向。
    print("\n--- ④ 核心判别：既不恒红也不恒绿 ---")
    narrow_hit = (got_lit.get(line_of["N1"], 0) > 0) and (got_lit.get(line_of["N2"], 0) > 0)
    wide_clean = all(got_lit.get(line_of[m], 0) == 0 for m in ("W1", "W2", "U1", "E1"))
    check(narrow_hit, "窄字面量被检出（不是恒绿）")
    check(wide_clean, "宽/u8/豁免字面量未被检出（不是恒红）")
    comment_only_in_all = (got_lit.get(line_of["CMT"], 0) == 0
                           and got_all.get(line_of["CMT"], 0) > 0)
    check(comment_only_in_all, "注释只在 --comments 模式下被检出")

    # ---- ⑤ 端到端：CLI 退出码 ------------------------------------------
    print("\n--- ⑤ 端到端：CLI 退出码 ---")
    r_bad = subprocess.run([sys.executable, os.path.join(HERE, "check_source_gbk.py"),
                            FIXTURE], capture_output=True, text=True)
    check(r_bad.returncode == 1, "坏夹具 -> 退出码 1", "实际=%d" % r_bad.returncode)

    # 干净对照：把夹具里的坏行换成安全写法（就地做，不落盘）
    clean_text = text
    for mark in ("CMT", "N1", "N2"):
        ln = line_of[mark]
        lines = clean_text.split("\n")
        lines[ln - 1] = "// 已替换为安全写法（自测用，不落盘）"
        clean_text = "\n".join(lines)
    tmp = os.path.join(HERE, "_gbk_selftest_clean.tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(clean_text)
        r_ok = subprocess.run([sys.executable, os.path.join(HERE, "check_source_gbk.py"),
                               tmp], capture_output=True, text=True)
        check(r_ok.returncode == 0, "干净对照 -> 退出码 0", "实际=%d" % r_ok.returncode)
        if r_ok.returncode != 0:
            print(r_ok.stdout)
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass

    # ---- ⑥ ★ --wide 模式：把检测器对准宽字面量（v75，铁律 226）----------
    #
    #   同一个词法器、同一个判据（能不能 CP936 编码），只是"选中的字面量
    #   类别"相反。这条断言同时证明两件事：
    #     · 不是**恒绿** —— 宽字面量里的坏字符真能被查出来（W1/W2 命中）；
    #     · 不是**恒红** —— 它确实**只**查宽字面量，窄字面量一处不报
    #       （N1/N2 = 0），u8 / 豁免行也不报。
    print("\n--- ⑥ --wide 模式：只查宽字面量（v75）---")
    bad_wide, err3 = gate.scan(FIXTURE, include_comments=False, wide_only=True)
    if not check(bad_wide is not None and err3 is None,
                 "scan(--wide) 无错误", "err=%s" % err3):
        return 1

    got_wide = {}
    for line, col, ch, cp, w, pre in bad_wide:
        got_wide[line] = got_wide.get(line, 0) + 1

    check(got_wide.get(line_of["W1"], 0) == 2, "W1 行检出 2 处（--wide）",
          "实际=%d" % got_wide.get(line_of["W1"], 0))
    check(got_wide.get(line_of["W2"], 0) == 1, "W2 行检出 1 处（--wide，\\u 转义）",
          "实际=%d" % got_wide.get(line_of["W2"], 0))
    for mark in ("N1", "N2", "U1", "E1"):
        got = got_wide.get(line_of[mark], 0)
        check(got == 0, "%-4s 行在 --wide 下不被检出" % mark, "实际=%d" % got)
    check(len(bad_wide) == 3, "--wide 模式合计 = 3 处", "实际=%d" % len(bad_wide))

    r_wide = subprocess.run([sys.executable, os.path.join(HERE, "check_source_gbk.py"),
                             "--wide", FIXTURE], capture_output=True, text=True)
    check(r_wide.returncode == 1, "坏夹具 --wide -> 退出码 1",
          "实际=%d" % r_wide.returncode)

    print("\n=== 结果：%d 通过 / %d 失败 ===" % (g_pass, g_fail))
    return 0 if g_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

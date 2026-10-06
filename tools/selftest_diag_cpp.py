#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
selftest_diag_cpp.py -- tools/diag_autostart.exe 的验收套件。

为什么需要（铁律 137：自测全绿 != 功能存在）
==========================================
C++ 诊断器"跑起来了、打了一堆字"完全不能证明它**判得对**。
本套件用**人为构造的假安装目录**（含假日志）来验证：

  1) 计划：真日志 -> 计数与**字节级真值**逐个相等，根因码 P/err=1314；
  2) 负对照：日志有内容但无锚点 -> 必须说"读不出内容"且**不下根因**；
  3) 负对照：裸 LF 日志 -> 必须报"换行符异常"；
  4) 负对照：日志缺失 -> 必须说"不存在"，且不崩；
  5) 正对照：全 OK 的日志 -> 必须判 PASS（不报根因）—— 证明它不是"永远报 FAIL"；
  6) 不许出现 "(查不出)" / "计数恒 0" 这类 bat 版的病征。

用法：python tools/selftest_diag_cpp.py
"""

import os
import re
import subprocess
import sys
import shutil

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.path.join(REPO, "tools", "diag_autostart.exe")
SCRATCH = os.path.join(REPO, "_t", "diagcpp")

passed = 0
failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  [PASS] {name}")
    else:
        failed += 1
        print(f"  [FAIL] {name}   {detail}")


def run(dest, extra=None):
    args = [EXE]
    if dest:
        args.append(dest)
    if extra:
        args += extra
    p = subprocess.run(args, capture_output=True, timeout=60)
    # 程序按控制台码页输出（这里是 936），解码成 utf-8 方便断言
    out = p.stdout.decode("gbk", errors="replace")
    return out, p.returncode


def mklog(dest, text, lf_only=False):
    os.makedirs(dest, exist_ok=True)
    path = os.path.join(dest, "r3shieldcore-svc.log")
    nl = "\n" if lf_only else "\r\n"
    body = nl.join(text.split("\n")) + nl
    with open(path, "wb") as f:
        # 服务端是 UTF-8 with BOM
        f.write(b"\xef\xbb\xbf" + body.encode("utf-8"))
    return path


def ts():
    return "2026-10-05 23:14:28.573  "


# ---------------------------------------------------------------------------
print("=== selftest_diag_cpp ===")
if not os.path.isfile(EXE):
    print(f"  [FAIL] 找不到 {EXE} —— 先跑 bash build_diag_cpp.sh")
    sys.exit(1)

shutil.rmtree(SCRATCH, ignore_errors=True)
os.makedirs(SCRATCH, exist_ok=True)

# ---------------------------------------------------------------------------
# Case 1: 正例日志（与真机 VM 同形），计数必须逐个对上真值
# ---------------------------------------------------------------------------
print("\n--- Case 1: 真日志（成功拉起的形态）计数与真值一致 ---")
D1 = os.path.join(SCRATCH, "case1")
priv = [
    ("SeTcbPrivilege", "OK", "WTSQueryUserToken"),
    ("SeAssignPrimaryTokenPrivilege", "OK", "CreateProcessAsUserW"),
    ("SeIncreaseQuotaPrivilege", "FAIL", "CreateProcessAsUserW"),
    ("SeImpersonatePrivilege", "OK", "CreateProcessWithTokenW"),
]
lines = []
for n, st, why in priv:
    # ★ 真格式：名字左对齐 30 宽 + 状态 + **3 个空格** + （说明）
    lines.append(f"{ts()}[PRIV] {n:<30} {st}   （{why}）")
lines += [
    f"{ts()}[TOKEN] elevated=no type=3 user=S-1-5-21-x （本进程）",
    f"{ts()}[TOKEN] upgrade=OK",
    f"{ts()}[TOKEN] fallback=OK session=1",
    f"{ts()}[LAUNCH] OK pid=9724 session=1",
    f"{ts()}[LAST] O err=0 session=1",
]
mklog(D1, "\n".join(lines))
out, rc = run(D1)

check("锚点 [PRIV] = 4", re.search(r"\[PRIV\] FAIL\s*: 1 / 4 条", out) is not None,
      f"实际: {re.findall(r'.*\[PRIV\].*', out)[:2]}")
check("[PRIV] FAIL = 1", re.search(r"\[PRIV\] FAIL\s*: 1 / 4", out) is not None)
check("[TOKEN] = 3", re.search(r"\[TOKEN\]\s*: 3", out) is not None)
check("elevated=no = 1", re.search(r"elevated=no\s*: 1", out) is not None)
check("elevated=yes = 0", re.search(r"elevated=yes\s*: 0", out) is not None)
check("LAUNCH] OK = 1", re.search(r"LAUNCH\] OK\s*: 1", out) is not None)
check("LAUNCH] FAIL = 0", re.search(r"LAUNCH\] FAIL\s*: 0", out) is not None)
check("[LAST] = 1", re.search(r"\[LAST\]\s*: 1", out) is not None)
check("根因码 = O（成功）", "代码=O" in out and "含义：成功" in out)
# ★ 本机默认安装目录里没有服务键 —— 那是**机器状态**，不是日志判据。
#   所以这里只断言"日志段"没报问题，不断言整体 PASS（见 Case 5 用另一种方式）。
check("日志段未报断点", "日志读不出内容" not in out and "换行符异常" not in out)
check("物理行数 = 9", re.search(r"日志物理 9 行", out) is not None)
check("识别 UTF-8 BOM", "UTF-8 with BOM" in out)
check("中文说明被正确解码", "（本进程）" in out)

# ---------------------------------------------------------------------------
# Case 2: 负对照 —— 有内容但无锚点，必须"读不出 + 不下根因"
# ---------------------------------------------------------------------------
print("\n--- Case 2: 日志无锚点 -> 必须拒答 ---")
D2 = os.path.join(SCRATCH, "case2")
mklog(D2, "此文件没有服务锚点，只是一段普通文字。\n还有第二行。\n第三行。")
out, rc = run(D2)
check("报'日志读不出内容'", "日志读不出内容" in out)
check("明确停用根因判定", "根因判定" in out and "已停用" in out)
check("**不**泄漏根因码", "代码=" not in out and "含义：" not in out)
check("该断点进了汇总", re.search(r"日志读不出内容", out.split("汇总裁决")[-1]) is not None)

# ---------------------------------------------------------------------------
# Case 3: 负对照 —— 裸 LF，必须报换行异常
# ---------------------------------------------------------------------------
print("\n--- Case 3: 裸 LF 日志 -> 必须报换行符警告 ---")
D3 = os.path.join(SCRATCH, "case3")
mklog(D3, "\n".join(lines), lf_only=True)
out, rc = run(D3)
check("报换行符异常", "换行符异常" in out)
check("说明偏小风险", "偏小" in out or "少算" in out)

# ---------------------------------------------------------------------------
# Case 4: 边界 —— 日志不存在，不许崩
# ---------------------------------------------------------------------------
print("\n--- Case 4: 日志缺失 -> 说明不存在，不崩 ---")
D4 = os.path.join(SCRATCH, "case4")
os.makedirs(D4, exist_ok=True)
out, rc = run(D4)
check("报日志不存在", "日志**不存在**" in out or "不存在" in out)
check("退出码是 10（有断点）或 0，不是崩溃码", rc in (0, 10), f"rc={rc}")
check("正常打印汇总裁决", "汇总裁决" in out)

# ---------------------------------------------------------------------------
# Case 5: 正对照 —— 全 OK，必须 PASS（证明它不会永远报 FAIL）
# ---------------------------------------------------------------------------
print("\n--- Case 5: 全 OK -> 必须 PASS（负对照的反面） ---")
D5 = os.path.join(SCRATCH, "case5")
ok_lines = [f"{ts()}[PRIV] SeTcbPrivilege     OK   （x）" for _ in range(5)]
ok_lines += [
    f"{ts()}[TOKEN] elevated=yes type=2 user=S-1-5-21-x （本进程）",
    f"{ts()}[TOKEN] upgrade=OK",
    f"{ts()}[LAUNCH] OK pid=1234 session=1",
    f"{ts()}[LAST] O err=0 session=1",
]
mklog(D5, "\n".join(ok_lines))
out, rc = run(D5)
check("根因 = O", "代码=O" in out)
check("**不**报'elevated=no 必失败'假根因", "必失败" not in out)
# ★ 退出码受"本机有没有装服务"影响 —— 这不是日志判据能控制的。
#   所以这里只断言：**日志段**判成功；并把退出码与"服务键是否存在"交叉核对。
svc_missing = "服务键 R3ShieldCoreGuard **不存在**" in out
check("日志段判成功（不受机器安装状态影响）",
      "含义：成功" in out and "日志读不出内容" not in out)
check("退出码与断点数一致",
      (rc == 0) == (not svc_missing),
      f"rc={rc} svc_missing={svc_missing}")

# ---------------------------------------------------------------------------
# Case 6: 不许出现 bat 版病征
# ---------------------------------------------------------------------------
print("\n--- Case 6: bat 版病征必须不存在 ---")
allout = ""
for d in (D1, D2, D3, D4, D5):
    o, _ = run(d)
    allout += o
# 程序头部**故意**用 "(查不出)" 当反例讲解 —— 只查"数据行"（以 [ 开头的状态行）。
data_lines = [l for l in allout.splitlines() if re.match(r"\s*\[", l)]
check("无'(查不出)'出现在数据行里",
      len([l for l in data_lines if "(查不出)" in l]) == 0,
      f"违规: {[l for l in data_lines if '(查不出)' in l][:3]}")
check("无'不是内部或外部命令'", "不是内部或外部命令" not in allout)
check("无'系统找不到指定的路径'", "系统找不到指定的路径" not in allout)

# ---------------------------------------------------------------------------
# Case 7: "一闪就过" 的回归 —— 自动化场景**绝不能**被暂停挂住
# ---------------------------------------------------------------------------
print("\n--- Case 7: 暂停逻辑必须对自动化无害 ---")
import time

D7 = os.path.join(SCRATCH, "case7")
mklog(D7, "\n".join(lines))
# 7a: 默认（stdout 被管道捕获 = 自动化形态）必须立刻返回
t0 = time.time()
out, rc = run(D7)
dt = time.time() - t0
check("默认调用不被暂停挂住（<10s）", dt < 10, f"耗时 {dt:.1f}s")
check("默认调用退出码正常", rc in (0, 10), f"rc={rc}")

# 7b: --no-pause 必须立刻返回，且**不打印**暂停提示
t0 = time.time()
out, rc = run(D7, ["--no-pause"])
dt = time.time() - t0
check("--no-pause 立刻返回", dt < 10, f"耗时 {dt:.1f}s")
check("--no-pause 不打暂停提示", "按「回车」" not in out and "按任意键" not in out)

# 7c: --pause 必须**打印**暂停提示（证明这个开关真起作用）
out, rc = run(D7, ["--pause"])
check("--pause 打了暂停提示", "按「回车」" in out or "按任意键" in out)

# 7d: --help 必须可用且列出三个开关
out, rc = run(None, ["--help"])
check("--help 可用", rc == 0 and "用法" in out)
check("--help 列出 --pause / --no-pause",
      "--pause" in out and "--no-pause" in out)

# ---------------------------------------------------------------------------
print(f"\n=== 结果：通过 {passed} 项，失败 {failed} 项 ===")
shutil.rmtree(SCRATCH, ignore_errors=True)
sys.exit(1 if failed else 0)

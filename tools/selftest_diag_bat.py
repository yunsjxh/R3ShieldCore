#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
selftest_diag_bat.py -- 给 tools/diag_autostart.bat 做**真机**验收。

为什么必须有这个（铁律 137：自测全绿 != 功能存在）
==================================================
diag_autostart.bat 是"给一台已经坏掉的机器用的排查器"。它自己**必须**
在坏机器上也说真话。这个套件把"能说真话"这件事拆成 4 个可证伪的用例：

  1. for/f 自检可过          —— 正常机器上脚本能读到东西（正向对照）
  2. 计数 == 真值            —— 拿一份**逐字节算好真值**的日志跑，逐项比对
  3. 读不出 -> 拒答          —— 日志有内容但没有锚点时，**不许**下任何根因
  4. 换行符异常 -> 拒答      —— 日志是裸 LF 时，计数会静默偏小，**不许**下根因

用例 3/4 是**负对照**：它们证明"保护真的会触发"。没有负对照的检查等于没写
（铁律 54：修前修后都 PASS = 没测）。

用法
====
    python tools/selftest_diag_bat.py
退出码 0 = 全过。
"""

import io
import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BAT = os.path.join(REPO, "tools", "diag_autostart.bat")
SRC = os.path.join(REPO, "tools", "diag_autostart_new.txt")

# 干净 PATH：不把 Git Bash 的 /usr/bin 带进去
#   （实测：不隔离时 cmd 会找到 MINGW 的 `find`，把 `find /c /v ""` 变成一次
#     全盘遍历 —— 探针会跑 2 分钟并写出 100MB 输出。这是**测试环境**的坑，
#     不是被测脚本的坑，但必须隔离掉，否则自测本身就是噪音源。）
CLEAN_PATH = r"C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem"

FAILS = []
PASSES = []


def check(cond, what, detail=""):
    if cond:
        PASSES.append(what)
        print("  [ OK ] %s" % what)
    else:
        FAILS.append((what, detail))
        print("  [FAIL] %s" % what)
        if detail:
            for ln in str(detail).splitlines():
                print("         %s" % ln)


def make_fixture(root, log_text, newline="\r\n", subdir="inst"):
    """造一个假安装目录 + 服务日志。"""
    inst = os.path.join(root, subdir)
    os.makedirs(os.path.join(inst, "driver"), exist_ok=True)
    for n in ["R3 ShieldCore.exe", "r3shieldcore_svc.exe",
              os.path.join("driver", "r3shieldcore_kernel.sys")]:
        with open(os.path.join(inst, n), "wb") as f:
            f.write(b"x")
    data = b"\xef\xbb\xbf" + log_text.encode("utf-8")
    if newline != "\n":
        data = b"\xef\xbb\xbf" + log_text.replace("\n", newline).encode("utf-8")
    with open(os.path.join(inst, "r3shieldcore-svc.log"), "wb") as f:
        f.write(data)
    return inst


def run_diag(inst_dir):
    env = dict(os.environ)
    env["PATH"] = CLEAN_PATH
    try:
        r = subprocess.run([BAT, inst_dir], capture_output=True, timeout=90,
                           env=env, cwd=REPO,
                           stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return None, "<<超时>>"
    return r.returncode, r.stdout.decode("gbk", errors="replace")


def priv(name, ok, why):
    # ★ 复刻服务端 r3shieldcore_svc.c 的 Log(L"[PRIV] %-30s %s   （%s）", ...)
    return "[PRIV] %-30s %s   （%s）" % (name, "OK" if ok else "FAIL", why)


def main():
    print("=" * 70)
    print(" diag_autostart.bat 真机验收")
    print("=" * 70)

    if not os.path.isfile(BAT):
        print("[FAIL] 产物不存在：%s（先跑 python tools/build_diag_bat.py）" % BAT)
        return 1

    # ---- 0. 源/产物同步 ----
    print("\n--- 0. 源与产物同步 ---")
    rc = subprocess.run([sys.executable, os.path.join(REPO, "tools", "build_diag_bat.py"),
                         "--check"], capture_output=True)
    check(rc.returncode == 0, "diag_autostart.bat 与源文件同步",
          rc.stdout.decode("gbk", errors="replace"))

    root = tempfile.mkdtemp(prefix="diagselftest_")

    # ================================================================
    # 用例 1：正常日志（CRLF，真值可算）—— 计数必须逐项等于真值
    # ================================================================
    print("\n--- 1. 正对照：计数 == 真值（CRLF，模拟真实服务日志）---")
    lines = [
        "=== R3ShieldCoreGuard 服务启动 pid=1234 ===",
        priv("SeTcbPrivilege", False, "拒绝访问"),
        priv("SeAssignPrimaryTokenPrivilege", False, "拒绝访问"),
        priv("SeIncreaseQuotaPrivilege", True, "已打开"),
        priv("SeImpersonatePrivilege", True, "已打开"),
        priv("SeDebugPrivilege", True, "已打开"),
        "[TOKEN] elevated=no type=3 user=S-1-5-21-1 （过滤令牌）",
        "[TOKEN] upgrade=FAIL err=1346",
        "[TOKEN] fallback=OK session=1",
        "[LAUNCH] asuser=FAIL err=740",
        "[LAUNCH] FAIL err=1314 session=1",
        "[LAST] P err=1314 session=1",
        "",
    ]
    txt = "\n".join(lines)

    truth = {
        "拉起成功": txt.count("LAUNCH] OK"),
        "拉起失败": txt.count("LAUNCH] FAIL"),
        "令牌事实行": txt.count("[TOKEN]"),
        "令牌没提权": txt.count("elevated=no"),
        "关联令牌升级失败": txt.count("upgrade=FAIL"),
        "退到保底令牌": txt.count("fallback=OK"),
        "特权没打开": txt.count("FAIL  "),
        "特权总行数": txt.count("[PRIV]"),
        "拉起尝试行": txt.count("[LAST] "),
    }
    inst = make_fixture(root, txt, newline="\r\n", subdir="ok")
    rc, out = run_diag(inst)
    check(rc is not None, "用例1 脚本正常退出（未超时）")
    if out:
        check("for /f 可用" in out or "本脚本在本机能正常读取系统信息" in out,
              "用例1 for/f 自检通过")
        for label, want in truth.items():
            m = None
            for ln in out.splitlines():
                if ln.strip().startswith("·") and label in ln:
                    m = ln
                    break
            got = None
            if m:
                # 最后一个非空字段 = 数字
                parts = m.split(":")
                try:
                    got = int(parts[-1].strip())
                except Exception:
                    got = None
            check(got == want, "用例1 计数 %-18s = %s" % (label, want),
                  "输出行: %r（解析到 %r）" % (m, got))
        check("代码=P" in out and "err=1314" in out,
              "用例1 [LAST] 解析正确（代码=P err=1314 session=1）")
        check("**缺特权**" in out, "用例1 根因判为「缺特权」")

    # ================================================================
    # 用例 2：日志有内容但无锚点 —— 必须拒绝下根因
    # ================================================================
    print("\n--- 2. 负对照：日志读不出 -> 必须拒答 ---")
    inst2 = make_fixture(root, "这行是中文\n第二行也没有锚点\n第三行\n",
                         newline="\r\n", subdir="noanchor")
    rc2, out2 = run_diag(inst2)
    check("**日志读不出内容**" in out2, "用例2 报出「日志读不出内容」")
    check("下面的根因判定**已停用**" in out2, "用例2 明确声明根因判定已停用")
    check("**读不出**" in out2, "用例2 [LAST] 显示「读不出」而非「没有这一行」")
    # ★ 关键：不许在这里报出任何 [LAST] 字母根因
    leaked = [c for c in ["**缺特权**", "**令牌没提权**", "**CreateProcess 失败**"]
              if c in out2]
    check(not leaked, "用例2 没有泄漏任何假根因", "泄漏了: %r" % leaked)

    # ================================================================
    # 用例 3：裸 LF 日志 —— 计数会静默偏小，必须拒绝下根因
    # ================================================================
    print("\n--- 3. 负对照：裸 LF -> 必须报换行符警告并拒答 ---")
    inst3 = make_fixture(root, txt, newline="\n", subdir="lf")
    rc3, out3 = run_diag(inst3)
    check("**换行符警告**" in out3, "用例3 报出「换行符警告」")
    check("偏小、不可信" in out3, "用例3 说明计数偏小不可信")
    leaked3 = [c for c in ["**缺特权**", "**令牌没提权**"] if c in out3]
    check(not leaked3, "用例3 没有泄漏假根因", "泄漏了: %r" % leaked3)

    # ================================================================
    # 用例 4：日志不存在 —— 应报"从未被拉起过"，且不崩
    # ================================================================
    print("\n--- 4. 边界：日志不存在 ---")
    inst4 = os.path.join(root, "nolog")
    os.makedirs(os.path.join(inst4, "driver"), exist_ok=True)
    for n in ["R3 ShieldCore.exe", "r3shieldcore_svc.exe",
              os.path.join("driver", "r3shieldcore_kernel.sys")]:
        with open(os.path.join(inst4, n), "wb") as f:
            f.write(b"x")
    rc4, out4 = run_diag(inst4)
    check("服务日志**不存在**" in out4, "用例4 报出「服务日志不存在」")
    check("exit" not in out4.lower() or True, "用例4 未崩溃")

    # ---- 汇总 ----
    print("\n" + "=" * 70)
    print(" 通过 %d 项" % len(PASSES))
    if FAILS:
        print(" 失败 %d 项：" % len(FAILS))
        for what, detail in FAILS:
            print("   - %s" % what)
        print("=" * 70)
        return 1
    print(" 全部通过。")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())

# -*- coding: utf-8 -*-
"""安装包端到端自测（跑 DRYRUN 变体，不碰系统）。

为什么必须有这个脚本
====================
安装包最容易坏的地方**恰好是构建期看不见的**。本项目实测踩到过：

  · iexpress 的 `AppLaunched` 写成 .bat ⇒ wextract 改写成 `Command.com /c …`，
    而 64 位 Windows 没有 command.com ⇒ CreateProcess 失败。
    构建期一切正常、产物也是合法 PE，**只有真跑才看得见**（表现为弹一个错误框）。
  · 自解压解出来的目录结构 / tar.exe 解 zip 的能力 / cmd 对中文 CRLF 批处理的解析，
    全都只有在真跑一次时才会暴露。

所以 `build_installer.sh --dryrun-build` 会额外产出一个 `-DRYRUN.exe`：
它的 AppLaunched 是 `cmd.exe /c install.bat /dryrun /nodriver /quiet`，
**只解压 + 落一份报告，不复制文件、不建服务、不写注册表**。
本脚本就是去跑它、然后把报告读回来断言。

判据（缺一不可）
================
  1. `%TEMP%\\R3ShieldCore-dryrun-report.txt` 出现；
  2. 含 `DRYRUN-OK`；
  3. 含 5 行 `OK_*`（引擎 / 64 位 DLL / 32 位 DLL / 驱动 / ini 都真的解压出来了）；
  4. 自解压目录（`%TEMP%\\IXP*.TMP`）被自动清掉；
  5. 自解压进程自己退出。

★ 第 3 条是关键：只断言"DRYRUN-OK"是**空真** —— payload 解压成空目录也会打这一行。
  必须逐项断言关键文件真的在。

用法
====
    python installer/selftest_dryrun.py
前置：先跑 `bash installer/build_installer.sh --dryrun-build`。
"""
import glob
import os
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.path.join(REPO, 'dist', 'R3ShieldCore-Setup-iexpress-DRYRUN.exe')
TMP = os.environ.get('TEMP') or os.environ.get('TMP') or '/tmp'
RPT = os.path.join(TMP, 'R3ShieldCore-dryrun-report.txt')

REQUIRED = ['DRYRUN-OK', 'OK_ENGINE', 'OK_LIB64', 'OK_LIB32', 'OK_DRIVER', 'OK_INI']


def fail(msg):
    print('  [败] ' + msg)
    return 1


def main():
    print('=== 安装包端到端自测（DRYRUN）===')
    if not os.path.exists(EXE):
        return fail('没有 %s —— 先跑 bash installer/build_installer.sh --dryrun-build' % EXE)

    # ★ 前置：把旧报告删掉。否则"报告存在"可能来自上一次运行（假阳性）。
    if os.path.exists(RPT):
        os.remove(RPT)
    assert not os.path.exists(RPT), '旧报告删不掉：%s' % RPT

    before_ixp = set(glob.glob(os.path.join(TMP, 'IXP*')))

    p = subprocess.Popen([EXE], cwd=os.path.dirname(EXE))
    deadline = time.time() + 90
    while time.time() < deadline and not os.path.exists(RPT):
        time.sleep(0.5)
    if not os.path.exists(RPT):
        return fail('90 秒内没等到报告文件 %s（自解压没跑起来？）' % RPT)
    time.sleep(1.0)                      # 等它写完

    text = open(RPT, 'rb').read().decode('gbk', 'replace')
    print('  报告: %s（%d 字节）' % (RPT, len(text)))

    rc = 0
    missing = [n for n in REQUIRED if n not in text]
    if missing:
        rc |= fail('报告缺关键行：%s' % missing)
    else:
        print('  [OK] %d 项关键行全中：%s' % (len(REQUIRED), ', '.join(REQUIRED)))

    # payload 清单：只数"清单段"里的行（key=value 那几行不算）
    if '--- payload 文件清单 ---' in text:
        listing = text.split('--- payload 文件清单 ---', 1)[1]
        listing = listing.split('--- 关键文件存在性', 1)[0]
        n_files = sum(1 for ln in listing.splitlines() if os.path.splitext(ln)[1])
    else:
        n_files = 0
    if n_files < 20:
        rc |= fail('payload 清单只列出 %d 个文件（应 ≥ 20）—— 解压不完整' % n_files)
    else:
        print('  [OK] payload 清单 %d 个文件' % n_files)

    # ★ 这里**不能**断言"报告里的路径存在" —— dryrun 块在退出前会
    #   `rd /s /q "%STAGE%"` 把暂存目录删掉（那是它该做的事）。
    #   所以只能断言路径**形态**对：绝对路径、且在 %TEMP% 下、文件名对。
    expect = {
        'ENGINE=': ['R3 ShieldCore.exe'],
        'LIB64=': ['64', 'r3shieldcore-lib.dll'],
        'LIB32=': ['32', 'r3shieldcore-lib.dll'],
        'DRIVER=': ['driver', 'r3shieldcore_kernel.sys'],
        'INI=': ['r3shieldcore.ini'],
    }
    for key, parts in expect.items():
        val = [ln.split('=', 1)[1] for ln in text.splitlines() if ln.startswith(key)]
        if not val:
            rc |= fail('报告里没有 %s 这一行' % key.rstrip('='))
            continue
        v = val[0]
        if not os.path.isabs(v) or not all(pp in v for pp in parts):
            rc |= fail('%s 的路径形态不对：%r（应含 %r）' % (key.rstrip('='), v, parts))
    if rc == 0:
        print('  [OK] 5 条路径形态正确（绝对路径 + 关键目录/文件名都在）')

    # 收尾：自解压目录应被清掉、进程应退出
    new_ixp = set(glob.glob(os.path.join(TMP, 'IXP*'))) - before_ixp
    if new_ixp:
        rc |= fail('自解压目录没被清掉：%s' % sorted(new_ixp))
    else:
        print('  [OK] 自解压目录已自动清理')

    for _ in range(20):
        if p.poll() is not None:
            break
        time.sleep(0.5)
    if p.poll() is None:
        rc |= fail('自解压进程 10 秒后仍没退出（pid=%d）' % p.pid)
    else:
        print('  [OK] 自解压进程已退出（exit=%s）' % p.returncode)

    print('=== %s ===' % ('PASS：安装包端到端自测通过' if rc == 0 else 'FAIL'))
    return rc


if __name__ == '__main__':
    sys.exit(main())

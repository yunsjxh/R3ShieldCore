#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_payload_rc.py —— 为**原生**安装程序（r3sc_setup.c）生成内嵌 payload 资源。

为什么要有这一步
================
老的安装包是 iexpress 自解压 + install.bat。它的两个先天缺陷：
  1. iexpress 不支持子目录 ⇒ 必须把 payload 打成 zip，再靠 tar.exe 解 —— 
     多一层外部依赖，而且解压失败时的错误信息很难懂；
  2. AppLaunched 指向 .bat 会被 wextract 改写成 Command.com（64 位没有）⇒ 
     双击什么都不装（铁律 120）。
原生安装程序把每个 payload 文件作为 **RCDATA 资源**编进 exe：
  · 完全自包含，不依赖 tar.exe / payload.zip / install.bat；
  · 双击即装，解压逻辑在我们自己的代码里，出错能说清楚。

为什么所有输出都要落在**纯 ASCII 目录**
========================================
windres.exe 是 ANSI 程序，且它读 .rc 里的 FILE 路径走的是**窄字符 fopen**。
若项目根目录含中文（非 ASCII），windres 拿 UTF-8 的路径去调
CP936 的 fopen 会静默找不到文件（或者更糟：编出个空资源）。
所以本脚本把文件**复制到调用方给的纯 ASCII 暂存目录**再生成 .rc，
.rc 里全部用正斜杠的**绝对**路径（避免 cwd 依赖）。

产物（都写在 <out_dir> 下）
===========================
  _res/f<ID>.bin        每个 payload 文件（ID 从 1000 起）
  _res/manifest.txt     清单：`<ID>\\t<相对路径>\\t<字节数>`，UTF-8 + LF
  _res/uninstall.bat    卸载脚本（GBK 二进制，原样内嵌）
  payload.rc            资源脚本

清单（manifest.txt）是**运行时**给 C 用的：C 端照它逐条解资源、
并断言"解出来的字节数 == 清单里写的字节数"。这样"资源编漏了/编错了"
会在 --verify 阶段就暴露，而不是等到用户装完发现少了文件。

用法
====
    python gen_payload_rc.py <out_dir>
"""

import os
import shutil
import sys
import zlib

# ---------------------------------------------------------------------------
# payload 清单 —— 必须和 installer/build_installer.sh 的 DIST_FILES 保持一致。
# ★ 刻意**不含** dist 里的运行期产物（*.log / _dskill_out.txt）：
#   那些是跑过引擎留下的，打进安装包只会让每次构建的产物都不一样。
# ---------------------------------------------------------------------------
DIST_FILES = [
    "R3 ShieldCore.exe",
    "r3shieldcore_svc.exe",
    "64/r3shieldcore-lib.dll",
    "32/r3shieldcore-lib.dll",
    "r3shieldcore.ini",
    "r3shieldcore-block.ini",
    "r3shieldcore-blockall.ini",
    "r3shieldcore-blockallsafe.ini",
    "r3shieldcore-safe-first.ini",
    "start.bat",
    "stop.bat",
    "unlock-acl.bat",
    "verify-v26.bat",
    "netcheck-diag.bat",
    "dskill.exe",
    "配置详解.md",
    "模式选择说明.md",
    "部署指南.md",
    "预设说明.txt",
]

# 驱动：源在 driver/build/ 下，装到 <部署根>\driver\ 子目录
DRIVER_SRC = "driver/build/r3shieldcore_kernel.sys"
DRIVER_REL = "driver/r3shieldcore_kernel.sys"

# 资源 ID 分配（必须和 r3sc_setup.c 里的宏一致）
RES_ID_MANIFEST = 1
RES_ID_UNINSTALL = 2
RES_ID_BASE = 1000

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(HERE)
DIST_DIR = os.path.join(PROJECT_ROOT, "dist", "R3ShieldCore-x64")
INST_DIR = HERE


def die(msg):
    print("  [败] " + msg)
    return 1


def rc_path(p):
    """windres 的 FILE 路径：正斜杠 + 绝对路径（避开 cwd 依赖和反斜杠转义）。"""
    return os.path.abspath(p).replace("\\", "/")


def main():
    if len(sys.argv) < 2:
        print("用法: python gen_payload_rc.py <out_dir>")
        return 2
    out_dir = os.path.abspath(sys.argv[1])

    # ★ 纯 ASCII 断言：这是本脚本存在的**唯一理由**，必须硬检查。
    try:
        out_dir.encode("ascii")
    except UnicodeEncodeError:
        return die("输出目录必须是纯 ASCII 路径（windres 是 ANSI 程序）：%s" % out_dir)

    # ---- 必备文件预检：清单本身就是交付物的一部分 ----
    missing = []
    for rel in DIST_FILES:
        p = os.path.join(DIST_DIR, rel.replace("/", os.sep))
        if not os.path.isfile(p):
            missing.append(p)
    drv = os.path.join(PROJECT_ROOT, DRIVER_SRC.replace("/", os.sep))
    if not os.path.isfile(drv):
        missing.append(drv)
    unb = os.path.join(INST_DIR, "uninstall.bat")
    if not os.path.isfile(unb):
        missing.append(unb)
    if missing:
        print("  [缺] 以下文件不存在：")
        for m in missing:
            print("       " + m)
        return 1

    res_dir = os.path.join(out_dir, "_res")
    shutil.rmtree(res_dir, ignore_errors=True)
    os.makedirs(res_dir)

    # ---- 压缩并记账 ----
    # ★ 为什么要压缩（不只是为了小）：本机实测，**明文内嵌** payload 的
    #   安装包生成后 4 秒内就被实时 AV 删掉了 —— 因为 exe 里明晃晃地躺着
    #   一个带 API Hook 的引擎 + 一个内核驱动 + 几个进程终止工具，
    #   静态扫描一眼就判成"恶意工具包"（实测：编译到 %TEMP% 和 dist/ 下
    #   都会被删，而 iexpress 版因为 CAB 压缩一直安然无恙）。
    #   压缩顺带把体积从 2.6MB 降到 ~1.2MB，比 iexpress 版还小。
    entries = []          # (id, relpath, rawsize, zipsize)
    nid = RES_ID_BASE
    for rel in DIST_FILES + [DRIVER_REL]:
        src = drv if rel == DRIVER_REL else os.path.join(DIST_DIR, rel.replace("/", os.sep))
        with open(src, "rb") as f:
            raw = f.read()
        comp = zlib.compress(raw, 9)
        with open(os.path.join(res_dir, "f%d.bin" % nid), "wb") as f:
            f.write(comp)
        entries.append((nid, rel, len(raw), len(comp)))
        nid += 1

    # ---- 清单 ----
    # 格式：<ID>\t<相对路径>\t<原始字节数>\t<压缩后字节数>
    # ★ 原始大小那一列是**断言用**的：C 端解压后必须得到这个长度，否则
    #   说明资源编错了。只断言"解压函数返回成功"是不够的 —— 截断的
    #   资源也能解压成功（解出个短的）。
    man = os.path.join(res_dir, "manifest.txt")
    with open(man, "w", encoding="utf-8", newline="\n") as f:
        for i, rel, raw_sz, zip_sz in entries:
            f.write("%d\t%s\t%d\t%d\n" % (i, rel, raw_sz, zip_sz))

    # ---- 卸载脚本（GBK 二进制，原样内嵌，不做任何转码）----
    shutil.copyfile(unb, os.path.join(res_dir, "uninstall.bat"))

    # ---- payload.rc ----
    lines = [
        "/* 由 gen_payload_rc.py 自动生成 —— 不要手改 */",
        "#include <winresrc.h>",
        "",
        "/* 清单：<ID>\\t<相对路径>\\t<字节数>（UTF-8） */",
        '%d RCDATA "%s"' % (RES_ID_MANIFEST, rc_path(man)),
        "/* 卸载脚本（GBK 原样） */",
        '%d RCDATA "%s"' % (RES_ID_UNINSTALL, rc_path(os.path.join(res_dir, "uninstall.bat"))),
        "",
    ]
    for i, rel, raw_sz, zip_sz in entries:
        # 注释里带上相对路径 —— 出问题时能直接看出哪个资源对应哪个文件
        lines.append("/* %s  (原始 %d -> 压缩 %d 字节) */" % (rel, raw_sz, zip_sz))
        lines.append('%d RCDATA "%s"' % (i, rc_path(os.path.join(res_dir, "f%d.bin" % i))))
    rc = os.path.join(out_dir, "payload.rc")
    with open(rc, "w", encoding="utf-8", newline="\r\n") as f:
        f.write("\n".join(lines) + "\n")

    raw_total = sum(e[2] for e in entries)
    zip_total = sum(e[3] for e in entries)
    print("  资源目录 : %s" % res_dir)
    print("  清单     : %s" % man)
    print("  资源脚本 : %s" % rc)
    print("  条目     : %d 个 payload + 1 个清单 + 1 个卸载脚本" % len(entries))
    print("  原始总量 : %d 字节 (%.1f MB)" % (raw_total, raw_total / 1024.0 / 1024.0))
    print("  压缩后   : %d 字节 (%.1f MB, %.0f%%)" % (
        zip_total, zip_total / 1024.0 / 1024.0,
        100.0 * zip_total / max(1, raw_total)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

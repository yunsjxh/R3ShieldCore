#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pe_version.py —— 从 PE 的**资源目录**里读出真实的版本号（RT_VERSION）。

为什么要专门写这个
==================
v1.0.1 出包前发现：主程序 `R3 Shield Core.exe` 在资源管理器「详细信息」里
**版本号是空的**，而 build.sh 明明传了 `/VERSION:65.0`。

真因：`link /VERSION:x.y` 写的是 **PE 可选头的 ImageVersion 两个字段**，
它**不是资源**、也不会生成 RT_VERSION。而 `r3shieldcore.rc` 的注释一直写着
"link 会自动生成一份 VS_VERSION_INFO" —— 于是这一版之前**从来没有过**版本资源。

★ 这就是"构建报绿 ≠ 功能存在"（铁律 137）的又一例：
  rc.exe 返回 0、link 返回 0、exe 正常运行，只有右键属性是空的。

常见的**假判据**：
  ✗ `grep "FileVersion" xxx.rc`   → 只证明**源码里写了**，不证明编进产物了
  ✗ `grep -a "1.0.1.0" exe`       → UTF-16 存储，ASCII grep 永远搜不到（假绿）
  ✗ 用 PowerShell 读 VersionInfo  → 能用，但闸门是 bash，跨进程调用又慢又脆

真判据：走 PE 资源目录树 → RT_VERSION → VS_FIXEDFILEINFO 的
        dwFileVersionMS/LS，把它还原成 `major.minor.build.revision`。

用法
====
    python pe_version.py <exe>                  # 只打印读到的版本号
    python pe_version.py <exe> 1.0.1.0          # 顺带比对，不一致就报错

退出码：
    0 = 有版本资源（给了期望值时必须相等）
    2 = 没有 RT_VERSION（真失败：右键属性里版本是空的）
    3 = 文件不是合法 PE / 读不了
    4 = 有版本资源但与期望值不符（只比前三段：build 段允许为 0）
"""

import struct
import sys


def _rva_to_off(sections, rva):
    for va, vsize, raw, rawsize in sections:
        if va <= rva < va + max(vsize, rawsize):
            return raw + (rva - va)
    return None


def _u16(b, off):
    return struct.unpack_from("<H", b, off)[0]


def _u32(b, off):
    return struct.unpack_from("<I", b, off)[0]


def _load_sections(data):
    """返回 (sections, res_base)；失败返回 (None, None)。"""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None, None
    e_lfanew = _u32(data, 0x3C)
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return None, None

    coff = e_lfanew + 4
    n_sections = _u16(data, coff + 2)
    opt_size = _u16(data, coff + 16)
    opt = coff + 20
    magic = _u16(data, opt)
    if magic == 0x20B:      # PE32+
        dd = opt + 0x70
    elif magic == 0x10B:    # PE32
        dd = opt + 0x60
    else:
        return None, None

    res_rva = _u32(data, dd + 2 * 8)     # DataDirectory[2] = 资源表
    if res_rva == 0:
        return [], None

    sec_off = opt + opt_size
    sections = []
    for i in range(n_sections):
        s = sec_off + i * 40
        vsize = _u32(data, s + 8)
        va = _u32(data, s + 12)
        rawsize = _u32(data, s + 16)
        raw = _u32(data, s + 20)
        sections.append((va, vsize, raw, rawsize))

    return sections, _rva_to_off(sections, res_rva)


def _find_entry(data, dir_off, want_id):
    """在 IMAGE_RESOURCE_DIRECTORY 里找 Name==want_id 的条目，返回 OffsetToData。"""
    named = _u16(data, dir_off + 12)
    ids = _u16(data, dir_off + 14)
    ent = dir_off + 16
    for i in range(named + ids):
        e = ent + i * 8
        name = _u32(data, e)
        if name & 0x80000000:       # 字符串名，不关心
            continue
        if (name & 0xFFFF) == want_id:
            return _u32(data, e + 4)
    return None


def read_file_version(data):
    """
    返回 (file_version_tuple, product_version_tuple) 或 None。
    """
    sections, base = _load_sections(data)
    if sections is None:
        raise ValueError("不是合法 PE")
    if base is None:
        return None                     # 完全没有资源

    # 第 1 层：类型。RT_VERSION = 16
    sub = _find_entry(data, base, 16)
    if sub is None or not (sub & 0x80000000):
        return None
    # 第 2 层：名字（通常是 1）。取第一条即可。
    name_dir = base + (sub & 0x7FFFFFFF)
    named = _u16(data, name_dir + 12)
    ids = _u16(data, name_dir + 14)
    if named + ids == 0:
        return None
    lang = _u32(data, name_dir + 16 + 4)
    if not (lang & 0x80000000):
        return None
    # 第 3 层：语言。取第一条 = IMAGE_RESOURCE_DATA_ENTRY
    lang_dir = base + (lang & 0x7FFFFFFF)
    if _u16(data, lang_dir + 12) + _u16(data, lang_dir + 14) == 0:
        return None
    leaf = _u32(data, lang_dir + 16 + 4)
    if leaf & 0x80000000:               # 不该再是子目录
        return None
    de = base + leaf
    data_rva = _u32(data, de)
    data_size = _u32(data, de + 4)

    blob_off = _rva_to_off(sections, data_rva)
    if blob_off is None:
        return None
    blob = data[blob_off:blob_off + data_size]

    # ★ 不逐字段解析 VS_VERSIONINFO 的对齐规则（wLength/wValueLength/padding
    #   在 32/64 位、不同 rc 编译器下有差异），直接找 VS_FIXEDFILEINFO 的签名。
    #   0xFEEF04BD 在整块里唯一，且紧跟着就是四个版本 dword。
    sig = struct.pack("<I", 0xFEEF04BD)
    p = blob.find(sig)
    if p < 0 or p + 24 > len(blob):
        return None
    ms = _u32(blob, p + 8)
    ls = _u32(blob, p + 12)
    pms = _u32(blob, p + 16)
    pls = _u32(blob, p + 20)
    fv = (ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF)
    pv = (pms >> 16, pms & 0xFFFF, pls >> 16, pls & 0xFFFF)
    return fv, pv


def main():
    if len(sys.argv) < 2:
        print("用法: python pe_version.py <exe> [期望版本，如 1.0.1.0]")
        return 1
    path = sys.argv[1]
    want = sys.argv[2].strip() if len(sys.argv) > 2 else None

    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        print("读不了文件: %s (%s)" % (path, e))
        return 3

    try:
        got = read_file_version(data)
    except ValueError as e:
        print("%s: %s" % (path, e))
        return 3

    if got is None:
        print("%s: 没有 RT_VERSION 资源 —— 右键属性里版本号会是空的" % path)
        return 2

    fv, pv = got
    fvs = "%d.%d.%d.%d" % fv
    pvs = "%d.%d.%d.%d" % pv
    print("%s: FileVersion=%s ProductVersion=%s" % (path, fvs, pvs))

    if want:
        # ★ 只比前三段：第四段（revision）在不同链接器下常被填 0，
        #   拿它当判据会变成"换台机器就红"（铁律 184）。
        w = want.split(".")
        if len(w) < 3:
            print("期望版本要至少三段，如 1.0.1.0（收到 %r）" % want)
            return 1
        if fv[:3] != tuple(int(x) for x in w[:3]):
            print("版本不符：产物 %s，期望 %s" % (fvs, want))
            return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())

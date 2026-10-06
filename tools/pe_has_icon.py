#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pe_has_icon.py —— 判断一个 PE 文件的**资源目录**里到底有没有图标。

为什么要专门写这个
==================
"构建成功"完全不能证明图标编进去了。资源 .res 漏喂给 link 时：
  · rc.exe 返回 0（它编的没错）；
  · link 返回 0（它链接的也没错）；
  · exe 正常启动、功能一切正常；
  · 只是图标悄悄变回系统的空白默认图标。
—— 又一个"构建报绿 ≠ 功能存在"（铁律 137）。

常见的**假判据**（本项目都踩过或差点踩）：
  ✗ `grep -q ".rsrc"` 产物      → /MANIFEST:EMBED 下 link **总会**建 .rsrc
                                  装 manifest，所以这个条件恒真（铁律 110）。
  ✗ `grep -a "RT_ICON" 产物`    → 资源表里存的是**数字 ID**，不是这个名字。
  ✗ 只看 .rsrc 段大小           → manifest 也有几十 KB，阈值不好定，
                                   而且换了图标尺寸就漂。

真判据：直接走 PE 资源目录树，看**类型层**里有没有
    ID 3  (RT_ICON)       单个图标位图
    ID 14 (RT_GROUP_ICON) 图标组（shell 实际读的是这个）
两个都在才算图标真的进了 exe。

用法
====
    python pe_has_icon.py <exe>
退出码：
    0 = 有图标
    2 = 没有图标（真失败）
    3 = 文件不是合法 PE / 读不了（区别于"没有图标"，便于分型诊断）
"""

import struct
import sys


def _rva_to_off(sections, rva):
    """把 RVA 映射到文件偏移。资源目录里的地址都是 RVA。"""
    for va, vsize, raw, rawsize in sections:
        if va <= rva < va + max(vsize, rawsize):
            return raw + (rva - va)
    return None


def _read_u16(b, off):
    return struct.unpack_from("<H", b, off)[0]


def _read_u32(b, off):
    return struct.unpack_from("<I", b, off)[0]


def parse_resource_types(data):
    """
    返回资源目录**类型层**的 ID 集合（如 {3, 14, 16, 24, 10}）。
    失败返回 None。
    """
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    e_lfanew = _read_u32(data, 0x3C)
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return None

    coff = e_lfanew + 4
    n_sections = _read_u16(data, coff + 2)
    opt_size = _read_u16(data, coff + 16)
    opt = coff + 20
    magic = _read_u16(data, opt)
    if magic == 0x20B:          # PE32+
        n_dir_off = opt + 0x6C + 4      # NumberOfRvaAndSizes 之后是第 0 项
        dd = opt + 0x70
    elif magic == 0x10B:        # PE32
        dd = opt + 0x60
    else:
        return None

    # DataDirectory[2] = 资源表
    res_rva = _read_u32(data, dd + 2 * 8)
    if res_rva == 0:
        return set()            # 完全没资源

    sec_off = opt + opt_size
    sections = []
    for i in range(n_sections):
        s = sec_off + i * 40
        vsize = _read_u32(data, s + 8)
        va = _read_u32(data, s + 12)
        rawsize = _read_u32(data, s + 16)
        raw = _read_u32(data, s + 20)
        sections.append((va, vsize, raw, rawsize))

    base = _rva_to_off(sections, res_rva)
    if base is None:
        return None

    # IMAGE_RESOURCE_DIRECTORY: 16 字节头 + entries
    # ★ 类型层的 Name 字段是**整数 ID**（高位为 0 时）；高位为 1 表示
    #   指向字符串，本工具不关心。Named entries 排在前，随后是 ID entries，
    #   但两者都在同一张表里，靠 Name 高位区分。
    named = _read_u16(data, base + 12)
    ids = _read_u16(data, base + 14)
    types = set()
    ent = base + 16
    for i in range(named + ids):
        e = ent + i * 8
        name = _read_u32(data, e)
        if not (name & 0x80000000):
            types.add(name & 0xFFFF)
    return types


def main():
    if len(sys.argv) < 2:
        print("用法: python pe_has_icon.py <exe>")
        return 1
    path = sys.argv[1]
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        print("读不了文件: %s (%s)" % (path, e))
        return 3

    types = parse_resource_types(data)
    if types is None:
        print("%s: 不是合法 PE 或资源目录损坏" % path)
        return 3

    # 3 = RT_ICON, 14 = RT_GROUP_ICON
    has_icon = 3 in types
    has_group = 14 in types
    if has_icon and has_group:
        print("%s: OK 有图标（RT_ICON=3, RT_GROUP_ICON=14）；资源类型=%s"
              % (path, sorted(types)))
        return 0
    print("%s: 缺图标！资源类型=%s（需要 3 和 14）"
          % (path, sorted(types) if types else "空"))
    return 2


if __name__ == "__main__":
    sys.exit(main())

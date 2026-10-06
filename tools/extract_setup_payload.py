#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract_setup_payload.py —— 从 `dist/R3ShieldCore-Setup.exe` 里**把 payload 抠出来**，
再和 `dist/R3ShieldCore-x64/` 里的磁盘文件逐字节比对。

【为什么需要它 —— 铁律 153 / 162】

    "构建出来的产物" ≠ "装进去的产物"。

    安装包的 payload 是**构建期**由 `installer/gen_payload_rc.py` 从 dist 读出来、
    zlib 压掉、编成 RCDATA 资源塞进 exe 的。所以只要"重编了 payload 却没重打安装包"，
    或者"重打了安装包但 dist 又被换了"，**包里和盘上就不一样**。

    而这件事从外面**完全看不出来**：
      · 安装包体积正常、PE 合法、双击能装；
      · `--verify` 能过（它校验的是"包内自洽"，不是"和 dist 一致"）；
      · 自测也能过（它跑的是解包后的文件，不会回头比 md5）。
    ⇒ 必须**直接解析 PE 资源表**，把每个 ID 解出来，和 dist 里的文件比 md5。

【为什么不跑 `--verify` 而是自己解析】

    `R3ShieldCore-Setup.exe` 的 manifest 是 `requireAdministrator`。
    从 bash / CI 里起它必然 `CreateProcess` 失败 **err=740**（铁律 130），
    拿不到任何输出。所以"验证包里有什么"这件事**只能静态做**。

【资源布局】（必须与 `installer/gen_payload_rc.py` 一致，改了那边要改这边）

    ID 1          RCDATA  manifest.txt   **未压缩**，UTF-8
    ID 2          RCDATA  uninstall.bat  **未压缩**，GBK（原样内嵌）
    ID 1000..     RCDATA  每个 payload   **zlib 压缩**
    ID 起始值 / 顺序见 gen_payload_rc.py 的 RES_ID_BASE 与 DIST_FILES

    清单每行： <ID>\\t<相对路径>\\t<原始字节数>\\t<压缩后字节数>

【★ 断言"原始字节数"这一列】

    只断言"zlib 解压成功"是不够的 —— **被截断的资源也能解压成功**（解出个短的）。
    所以必须比：解压后长度 == 清单里的原始字节数，**并且** md5 == dist 里的文件。

用法：
    python tools/extract_setup_payload.py
    python tools/extract_setup_payload.py --list      # 只列清单，不比对
    python tools/extract_setup_payload.py --dump DIR  # 把 payload 解到 DIR
退出码：0 = 包里和 dist 完全一致；1 = 有差异 / 解析失败
"""

import hashlib
import os
import struct
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SETUP_EXE = os.path.join(ROOT, "dist", "R3ShieldCore-Setup.exe")
DIST_DIR = os.path.join(ROOT, "dist", "R3ShieldCore-x64")
UNINSTALL_BAT = os.path.join(ROOT, "installer", "uninstall.bat")

# ---------------------------------------------------------------------------
# ★ 驱动是**安装包专有**的 payload，**不在 dist 里** —— 它的对照物是构建源。
# ---------------------------------------------------------------------------
#   为什么不在 dist：内核驱动要管理员 + 签名（或测试签名）才能装，
#   绿色包是"解压即用"，不承担装驱动的职责。
#   所以 `gen_payload_rc.py` 里驱动的源是 `driver/build/r3shieldcore_kernel.sys`，
#   而它在包内的相对路径是 `driver\r3shieldcore_kernel.sys`（安装后的落点）。
#
#   ⚠️ 这两个常量必须和 `installer/gen_payload_rc.py` 的 DRIVER_SRC / DRIVER_REL
#      保持一致。漂了会怎样：本工具会把驱动当成"dist 里缺文件"而**报假 FAIL**
#      （本工具第一次跑就是这么红的 —— 见下面 manifest 里那条存在性断言）。
DRIVER_REL = "driver/r3shieldcore_kernel.sys"
DRIVER_SRC = os.path.join(ROOT, "driver", "build", "r3shieldcore_kernel.sys")

RES_ID_MANIFEST = 1
RES_ID_UNINSTALL = 2
RES_TYPE_RCDATA = 10


def disk_counterpart(rel):
    """包内相对路径 → 磁盘上应当逐字节相等的那个文件。"""
    if rel == DRIVER_REL:
        return DRIVER_SRC
    return os.path.join(DIST_DIR, rel.replace("/", os.sep))


# ===========================================================================
# 极简 PE 解析（只做"找到资源段 + 走资源目录树"这一件事）
# ===========================================================================

def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def rva_to_off(sections, rva):
    """把 RVA 映射成文件偏移。找不到返回 None（调用方必须当成失败）。"""
    for va, vsize, praw, rsize in sections:
        span = max(vsize, rsize)
        if va <= rva < va + span:
            return rva - va + praw
    return None


def parse_sections(data):
    e_lfanew = _u32(data, 0x3C)
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise ValueError("不是 PE 文件（e_lfanew 处没有 PE 签名）")

    coff = e_lfanew + 4
    num_sections = _u16(data, coff + 2)
    size_opt = _u16(data, coff + 16)
    opt = coff + 20

    magic = _u16(data, opt)
    if magic == 0x20B:
        dd_off = opt + 112
    elif magic == 0x10B:
        dd_off = opt + 96
    else:
        raise ValueError("未知的 Optional Header magic: 0x%X" % magic)

    # DataDirectory[2] = Resource Table
    res_rva = _u32(data, dd_off + 2 * 8)
    res_size = _u32(data, dd_off + 2 * 8 + 4)

    sections = []
    sec = opt + size_opt
    for i in range(num_sections):
        o = sec + i * 40
        va = _u32(data, o + 12)
        vsize = _u32(data, o + 8)
        rsize = _u32(data, o + 16)
        praw = _u32(data, o + 20)
        sections.append((va, vsize, praw, rsize))

    return sections, res_rva, res_size


def walk_resources(data, sections, res_rva, res_size):
    """返回 {type_id: {name_or_id: {lang: (data_rva, size)}}}。

    只关心**数字 ID**（本项目的资源全是数字 ID），命名条目直接跳过并记录。
    """
    base = rva_to_off(sections, res_rva)
    if base is None:
        raise ValueError("资源目录 RVA 0x%X 不在任何节里" % res_rva)

    out = {}
    named = []

    def entries_of(dir_off):
        """列出一个 IMAGE_RESOURCE_DIRECTORY 的所有条目。"""
        nnamed = _u16(data, dir_off + 12)
        nid = _u16(data, dir_off + 14)
        res = []
        p = dir_off + 16
        for i in range(nnamed + nid):
            name = _u32(data, p)
            off = _u32(data, p + 4)
            res.append((name, off))
            p += 8
        return res

    for name, off in entries_of(base):
        is_named = bool(name & 0x80000000)
        type_id = name & 0x7FFFFFFF if not is_named else None
        if is_named or not (off & 0x80000000):
            named.append(("type", name))
            continue
        lvl2 = base + (off & 0x7FFFFFFF)
        out.setdefault(type_id, {})
        for name2, off2 in entries_of(lvl2):
            if name2 & 0x80000000 or not (off2 & 0x80000000):
                named.append(("name", name2))
                continue
            item_id = name2 & 0x7FFFFFFF
            lvl3 = base + (off2 & 0x7FFFFFFF)
            for name3, off3 in entries_of(lvl3):
                if off3 & 0x80000000:
                    named.append(("lang-subdir", name3))
                    continue
                lang = name3 & 0x7FFFFFFF
                ent = base + off3
                data_rva = _u32(data, ent)
                size = _u32(data, ent + 4)
                out[type_id][item_id] = (data_rva, size)

    return out, named


def get_rcdatas(data, sections, res):
    """取 RCDATA 下所有 {id: bytes}。"""
    result = {}
    for item_id, (data_rva, size) in res.get(RES_TYPE_RCDATA, {}).items():
        off = rva_to_off(sections, data_rva)
        if off is None:
            raise ValueError("资源 ID %d 的数据 RVA 0x%X 不在任何节里" % (item_id, data_rva))
        result[item_id] = data[off:off + size]
    return result


# ===========================================================================

def md5(b):
    return hashlib.md5(b).hexdigest()


def md5_file(p):
    with open(p, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def main():
    args = sys.argv[1:]
    only_list = "--list" in args
    dump_dir = None
    if "--dump" in args:
        i = args.index("--dump")
        if i + 1 >= len(args):
            print("用法: --dump <目录>")
            return 1
        dump_dir = args[i + 1]

    g_pass = 0
    g_fail = 0

    def check(ok, label, detail=""):
        nonlocal g_pass, g_fail
        if ok:
            g_pass += 1
        else:
            g_fail += 1
        print("%s %s%s" % ("  ok  " if ok else "  FAIL", label,
                           ("  -- " + detail) if detail else ""))
        return ok

    print("=== 安装包 payload 解包比对（铁律 153/162）===")
    print("安装包 : %s" % SETUP_EXE)
    print("对照   : %s" % DIST_DIR)
    print("")

    if not os.path.isfile(SETUP_EXE):
        print("  FAIL 安装包不存在（先跑 bash installer/build_setup.sh）")
        return 1

    with open(SETUP_EXE, "rb") as f:
        data = f.read()
    print("安装包大小 : %d 字节" % len(data))

    try:
        sections, res_rva, res_size = parse_sections(data)
        res, named = walk_resources(data, sections, res_rva, res_size)
        rcdatas = get_rcdatas(data, sections, res)
    except Exception as e:
        print("  FAIL PE 解析失败: %s" % e)
        return 1

    print("资源类型   : %s" % sorted(res.keys()))
    print("RCDATA 条目: %d 个（ID: %s）"
          % (len(rcdatas), ", ".join(str(k) for k in sorted(rcdatas))))
    if named:
        print("命名条目   : %s（本工具只处理数字 ID）" % named[:5])
    print("")

    # ---- ① 清单必须存在且能解析 ------------------------------------------
    if not check(RES_ID_MANIFEST in rcdatas, "清单资源 ID=%d 存在" % RES_ID_MANIFEST):
        return 1
    try:
        manifest = rcdatas[RES_ID_MANIFEST].decode("utf-8")
    except UnicodeDecodeError as e:
        check(False, "清单是合法 UTF-8", str(e))
        return 1
    check(True, "清单是合法 UTF-8（%d 字节）" % len(rcdatas[RES_ID_MANIFEST]))

    rows = []
    for line in manifest.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) != 4:
            check(False, "清单行格式（应为 4 列）", repr(line))
            continue
        rows.append((int(parts[0]), parts[1], int(parts[2]), int(parts[3])))

    check(len(rows) > 0, "清单解析出条目", "%d 条" % len(rows))

    if only_list:
        print("")
        for i, rel, raw_sz, zip_sz in rows:
            print("  ID %-6d %-40s raw=%-9d zip=%d" % (i, rel, raw_sz, zip_sz))
        print("\n（--list 模式：只列清单，不比对）")
        return 0

    # ---- ② 清单里的每个 ID 都要在资源里，且解压后长度/md5 都对 ------------
    print("\n--- 逐条比对（解压长度 + md5）---")
    for i, rel, raw_sz, zip_sz in rows:
        if i not in rcdatas:
            check(False, "ID %d (%s) 在资源里" % (i, rel), "资源表里没有这个 ID")
            continue
        blob = rcdatas[i]
        # 压缩后长度也要对（清单里第二列）
        if not check(len(blob) == zip_sz,
                     "ID %-5d %-34s 压缩后长度 %d" % (i, rel, zip_sz),
                     "实际=%d" % len(blob)):
            continue
        try:
            raw = zlib.decompress(blob)
        except zlib.error as e:
            check(False, "ID %-5d %-34s zlib 解压" % (i, rel), str(e))
            continue
        # ★ 只断言"解压成功"不够 —— 截断的资源也能解压成功。必须比长度。
        if not check(len(raw) == raw_sz,
                     "ID %-5d %-34s 解压后长度 %d" % (i, rel, raw_sz),
                     "实际=%d" % len(raw)):
            continue

        disk = disk_counterpart(rel)
        if not os.path.isfile(disk):
            check(False, "ID %-5d %-34s 对照文件存在" % (i, rel), disk)
            continue
        a, b = md5(raw), md5_file(disk)
        check(a == b, "ID %-5d %-34s md5 一致" % (i, rel),
              "包里=%s 盘上=%s" % (a[:12], b[:12]))

        if dump_dir:
            os.makedirs(dump_dir, exist_ok=True)
            dst = os.path.join(dump_dir, rel.replace("/", os.sep))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as f:
                f.write(raw)

    # ---- ③ 资源里不能有清单没登记的 ID（多编进去的东西同样是问题）--------
    print("\n--- 反向：资源里的 ID 都要在清单里 ---")
    known = {r[0] for r in rows} | {RES_ID_MANIFEST, RES_ID_UNINSTALL}
    extra = sorted(set(rcdatas) - known)
    check(not extra, "没有清单外的多余 ID", "多余=%s" % extra if extra else "")

    # ---- ③b 驱动的相对路径必须真的出现在清单里 --------------------------
    #
    # ★ 为什么单独断言：驱动**不在 dist 里**（对照物是 driver/build/），
    #   所以它走的是 disk_counterpart() 的特例分支。万一 gen_payload_rc.py
    #   把 DRIVER_REL 改名了，本工具的特例就**匹配不上** ——
    #   那时它会退化成"去 dist/driver/... 找"，然后报一条**假 FAIL**，
    #   把排查方向引到"dist 是不是漏打包了驱动"上（本工具第一次跑就是这情况）。
    #   有了这条断言，改名会在这里直接红，且原因写在脸上。
    print("\n--- 驱动 payload 的相对路径登记 ---")
    rels = {r[1] for r in rows}
    check(DRIVER_REL in rels,
          "清单里有驱动条目 '%s'" % DRIVER_REL,
          "清单里带 driver/ 的条目=%s" % sorted(r for r in rels if "driver" in r))
    check(os.path.isfile(DRIVER_SRC), "驱动构建源存在", DRIVER_SRC)

    # ---- ④ 卸载脚本（GBK 原样内嵌，不压缩）-------------------------------
    print("\n--- 卸载脚本（ID %d，原样内嵌不压缩）---" % RES_ID_UNINSTALL)
    if check(RES_ID_UNINSTALL in rcdatas, "卸载脚本资源存在"):
        blob = rcdatas[RES_ID_UNINSTALL]
        if os.path.isfile(UNINSTALL_BAT):
            a, b = md5(blob), md5_file(UNINSTALL_BAT)
            check(a == b, "卸载脚本 md5 一致",
                  "包里=%s 盘上=%s" % (a[:12], b[:12]))
        else:
            check(False, "installer/uninstall.bat 存在", UNINSTALL_BAT)
        # ★ 卸载脚本必须是**未压缩**的原样内嵌 —— 试解压应当失败。
        #   如果它能被 zlib 解开，说明有人给它加上了压缩，而 C 端是**按原样**
        #   写的（不经过 zlib）⇒ 卸载时写出来的是压缩字节 = 一个坏 bat。
        try:
            zlib.decompress(blob)
            check(False, "卸载脚本确实是未压缩的原样字节",
                  "它居然能 zlib 解压 ⇒ 和 C 端的读法不一致了")
        except zlib.error:
            check(True, "卸载脚本确实是未压缩的原样字节")

    print("\n=== 结果：%d 通过 / %d 失败 ===" % (g_pass, g_fail))
    if g_fail == 0:
        print("PASS：安装包里装的就是 dist 里现在这些文件（逐条 md5 相等）。")
    else:
        print("FAIL：安装包与 dist 不一致 —— **不要发布**，重跑 installer/build_setup.sh。")
    return 0 if g_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

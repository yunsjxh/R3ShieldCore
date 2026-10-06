#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_payload_manifest.py —— 安装包 payload 清单一致性闸门

【为什么需要它】
安装包的 payload 清单（20 个发布文件 + 1 个内核驱动）**同时存在于 6 个文件里**，
而且每一份都是"手写的一份拷贝"：

    1. installer/gen_payload_rc.py    → DIST_FILES      （决定往 .rc 里塞哪些文件）
    2. installer/build_installer.sh   → DIST_FILES      （iexpress 老路的预检清单）
    3. installer/selftest_setup.py    → DIST_FILES      （自测的期望清单）
    4. installer/r3sc_setup.c         → ENGINE_EXE / DRV_SYS_NAME（安装器运行时用的名字）
    5. tools/diag_autostart.py        → 排查工具的常量（第 5 份拷贝）
    6. tools/diag_autostart.bat       → 排查工具的常量（第 6 份拷贝）

★ 又踩过（2026-10-05，同一个坑的第二次）：新写的排查工具 `diag_autostart.*`
  把引擎名漂成了 `R3 Shield Core.exe`（多一个空格），于是它报出
  "安装目录里缺主程序"这条**假 FAIL** —— 排查方向被引到"是不是被杀软删了主程序"上。
  **同一个坑踩两次**，说明"记得小心"根本不是修法，闸门才是。

★ 踩过（v65c）：自测第 4 层把引擎名手写成 `R3 Shield Core.exe`（Shield 和 Core
  之间**多了一个空格**），真名是 `R3 ShieldCore.exe`。结果**安装完全正常**，
  自测却报了一条 FAIL —— 排查方向被引到"安装器是不是没装引擎"上，浪费一轮。
  同一份清单的第 1 层、第 2 层用的是正确名字，所以那两层全绿、只有第 4 层红。

★ 通用化（铁律 115/116 的同类）：**同一份"名字清单"只要被拷贝多份，就一定会漂。**
  修法不是"下次小心点"，而是：
    · 能收敛成一处就收敛（自测里的 KEY_FILES 就是这么做的）；
    · 收敛不了的（跨语言：Python / Bash / C），就必须有一条闸门**互相比对**。

【判据】
  A. 三份 DIST_FILES 必须**逐项相等**（顺序也一致 —— 顺序决定资源 ID，改了顺序
     等于改了产物字节，会让"产物可复现"这条失效）。
  B. r3sc_setup.c 的 ENGINE_EXE 必须在 DIST_FILES 里（否则安装器找不到主程序）。
  C. r3sc_setup.c 的 DRV_SYS_NAME 必须等于 gen_payload_rc.py 的 DRIVER_REL 的文件名。
     ★ 这条钉的是另一个真 bug：DRV_SYS_NAME 曾被写成服务名 R3ShieldCoreKernel.sys
       （无下划线），和 payload 里的 r3shieldcore_kernel.sys 差一个下划线
       ⇒ 驱动那步**永远静默跳过**。
  D. selftest 的 KEY_FILES 必须都真的在清单里。
  E. 清单里的每个文件必须真的存在于 dist 发布目录（缺一个就 FAIL —— 铁律 117：
     声明的路径必须存在，否则闸门会在"什么都没查"的情况下报绿）。
  F. 开机启动**服务**的名字（SVC_NAME / SVC_EXE_NAME）必须跨 C / 卸载脚本 /
     安装脚本 / 自测四处一致 —— 装一个名、卸另一个名 ⇒ 服务**永远删不掉**。
  G. 排查工具（diag_autostart.py / .bat）里的 ENGINE_EXE / SVC_NAME / SVC_EXE /
     DRV_SVC / DRV_SYS / DEFAULT_DIR 必须与安装器**逐个相等** —— 排查器查错对象
     会给出**假结论**，比查不出来更贵（铁律 127）。

用法：
    python tools/check_payload_manifest.py           # 检查
    python tools/check_payload_manifest.py --quiet   # 只在失败时输出
    python tools/check_payload_manifest.py --selftest # 负对照：证明本闸门真的会失败
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

GEN_PY = os.path.join(ROOT, "installer", "gen_payload_rc.py")
BUILD_SH = os.path.join(ROOT, "installer", "build_installer.sh")
SETUP_C = os.path.join(ROOT, "installer", "r3sc_setup.c")
SELFTEST = os.path.join(ROOT, "installer", "selftest_setup.py")
UNINSTALL = os.path.join(ROOT, "installer", "uninstall.bat")
INSTALL = os.path.join(ROOT, "installer", "install.bat")
# ★ 2026-10-05：排查工具也是"名字清单的又一份拷贝"，必须一起钉。
DIAG_PY = os.path.join(ROOT, "tools", "diag_autostart.py")
DIAG_BAT = os.path.join(ROOT, "tools", "diag_autostart.bat")
DIST_DIR = os.path.join(ROOT, "dist", "R3ShieldCore-x64")
DRIVER_DIR = os.path.join(ROOT, "driver", "build")

GEN = "gen_payload_rc.py"
SH = "build_installer.sh"
C = "r3sc_setup.c"
ST = "selftest_setup.py"
UN = "uninstall.bat"
IN = "install.bat"
DP = "diag_autostart.py"
DB = "diag_autostart.bat"


def read_text(path):
    """按 UTF-8 读；失败则按 GBK 兜底（本仓 .bat 是 GBK）。"""
    with open(path, "rb") as f:
        raw = f.read()
    for enc in ("utf-8", "gbk"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def extract_block_list(text, start_pat, what, ident_map, fails):
    """从 `NAME = [` / `NAME=(` 开始，取到配对的 `]` / `)`，抽出其中的项。

    ★ 项有两种形态：**字面量**（"a/b.txt"）和**裸标识符**（DRIVER_REL）。
      第一版只认字面量 ⇒ `KEY_FILES` 里那个 `DRIVER_REL` 被**静默丢掉**，
      闸门报"4 项全在清单里"而实际块里有 5 项 —— 闸门自己犯了"静默漏检"
      （铁律 117/103：漏检不会自己暴露，因为漏掉的正是可能出问题的那项）。
      现在：认识的标识符查表替换，不认识的**直接 FAIL**，绝不静默丢。
    """
    # ★ 必须带 re.M：`^DIST_FILES` 是**行首**锚点，不带 MULTILINE 时 `^` 只匹配
    #   整个文本的开头 ⇒ 三份清单全部"找不到"，闸门以 4 条 FAIL 的形态**假失败**。
    m = re.search(start_pat, text, re.M)
    if not m:
        fails.append("%s：找不到清单块（正则 %r）" % (what, start_pat))
        return None
    tail = text[m.end():]
    # 找第一个收尾括号（本仓这两个块的内部不含括号）
    m2 = re.search(r"[\]\)]", tail)
    if not m2:
        fails.append("%s：清单块没有收尾括号" % what)
        return None
    body = tail[:m2.start()]

    items = re.findall(r'"([^"\n]+)"', body) + re.findall(r"'([^'\n]+)'", body)

    # 把注释和字面量都抠掉，剩下的就是裸标识符
    stripped = "\n".join(l.split("#", 1)[0] for l in body.splitlines())
    stripped = re.sub(r'"[^"\n]*"', " ", stripped)
    stripped = re.sub(r"'[^'\n]*'", " ", stripped)
    for ident in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", stripped):
        if ident in ident_map:
            val = ident_map[ident]
            if val is None:
                fails.append("%s：标识符 %s 无法解析（上游定义缺失）" % (what, ident))
            elif val not in items:
                items.append(val)
        else:
            fails.append("%s：清单块里有无法解析的项 %r —— 闸门只认字面量和已知标识符；"
                         "**不认识就报错，绝不静默跳过**（否则会少数）" % (what, ident))

    if not items:
        fails.append("%s：清单块是空的（铁律 117 —— 空的检查会假绿）" % what)
        return None
    return items


def extract_define(text, name, what, fails):
    m = re.search(r'#define\s+%s\s+L"([^"]+)"' % re.escape(name), text)
    if not m:
        fails.append("%s：找不到 #define %s" % (what, name))
        return None
    return m.group(1)


def extract_assign_str(text, name, what, fails):
    m = re.search(r'^%s\s*=\s*"([^"]+)"' % re.escape(name), text, re.M)
    if not m:
        fails.append("%s：找不到 %s = \"...\"" % (what, name))
        return None
    return m.group(1)


def check_all(texts, dist_dir, driver_dir):
    """核心检查。texts = {GEN, SH, C, ST} → 文本。返回 (fails, notes)。

    ★ 抽成函数是为了让 --selftest 能拿**改坏了的文本**去喂同一套逻辑 ——
      负对照必须走真判据，不能另写一份"我以为的判据"。
    """
    fails, notes = [], []
    gen_txt, sh_txt, c_txt, st_txt = texts[GEN], texts[SH], texts[C], texts[ST]
    un_txt = texts.get(UN, "")
    in_txt = texts.get(IN, "")
    diag_py_txt = texts.get(DP, "")
    diag_bat_txt = texts.get(DB, "")

    # ★ 先把 DRIVER_REL 解出来 —— 它是 KEY_FILES 里那个裸标识符的唯一取值来源，
    #   必须在解析 KEY_FILES **之前**拿到（否则 KEY_FILES 会少一项，静默少数）。
    driver_rel = extract_assign_str(gen_txt, "DRIVER_REL", GEN, fails)
    ident_map = {"DRIVER_REL": driver_rel}

    # ---- A. 三份 DIST_FILES ----
    gen_list = extract_block_list(gen_txt, r"^DIST_FILES\s*=\s*\[", GEN, ident_map, fails)
    sh_list = extract_block_list(sh_txt, r"^DIST_FILES=\(", SH, ident_map, fails)
    st_list = extract_block_list(st_txt, r"^DIST_FILES\s*=\s*\[", ST, ident_map, fails)

    for other_list, other_name in ((sh_list, SH), (st_list, ST)):
        if gen_list is None or other_list is None:
            continue
        if gen_list == other_list:
            notes.append("DIST_FILES：%s == %s（%d 项）" % (GEN, other_name, len(gen_list)))
            continue
        only_gen = [x for x in gen_list if x not in other_list]
        only_oth = [x for x in other_list if x not in gen_list]
        if only_gen or only_oth:
            fails.append("DIST_FILES 不一致（%s vs %s）：只在 %s 里 %r / 只在 %s 里 %r"
                         % (GEN, other_name, GEN, only_gen, other_name, only_oth))
        else:
            # 集合相同但顺序不同 —— 顺序决定资源 ID，同样要报
            fails.append("DIST_FILES 顺序不一致（%s vs %s）—— "
                         "顺序决定资源 ID，会改变产物字节" % (GEN, other_name))

    # ---- B/C. r3sc_setup.c 里的名字 ----
    engine_exe = extract_define(c_txt, "ENGINE_EXE", C, fails)
    drv_sys_name = extract_define(c_txt, "DRV_SYS_NAME", C, fails)
    drv_svc = extract_define(c_txt, "DRV_SVC", C, fails)

    if engine_exe and gen_list:
        if engine_exe in gen_list:
            notes.append("ENGINE_EXE %r 在 payload 清单里" % engine_exe)
        else:
            fails.append("ENGINE_EXE %r **不在** payload 清单里 —— "
                         "安装器会找不到主程序（清单里的 .exe 是 %r）"
                         % (engine_exe, [x for x in gen_list if x.lower().endswith(".exe")]))

    if drv_sys_name and driver_rel:
        if drv_sys_name == os.path.basename(driver_rel):
            notes.append("DRV_SYS_NAME %r == DRIVER_REL 的文件名" % drv_sys_name)
        else:
            fails.append("驱动文件名对不上：r3sc_setup.c 的 DRV_SYS_NAME=%r，"
                         "而 payload 里是 %r —— 驱动那步会**静默跳过**"
                         % (drv_sys_name, os.path.basename(driver_rel)))
        if drv_svc and drv_svc == drv_sys_name:
            fails.append("DRV_SVC == DRV_SYS_NAME（%r）—— 服务名和文件名被写成了同一个，"
                         "多半是把服务名当文件名用了" % drv_svc)

    # ---- D. selftest 的 KEY_FILES ----
    key_list = extract_block_list(st_txt, r"^KEY_FILES\s*=\s*\[", ST, ident_map, fails)
    if key_list is not None and gen_list is not None:
        allowed = list(gen_list) + ([driver_rel] if driver_rel else [])
        stray = [x for x in key_list if x not in allowed]
        if stray:
            fails.append("selftest 的 KEY_FILES 里有清单外的名字 %r —— "
                         "自测期望的名字必须真的会被安装（会造出假 FAIL）" % stray)
        else:
            notes.append("selftest KEY_FILES 全部在 payload 清单里（%d 项）" % len(key_list))

    # ---- F. 开机自启（**服务**）的名字必须跨文件一致 ----
    #   ★ 2026-10-05：自启机制由「计划任务」改成「Windows 服务」。
    #     服务名同样要穿过 sc.exe / 注册表多处：装的时候一个名、卸的时候另一个名
    #     ⇒ 服务**永远删不掉**，而且 `sc delete` 对不存在的服务也可能"成功"。
    #   ★ 它天然存在于 4 个文件里（C 定义 / 卸载脚本 / 安装脚本 / 自测断言），
    #     正是铁律 127 说的"拷贝多份必漂"，所以必须比对。
    svc_c = extract_define(c_txt, "SVC_NAME", C, fails)
    svc_st = extract_assign_str(st_txt, "SVC_NAME", ST, fails)

    def _svc_in_bat(txt, label, verb):
        """从 .bat 里抽 `sc[.exe] <verb> "<服务名>"` 的服务名。

        ★ 必须**排除 %VAR% 形式**：卸载/安装脚本里还有驱动那一套
          `sc.exe delete "%DRV_SVC%"`，那不是服务名而是批处理变量。
          第一版不排除的话，会把 `%DRV_SVC%` 当成"自启服务名"抓出来，
          然后报一条**假 FAIL**（比漏报更贵，铁律 127）。
        """
        if not txt:
            fails.append("缺少 %s 的文本（无法校验开机启动服务名）" % label)
            return None
        cands = re.findall(r'sc(?:\.exe)?"?\s+%s\s+"([^"]+)"' % verb, txt)
        cands = [c for c in cands if not c.startswith("%")]
        uniq = sorted(set(cands))
        if not uniq:
            fails.append("%s：找不到 `sc %s \"<服务名>\"`（已排除 %%VAR%% 形式）—— "
                         "这个脚本不处理开机启动服务" % (label, verb))
            return None
        if len(uniq) > 1:
            fails.append("%s：`sc %s` 出现了多个不同的服务名 %r —— "
                         "闸门无法判断哪个是开机启动服务" % (label, verb, uniq))
            return None
        return uniq[0]

    svc_un = _svc_in_bat(un_txt, UN, "delete")
    svc_in = _svc_in_bat(in_txt, IN, "create")

    quad = [(C, svc_c), (ST, svc_st), (UN, svc_un), (IN, svc_in)]
    named = [(n, v) for n, v in quad if v]
    if len(named) >= 2:
        base_n, base_v = named[0]
        for n, v in named[1:]:
            if v != base_v:
                fails.append("开机启动服务名不一致：%s 是 %r，而 %s 是 %r —— "
                             "装的时候一个名、卸的时候另一个名 → 服务删不掉"
                             % (base_n, base_v, n, v))
        if not any("开机启动服务名不一致" in f for f in fails):
            notes.append("开机启动服务名四处一致：%r" % base_v)

    # ---- F2. 服务二进制的名字必须和 payload 清单一致 ----
    #   ★ 名字对不上时，安装那步只会打一行"找不到 xxx"的**警告**然后继续 ——
    #     装完报成功、目录看着也齐，但开机什么都不启动（铁律 100 的形态）。
    svc_exe_c = extract_define(c_txt, "SVC_EXE_NAME", C, fails)
    svc_exe_st = extract_assign_str(st_txt, "SVC_EXE_NAME", ST, fails)

    if svc_exe_c and gen_list:
        if svc_exe_c in gen_list:
            notes.append("SVC_EXE_NAME %r 在 payload 清单里" % svc_exe_c)
        else:
            fails.append("SVC_EXE_NAME %r **不在** payload 清单里 —— "
                         "安装时开机自启那步只会打警告然后跳过（假成功）" % svc_exe_c)

    if svc_exe_c and svc_exe_st and svc_exe_c != svc_exe_st:
        fails.append("SVC_EXE_NAME 不一致：%s 是 %r，%s 是 %r"
                     % (C, svc_exe_c, ST, svc_exe_st))

    # ---- G. 清单里的文件真的在发布目录 ----
    if gen_list is not None:
        if not os.path.isdir(dist_dir):
            fails.append("发布目录不存在：%s —— 先构建（铁律 117：声明的路径必须存在，"
                         "否则闸门会在什么都没查的情况下报绿）" % dist_dir)
        else:
            missing = []
            for rel in list(gen_list) + ([driver_rel] if driver_rel else []):
                if driver_rel and rel == driver_rel:
                    p = os.path.join(driver_dir, os.path.basename(driver_rel))
                else:
                    p = os.path.join(dist_dir, rel.replace("/", os.sep))
                if not os.path.isfile(p):
                    missing.append(rel)
            if missing:
                fails.append("清单里有 %d 个文件在磁盘上不存在：%r" % (len(missing), missing))
            else:
                notes.append("清单里 %d 个文件全部存在于磁盘" % (len(gen_list) + 1))

    # ---- H. 排查工具（diag_autostart.*）里的名字必须与安装器一致 ----
    #   ★ 2026-10-05 真事故：这两个脚本把引擎名漂成了 "R3 Shield Core.exe"
    #     （Shield 和 Core 之间**多一个空格**，真名是 "R3 ShieldCore.exe"）⇒
    #     排查器报出"安装目录里缺主程序"这条**假 FAIL**，把排查方向引到
    #     "是不是被杀软删了主程序"上 —— 正是铁律 127 说的"假 FAIL 比漏报更贵"。
    #   ★ 这两个文件是**新加进来的名字拷贝**，必须并进这道闸门，否则
    #     diag_autostart.py 头部那句"漂了会被 check_payload_manifest 抓"
    #     就是空话（铁律 93：文档里写了 ≠ 代码会读）。
    app_name = extract_define(c_txt, "APP_NAME", C, fails)

    def _diag_get(txt, key, label):
        r"""抽 `set "KEY=值"`（.bat）或 `KEY = "值"` / `KEY = r"值"`（.py）。

        ★ 两种形态**必须分开写正则**。第一版合成一条
          `^\s*(?:set\s+")?KEY\s*=\s*r?"?([^"...]+?)"?\s*$`，
          那个可选的 `r?` 会把**值本身开头的 r 吃掉** ——
          `set "SVC_EXE=r3shieldcore_svc.exe"` 被读成 `3shieldcore_svc.exe`，
          于是闸门对着**完全正确的文件**报了两条 FAIL（又一条假 FAIL，铁律 127）。
        """
        if not txt:
            fails.append("缺少 %s 的文本（无法校验排查工具里的名字）" % label)
            return None
        for pat in (r'^\s*set\s+"' + key + r'=([^"\r\n]+)"\s*$',
                    r'^\s*' + key + r'\s*=\s*r?"([^"\r\n]+)"\s*$'):
            m = re.search(pat, txt, re.M)
            if m:
                return m.group(1).strip()
        return None

    for label, txt in ((DP, diag_py_txt), (DB, diag_bat_txt)):
        got_engine = _diag_get(txt, "ENGINE_EXE", label)
        if got_engine and engine_exe and got_engine != engine_exe:
            fails.append("%s 的 ENGINE_EXE=%r，而安装器是 %r —— "
                         "排查器会去找一个**不存在的文件**，报出假 FAIL（铁律 127）"
                         % (label, got_engine, engine_exe))
        elif got_engine:
            notes.append("%s 的 ENGINE_EXE %r == 安装器" % (label, got_engine))

        for key, want in (("SVC_NAME", svc_c), ("SVC_EXE", svc_exe_c),
                          ("DRV_SVC", drv_svc), ("DRV_SYS", drv_sys_name)):
            got = _diag_get(txt, key, label)
            if got and want and got != want:
                fails.append("%s 的 %s=%r，而安装器是 %r —— "
                             "排查器会查错对象，报出假结论" % (label, key, got, want))

        dd = _diag_get(txt, "DEFAULT_DIR", label)
        if dd and app_name:
            want_dd = "C:\\Program Files\\" + app_name
            if dd != want_dd:
                fails.append("%s 的 DEFAULT_DIR=%r，期望 %r（= %%ProgramFiles%%\\APP_NAME）"
                             % (label, dd, want_dd))
            else:
                notes.append("%s 的 DEFAULT_DIR 与 APP_NAME 一致" % label)

    return fails, notes


# ---------------------------------------------------------------------------
# 负对照：证明这个闸门**真的会失败**
# ---------------------------------------------------------------------------
def run_selftest():
    """给真文本注入 5 种"漂移"，逐一断言被抓到。

    ★ 铁律 108/124：一个只会 PASS 的闸门等于没有闸门。而且**必须走真判据** ——
      不能另写一份"我以为的检查逻辑"来自测，否则测的是那份副本。
      所以这里调用的是 check_all() 本体。
    """
    texts = {
        GEN: read_text(GEN_PY),
        SH: read_text(BUILD_SH),
        C: read_text(SETUP_C),
        ST: read_text(SELFTEST),
        UN: read_text(UNINSTALL),
        IN: read_text(INSTALL),
        DP: read_text(DIAG_PY),
        DB: read_text(DIAG_BAT),
    }

    # 正向对照：原样必须 0 失败（否则下面的"抓到了"毫无意义）
    base_fails, base_notes = check_all(texts, DIST_DIR, DRIVER_DIR)
    if base_fails:
        print("负对照前置失败：原始文件本来就不干净，先修好再谈负对照")
        for f in base_fails:
            print("  x %s" % f)
        return 1

    cases = []

    def mutate(key, new_text, title, expect):
        """造一个"改坏了"的文本，并**自证注入生效**。

        ★ 铁律 108：负对照的"抓到了"必须以"注入真的生效"为前提。
          第一版第 3 例的替换因为 CRLF 没匹配上、文本其实**没变**，
          于是报"没抓住"—— 差点被误读成"闸门有盲区"。
          所以每个用例都先断言 new_text != 原文本，注入失败就直接报脚本自身错误。
        """
        if new_text == texts[key]:
            print("负对照脚本自身错误：%r 的注入没生效（替换没匹配上）" % title)
            return None
        t = dict(texts)
        t[key] = new_text
        return (title, t, expect)

    # 1) 自测里引擎名多一个空格（**本次真实踩到的那个 bug**）
    cases.append(mutate(ST, texts[ST].replace('"R3 ShieldCore.exe"',
                                              '"R3 Shield Core.exe"', 1),
                        "自测引擎名漂移（多一个空格）", "DIST_FILES 不一致"))

    # 2) r3sc_setup.c 的 DRV_SYS_NAME 被写成服务名（**另一个真实 bug**）
    cases.append(mutate(C, texts[C].replace('L"r3shieldcore_kernel.sys"',
                                            'L"R3ShieldCoreKernel.sys"', 1),
                        "驱动文件名被写成服务名", "驱动文件名对不上"))

    # 3) build_installer.sh 清单少一项（三份拷贝漂移）
    #    ★ 必须写 CRLF 兼容的正则：这个文件是 CRLF，第一版用 '...txt"\n' 去 replace
    #      **一次都没匹配上** ⇒ 注入的"漂移"根本不存在 ⇒ 负对照报"没抓住"。
    #      负对照在这里反而抓住了**我自己**的错误，这正是它存在的意义。
    cases.append(mutate(SH, re.sub(r'^[ \t]*"预设说明\.txt"\r?\n', "", texts[SH],
                                   count=1, flags=re.M),
                        "build_installer.sh 清单少一项", "DIST_FILES 不一致"))

    # 4) KEY_FILES 里出现清单外的名字
    cases.append(mutate(ST, texts[ST].replace(
        '    "r3shieldcore.ini",\r\n    DRIVER_REL,',
        '    "r3shieldcore.ini",\r\n    DRIVER_REL,\r\n    "no-such-file.exe",', 1)
        if '\r\n' in texts[ST] else texts[ST].replace(
        '    "r3shieldcore.ini",\n    DRIVER_REL,',
        '    "r3shieldcore.ini",\n    DRIVER_REL,\n    "no-such-file.exe",', 1),
        "KEY_FILES 混进清单外的名字", "KEY_FILES 里有清单外的名字"))

    # 5) 清单块变成空的（空真 / 假绿）
    cases.append(mutate(SH, re.sub(r"^DIST_FILES=\(.*?^\)", "DIST_FILES=(\n)",
                                   texts[SH], count=1, flags=re.M | re.S),
                        "build_installer.sh 清单被清空", "清单块是空的"))

    # 6) 卸载脚本删的是**另一个名字**的服务（装一个名、卸另一个名 ⇒ 永远删不掉）
    cases.append(mutate(UN, texts[UN].replace('sc.exe" delete "R3ShieldCoreGuard"',
                                              'sc.exe" delete "R3ShieldCoreGuardX"', 1),
                        "卸载脚本的服务名漂了", "开机启动服务名不一致"))

    # 7) 服务 exe 的名字和 payload 清单对不上（安装时会静默跳过 = 假成功）
    cases.append(mutate(C, texts[C].replace('SVC_EXE_NAME       L"r3shieldcore_svc.exe"',
                                            'SVC_EXE_NAME       L"r3shieldcore_svcX.exe"', 1),
                        "服务 exe 名不在 payload 清单里", "不在** payload 清单里"))

    # 8) 排查工具把引擎名漂成"多一个空格"（**本次真实踩到的那个 bug**）
    #    ★ 这正是 tools/diag_autostart.py 曾经的样子：它报出"安装目录里缺主程序"
    #      这条假 FAIL，把排查方向引到"是不是被杀软删了主程序"上。
    cases.append(mutate(DP, texts[DP].replace('ENGINE_EXE = "R3 ShieldCore.exe"',
                                              'ENGINE_EXE = "R3 Shield Core.exe"', 1),
                        "排查工具引擎名漂移（多一个空格）",
                        "排查器会去找一个**不存在的文件**"))

    # 9) 排查工具的默认安装目录和 APP_NAME 对不上
    #    ★ 这条和 8 是同一次事故的另一半：DEFAULT_DIR 也漂成了 "R3 Shield Core"。
    cases.append(mutate(DB, texts[DB].replace(
        r'set "DEFAULT_DIR=C:\Program Files\R3 ShieldCore"',
        r'set "DEFAULT_DIR=C:\Program Files\R3 Shield Core"', 1),
        "排查工具默认安装目录漂移", "DEFAULT_DIR="))

    if any(c is None for c in cases):
        return 1

    print("=" * 64)
    print(" 闸门负对照（--selftest）")
    print("=" * 64)
    print("  正向对照：原始文件 -> 0 失败（%d 条说明）" % len(base_notes))

    bad = 0
    for title, t, expect in cases:
        fails, _ = check_all(t, DIST_DIR, DRIVER_DIR)
        hit = [f for f in fails if expect in f]
        # ★ 断言在**字段**上（具体那条消息），不是"有任意一条失败"
        if hit:
            print("  [OK]   %s  -> 被抓住：%s" % (title, hit[0][:64]))
        else:
            bad += 1
            print("  [FAIL] %s  -> 没抓住（期望含 %r，实得 %r）"
                  % (title, expect, fails))

    print("-" * 64)
    if bad:
        print(" 负对照失败 %d/%d —— 闸门有盲区" % (bad, len(cases)))
        return 1
    print(" 负对照全部通过：%d/%d 种漂移都被抓住" % (len(cases), len(cases)))
    return 0


def main():
    if "--selftest" in sys.argv:
        return run_selftest()

    quiet = "--quiet" in sys.argv

    for p in (GEN_PY, BUILD_SH, SETUP_C, SELFTEST, UNINSTALL, INSTALL,
              DIAG_PY, DIAG_BAT):
        if not os.path.isfile(p):
            print("x 缺少文件：%s" % p)
            return 1

    texts = {
        GEN: read_text(GEN_PY),
        SH: read_text(BUILD_SH),
        C: read_text(SETUP_C),
        ST: read_text(SELFTEST),
        UN: read_text(UNINSTALL),
        IN: read_text(INSTALL),
        DP: read_text(DIAG_PY),
        DB: read_text(DIAG_BAT),
    }
    fails, notes = check_all(texts, DIST_DIR, DRIVER_DIR)

    if fails:
        print("=" * 64)
        print(" payload 清单一致性：FAIL（%d 项）" % len(fails))
        print("=" * 64)
        for f in fails:
            print("  x %s" % f)
        return 1

    if not quiet:
        print("=" * 64)
        print(" payload 清单一致性：PASS")
        print("=" * 64)
        for n in notes:
            print("  - %s" % n)
    else:
        print("payload 清单一致性：PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())

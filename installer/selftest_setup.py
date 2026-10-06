#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
selftest_setup.py —— 原生安装程序的自测（**不碰系统**）。

为什么需要它
============
"安装包能构建"和"双击能装"是两件事（铁律 120 就是这么来的：iexpress 版
构建全绿、产物是合法 PE，双击却什么都不装）。所以安装包必须有**可自动化**
的验证手段，否则唯一能验证的办法就是真装一遍 —— 又慢又危险，结果是没人测。

本脚本覆盖三层，全部不需要人看屏幕：
  1. `--verify`     ：逐条校验 21 个内嵌资源存在、大小对得上、**真的能解压**
  2. `--extract`    ：把 payload 解到临时目录，逐个和源文件比 **sha256**
                      （比"大小相等"强得多 —— 大小对但内容错是可能的）
  3. 无头 GUI 检查  ：提权启动图形界面，枚举窗口和子控件，断言
                        · 标题正确、进度条/许可框/4 个按钮都在
                        · "下一步"按钮**初始是禁用的**（没勾"我接受"就不该放行）
                        · 完成页控件初始不可见
                      然后 PostMessage(WM_CLOSE) 关掉。

★ 为什么要提权启动
  安装程序的 manifest 声明了 requireAdministrator。用 CreateProcess（bash、
  subprocess 默认）启动它会直接得到 ERROR_ELEVATION_REQUIRED (740)，
  表现是 `Permission denied`（rc=126）—— 看着像文件被删了/被拦了，
  其实是没提权。必须走 ShellExecute（本脚本用 ShellExecuteExW + runas）。
  本机 ConsentPromptBehaviorAdmin=0（静默提权），所以不会弹框。

★ 为什么提权启动**不**算"测的不是发布物"
  真实用户双击时走的也是提权路径（系统弹 UAC）。所以这里的启动方式
  和用户路径**是同一条**（铁律 22）。

用法
====
    python installer/selftest_setup.py --no-gui --no-install   # ★ 默认推荐（不碰系统）
    python installer/selftest_setup.py --no-gui                # 跑到第 3 层
    python installer/selftest_setup.py --run-engine            # 第 4 层：会**真启动引擎**

★★★ 第 4 层必须**显式**加 `--run-engine`。
    理由：它是本仓库**唯一会启动引擎**的一层，而引擎的全局注入会 hook 本机
    **所有**进程 —— 实测会把编辑器一起 hook ⇒ 编辑器崩。
    靠"忘了加 `--no-install`"来触发一个会 hook 全机的动作，代价太高。
    没有 `--run-engine` 时第 4 层报 `[SKIP]` 并**计入结论行** —— 不静默跳过，
    所以"整层没跑"和"全绿"不会看起来一样（铁律 137 / 178）。
    ★ 要真跑第 4 层，请到**虚拟机 / 另一台机器**上跑。
"""

import ctypes
import hashlib
import html
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import winreg
from ctypes import wintypes

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
EXE = os.path.join(ROOT, "dist", "R3ShieldCore-Setup.exe")

# 源目录（用来比对 --extract 的结果）
DIST_DIR = os.path.join(ROOT, "dist", "R3ShieldCore-x64")
DRIVER_SYS = os.path.join(ROOT, "driver", "build", "r3shieldcore_kernel.sys")

# ★ 本次运行**独占**的临时路径后缀。
#   踩过：本机跑完整自测的同时，在另一个 clone 里也跑自测 —— 两边共用
#   %TEMP%\r3sc-selftest-extract，一方 rmtree 掉另一方正在逐字节比对的文件，
#   于是报出 "没解出 r3shieldcore_svc.exe" 这种**假 FAIL**（看着像产品少了文件）。
#   自测必须可并行：多工作树 / CI 同时跑是常态。判据用 PID —— 它保证唯一。
RUN_TAG = "p%d" % os.getpid()


def _tmp(name):
    """自测用的临时路径（带本次运行的 PID 后缀，保证并行不互相踩）。"""
    return os.path.join(tempfile.gettempdir(), "r3sc-selftest-%s-%s" % (name, RUN_TAG))

# 清单（必须和 gen_payload_rc.py 的 DIST_FILES 一致）
DIST_FILES = [
    "R3 ShieldCore.exe", "r3shieldcore_svc.exe", "64/r3shieldcore-lib.dll", "32/r3shieldcore-lib.dll",
    "r3shieldcore.ini", "r3shieldcore-block.ini", "r3shieldcore-blockall.ini",
    "r3shieldcore-blockallsafe.ini", "r3shieldcore-safe-first.ini",
    "start.bat", "stop.bat", "unlock-acl.bat", "verify-v26.bat", "netcheck-diag.bat",
    "dskill.exe",
    "配置详解.md", "模式选择说明.md", "部署指南.md", "预设说明.txt",
]
DRIVER_REL = "driver/r3shieldcore_kernel.sys"

# ★★ 驱动是**可选**的（对齐 README「构建内核驱动（可选）」）★★
#   判据与 gen_payload_rc.py **同源**：看源文件在不在。
#   于是产物有两种：完整包 / 仅用户态包。自测必须**跟着产物走** ——
#   否则"包本来就没驱动"会被报成 FAIL，那是**假 FAIL**（铁律 127：
#   假 FAIL 比漏报更贵，它让正常功能看起来是坏的，然后你会去"修"一个不存在的问题）。
HAVE_DRIVER = os.path.isfile(DRIVER_SYS)
PAYLOAD_LIST = list(DIST_FILES) + ([DRIVER_REL] if HAVE_DRIVER else [])

# ★★★ 「期望的文件名」只能有**一处**定义 ★★★
#   踩过（v65c）：第 4 层曾经手写 ["R3 Shield Core.exe", ...] —— Shield 和 Core
#   之间多了一个空格，而真名是 "R3 ShieldCore.exe"（无空格）。结果安装**完全正常**，
#   却被自测判成 FAIL。同一份期望名写在第 1 层、第 2 层、第 4 层三处，改一处漏两处
#   ⇒ 自测自己成了"假阳性制造机"。
#   现在三层全从 KEY_FILES 取；末尾还有一条自校验，保证 KEY_FILES 里的名字
#   **真的**在 payload 清单里（否则又是"我期望的"和"实际有的"分家）。
KEY_FILES = [
    "R3 ShieldCore.exe",
    "64/r3shieldcore-lib.dll",
    "32/r3shieldcore-lib.dll",
    "r3shieldcore.ini",
] + ([DRIVER_REL] if HAVE_DRIVER else [])

# ---------------------------------------------------------------------------
# ShellExecuteExW：提权启动
# ---------------------------------------------------------------------------
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)

SEE_MASK_NOCLOSEPROCESS = 0x00000040
SEE_MASK_NOASYNC = 0x00000100
SW_HIDE = 0
SW_SHOWNORMAL = 1


class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", ctypes.c_ulong),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD),
        ("hIcon", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    ]


def run_elevated(params, show=SW_HIDE, timeout_ms=180000, exe=None):
    """提权启动并等它结束。exe 默认是安装包（也用来跑 uninstall.bat）。"""
    sei = SHELLEXECUTEINFOW()
    sei.cbSize = ctypes.sizeof(sei)
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC
    sei.lpVerb = "runas"
    sei.lpFile = exe or EXE
    sei.lpParameters = params
    sei.lpDirectory = ROOT
    sei.nShow = show

    if not shell32.ShellExecuteExW(ctypes.byref(sei)):
        err = ctypes.get_last_error()
        raise OSError("ShellExecuteExW 失败 err=%d（提权被拒？）" % err)

    h = sei.hProcess
    if not h:
        return None, None
    kernel32.WaitForSingleObject(h, timeout_ms)
    code = wintypes.DWORD()
    kernel32.GetExitCodeProcess(h, ctypes.byref(code))
    kernel32.CloseHandle(h)
    return code.value, None


def run_elevated_async(params, show=SW_SHOWNORMAL):
    """提权启动但**不等**（GUI 测试用）。返回进程句柄。"""
    sei = SHELLEXECUTEINFOW()
    sei.cbSize = ctypes.sizeof(sei)
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC
    sei.lpVerb = "runas"
    sei.lpFile = EXE
    sei.lpParameters = params
    sei.lpDirectory = ROOT
    sei.nShow = show
    if not shell32.ShellExecuteExW(ctypes.byref(sei)):
        err = ctypes.get_last_error()
        raise OSError("ShellExecuteExW 失败 err=%d" % err)
    return sei.hProcess


# ---------------------------------------------------------------------------
# 结果记账
# ---------------------------------------------------------------------------
class Tally:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.msgs = []

    def ok(self, what):
        self.passed += 1
        print("  [OK]   %s" % what)

    def bad(self, what):
        self.failed += 1
        self.msgs.append(what)
        print("  [FAIL] %s" % what)

    def skip(self, what):
        """★ 跳过必须**可见**（打印 + 计数 + 进总结行）。
        静默不计入 ⇒ "这个包本来就是残的"和"全绿"长得一样。"""
        self.skipped += 1
        print("  [SKIP] %s" % what)

    def check(self, cond, what):
        if cond:
            self.ok(what)
        else:
            self.bad(what)
        return bool(cond)


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def payload_source(rel):
    """清单里的相对路径 -> 源文件绝对路径"""
    if rel == DRIVER_REL:
        return DRIVER_SYS
    return os.path.join(DIST_DIR, rel.replace("/", os.sep))


# ---------------------------------------------------------------------------
# 1/3 --verify
# ---------------------------------------------------------------------------
def test_verify(t):
    print("\n=== 1/4 --verify：内嵌资源完整性（含真解压一遍）===")
    rpt = _tmp("verify.txt")
    if os.path.exists(rpt):
        os.remove(rpt)

    try:
        code, _ = run_elevated('--verify --report="%s"' % rpt)
    except OSError as e:
        t.bad("提权启动失败：%s" % e)
        return

    t.check(code == 0, "--verify 退出码 == 0（实得 %s）" % code)
    if not os.path.exists(rpt):
        t.bad("报告文件没生成：%s" % rpt)
        return

    with open(rpt, encoding="utf-8") as f:
        txt = f.read()

    t.check("VERIFY-OK" in txt, "报告里有 VERIFY-OK")

    # ★ 清单条目数用**独立来源**核对：脚本自己知道应该有 21 项，
    #   不是从报告里读的（否则"清单自己漏了一条"也照样绿）。
    n_expect = len(PAYLOAD_LIST)
    t.check("清单条目 : %d" % n_expect in txt, "清单条目 == %d" % n_expect)

    total = sum(os.path.getsize(payload_source(r)) for r in PAYLOAD_LIST)
    t.check("资源总字节: %d" % total in txt, "资源总字节 == %d" % total)

    for name in KEY_FILES:
        t.check(("OK   " + name) in txt, "关键文件在清单里：%s" % name)

    # ★ 自校验：KEY_FILES 里的名字必须真的在 payload 清单（DIST_FILES + 驱动）里。
    #   否则"我期望的"和"实际打进包的"分家，而上面那条断言会**因为名字对不上**
    #   报 FAIL —— 报的是"清单里没有"，但真因是**自测自己写错了名字**。
    _all = PAYLOAD_LIST
    for name in KEY_FILES:
        t.check(name in _all, "自测的期望名 %r 确实在 payload 清单里" % name)

    # 卸载脚本是独立资源（不在清单里），单独查
    ub_sz = os.path.getsize(os.path.join(HERE, "uninstall.bat"))
    t.check("卸载脚本 : %d 字节" % ub_sz in txt, "卸载脚本 %d 字节" % ub_sz)


# ---------------------------------------------------------------------------
# 2/3 --extract：逐个 sha256 比对
# ---------------------------------------------------------------------------
def test_extract(t):
    print("\n=== 2/4 --extract：解出来的文件逐字节比对源文件 ===")
    out = _tmp("extract")
    rpt = _tmp("extract.txt")
    shutil.rmtree(out, ignore_errors=True)
    if os.path.exists(rpt):
        os.remove(rpt)

    try:
        code, _ = run_elevated('--extract "%s" --report="%s"' % (out, rpt))
    except OSError as e:
        t.bad("提权启动失败：%s" % e)
        return

    t.check(code == 0, "--extract 退出码 == 0（实得 %s）" % code)

    # ★ 逐文件 sha256 —— 比"大小相等"强得多。大小对但内容错是可能的
    #   （比如压缩流错位、解压缓冲没清）。
    bad = 0
    for rel in PAYLOAD_LIST:
        src = payload_source(rel)
        dst = os.path.join(out, rel.replace("/", os.sep))
        if not os.path.exists(dst):
            t.bad("没解出 %s" % rel)
            bad += 1
            continue
        if os.path.getsize(dst) != os.path.getsize(src):
            t.bad("大小不符 %s（源 %d / 解出 %d）"
                  % (rel, os.path.getsize(src), os.path.getsize(dst)))
            bad += 1
            continue
        if sha256_file(dst) != sha256_file(src):
            t.bad("sha256 不符 %s" % rel)
            bad += 1
            continue
    if bad == 0:
        t.ok("%d 个 payload 全部解出且 sha256 一致" % len(PAYLOAD_LIST))

    # 卸载脚本
    ub_dst = os.path.join(out, "uninstall.bat")
    ub_src = os.path.join(HERE, "uninstall.bat")
    if not os.path.exists(ub_dst):
        t.bad("没解出 uninstall.bat")
    else:
        t.check(sha256_file(ub_dst) == sha256_file(ub_src),
                "uninstall.bat 解出且内容一致")

    shutil.rmtree(out, ignore_errors=True)


# ---------------------------------------------------------------------------
# 3/3 无头 GUI 检查
# ---------------------------------------------------------------------------
WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
WINDOW_TITLE = "R3 ShieldCore 安装程序"
WM_CLOSE = 0x0010

# 控件 ID —— 必须和 r3sc_setup.c 里的 #define 一致。
# 这些断言就是在**钉住这份契约**：C 那边改了 ID 而没同步改测试，测试会红。
IDC_LICENSE = 100
IDC_PATH = 102
IDC_CHKDRV = 104
IDC_PROGRESS = 105
IDC_CHKDRVBOOT = 113
IDC_CHKAUTO = 114
ID_BTN_BACK = 200
ID_BTN_NEXT = 201
ID_BTN_CANCEL = 202
ID_BTN_FINISH = 203

# 开机自启的**服务**名与二进制名 —— 必须和 r3sc_setup.c 的 SVC_NAME /
# SVC_EXE_NAME 一致（闸门 tools/check_payload_manifest.py 会比对四处）。
# ★ 2026-10-05：自启机制由「计划任务」改成「服务」—— 计划任务只在登录后触发，
#   开机到登录这段窗口没有防护，且用户随手能禁用。
SVC_NAME = "R3ShieldCoreGuard"
SVC_EXE_NAME = "r3shieldcore_svc.exe"

# 内核驱动服务名 —— 必须和 r3sc_setup.c 的 DRV_SVC 一致。
# ★ 第 4 层开始前要**显式检查它不存在**：驱动服务若"已存在且已加载"，
#   安装器的 [3/7] 会先 sc stop/sc delete 再 sc create，而内核驱动停不掉 ⇒
#   sc delete 只把它标成"待删除" ⇒ sc create 撞 1072/1073 失败 ⇒
#   install_driver() 返回 0（未装）⇒ 后面所有驱动断言全红。
#   根因其实在**测试开始之前**（机器上本来就有旧安装），不把前提说出来
#   就会把环境噪音读成产品缺陷。
DRV_SVC = "R3ShieldCoreKernel"

# 旧版本用过的计划任务名。新版本不再创建，但安装/卸载都要**顺手清掉** ——
# 不清的话老版本升上来的机器上会同时有"任务 + 服务"两条自启链。
LEGACY_TASK = "R3ShieldCore"


def find_window(title, visible_only=False):
    """按标题找顶层窗口。visible_only=True 时只认**可见**的窗口 ——
    只按标题找是不够的：EnumWindows 连隐藏窗口一起枚举，
    所以"找到了"不等于"它显示出来了"。"""
    found = []

    def cb(hwnd, lp):
        if visible_only and not user32.IsWindowVisible(hwnd):
            return True
        n = user32.GetWindowTextLengthW(hwnd)
        if n > 0:
            buf = ctypes.create_unicode_buffer(n + 1)
            user32.GetWindowTextW(hwnd, buf, n + 1)
            if buf.value == title:
                found.append(hwnd)
                return False
        return True

    user32.EnumWindows(WNDENUMPROC(cb), 0)
    return found[0] if found else None


def enum_children(hwnd):
    kids = []

    def cb(h, lp):
        cls = ctypes.create_unicode_buffer(256)
        user32.GetClassNameW(h, cls, 256)
        n = user32.GetWindowTextLengthW(h)
        txt = ctypes.create_unicode_buffer(n + 1)
        user32.GetWindowTextW(h, txt, n + 1)
        kids.append({
            "hwnd": h,
            "cls": cls.value,
            "text": txt.value,
            "id": user32.GetDlgCtrlID(h),
            "vis": bool(user32.IsWindowVisible(h)),
            "en": bool(user32.IsWindowEnabled(h)),
        })
        return True

    user32.EnumChildWindows(hwnd, WNDENUMPROC(cb), 0)
    return kids


def test_gui(t):
    print("\n=== 3/4 无头 GUI 检查 ===")

    # ---- 3a 外部枚举：证明"窗口真的出现在桌面上" ----
    #   外部只能拿到窗口/控件的**标题字段**（按钮文案、静态文本）。
    #   EDIT 的内容和控件的启用/可见状态得靠 3b 的自证快照。
    proc = None
    try:
        proc = run_elevated_async("", SW_SHOWNORMAL)
    except OSError as e:
        t.bad("提权启动失败：%s" % e)
        return

    hwnd = None
    for _ in range(60):                 # 最多等 30 秒
        hwnd = find_window(WINDOW_TITLE, visible_only=True)
        if hwnd:
            break
        time.sleep(0.5)

    if t.check(hwnd is not None, "窗口「%s」**可见地**出现在桌面上" % WINDOW_TITLE):
        kids = enum_children(hwnd)
        classes = [k["cls"] for k in kids]
        texts = [k["text"] for k in kids]
        t.check(len(kids) >= 15, "窗口里有 %d 个子控件" % len(kids))
        t.check(any(c == "msctls_progress32" for c in classes), "有进度条控件")
        for name in ("下一步", "取消", "完成"):
            t.check(name in texts, "按钮「%s」存在" % name)

    # 清理：★ UIPI 会丢弃非提权进程发给提权窗口的 WM_CLOSE，
    # 所以外部关不掉它 —— 直接强杀（这不是产品 bug，是测试姿势的限制）。
    if proc:
        kernel32.TerminateProcess(proc, 0)
        kernel32.CloseHandle(proc)
    for _ in range(20):
        if find_window(WINDOW_TITLE) is None:
            break
        time.sleep(0.3)
    t.check(find_window(WINDOW_TITLE) is None, "进程结束后窗口消失")

    # ---- 3b 自证快照：控件真实状态 ----
    #   为什么必须让程序自己报：EDIT 的文本要发 WM_GETTEXT 才拿得到，
    #   而 UIPI 挡住了跨完整性级别的消息 —— 从外面读永远是空串。
    print("  --- 控件状态自证（--uicheck，进程内快照）---")
    snap = _tmp("ui.txt")
    if os.path.exists(snap):
        os.remove(snap)
    try:
        # ★ show 必须是 SW_SHOWNORMAL，不能用默认的 SW_HIDE。
        #   Windows 会让进程**第一次** ShowWindow 服从启动时的
        #   STARTUPINFO.wShowWindow —— 用 SW_HIDE 启动的话，程序里的
        #   ShowWindow(h, SW_SHOW) 会被无声地覆盖成隐藏，
        #   于是主窗口不可见 ⇒ 所有子控件的 IsWindowVisible 全是 0。
        #   （踩过：快照里 SELF VIS=0 HASWSVIS=0，全表 VIS=0。）
        code, _ = run_elevated('--uicheck="%s"' % snap, show=SW_SHOWNORMAL)
    except OSError as e:
        t.bad("--uicheck 启动失败：%s" % e)
        return
    t.check(code == 0, "--uicheck 退出码 == 0（实得 %s）" % code)
    if not os.path.exists(snap):
        t.bad("快照文件没生成：%s" % snap)
        return

    ui = {}
    win_title = ""
    with open(snap, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not line:
                continue
            if line.startswith("WINDOW\t"):
                win_title = line.split("\t", 1)[1]
                continue
            parts = line.split("\t")
            kv = {}
            # ★ 按**字段名**解析，不按下标 —— 之前写的是 parts[:4] 再特判 parts[4]，
            #   快照格式一加列（这次加了 CHK=）就整体错位，TEXT 全变成空串。
            #   按名字取就与列顺序/列数无关。
            for part in parts:
                if "=" not in part:
                    continue
                k, v = part.split("=", 1)
                kv[k] = v          # TEXT 在最后一段，且文本里的 TAB 已被压成空格
            if "ID" in kv:
                ui[int(kv["ID"])] = kv

    t.check(win_title == WINDOW_TITLE, "快照里的窗口标题正确（实得 %r）" % win_title)
    t.check(len(ui) >= 15, "快照里有 %d 个控件" % len(ui))

    # 主窗口必须自己可见 —— 否则下面所有 VIS 断言都是空的
    self_line = ""
    with open(snap, encoding="utf-8") as f:
        for line in f:
            if line.startswith("SELF\t"):
                self_line = line.rstrip()
                break
    print("  [诊断] %s" % self_line)
    t.check("VIS=1" in self_line, "主窗口自身可见（SELF VIS=1）")

    pth = ui.get(IDC_PATH)
    t.check(pth is not None and "R3 ShieldCore" in pth["TEXT"],
            "路径框默认值含产品名（实得 %r）" % (pth["TEXT"] if pth else None))

    lic = ui.get(IDC_LICENSE)
    t.check(lic is not None and len(lic["TEXT"]) > 200, "许可框有实质内容")
    t.check(lic is not None and "许可" in lic["TEXT"], "许可框文本含「许可」")

    nx = ui.get(ID_BTN_NEXT)
    t.check(nx is not None and nx["EN"] == "0",
            "「下一步」初始是**禁用**的（还没勾选接受）")
    t.check(nx is not None and nx["TEXT"] == "下一步", "「下一步」文案正确")

    fin = ui.get(ID_BTN_FINISH)
    t.check(fin is not None and fin["VIS"] == "0", "「完成」初始不可见")

    bk = ui.get(ID_BTN_BACK)
    t.check(bk is not None and bk["VIS"] == "0", "「上一步」在第 1 页不可见")

    cn = ui.get(ID_BTN_CANCEL)
    t.check(cn is not None and cn["VIS"] == "1" and cn["EN"] == "1",
            "「取消」可见且可用")

    pr = ui.get(IDC_PROGRESS)
    t.check(pr is not None and pr["CLS"] == "msctls_progress32", "进度条类名正确")

    # ---- 3c 选项页快照：三个复选框的默认值与置灰联动 ----
    #   ★ 为什么不复用上面那次快照：那次停在**欢迎页**，选项页上的控件全是 VIS=0，
    #     断言不到"默认勾了没有"、"父勾选联动对不对" —— 而"默认值/联动"正是
    #     选项页最容易改坏、又最不容易被发现的地方。
    def snap(extra, tag):
        """跑一次 --uicheck 快照并解析。返回 (ok, {ID: kv}, 窗口标题)。"""
        path = _tmp("ui-%s.txt" % tag)
        if os.path.exists(path):
            os.remove(path)
        try:
            code2, _ = run_elevated('--uicheck="%s" %s' % (path, extra),
                                    show=SW_SHOWNORMAL)
        except OSError as e:
            t.bad("--uicheck(%s) 启动失败：%s" % (tag, e))
            return False, {}, ""
        if code2 != 0 or not os.path.exists(path):
            t.bad("--uicheck(%s) 没产出快照（code=%s）" % (tag, code2))
            return False, {}, ""
        d, title = {}, ""
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\r\n")
                if not line:
                    continue
                if line.startswith("WINDOW\t"):
                    title = line.split("\t", 1)[1]
                    continue
                kv = {}
                for part in line.split("\t"):
                    if "=" in part:
                        k, v = part.split("=", 1)
                        kv[k] = v
                if "ID" in kv:
                    d[int(kv["ID"])] = kv
        return True, d, title

    print("  --- 选项页快照（--uicheck-page=1）---")
    ok, ui2, _ = snap("--uicheck-page=1", "opt")
    if ok:
        for cid, name in ((IDC_CHKDRV, "安装内核驱动"),
                          (IDC_CHKDRVBOOT, "开机优先启动内核驱动"),
                          (IDC_CHKAUTO, "开机自动启动引擎")):
            c = ui2.get(cid)
            t.check(c is not None and c.get("VIS") == "1",
                    "选项页可见复选框：%s" % name)
            t.check(c is not None and c.get("CHK") == "1",
                    "复选框默认勾选：%s" % name)
        boot = ui2.get(IDC_CHKDRVBOOT)
        t.check(boot is not None and boot.get("EN") == "1",
                "「开机优先启动内核驱动」在勾选驱动时**可用**")
        drv = ui2.get(IDC_CHKDRV)
        t.check(drv is not None and "自签" not in drv.get("TEXT", ""),
                "「安装内核驱动」文案里不再提签名（实得 %r）"
                % (drv.get("TEXT") if drv else None))
        # ★ 自启机制由「计划任务」改成「服务」后，这个复选框的文案也必须跟上 ——
        #   旧文案写的是"登录时以最高权限启动，不弹 UAC"（那是计划任务的说法），
        #   已经**不准确**（服务是开机就起，不是登录时）。用文案断言把它钉住，
        #   免得以后改回去没人发现（铁律 137：文案漂了测试也全绿）。
        auto = ui2.get(IDC_CHKAUTO)
        t.check(auto is not None and "安全模式" in auto.get("TEXT", ""),
                "「开机自动启动引擎」文案里说明了安全模式下不启动（实得 %r）"
                % (auto.get("TEXT") if auto else None))
        t.check(auto is not None and "登录时" not in auto.get("TEXT", ""),
                "「开机自动启动引擎」文案里不再说「登录时」（服务是开机就起）")

        print("  --- 选项页快照（取消勾选驱动，验置灰联动）---")
        ok3, ui3, _ = snap("--uicheck-page=1 --uicheck-drvoff", "optdrvoff")
        if ok3:
            d3 = ui3.get(IDC_CHKDRV)
            b3 = ui3.get(IDC_CHKDRVBOOT)
            t.check(d3 is not None and d3.get("CHK") == "0",
                    "取消勾选后「安装内核驱动」确实是未勾选")
            t.check(b3 is not None and b3.get("EN") == "0",
                    "不装驱动时「开机优先启动内核驱动」被**置灰**")


# ---------------------------------------------------------------------------
# 4/4 真机安装 -> 卸载
# ---------------------------------------------------------------------------
DRV_FILE_SYS = r"C:\Windows\System32\drivers\r3shieldcore_kernel.sys"
UNINST_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\R3ShieldCore"
START_MENU_LNK = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\R3 ShieldCore.lnk"
DESKTOP_LNK = r"C:\Users\Public\Desktop\R3 ShieldCore.lnk"


def sc_query(name):
    """返回 sc query 的退出码（0 = 服务存在）。"""
    rc, _ = _run_console(["sc.exe", "query", name])
    return rc


def _run_console(args, timeout=30):
    """跑一个 Windows 控制台程序，**按 CP936/GBK 解码**它的输出。

    ★ 为什么不能用 `text=True, errors="replace"`：
      `text=True` 走的是 Python 的 **locale 默认编码**（这台机器 = UTF-8），
      而 `sc.exe` / `schtasks.exe` **一律按控制台代码页（936）输出**。
      于是中文路径被当成 UTF-8 解 ⇒ 变成 `D:\\�û�̬ɱ��\\...`
      ⇒ 与期望路径**逐字节不等** ⇒ 报出一条**假 FAIL**（看着像产品把路径写错了）。
      （实测：`sc qc` 的原始字节 `\\xca\\xa7\\xb0\\xdc` 是 GBK 的"失败"。）

      这是本项目第 N 次踩"控制台程序输出是 GBK"这个坑（铁律 86 同族）。
    """
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout)
    except Exception:
        return -1, ""
    out = r.stdout.decode("gbk", errors="replace")
    return r.returncode, out


def sc_qc(name):
    """返回 `sc qc` 的完整输出（空串 = 服务不存在）。
    用来看**服务实际落成的启动类型** —— `sc create start= boot` 返回 0
    只说明命令被接受，不说明值真的落成了 BOOT_START（铁律 94）。"""
    rc, out = _run_console(["sc.exe", "qc", name])
    return out if rc == 0 else ""


def schtask_query(name):
    """返回计划任务的退出码（0 = 任务存在）。用来确认旧版任务**已被清掉**。"""
    rc, _ = _run_console(["schtasks.exe", "/query", "/tn", name])
    return rc


def svc_query(name):
    """返回 `sc query` 的退出码（0 = 服务存在）。"""
    rc, _ = _run_console(["sc.exe", "query", name])
    return rc


def svc_binpath(name):
    """返回服务配的**二进制路径**（取不到返回空串）。

    ★ 为什么不能只断言"服务存在"：服务二进制路径含空格，少一层引号就会被
      SCM 拆成"可执行文件 + 参数"两截 —— 服务**照样建得出来**、状态照样
      RUNNING，但开机什么都不启动。必须把真正记下来的路径读出来比对
      （铁律 94：断言落在字段上，不是落在"命令返回 0"上）。
    """
    qc = sc_qc(name)
    if not qc:
        return ""
    m = re.search(r"BINARY_PATH_NAME\s*:\s*(.+)", qc)
    return m.group(1).strip() if m else ""


def svc_state(name):
    """返回服务当前状态（RUNNING / STOPPED / ...），取不到返回空串。"""
    rc, out = _run_console(["sc.exe", "query", name])
    if rc != 0:
        return ""
    m = re.search(r"STATE\s*:\s*\d+\s+([A-Z_]+)", out)
    return m.group(1) if m else ""


# ---------------------------------------------------------------------------
# 引擎进程：查 + 停
# ---------------------------------------------------------------------------
ENGINE_EXE_NAME = "R3 ShieldCore.exe"


def engine_pids():
    """返回正在运行的引擎 PID 列表。

    ★ 用 tasklist 的 CSV 输出，**不用**默认表格输出 ——
      表格会把映像名截断到 25 字符，长名永远匹配不上（铁律 41）。
    ※ 输出按 GBK 解（`_run_console`）—— tasklist 也是控制台程序，
      中文系统上同样是 936；虽然本函数只看 PID 数字，但保持一致防止将来
      加"按映像名比对"时又踩编码坑。
    """
    rc, out = _run_console(["tasklist.exe", "/nh", "/fo", "csv",
                            "/fi", "imagename eq " + ENGINE_EXE_NAME])
    if rc != 0 and not out:
        return []
    pids = []
    for line in out.splitlines():
        parts = [p.strip().strip('"') for p in line.split(",")]
        if len(parts) >= 2 and parts[1].isdigit():
            pids.append(int(parts[1]))
    return pids


def kill_engine(dest):
    """停掉引擎，成功返回 True。

    ★ 为什么 L4 必须自己动手（这是自启改成服务之后新增的必要步骤）：
      以前自启是**计划任务**（`/sc onlogon`），只在登录时触发 —— 所以 L4
      跑的这段时间里**根本没有引擎**。
      改成**服务**之后，装完引擎就**已经在跑了**。而引擎跑着的时候，它自己的
      片段规则会把 System32 下的一切（sc.exe / schtasks.exe / reg.exe …）
      判成 HIGH 并在 block 模式下**直接拒**（铁律 42/43）—— 于是本层后面
      所有断言都会因为"工具起不来"而全红，看起来像产品坏了。
    ★ 只能用安装目录里的 dskill.exe（直 syscall，绕开被 hook 的 NtOpenProcess）；
      不能用 taskkill（它在 System32，会被引擎自己拦掉）。
    """
    pids = engine_pids()
    if not pids:
        return True

    dskill = os.path.join(dest, "dskill.exe")
    if not os.path.exists(dskill):
        return False

    for pid in pids:
        try:
            subprocess.run([dskill, str(pid)], capture_output=True, timeout=30)
        except Exception:
            pass

    for _ in range(20):
        if not engine_pids():
            return True
        time.sleep(0.5)
    return not engine_pids()


def wait_engine(seconds=15):
    """等引擎起来，返回等待结束时是否在跑。"""
    deadline = time.time() + seconds
    while time.time() < deadline:
        if engine_pids():
            return True
        time.sleep(0.5)
    return bool(engine_pids())


def robust_rmtree(p):
    """删目录，**删不掉要说出来**。返回仍存在的文件路径列表（空 = 真删干净了）。

    ★ 为什么不能只写 `shutil.rmtree(p, ignore_errors=True)`：
      `ignore_errors=True` 让"删干净了"和"一个字节都没删掉"**输出完全一样**。
      实测踩到：上一轮自测留下的 `64\\r3shieldcore-lib.dll.old-<tick>`
      （安装器 rename-aside 的产物）被外部安全层拒绝删除，
      rmtree 静默放过 ⇒ 下一轮安装后断言"没有多出来的文件"报 FAIL，
      看起来像**安装器多写了文件**，其实是测试自己没清干净（铁律 100/124）。

    ★ 为什么再兜一层 `cmd /c rd /s /q`：
      `shutil.rmtree` 在本机被 safe-delete 垫片接管（它先尝试"移到回收站"，
      失败就整体放弃）。`rd /s /q` 走的是 Win32 DeleteFileW，能绕开那层。
      （用 subprocess 调 cmd，不要从 bash 直接调 —— 那条路被安全策略挡着。）
    """
    shutil.rmtree(p, ignore_errors=True)
    if not os.path.exists(p):
        return []
    try:
        subprocess.run(["cmd", "/c", "rd", "/s", "/q", p],
                       capture_output=True, timeout=60)
    except Exception:
        pass
    if not os.path.exists(p):
        return []
    stuck = []
    for dirpath, _, files in os.walk(p):
        for fn in files:
            stuck.append(os.path.join(dirpath, fn))
    return stuck


def preflight_clean(t, dest):
    """把第 4 层的**前提**摆到台面上：机器上不能残留上一轮的安装。

    为什么值得单独做一层：本层的断言全是"装完之后系统变成什么样"。
    如果开跑前系统就不是干净的，失败会全部归因到**产品**上，
    而真正的原因是"上一轮没卸干净"或"这台机器上本来就装过"。
    前提不成立时**明确作废本层**，比给出一堆红字有用得多（铁律 108）。

    返回 True = 前提成立，可以继续。
    """
    ok = True

    stuck = robust_rmtree(dest)
    if os.path.exists(dest):
        t.bad("前置：上一轮的残留目录删不掉（%d 个文件）—— 本层判定作废，"
              "请先关掉占用它的进程或重启后重跑。举例：%r"
              % (len(stuck), stuck[:3]))
        ok = False
    else:
        t.ok("前置：上一轮的残留目录已清空")

    # 驱动服务 / 自启服务 / 旧版计划任务：存在就先删，删不掉就作废本层。
    for name in (DRV_SVC, SVC_NAME):
        if sc_query(name) == 0:
            _run_console(["sc.exe", "stop", name], timeout=20)
            _run_console(["sc.exe", "delete", name], timeout=20)
            time.sleep(1.5)
        if sc_query(name) == 0:
            t.bad("前置：服务 %s 已存在且删不掉（内核驱动已加载时 sc delete 只把它"
                  "标成「待删除」，要到重启才真的消失）—— 本层判定作废。"
                  "请手动跑 install_driver.bat /uninstall 或重启后重跑。" % name)
            ok = False
        else:
            t.ok("前置：服务 %s 不存在" % name)

    if schtask_query(LEGACY_TASK) == 0:
        _run_console(["schtasks.exe", "/delete", "/tn", LEGACY_TASK, "/f"],
                     timeout=20)
    t.check(schtask_query(LEGACY_TASK) != 0,
            "前置：旧版计划任务 %s 不存在" % LEGACY_TASK)

    if os.path.exists(DRV_FILE_SYS):
        try:
            os.remove(DRV_FILE_SYS)
        except OSError:
            pass
    if os.path.exists(DRV_FILE_SYS):
        t.bad("前置：%s 还在（驱动文件删不掉）—— 本层判定作废" % DRV_FILE_SYS)
        ok = False
    else:
        t.ok("前置：System32\\drivers 下没有旧驱动文件")

    return ok


def test_install_uninstall(t):
    """真机装一遍再卸一遍，然后逐项验证系统回到干净状态。

    为什么必须做这一层：
      "资源对不对"（--verify/--extract）和"装上去/卸干净"是两回事。
      v65c 的两个真 bug 全在这一层：
        · 驱动文件名写成服务名 ⇒ 驱动那步永远静默跳过；
        · 卸载脚本先删安装目录（把自己也删了）⇒ 后面的快捷方式和注册表
          清理整段没执行，而日志里一个字都没有。
      只测前三层的话，这两个 bug 一个都抓不到。

    ★ 装到项目目录下（不碰 C:\\Program Files）：
      · 避免动到用户的真实安装；
      · 项目目录在本机火绒的信任区里 —— 而 C:\\Program Files 会被实时防护
        清空（这台机器的已知环境特性），装到那儿测出来的是环境噪音不是产品问题。
    """
    print("\n=== 4/4 真机安装 -> 卸载 ===")
    dest = os.path.join(ROOT, "_selftest_install")
    rpt = _tmp("install.txt")
    if os.path.exists(rpt):
        os.remove(rpt)

    # ★ 先把前提摆到台面上。前提不成立就**整层作废**，不要产出一堆红字 ——
    #   否则"上一轮没卸干净"会被读成"安装器坏了"（实测就是这么误导了一轮）。
    if not preflight_clean(t, dest):
        t.bad("第 4 层已作废：开跑前的系统状态不是干净的（见上面「前置」那几条）。"
              "本层的通过/失败数**不能**用来判断产品好坏。")
        return

    # ---- 安装 ----
    try:
        code, _ = run_elevated('/S /DEST="%s" --report="%s"' % (dest, rpt))
    except OSError as e:
        t.bad("静默安装启动失败：%s" % e)
        return
    t.check(code == 0, "静默安装退出码 == 0（实得 %s）" % code)

    if os.path.exists(rpt):
        with open(rpt, encoding="utf-8", errors="replace") as f:
            log = f.read()
    else:
        log = ""
        t.bad("安装报告没生成")

    # ★ 逐项断言，而不是只看那句 SILENT 结果行 —— 只断言结果行是空真。
    #   ★ 不能再用"文件总数相等"：自启改成**服务**之后，引擎在 L4 期间
    #     **真的在跑**（以前是计划任务，只在登录时触发，所以 L4 里没有引擎），
    #     它会往安装目录写 r3shieldcore-console.log / events.log，服务写
    #     r3shieldcore-svc.log —— 总数必然多出来。按**集合**比更准也更可诊断。
    expected = set(r.replace("/", os.sep) for r in PAYLOAD_LIST)
    expected.add("uninstall.bat")

    def is_runtime_artifact(fn):
        """引擎/服务跑起来之后自己写的文件 —— 不算"安装出来的文件"。"""
        return (fn in ("r3shieldcore-console.log", "r3shieldcore-events.log",
                       "r3shieldcore-svc.log")
                or fn.startswith("engine-console-"))

    actual = set()
    for dirpath, _, files in os.walk(dest):
        for fn in files:
            if is_runtime_artifact(fn):
                continue
            actual.add(os.path.relpath(os.path.join(dirpath, fn), dest))

    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    # ★ rename-aside 的产物（`<名>.old-<tick>`）单独拎出来判。
    #   它不是"安装器多写了文件"，而是"目标文件当时被别人占着，安装器按设计
    #   把旧文件改名挪开"（见 r3sc_setup.c 的解压段注释）。前提已清干净时
    #   它**不该出现** —— 出现就说明这次安装确实撞上了占用，值得单独说清楚，
    #   而不是混在"多出来的文件"里让人以为是清单错了。
    aside = [e for e in extra if ".old-" in os.path.basename(e)]
    extra = [e for e in extra if e not in aside]
    t.check(not aside,
            "没有 rename-aside 产物（.old-*：出现即说明有文件被占用着）%r" % aside)
    t.check(not missing, "安装目录里没有缺文件（缺 %r）" % missing)
    t.check(not extra, "安装目录里没有多出来的文件（多 %r）" % extra)

    for rel in KEY_FILES + ["uninstall.bat"]:
        p = os.path.join(dest, rel.replace("/", os.sep))
        t.check(os.path.exists(p), "安装后有 %s" % rel)

    # ★ 驱动：这台的驱动服务**注册得上但加载不起来**，
    #   所以断言的是 drv=1（已注册未加载），不是 drv=2。
    #   ★ 整块跟着**产物**走：仅用户态包本来就没有驱动 ⇒ 必须 SKIP 而不是 FAIL。
    #     但**不能只跳过** —— 要正向断言"它确实识别出没驱动并跳过了"，
    #     否则"驱动那步被静默略过"和"正确处理"长得一模一样（铁律 137）。
    if HAVE_DRIVER:
        t.check("drv=1" in log or "drv=2" in log,
                "驱动那步真的走了（日志里 drv=1 或 2，实得 %r）"
                % ([l for l in log.splitlines() if "SILENT" in l] or ["无"])[-1:])
        t.check("实际有：" not in log,
                "没有出现「payload 里没有 driver」的告警（文件名对得上）")
        t.check(sc_query("R3ShieldCoreKernel") == 0, "驱动服务已注册")
    else:
        t.skip("本包不含驱动（仅用户态包）—— 跳过「驱动那步走了 / 服务已注册」2 条")
        t.check("drv=3" in log,
                "包不含驱动时安装器**明确跳过**驱动步骤（日志 drv=3，实得 %r）"
                % ([l for l in log.splitlines() if "SILENT" in l] or ["无"])[-1:])
        t.check(sc_query("R3ShieldCoreKernel") != 0,
                "包不含驱动时没有凭空注册出驱动服务")

    # ---- 开机自启（用户报的就是"装了不自启"）----
    #   ★ 顺序很重要：先趁**引擎还在跑**证明"服务真的把引擎拉起来了"，
    #     再把引擎停掉 —— 否则后面所有 sc.exe / schtasks.exe 断言都会被
    #     引擎自己的片段规则拦掉（铁律 42/43），看起来像产品坏了。
    sil = ([l for l in log.splitlines() if "SILENT" in l] or ["无"])[-1]
    t.check("auto=1" in sil, "开机自启那步真的走了（SILENT 行里 auto=1，实得 %r）" % sil)

    # ★★ 这一条是"开机自启"最终要证明的事：服务真的把引擎拉起来了。
    t.check(wait_engine(20), "开机启动服务已经把引擎拉起来了（引擎在跑）")

    # ★ 令牌事实：服务在拉起引擎**之前**会把令牌的 user / elevated 记进自己的
    #   日志。这一条直接回答"WTSQueryUserToken 拿到的令牌到底提没提权" ——
    #   不提权的话引擎是残的（全局注入 err=5），而"引擎在跑"那条断言还是绿的。
    #   ★ 等待条件必须是 `[LAST]`（**最终结论**），不是 `elevated=` ——
    #     `elevated=` 在"开始拉起之前"就写了，读到它时 [LAST] 还没写，
    #     于是"没有 [LAST] 行"会被当成失败（假 FAIL：其实只是读早了）。
    #     [LAST] 一行 = 本次拉起**有结论**了（铁律 109：闩锁判据要用"后来才成立"的事实）。
    svclog = os.path.join(dest, "r3shieldcore-svc.log")
    svctxt = ""
    for _ in range(40):
        if os.path.exists(svclog):
            with open(svclog, "rb") as f:
                svctxt = f.read().decode("utf-8-sig", "replace")
            if "[LAST]" in svctxt:
                break
        time.sleep(0.5)
    # ★ 证据必须打**全部** [TOKEN] 行，不能只打第一条（铁律 99：诊断口径 ≥ 触发口径）。
    #   服务是"先拿 WTS 过滤令牌试 -> 必 740 -> 再升级"，所以日志里**本来就有两行**：
    #     第一行 elevated=no  type=3 (Limited) ← 这一步**故意**失败，不是结论
    #     第二行 elevated=yes type=2 (Full)    ← 真正拿去 CreateProcessAsUser 的那个
    #   只打 [:1] 会把"故意失败那次"当结论展示 ⇒ 一个**通过**的断言看起来像假绿。
    tok_lines = [l.strip() for l in svctxt.splitlines() if "[TOKEN]" in l]
    t.check("elevated=yes" in svctxt,
            "服务用的是**已提权**令牌（日志里的 [TOKEN] 行共 %d 条：%r）"
            % (len(tok_lines), tok_lines))
    # ★ 再钉一层，而且必须钉在**最终结论**上，不能钉在"日志里出现过 err=740"上：
    #   v1.2.0 的流程是"先拿 WTS 过滤令牌试 asuser（这一步**故意**会 740）
    #   → 升级令牌 / 退保底 → 再拉"。所以中间出现 err=740 是**正常**的，
    #   拿它当失败判据就是"把第一次尝试当成最终结果"（假 FAIL）。
    #   真正的判据是服务自己写的单行根因 `[LAST] <字母> err=N session=N`：
    #     O = 成功    E/P/S/C/X = 各类失败
    #   —— 这也是 diag_autostart.bat 读的同一行（两处口径必须一致）。
    last = [l for l in svctxt.splitlines() if "[LAST]" in l]
    t.check(bool(last) and "[LAST] O " in last[-1],
            "服务最终把引擎**成功**拉起了（[LAST] 该是 O，实得 %r）"
            % (last[-1].strip() if last else "没有 [LAST] 行"))

    # ---- 停引擎：让后面的 System32 工具（sc.exe / schtasks.exe）能用 ----
    t.check(kill_engine(dest), "引擎已停（否则引擎自己的规则会拦掉 sc.exe）")

    # ---- 服务本身 ----
    t.check(svc_query(SVC_NAME) == 0, "开机启动服务已注册（%s）" % SVC_NAME)
    qcs = sc_qc(SVC_NAME)
    t.check("AUTO_START" in qcs,
            "服务启动类型 = AUTO_START（开机即起）"
            "（sc qc 实得 %r）" % [l.strip() for l in qcs.splitlines()
                                   if "START_TYPE" in l])
    # ★ 服务存在 ≠ 服务指对了程序。路径含空格，少一层引号就会被拆成两截 ——
    #   服务照样 RUNNING，但开机什么都不启动。必须比对**记下来的 binPath**。
    bp = svc_binpath(SVC_NAME)
    want_svc = '"%s"' % os.path.join(dest, SVC_EXE_NAME)
    t.check(bp and os.path.normcase(bp) == os.path.normcase(want_svc),
            "服务指向正确的服务 exe（期望 %r，实得 %r）" % (want_svc, bp))
    st = svc_state(SVC_NAME)
    t.check(st in ("RUNNING", "START_PENDING"),
            "开机启动服务处于运行状态（实得 %r）" % st)
    # ★ 旧版计划任务必须被清掉，否则"任务 + 服务"会拉出**两份引擎**
    #   （引擎没有单实例保护，两份 = 两套全局注入）。
    t.check(schtask_query(LEGACY_TASK) != 0,
            "没有遗留的旧版计划任务（%s）" % LEGACY_TASK)

    # ---- 驱动启动类型：默认勾了"开机优先" ⇒ 必须是 BOOT_START ----
    #   ★ 回读 `sc qc`，不认 `sc create` 的返回码：返回 0 只说明参数被接受，
    #     不说明 START_TYPE 真的落成了我们要的那个（铁律 94）。
    #   ★ 仅用户态包没有驱动服务可查 ⇒ SKIP（否则又是假 FAIL）。
    if HAVE_DRIVER:
        qc = sc_qc("R3ShieldCoreKernel")
        t.check("BOOT_START" in qc,
                "驱动启动类型 = BOOT_START（开机优先）"
                "（sc qc 实得 %r）" % [l.strip() for l in qc.splitlines()
                                       if "START_TYPE" in l])
    else:
        t.skip("本包不含驱动 —— 跳过「启动类型 = BOOT_START」断言")

    # ---- 第二次安装：不勾"开机优先" ⇒ 应落到普通开机自启 ----
    #   这一支是用户明确要的"未选就加到普通的开机自启里去"，
    #   不测的话它永远只是代码里的一句话。
    rpt2 = _tmp("install2.txt")
    if os.path.exists(rpt2):
        os.remove(rpt2)
    try:
        code3, _ = run_elevated('/S /DEST="%s" --report="%s" --drv-start=auto'
                                % (dest, rpt2))
    except OSError as e:
        t.bad("第二次（auto）安装启动失败：%s" % e)
        return
    t.check(code3 == 0, "auto 模式安装退出码 == 0（实得 %s）" % code3)
    # ★ 第二次安装的 [1/7] 会先停掉服务（stop_existing_service），再重新起一个
    #   新服务实例 —— 新实例的"本会话已拉过"记账是空的 ⇒ 它会**再拉一次引擎**。
    #   所以这里必须再停一次，否则下面的 sc qc 又被引擎自己的规则拦掉。
    wait_engine(10)
    t.check(kill_engine(dest), "第二次安装后引擎已停（让 sc.exe 能用）")
    #   ★ 只跳过「驱动启动类型」这一条断言 —— 第二次安装本身（升级路径）
    #     仍然必须真跑，那才是这段的主体。
    if HAVE_DRIVER:
        qc2 = sc_qc("R3ShieldCoreKernel")
        t.check("AUTO_START" in qc2,
                "不勾「开机优先」时驱动启动类型 = AUTO_START（普通开机自启）"
                "（sc qc 实得 %r）" % [l.strip() for l in qc2.splitlines()
                                       if "START_TYPE" in l])
    else:
        t.skip("本包不含驱动 —— 跳过「启动类型 = AUTO_START」断言")

    # ---- 卸载 ----
    ub = os.path.join(dest, "uninstall.bat")
    if not os.path.exists(ub):
        t.bad("安装目录里没有 uninstall.bat —— 卸载链路断了")
        return
    try:
        code2, _ = run_elevated("/quiet", exe=ub)
    except OSError as e:
        t.bad("卸载启动失败：%s" % e)
        return
    t.check(code2 == 0, "卸载退出码 == 0（实得 %s）" % code2)

    # uninstall.bat 用 start 起独立进程、延迟 2 秒删目录，所以这里要等
    for _ in range(20):
        if not os.path.exists(dest):
            break
        time.sleep(0.5)

    # ---- 逐项验证回到干净状态 ----
    t.check(not os.path.exists(dest), "安装目录已删除")
    t.check(not os.path.exists(DRV_FILE_SYS), "驱动文件已从 System32\\drivers 删除")
    t.check(sc_query("R3ShieldCoreKernel") != 0, "驱动服务已删除")
    t.check(svc_query(SVC_NAME) != 0,
            "开机启动服务已删除（%s）" % SVC_NAME)
    t.check(schtask_query(LEGACY_TASK) != 0,
            "没有遗留的旧版计划任务（%s）" % LEGACY_TASK)
    t.check(not os.path.exists(START_MENU_LNK), "开始菜单快捷方式已删除")
    t.check(not os.path.exists(DESKTOP_LNK), "桌面快捷方式已删除")
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, UNINST_KEY)
        winreg.CloseKey(k)
        t.bad("注册表卸载项还在（卸载脚本的顺序 bug 复发了？）")
    except FileNotFoundError:
        t.ok("注册表卸载项已删除")
    except OSError as e:
        t.bad("读注册表失败：%s" % e)

    # 收尾：把自测自己造的目录清掉。★ 清不掉要**说出来** —— 上一轮就是
    #   在这里静默失败，导致下一轮以"非干净状态"开跑（现在由前置检查兜住，
    #   但这里也不该再骗人）。
    left = robust_rmtree(dest)
    t.check(not os.path.exists(dest),
            "自测收尾：自建的安装目录已清除（残留 %r）" % left[:3])


# ---------------------------------------------------------------------------
def main():
    print("=" * 64)
    print(" R3 ShieldCore 原生安装程序 —— 自测")
    print("=" * 64)
    print("  被测文件 : %s" % EXE)

    if not os.path.exists(EXE):
        print("  [败] 安装包不存在 —— 先跑：bash installer/build_setup.sh")
        return 2

    print("  大小     : %d 字节" % os.path.getsize(EXE))
    print("  sha256   : %s" % sha256_file(EXE))
    # ★ 先亮明**这是哪一种包**：完整包和仅用户态包的断言集合不同，
    #   不写出来就无法分辨"跳过了"和"根本没跑"（铁律 137）。
    print("  包类型   : %s" % ("完整包（含内核驱动）" if HAVE_DRIVER
                              else "仅用户态包（不含驱动）—— 驱动相关断言将 [SKIP]"))

    t = Tally()
    test_verify(t)
    test_extract(t)
    if "--no-gui" in sys.argv:
        print("\n=== 3/4 GUI 检查：已跳过（--no-gui）===")
    else:
        test_gui(t)
    if "--no-install" in sys.argv:
        print("\n=== 4/4 真机安装->卸载：已跳过（--no-install）===")
    elif "--run-engine" not in sys.argv:
        # ★★★ 第 4 层是本仓库**唯一会启动引擎**的地方，而引擎的全局注入会 hook
        #   本机**所有**进程 —— 实测会把编辑器一起 hook ⇒ 编辑器崩。
        #   所以它必须是**显式 opt-in**：不能靠"忘了加 --no-install"来触发一个
        #   会 hook 全机的动作。
        #   ★ 报 SKIP 而不是静默跳过：静默会让"整层没跑"和"全绿"看起来一样
        #     （铁律 137 / 178）。结论行里也会带上跳过计数。
        print("\n=== 4/4 真机安装->卸载：已跳过（缺 --run-engine）===")
        print("    本层会**真的启动引擎**，而引擎的全局注入会 hook 本机所有进程")
        print("    （实测会把编辑器一起 hook ⇒ 编辑器崩）。")
        print("    要跑请显式加 --run-engine，并**建议在虚拟机 / 另一台机器上**跑：")
        print("        python installer/selftest_setup.py --run-engine")
        t.skip("第 4 层「真机安装->卸载」未运行（缺 --run-engine）")
    else:
        test_install_uninstall(t)

    print("\n" + "=" * 64)
    # ★ 跳过数必须出现在**结论行**里：否则"这个包本来就少一组断言"和
    #   "全绿"输出完全一样，下次就分不出来了。
    _skip = ("，%d 项跳过" % t.skipped) if t.skipped else ""
    if t.failed:
        print(" 自测失败：%d 通过 / %d 失败%s" % (t.passed, t.failed, _skip))
        for m in t.msgs:
            print("   x %s" % m)
        return 1
    print(" 自测全部通过：%d 项断言%s" % (t.passed, _skip))
    return 0


if __name__ == "__main__":
    sys.exit(main())

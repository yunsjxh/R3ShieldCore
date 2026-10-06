#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
diag_autostart.py -- 「开机自启没生效」的只读排查器
==================================================

设计原则
--------
1. **只读**：不装、不删、不改、不启动任何东西。任何一步失败都只是"这一格查不出来"，
   不影响别的格（否则一次报错就把整份诊断吞掉，等于没写）。
2. **按三层链的顺序查**，最后**只报"第一个断掉的环节"**（按优先级，不按发现顺序）——
   排查的价值在于"下一个该动哪里"，不是把 20 项全列出来。
3. **不 spawn System32 工具**（`sc.exe` / `tasklist.exe` 会被引擎自己的片段规则拦掉，
   铁律 42/43）。全部走 winreg + ctypes + 直接读文件。
4. **判据要有前提**：说"没问题"之前先确认"我看到的东西存在"（铁律 117）。

三层链（哪一层断了，现象都是同一句"没有开机自启"）
--------------------------------------------------
    驱动 r3shieldcore_kernel.sys   BOOT_START   只加载，不拉进程
    服务 R3ShieldCoreGuard         AUTO_START   把引擎拉进交互会话
    引擎 R3 ShieldCore.exe         用户会话      真正干活

用法
----
    python tools/diag_autostart.py [--dir "C:\\Program Files\\R3 ShieldCore"]
"""

import argparse
import ctypes
import ctypes.wintypes as wt
import os
import re
import sys
import time
import winreg

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HKLM = winreg.HKEY_LOCAL_MACHINE

# ---------------------------------------------------------------------------
# 常量（和服务/安装器保持一致；漂了会被 tools/check_payload_manifest.py 抓）
# ---------------------------------------------------------------------------
SVC_NAME = "R3ShieldCoreGuard"
SVC_EXE = "r3shieldcore_svc.exe"
DRV_SVC = "R3ShieldCoreKernel"
DRV_SYS = "r3shieldcore_kernel.sys"
ENGINE_EXE = "R3 ShieldCore.exe"
SVC_LOG = "r3shieldcore-svc.log"
UNINST_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\R3ShieldCore"
DEFAULT_DIR = r"C:\Program Files\R3 ShieldCore"
SERVICES = r"SYSTEM\CurrentControlSet\Services"
BIOS_KEY = r"HARDWARE\DESCRIPTION\System\BIOS"

START_TYPES = {0: "0 (Boot)", 1: "1 (System)", 2: "2 (Auto)",
               3: "3 (Demand)", 4: "4 (Disabled)"}

WTS_CURRENT_SERVER_HANDLE = None
WTSUserName = 5
WTSConnectState = 8
SM_CLEANBOOT = 67

OK, BAD, WARN, INFO = "[ OK ]", "[ 断 ]", "[注意]", "[信息]"

# 服务的日志里哪些行有诊断价值（按重要性排）
LOG_PATTERNS = [
    (r"检测到\*\*安全模式\*\*", "安全模式闸门生效（按要求不拉起引擎）"),
    (r"还不能拉起：(.+)", "会话判据没过"),
    (r"内就退出了（退出码\s*[0-9A-Fa-fx]+)", "引擎拉起后**秒退**"),
    (r"拉起引擎失败 err=(\d+)", "拉起失败"),
    (r"并确认存活", "★ 成功拉起并确认存活"),
    (r"已拉起引擎 pid=(\d+)", "拉起过（未确认存活 —— 旧版本日志）"),
    (r"令牌（[^）]*）：(.+)", "令牌事实"),
    (r"=== .*启动 pid=(\d+)", "服务被 SCM 拉起"),
    (r"=== .*停止", "服务已停止"),
]

findings = []   # [(优先级, 文字), ...]  优先级越小越"根本"


def finding(pri, text):
    findings.append((pri, text))


# ---------------------------------------------------------------------------
# 输出小工具
# ---------------------------------------------------------------------------

def head(t):
    print("\n=== %s ===" % t)


def line(tag, text):
    print("  %s %s" % (tag, text))


def note(text):
    print("        %s" % text)


# ---------------------------------------------------------------------------
# 读取工具（全部容错：读不到返回 None，不抛）
# ---------------------------------------------------------------------------

def reg_read(path, name, root=HKLM):
    try:
        with winreg.OpenKey(root, path) as k:
            v, _ = winreg.QueryValueEx(k, name)
            return v
    except Exception:
        return None


def reg_exists(path, root=HKLM):
    try:
        with winreg.OpenKey(root, path):
            return True
    except Exception:
        return False


def file_state(p):
    """返回 (是否存在, 字节数, 修改时间字符串)。"""
    try:
        st = os.stat(p)
        return True, st.st_size, time.strftime("%Y-%m-%d %H:%M:%S",
                                               time.localtime(st.st_mtime))
    except Exception:
        return False, 0, "-"


def get_tick_ms():
    """系统已运行毫秒（64 位；GetTickCount 会 ~49 天溢出，不能用）。"""
    try:
        k = ctypes.windll.kernel32
        k.GetTickCount64.restype = ctypes.c_ulonglong
        return k.GetTickCount64()
    except Exception:
        return None


def vm_info():
    man = reg_read(BIOS_KEY, "SystemManufacturer") or ""
    prod = reg_read(BIOS_KEY, "SystemProductName") or ""
    blob = ("%s %s" % (man, prod)).lower()
    marks = ["vmware", "virtualbox", "vbox", "qemu", "kvm", "hyper-v",
             "parallels", "xen", "bochs", "innotek", "virtual machine",
             "microsoft corporation"]
    return any(m in blob for m in marks), ("%s / %s" % (man, prod)).strip(" /")


def is_safe_mode():
    """0 = 正常；1 = 安全模式；2 = 带网络的安全模式。"""
    try:
        return int(ctypes.windll.user32.GetSystemMetrics(SM_CLEANBOOT))
    except Exception:
        return -1


def session_user(session):
    """该会话里登录的用户名（空 = 没人登录）。★ 不需要 SeTcbPrivilege。"""
    try:
        wts = ctypes.windll.wtsapi32
        buf = ctypes.c_void_p()
        n = wt.DWORD()
        ok = wts.WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE, wt.DWORD(session), WTSUserName,
            ctypes.byref(buf), ctypes.byref(n))
        if ok and buf.value:
            s = ctypes.wstring_at(buf)
            wts.WTSFreeMemory.argtypes = [ctypes.c_void_p]
            wts.WTSFreeMemory(buf)
            return s or ""
    except Exception:
        pass
    return ""


def session_state(session):
    """WTSActive = 0。返回 int 或 None。"""
    try:
        wts = ctypes.windll.wtsapi32
        buf = ctypes.c_void_p()
        n = wt.DWORD()
        ok = wts.WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE, wt.DWORD(session), WTSConnectState,
            ctypes.byref(buf), ctypes.byref(n))
        if ok and buf.value:
            v = ctypes.cast(buf, ctypes.POINTER(wt.DWORD)).contents.value
            wts.WTSFreeMemory.argtypes = [ctypes.c_void_p]
            wts.WTSFreeMemory(buf)
            return int(v)
    except Exception:
        pass
    return None


def active_console_session():
    try:
        v = ctypes.windll.kernel32.WTSGetActiveConsoleSessionId()
        return None if v in (0xFFFFFFFF, -1) else int(v)
    except Exception:
        return None


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
                ("th32ProcessID", wt.DWORD), ("th32DefaultHeapID", ctypes.c_void_p),
                ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
                ("th32ParentProcessID", wt.DWORD), ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wt.DWORD), ("szExeFile", ctypes.c_wchar * 260)]


def find_processes(exe_name):
    """按映像名找进程，返回 [(pid, session), ...]。"""
    out = []
    k = ctypes.windll.kernel32
    k.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    k.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
    k.CloseHandle.argtypes = [ctypes.c_void_p]
    snap = k.CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
    if not snap or snap == ctypes.c_void_p(-1).value:
        return out
    try:
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if k.Process32FirstW(snap, ctypes.byref(pe)):
            while True:
                if (pe.szExeFile or "").lower() == exe_name.lower():
                    sid = wt.DWORD()
                    k.ProcessIdToSessionId(pe.th32ProcessID, ctypes.byref(sid))
                    out.append((int(pe.th32ProcessID), int(sid.value)))
                if not k.Process32NextW(snap, ctypes.byref(pe)):
                    break
    except Exception:
        pass
    finally:
        k.CloseHandle(snap)
    return out


def scan_log(path):
    """返回 (全文 或 None, [(描述, 原文), ...])。"""
    try:
        with open(path, "rb") as f:
            txt = f.read().decode("utf-8-sig", "replace")
    except Exception:
        return None, []
    hits = []
    for ln in txt.splitlines():
        s = ln.strip()
        if not s:
            continue
        for pat, desc in LOG_PATTERNS:
            if re.search(pat, s):
                hits.append((desc, s))
                break
    return txt, hits


def resolve_dir(arg_dir):
    if arg_dir:
        return arg_dir, "命令行 --dir"
    v = reg_read(UNINST_KEY, "InstallLocation")
    if v:
        return v, "注册表 InstallLocation"
    return DEFAULT_DIR, "默认路径（卸载项里没有 InstallLocation —— 可能没装过）"


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="R3 ShieldCore 开机自启只读排查器")
    ap.add_argument("--dir", default=None, help="安装目录（默认从卸载项/默认路径推导）")
    args = ap.parse_args()

    print("=" * 70)
    print(" R3 ShieldCore 开机自启诊断（只读：不装不删不改不启动）")
    print("=" * 70)

    # ---------------- 0. 环境 ----------------
    head("0. 环境")
    is_vm, model = vm_info()
    line(INFO, "虚拟机        : %s%s" % ("是" if is_vm else "否",
                                       ("（%s）" % model) if model else ""))

    sm = is_safe_mode()
    line(INFO, "安全模式      : %s" % {0: "否", 1: "是（安全模式）",
                                       2: "是（带网络的安全模式）"}.get(
                                           sm, "查不出来（%s）" % sm))
    if sm > 0:
        note("★ 安全模式下**按设计不启动**引擎（驱动仍会加载）。这不是故障。")

    tick = get_tick_ms()
    boot_time = None
    if tick is not None:
        boot_time = time.time() - tick / 1000.0
        line(INFO, "系统启动于    : %s（已运行 %.1f 小时）"
             % (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(boot_time)),
                tick / 3600000.0))
    else:
        line(WARN, "系统启动时间  : 查不出来（GetTickCount64 失败）")

    console = active_console_session()
    if console is None:
        line(INFO, "控制台会话    : (无)")
    else:
        u = session_user(console)
        st = session_state(console)
        line(INFO, "控制台会话    : %s，用户=%s，状态=%s"
             % (console, u if u else "(还没有人登录)",
                "活动(WTSActive)" if st == 0 else str(st)))

    # ---------------- 1. 安装目录与文件 ----------------
    head("1. 安装目录与文件")
    dest, how = resolve_dir(args.dir)
    line(INFO, "安装目录      : %s   （来源：%s）" % (dest, how))

    install_ctime = None
    if os.path.isdir(dest):
        line(OK, "目录存在")
        try:
            install_ctime = os.path.getctime(dest)
            line(INFO, "目录创建于    : %s（≈ 安装时刻）"
                 % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(install_ctime)))
        except Exception:
            pass
    else:
        line(BAD, "目录**不存在**")
        finding(10, "安装目录不存在 —— 没装成功 / 已被卸载 / **VM 上回滚了快照**")

    for label, rel, critical in (("引擎  ", ENGINE_EXE, True),
                                 ("服务  ", SVC_EXE, True),
                                 ("驱动  ", os.path.join("driver", DRV_SYS), True),
                                 ("日志  ", SVC_LOG, False)):
        p = os.path.join(dest, rel)
        ex, size, mt = file_state(p)
        if ex:
            line(OK, "%s %-26s %8d B  改于 %s" % (label, rel, size, mt))
        else:
            line(BAD if critical else WARN, "%s %-26s **不存在**" % (label, rel))
            if critical:
                finding(20, "安装目录里缺 %s —— 文件没装全" % rel)

    # ★ VM 专项：安装之后到底重启过没有
    if install_ctime and boot_time and boot_time < install_ctime:
        print()
        line(BAD, "★ 安装之后**还没有真正重启过**")
        note("安装于 %s，而系统是 %s 启动的。"
             % (time.strftime("%H:%M:%S", time.localtime(install_ctime)),
                time.strftime("%H:%M:%S", time.localtime(boot_time))))
        note("开机自启**只能靠「重启后」证明**。")
        if is_vm:
            note("★★ VM 专项：虚拟机上的重启必须是**真正的关机再开机**。")
            note("    「挂起 / 保存状态后恢复」**不算重启** —— 内核状态原样恢复，")
            note("    服务的 AUTO_START 不会再触发、驱动的 BOOT_START 也不会重跑；")
            note("    「快照回滚」更糟 —— 它把服务注册和文件一起回滚掉。")
        finding(70, "安装后还没真正重启过（或用了挂起/快照）—— 先真重启一次再看")

    # ---------------- 2. 驱动层 ----------------
    head("2. 驱动层（BOOT_START，只负责被加载）")
    drv_path = "%s\\%s" % (SERVICES, DRV_SVC)
    drv_ok = True
    if not reg_exists(drv_path):
        line(WARN, "服务键 %s **不存在**（驱动没注册）" % DRV_SVC)
        note("⇒ 只是「没有内核组件」。三层是独立的，**不影响用户态引擎的自启**。")
        drv_ok = False
    else:
        st = reg_read(drv_path, "Start")
        ip = reg_read(drv_path, "ImagePath") or ""
        line(OK, "服务键存在")
        line(OK if st == 0 else WARN, "Start          : %s%s"
             % (START_TYPES.get(st, st), "" if st == 0 else "   （期望 0 = Boot）"))
        line(INFO, "ImagePath      : %s" % ip)
        sysroot = os.environ.get("SystemRoot", r"C:\Windows")
        sysfile = os.path.join(sysroot, "System32", "drivers", DRV_SYS)
        ex, size, mt = file_state(sysfile)
        if ex:
            line(OK, "驱动文件       : 存在（%d B）  %s" % (size, sysfile))
        else:
            line(BAD, "驱动文件       : **不存在**  %s" % sysfile)
            finding(95, "驱动服务键在，但 %s 不在 System32\\drivers 里" % DRV_SYS)
            drv_ok = False

        # ★ 铁律 114：驱动自报的"自开机到被加载"毫秒数 —— 这才是开机自启的证据。
        stamp = reg_read(drv_path, "LoadSinceBootMs")
        if stamp is None:
            line(WARN, "LoadSinceBootMs: 没有这个值（驱动可能还没被加载过）")
        else:
            line(INFO, "LoadSinceBootMs: %s ms" % stamp)
            if stamp == 0:
                note("★ 0 对 BOOT_START 是**正常且最好**的结果（引导阶段中断计时器几乎还没走）。")
            elif stamp < 60000:
                note("很小 ⇒ 确实是**开机时**加载的。")
            else:
                note("较大 ⇒ 更像**手动 sc start** 起来的，不是开机自启。")

    # ---------------- 3. 服务层（关键） ----------------
    head("3. 服务层（AUTO_START，负责把引擎拉进交互会话）")
    svc_path = "%s\\%s" % (SERVICES, SVC_NAME)
    if not reg_exists(svc_path):
        line(BAD, "服务键 %s **不存在** —— 开机自启根本没注册" % SVC_NAME)
        note("可能原因：装的时候「开机自动启动引擎」那格没勾 / 注册那步失败 /")
        note("          服务被 sc delete 了 / **VM 上回滚了快照**。")
        finding(40, "开机启动服务没注册 —— 重装一次并勾上「开机自动启动引擎」")
    else:
        line(OK, "服务键存在")
        st = reg_read(svc_path, "Start")
        ip = reg_read(svc_path, "ImagePath") or ""
        line(OK if st == 2 else BAD, "Start          : %s%s"
             % (START_TYPES.get(st, st), "" if st == 2 else "   （期望 2 = Auto）"))
        line(INFO, "ImagePath      : %s" % ip)
        if st != 2:
            finding(50, "服务启动类型不是 AUTO_START（现在是 %s）—— 开机不会自启"
                    % START_TYPES.get(st, st))

        # ★ 铁律 135/139：注册项"存在" != "指对了程序"。回读目标字段并验它真存在。
        target = ip.strip().strip('"')
        tex, tsize, _ = file_state(target)
        if tex:
            line(OK, "指向的服务 exe : 存在（%d B）" % tsize)
        else:
            line(BAD, "指向的服务 exe : **不存在** —— %s" % target)
            finding(60, "服务指向的 exe 不存在（binPath 写错 / 文件被删）")

        # ---- 服务日志：这是"为什么没自启"的第一诊断口径 ----
        log_path = os.path.join(dest, SVC_LOG)
        txt, hits = scan_log(log_path)
        print()
        if txt is None:
            line(BAD, "服务日志**不存在**：%s" % log_path)
            note("⇒ 服务**从来没被启动过**（服务一起来第一件事就是写日志）。")
            finding(75, "服务从未被拉起过（日志不存在）—— 服务注册了但没跑起来")
        elif not hits:
            line(WARN, "服务日志存在，但没有任何关键行（可能刚建、还没跑过）")
            finding(75, "服务日志里没有关键行 —— 服务可能没跑起来")
        else:
            line(INFO, "服务日志关键行（%d 条，按时间序，末尾 14 条）：" % len(hits))
            for desc, raw in hits[-14:]:
                print("        · %-30s %s" % (desc, raw))
            joined = "\n".join(r for _, r in hits)

            if re.search(r"检测到\*\*安全模式\*\*", joined):
                line(INFO, "⇒ 安全模式下闸门生效，**这是预期行为**（不是故障）")
            m = re.search(r"还不能拉起：(.+)", joined)
            if m:
                why = m.group(1).strip()
                line(BAD, "⇒ 会话判据没过：%s" % why)
                finding(80, "会话判据没过：%s" % why)
            m = re.search(r"内就退出了（退出码\s*([0-9A-Fa-fx]+)", joined)
            if m:
                line(BAD, "⇒ 引擎被拉起来了但**秒退**，退出码 %s" % m.group(1))
                note("这是**引擎自己**启动失败（缺 DLL / 配置 / 目录 ACL），")
                note("不是自启链的问题 —— 去引擎自己的 console log 里找原因。")
                finding(85, "引擎拉起后秒退（退出码 %s）—— 问题在引擎自身，不在自启链"
                        % m.group(1))
            m = re.search(r"拉起引擎失败 err=(\d+)", joined)
            if m:
                line(BAD, "⇒ 拉起失败 err=%s" % m.group(1))
                note("1314 = 缺权限；5 = 拒绝访问；2 = 文件不存在。")
                finding(88, "拉起引擎失败 err=%s" % m.group(1))

    # ---------------- 4. 引擎层 ----------------
    head("4. 引擎层（真正干活的）")
    procs = find_processes(ENGINE_EXE)
    if procs:
        for pid, sid in procs:
            u = session_user(sid)
            line(OK, "引擎在跑：pid=%d  会话=%d  用户=%s" % (pid, sid, u if u else "?"))
        if len(procs) > 1:
            line(BAD, "★ 有 %d 份引擎同时在跑 —— 引擎没有单实例互斥体，会互相打架！"
                 % len(procs))
            finding(90, "同时有多份引擎在跑（互咬）")
    else:
        line(WARN, "引擎**没在跑**")

    # ---------------- 5. 结论 ----------------
    print()
    print("=" * 70)
    if findings:
        findings.sort(key=lambda x: x[0])
        print(" 第一个断掉的环节：")
        print("   → %s" % findings[0][1])
        if len(findings) > 1:
            print()
            print(" 后面还排着 %d 个（修完上面那个再看）：" % (len(findings) - 1))
            for pri, txt in findings[1:4]:
                print("   · %s" % txt)
        print()
        print(" 修完再跑一次本诊断，看下一个断点在哪。")
    else:
        print(" 三层链**全通**：服务已注册且指向正确、引擎正在跑。")
    if not drv_ok:
        print()
        print(" 注：驱动那层没通，但它和引擎自启是**独立**的两件事（不影响本次结论）。")
    print("=" * 70)
    print()
    print(" 排查顺序永远是这条链：驱动（被加载）→ 服务（被 SCM 拉起）→ 引擎（被服务拉起）")
    print(" 三层任何一层断了，用户看到的现象都是同一句「没有开机自启」。")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)

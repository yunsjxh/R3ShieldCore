# -*- coding: utf-8 -*-
#
# winprobe.py — 窗口归属与关闭行为探针
#
# 回答两个问题：
#   1) 引擎的控制台窗口，拥有者到底是不是引擎进程？（Windows 7+ 是 conhost.exe）
#   2) 给 GUI 主窗口发 WM_CLOSE 会怎样？窗口消失？进程死掉？
#
# 用法:
#   python winprobe.py list <pid>              # 只列出该 pid 的顶层窗口
#   python winprobe.py close <pid> [className] # 给匹配窗口发 WM_CLOSE，再复查
#   python winprobe.py all                     # 列出所有含 inject 的窗口 + conhost
#
import ctypes
import ctypes.wintypes as wt
import sys

u32 = ctypes.WinDLL("user32", use_last_error=True)
k32 = ctypes.WinDLL("kernel32", use_last_error=True)

WM_CLOSE = 0x0010
EnumWindowsProc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

# ⚠️ 必须显式声明 argtypes/restype。64 位下不声明的话，HANDLE 会被 ctypes 当成
#    32 位 int 传参 → 句柄高位被截断 → 调用失败或返回垃圾，而返回值又是"成功"。
#    （第一版就栽在这里：所有进程的镜像路径都读错。）
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.OpenProcess.restype = wt.HANDLE
k32.CloseHandle.argtypes = [wt.HANDLE]
k32.CloseHandle.restype = wt.BOOL
k32.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR,
                                           ctypes.POINTER(wt.DWORD)]
k32.QueryFullProcessImageNameW.restype = wt.BOOL
k32.GetExitCodeProcess.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
k32.GetExitCodeProcess.restype = wt.BOOL

u32.EnumWindows.argtypes = [EnumWindowsProc, wt.LPARAM]
u32.EnumWindows.restype = wt.BOOL
u32.GetClassNameW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
u32.GetClassNameW.restype = ctypes.c_int
u32.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
u32.GetWindowTextW.restype = ctypes.c_int
u32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
u32.GetWindowThreadProcessId.restype = wt.DWORD
u32.IsWindowVisible.argtypes = [wt.HWND]
u32.IsWindowVisible.restype = wt.BOOL
u32.IsWindow.argtypes = [wt.HWND]
u32.IsWindow.restype = wt.BOOL
u32.PostMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
u32.PostMessageW.restype = wt.BOOL


class RECT(ctypes.Structure):
    _fields_ = [("left", wt.LONG), ("top", wt.LONG),
                ("right", wt.LONG), ("bottom", wt.LONG)]


def window_pid(hwnd):
    pid = wt.DWORD(0)
    u32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value


def class_name(hwnd):
    buf = ctypes.create_unicode_buffer(512)
    u32.GetClassNameW(hwnd, buf, 512)
    return buf.value


def title(hwnd):
    buf = ctypes.create_unicode_buffer(512)
    u32.GetWindowTextW(hwnd, buf, 512)
    return buf.value


def visible(hwnd):
    return bool(u32.IsWindowVisible(hwnd))


def is_window(hwnd):
    return bool(u32.IsWindow(hwnd))


def enum_top_level():
    out = []

    def cb(hwnd, _):
        out.append(hwnd)
        return True

    u32.EnumWindows(EnumWindowsProc(cb), 0)
    return out


def proc_alive(pid):
    """用 OpenProcess(QUERY_LIMITED_INFORMATION) + GetExitCodeProcess 判存活。"""
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None, ctypes.get_last_error()
    try:
        code = wt.DWORD(0)
        if k32.GetExitCodeProcess(h, ctypes.byref(code)):
            return (code.value == 259), code.value  # 259 = STILL_ACTIVE
        return None, ctypes.get_last_error()
    finally:
        k32.CloseHandle(h)


def proc_image(pid):
    """拿进程镜像名（QueryFullProcessImageName）。"""
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = wt.DWORD(1024)
        if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return buf.value
        return None
    finally:
        k32.CloseHandle(h)


def dump(hwnds, pid_filter=None, label=""):
    print("=" * 78)
    print(label)
    print("=" * 78)
    for h in hwnds:
        pid = window_pid(h)
        if pid_filter is not None and pid != pid_filter:
            continue
        img = proc_image(pid) or "(读不到镜像路径)"
        print(f"hwnd=0x{h:08X}  pid={pid:<7} visible={str(visible(h)):<5} "
              f"class={class_name(h)!r}")
        print(f"    title = {title(h)!r}")
        print(f"    image = {img}")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    mode = sys.argv[1]

    if mode == "all":
        hwnds = enum_top_level()
        print(f"顶层窗口总数 = {len(hwnds)}")
        print()
        print("---- 拥有者进程镜像名含 inject 的窗口 ----")
        for h in hwnds:
            pid = window_pid(h)
            img = proc_image(pid) or ""
            if "inject" in img.lower():
                print(f"hwnd=0x{h:08X}  pid={pid:<7} visible={str(visible(h)):<5} "
                      f"class={class_name(h)!r}  title={title(h)!r}")
        print()
        print("---- 拥有者进程镜像名含 conhost 的窗口（控制台窗口在这里！）----")
        n = 0
        for h in hwnds:
            pid = window_pid(h)
            img = proc_image(pid) or ""
            if "conhost" in img.lower():
                n += 1
                print(f"hwnd=0x{h:08X}  pid={pid:<7} visible={str(visible(h)):<5} "
                      f"class={class_name(h)!r}  title={title(h)!r}")
        print(f"（共 {n} 个）")
        return 0

    pid = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    if not pid:
        print("需要 pid")
        return 1

    hwnds = [h for h in enum_top_level() if window_pid(h) == pid]
    dump(hwnds, pid, f"pid={pid} 的顶层窗口")

    alive, code = proc_alive(pid)
    print(f"\n进程存活检查: alive={alive} exitCode={code if code is not None else '-'}")

    if mode == "list":
        return 0

    if mode == "close":
        target_class = sys.argv[3] if len(sys.argv) > 3 else "R3ShieldCoreMainWindow"
        targets = [h for h in hwnds if class_name(h) == target_class]
        print(f"\n---- 对 class={target_class!r} 的 {len(targets)} 个窗口 PostMessage(WM_CLOSE) ----")
        for h in targets:
            before = visible(h)
            ctypes.set_last_error(0)
            ok = u32.PostMessageW(h, WM_CLOSE, 0, 0)
            err = ctypes.get_last_error()
            print(f"hwnd=0x{h:08X}  PostMessage -> {ok}  GetLastError={err}  "
                  f"(before visible={before})")
            if not ok:
                if err == 5:
                    print("    ⚠️ err=5 = UIPI 拦截：本进程权限低于窗口所属进程，消息根本没发出去")
                else:
                    print(f"    ⚠️ 发送失败 err={err}")

        import time
        time.sleep(1.0)
        print("\n---- 1 秒后复查 ----")
        for h in targets:
            print(f"hwnd=0x{h:08X}  IsWindow={is_window(h)}  visible={visible(h)}")
        alive2, code2 = proc_alive(pid)
        print(f"进程存活检查: alive={alive2} exitCode={code2 if code2 is not None else '-'}")
        return 0

    print(f"未知模式 {mode!r}")
    return 1


if __name__ == "__main__":
    sys.exit(main())

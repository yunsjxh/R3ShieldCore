# -*- coding: utf-8 -*-
"""真的点一遍高级页（v128）：点行 / 改规则 / 加入-更新 / 删除 / 载入 / 保存 / 滚轮。

为什么不用探针：探针只截图 + 读日志，它不会**点**。用户的原话是
「那真的能用吗？你自己试试看」—— 那就得真的把消息发进去、再把
结果（输入框内容 / 规则条数 / 规则文件）读出来。

★ 输入框必须用 `GetDlgItem(hwnd, 4001)`（`AdvEditId`）拿 ——
  配置页里有**一堆** class=Edit 的子控件，按类名取第一个会拿到配置页那个，
  读出来永远是空串（第一版驱动就踩了：判据全绿/全红都是假的）。
"""
import ctypes
import ctypes.wintypes as wt
import os
import sys
import time

u32 = ctypes.WinDLL("user32", use_last_error=True)

WM_LBUTTONDOWN, WM_LBUTTONUP = 0x0201, 0x0202
WM_SETTEXT, WM_GETTEXT, WM_GETTEXTLENGTH = 0x000C, 0x000D, 0x000E
WM_MOUSEWHEEL = 0x020A
MK_LBUTTON = 0x0001
ADV_EDIT_ID = 4001

u32.FindWindowW.restype = wt.HWND
u32.FindWindowW.argtypes = [wt.LPCWSTR, wt.LPCWSTR]
u32.GetDlgItem.restype = wt.HWND
u32.GetDlgItem.argtypes = [wt.HWND, ctypes.c_int]

TABLE_TOP, ROW_H = 204, 19
BTN_TOP = 692
BTN_X = [20, 168, 316, 464, 612, 760]   # 加入/更新 · 删除 · 保存 · 载入 · 示例 · 清空
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                     "R3 Shield Core", "r3shieldcore-rules.txt")
LOG = os.path.join(ROOT, "_t", "drv.log")

ok = fail = 0


def check(cond, name, extra=""):
    global ok, fail
    if cond:
        ok += 1
        print("  [PASS] " + name + ((" —— " + extra) if extra else ""))
    else:
        fail += 1
        print("  [FAIL] " + name + ((" —— " + extra) if extra else ""))


def get_text(h):
    n = u32.SendMessageW(h, WM_GETTEXTLENGTH, 0, 0)
    buf = ctypes.create_unicode_buffer(n + 1)
    u32.SendMessageW(h, WM_GETTEXT, n + 1, ctypes.byref(buf))
    return buf.value


def set_text(h, s):
    u32.SendMessageW(h, WM_SETTEXT, 0, s)


def client_origin(hwnd):
    pt = wt.POINT(0, 0)
    u32.ClientToScreen(hwnd, ctypes.byref(pt))
    return pt.x, pt.y


def post_click(hwnd, cx, cy):
    lp = (cy << 16) | (cx & 0xFFFF)
    u32.PostMessageW(hwnd, WM_LBUTTONDOWN, MK_LBUTTON, lp)
    u32.PostMessageW(hwnd, WM_LBUTTONUP, 0, lp)
    time.sleep(0.25)


def real_click(hwnd, cx, cy):
    """真·鼠标事件（走 OS 命中测试 + 激活）。★ 点两下：
    第一下被 `WM_MOUSEACTIVATE` 吃掉（激活窗口，不投递给客户区）——这是
    Windows 的既定行为，不是程序的问题。"""
    ox, oy = client_origin(hwnd)
    old = wt.POINT(0, 0)
    u32.GetCursorPos(ctypes.byref(old))
    u32.SetCursorPos(ox + cx, oy + cy)
    time.sleep(0.06)
    for _ in range(2):
        u32.mouse_event(0x0002, 0, 0, 0, 0)
        time.sleep(0.04)
        u32.mouse_event(0x0004, 0, 0, 0, 0)
        time.sleep(0.12)
    u32.SetCursorPos(old.x, old.y)


def wheel(hwnd, cx, cy, notches):
    ox, oy = client_origin(hwnd)
    lp = ((oy + cy) << 16) | ((ox + cx) & 0xFFFF)
    wp = ((-120 * notches) & 0xFFFF) << 16
    u32.PostMessageW(hwnd, WM_MOUSEWHEEL, wp, lp)
    time.sleep(0.25)


def log_lines():
    try:
        raw = open(LOG, "rb").read()
    except OSError:
        return []
    return [ln for ln in raw.decode("gbk", "replace").splitlines()
            if ln.startswith("[adv]")]


def new_log(n0):
    return log_lines()[n0:]


def rule_file():
    try:
        raw = open(RULES, "rb").read()
    except OSError:
        return []
    return [ln for ln in raw.decode("utf-8-sig", "replace").splitlines() if ln.strip()]


def apply_rule(hwnd, edit, line):
    """把一行写进输入框，然后点「加入/更新规则」。返回这一步的新日志。"""
    set_text(edit, line)
    u32.RedrawWindow(hwnd, None, None, 0x0001 | 0x0080)
    time.sleep(0.1)
    n0 = len(log_lines())
    post_click(hwnd, BTN_X[0] + 70, BTN_TOP + 14)
    return new_log(n0)


hwnd = u32.FindWindowW("R3ShieldCoreCfgWnd", None)
if not hwnd:
    print("FAIL 找不到窗口（cfg 没在跑？）")
    sys.exit(1)
edit = u32.GetDlgItem(hwnd, ADV_EDIT_ID)
print("窗口 hwnd=%s  高级页输入框=%s" % (hwnd, edit))
if not edit:
    print("FAIL 找不到高级页的 EDIT（id=4001）")
    sys.exit(1)

print("\n== 0. 起始状态 ==")
n_rules = len(rule_file())
print("  规则文件 %d 条；输入框=%r" % (n_rules, get_text(edit)))
check(get_text(edit) == "", "一打开输入框是空的")

print("\n== 1. 真鼠标点规则表第 3 行（#2）==")
u32.SetWindowPos(hwnd, -1, 0, 0, 0, 0, 0x53)   # TOPMOST
time.sleep(0.15)
u32.SetWindowPos(hwnd, -2, 0, 0, 0, 0, 0x53)   # NOTOPMOST
time.sleep(0.15)
real_click(hwnd, 200, TABLE_TOP + 2 * ROW_H + 9)
t = get_text(edit)
print("  输入框 -> %r" % t)
check(t.strip() != "", "点第 3 行后输入框里出现了规则")
check("注册表枚举" in t, "载入的正是第 3 条（枚举面）", t)

print("\n== 2. 改这一行 + 点「加入/更新规则」（应原地替换 #2，条数不变）==")
got = apply_rule(hwnd, edit, '当 注册表枚举 的 子键名 含 "SecretKey" 时 隐藏')
print("  新日志: %s" % got)
check(any("动作 #3" in ln for ln in got), "「加入/更新规则」真的执行了")
check(any("规则=%d" % n_rules in ln for ln in got),
      "条数没变（原地替换，不是先删后加）", "规则=%d" % n_rules)

print("\n== 3. 点「保存到规则文件」= 文件真的被改写 ==")
n0 = len(log_lines())
post_click(hwnd, BTN_X[2] + 70, BTN_TOP + 14)
lines = rule_file()
hit = [ln for ln in lines if "SecretKey" in ln]
print("  文件 %d 条；含 SecretKey 的行 = %s" % (len(lines), hit))
check(bool(hit), "保存把改后的内容写进了文件")
check(len(lines) == n_rules, "文件条数没变（%d）" % len(lines))

print("\n== 4. 点「从规则文件载入」两次（旧缺陷：每点一次翻倍）==")
for i in range(2):
    n0 = len(log_lines())
    post_click(hwnd, BTN_X[3] + 70, BTN_TOP + 14)
    got = [ln for ln in new_log(n0) if "规则=" in ln]
    print("  第 %d 次载入: %s" % (i + 1, got))
    check(any("规则=%d" % n_rules in ln for ln in got),
          "第 %d 次载入后仍是 %d 条（没有翻倍）" % (i + 1, n_rules))

print("\n== 5. 点「重置为示例规则」= 3 条 ==")
n0 = len(log_lines())
post_click(hwnd, BTN_X[4] + 70, BTN_TOP + 14)
got = [ln for ln in new_log(n0) if "规则=" in ln]
print("  %s" % got)
check(any("规则=3" in ln for ln in got), "重置回 3 条示例")

print("\n== 6. 灌到 8 条（超过一屏上限 6）==")
last = ""
for i in range(5):
    got = apply_rule(hwnd, edit, '当 注册表值 的 值名 含 "DRV%d" 时 替换为 "1"' % i)
    if got:
        last = got[-1]
print("  最后一条动作日志: %s" % last)
check("规则=8" in last, "连点 5 次「加入」真的加到 8 条（不是覆盖同一条）", last)

n0 = len(log_lines())
print("\n== 7. 滚轮：光标停在规则表里向上滚 2 格（加完在底部，只能往上翻）==")
wheel(hwnd, 200, TABLE_TOP + 9, -2)
got = [ln for ln in new_log(n0) if "规则表滚动" in ln]
print("  %s" % got)
check(any("首行=" in ln for ln in got), "滚轮真的翻动了规则表")
check(any("首行=0" in ln for ln in got), "向上滚回到第 0 行")

print("\n== 8. 点第 1 行选中，再点「删除选中」==")
post_click(hwnd, 200, TABLE_TOP + 9)
t = get_text(edit)
print("  输入框 -> %r" % t)
n0 = len(log_lines())
post_click(hwnd, BTN_X[1] + 70, BTN_TOP + 14)
got = [ln for ln in new_log(n0) if "规则=" in ln]
print("  %s" % got)
check(any("规则=7" in ln for ln in got), "删除后 8 -> 7 条")

print("\n结果：通过 %d / 失败 %d" % (ok, fail))
sys.exit(0 if fail == 0 else 1)


# 用法（★ 先起界面，再跑本脚本）：
#   R3SHIELDCORE_GLASS_NO_WDA=1 R3SHIELDCORE_PREVIEW_ADV=editor \
#       ./dist/R3ShieldCore-x64/r3shieldcore-cfg.exe --gui-preview --page 2 > _t/drv.log &
#   python tools/drive_cfg_adv.py
# ★ 会点「保存到规则文件」⇒ 先备份 %ProgramData%/R3 Shield Core 下的规则文件
# ★ 版面常量按 1024x740 写死（TABLE_TOP/ROW_H/BTN_TOP），换尺寸要跟着改

<#
    R3ShieldCore 输入失效 / 光标异常 诊断脚本（只读，不改任何项目代码）

    用途
    ----
    运行本引擎后出现「点击输入框后键盘无响应」「鼠标光标恒为 I 型（文本输入）样式」
    时，用本脚本一次性采集根因证据：

      S0 环境基线      —— 输入桌面 / 会话 / 提权 / 键盘布局 / 辅助功能 / 光标方案
      S1 引擎与注入面  —— 引擎进程、配置 mode、被注入进程清单、日志中的拦截记录
      S2 焦点与捕获    —— 前台窗口、目标线程 hwndFocus/hwndActive/hwndCapture、卡死判定
      S2.5 目标程序专项 —— ★ -TargetApp 指定出问题的程序后，焦点/光标/band 全部只针对它
      S3 覆盖窗口普查  —— topmost / 全屏 / 覆盖光标的窗口 + **窗口 Band 普查**
                          （band=2 = UIAccess 波段。注意 AMD 驱动/IME 也会用 band=2，
                            但只放不可见小窗口；**可见且够大**的 band=2 才是超级置顶嫌疑）
      S4 光标身份      —— 当前光标句柄与标准光标比对、类光标、ClipCursor 状态
      S5 输入可达性    —— GetLastInputInfo 前进性 + 低级键鼠钩子能否收到事件
                          + 前台窗口**序列**（判断"点了目标程序但它没拿到前台"）
      S6 引擎 hook 探针 —— 主动复现：GetKeyboardState / SetWindowsHookEx /
                          RegisterRawInputDevices 是否被引擎 hook 吞掉（err=5 即铁证）
      S7 残留 hook / 持久化注入点审计
      S8 结论          —— H1~H16 逐条判定 + 最可能根因排序 + 处置阶梯

    设计要点
    --------
    * 全部探测均为「读」或「自进程内可逆操作」，不发送合成输入（除非显式 -InjectTest）。
    * 本脚本进程是 powershell.exe，**不在**引擎 bypass 白名单（白名单只列 System32 下
      35 个具体镜像）⇒ 引擎在跑且 hook_input=1 时，本进程会被注入，
      S6 的探针即可直接观察到引擎 hook 的行为。
    * 报告文件用 UTF-8 with BOM 写（PS 5.1 无 BOM 会按 GBK 解码导致中文乱码）；
      控制台输出保持纯 ASCII，避免不同代码页下乱码。

    用法
    ----
      powershell -NoProfile -ExecutionPolicy Bypass -File tools\diag-input-focus.ps1
      powershell ... -File tools\diag-input-focus.ps1 -SkipInteractive     # 不等待人工操作
      powershell ... -File tools\diag-input-focus.ps1 -WatchSeconds 15    # 拉长观察窗
      powershell ... -File tools\diag-input-focus.ps1 -TargetApp notepad  # ★ 盯着目标程序看

    ★ 关于 -TargetApp（强烈建议用）
    ------------------------------
      前两次采集都没抓到症状，原因不是脚本测得少，而是**测错了对象**：
      脚本自己开在 cmd.exe 里跑，前台窗口就是那个控制台，于是
        · H4「前台无键盘焦点」稳定命中 —— 但那是控制台窗口的正常现象（conhost 代管输入）；
        · 光标采样落在 MyApp / 控制台上，而不是出问题的那个程序上。
      用 -TargetApp 指定出问题的程序（进程名或 pid），脚本会额外做一节「目标程序专项」：
      列出它的所有窗口、逐个查 GetGUIThreadInfo、查它的 band、查它是否卡死、
      并在观察窗内**只统计目标程序的前台/焦点变化**，从根上避免"测错对象"。

    参数
    ----
      -TargetApp <string>      ★ 出问题的程序：进程名（可省 .exe，如 notepad）或 pid。
                                 给了它才会做 S2.5「目标程序专项」。
      -WatchSeconds <int>      被动观察窗（秒），期间请移动鼠标/点击输入框/按键。0 = 跳过。默认 8
      -HookProbeSeconds <int>  装低级键鼠钩子并泵消息的时长（秒），期间请按键/动鼠标。默认 6
      -SkipInteractive         等价于上面两个都置 0
      -SkipHookProbe           只跳过 S6 的 hook 行为探针（S5 的钩子计数仍会做）
      -InjectTest              额外做一次合成输入自测（会真的动鼠标/按键，默认关）
      -OutDir <path>           报告输出目录，默认 <仓库根>\tools\_probe_results
#>
[CmdletBinding()]
param(
    [string]$TargetApp = "",
    [int]$WatchSeconds = 8,
    [int]$HookProbeSeconds = 6,
    [switch]$SkipInteractive,
    [switch]$SkipHookProbe,
    [switch]$InjectTest,
    [string]$OutDir = ""
)

$ErrorActionPreference = "Continue"
Set-StrictMode -Off

if ($SkipInteractive) { $WatchSeconds = 0; $HookProbeSeconds = 0 }

# ==================================================================
# 0. 基础设施
# ==================================================================

$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) { $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
$RepoRoot  = Split-Path -Parent $ScriptDir
if (-not $OutDir -or $OutDir -eq "") { $OutDir = Join-Path $ScriptDir "_probe_results" }

$ReportLines = New-Object System.Collections.Generic.List[string]
$Fact = [ordered]@{}

function L {
    param([string]$Text = "")
    $ReportLines.Add($Text) | Out-Null
}

function Sec {
    param([string]$Title)
    L ""
    L ("=" * 78)
    L ("【" + $Title + "】")
    L ("=" * 78)
}

function KV {
    param([string]$Key, $Value)
    L ("  " + $Key.PadRight(26) + " : " + $Value)
}

function Note {
    param([string]$Text)
    L ("  · " + $Text)
}

# 判定表：id -> @(名称, 状态, 证据)
$Verdicts = New-Object System.Collections.Generic.List[object]
function Verdict {
    param([string]$Id, [string]$Name, [string]$State, [string]$Evidence)
    $Verdicts.Add([pscustomobject]@{ Id = $Id; Name = $Name; State = $State; Evidence = $Evidence }) | Out-Null
}

# ==================================================================
# 1. P/Invoke
# ==================================================================

$cs = @'
using System;
using System.Text;
using System.Runtime.InteropServices;

public static class W
{
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
    [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X; public int Y; }
    [StructLayout(LayoutKind.Sequential)] public struct CURSORINFO { public int cbSize; public int flags; public IntPtr hCursor; public POINT ptScreenPos; }
    [StructLayout(LayoutKind.Sequential)] public struct GUITHREADINFO
    {
        public int cbSize; public int flags;
        public IntPtr hwndActive; public IntPtr hwndFocus; public IntPtr hwndCapture;
        public IntPtr hwndMenuOwner; public IntPtr hwndMoveSize; public IntPtr hwndCaret;
        public RECT rcCaret;
    }
    [StructLayout(LayoutKind.Sequential)] public struct LASTINPUTINFO { public int cbSize; public int dwTime; }
    [StructLayout(LayoutKind.Sequential)] public struct FILTERKEYS { public int cbSize; public int dwFlags; public int iWaitMSec; public int iDelayMSec; public int iRepeatMSec; public int iBounceMSec; }
    // ⚠️ STICKYKEYS / TOGGLEKEYS 只有 cbSize + dwFlags 两个 DWORD（8 字节）。
    //    曾误用 FILTERKEYS(20 字节) 传 cbSize ⇒ SystemParametersInfo 直接失败返回 -1。
    [StructLayout(LayoutKind.Sequential)] public struct STICKYKEYS { public int cbSize; public int dwFlags; }
    [StructLayout(LayoutKind.Sequential)] public struct TOGGLEKEYS { public int cbSize; public int dwFlags; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WNDCLASSEXW
    {
        public int cbSize; public uint style; public IntPtr lpfnWndProc;
        public int cbClsExtra; public int cbWndExtra; public IntPtr hInstance;
        public IntPtr hIcon; public IntPtr hCursor; public IntPtr hbrBackground;
        [MarshalAs(UnmanagedType.LPWStr)] public string lpszMenuName;
        [MarshalAs(UnmanagedType.LPWStr)] public string lpszClassName;
        public IntPtr hIconSm;
    }
    [StructLayout(LayoutKind.Sequential)] public struct RAWINPUTDEVICE { public ushort usUsagePage; public ushort usUsage; public uint dwFlags; public IntPtr hwndTarget; }
    [StructLayout(LayoutKind.Sequential)] public struct MSG { public IntPtr hwnd; public uint message; public IntPtr wParam; public IntPtr lParam; public uint time; public POINT pt; }

    public delegate bool EnumProc(IntPtr hwnd, IntPtr lParam);
    public delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);
    public delegate IntPtr WndProcDelegate(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr GetModuleHandleW(string name);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern ushort RegisterClassExW(ref WNDCLASSEXW wc);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern IntPtr CreateWindowExW(uint exStyle, string cls, string title, uint style, int x, int y, int w, int h, IntPtr parent, IntPtr menu, IntPtr inst, IntPtr param);
    [DllImport("user32.dll", EntryPoint = "DefWindowProcW")] public static extern IntPtr DefWindowProc(IntPtr h, uint m, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] public static extern bool DestroyWindow(IntPtr h);

    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern IntPtr GetFocus();
    [DllImport("user32.dll")] public static extern IntPtr GetCapture();
    [DllImport("user32.dll")] public static extern IntPtr WindowFromPoint(POINT p);
    [DllImport("user32.dll")] public static extern IntPtr GetAncestor(IntPtr h, uint flags);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
    [DllImport("user32.dll")] public static extern bool IsHungAppWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr h);
    [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW")] public static extern IntPtr GetWindowLongPtr(IntPtr h, int idx);
    [DllImport("user32.dll", EntryPoint = "GetClassLongPtrW")] public static extern IntPtr GetClassLongPtr(IntPtr h, int idx);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
    // user32!GetWindowBand —— 未文档化导出（Win7+ 都有）。实测本机存在且可调用。
    // ★ 为什么必须看 band 而不能只看 WS_EX_TOPMOST：
    //   SetWindowBand 是「超级置顶」把窗口抬进 UIAccess 波段的唯一手段，而实测
    //   SetWindowBand 在**没有 UIAccess 令牌**时一律失败（err=5 / err=87，见 tools/bandprobe.cpp）。
    //   ⇒ 「存在 band != 1 的可见窗口」几乎等价于「某个 UIAccess 进程留下了窗口」，
    //     在本项目里这个进程只可能是超级置顶拉起的那个 SYSTEM+UIAccess 子实例。
    //   实测：普通窗口 band = 1（不是 0），所以判据是「band != 1」。
    [DllImport("user32.dll", SetLastError = true)] public static extern bool GetWindowBand(IntPtr h, out uint band);
    [DllImport("user32.dll")] public static extern bool GetGUIThreadInfo(uint tid, ref GUITHREADINFO gti);
    [DllImport("user32.dll")] public static extern bool GetCursorInfo(ref CURSORINFO ci);
    [DllImport("user32.dll")] public static extern bool GetCursorPos(out POINT p);
    [DllImport("user32.dll")] public static extern IntPtr GetCursor();
    [DllImport("user32.dll")] public static extern IntPtr LoadCursor(IntPtr inst, IntPtr name);
    [DllImport("user32.dll")] public static extern bool GetClipCursor(out RECT r);
    [DllImport("user32.dll")] public static extern bool GetLastInputInfo(ref LASTINPUTINFO li);
    [DllImport("user32.dll", SetLastError = true)] public static extern bool GetKeyboardState(byte[] keys);
    [DllImport("user32.dll", SetLastError = true)] public static extern short GetKeyState(int vk);
    [DllImport("user32.dll", SetLastError = true)] public static extern short GetAsyncKeyState(int vk);
    // ⚠️ 必须声明成 IntPtr：HKL 是句柄。写成 int 后在 .NET Framework（Windows PowerShell 5.1）
    //    下 Add-Type 会直接编译失败（int→IntPtr 无隐式转换）；只有 .NET 7+ 的 nint 才隐式可转。
    [DllImport("user32.dll")] public static extern IntPtr GetKeyboardLayout(uint tid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetKeyboardLayoutName(StringBuilder s);
    [DllImport("user32.dll", SetLastError = true)] public static extern IntPtr SetWindowsHookEx(int idHook, HookProc lpfn, IntPtr hmod, uint tid);
    [DllImport("user32.dll", SetLastError = true)] public static extern bool UnhookWindowsHookEx(IntPtr h);
    [DllImport("user32.dll")] public static extern IntPtr CallNextHookEx(IntPtr h, int code, IntPtr w, IntPtr l);
    [DllImport("user32.dll", SetLastError = true)] public static extern bool RegisterRawInputDevices(RAWINPUTDEVICE[] d, uint n, uint sz);
    [DllImport("user32.dll", SetLastError = true)] public static extern bool SystemParametersInfo(uint a, uint b, ref FILTERKEYS p, uint f);
    [DllImport("user32.dll", EntryPoint = "SystemParametersInfoW", SetLastError = true)] public static extern bool SystemParametersInfoSticky(uint a, uint b, ref STICKYKEYS p, uint f);
    [DllImport("user32.dll", EntryPoint = "SystemParametersInfoW", SetLastError = true)] public static extern bool SystemParametersInfoToggle(uint a, uint b, ref TOGGLEKEYS p, uint f);
    [DllImport("user32.dll")] public static extern int GetSystemMetrics(int i);
    [DllImport("user32.dll")] public static extern bool PeekMessage(out MSG m, IntPtr h, uint a, uint b, uint r);
    [DllImport("user32.dll")] public static extern bool TranslateMessage(ref MSG m);
    [DllImport("user32.dll")] public static extern IntPtr DispatchMessage(ref MSG m);
    [DllImport("user32.dll", SetLastError = true)] public static extern IntPtr SendMessageTimeout(IntPtr h, uint msg, IntPtr w, IntPtr l, uint flags, uint timeout, out IntPtr res);
    [DllImport("user32.dll", SetLastError = true)] public static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint access);
    [DllImport("user32.dll", SetLastError = true)] public static extern bool CloseDesktop(IntPtr h);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern bool GetUserObjectInformation(IntPtr h, int idx, StringBuilder info, int len, out int needed);
    [DllImport("user32.dll", SetLastError = true)] public static extern IntPtr GetThreadDesktop(uint tid);
    [DllImport("user32.dll")] public static extern IntPtr GetDesktopWindow();
    [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("kernel32.dll")] public static extern bool ProcessIdToSessionId(uint pid, out uint sid);
    [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();

    // ---- 常量 ----
    public const int GWL_STYLE = -16;
    public const int GWL_EXSTYLE = -20;
    public const int GCLP_HCURSOR = -34;

    public const long WS_DISABLED = 0x08000000L;
    public const long WS_VISIBLE = 0x10000000L;

    public const long WS_EX_TOPMOST = 0x00000008L;
    public const long WS_EX_TRANSPARENT = 0x00000020L;
    public const long WS_EX_TOOLWINDOW = 0x00000080L;
    public const long WS_EX_LAYERED = 0x00080000L;
    public const long WS_EX_NOACTIVATE = 0x08000000L;
    public const long WS_EX_APPWINDOW = 0x00040000L;
    public const long WS_EX_NOREDIRECTIONBITMAP = 0x00200000L;

    public const int IDC_ARROW = 32512;
    public const int IDC_IBEAM = 32513;
    public const int IDC_WAIT = 32514;
    public const int IDC_CROSS = 32515;
    public const int IDC_UPARROW = 32516;
    public const int IDC_SIZENWSE = 32642;
    public const int IDC_SIZENESW = 32643;
    public const int IDC_SIZEWE = 32644;
    public const int IDC_SIZENS = 32645;
    public const int IDC_SIZEALL = 32646;
    public const int IDC_NO = 32648;
    public const int IDC_HAND = 32649;
    public const int IDC_APPSTARTING = 32650;
    public const int IDC_HELP = 32651;

    public const uint CURSOR_SHOWING = 0x00000001;
    public const uint CURSOR_SUPPRESSED = 0x00000002;

    public const uint SMTO_ABORTIFHUNG = 0x0002;
    public const uint SMTO_BLOCK = 0x0001;
    public const uint PM_REMOVE = 0x0001;

    public const uint DESKTOP_READOBJECTS = 0x0001;
    public const int UOI_NAME = 2;
    public const int UOI_FLAGS = 1;

    public const int WH_KEYBOARD = 2;
    public const int WH_KEYBOARD_LL = 13;
    public const int WH_MOUSE_LL = 14;

    public const uint RIDEV_REMOVE = 0x00000001;
    public const uint RIDEV_INPUTSINK = 0x00000100;

    public const uint SPI_GETFILTERKEYS = 0x0032;
    public const uint SPI_GETSTICKYKEYS = 0x003A;
    public const uint SPI_GETTOGGLEKEYS = 0x0034;

    public static string ClassName(IntPtr h)
    {
        StringBuilder sb = new StringBuilder(256);
        GetClassName(h, sb, sb.Capacity);
        return sb.ToString();
    }

    public static string Title(IntPtr h)
    {
        StringBuilder sb = new StringBuilder(512);
        GetWindowText(h, sb, sb.Capacity);
        string s = sb.ToString();
        if (s.Length > 60) { s = s.Substring(0, 60) + "..."; }
        return s;
    }

    public static string CursorName(IntPtr hCursor)
    {
        int[] ids = new int[] { IDC_ARROW, IDC_IBEAM, IDC_WAIT, IDC_CROSS, IDC_UPARROW,
            IDC_SIZENWSE, IDC_SIZENESW, IDC_SIZEWE, IDC_SIZENS, IDC_SIZEALL,
            IDC_NO, IDC_HAND, IDC_APPSTARTING, IDC_HELP };
        string[] names = new string[] { "IDC_ARROW(箭头)", "IDC_IBEAM(文本I型)", "IDC_WAIT(忙)", "IDC_CROSS(十字)",
            "IDC_UPARROW(上箭头)", "IDC_SIZENWSE", "IDC_SIZENESW", "IDC_SIZEWE(左右)", "IDC_SIZENS(上下)",
            "IDC_SIZEALL(移动)", "IDC_NO(禁止)", "IDC_HAND(手/点击)", "IDC_APPSTARTING(后台忙)", "IDC_HELP" };
        for (int i = 0; i < ids.Length; i++)
        {
            IntPtr std = LoadCursor(IntPtr.Zero, new IntPtr(ids[i]));
            if (std != IntPtr.Zero && std == hCursor) { return names[i]; }
        }
        if (hCursor == IntPtr.Zero) { return "(空句柄)"; }
        return "非标准光标/自定义(h=" + hCursor.ToInt64().ToString("X") + ")";
    }

    public static string ExStyleText(long ex)
    {
        StringBuilder sb = new StringBuilder();
        if ((ex & WS_EX_TOPMOST) != 0) { sb.Append("TOPMOST|"); }
        if ((ex & WS_EX_LAYERED) != 0) { sb.Append("LAYERED|"); }
        if ((ex & WS_EX_TRANSPARENT) != 0) { sb.Append("CLICK-THROUGH|"); }
        if ((ex & WS_EX_NOACTIVATE) != 0) { sb.Append("NOACTIVATE|"); }
        if ((ex & WS_EX_TOOLWINDOW) != 0) { sb.Append("TOOLWINDOW|"); }
        if ((ex & WS_EX_APPWINDOW) != 0) { sb.Append("APPWINDOW|"); }
        if ((ex & WS_EX_NOREDIRECTIONBITMAP) != 0) { sb.Append("NOREDIRECTIONBITMAP|"); }
        string s = sb.ToString();
        if (s.EndsWith("|")) { s = s.Substring(0, s.Length - 1); }
        return s;
    }

    // 窗口所在 band。普通窗口 = 1；band 2 = UIAccess 波段（超级置顶的落点）。
    // GetWindowBand 是未文档化导出，老系统上可能没有 —— 失败一律返回 -1（"读不到"），
    // 绝不返回 1，否则会把"读不到"误判成"正常"。
    public static int BandOf(IntPtr h)
    {
        try {
            uint band = 0;
            if (GetWindowBand(h, out band)) { return (int)band; }
            return -1;
        } catch { return -1; }
    }

    // 某个 pid 的顶层窗口概况：总数|可见数|最小化数|首个窗口类名|首个窗口标题
    public static string WindowsOfProcess(uint pid)
    {
        int total = 0, visible = 0, iconic = 0;
        string firstClass = "", firstTitle = "";
        string[] recs = EnumTopWindows();
        for (int i = 0; i < recs.Length; i++)
        {
            string[] f = recs[i].Split('|');
            if (f.Length < 5) { continue; }
            if (f[1] != pid.ToString()) { continue; }
            total++;
            if (f[7] == "1") { visible++; }
            IntPtr h = new IntPtr(long.Parse(f[0]));
            if (IsIconic(h)) { iconic++; }
            if (firstClass.Length == 0) { firstClass = f[3]; firstTitle = f[4]; }
        }
        return total + "|" + visible + "|" + iconic + "|" + firstClass + "|" + firstTitle;
    }

    // hwnd|pid|tid|class|title|style|exstyle|vis|en|hung|left|top|right|bottom|band
    // ★ band 加在**末尾**：前面的下标（$f[0]..$f[13]）全部保持不变，避免改坏既有判据。
    public static string WindowRecord(IntPtr hwnd)
    {
        uint pid = 0;
        uint tid = GetWindowThreadProcessId(hwnd, out pid);
        long style = GetWindowLongPtr(hwnd, GWL_STYLE).ToInt64();
        long ex = GetWindowLongPtr(hwnd, GWL_EXSTYLE).ToInt64();
        RECT rc = new RECT();
        GetWindowRect(hwnd, out rc);
        return string.Join("|", new string[] {
            hwnd.ToInt64().ToString(),
            pid.ToString(),
            tid.ToString(),
            ClassName(hwnd),
            Title(hwnd),
            "0x" + style.ToString("X"),
            "0x" + ex.ToString("X"),
            IsWindowVisible(hwnd) ? "1" : "0",
            IsWindowEnabled(hwnd) ? "1" : "0",
            IsHungAppWindow(hwnd) ? "1" : "0",
            rc.Left.ToString(), rc.Top.ToString(), rc.Right.ToString(), rc.Bottom.ToString(),
            BandOf(hwnd).ToString()
        });
    }

    public static string[] EnumTopWindows()
    {
        System.Collections.Generic.List<string> list = new System.Collections.Generic.List<string>();
        EnumWindows(delegate(IntPtr hwnd, IntPtr lp) {
            try { list.Add(WindowRecord(hwnd)); } catch { }
            return true;
        }, IntPtr.Zero);
        return list.ToArray();
    }

    // active|focus|capture|menuowner|movesize|caret|rcCaret|ok
    public static string GuiThreadInfo(uint tid)
    {
        GUITHREADINFO g = new GUITHREADINFO();
        g.cbSize = Marshal.SizeOf(typeof(GUITHREADINFO));
        bool ok = GetGUIThreadInfo(tid, ref g);
        return string.Join("|", new string[] {
            g.hwndActive.ToInt64().ToString(),
            g.hwndFocus.ToInt64().ToString(),
            g.hwndCapture.ToInt64().ToString(),
            g.hwndMenuOwner.ToInt64().ToString(),
            g.hwndMoveSize.ToInt64().ToString(),
            g.hwndCaret.ToInt64().ToString(),
            g.rcCaret.Left.ToString() + "," + g.rcCaret.Top.ToString(),
            ok ? "1" : "0"
        });
    }

    public static string DesktopNameOf(IntPtr hDesk)
    {
        if (hDesk == IntPtr.Zero) { return "(null)"; }
        StringBuilder sb = new StringBuilder(256);
        int needed = 0;
        if (GetUserObjectInformation(hDesk, UOI_NAME, sb, sb.Capacity * 2, out needed)) { return sb.ToString(); }
        return "(读取失败 err=" + Marshal.GetLastWin32Error().ToString() + ")";
    }

    // 输入桌面名|输入桌面句柄是否拿到|本线程桌面名
    public static string DesktopState()
    {
        IntPtr inDesk = OpenInputDesktop(0, false, DESKTOP_READOBJECTS);
        int err = Marshal.GetLastWin32Error();
        string inName;
        if (inDesk == IntPtr.Zero) { inName = "(OpenInputDesktop 失败 err=" + err.ToString() + ")"; }
        else { inName = DesktopNameOf(inDesk); CloseDesktop(inDesk); }
        IntPtr thDesk = GetThreadDesktop(GetCurrentThreadId());
        string thName = DesktopNameOf(thDesk);
        return inName + "|" + thName;
    }

    // 单次采样：fgHwnd|fgPid|fgTid|curFlags|hCursor|cx|cy|underHwnd|underPid|underClass|lastInput|now
    public static string SampleState()
    {
        IntPtr fg = GetForegroundWindow();
        uint fgPid = 0; uint fgTid = 0;
        if (fg != IntPtr.Zero) { fgTid = GetWindowThreadProcessId(fg, out fgPid); }
        CURSORINFO ci = new CURSORINFO();
        ci.cbSize = Marshal.SizeOf(typeof(CURSORINFO));
        GetCursorInfo(ref ci);
        POINT pt = new POINT();
        GetCursorPos(out pt);
        POINT hitPt = pt;
        IntPtr under = WindowFromPoint(hitPt);
        uint uPid = 0;
        if (under != IntPtr.Zero) { GetWindowThreadProcessId(under, out uPid); }
        LASTINPUTINFO li = new LASTINPUTINFO();
        li.cbSize = Marshal.SizeOf(typeof(LASTINPUTINFO));
        GetLastInputInfo(ref li);
        return string.Join("|", new string[] {
            fg.ToInt64().ToString(), fgPid.ToString(), fgTid.ToString(),
            ci.flags.ToString(), ci.hCursor.ToInt64().ToString(),
            pt.X.ToString(), pt.Y.ToString(),
            under.ToInt64().ToString(), uPid.ToString(), ClassName(under),
            li.dwTime.ToString(), Environment.TickCount.ToString()
        });
    }

    // 光标 + 光标下窗口 + 类光标 + 裁剪矩形
    public static string CursorState()
    {
        CURSORINFO ci = new CURSORINFO();
        ci.cbSize = Marshal.SizeOf(typeof(CURSORINFO));
        GetCursorInfo(ref ci);
        POINT pt = new POINT();
        GetCursorPos(out pt);
        POINT hit = pt;
        IntPtr under = WindowFromPoint(hit);
        IntPtr underRoot = GetAncestor(under, 2 /*GA_ROOT*/);
        uint uPid = 0;
        if (under != IntPtr.Zero) { GetWindowThreadProcessId(under, out uPid); }
        long clsCur = under != IntPtr.Zero ? GetClassLongPtr(under, GCLP_HCURSOR).ToInt64() : 0;
        RECT clip = new RECT();
        GetClipCursor(out clip);
        IntPtr thCur = GetCursor();
        return string.Join("|", new string[] {
            ci.flags.ToString(),
            ci.hCursor.ToInt64().ToString(),
            CursorName(ci.hCursor),
            pt.X.ToString(), pt.Y.ToString(),
            under.ToInt64().ToString(),
            uPid.ToString(),
            ClassName(under),
            Title(under),
            underRoot.ToInt64().ToString(),
            clsCur.ToString(),
            clsCur != 0 ? CursorName(new IntPtr(clsCur)) : "(无类光标)",
            clip.Left + "," + clip.Top + "," + clip.Right + "," + clip.Bottom,
            thCur.ToInt64().ToString(),
            (GetWindowLongPtr(under, GWL_EXSTYLE).ToInt64() & WS_EX_TRANSPARENT) != 0 ? "1" : "0",
            (GetWindowLongPtr(under, GWL_EXSTYLE).ToInt64() & WS_EX_LAYERED) != 0 ? "1" : "0"
        });
    }

    // 是否卡死：IsHung + SendMessageTimeout(WM_NULL)
    public static string HungProbe(IntPtr hwnd)
    {
        if (hwnd == IntPtr.Zero || !IsWindow(hwnd)) { return "no-window"; }
        bool hung = IsHungAppWindow(hwnd);
        IntPtr res = IntPtr.Zero;
        IntPtr rc = SendMessageTimeout(hwnd, 0 /*WM_NULL*/, IntPtr.Zero, IntPtr.Zero,
            SMTO_ABORTIFHUNG | SMTO_BLOCK, 1200, out res);
        int err = Marshal.GetLastWin32Error();
        return "IsHungAppWindow=" + (hung ? "1" : "0") + ";SendMessageTimeout=" + (rc != IntPtr.Zero ? "ok" : ("timeout err=" + err));
    }

    public static string AccessibilityState()
    {
        FILTERKEYS fk = new FILTERKEYS();
        fk.cbSize = Marshal.SizeOf(typeof(FILTERKEYS));
        bool ok = SystemParametersInfo(SPI_GETFILTERKEYS, (uint)fk.cbSize, ref fk, 0);
        STICKYKEYS sk = new STICKYKEYS();
        sk.cbSize = Marshal.SizeOf(typeof(STICKYKEYS));
        bool ok2 = SystemParametersInfoSticky(SPI_GETSTICKYKEYS, (uint)sk.cbSize, ref sk, 0);
        TOGGLEKEYS tk = new TOGGLEKEYS();
        tk.cbSize = Marshal.SizeOf(typeof(TOGGLEKEYS));
        bool ok3 = SystemParametersInfoToggle(SPI_GETTOGGLEKEYS, (uint)tk.cbSize, ref tk, 0);
        return "FilterKeys ok=" + (ok ? "1" : "0") + " flags=0x" + fk.dwFlags.ToString("X") +
               " wait=" + fk.iWaitMSec + " delay=" + fk.iDelayMSec + " repeat=" + fk.iRepeatMSec + " bounce=" + fk.iBounceMSec +
               " ;StickyKeys ok=" + (ok2 ? "1" : "0") + " flags=0x" + sk.dwFlags.ToString("X") +
               " ;ToggleKeys ok=" + (ok3 ? "1" : "0") + " flags=0x" + tk.dwFlags.ToString("X");
    }

    // FKF_FILTERKEYSON = 0x1 / SKF_STICKYKEYSON = 0x1：只看 bit0，别被 AVAILABLE|HOTKEYSOUND 等常驻位误导
    public static int FilterKeysActive()
    {
        FILTERKEYS fk = new FILTERKEYS();
        fk.cbSize = Marshal.SizeOf(typeof(FILTERKEYS));
        if (!SystemParametersInfo(SPI_GETFILTERKEYS, (uint)fk.cbSize, ref fk, 0)) { return -1; }
        return (fk.dwFlags & 0x1) != 0 ? 1 : 0;
    }

    public static int StickyKeysActive()
    {
        STICKYKEYS sk = new STICKYKEYS();
        sk.cbSize = Marshal.SizeOf(typeof(STICKYKEYS));
        if (!SystemParametersInfoSticky(SPI_GETSTICKYKEYS, (uint)sk.cbSize, ref sk, 0)) { return -1; }
        return (sk.dwFlags & 0x1) != 0 ? 1 : 0;
    }

    public static string LayoutState()
    {
        IntPtr hkl = GetKeyboardLayout(GetCurrentThreadId());
        StringBuilder sb = new StringBuilder(16);
        GetKeyboardLayoutName(sb);
        return "HKL=0x" + hkl.ToInt64().ToString("X") + " name=" + sb.ToString() +
               " (hkl低16位=语言ID 0x" + ((hkl.ToInt64()) & 0xFFFF).ToString("X") + ")";
    }
}

// ==================================================================
// 输入钩子探针：装低级键鼠钩子并计数（仅本进程，用完即卸）
// ==================================================================
public static class HookProbe
{
    public static int KbCount = 0, MsCount = 0, KbInjected = 0, MsInjected = 0;
    public static int LastVk = -1, LastVkFlags = 0, LastMsFlags = 0;
    static W.HookProc kbProc = null, msProc = null;
    static IntPtr kbHook = IntPtr.Zero, msHook = IntPtr.Zero;

    static IntPtr KbCallback(int code, IntPtr w, IntPtr l)
    {
        if (code == 0)
        {
            KbCount++;
            if (l != IntPtr.Zero)
            {
                LastVk = Marshal.ReadInt32(l, 0);
                LastVkFlags = Marshal.ReadInt32(l, 8);
                if ((LastVkFlags & 0x10) != 0) { KbInjected++; }
            }
        }
        return W.CallNextHookEx(kbHook, code, w, l);
    }

    static IntPtr MsCallback(int code, IntPtr w, IntPtr l)
    {
        if (code == 0)
        {
            MsCount++;
            if (l != IntPtr.Zero)
            {
                LastMsFlags = Marshal.ReadInt32(l, 12);
                if ((LastMsFlags & 0x01) != 0) { MsInjected++; }
            }
        }
        return W.CallNextHookEx(msHook, code, w, l);
    }

    public static string Install()
    {
        kbProc = new W.HookProc(KbCallback);
        msProc = new W.HookProc(MsCallback);
        kbHook = W.SetWindowsHookEx(W.WH_KEYBOARD_LL, kbProc, IntPtr.Zero, 0);
        int e1 = Marshal.GetLastWin32Error();
        msHook = W.SetWindowsHookEx(W.WH_MOUSE_LL, msProc, IntPtr.Zero, 0);
        int e2 = Marshal.GetLastWin32Error();
        return "WH_KEYBOARD_LL=" + (kbHook != IntPtr.Zero ? "OK" : ("FAIL err=" + e1)) +
               ";WH_MOUSE_LL=" + (msHook != IntPtr.Zero ? "OK" : ("FAIL err=" + e2));
    }

    public static string Uninstall()
    {
        if (kbHook != IntPtr.Zero) { W.UnhookWindowsHookEx(kbHook); kbHook = IntPtr.Zero; }
        if (msHook != IntPtr.Zero) { W.UnhookWindowsHookEx(msHook); msHook = IntPtr.Zero; }
        return "unhooked";
    }

    public static string Stats()
    {
        return "kb=" + KbCount + " (injected=" + KbInjected + ") ms=" + MsCount + " (injected=" + MsInjected + ")" +
               " lastVk=0x" + LastVk.ToString("X") + " lastVkFlags=0x" + LastVkFlags.ToString("X");
    }
}

// ==================================================================
// 消息专用窗口（HWND_MESSAGE）：给 RegisterRawInputDevices 当 hwndTarget 用
// ==================================================================
public static class HiddenWin
{
    static W.WndProcDelegate proc = null;
    static IntPtr hwnd = IntPtr.Zero;
    static bool registered = false;

    public static IntPtr Get()
    {
        if (hwnd != IntPtr.Zero) { return hwnd; }
        IntPtr inst = W.GetModuleHandleW(null);
        if (!registered)
        {
            proc = new W.WndProcDelegate(delegate(IntPtr h, uint m, IntPtr wp, IntPtr lp) {
                return W.DefWindowProc(h, m, wp, lp);
            });
            W.WNDCLASSEXW wc = new W.WNDCLASSEXW();
            wc.cbSize = Marshal.SizeOf(typeof(W.WNDCLASSEXW));
            wc.lpfnWndProc = Marshal.GetFunctionPointerForDelegate(proc);
            wc.hInstance = inst;
            wc.lpszClassName = "R3ShieldCoreDiagMsgWin";
            if (W.RegisterClassExW(ref wc) == 0)
            {
                // 类可能已存在（重复注册），继续尝试建窗
            }
            registered = true;
        }
        hwnd = W.CreateWindowExW(0, "R3ShieldCoreDiagMsgWin", "", 0, 0, 0, 0, 0,
            new IntPtr(-3) /*HWND_MESSAGE*/, IntPtr.Zero, inst, IntPtr.Zero);
        return hwnd;
    }
}

// ==================================================================
// 引擎 hook 行为探针（主动复现）
// ==================================================================
public static class HookBehavior
{
    // 在 <100ms 内连调 GetKeyboardState，观察是否被"密度判据"拦成 FALSE
    // 正常：全部返回 TRUE；被引擎 hook 吞掉：第 61 次左右开始返回 FALSE 且 err=5
    public static string KeyboardStateProbe()
    {
        byte[] buf = new byte[256];
        bool first = W.GetKeyboardState(buf);
        // ⚠️ 只在失败时才读 LastWin32Error：成功时它是"上一次的残留值"，
        //    .NET Framework(PS 5.1) 下会读出 203 这种无关错误，误报成"被拒"。
        int firstErr = first ? 0 : Marshal.GetLastWin32Error();

        int tripAt = -1;
        int falseCount = 0;
        int tripErr = 0;
        int msAtTrip = -1;
        System.Diagnostics.Stopwatch sw = System.Diagnostics.Stopwatch.StartNew();
        for (int i = 2; i <= 200; i++)
        {
            bool ok = W.GetKeyboardState(buf);
            if (!ok)
            {
                falseCount++;
                if (tripAt < 0)
                {
                    tripAt = i;
                    tripErr = Marshal.GetLastWin32Error();
                    msAtTrip = (int)sw.ElapsedMilliseconds;   // ★ 这一笔就是"调用方线程被冻住多久"
                }
            }
        }
        long ms = sw.ElapsedMilliseconds;

        // 冷却 3s 之后再打一次，看是否恢复；同时量这一笔的耗时
        System.Threading.Thread.Sleep(3200);
        System.Diagnostics.Stopwatch sw2 = System.Diagnostics.Stopwatch.StartNew();
        bool afterCooldown = W.GetKeyboardState(buf);
        int afterErr = afterCooldown ? 0 : Marshal.GetLastWin32Error();
        long msAfter = sw2.ElapsedMilliseconds;

        return "first=" + (first ? "TRUE" : "FALSE") + "(err=" + firstErr + ")" +
               ";tripAtCall=" + (tripAt < 0 ? "never" : tripAt.ToString()) +
               ";falseCount=" + falseCount + "/199" +
               ";tripErr=" + tripErr +
               ";msAtTrip=" + msAtTrip +
               ";loopMs=" + ms +
               ";after3sCooldown=" + (afterCooldown ? "TRUE" : "FALSE") + "(err=" + afterErr + ",ms=" + msAfter + ")";
    }

    // SetWindowsHookEx 探针：全局低级键盘钩子 + 本线程键盘钩子
    public static string SetHookProbe()
    {
        W.HookProc p1 = new W.HookProc(Noop);
        W.HookProc p2 = new W.HookProc(Noop);
        IntPtr h1 = W.SetWindowsHookEx(W.WH_KEYBOARD_LL, p1, IntPtr.Zero, 0);
        int e1 = Marshal.GetLastWin32Error();
        if (h1 != IntPtr.Zero) { W.UnhookWindowsHookEx(h1); }
        IntPtr h2 = W.SetWindowsHookEx(W.WH_KEYBOARD, p2, IntPtr.Zero, W.GetCurrentThreadId());
        int e2 = Marshal.GetLastWin32Error();
        if (h2 != IntPtr.Zero) { W.UnhookWindowsHookEx(h2); }
        GC.KeepAlive(p1); GC.KeepAlive(p2);
        return "WH_KEYBOARD_LL(全局)=" + (h1 != IntPtr.Zero ? "OK" : ("FAIL err=" + e1)) +
               ";WH_KEYBOARD(本线程)=" + (h2 != IntPtr.Zero ? "OK" : ("FAIL err=" + e2));
    }

    static IntPtr Noop(int code, IntPtr w, IntPtr l) { return W.CallNextHookEx(IntPtr.Zero, code, w, l); }

    // RegisterRawInputDevices 探针：注册 RIDEV_INPUTSINK 键盘（高危判据），随即撤销
    // ⚠️ RIDEV_INPUTSINK 要求 hwndTarget 是**本进程的有效窗口**（用桌面窗口会 err=87），
    //    所以这里自建一个 HWND_MESSAGE 消息专用窗口当靶子，不干扰任何程序。
    public static string RawInputProbe()
    {
        IntPtr target = HiddenWin.Get();
        string tgtDesc = "msgwin";
        if (target == IntPtr.Zero)
        {
            target = W.GetDesktopWindow();
            tgtDesc = "desktop(回退)";
        }
        W.RAWINPUTDEVICE[] d = new W.RAWINPUTDEVICE[1];
        d[0].usUsagePage = 1;
        d[0].usUsage = 6;
        d[0].dwFlags = W.RIDEV_INPUTSINK;
        d[0].hwndTarget = target;
        bool ok = W.RegisterRawInputDevices(d, 1, (uint)Marshal.SizeOf(typeof(W.RAWINPUTDEVICE)));
        int err = Marshal.GetLastWin32Error();

        string removed = "n/a";
        if (ok)
        {
            W.RAWINPUTDEVICE[] r = new W.RAWINPUTDEVICE[1];
            r[0].usUsagePage = 1;
            r[0].usUsage = 6;
            r[0].dwFlags = W.RIDEV_REMOVE;
            r[0].hwndTarget = IntPtr.Zero;   // RIDEV_REMOVE 要求 hwndTarget 必须为 NULL，否则 err=87
            bool ok2 = W.RegisterRawInputDevices(r, 1, (uint)Marshal.SizeOf(typeof(W.RAWINPUTDEVICE)));
            removed = ok2 ? "OK" : ("FAIL err=" + Marshal.GetLastWin32Error());
        }
        return "RIDEV_INPUTSINK(键盘,target=" + tgtDesc + ")=" + (ok ? "OK" : ("FAIL err=" + err)) + ";撤销=" + removed;
    }
}
'@

try {
    Add-Type -TypeDefinition $cs -Language CSharp -ErrorAction Stop
}
catch {
    Write-Output ("Add-Type FAILED: " + $_.Exception.Message)
    exit 2
}

# ==================================================================
# 1.5 控制台开场横幅（双击启动时，用户全程只看到这个窗口）
# ==================================================================
# 说明：控制台文字一律用 ASCII，避免代码页不一致导致乱码；
#       中文说明只写进报告文件（UTF-8 with BOM）。
$consoleSec = [Math]::Max($WatchSeconds, $HookProbeSeconds)
Write-Output ""
Write-Output "============================================================"
Write-Output " R3ShieldCore  input / cursor  diagnostic      (READ-ONLY)"
Write-Output "============================================================"
if ($consoleSec -gt 0) {
    Write-Output (" Total run time is about " + ($consoleSec + 20) + " seconds.  Do NOT close this window.")
    Write-Output ""
    Write-Output (" [!] For the next " + $consoleSec + " seconds you MUST really use the mouse and keyboard:")
    Write-Output "       - click into the text box of the AFFECTED app"
    Write-Output "       - type a few keys, then move the mouse around"
    Write-Output "     Do NOT type into THIS console window -- it would measure the wrong app."
} else {
    Write-Output " Interactive sampling is skipped (-SkipInteractive)."
}
Write-Output "============================================================"
Write-Output ""

# ==================================================================
# 2. 采集
# ==================================================================

$Now      = Get-Date
$HostName = $env:COMPUTERNAME
$User     = "$env:USERDOMAIN\$env:USERNAME"
$IsAdmin  = $false
try {
    $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }
if (-not $IsAdmin) {
    Write-Output " [i] Not elevated: IFEO / service / task autostart audit will be partial."
    Write-Output "     (right-click the .bat -> Run as administrator for the full audit)"
    Write-Output ""
}

L "R3ShieldCore 输入失效 / 光标异常 诊断报告"
L ("生成时间 : " + $Now.ToString("yyyy-MM-dd HH:mm:ss"))
L ("主机/用户 : " + $HostName + " / " + $User + "  提权=" + ($(if ($IsAdmin) { "是" } else { "否（部分检查降级）" })))
L ("脚本/参数 : WatchSeconds=" + $WatchSeconds + " HookProbeSeconds=" + $HookProbeSeconds +
   " SkipHookProbe=" + [int]$SkipHookProbe.IsPresent + " InjectTest=" + [int]$InjectTest.IsPresent)

# ---------------- S0 环境基线 ----------------
Sec "S0 环境基线"

$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
if ($os) {
    KV "OS" ($os.Caption + " build " + $os.BuildNumber + " (" + $os.Version + ")")
    KV "OS 架构/启动时间" ($os.OSArchitecture + " / " + $os.LastBootUpTime)
}
$cv = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue
if ($cv) { KV "BuildLabEx" $cv.BuildLabEx }
KV "PowerShell" ($PSVersionTable.PSVersion.ToString() + " / 64位=" + [System.Environment]::Is64BitProcess)

$myPid = $PID
[uint32]$mySid = 0
[void][W]::ProcessIdToSessionId([uint32]$myPid, [ref]$mySid)
$consoleSid = [W]::WTSGetActiveConsoleSessionId()
KV "本进程 PID / 会话" ("$myPid / $mySid")
KV "活动控制台会话 ID" $consoleSid
if ($mySid -ne $consoleSid) {
    Note "⚠️ 本脚本不在活动控制台会话里，窗口/焦点相关的判定会失真。"
}

$desk = [W]::DesktopState() -split '\|'
KV "输入桌面 (InputDesktop)" $desk[0]
KV "本线程所在桌面" $desk[1]
$Fact["InputDesktop"] = $desk[0]

KV "键盘布局" ([W]::LayoutState())
KV "辅助功能" ([W]::AccessibilityState())
$acc = [W]::AccessibilityState()
$Fact["Accessibility"] = $acc
$fkActive = [W]::FilterKeysActive()
$skActive = [W]::StickyKeysActive()
KV "FilterKeys/StickyKeys 生效位" ("FilterKeys=" + $fkActive + " StickyKeys=" + $skActive + "  (1=已开启，0=未开启)")
$Fact["FilterKeysActive"] = $fkActive
$Fact["StickyKeysActive"] = $skActive

$curScheme = Get-ItemProperty "HKCU:\Control Panel\Cursors" -ErrorAction SilentlyContinue
if ($curScheme) { KV "光标方案 (HKCU)" ("(默认)=" + $curScheme.'(默认)' + " Source=" + $curScheme.'Scheme Source') }
KV "鼠标按键数" ([W]::GetSystemMetrics(43))   # SM_CMOUSEBUTTONS
KV "屏幕尺寸" ([W]::GetSystemMetrics(0).ToString() + " x " + [W]::GetSystemMetrics(1).ToString())

# 本进程是否被注入
$injected = $false
$libPath = ""
try {
    $me = [System.Diagnostics.Process]::GetCurrentProcess()
    foreach ($m in $me.Modules) {
        if ($m.ModuleName -ieq "lib.dll") { $injected = $true; $libPath = $m.FileName; break }
    }
} catch { }
KV "本进程是否被注入 lib.dll" ($(if ($injected) { "是  (" + $libPath + ")" } else { "否" }))
$Fact["SelfInjected"] = $injected
if (-not $injected) {
    Note "本进程未被注入 ⇒ S6 的 hook 行为探针只能反映「未被 hook 的基线」，不能证明引擎是否在吞键盘状态。"
    Note "若引擎确实在运行，请确认 hook_input=1，并用非白名单路径的宿主（如本 powershell）重跑。"
}

# ---------------- S1 引擎与注入面 ----------------
Sec "S1 引擎与注入面"

$engineNames = @("R3 ShieldCore", "R3ShieldCore")
$engines = @()
foreach ($n in $engineNames) {
    $p = Get-Process -Name $n -ErrorAction SilentlyContinue
    if ($p) { $engines += $p }
}
if ($engines.Count -eq 0) {
    Note "未发现引擎进程（R3ShieldCore*.exe）—— 下面的 hook 相关结论按「引擎未运行」解读。"
    $Fact["EngineRunning"] = $false
} else {
    $Fact["EngineRunning"] = $true
    foreach ($e in $engines) {
        L ("  --- 引擎进程 pid=" + $e.Id + " ---")
        KV "  路径" $e.Path
        KV "  启动时间" $e.StartTime
        try {
            $cl = (Get-CimInstance Win32_Process -Filter ("ProcessId=" + $e.Id) -ErrorAction SilentlyContinue).CommandLine
            KV "  命令行" $cl
            if ($cl -match "superdesk-selftest") { Note "命令行含 --superdesk-selftest ⇒ 正在走 A 配方（会往 winsta0\Winlogon 安全桌面拉窗口）。" }
            if ($cl -match "super-panel")       { Note "命令行含 --super-panel ⇒ 面板窗口进程。"; }
            if ($cl -match "uiaccess-ready-event") { Note "命令行含 --uiaccess-ready-event ⇒ UIAccess 接管实例。"; }
        } catch { }
        KV "  线程数/句柄数" ($e.Threads.Count.ToString() + " / " + $e.HandleCount)
        # ★ 引擎自己的窗口状态：WM_CLOSE 只最小化（r3shieldcore_gui.cpp），
        #   点 GUI 的 X 会让人误以为"引擎已停"，其实拦截全在生效。
        $ws = [W]::WindowsOfProcess([uint32]$e.Id) -split '\|'
        KV "  顶层窗口 总数/可见/最小化" ($ws[0] + " / " + $ws[1] + " / " + $ws[2])
        if ($ws[0] -ne "0") { KV "  首个窗口 类名/标题" ($ws[3] + " / " + $ws[4]) }
        if ([int]$ws[2] -gt 0) {
            $Fact["EngineGuiMinimized"] = $true
            Note "⚠️ 引擎窗口处于**最小化**状态 —— 高度符合「点了右上角 X 以为退出了」："
            Note "   r3shieldcore_gui.cpp 的 WM_CLOSE 是 SW_MINIMIZE，引擎进程仍在跑、拦截仍在生效。"
        } else {
            $Fact["EngineGuiMinimized"] = $false
        }
    }
}

# 被注入进程清单（CSV 解析，避免本地化表头/编码干扰）
$injOut = & tasklist /m lib.dll /fo csv /nh 2>$null
$injProcs = @()
foreach ($ln in @($injOut)) {
    if (-not $ln) { continue }
    $parts = ($ln.Trim('"')) -split '","'
    if ($parts.Count -lt 3) { continue }
    if ($parts[-1] -notmatch "lib\.dll") { continue }
    try { $injProcs += [pscustomobject]@{ Name = $parts[0]; Pid = [int]$parts[1] } } catch { }
}
KV "仍加载 lib.dll 的进程数" $injProcs.Count
foreach ($p in ($injProcs | Select-Object -First 15)) {
    $st = "?"
    try { $st = (Get-Process -Id $p.Pid -ErrorAction Stop).StartTime.ToString("MM-dd HH:mm:ss") } catch { }
    Note ("pid=" + $p.Pid + "  " + $p.Name + "  启动=" + $st)
}
if ($injProcs.Count -gt 15) { Note ("... 其余 " + ($injProcs.Count - 15) + " 个省略") }
$Fact["InjectedProcCount"] = $injProcs.Count
if ($Fact["EngineRunning"] -eq $false -and $injProcs.Count -gt 0) {
    Note ("★★ 引擎进程**已不在**，但仍有 " + $injProcs.Count + " 个进程加载着 lib.dll —— 这些进程的 hook 依赖")
    Note "   「等待引擎进程句柄」的线程醒来做 MH_DisableHook（customization_session.cpp:Run()）。"
    Note "   若这些进程卡在别的等待上（或刚被挂起过），清理可能迟迟不发生 ⇒ 必须先重启它们。"
}

# 配置
$iniCandidates = @()
if ($engines.Count -gt 0) {
    foreach ($e in $engines) {
        $d = Split-Path -Parent $e.Path
        $iniCandidates += (Join-Path $d "r3shieldcore.ini")
    }
}
$iniCandidates += (Join-Path $RepoRoot "dist\R3ShieldCore-x64\r3shieldcore.ini")
$iniCandidates += (Join-Path $RepoRoot "R3ShieldCore\Release\r3shieldcore.ini")
$usedIni = $null
foreach ($c in $iniCandidates) { if (Test-Path $c) { $usedIni = $c; break } }

$mode = ""; $hookInput = ""; $hookInject = ""; $promptTimeout = ""; $logPath = ""
if ($usedIni) {
    KV "配置文件" $usedIni
    $cfg = Get-Content -LiteralPath $usedIni -Encoding UTF8 -ErrorAction SilentlyContinue
    foreach ($line in $cfg) {
        $t = $line.Trim()
        if ($t -match "^\s*#" -or $t -eq "") { continue }
        if ($t -match "^\s*mode\s*=\s*(\S+)")            { $mode = $Matches[1] }
        if ($t -match "^\s*hook_input\s*=\s*(\S+)")      { $hookInput = $Matches[1] }
        if ($t -match "^\s*hook_input_inject\s*=\s*(\S+)"){ $hookInject = $Matches[1] }
        if ($t -match "^\s*prompt_timeout\s*=\s*(\S+)")  { $promptTimeout = $Matches[1] }
        if ($t -match "^\s*log\s*=\s*(.+)$")             { $logPath = $Matches[1].Trim() }
    }
    KV "mode" $mode
    KV "hook_input / hook_input_inject" ("$hookInput / $hookInject")
    KV "prompt_timeout" $promptTimeout
    KV "log 路径" $logPath
    $Fact["Mode"] = $mode
    $Fact["HookInput"] = $hookInput
    $Fact["HookInputInject"] = $hookInject
} else {
    Note "未找到 r3shieldcore.ini。"
}

# 日志统计
$logFiles = @()
if ($logPath -and (Test-Path $logPath)) { $logFiles += $logPath }
$logFiles += (Join-Path $RepoRoot "R3ShieldCore\Release\r3shieldcore-events.log")
$logFiles += (Join-Path $RepoRoot "dist\r3shieldcore-events.log")
$logFile = $null
foreach ($f in $logFiles) { if (Test-Path $f) { $logFile = $f; break } }

if ($logFile) {
    KV "事件日志" $logFile
    try { KV "日志最后修改时间" ((Get-Item $logFile).LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")) } catch { }
    $tail = Get-Content -LiteralPath $logFile -Tail 400 -Encoding UTF8 -ErrorAction SilentlyContinue
    if ($tail) {
        $tailCount = @($tail).Count
        $lastLine = @($tail)[-1]
        if ($lastLine -match "^\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})") { KV "日志最后一条时间" $Matches[1] }
        $blocked = @($tail | Where-Object { $_ -match "\[by R3ShieldCore\]" })
        $inputEv = @($tail | Where-Object { $_ -match "GetAsyncKeyState|GetKeyboardState|GetKeyState|轮询读取|SetWindowsHookEx|RegisterRawInput|BlockInput|ClipCursor|SendInput" })
        $blockedInput = @($inputEv | Where-Object { $_ -match "BLOCK" })
        KV "尾部行数" $tailCount
        KV "其中被拒([by R3ShieldCore])" $blocked.Count
        KV "其中输入类事件" $inputEv.Count
        KV "其中输入类被拒" $blockedInput.Count
        if ($blockedInput.Count -gt 0) {
            L "  --- 输入类拦截样本（最多 8 条）---"
            foreach ($l in ($blockedInput | Select-Object -Last 8)) { Note $l }
        }
        L "  --- 日志最后 5 行 ---"
        foreach ($l in ($tail | Select-Object -Last 5)) { Note $l }
        $Fact["LogBlockedInput"] = $blockedInput.Count
    }
} else {
    Note "未找到事件日志文件。"
}

# ---------------- S2 焦点 / 捕获 / 卡死 ----------------
Sec "S2 焦点 / 捕获 / 卡死"

$recs = [W]::EnumTopWindows()
$winMap = @{}
foreach ($wrec in $recs) {
    $f = $wrec -split '\|'
    $winMap[$f[0]] = [pscustomobject]@{
        Hwnd = $f[0]; Pid = [int]$f[1]; Tid = [int]$f[2]; Class = $f[3]; Title = $f[4]
        Style = $f[5]; ExStyle = $f[6]; Visible = ($f[7] -eq "1"); Enabled = ($f[8] -eq "1")
        Hung = ($f[9] -eq "1"); L = [int]$f[10]; T = [int]$f[11]; R = [int]$f[12]; B = [int]$f[13]
    }
}
KV "顶层窗口总数" $recs.Count

$fg = [W]::GetForegroundWindow()
$fgH = $fg.ToInt64().ToString()
[uint32]$fgPid = 0
$fgTid = 0
if ($fg -ne [IntPtr]::Zero) { $fgTid = [W]::GetWindowThreadProcessId($fg, [ref]$fgPid) }
KV "前台窗口 hwnd/pid/tid" ("$fgH / $fgPid / $fgTid")
if ($winMap.ContainsKey($fgH)) {
    $w = $winMap[$fgH]
    KV "  类名/标题" ($w.Class + " / " + $w.Title)
    KV "  样式" ($w.Style + "  ex=" + $w.ExStyle)
    KV "  可见/可用/卡死" ("$($w.Visible) / $($w.Enabled) / $($w.Hung)")
    KV "  矩形" ("($($w.L),$($w.T))-($($w.R),$($w.B))")
    $Fact["FgClass"] = $w.Class
}
try {
    $fgProc = Get-Process -Id $fgPid -ErrorAction SilentlyContinue
    if ($fgProc) { KV "  前台进程" ($fgProc.ProcessName + "  " + $fgProc.Path) }
} catch { }

# ★ 前台是不是控制台窗口 —— 决定 H4 的 hwndFocus=0 能不能当证据用。
#   控制台窗口（ConsoleWindowClass）的输入由 conhost 代管，GetGUIThreadInfo 对它的
#   宿主线程返回 hwndFocus=0 是**正常现象**，不是"焦点丢失"。
#   本脚本自己就开在 cmd.exe 里跑，所以前台几乎必然是控制台 —— 不加这个豁免，
#   H4 会在每一次运行里稳定误报"命中"（2026-10-03 两次报告都是这么来的）。
$fgIsConsole = ($Fact.Contains("FgClass") -and ([string]$Fact["FgClass"]) -ieq "ConsoleWindowClass")
$Fact["FgIsConsole"] = $fgIsConsole

# 前台线程的 GUI 焦点状态
if ($fgTid -ne 0) {
    $g = [W]::GuiThreadInfo([uint32]$fgTid) -split '\|'
    KV "前台线程 hwndActive" $g[0]
    KV "前台线程 hwndFocus" $g[1]
    KV "前台线程 hwndCapture" $g[2]
    KV "前台线程 hwndMenuOwner" $g[3]
    KV "前台线程 hwndMoveSize" $g[4]
    KV "前台线程 hwndCaret" $g[5]
    $Fact["FgFocus"] = $g[1]
    $Fact["FgCapture"] = $g[2]
    if ($g[1] -eq "0") {
        Note "⚠️ 前台线程 hwndFocus = 0 ⇒ 该窗口队列里**没有任何控件持有键盘焦点**。"
        Note "   在正常系统上，前台窗口的输入线程一定有一个焦点窗口（哪怕就是主窗口本身）。"
    }
    if ($g[2] -ne "0") {
        Note "⚠️⚠️ 前台线程 hwndCapture != 0 ⇒ 有窗口正持有**鼠标捕获**，系统会把所有鼠标消息送给它，"
        Note "     其它窗口收不到点击、光标也不会更新。这是「键盘无响应 + 光标冻结」的经典成因。"
    }
    KV "前台窗口卡死探测" ([W]::HungProbe($fg))
}

# 全系统 GUI 线程的捕获普查
L "  --- 全系统 GUI 线程鼠标捕获普查 ---"
$tids = @()
foreach ($r in $recs) { $f = $r -split '\|'; $t = [int]$f[2]; if ($t -ne 0 -and ($tids -notcontains $t)) { $tids += $t } }
$captureHits = 0
foreach ($t in $tids) {
    $g = [W]::GuiThreadInfo([uint32]$t) -split '\|'
    if ($g[2] -ne "0") {
        $captureHits++
        $capHwnd = $g[2]
        $info = "tid=$t captureHwnd=$capHwnd"
        if ($winMap.ContainsKey($capHwnd)) {
            $w = $winMap[$capHwnd]
            $info += " class=" + $w.Class + " pid=" + $w.Pid + " title=" + $w.Title + " visible=" + $w.Visible
        }
        Note ("★ " + $info)
    }
}
KV "持有鼠标捕获的 GUI 线程数" $captureHits
$Fact["CaptureHits"] = $captureHits
if ($captureHits -eq 0) { Note "未发现任何线程持有鼠标捕获。" }

# ---------------- S2.5 目标程序专项（-TargetApp） ----------------
# ★ 这一节是为了修掉「测错对象」这个结构性缺陷：
#   脚本跑在 cmd.exe 里，前台永远是那个控制台，于是 H4 会稳定误报、
#   光标采样也落在控制台/编辑器上。指定 -TargetApp 后，焦点/光标/band 的判定
#   才真正落在「出问题的那个程序」上。
$targetPids = @()
if ($TargetApp -ne "") {
    Sec "S2.5 目标程序专项（-TargetApp $TargetApp）"

    $tpId = 0
    if ([int]::TryParse($TargetApp, [ref]$tpId)) {
        if (Get-Process -Id $tpId -ErrorAction SilentlyContinue) { $targetPids = @($tpId) }
    }
    else {
        $base = $TargetApp
        if ($base -imatch '\.exe$') { $base = $base.Substring(0, $base.Length - 4) }
        try { $targetPids = @(Get-Process -Name $base -ErrorAction SilentlyContinue | ForEach-Object { $_.Id }) } catch { }
    }

    if ($targetPids.Count -eq 0) {
        KV "目标程序" ("未找到匹配的进程: " + $TargetApp)
        Note "· 请确认进程名拼写（可省略 .exe），或直接用 pid 运行：-TargetApp 1234"
        Note "· 也可以先在任务管理器里看一眼那个程序的 PID，再传数字过来。"
    }
    else {
        KV "匹配到的 pid" ($targetPids -join ", ")
        $Fact["TargetPids"] = ($targetPids -join ",")

        $tWinCount = 0
        $tBandBad = 0
        $tHung = 0
        $tFocusSeen = $false
        foreach ($pidX in $targetPids) {
            $proc = Get-Process -Id $pidX -ErrorAction SilentlyContinue
            if (-not $proc) { continue }
            L ("  --- pid=" + $pidX + "  " + $proc.ProcessName + " ---")
            try { KV "  路径" $proc.Path } catch { KV "  路径" "(读不到，可能更高完整性级别)" }
            KV "  会话 ID" $proc.SessionId

            $tidSeen = @()
            foreach ($wrec in $recs) {
                $f = $wrec -split '\|'
                if ([int]$f[1] -ne [int]$pidX) { continue }
                $tWinCount++
                $band = -1
                if ($f.Count -ge 15) { $band = [int]$f[14] }
                $flags = @()
                if ($f[7] -eq "1") { $flags += "visible" }
                if ($f[9] -eq "1") { $flags += "HUNG" ; $tHung++ }
                if ($band -eq 2) { $flags += ("band=2 ★UIAccess 波段（超级置顶指纹）") ; $tBandBad++ }
                elseif ($band -eq 1) { $flags += "band=1" }
                elseif ($band -ge 0) { $flags += ("band=" + $band + "（系统波段，正常）") }
                else { $flags += "band=?" }
                Note ("hwnd=$($f[0]) class=$($f[3]) tid=$($f[2]) rect=($($f[10]),$($f[11]))-($($f[12]),$($f[13])) title=$($f[4])  [" + ($flags -join " ") + "]")
                if ([int]$f[2] -ne 0 -and ($tidSeen -notcontains [int]$f[2])) { $tidSeen += [int]$f[2] }
            }
            if ($tWinCount -eq 0) { Note "  （该 pid 当前没有顶层窗口）" }

            foreach ($t in $tidSeen) {
                $g = [W]::GuiThreadInfo([uint32]$t) -split '\|'
                Note ("  线程 tid=$t  hwndActive=$($g[0])  hwndFocus=$($g[1])  hwndCapture=$($g[2])")
                if ($g[1] -ne "0") { $tFocusSeen = $true }
                if ($g[2] -ne "0") { Note ("  ⚠️⚠️ 该线程持有鼠标捕获 hwndCapture=$($g[2]) —— 所有鼠标消息都被它独占。") }
            }
        }

        KV "目标程序顶层窗口数" $tWinCount
        KV "目标程序中卡死的窗口数" $tHung
        KV "目标程序中 band=2(UIAccess) 的窗口数" $tBandBad
        $Fact["TargetWinCount"] = $tWinCount
        $Fact["TargetBandBad"] = $tBandBad
        $Fact["TargetHung"] = $tHung

        if ($tBandBad -gt 0) {
            Note "⚠️ 目标程序自己就有窗口处在 UIAccess 波段（band=2）⇒ 它被超级置顶接管过。"
        }
        if ($tHung -gt 0) {
            Note "⚠️ 目标程序有卡死窗口 ⇒ 它自己的 UI 线程没在泵消息，键盘/光标都会看起来没反应。"
        }
        if (-not $tFocusSeen -and $tWinCount -gt 0) {
            Note "· 目标程序当前**没有任何线程持有键盘焦点** —— 若此时它就在前台，这就是 H4 的真命中。"
        }
    }
}
else {
    Note "· 未指定 -TargetApp ⇒ 焦点/光标的判定对象是「当前前台窗口」，很可能就是本脚本自己的控制台。"
    Note "  要让结论落在出问题的那个程序上，请加：-TargetApp <进程名或pid>"
}

# ---------------- S3 覆盖窗口普查 ----------------
Sec "S3 覆盖窗口普查（topmost / 全屏 / 覆盖光标）"

$cursorPos = New-Object W+POINT
[void][W]::GetCursorPos([ref]$cursorPos)
KV "当前光标位置" ("(" + $cursorPos.X + "," + $cursorPos.Y + ")")

$screenW = [W]::GetSystemMetrics(0)
$screenH = [W]::GetSystemMetrics(1)
$screenArea = [double]($screenW * $screenH)

L "  --- 可见 + TOPMOST 的窗口 ---"
$topCount = 0
$topOverCursor = 0
foreach ($wrec in $recs) {
    $f = $wrec -split '\|'
    if ($f[7] -ne "1") { continue }
    $ex = [Convert]::ToInt64($f[6].Substring(2), 16)
    if (($ex -band 0x00000008L) -eq 0) { continue }
    $topCount++
    $l = [int]$f[10]; $t = [int]$f[11]; $rr = [int]$f[12]; $b = [int]$f[13]
    $area = [double](($rr - $l) * ($b - $t))
    $cov = ""
    if ($screenArea -gt 0) { $cov = "{0:P1}" -f ($area / $screenArea) }
    $hit = ""
    if ($cursorPos.X -ge $l -and $cursorPos.X -lt $rr -and $cursorPos.Y -ge $t -and $cursorPos.Y -lt $b) { $hit = "  ★覆盖光标"; $topOverCursor++ }
    Note ("hwnd=$($f[0]) pid=$($f[1]) class=$($f[3]) rect=($l,$t)-($rr,$b) 占屏=$cov ex=" + [W]::ExStyleText($ex) + " title=$($f[4])$hit")
}
KV "可见 TOPMOST 窗口数" $topCount
KV "其中覆盖光标的 TOPMOST 窗口数" $topOverCursor
$Fact["TopmostOverCursor"] = $topOverCursor

L "  --- 面积 > 80% 屏幕的可见窗口（排除最小化/屏幕外；仅作参考）---"
$bigCount = 0
$bigTop = 0
foreach ($wrec in $recs) {
    $f = $wrec -split '\|'
    if ($f[7] -ne "1") { continue }
    $l = [int]$f[10]; $t = [int]$f[11]; $rr = [int]$f[12]; $b = [int]$f[13]
    if ($l -lt -10000 -or $t -lt -10000) { continue }
    if ($rr -le 0 -or $b -le 0) { continue }
    $area = [double](($rr - $l) * ($b - $t))
    if ($screenArea -le 0) { continue }
    if (($area / $screenArea) -lt 0.8) { continue }
    $bigCount++
    $ex = [Convert]::ToInt64($f[6].Substring(2), 16)
    $isTop = (($ex -band 0x00000008L) -ne 0)
    $mark = ""
    if ($isTop) { $bigTop++; $mark = "  ★TOPMOST" }
    Note ("hwnd=$($f[0]) pid=$($f[1]) class=$($f[3]) rect=($l,$t)-($rr,$b) ex=" + [W]::ExStyleText($ex) + " title=$($f[4])$mark")
}
KV "大面积可见窗口数" $bigCount
KV "其中 TOPMOST 的" $bigTop
$Fact["BigWindows"] = $bigCount
$Fact["BigTopmost"] = $bigTop

# --- 窗口 Band 普查：超级置顶（UIAccess 波段）的专属指纹 ---
# ★ 为什么单列这一节：WS_EX_TOPMOST 只说明"普通置顶"，而「超级置顶」用的是
#   未文档化的 SetWindowBand(..., band=2)。实测（tools/bandprobe.cpp）：
#     · 普通窗口 GetWindowBand = 1
#     · 没有 UIAccess 令牌的进程调 SetWindowBand **任何组合都失败**（err=5 / err=87）
#   ⇒ 谁能把窗口放进 UIAccess 波段？只有带 UIAccess 令牌的进程。在本项目里，
#     那就是「超级置顶」拉起的 SYSTEM+UIAccess 子实例。
#   这就是「不用超级置顶就正常」这句话在系统里的可观测对应物。
#
# ⚠️ 判据必须是 **band == 2（ZBID_UIACCESS）**，不能写成"band != 1"。
#    实测 2026-10-03 16:54 那次跑出来 band=16 出现在 IME / ForegroundStaging 这类
#    **正常系统窗口**上 —— ZBID 里 16 = ZBID_SYSTEM_TOOLS，属正常。
#    写成"band != 1"会把 IME 窗口全部误报成"被超级置顶接管"。
$zbNames = @{
    0 = "ZBID_DEFAULT"; 1 = "ZBID_DESKTOP"; 2 = "ZBID_UIACCESS"; 3 = "ZBID_IMMERSIVE_IHM"
    4 = "ZBID_IMMERSIVE_NOTIFICATION"; 5 = "ZBID_IMMERSIVE_APPCHROME"; 6 = "ZBID_IMMERSIVE_MOLL"
    7 = "ZBID_IMMERSIVE_EDGY"; 8 = "ZBID_IMMERSIVE_INACTIVEMOBODY"; 9 = "ZBID_IMMERSIVE_INACTIVEDOCK"
    10 = "ZBID_IMMERSIVE_ACTIVEMOBODY"; 11 = "ZBID_IMMERSIVE_ACTIVEDOCK"; 12 = "ZBID_IMMERSIVE_BACKGROUND"
    13 = "ZBID_IMMERSIVE_SEARCH"; 14 = "ZBID_GENUINE_WINDOWS"; 15 = "ZBID_IMMERSIVE_RESTRICTED"
    16 = "ZBID_SYSTEM_TOOLS"; 17 = "ZBID_LOCK"; 18 = "ZBID_ABOVELOCK_UX"
}
function BandName { param([int]$b)
    if ($zbNames.ContainsKey($b)) { return $zbNames[$b] }
    return ("band#" + $b)
}

# ⚠️⚠️ 判据不能只写 band == 2！实测 2026-10-03 16:55 发现 **正常软件也在用 band=2**：
#     · AMD 显卡驱动（amdow.exe / AMDRSServ.exe）的 overlay 窗口
#     · IME 窗口（Default IME）
#   它们的共同点是：**不可见** 且 **极小**（1x1 或 16x16）。
#   而「超级置顶」拉起的那个 GUI 窗口是**可见 + 正常尺寸**。
#   ⇒ 报警判据 = band==2 **且 可见** **且 面积 ≥ 1% 屏**。
#     只写 band==2 会被 AMD 驱动淹掉（本次实测一次就 12 个假阳性）。
$bandMinArea = $screenArea * 0.01
L "  --- 窗口 Band 普查（1=普通；★2=UIAccess 波段；16=SYSTEM_TOOLS；AMD/IME 也会用 2）---"
$bandReadable = 0
$bandUiAccess = 0
$bandUiAccessRelevant = 0
$bandUiAccessTopmost = 0
$bandOther = 0
foreach ($wrec in $recs) {
    $f = $wrec -split '\|'
    if ($f.Count -lt 15) { continue }
    $band = [int]$f[14]
    if ($band -lt 0) { continue }            # 读不到，不计
    $bandReadable++
    if ($band -eq 1) { continue }            # 普通波段，不列
    $visible = ($f[7] -eq "1")
    $ex = [Convert]::ToInt64($f[6].Substring(2), 16)
    $isTop = (($ex -band 0x00000008L) -ne 0)
    $l = [int]$f[10]; $t = [int]$f[11]; $rr = [int]$f[12]; $b = [int]$f[13]
    $area = [double](($rr - $l) * ($b - $t))
    $big = ($area -ge $bandMinArea)
    $hit = ""
    if ($visible -and $cursorPos.X -ge $l -and $cursorPos.X -lt $rr -and $cursorPos.Y -ge $t -and $cursorPos.Y -lt $b) { $hit = "  ★覆盖光标" }
    $vis = ""
    if (-not $visible) { $vis = " [不可见]" }
    if ($band -eq 2) {
        $bandUiAccess++
        if ($isTop) { $bandUiAccessTopmost++ }
        if ($visible -and $big) {
            # ★ 唯一需要报警的组合
            $bandUiAccessRelevant++
            Note ("★ hwnd=$($f[0]) pid=$($f[1]) class=$($f[3]) band=2 可见且面积>=1%屏 ex=" + [W]::ExStyleText($ex) + " rect=($l,$t)-($rr,$b) title=$($f[4])$hit")
        }
        else {
            Note ("· hwnd=$($f[0]) pid=$($f[1]) class=$($f[3]) band=2 但不可见或极小" + $vis + " ex=" + [W]::ExStyleText($ex) + " rect=($l,$t)-($rr,$b) title=$($f[4])   [正常软件也这样，如 AMD 驱动/IME]")
        }
    }
    else {
        $bandOther++
        Note ("· hwnd=$($f[0]) pid=$($f[1]) class=$($f[3]) band=$band (" + (BandName $band) + ") ex=" + [W]::ExStyleText($ex) + " title=$($f[4])$vis   [非 UIAccess，仅供参考]")
    }
}
if ($bandReadable -eq 0) {
    Note "· GetWindowBand 在本机不可用（未文档化导出，老系统可能没有）⇒ 本项跳过，不能据此下结论。"
} elseif ($bandUiAccessRelevant -eq 0) {
    Note ("· 已扫描 " + $bandReadable + " 个窗口：**没有「可见且面积>=1%屏」的 band=2 窗口**")
    Note ("  ⇒ 没有超级置顶留下的 UIAccess 波段窗口。")
    if ($bandUiAccess -gt 0) {
        Note ("  （有 " + $bandUiAccess + " 个 band=2 窗口，但都是不可见/极小的 —— AMD 驱动和 IME 本来就使用这个波段，属正常。）")
    }
    if ($bandOther -gt 0) { Note ("  （另有 " + $bandOther + " 个其它波段窗口，均为系统自带。）") }
} else {
    Note ("⚠️⚠️ 发现 " + $bandUiAccessRelevant + " 个「可见且面积>=1%屏」的 band=2 窗口（band=2 总数 " + $bandUiAccess + "，其中 TOPMOST " + $bandUiAccessTopmost + "）。")
    Note "   普通软件（AMD 驱动 / IME）只会把**不可见的小窗口**放进这个波段；"
    Note "   一个**可见的大窗口**出现在这里，与「超级置顶」的行为吻合。"
    Note "   ⇒ 请先杀掉上面 ★ 行里的 pid，再看输入是否立刻恢复；能恢复就说明是超级置顶的残留。"
}
KV "可读 band 的窗口数" $bandReadable
KV "band=2 (UIAccess) 窗口总数" $bandUiAccess
KV "★ 其中「可见且面积>=1%屏」的（才报警）" $bandUiAccessRelevant
KV "其它波段（正常系统窗口）" $bandOther
$Fact["BandReadable"] = $bandReadable
$Fact["BandUiAccess"] = $bandUiAccess
$Fact["BandUiAccessRelevant"] = $bandUiAccessRelevant
$Fact["BandOther"] = $bandOther
$Fact["BandUiAccessTopmost"] = $bandUiAccessTopmost

# ---------------- S4 光标身份 ----------------
Sec "S4 光标身份"

$cs2 = [W]::CursorState() -split '\|'
KV "CursorInfo.flags" ($cs2[0] + "  (1=SHOWING 2=SUPPRESSED)")
KV "当前光标句柄" $cs2[1]
KV "当前光标名称" $cs2[2]
$Fact["CursorName"] = $cs2[2]
KV "光标位置" ("(" + $cs2[3] + "," + $cs2[4] + ")")
KV "光标下窗口 hwnd" $cs2[5]
KV "光标下窗口 pid" $cs2[6]
KV "光标下窗口类名" $cs2[7]
KV "光标下窗口标题" $cs2[8]
KV "光标下顶层窗口" $cs2[9]
KV "该类声明的类光标" ($cs2[11] + "  (h=" + $cs2[10] + ")")
KV "光标下窗口 ex" ("CLICK-THROUGH=" + $cs2[14] + " LAYERED=" + $cs2[15])
KV "ClipCursor 裁剪矩形" $cs2[12]
KV "本线程 GetCursor()" $cs2[13]

# ★ 光标形状是由「光标下窗口」的线程处理的，不一定是前台窗口。
#   所以这里单独探光标下窗口是否卡死 —— 这是「光标形状冻结」的直接成因。
if ($cs2[5] -ne "0") {
    $underHwnd = [IntPtr]([int64]$cs2[5])
    [uint32]$underPid2 = 0
    $underTid = [W]::GetWindowThreadProcessId($underHwnd, [ref]$underPid2)
    KV "光标下窗口 卡死探测" ([W]::HungProbe($underHwnd))
    if ($underTid -ne 0) {
        $ug = [W]::GuiThreadInfo([uint32]$underTid) -split '\|'
        KV "光标下窗口线程 tid/hwndFocus" ($underTid.ToString() + " / " + $ug[1])
        if ($ug[1] -eq "0") {
            Note "⚠️ 光标下窗口所属线程 hwndFocus=0 —— 该线程没有键盘焦点窗口，"
            Note "   它收不到也处理不了键盘消息；若同时 S5 显示光标句柄不变，即「光标冻结」的成因。"
        }
    }
}
if ([int]$cs2[0] -band 2) { Note "⚠️ CURSOR_SUPPRESSED：系统报告光标被抑制（触摸/笔输入或全屏独占时会出现）。" }
if ($cs2[12] -ne "0,0,0,0") {
    $cl = $cs2[12] -split ','
    if ([int]$cl[0] -ne 0 -or [int]$cl[1] -ne 0 -or [int]$cl[2] -ne [W]::GetSystemMetrics(0) -or [int]$cl[3] -ne [W]::GetSystemMetrics(1)) {
        Note "⚠️ 鼠标被 ClipCursor 限制在非全屏矩形内 ⇒ 有进程调用了 ClipCursor 且未解除。"
    }
}

# ---------------- S5 输入可达性 ----------------
Sec "S5 输入可达性（被动观察 + 低级钩子计数）"

$samples = @()
$hookInstallResult = ""
$hookStatsBefore = ""
if ($WatchSeconds -gt 0 -or $HookProbeSeconds -gt 0) {
    L "  >>> 请现在开始：移动鼠标、点击输入框、按几下键盘 <<<"
} else {
    Note "已跳过被动采样与钩子计数（WatchSeconds / HookProbeSeconds = 0）。"
    Note "要复现问题，请在目标程序正在卡住时这样跑：-WatchSeconds 15 -HookProbeSeconds 10，"
    Note "并在观察窗内持续移动鼠标、点击输入框、按键 —— S5 的光标/前台/输入活动变化量是判定「光标冻结」的关键证据。"
}

if ($HookProbeSeconds -gt 0 -and -not $SkipHookProbe) {
    $hookInstallResult = [HookProbe]::Install()
    KV "低级钩子安装结果" $hookInstallResult
    if ($hookInstallResult -match "FAIL err=5") {
        Note "⚠️⚠️ SetWindowsHookEx(WH_KEYBOARD_LL/WH_MOUSE_LL) 返回失败且 err=5(ACCESS_DENIED)"
        Note "     ⇒ 引擎的 input_hook_guard 正在**拒绝本进程安装输入钩子**（block/block_all 模式）。"
    }
}

$totalSec = [Math]::Max($WatchSeconds, $HookProbeSeconds)
if ($totalSec -gt 0) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $lastShown = -1
    while ($sw.Elapsed.TotalSeconds -lt $totalSec) {
        $samples += ([W]::SampleState())
        # 泵一下消息，让低级钩子有机会被回调
        $msg = New-Object W+MSG
        while ([W]::PeekMessage([ref]$msg, [IntPtr]::Zero, 0, 0, [W]::PM_REMOVE)) {
            [void][W]::TranslateMessage([ref]$msg)
            [void][W]::DispatchMessage([ref]$msg)
        }
        # 控制台实时倒计时：否则双击启动时用户面对一个纯黑窗口，不知道该干什么
        $left = [int][Math]::Ceiling($totalSec - $sw.Elapsed.TotalSeconds)
        if ($left -ne $lastShown) {
            $lastShown = $left
            try {
                [Console]::Write("`r  >>> WATCHING ... {0,3}s left -- use the AFFECTED app now   " -f $left)
                [Console]::Out.Flush()
            } catch { }
        }
        Start-Sleep -Milliseconds 200
    }
    $sw.Stop()
    try { [Console]::WriteLine(""); [Console]::Out.Flush() } catch { }
    Write-Output (" Sampling done: " + $samples.Count + " samples.")
    Write-Output ""
}

if ($HookProbeSeconds -gt 0 -and -not $SkipHookProbe) {
    $hookStatsBefore = [HookProbe]::Stats()
    KV "低级钩子收到的事件" $hookStatsBefore
    [void][HookProbe]::Uninstall()
}

if ($samples.Count -gt 0) {
    $fgSet = @(); $curSet = @(); $underSet = @(); $posSet = @(); $lastInputVals = @()
    $fgSeq = @()
    $targetFgSamples = 0
    foreach ($s in $samples) {
        $f = $s -split '\|'
        if ($fgSet -notcontains $f[0]) { $fgSet += $f[0] }
        if ($curSet -notcontains $f[4]) { $curSet += $f[4] }
        if ($underSet -notcontains $f[7]) { $underSet += $f[7] }
        $p = "$($f[5]),$($f[6])"
        if ($posSet -notcontains $p) { $posSet += $p }
        if ($lastInputVals -notcontains $f[10]) { $lastInputVals += $f[10] }
        if ($targetPids.Count -gt 0 -and ($targetPids -contains [int]$f[1])) { $targetFgSamples++ }
        $fgSeq += $f[1]
    }
    $li0 = [int](($samples[0] -split '\|')[10])
    $liN = [int](($samples[-1] -split '\|')[10])
    $t0  = [int](($samples[0] -split '\|')[11])
    $tN  = [int](($samples[-1] -split '\|')[11])

    KV "采样次数/时长" ($samples.Count.ToString() + " 次 / 约 " + $totalSec + " 秒")
    KV "GetLastInputInfo 变化" ("起点=" + $li0 + " 终点=" + $liN + " 差=" + ($liN - $li0) + "ms")
    KV "采样期间光标位置变化数" $posSet.Count
    KV "采样期间光标句柄变化数" $curSet.Count
    KV "采样期间前台窗口变化数" $fgSet.Count
    KV "采样期间光标下窗口变化数" $underSet.Count
    KV "采样期间系统 tick 前进" ($tN - $t0)

    # ★ 前台窗口的**序列**（不只是变化次数）：用来判断"点了目标程序但它没拿到前台"。
    #   只报次数的话，"控制台→控制台→…" 和 "控制台→目标程序→控制台" 看起来一样。
    $fgSeqText = ""
    $prev = ""
    foreach ($p in $fgSeq) {
        if ($p -ne $prev) { if ($fgSeqText.Length -gt 0) { $fgSeqText += " -> " } ; $fgSeqText += $p ; $prev = $p }
    }
    KV "采样期间前台窗口序列(pid)" $fgSeqText
    if ($targetPids.Count -gt 0) {
        KV "其中目标程序处于前台的采样数" ($targetFgSamples.ToString() + " / " + $samples.Count)
        if ($targetFgSamples -eq 0) {
            Note "★ 整个观察窗内**目标程序一次都没成为前台** —— 你点它了但它没拿到前台，"
            Note "  或者这 8 秒里你其实一直在操作别的窗口（很可能是本脚本的控制台）。"
            Note "  ⇒ 这种情况下 H2/H4 的结论对目标程序无效，请重跑并确保点击的是目标程序。"
        }
    }
    $Fact["TargetFgSamples"] = $targetFgSamples

    $Fact["CursorPosChanges"] = $posSet.Count
    $Fact["CursorHandleChanges"] = $curSet.Count
    $Fact["ForegroundChanges"] = $fgSet.Count
    $Fact["UnderWindowChanges"] = $underSet.Count
    $Fact["LastInputDelta"] = ($liN - $li0)
    $Fact["HookKbCount"] = 0
    if ($hookStatsBefore -match "kb=(\d+)") { $Fact["HookKbCount"] = [int]$Matches[1] }

    if (($liN - $li0) -le 0 -and $posSet.Count -le 1) {
        Note "输入活动完全没前进 ⇒ 可能没有任何输入事件进入系统（或本次观察窗内确实没有人工操作）。"
    }
    # ★ 光标"冻结"的判定必须要求**鼠标跨过窗口边界**。
    #   只在一个窗口内部移动时，光标形状本来就该保持不变（例如一直悬在同一个文本框上
    #   就一直是 I 型光标）—— 旧版判据只看"位置变了但句柄没变"，会把这种**正常**情况
    #   报成"光标冻结"。2026-10-03 16:46 那次报告就是这样误报的（光标下窗口变化数=1）。
    if ($posSet.Count -gt 1 -and $curSet.Count -le 1 -and $underSet.Count -gt 1) {
        Note ("★ 鼠标跨过了 " + $underSet.Count + " 个不同窗口，但**光标句柄始终不变**（" + $curSet.Count + " 种）")
        Note "  ⇒ 系统没有在处理 WM_SETCURSOR / 光标形状被冻结。"
        Note "  典型成因：光标下窗口所属线程不响应消息（卡死）、或有窗口持有鼠标捕获。"
    }
    elseif ($posSet.Count -gt 1 -and $curSet.Count -le 1 -and $underSet.Count -le 1) {
        Note ("· 鼠标在动、光标句柄也没变，但**始终在同一个窗口内**（光标下窗口只有 1 种）")
        Note "  ⇒ 无法据此判定光标冻结：同一个窗口内部光标形状不变是正常现象。"
        Note "    要判定冻结，请在观察窗内把鼠标**移过多个不同窗口**（例如从目标程序移到桌面/任务栏）。"
    }
    if ($posSet.Count -gt 1 -and $underSet.Count -le 1) {
        Note "★ 鼠标在动但**光标下窗口始终是同一个** ⇒ 该窗口覆盖了鼠标活动区域（顶层/全屏覆盖层）。"
    }
}

# ---------------- S6 引擎 hook 行为探针 ----------------
Sec "S6 引擎 hook 行为探针（主动复现）"

if ($SkipHookProbe) {
    Note "已按参数跳过。"
} else {
    L "  --- 6.1 GetKeyboardState 密度探针（<100ms 内连调 200 次）---"
    Note "原理：引擎把 GetAsyncKeyState/GetKeyState/GetKeyboardState 的「轮询密度」判据设为"
    Note "      60 次/100ms；规则层对 PollKeyState/PollAsyncKeyState **一律判高危**。"
    Note "      · log 模式   ：高危也只记录，探针应恒 TRUE、耗时 ~0ms。"
    Note "      · block 模式 ：第 61 次左右开始返回 FALSE 且 err=5（不调原函数）。"
    Note "      · ask 模式   ：第 61 次会真的弹窗询问并**阻塞调用线程**到 prompt_timeout"
    Note "                     （默认 30s）—— msAtTrip 就是「应用被冻住多久」的硬证据。"
    $ksp = [HookBehavior]::KeyboardStateProbe()
    KV "结果" $ksp
    $Fact["KeyboardStateProbe"] = $ksp
    if ($ksp -match "tripAtCall=never" -and $ksp -match "falseCount=0") {
        Note "✔ 未观察到键盘状态被吞（本进程内）。"
    } else {
        Note "⚠️ 观察到 GetKeyboardState 被吞（详见上面的 tripAtCall / falseCount / tripErr / msAtTrip）。"
        if ($ksp -match "msAtTrip=(\d+)") {
            $msTrip = [int]$Matches[1]
            if ($msTrip -ge 500) {
                Note ("⚠️⚠️ 单次调用被阻塞 " + $msTrip + " ms ⇒ 调用方（应用的 UI 线程）在这段时间内不处理任何消息：")
                Note "     表现就是「键盘敲了没反应 + 光标形状冻住不更新」。这是本脚本能直接复现的根因。"
            }
        }
    }

    L "  --- 6.2 SetWindowsHookEx 探针 ---"
    $shp = [HookBehavior]::SetHookProbe()
    KV "结果" $shp
    $Fact["SetHookProbe"] = $shp
    if ($shp -match "err=5") {
        Note "⚠️ 安装钩子被拒且 err=5 ⇒ 引擎 input_hook_guard 在拦（本进程内所有应用级热键/钩子都会失效）。"
    } else {
        Note "✔ 钩子可正常安装。"
    }

    L "  --- 6.3 RegisterRawInputDevices 探针（RIDEV_INPUTSINK 键盘，注册后立即撤销）---"
    $rip = [HookBehavior]::RawInputProbe()
    KV "结果" $rip
    $Fact["RawInputProbe"] = $rip
    if ($rip -match "err=5") {
        Note "⚠️ 原始输入注册被拒且 err=5 ⇒ 引擎按「后台收输入=高危」拦掉；依赖原始输入的程序会收不到键鼠。"
    } elseif ($rip -match "err=87") {
        Note "err=87 = ERROR_INVALID_PARAMETER：探针参数问题（RIDEV_INPUTSINK 要求 hwndTarget 有效），不代表引擎拦截。"
    } else {
        Note "✔ 原始输入注册正常。"
    }

    L "  --- 6.4 探针副作用与交叉验证 ---"
    Note "上述 6.1 会在引擎日志里留下「轮询读取全键盘状态」事件 —— 这本身就是 hook 已生效的正向证据。"
    Note "请在 S1 的日志统计里核对：跑完本脚本后输入类事件条数应增加。"
}

# ---------------- S7 残留 hook / 持久化注入点审计 ----------------
Sec "S7 「停引擎也没好」专用：残留 hook 与持久化注入点审计"

L "  --- 7.1 引擎到底退没退 ---"
if ($Fact["EngineRunning"]) {
    Note "★ 引擎进程**仍在运行** ⇒ 拦截照旧生效，症状当然不会消失。"
    Note "  正确停法（三选一）：① 控制台窗口按 Ctrl+C；② 直接关掉控制台窗口；"
    Note "  ③ tools\\dskill.exe <引擎pid>（直 syscall，绕得过用户态 hook）。"
    Note "  ⚠️ 点 R3ShieldCore GUI 窗口右上角 X **不会**退出：r3shieldcore_gui.cpp 的 WM_CLOSE 是 SW_MINIMIZE。"
    Note "  ⚠️ self_protect=1 时任务管理器 / taskkill 杀不掉它（NtOpenProcess 剥掉了 PROCESS_TERMINATE）。"
} else {
    Note "引擎进程已不在运行。"
    if ($Fact["InjectedProcCount"] -gt 0) {
        Note ("  但仍有 " + $Fact["InjectedProcCount"] + " 个进程加载着 lib.dll（见 S1）—— 见 7.2。")
    } else {
        Note "  且已无进程加载 lib.dll ⇒ 注入面已经彻底清干净（见 7.3 持久化审计）。"
    }
}

L "  --- 7.2 残留注入：引擎已退，hook 未必已撤 ---"
Note "机制：被注入进程里有一个线程 `WaitForSingleObject(引擎进程句柄, INFINITE)`，"
Note "      引擎**真的退出**后它才醒来执行 `UninitSession()` → `MH_DisableHook(MH_ALL_HOOKS)`。"
Note "      （customization_session.cpp:220-230 / 232-281）。"
Note "      引擎侧 `GlobalHookSessionEnd`（main.cpp:238）**只关自己的日志/通道/UI，"
Note "      从不逐个通知被注入进程** —— 所以「停引擎」与「hook 真的停掉」之间有延迟，"
Note "      而且只在那个进程还能正常调度时才做得到。"
if ($Fact["InjectedProcCount"] -gt 0) {
    Note ("★ 当前仍有 " + $Fact["InjectedProcCount"] + " 个进程带着 lib.dll 在跑。")
    Note "  判定：引擎已退 + 该进程启动时间**早于**引擎最后活动时间 ⇒ 它属于「残留」。"
    Note "  处置：**重启这些进程**（关掉再打开）即可让它们以未注入的状态重来；"
    Note "        不重启的话，即使引擎没了，它们也会继续按关闭前最后一次的 policy->Mode 执行判定。"
} else {
    Note "✔ 没有进程加载 lib.dll ⇒ 没有残留注入面。"
}

L "  --- 7.3 持久化注入点审计（决定「重启电脑后还会不会复发」）---"
Note "判定口径：只有**指向 R3ShieldCore 自己**（r3shieldcore / lib.dll / superdesk）的条目，"
Note "          才算「引擎会跟着开机复发」。"
Note "          单纯「路径落在 AppData/ProgramData/Desktop」是**另一个话题**（用户可写路径的服务/驱动），"
Note "          下面单独统计、不计入引擎复发项 —— 否则 Defender / Battle.net / 百度网盘之类会把它淹掉。"
$markers      = 'r3shieldcore|lib\.dll|superdesk'
$markersBroad = 'r3shieldcore|lib\.dll|superdesk|\\AppData\\|\\Temp\\|\\Desktop\\|\\Downloads\\|\\ProgramData\\'
$script:persistHits = 0
function CheckReg {
    param([string]$RegPath, [string]$Name, [string]$Label, [string]$Pattern)
    if (-not $Pattern) { $Pattern = $script:markersBroad }
    $v = $null
    try { $v = (Get-ItemProperty -LiteralPath $RegPath -Name $Name -ErrorAction Stop).$Name } catch {
        Note ($Label.PadRight(30) + " = (未设置 / 无权读取)"); return
    }
    if ($null -eq $v) { Note ($Label.PadRight(30) + " = (未设置)"); return }
    $s = ($v -join " | ").Trim()
    if ($s -eq "") { Note ($Label.PadRight(30) + " = (空)"); return }
    $flag = ""
    if ($s -match $Pattern) { $flag = "   ★可疑"; $script:persistHits++ }
    Note ($Label.PadRight(30) + " = " + $s + $flag)
}
CheckReg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' 'AppInit_DLLs' 'AppInit_DLLs(HKLM)'
CheckReg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' 'LoadAppInit_DLLs' 'LoadAppInit_DLLs'
CheckReg 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows' 'AppInit_DLLs' 'AppInit_DLLs(HKLM WOW64)'
CheckReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'BootExecute' 'BootExecute'
CheckReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'SetupExecute' 'SetupExecute'
CheckReg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Shell' 'Winlogon Shell'
CheckReg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Userinit' 'Winlogon Userinit'
CheckReg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AppSetup' 'Winlogon AppSetup'
CheckReg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'VmApplet' 'Winlogon VmApplet'
CheckReg 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows' 'Load' 'HKCU Windows Load'
CheckReg 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows' 'Run' 'HKCU Windows Run'

# AppCertDlls（多值）
$appCertShown = 0
try {
    $k = Get-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls' -ErrorAction Stop
    foreach ($n in $k.GetValueNames()) {
        $v = "$($k.GetValue($n))"
        $flag = ""
        if ($v -match $script:markersBroad) { $flag = "   ★可疑"; $script:persistHits++ }
        Note ("AppCertDlls[" + $n + "]".PadRight(30) + " = " + $v + $flag)
        $appCertShown++
    }
} catch { }
if ($appCertShown -eq 0) { Note "AppCertDlls                    = (未设置 / 无权读取)" }

# IFEO Debugger：只报可疑的（正常 IFEO 条目很多，全列会淹掉信号）
$suspIfeo = 0
try {
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction Stop |
        ForEach-Object {
            $d = $null
            try { $d = (Get-ItemProperty -LiteralPath $_.PSPath -Name Debugger -ErrorAction Stop).Debugger } catch { }
            if ($d -and $d -match $script:markersBroad) {
                $suspIfeo++; $script:persistHits++
                Note ("IFEO[" + $_.PSChildName + "].Debugger".PadRight(30) + " = " + $d + "   ★可疑")
            }
        }
} catch { Note "IFEO 扫描                          = (无权读取，需要管理员)" }
if ($suspIfeo -eq 0) { Note "IFEO Debugger                  = 无可疑项" }

# 服务 ImagePath：只报「引擎相关」的；用户可写路径的另计一项，不算引擎复发
$suspSvc = 0
$suspSvcOther = 0
try {
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction Stop | ForEach-Object {
        $ip = $null
        try { $ip = (Get-ItemProperty -LiteralPath $_.PSPath -Name ImagePath -ErrorAction Stop).ImagePath } catch { }
        if ($ip -and $ip -match $script:markers) {
            $suspSvc++; $script:persistHits++
            Note ("Service[" + $_.PSChildName + "].ImagePath".PadRight(30) + " = " + $ip + "   ★可疑(引擎)")
        } elseif ($ip -and $ip -match $script:markersBroad) {
            $suspSvcOther++
        }
    }
} catch { Note "服务扫描                            = (无权读取，需要管理员)" }
if ($suspSvc -eq 0) { Note "服务 ImagePath                 = 无「引擎相关」项" }
Note ("服务（仅路径可写，与引擎无关）        = " + $suspSvcOther + " 项，已忽略（Defender/Battle.net/网盘等正常软件）")

# 计划任务 XML：只报「引擎相关」的
$suspTask = 0
$suspTaskOther = 0
try {
    Get-ChildItem 'C:\Windows\System32\Tasks' -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $c = $null
        try { $c = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction Stop } catch { }
        if ($c -and $c -match $script:markers) {
            $suspTask++; $script:persistHits++
            Note ("Task".PadRight(30) + " = " + $_.FullName + "   ★可疑(引擎)")
        } elseif ($c -and $c -match $script:markersBroad) {
            $suspTaskOther++
        }
    }
} catch { Note "计划任务扫描                        = (跳过)" }
if ($suspTask -eq 0) { Note "计划任务                      = 无「引擎相关」项" }
Note ("计划任务（仅路径可写，与引擎无关）    = " + $suspTaskOther + " 项，已忽略")

KV "持久化可疑项合计（引擎相关）" $script:persistHits
$Fact["PersistHits"] = $script:persistHits
if ($script:persistHits -eq 0) {
    Note "✔ 未发现**引擎相关**的持久化注入点 ⇒ 重启电脑后引擎不会自动回来，症状只可能来自当前内存里的残留。"
} else {
    Note "⚠️ 发现**引擎相关**的持久化注入点 ⇒ 重启电脑**也会复发**，必须先把这些项清掉再重启。"
}
Note "（本项需要管理员权限才完整；非管理员时 IFEO/服务两项会显示「无权读取」。）"

# ---------------- S8 结论 ----------------
Sec "S8 结论"

$inputDeskOk = ($desk[0] -ieq "Default")
Verdict "H1" "输入桌面被切到安全桌面" `
    ($(if ($inputDeskOk) { "未命中" } else { "命中" })) `
    ("InputDesktop=" + $desk[0])

$cursorFrozen = $false
$cursorEvidence = "未采样（WatchSeconds=0）"
$cursorInconclusive = $false
if ($samples.Count -gt 0 -and $Fact.Contains("CursorPosChanges")) {
    # ★ 必须要求「跨过多个窗口」才敢判冻结 —— 见 S5 里的说明。
    if ($Fact["CursorPosChanges"] -gt 1 -and $Fact["CursorHandleChanges"] -le 1 -and
        $Fact.Contains("UnderWindowChanges") -and $Fact["UnderWindowChanges"] -gt 1) {
        $cursorFrozen = $true
    }
    elseif ($Fact["CursorPosChanges"] -gt 1 -and $Fact["CursorHandleChanges"] -le 1) {
        $cursorInconclusive = $true
    }
    $cursorEvidence = ("位置变化=" + $Fact["CursorPosChanges"] + " 光标句柄变化=" + $Fact["CursorHandleChanges"] +
        " 光标下窗口变化=" + $(if ($Fact.Contains("UnderWindowChanges")) { $Fact["UnderWindowChanges"] } else { "?" }))
    if ($cursorInconclusive) { $cursorEvidence += "  （鼠标没跨窗口 ⇒ 不足以判定冻结）" }
}
Verdict "H2" "光标形状被冻结（WM_SETCURSOR 无人处理）" `
    ($(if ($cursorFrozen) { "命中" } elseif ($cursorInconclusive) { "证据不足（鼠标未跨窗口）" } else { "未命中" })) $cursorEvidence

$capt = 0
if ($Fact.Contains("CaptureHits")) { $capt = $Fact["CaptureHits"] }
Verdict "H3" "有窗口持有鼠标捕获（点击/光标被独吞）" `
    ($(if ($capt -gt 0) { "命中" } else { "未命中" })) ("captureThreads=" + $capt)

$focusZero = $false
$focusNa = $false
if ($Fact.Contains("FgFocus")) { if ($Fact["FgFocus"] -eq "0") { $focusZero = $true } }
# ★ 前台是控制台窗口时 hwndFocus=0 属正常，不能当"焦点丢失"。
if ($focusZero -and $Fact.Contains("FgIsConsole") -and $Fact["FgIsConsole"]) { $focusNa = $true; $focusZero = $false }
Verdict "H4" "前台窗口没有键盘焦点（焦点被夺/未建立）" `
    ($(if ($focusNa) { "不适用（前台是控制台窗口）" } elseif ($focusZero) { "命中" } else { "未命中" })) `
    ("fgHwndFocus=" + $Fact["FgFocus"] + " fgClass=" + $(if ($Fact.Contains("FgClass")) { $Fact["FgClass"] } else { "?" }) +
     $(if ($focusNa) { "  ⇒ 控制台窗口的输入由 conhost 代管，hwndFocus=0 是正常现象；要判 H4 请让**目标程序**处于前台再跑一次" } else { "" }))

$fgIsEngine = $false
if ($engines.Count -gt 0) { foreach ($e in $engines) { if ($e.Id -eq $fgPid) { $fgIsEngine = $true } } }
Verdict "H5" "前台窗口属于引擎自身（抢了前台）" `
    ($(if ($fgIsEngine) { "命中" } else { "未命中" })) ("fgPid=" + $fgPid)

$big = 0
if ($Fact.Contains("BigWindows")) { $big = $Fact["BigWindows"] }
$bigTop = 0
if ($Fact.Contains("BigTopmost")) { $bigTop = $Fact["BigTopmost"] }
$topOver = 0
if ($Fact.Contains("TopmostOverCursor")) { $topOver = $Fact["TopmostOverCursor"] }
Verdict "H6" "存在 TOPMOST 覆盖层压在光标/目标窗口上" `
    ($(if ($topOver -gt 0) { "命中" } else { "未命中" })) `
    ("覆盖光标的 TOPMOST 窗口=" + $topOver + "；大面积可见窗口=" + $big + "（其中 TOPMOST=" + $bigTop + "）")

$lastDelta = 0
$lastEvidence = "未采样（WatchSeconds=0）"
if ($Fact.Contains("LastInputDelta")) {
    $lastDelta = $Fact["LastInputDelta"]
    $lastEvidence = ("LastInputInfo 前进=" + $lastDelta + "ms；光标位置变化=" + $Fact["CursorPosChanges"] + " 次")
}
Verdict "H7" "输入事件未进入系统（GetLastInputInfo 不前进）" `
    ($(if ($WatchSeconds -gt 0 -and $lastDelta -le 0) { "证据不足（也可能观察窗内无人操作）" } else { "未命中" })) $lastEvidence

$kbProbeBlocked = $false
$kbFrozenMs = 0
if ($Fact.Contains("KeyboardStateProbe")) {
    $ksp = [string]$Fact["KeyboardStateProbe"]
    # 主判据 = 出现过 FALSE（falseCount 不为 0）；err=5 只是"被引擎拒"的旁证。
    # 只看 err=5 会漏掉"hook 直接返 FALSE 但没设 LastError"的实现。
    if ($ksp -notmatch "falseCount=0/") { $kbProbeBlocked = $true }
    if ($ksp -match "msAtTrip=(\d+)") { $kbFrozenMs = [int]$Matches[1] }
}
Verdict "H8" "引擎吞掉键盘状态（GetKeyboardState 密度触发后被拒/被阻塞）" `
    ($(if ($kbProbeBlocked -or $kbFrozenMs -ge 500) { "命中" } else { "未命中" })) ($Fact["KeyboardStateProbe"])

$hookBlocked = $false
if ($Fact.Contains("SetHookProbe")) { if ([string]$Fact["SetHookProbe"] -match "FAIL") { $hookBlocked = $true } }
Verdict "H9" "引擎拒绝应用安装输入钩子（SetWindowsHookEx 失败，常见 err=5）" `
    ($(if ($hookBlocked) { "命中" } else { "未命中" })) ($Fact["SetHookProbe"])

$rawBlocked = $false
$rawNote = ""
if ($Fact.Contains("RawInputProbe")) {
    $rip = [string]$Fact["RawInputProbe"]
    if ($rip -match "FAIL err=5") { $rawBlocked = $true; $rawNote = "被引擎 hook 拒（err=5=ACCESS_DENIED）" }
    elseif ($rip -match "err=87") { $rawNote = "err=87=ERROR_INVALID_PARAMETER（探针自身参数问题，不代表引擎拦截）" }
    elseif ($rip -match "FAIL") { $rawBlocked = $true; $rawNote = "注册失败（非 87，需看具体 err）" }
    else { $rawNote = "正常" }
}
Verdict "H10" "引擎拒绝原始输入注册（RIDEV_INPUTSINK 注册失败）" `
    ($(if ($rawBlocked) { "命中" } else { "未命中" })) ($Fact["RawInputProbe"] + "  => " + $rawNote)

$fkOn = $false
if ($Fact.Contains("FilterKeysActive")) { if ($Fact["FilterKeysActive"] -eq 1) { $fkOn = $true } }
$skOn = $false
if ($Fact.Contains("StickyKeysActive")) { if ($Fact["StickyKeysActive"] -eq 1) { $skOn = $true } }
Verdict "H11" "辅助功能（筛选键/粘滞键）已开启导致键盘迟钝" `
    ($(if ($fkOn -or $skOn) { "命中" } else { "未命中" })) `
    ("FilterKeys生效=" + $Fact["FilterKeysActive"] + " StickyKeys生效=" + $Fact["StickyKeysActive"] + "  [" + $Fact["Accessibility"] + "]")

$modeBlocking = ($mode -eq "block" -or $mode -eq "block_all" -or $mode -eq "block_all_safe" -or $mode -eq "ask")
Verdict "H12" "引擎处于会拦截的模式（block / block_all / ask）" `
    ($(if ($modeBlocking) { "命中" } else { "未命中" })) ("mode=" + $mode)

$engineRunning = $false
if ($Fact.Contains("EngineRunning")) { $engineRunning = $Fact["EngineRunning"] }
$guiMin = $false
if ($Fact.Contains("EngineGuiMinimized")) { $guiMin = $Fact["EngineGuiMinimized"] }
Verdict "H13" "引擎其实没退出（点 X 只是最小化 / taskkill 被自我保护挡）" `
    ($(if ($engineRunning) { "命中" } else { "未命中" })) `
    ("引擎进程在运行=" + $engineRunning + "；其 GUI 处于最小化=" + $guiMin)

$injCount = 0
if ($Fact.Contains("InjectedProcCount")) { $injCount = $Fact["InjectedProcCount"] }
Verdict "H14" "引擎已退但仍有进程带着 lib.dll 残留（hook 未撤）" `
    ($(if ((-not $engineRunning) -and $injCount -gt 0) { "命中" } else { "未命中" })) `
    ("引擎在运行=" + $engineRunning + "；仍加载 lib.dll 的进程数=" + $injCount)

$persistHits = 0
if ($Fact.Contains("PersistHits")) { $persistHits = $Fact["PersistHits"] }
Verdict "H15" "存在**引擎相关**的持久化注入点（重启电脑也会复发）" `
    ($(if ($persistHits -gt 0) { "命中" } else { "未命中" })) `
    ("引擎相关持久化可疑项=" + $persistHits + "（用户可写路径的服务/驱动不计入）")

$bandUiAccess = 0
if ($Fact.Contains("BandUiAccess")) { $bandUiAccess = $Fact["BandUiAccess"] }
$bandUiAccessRelevant = 0
if ($Fact.Contains("BandUiAccessRelevant")) { $bandUiAccessRelevant = $Fact["BandUiAccessRelevant"] }
$bandReadable = 0
if ($Fact.Contains("BandReadable")) { $bandReadable = $Fact["BandReadable"] }
$bandOther = 0
if ($Fact.Contains("BandOther")) { $bandOther = $Fact["BandOther"] }
Verdict "H16" "存在「可见且够大」的 band=2 窗口 —— 超级置顶残留嫌疑" `
    ($(if ($bandReadable -eq 0) { "无法判定（GetWindowBand 不可用）" } elseif ($bandUiAccessRelevant -gt 0) { "命中" } else { "未命中" })) `
    ("可见且面积>=1%屏的 band=2 窗口=" + $bandUiAccessRelevant + "；band=2 总数=" + $bandUiAccess +
     "（AMD 驱动/IME 也占 band=2，故必须叠加可见+尺寸才作数）；已扫描 " + $bandReadable + " 个")

L ""
L "--- 判定汇总 ---"
foreach ($v in $Verdicts) {
    L ("  [" + $v.Id.PadRight(3) + "] " + $v.Name.PadRight(38) + " => " + $v.State)
    L ("        证据: " + $v.Evidence)
}

L ""
L "--- 最可能根因排序（按证据强度）---"
$rank = 0
if ($engineRunning) { $rank++; L ("  " + $rank + ". 【引擎还在跑】拦截仍在生效 —— 症状不可能因为「以为停了」而消失。按 7.1 的三条正确停法之一再试。") }
if ((-not $engineRunning) -and $injCount -gt 0) { $rank++; L ("  " + $rank + ". 【残留注入】引擎已退，但仍有 " + $injCount + " 个进程带着 lib.dll 在跑 ⇒ 必须**重启这些进程**，它们不会自己立刻变干净。") }
if ($persistHits -gt 0) { $rank++; L ("  " + $rank + ". 【引擎持久化】有 " + $persistHits + " 项**指向 R3ShieldCore 自己**的持久化条目 ⇒ 重启电脑也会复发，先清掉再重启。") }
if ($bandUiAccessRelevant -gt 0) { $rank++; L ("  " + $rank + ". 【超级置顶残留】有 " + $bandUiAccessRelevant + " 个「可见且面积>=1%屏」的 band=2 窗口。") ; L "     普通软件只把不可见小窗口放进这个波段（AMD 驱动/IME），可见的大窗口与之行为吻合。" ; L "     处置：把 S3 band 那一节标 ★ 的 pid 全部杀掉，再看输入是否立刻恢复。" }
if ($capt -gt 0) { $rank++; L ("  " + $rank + ". 【鼠标捕获未释放】有 " + $capt + " 个 GUI 线程持有 hwndCapture —— 直接解释「点击无效 + 光标冻结」，与引擎无关，处置是结束持有捕获的那个进程。") }
if ($cursorFrozen) { $rank++; L ("  " + $rank + ". 【光标冻结】鼠标在动但光标句柄不变 —— 光标下窗口的线程没有处理 WM_SETCURSOR（通常是该线程被阻塞/卡死）。") }
if ($kbFrozenMs -ge 500) { $rank++; L ("  " + $rank + ". 【应用线程被询问阻塞】GetKeyboardState 单次调用被阻塞 " + $kbFrozenMs + " ms ⇒ 该应用的 UI 线程在此期间完全不处理消息（键盘无响应 + 光标形状冻结）。") }
if ($kbProbeBlocked) { $rank++; L ("  " + $rank + ". 【引擎吞键盘状态】GetKeyboardState 密度触发后返回 FALSE/err=5 —— 该进程内所有依赖键盘状态的输入处理都会失效。") }
if ($hookBlocked) { $rank++; L ("  " + $rank + ". 【引擎拒绝装钩子】应用级热键/输入法辅助钩子装不上。") }
if ($rawBlocked) { $rank++; L ("  " + $rank + ". 【引擎拒绝原始输入】依赖 RawInput 的程序收不到键鼠。") }
if (-not $inputDeskOk) { $rank++; L ("  " + $rank + ". 【输入桌面异常】当前输入桌面 = " + $desk[0] + "，不是 Default。") }
if ($focusZero) { $rank++; L ("  " + $rank + ". 【前台无键盘焦点】目标窗口队列里 hwndFocus=0。") }
if ($topOver -gt 0) { $rank++; L ("  " + $rank + ". 【TOPMOST 覆盖层】有 " + $topOver + " 个可见 TOPMOST 窗口压在光标位置上 —— 确认它是否挡住了目标输入框/是否点击穿透。") }
if ($rank -eq 0) { L "  未发现明确的软件层根因。先确认「这次有没有真的抓到症状」—— 看上面两项：" ; L "    · under_win_chg / 采样期间光标下窗口变化数 = 1  ⇒ 鼠标没跨过窗口，光标形状本就不该变；" ; L "    · 加了 -TargetApp 时 target_fg_samples = 0 ⇒ 目标程序全程没到前台，判定对象错了。" ; L "  两者任一成立 ⇒ 这次报告对目标程序无效，请加 -TargetApp 重跑，并真的去点目标程序。" }

L ""
L "--- 处置阶梯（「停引擎也没好」按这个顺序走）---"
L "  0. 先看 7.1：引擎进程到底还在不在。点 GUI 的 X 只是最小化；self_protect=1 时"
L "     任务管理器/taskkill 也杀不掉 —— 用控制台 Ctrl+C、关控制台窗口、或 tools\dskill.exe <pid>。"
L "  1. 再看 7.2：引擎退了但还有进程带着 lib.dll ⇒ **重启这些进程**（关掉再打开）。"
L "     它们要等「引擎进程句柄」唤醒自清理线程才 MH_DisableHook，进程卡住就等不到。"
L "  2. ★ 若 H16 命中（有「可见且够大」的 band=2 窗口）⇒ 这是「超级置顶」留下的 UIAccess 波段窗口。"
L "     把 S3 band 一节列出的 pid 全部杀掉，立刻再试键盘；能恢复就是它。"
L "     这一条正对应你说的「不用超级置顶的输入是好的」。"
L "  3. 重启进程后仍复现 ⇒ 注销/重启电脑。"
L "  4. 重启电脑后**仍**复现 ⇒ 跑 7.3 持久化审计（AppInit_DLLs / IFEO / Winlogon / 服务 / 计划任务），"
L "     那里命中的项才是「每次开机都复发」的原因。"
L "  5. 若 H3（鼠标捕获）/ H4（无焦点）/ H6（TOPMOST 覆盖）/ H1（输入桌面非 Default）命中 ⇒"
L "     根因**不在**引擎，停引擎当然没用：捕获要结束持有它的进程，桌面被切要注销会话。"
L "     ⚠️ 注意 H4 的豁免：前台是控制台窗口时 hwndFocus=0 属正常，必须用 -TargetApp 才作数。"
L "  6. 若 H8/H9/H10 命中（引擎 hook 在吞输入）⇒ 把 ini 的 mode 改 log、hook_input=0 重启引擎做二分。"
L "  7. 取「对照样本」：症状不在时跑一遍同样的脚本（同样的 -TargetApp），"
L "     比较 S2/S2.5/S3/S4/S6/S7 的差异 —— 差异项才是引入者。"

# ==================================================================
# 3. 输出
# ==================================================================

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$stamp = $Now.ToString("yyyyMMdd-HHmmss")
$txtPath = Join-Path $OutDir ("diag-input-focus-" + $stamp + ".txt")
$jsonPath = Join-Path $OutDir ("diag-input-focus-" + $stamp + ".json")

$text = ($ReportLines -join "`r`n")
[System.IO.File]::WriteAllText($txtPath, $text, (New-Object System.Text.UTF8Encoding($true)))

$Fact["Verdicts"] = @($Verdicts | ForEach-Object { ($_.Id + " " + $_.Name + " => " + $_.State) })
$Fact["Report"] = $txtPath
try {
    $json = $Fact | ConvertTo-Json -Depth 5
    [System.IO.File]::WriteAllText($jsonPath, $json, (New-Object System.Text.UTF8Encoding($true)))
} catch { }

# 控制台只输出 ASCII，避免代码页问题（用 Write-Output，便于被上层捕获）
function Fmt {
    param($V)
    if ($null -eq $V -or "$V" -eq "") { return "n/a" }
    return "$V"
}
Write-Output ""
Write-Output "=== diag-input-focus summary (ASCII) ==="
Write-Output ("engine_running    : " + (Fmt $Fact["EngineRunning"]))
Write-Output ("self_injected     : " + (Fmt $Fact["SelfInjected"]))
Write-Output ("input_desktop     : " + (Fmt $Fact["InputDesktop"]))
Write-Output ("mode              : " + (Fmt $Fact["Mode"]))
Write-Output ("cursor            : " + (Fmt $Fact["CursorName"]))
Write-Output ("capture_threads   : " + (Fmt $Fact["CaptureHits"]))
Write-Output ("topmost_over_cur  : " + (Fmt $Fact["TopmostOverCursor"]))
Write-Output ("big_windows/top   : " + (Fmt $Fact["BigWindows"]) + "/" + (Fmt $Fact["BigTopmost"]))
Write-Output ("band2_visible_big: " + (Fmt $Fact["BandUiAccessRelevant"]) + "  (band-2 windows that are visible AND >=1% screen = super-topmost suspect)")
Write-Output ("band2_total      : " + (Fmt $Fact["BandUiAccess"]) + "  (AMD driver / IME also use band 2 with tiny hidden windows)")
Write-Output ("filterkeys/sticky : " + (Fmt $Fact["FilterKeysActive"]) + "/" + (Fmt $Fact["StickyKeysActive"]))
Write-Output ("cursor_pos_chg    : " + (Fmt $Fact["CursorPosChanges"]))
Write-Output ("cursor_handle_chg : " + (Fmt $Fact["CursorHandleChanges"]))
Write-Output ("under_win_chg     : " + (Fmt $Fact["UnderWindowChanges"]) + "  (0/1 => cursor never crossed a window; H2 cannot be judged)")
Write-Output ("fg_changes        : " + (Fmt $Fact["ForegroundChanges"]))
Write-Output ("target_app        : " + $(if ($TargetApp -eq "") { "(not set -- focus/cursor may be measured on THIS console)" } else { $TargetApp }))
if ($TargetApp -ne "") { Write-Output ("target_fg_samples : " + (Fmt $Fact["TargetFgSamples"]) + "  (0 => the target never became foreground; H2/H4 are void for it)") }
Write-Output ("lastinput_delta   : " + (Fmt $Fact["LastInputDelta"]))
Write-Output ("kbstate_probe     : " + (Fmt $Fact["KeyboardStateProbe"]))
Write-Output ("sethook_probe     : " + (Fmt $Fact["SetHookProbe"]))
Write-Output ("rawinput_probe    : " + (Fmt $Fact["RawInputProbe"]))
Write-Output ""
Write-Output "--- H1..H16 verdicts (Chinese; see the report for full evidence) ---"
foreach ($v in $Verdicts) { Write-Output ("  " + $v.Id + " " + $v.State) }

# ASCII 版关键结论：任何代码页下都能读
$hitIds = @()
foreach ($v in $Verdicts) { if ($v.State -eq "命中") { $hitIds += $v.Id } }
Write-Output ""
Write-Output "--- KEY RESULT (ASCII) ---"
if ($hitIds.Count -eq 0) {
    Write-Output " HITS: none"
    Write-Output " => No software-layer root cause found in this run."
    Write-Output "    Most common reason: the symptom was NOT present while this ran,"
    Write-Output "    or the measurement landed on this console instead of the app."
    Write-Output "    Re-run WITH -TargetApp <name-or-pid> WHILE the symptom is happening."
} else {
    Write-Output (" HITS: " + ($hitIds -join ", "))
    Write-Output " => Open the report below and read the section for each hit id."
    if ($hitIds -contains "H16") {
        Write-Output "    H16 = a visible, screen-sized window sits in band 2. That is the"
        Write-Output "    super-topmost suspect. Kill the pids marked * in the S3 band"
        Write-Output "    section, then test the keyboard again immediately."
    }
}
Write-Output ""
Write-Output "============================================================"
Write-Output " FULL REPORT (Chinese, open with Notepad / VSCode):"
Write-Output ("   " + $txtPath)
Write-Output (" JSON: " + $jsonPath)
Write-Output "============================================================"
Write-Output ""

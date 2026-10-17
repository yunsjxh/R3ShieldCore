// tray_icon.h —— 系统托盘（通知区）图标：**关闭窗口 = 收进托盘**的共享实现。
//
//   为什么抽成共享头（铁律 127）：
//     主程序（`R3 Shield Core.exe`）与配置工具（`r3shieldcore-cfg.exe`）
//     **都要**"关闭窗口不退出、收进托盘"这一套。各写一份的后果是两边行为
//     慢慢分叉（回调消息 id 撞车、图标 id 撞车、菜单项不一致），
//     而且这些差异**不会报错**，只有用户看得见。
//
//   提供三件事：
//     · `TrayIcon` —— 一条 RAII 生命周期的托盘图标（NIM_ADD/NIM_DELETE）；
//     · `TrayMenuAction` / `TrayMenuFromCommand` —— 菜单项 id 的**唯一映射**；
//     · `FormatTrayTip` —— 托盘提示文字（带长度截断，见下）。
//
//   ★★ 为什么"关闭 = 收进托盘"要配一个**托盘右键菜单**（而不是只用一个图标）：
//     窗口藏起来之后，**看不出它还在跑**。如果没有一个显式的"退出"入口，
//     用户就只剩任务管理器强杀这一条路 —— 那正是"关不掉的程序"的观感，
//     而且强杀会跳过引擎的收尾（铁律 107：强杀测不出收尾）。
//     ⇒ 菜单里必须有「显示窗口」与「退出」两项，退出还要二次确认。
//
//   ★★ 图标 id 与回调消息必须**每个进程各不相同**：
//     托盘回调消息用 `RegisterWindowMessageW` 注册（幂等，跨进程同串得同 id）——
//     这正是我们**不**希望"共享"的地方：两个 exe 各用各的字符串，
//     否则同一台机器上两个进程会收到同一个消息 id（虽然 hwnd 不同、不会串，
//     但排查时看不出是谁的）。见 `kTrayCallbackMessageA/B`。
//
//   本头只依赖 Win32（两个 exe 都能直接 #include）。
#pragma once
#ifndef R3SHIELDCORE_TRAY_ICON_H
#define R3SHIELDCORE_TRAY_ICON_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>
#include <string>

namespace R3ShieldCoreTray {

// ---------------------------------------------------------------------------
//  托盘回调消息名
// ---------------------------------------------------------------------------
//
//   ★ 两个 exe 用**不同**的字符串（各注册各的）。理由见文件头。
constexpr wchar_t kCallbackMessageMain[] = L"R3ShieldCore.TrayIcon.Main";
constexpr wchar_t kCallbackMessageCfg[]  = L"R3ShieldCore.TrayIcon.Cfg";

//  托盘图标自身的 id（只在本进程内有效；两个 exe 都用 1 也没关系，
//  因为它们各自有独立的托盘图标表 —— 真正要区分的是上面的**消息名**）。
constexpr UINT kIconId = 1;

//  ★★ 代次标记（v82）：给发布闸门 `check_dist_sync.sh` 查"托盘这套代码真的
//     编进了 exe"用的**宽**字符串。
//
//     为什么必须是**宽**串：闸门用 `strings -el`（UTF-16LE）查它。而
//     `printf("[tray] ... 托盘图标已就绪 ...")` 里的中文是**窄**字面量
//     （按 CP936 存成 GBK 字节），`strings -el` **永远查不到**；
//     用 `strings -a` 也会因为前后是 ASCII 而被切碎（实测过）。
//     ⇒ 把标记单独做成宽串常量，闸门只查它，不碰日志文本本身。
//     （这跟 v80/v81 的 `R3SHIELDCORE_PREVIEW_*` 是同一套做法。）
constexpr wchar_t kGenerationMarker[] = L"R3ShieldCoreTray.v82";

inline UINT CallbackMessageId(const wchar_t* name) {
	// static：注册一次就够（幂等）。按名字缓存，避免重复哈希查找。
	// ★ 这里只会有两个不同的名字，用两个 static 足够，不必上 map。
	static const UINT idMain = ::RegisterWindowMessageW(kCallbackMessageMain);
	static const UINT idCfg  = ::RegisterWindowMessageW(kCallbackMessageCfg);
	return (name == kCallbackMessageCfg) ? idCfg : idMain;
}

// ---------------------------------------------------------------------------
//  菜单项 —— id 的**唯一映射**（别在 WndProc 里写裸数字）
// ---------------------------------------------------------------------------
enum class TrayMenuAction : UINT {
	None = 0,
	ShowWindow,
	ToggleEngine,     // 仅主程序用：退出/启动引擎
	ToggleUi,         // 仅主程序用：界面风格（液态玻璃 ⇄ 经典）
	Exit,
};

//  菜单项用的命令 id（WM_COMMAND 的 LOWORD）。故意从一个不容易撞的基数起，
//  免得和窗口自身的控件 id 冲突。
constexpr UINT kCmdBase        = 0x7E00;
constexpr UINT kCmdShowWindow  = kCmdBase + 1;
constexpr UINT kCmdToggleEngine= kCmdBase + 2;
constexpr UINT kCmdExit        = kCmdBase + 3;
constexpr UINT kCmdToggleUi    = kCmdBase + 4;

//  命令 id -> 语义。**取反必须是 None**（下面 TrayMenuFromCommand 也查它）。
inline TrayMenuAction TrayMenuFromCommand(UINT cmd) {
	switch (cmd) {
	case kCmdShowWindow:   return TrayMenuAction::ShowWindow;
	case kCmdToggleEngine: return TrayMenuAction::ToggleEngine;
	case kCmdToggleUi:     return TrayMenuAction::ToggleUi;
	case kCmdExit:         return TrayMenuAction::Exit;
	default:               return TrayMenuAction::None;
	}
}

//  action -> 命令 id。给"要往菜单里加哪几项"用。
inline UINT CommandFromTrayMenu(TrayMenuAction a) {
	switch (a) {
	case TrayMenuAction::ShowWindow:   return kCmdShowWindow;
	case TrayMenuAction::ToggleEngine: return kCmdToggleEngine;
	case TrayMenuAction::ToggleUi:     return kCmdToggleUi;
	case TrayMenuAction::Exit:         return kCmdExit;
	default:                           return 0;
	}
}

// ---------------------------------------------------------------------------
//  托盘提示（气泡 + 悬停）
// ---------------------------------------------------------------------------
//
//   ★ `NOTIFYICONDATA.szTip` 只有 128 个 wchar（含结尾）⇒ **超长会被静默截断**。
//     这里显式截断并保证结尾，免得把一句中文从中间劈开变成乱码
//     （本项目吃过"静默截断"的亏，铁律 55/252 家族）。
constexpr size_t kMaxTipChars = 127;   // 128 - 1（结尾 NUL）

inline std::wstring FormatTrayTip(const std::wstring& text) {
	if (text.size() <= kMaxTipChars) {
		return text;
	}
	return text.substr(0, kMaxTipChars);
}

// ---------------------------------------------------------------------------
//  TrayIcon —— 一条 RAII 的托盘图标
// ---------------------------------------------------------------------------
class TrayIcon {
public:
	TrayIcon() = default;
	~TrayIcon() { Remove(); }

	TrayIcon(const TrayIcon&) = delete;
	TrayIcon& operator=(const TrayIcon&) = delete;

	// 添加图标。`icon` 为 nullptr 时用 `LoadIcon(nullptr, IDI_APPLICATION)` 兜底
	// （★ 调用方应当传**自己 exe 的资源图标** —— 传 nullptr 只会得到系统默认图标，
	//   与 class 图标那段注释是同一件事）。
	//
	// 返回 false 表示**没加上**：调用方要知道这一点 —— 没加上还去 `SW_HIDE`
	// 的话，窗口从任务栏和托盘**同时**消失 = 用户彻底找不到它（最坏的结果）。
	bool Add(HWND owner, HICON icon, const std::wstring& tip, const wchar_t* callbackName) {
		if (m_added || !owner) {
			return m_added;
		}
		m_owner = owner;
		m_callbackMessage = CallbackMessageId(callbackName);
		m_icon = icon ? icon : ::LoadIconW(nullptr, IDI_APPLICATION);

		NOTIFYICONDATAW nid = {};
		nid.cbSize = sizeof(nid);
		nid.hWnd = owner;
		nid.uID = kIconId;
		nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
		nid.uCallbackMessage = m_callbackMessage;
		nid.hIcon = m_icon;
		// ★ 用 FormatTrayTip 而不是 wcsncpy_s 硬拷：超长会被静默截断（见上）。
		const std::wstring safe = FormatTrayTip(tip);
		wcsncpy_s(nid.szTip, safe.c_str(), _TRUNCATE);

		if (!::Shell_NotifyIconW(NIM_ADD, &nid)) {
			return false;
		}
		// ★ v4+ 的行为位：没有它，任务栏重启（explorer 崩溃重开）后图标**不会回来**。
		//   设了它，explorer 会重新向所有顶层窗口广播 TaskbarCreated。
		//   ⚠️ 这条**必须在 NIM_ADD 成功之后**再发 —— 对不存在的图标设版本号会失败。
		nid.uVersion = NOTIFYICON_VERSION_4;
		::Shell_NotifyIconW(NIM_SETVERSION, &nid);

		m_added = true;
		return true;
	}

	// 更新提示文字（状态变了要跟着变，否则用户看到的是过期的信息 —— 铁律 97）。
	void SetTip(const std::wstring& tip) {
		if (!m_added) {
			return;
		}
		NOTIFYICONDATAW nid = {};
		nid.cbSize = sizeof(nid);
		nid.hWnd = m_owner;
		nid.uID = kIconId;
		nid.uFlags = NIF_TIP;
		const std::wstring safe = FormatTrayTip(tip);
		wcsncpy_s(nid.szTip, safe.c_str(), _TRUNCATE);
		::Shell_NotifyIconW(NIM_MODIFY, &nid);
	}

	// 换图标（主程序用它区分"引擎在跑/已停"）。
	void SetIcon(HICON icon) {
		if (!m_added || !icon) {
			return;
		}
		m_icon = icon;
		NOTIFYICONDATAW nid = {};
		nid.cbSize = sizeof(nid);
		nid.hWnd = m_owner;
		nid.uID = kIconId;
		nid.uFlags = NIF_ICON;
		nid.hIcon = icon;
		::Shell_NotifyIconW(NIM_MODIFY, &nid);
	}

	// 弹气泡。★ 只在**真的发生了用户需要知道的事**时用（本项目的用法：
	// "窗口已收进托盘，监控仍在运行"）—— 滥用气泡会让人关掉通知，
	// 而那时真正要紧的一条也一起被关掉了。
	void Balloon(const std::wstring& title, const std::wstring& text,
		DWORD infoFlags = NIIF_INFO) {
		if (!m_added) {
			return;
		}
		NOTIFYICONDATAW nid = {};
		nid.cbSize = sizeof(nid);
		nid.hWnd = m_owner;
		nid.uID = kIconId;
		nid.uFlags = NIF_INFO;
		nid.dwInfoFlags = infoFlags;
		wcsncpy_s(nid.szInfoTitle, FormatTrayTip(title).c_str(), _TRUNCATE);
		// szInfo 是 256 个 wchar，比 szTip 宽 —— 仍然显式截断。
		const std::wstring body = (text.size() <= 255) ? text : text.substr(0, 255);
		wcsncpy_s(nid.szInfo, body.c_str(), _TRUNCATE);
		::Shell_NotifyIconW(NIM_MODIFY, &nid);
	}

	void Remove() {
		if (!m_added) {
			return;
		}
		NOTIFYICONDATAW nid = {};
		nid.cbSize = sizeof(nid);
		nid.hWnd = m_owner;
		nid.uID = kIconId;
		::Shell_NotifyIconW(NIM_DELETE, &nid);
		m_added = false;
	}

	bool added() const { return m_added; }
	UINT callbackMessage() const { return m_callbackMessage; }

private:
	HWND  m_owner = nullptr;
	HICON m_icon = nullptr;
	UINT  m_callbackMessage = 0;
	bool  m_added = false;
};

// ---------------------------------------------------------------------------
//  菜单：在光标处弹出，返回用户选了哪一项（取消 = None）
// ---------------------------------------------------------------------------
//
//   ★★ 弹菜单前必须 `SetForegroundWindow(owner)`，弹完必须 `PostMessage(WM_NULL)`。
//      这是 Win32 的一条**没写在文档正文里**的规矩：不这么做，菜单点完之后
//      **不会消失**（它拿不到失去焦点的通知），得再点一下别处才走。
//      这个 bug 只在"真的用鼠标点过"时才看得见 —— 自动化点不出来（铁律 24/28）。
//
//   `extraItems` 里可以塞调用方自己的项（主程序用「退出引擎」）。
inline TrayMenuAction ShowTrayMenu(HWND owner, const std::wstring& showLabel,
	bool withToggleEngine, const std::wstring& toggleEngineLabel,
	const std::wstring& uiLabel = std::wstring()) {
	HMENU menu = ::CreatePopupMenu();
	if (!menu) {
		return TrayMenuAction::None;
	}
	::AppendMenuW(menu, MF_STRING, kCmdShowWindow, showLabel.c_str());
	if (withToggleEngine && !toggleEngineLabel.empty()) {
		::AppendMenuW(menu, MF_STRING, kCmdToggleEngine, toggleEngineLabel.c_str());
	}
	if (!uiLabel.empty()) {
		::AppendMenuW(menu, MF_STRING, kCmdToggleUi, uiLabel.c_str());
	}
	::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
	::AppendMenuW(menu, MF_STRING, kCmdExit, L"退出");

	POINT pt = {};
	::GetCursorPos(&pt);

	::SetForegroundWindow(owner);
	const UINT cmd = ::TrackPopupMenu(menu,
		TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY,
		pt.x, pt.y, 0, owner, nullptr);
	// ★ 上面那条规矩的第二步。少了它菜单不消失（见函数头注释）。
	::PostMessageW(owner, WM_NULL, 0, 0);

	::DestroyMenu(menu);
	return TrayMenuFromCommand(cmd);
}

}  // namespace R3ShieldCoreTray

#endif  // R3SHIELDCORE_TRAY_ICON_H

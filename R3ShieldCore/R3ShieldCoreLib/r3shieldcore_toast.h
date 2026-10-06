#pragma once

#include <r3shieldcore/r3shieldcore_shared.h>

//
// 右下角通知卡片。
//
// 与之前的居中 TaskDialog 不同：通知不抢焦点、不阻塞、可以同时存在多个，
// 纵向堆叠在任务栏上方。用户点击按钮后结论通过回调返回给 UI 线程。
//
// 设计约束：
//   - 一个线程独占一个窗口类；消息泵在这里自己跑（UI 线程需要在等结论时
//     继续泵消息，否则卡片上的按钮点不动）。
//   - 卡片数量上限 4，超出时最旧的一张自动按兜底结论收掉。
//
namespace R3ShieldCoreToast
{
	enum class Action
	{
		None = 0,        // 还没点
		Allow,           // 允许这一次
		Deny,            // 拒绝这一次
		AllowAlways,     // 始终允许此程序
		DenyAlways,      // 始终拒绝此程序
		Expired,         // 倒计时走完
	};

	struct Request
	{
		const WCHAR* Title;          // 主标题，如 "chrome.exe 想要修改注册表"
		const WCHAR* Operation;      // 操作名，如 "SetValueKey" / "CreateFile"
		const WCHAR* Target;         // 键路径 / 文件路径 / 镜像路径 / .sys 路径 / 远端地址
		const WCHAR* Extra;          // 值名 / hive 文件 / 服务名（可空）
		const WCHAR* NetDetail;      // 网络事件专用：端口/协议/本端端点（可空）
		const WCHAR* ProcessPath;    // 完整镜像路径
		ULONG ProcessId;
		ULONG ObjectType;            // R3ShieldCore::ObjectType —— 决定字段标签
		ULONG TargetProcessId;       // 进程/线程事件的 pid（可空）
		bool IsHive;                 // true = hive 级操作，措辞不同
		bool IsFile;                 // true = 文件操作，字段标签用「文件」
		bool IsHighRisk;             // true = 命中高危规则，卡片用警示配色
		ULONG TimeoutMs;             // 0 = 不自动关闭
		R3ShieldCore::Verdict TimeoutVerdict;
	};

	// 注册窗口类。整个进程只调一次。
	bool Initialize(HINSTANCE instance) noexcept;
	void Shutdown() noexcept;

	// 弹出通知。返回用户的点击结论。
	// 内部会跑消息泵直到用户点击或倒计时结束。
	// 每次 Show() 返回后，用 LastWasTimedOut() 判断这次是不是倒计时兜底。
	R3ShieldCoreToast::Action Show(const Request& request) noexcept;

	// 上一次 Show() 的结论是否来自倒计时兜底（而非用户点击）。
	bool LastWasTimedOut() noexcept;

	// UI 线程在等待期间调用，处理挂起的窗口消息。
	void PumpMessages() noexcept;
}

#pragma once
//
// advanced_quiz.h —— 「高级模式」的**三道 Win32 编程题**（闸门）。
//
// ★ 为什么抽成共享头（铁律 195：同一份逻辑不抄第二遍）
//   同一个闸门有**两个**入口，题目必须**逐字一致**：
//     · `tools/spoof_console.cpp`             —— 交互式控制台（命令行问答）
//     · `R3ShieldCore/r3shieldcore_gui.cpp`   —— 主程序「高级」页（页内问答）
//   抄两份必然漂（铁律 127）：漂了之后"控制台过了、界面过不了"，
//   而两边**都不会报错** —— 用户只会觉得"这软件有毛病"。
//
// ★ 题目本身是这个项目**真踩过**的坑，不是随便找的 Win32 冷知识：
//     #1 伪句柄当 `RootDirectory`   → v75 KTM 探针踩过（见铁律 219）
//     #2 vtable 模块级共享          → v73 摄像头帧替换踩过（见铁律 210）
//     #3 WOW64 注册表重定向         → 32/64 位双架构构建的常客
//   所以"答对"等价于"知道这个项目的替换面在哪些地方会骗人"。
//
// ★ 答案顺序（A/B/C/D）**不要动**：控制台的 `--selftest` 与界面的
//   核对脚本都按现在的答案写断言（C / B / A）。
//
#ifndef _WINDOWS_
#include <windows.h>
#endif

namespace R3ShieldCoreQuiz
{
	struct Question
	{
		const WCHAR* text;      // 题干（可含 '\n' 换行；界面按行画）
		const WCHAR* opt[4];    // A / B / C / D
		WCHAR        answer;    // 'A'..'D'
		const WCHAR* why;       // 全对之后才展示的解析
	};

	inline int Count() noexcept { return 3; }

	inline const Question* Questions() noexcept
	{
		static const Question kQuiz[3] = {
			{
				L"NtOpenKey / NtOpenKeyTransacted 把**预定义伪句柄**（HKEY_CURRENT_USER /\n"
				L"    HKEY_LOCAL_MACHINE 这类固定常量）当作 RootDirectory 传进去，会返回什么？",
				{
					L"STATUS_OBJECT_NAME_NOT_FOUND   (0xC0000034)",
					L"STATUS_ACCESS_DENIED           (0xC0000022)",
					L"STATUS_INVALID_HANDLE          (0xC0000008)",
					L"STATUS_INVALID_PARAMETER       (0xC000000D)",
				},
				L'C',
				L"`Nt*` 层**不吃**伪句柄。advapi32 的 RegOpenKeyExW(HKEY_CURRENT_USER, ...) 能跑，\n"
				L"    是因为它**自己**先把伪句柄换成了真句柄 —— 这个替换把坑盖住了。\n"
				L"    Nt* 只有两条路：① RootDirectory=真键句柄 + 相对名；② RootDirectory=NULL +\n"
				L"    绝对 NT 路径（\\REGISTRY\\USER\\<SID>\\...）。"
			},
			{
				L"COM 接口的 vtable 在**同一个模块内是按类共享**的。现在只想对某个实例生效，\n"
				L"    给 IMediaSample::GetPointer 做 inline patch：\"要不要替换\"按什么记？原件按什么存？",
				{
					L"标记按 vtable 记，原件按实例存",
					L"标记按实例记，原件按 vtable 存",
					L"每个实例各自 patch 一份自己的 vtable 就行，不用记",
					L"vtable 每个实例独立，怎么记都一样",
				},
				L'B',
				L"vtable 是**模块级共享**的：patch 一次，所有实例一起变。所以必须\n"
				L"    「补丁全局、策略逐对象」—— 要不要替换按**实例**记；\n"
				L"    而原件必须按 **vtable** 存，否则第二个实例再来 patch 时，\n"
				L"    会把**已经被改过**的地址当成「原件」存下来，链就断了。"
			},
			{
				L"32 位进程在 64 位 Windows 上执行\n"
				L"        RegOpenKeyExW(HKEY_LOCAL_MACHINE, L\"SOFTWARE\\\\Foo\", 0, KEY_READ, &h)\n"
				L"    不带任何 KEY_WOW64_* 标志时，实际读的是哪个键？想强制读 64 位那份要怎么办？",
				{
					L"默认读 WOW6432Node 那份；加 KEY_WOW64_64KEY 才能读 64 位那份",
					L"默认读 64 位那份；加 KEY_WOW64_32KEY 才能读 WOW6432Node",
					L"默认读 WOW6432Node 那份；只能把 Wow6432Node 写进路径才能读到 64 位那份",
					L"由应用程序清单决定，与 KEY_WOW64_* 无关",
				},
				L'A',
				L"WOW64 默认把 32 位进程的 HKLM\\SOFTWARE 重定向到 HKLM\\SOFTWARE\\WOW6432Node。\n"
				L"    KEY_WOW64_64KEY 强制走 64 位视图，KEY_WOW64_32KEY 强制走 32 位视图。\n"
				L"    （注意 HKCU 也重定向，但只对 HKCU\\Software\\Classes 那一段。）"
			},
		};
		return kQuiz;
	}
}

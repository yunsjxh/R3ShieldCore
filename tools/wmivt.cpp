// wmivt —— 排查 IWbemLocator 的 vtable 到底是不是"模块级共享"的。
//
// 背景：WmiSubscriptionGuard 在 Install 时自己 CoCreateInstance 拿到一个
//       IWbemLocator，patch 它的 slot 3（ConnectServer）成功（日志确认
//       hook=1、vtable=0x...A040）。但 v13probe dump 从**另一个调用点**
//       拿到的 IWbemLocator，slot 3 仍指向 wbemprox.dll。
//
// 假设：IWbemLocator 不是模块级单例 vtable —— 不同 CLSCTX / 不同线程
//       apartment 拿到的是不同实现。本工具把所有这些都打出来对比。
//
// 用法： wmivt.exe
//        （会尝试多种 CLSCTX + 多次调用，列出每次的 vtable 地址与 slot3 模块）

#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <psapi.h>
#include <wbemidl.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "psapi.lib")

static const char* ModOf(void* addr, char* buf, size_t cch)
{
	HMODULE owner = nullptr;
	if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
			| GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			reinterpret_cast<LPCSTR>(addr), &owner)) {
		strncpy_s(buf, cch, "(未知)", _TRUNCATE);
		return buf;
	}
	char path[MAX_PATH] = {};
	GetModuleFileNameA(owner, path, MAX_PATH);
	const char* slash = strrchr(path, '\\');
	strncpy_s(buf, cch, slash ? slash + 1 : path, _TRUNCATE);
	return buf;
}

static void DumpOne(const char* tag, IUnknown* obj)
{
	if (!obj) {
		printf("  %-28s (空)\n", tag);
		return;
	}
	void** vt = *reinterpret_cast<void***>(obj);
	char m0[64] = {}, m3[64] = {};
	printf("  %-28s obj=%p vtable=%p  slot0=%s  slot3=%s\n",
		tag, obj, vt,
		ModOf(vt[0], m0, sizeof(m0)),
		ModOf(vt[3], m3, sizeof(m3)));
}

static void TryCreate(const char* tag, DWORD clsctx)
{
	IUnknown* p = nullptr;
	HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, clsctx,
		IID_IWbemLocator, reinterpret_cast<void**>(&p));
	if (FAILED(hr)) {
		printf("  %-28s 失败 hr=0x%08X\n", tag, hr);
		return;
	}
	DumpOne(tag, p);
	p->Release();
}

static DWORD WINAPI ThreadProc(LPVOID)
{
	// MTA 线程上再拿一次
	CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	TryCreate("[MTA线程] INPROC_SERVER", CLSCTX_INPROC_SERVER);
	TryCreate("[MTA线程] ALL", CLSCTX_ALL);
	TryCreate("[MTA线程] LOCAL_SERVER", CLSCTX_LOCAL_SERVER);
	CoUninitialize();
	return 0;
}

int main()
{
	setlocale(LC_ALL, "");

	printf("wmivt  (pid=%u)\n", GetCurrentProcessId());
	printf("等待 3s 让引擎完成注入...\n");
	Sleep(3000);

	printf("\n=== 各模块基址 ===\n");
	const char* kMods[] = { "wbemprox.dll", "fastprox.dll", "wbemcomn.dll", "combase.dll", "ole32.dll" };
	for (const char* m : kMods) {
		HMODULE h = GetModuleHandleA(m);
		printf("  %-16s %p\n", m, h);
	}

	printf("\n=== 主线程（STA）===\n");
	HRESULT hrInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
	printf("  CoInitializeEx(STA) hr=0x%08X\n", hrInit);
	TryCreate("[主] INPROC_SERVER", CLSCTX_INPROC_SERVER);
	TryCreate("[主] ALL", CLSCTX_ALL);
	TryCreate("[主] LOCAL_SERVER", CLSCTX_LOCAL_SERVER);

	printf("\n=== 新 MTA 线程 ===\n");
	HANDLE t = CreateThread(nullptr, 0, ThreadProc, nullptr, 0, nullptr);
	if (t) {
		WaitForSingleObject(t, 10000);
		CloseHandle(t);
	}

	printf("\ndone\n");
	return 0;
}

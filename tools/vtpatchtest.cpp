// vtpatchtest —— 亲自验证"IWbemLocator 的 vtable 能不能 patch 成功并保持"。
//
// 动机：guard 日志说 patch 成功（vtable=0x...A040），但探针读回还是 wbemprox。
//       本工具在同一进程里做三件事，把问题切成互斥的可能：
//         1) 拿 IWbemLocator，记下 slot3 原值
//         2) VirtualProtect + 写入一个标记函数 + 读回验证
//         3) Sleep 1s 后再读一次 —— 看是否被"还原"
//
// 用法： vtpatchtest.exe

#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <wbemidl.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wbemuuid.lib")

static void* g_marker = nullptr;

static HRESULT WINAPI MarkerConnectServer(IWbemLocator*, BSTR, BSTR, BSTR, BSTR,
	LONG, BSTR, BSTR, IWbemServices**)
{
	return E_NOTIMPL;
}

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

static void Show(const char* tag, void** vt)
{
	char m[64] = {};
	printf("  %-24s slot3=%p (%s)\n", tag, vt[3], ModOf(vt[3], m, sizeof(m)));
}

int main()
{
	setlocale(LC_ALL, "");
	printf("vtpatchtest  (pid=%u)\n", GetCurrentProcessId());
	Sleep(3000);

	HRESULT hrInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
	printf("CoInitializeEx hr=0x%08X\n", hrInit);

	IWbemLocator* loc = nullptr;
	HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, reinterpret_cast<void**>(&loc));
	if (FAILED(hr) || !loc) {
		printf("创建失败 hr=0x%08X\n", hr);
		return 1;
	}

	void** vt = *reinterpret_cast<void***>(loc);
	printf("\nvtable = %p\n", vt);
	Show("原样", vt);

	// ---- 第 2 步：patch ----
	DWORD oldProtect = 0;
	BOOL ok = VirtualProtect(&vt[3], sizeof(void*), PAGE_READWRITE, &oldProtect);
	printf("\nVirtualProtect 改可写: %s  oldProtect=0x%X  err=%u\n",
		ok ? "成功" : "失败", oldProtect, ok ? 0 : GetLastError());

	void* orig = vt[3];
	vt[3] = reinterpret_cast<void*>(MarkerConnectServer);
	Show("写入后（读回）", vt);

	DWORD ignored = 0;
	VirtualProtect(&vt[3], sizeof(void*), oldProtect, &ignored);
	Show("恢复保护后", vt);

	// ---- 第 3 步：等一秒再读 ----
	printf("\nSleep 1000ms...\n");
	Sleep(1000);
	Show("1 秒后", vt);

	// ---- 第 4 步：重新创建实例，看是否同一个 vtable ----
	IWbemLocator* loc2 = nullptr;
	if (SUCCEEDED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, reinterpret_cast<void**>(&loc2))) && loc2) {
		void** vt2 = *reinterpret_cast<void***>(loc2);
		printf("\n新实例 vtable = %p  (与原 vtable %s)\n", vt2, vt2 == vt ? "相同" : "不同");
		Show("新实例", vt2);
		loc2->Release();
	}

	loc->Release();
	printf("\ndone\n");
	return 0;
}

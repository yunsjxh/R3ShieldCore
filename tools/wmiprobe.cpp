//
// wmiprobe.cpp - 实测 WMI COM 接口的真实 vtable 形态。
//
// 为什么必须实测（同 audioprobe 的理由）：
//   1. IWbemServices / IWbemLocator 都是纯 COM 接口（无导出可挂），
//      只能 vtable patch。槽位数错一位 = patch 到别的函数 = 静默失效
//      （v12 计划任务那次就是这么栽的）。
//   2. **命名空间检查点**：ConnectServer 的第 1 个参数就是命名空间
//      （BSTR，如 L"root\\subscription"），这是判据的第一道闸。
//   3. PutInstance 的签名（要确认第几个参数是 IWbemClassObject*）。
//
// 用法：
//   wmiprobe.exe vtable    —— 打印 IWbemLocator / IWbemServices 的 vtable
//   wmiprobe.exe connect   —— 实测连接 root\subscription（只连接不写）
//   wmiprobe.exe all
//
#include <windows.h>
#include <wbemidl.h>
#include <stdio.h>
#include <locale.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")

static const char* ModuleOf(void* address, char* buffer, size_t cch)
{
	HMODULE owner = nullptr;
	if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
			| GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			reinterpret_cast<LPCSTR>(address), &owner)) {
		return "(未知)";
	}
	char path[MAX_PATH] = {};
	GetModuleFileNameA(owner, path, MAX_PATH);
	const char* slash = strrchr(path, '\\');
	const char* name = slash ? slash + 1 : path;
	strncpy_s(buffer, cch, name, _TRUNCATE);
	return buffer;
}

static void DumpVtable(const char* who, void* obj, int count)
{
	if (!obj) {
		printf("  %s: (null)\n", who);
		return;
	}
	__try {
		void** vtable = *reinterpret_cast<void***>(obj);
		printf("  %s  vtable=%p\n", who, (void*)vtable);
		for (int i = 0; i < count; i++) {
			char buf[128] = {};
			printf("    slot[%2d] %p  %s\n", i, vtable[i], ModuleOf(vtable[i], buf, sizeof(buf)));
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		printf("  %s: 读 vtable 异常\n", who);
	}
}

int main(int argc, char** argv)
{
	setlocale(LC_ALL, "");
	const char* mode = (argc > 1) ? argv[1] : "all";
	printf("R3ShieldCore WMI 探针  (pid=%u)  mode=%s\n\n", GetCurrentProcessId(), mode);

	HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	if (FAILED(hr)) {
		printf("CoInitializeEx 失败 hr=0x%08X\n", hr);
		return 1;
	}
	// 设置进程安全 —— WMI 需要（CoInitializeSecurity 只需一次，
	// 重复调用返 RPC_E_TOO_LATE，忽略）
	hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
		RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
		nullptr, EOAC_NONE, nullptr);

	IWbemLocator* locator = nullptr;
	hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, reinterpret_cast<void**>(&locator));
	if (FAILED(hr) || !locator) {
		printf("CoCreateInstance(CLSID_WbemLocator) 失败 hr=0x%08X\n", hr);
		CoUninitialize();
		return 1;
	}

	// IWbemLocator vtable（IUnknown 3 + 自身 1）：
	//   0 QI 1 AddRef 2 Release
	//   3 ConnectServer   ★ 唯一方法，第 1 个参数就是命名空间
	if (strcmp(mode, "vtable") == 0 || strcmp(mode, "all") == 0) {
		printf("=== 1. IWbemLocator（ConnectServer 在 slot 3）===\n");
		DumpVtable("IWbemLocator", locator, 4);
	}

	// 连到 root\subscription —— 正是攻击者用来装事件订阅的命名空间
	BSTR ns = SysAllocString(L"ROOT\\SUBSCRIPTION");
	BSTR empty = SysAllocString(L"");
	IWbemServices* services = nullptr;
	hr = locator->ConnectServer(ns, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &services);
	printf("\n=== 2. ConnectServer(root\\subscription) ===\n");
	printf("  hr=0x%08X %s\n", hr, SUCCEEDED(hr) ? "OK" : "(失败，可能权限/服务问题)");

	if (SUCCEEDED(hr) && services) {
		// IWbemServices vtable（IUnknown 3 + 自身 22）：
		//   3 OpenNamespace
		//   4 CancelAsyncCall
		//   5 QueryObjectSink
		//   6 GetObject
		//   7 GetObjectAsync
		//   8 PutClass
		//   9 PutClassAsync
		//   10 DeleteClass
		//   11 DeleteClassAsync
		//   12 CreateClassEnum
		//   13 CreateClassEnumAsync
		//   14 PutInstance                ★ 写实例（装 Filter/Consumer/Binding）
		//   15 PutInstanceAsync
		//   16 DeleteInstance
		//   17 DeleteInstanceAsync
		//   18 CreateInstanceEnum
		//   19 CreateInstanceEnumAsync
		//   20 ExecQuery
		//   21 ExecQueryAsync
		//   22 ExecNotificationQuery      ★ 订阅事件
		//   23 ExecNotificationQueryAsync
		//   24 ExecMethod
		//   25 ExecMethodAsync
		//
		// ⚠️ 实测数清楚。
		printf("\n=== 3. IWbemServices  ★ PutInstance 应当落在 slot 14 ===\n");
		DumpVtable("IWbemServices", services, 26);

		services->Release();
	}

	SysFreeString(ns);
	SysFreeString(empty);
	locator->Release();
	CoUninitialize();

	printf("\ndone\n");
	return 0;
}

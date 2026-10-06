// wtch —— 长时间监视 IWbemLocator / IAudioClient 的 vtable slot，
//         看 guard 的 patch 到底有没有"存在过"。
//
// 背景：guard 日志确认 patch 成功（IWbemLocator slot3 ← vtable 0x...A040），
//       但同进程里随后读到的 slot3 仍是 wbemprox.dll。
//       本工具从进程启动就开始高频采样，把每次变化都打时间戳 ——
//       若 patch 只在极短窗口存在，能抓到。
//
// 用法： wtch.exe [采样次数] [间隔毫秒]      默认 40 次 × 250ms = 10 秒

#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <wbemidl.h>
#include <mmdeviceapi.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wbemuuid.lib")

static const char* Base(void* addr, char* buf, size_t cch)
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

int main(int argc, char** argv)
{
	setlocale(LC_ALL, "");

	int samples = 40;
	int interval = 250;
	if (argc > 1) samples = atoi(argv[1]);
	if (argc > 2) interval = atoi(argv[2]);

	printf("wtch  (pid=%u)  采样 %d 次 × %dms\n", GetCurrentProcessId(), samples, interval);
	fflush(stdout);

	// ⚠️ 必须等注入完成再取对象 —— 否则拿到的对象是在"引擎还没装上 hook"
	//    的时刻创建的，采样窗口也可能整个落在 guard::Install 之前，
	//    于是永远看到原函数（曾因此把"WMI patch 未生效"误判了一轮）。
	printf("等待 3s 让引擎完成注入并 patch vtable...\n");
	Sleep(3000);

	CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

	// 先拿到对象（这一步本身会触发 ComHijackGuard 的懒 patch）
	IWbemLocator* loc = nullptr;
	CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, reinterpret_cast<void**>(&loc));
	void** vtLoc = loc ? *reinterpret_cast<void***>(loc) : nullptr;

	IMMDeviceEnumerator* en = nullptr;
	CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL,
		__uuidof(IMMDeviceEnumerator), reinterpret_cast<void**>(&en));
	void** vtDev = nullptr;
	if (en) {
		IMMDevice* dev = nullptr;
		if (SUCCEEDED(en->GetDefaultAudioEndpoint(eRender, eConsole, &dev)) && dev) {
			vtDev = *reinterpret_cast<void***>(dev);
			dev->Release();
		}
	}

	char vtMod[64] = {};
	printf("IWbemLocator  vtable=%p  (vtable 本体属模块: %s)\n", vtLoc,
		vtLoc ? Base(reinterpret_cast<void*>(vtLoc), vtMod, sizeof(vtMod)) : "(无)");
	printf("IMMDevice     vtable=%p\n\n", vtDev);
	fflush(stdout);

	const ULONGLONG t0 = GetTickCount64();
	char prevLoc[64] = {}, prevDev[64] = {};

	for (int i = 0; i < samples; ++i) {
		char lm[64] = {}, dm[64] = {};
		if (vtLoc) {
			Base(vtLoc[3], lm, sizeof(lm));
		}
		if (vtDev) {
			Base(vtDev[3], dm, sizeof(dm));
		}

		const bool changed = (strcmp(lm, prevLoc) != 0) || (strcmp(dm, prevDev) != 0);
		printf("  t=%5llums  loc.slot3=%-24s dev.slot3=%-24s%s\n",
			GetTickCount64() - t0, lm, dm, changed ? "   <== 变化" : "");
		fflush(stdout);

		strncpy_s(prevLoc, lm, _TRUNCATE);
		strncpy_s(prevDev, dm, _TRUNCATE);

		Sleep(interval);
	}

	if (en) en->Release();
	if (loc) loc->Release();
	CoUninitialize();
	printf("\ndone\n");
	return 0;
}

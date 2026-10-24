//
// engine_ipc_probe.cpp —— v89「引擎 ⇄ 界面」加密命名管道**端到端**探针。
//
//   ────────────────────────────────────────────────────────────────
//   它验的是什么（以及为什么必须真跑）
//   ────────────────────────────────────────────────────────────────
//   协议类 bug 是最会骗过推理的一类：AES-GCM 忘了设 GCM 链模式会**静默按
//   CBC 跑**（能加能解，tag 形同虚设）；事件编解码漏一个夹在中间的字段会
//   整段错位（症状是"端口"显示成一串乱码路径）；`ReadFile` 少读一次会把
//   下一帧的开头吃掉。这些都不会报错，只会"看起来能跑"。
//   ⇒ 所以这里不用眼睛看日志，而是**逐条比对字段**。
//
//   ────────────────────────────────────────────────────────────────
//   为什么用 `--dry-run` 的引擎
//   ────────────────────────────────────────────────────────────────
//   本机铁律：**禁止真跑引擎**（全局注入会 hook 编辑器，一跑就崩）。
//   `--dry-run` 的引擎不 LoadLibrary、不建会话、不注入，只跑管道 ——
//   于是"传输层"和"注入层"变成两个可以分别证伪的问题。
//   假事件（`--fake-events`）专门踩五个编解码易错点：中文 / 空字段 /
//   超长命令行 / 夹在中间的端口字段 / 尾部 Flags2。
//
//   ────────────────────────────────────────────────────────────────
//   用法
//   ────────────────────────────────────────────────────────────────
//     engine_ipc_probe.exe --launch <引擎exe> [--config-dir <dir>]
//     engine_ipc_probe.exe                       # 连已经在跑的引擎
//     engine_ipc_probe.exe --neg                 # 反向对照（必须报失败）
//
//   `--neg` 的判据是**故意用错的密钥**：如果对端照样回 Pong，说明 tag 根本
//   没被校验（= 加密是假的）。这条对照是"判据有分辨力"的证据。
//
//   退出码：0 = 全过；1 = 有失败；2 = 环境问题（连不上/引擎没起）。
//
#include <windows.h>
#include <aclapi.h>

#include <r3shieldcore/engine_ipc.h>

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace ipc = R3ShieldCoreEngineIpc;
using R3ShieldCore::Event;

namespace
{
	int g_pass = 0;
	int g_fail = 0;
	bool g_negMode = false;
	// `--verbose`：逐帧打印收到的帧。默认关 —— 正常跑一次要收几百帧统计，
	// 全打出来反而把真正的判据淹掉。
	bool g_verbose = false;

	// ★ 探针自己的输出**只用 ASCII 字面量**：`-source-charset:utf-8` 只决定
	//   源文件怎么读，窄字面量最终编码由**执行字符集**（默认 CP936）决定。
	//   所以中文一律走 `U8()` 显式转 UTF-8，配合 `SetConsoleOutputCP(CP_UTF8)`。
	//   （铁律 252 的邻居：别赌 printf 的编码。）
	std::string U8(const wchar_t* w)
	{
		if (!w || !*w) {
			return std::string();
		}
		const int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
		if (n <= 1) {
			return std::string();
		}
		std::string s(static_cast<size_t>(n - 1), '\0');
		WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], n, nullptr, nullptr);
		return s;
	}

	std::string U8(const std::wstring& w) { return U8(w.c_str()); }

	void Out(const char* fmt, ...)
	{
		char buf[4096];
		va_list args;
		va_start(args, fmt);
		_vsnprintf_s(buf, _countof(buf), _TRUNCATE, fmt, args);
		va_end(args);
		fputs(buf, stdout);
		fputc('\n', stdout);
		fflush(stdout);
	}

	void Ok(const char* what)
	{
		Out("[ OK ] %s", what);
		++g_pass;
	}

	void Fail(const char* what, const char* detail = nullptr)
	{
		if (detail && *detail) {
			Out("[FAIL] %s -- %s", what, detail);
		}
		else {
			Out("[FAIL] %s", what);
		}
		++g_fail;
	}

	void Info(const char* fmt, ...)
	{
		char buf[4096];
		va_list args;
		va_start(args, fmt);
		_vsnprintf_s(buf, _countof(buf), _TRUNCATE, fmt, args);
		va_end(args);
		Out("       %s", buf);
	}

	bool IsAdmin()
	{
		BOOL isAdmin = FALSE;
		PSID adminGroup = nullptr;
		SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
		if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
			DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
			CheckTokenMembership(nullptr, adminGroup, &isAdmin);
			FreeSid(adminGroup);
		}
		return isAdmin != FALSE;
	}

	// ---------------------------------------------------------------------
	// 收集到的帧
	// ---------------------------------------------------------------------
	struct Frame
	{
		ipc::Msg type = ipc::Msg::Ping;
		std::vector<BYTE> payload;
	};

	std::mutex g_framesMutex;
	std::vector<Frame> g_frames;

	void PushFrame(ipc::Msg type, const std::vector<BYTE>& payload)
	{
		std::lock_guard<std::mutex> lock(g_framesMutex);
		Frame f;
		f.type = type;
		f.payload = payload;
		g_frames.push_back(std::move(f));
	}

	// 取走第一条指定类型的帧。`timeoutMs` 内没有就返回 false。
	bool TakeFrame(ipc::Msg type, std::vector<BYTE>& out, int timeoutMs)
	{
		const ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(timeoutMs);
		while (GetTickCount64() < deadline) {
			{
				std::lock_guard<std::mutex> lock(g_framesMutex);
				for (size_t i = 0; i < g_frames.size(); ++i) {
					if (g_frames[i].type == type) {
						out = std::move(g_frames[i].payload);
						g_frames.erase(g_frames.begin() + static_cast<long>(i));
						return true;
					}
				}
			}
			Sleep(10);
		}
		return false;
	}

	// 把目前收到的所有 Events 帧解出来，累加到 out。
	int DrainEvents(std::vector<Event>& out)
	{
		std::vector<Frame> mine;
		{
			std::lock_guard<std::mutex> lock(g_framesMutex);
			for (size_t i = 0; i < g_frames.size();) {
				if (g_frames[i].type == ipc::Msg::Events) {
					mine.push_back(std::move(g_frames[i]));
					g_frames.erase(g_frames.begin() + static_cast<long>(i));
				}
				else {
					++i;
				}
			}
		}
		int bad = 0;
		for (const Frame& f : mine) {
			std::vector<Event> batch;
			if (!ipc::DecodeEvents(f.payload.data(), f.payload.size(), batch)) {
				++bad;
				continue;
			}
			for (const Event& e : batch) {
				out.push_back(e);
			}
		}
		return bad;
	}

	// ---------------------------------------------------------------------
	// 判据 1：AES-256-GCM 真的在验 tag（本地往返 + 篡改）
	// ---------------------------------------------------------------------
	// 为什么单独测：`BCryptEncrypt` 不显式设 `BCRYPT_CHAIN_MODE_GCM` 时会
	// **静默按 CBC 跑** —— 加密解密都成功，tag 位随便填也能过。
	// 唯一能拆穿它的是"改一个字节必须失败"。
	void CheckAeadSelfTest()
	{
		BYTE key[ipc::kKeyBytes];
		if (!NT_SUCCESS(BCryptGenRandom(nullptr, key, sizeof(key),
			BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
			Fail("AEAD 自检：生成随机密钥失败");
			return;
		}
		ipc::Aead aead;
		if (!aead.Init(key)) {
			Fail("AEAD 自检：Init 失败（BCrypt AES-GCM 不可用？）");
			return;
		}

		const char* plain = "R3ShieldCore engine ipc round-trip";
		const size_t plainLen = strlen(plain);
		BYTE iv[ipc::kIvBytes] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
		const BYTE aad[] = { 0x52, 0x33, 0x53, 0x43 };   // "R3SC"

		std::vector<BYTE> sealed;
		if (!aead.Seal(iv, aad, sizeof(aad), plain, plainLen, sealed)) {
			Fail("AEAD 自检：Seal 失败");
			return;
		}
		if (sealed.size() != plainLen + ipc::kPadBytes + ipc::kTagBytes) {
			Fail("AEAD 自检：密文长度不对（应有 明文+填充+16 tag）");
			return;
		}

		std::vector<BYTE> opened;
		if (!aead.Open(iv, aad, sizeof(aad), sealed.data(), sealed.size(), opened)
			|| opened.size() != plainLen
			|| memcmp(opened.data(), plain, plainLen) != 0) {
			Fail("AEAD 自检：明文往返不一致");
			return;
		}
		Ok("AEAD：明文往返一致");

		// ① 篡改密文一个字节 ⇒ 必须失败
		{
			std::vector<BYTE> t = sealed;
			t[0] ^= 0x01;
			std::vector<BYTE> sink;
			if (aead.Open(iv, aad, sizeof(aad), t.data(), t.size(), sink)) {
				Fail("AEAD：密文被篡改后仍然解开 —— tag 没有被校验（大概率静默跑成了 CBC）");
			}
			else {
				Ok("AEAD：密文篡改被拒（tag 真的在验）");
			}
		}

		// ② 篡改 AAD 一个字节 ⇒ 必须失败（否则 seq/type 可被改写而不被发现）
		{
			BYTE aad2[sizeof(aad)] = {};
			memcpy(aad2, aad, sizeof(aad));
			aad2[0] ^= 0xFF;
			std::vector<BYTE> sink;
			if (aead.Open(iv, aad2, sizeof(aad2), sealed.data(), sealed.size(), sink)) {
				Fail("AEAD：AAD 被篡改后仍然解开 —— 帧头（seq/type）没有进认证");
			}
			else {
				Ok("AEAD：AAD 篡改被拒（帧头进了认证）");
			}
		}

		// ③ 空载荷 + 错密钥 ⇒ 必须失败
		//
		// ★ 这条是**回归判据**：v89 第一版里 CNG 的 GCM 对零长度明文
		//   根本不校验 tag，于是空载荷的 Ping/ReadStats/StopEngine
		//   用乱密钥也能被接受（等于任何人可以叫停防护）。
		//   修法是 Seal 前置 1 字节填充（见 engine_ipc.h 的 kPadBytes）。
		//   没有这条判据，那个洞下次改回去也没人知道。
		{
			BYTE otherKey[ipc::kKeyBytes];
			BCryptGenRandom(nullptr, otherKey, sizeof(otherKey),
				BCRYPT_USE_SYSTEM_PREFERRED_RNG);
			ipc::Aead other;
			std::vector<BYTE> sealedEmpty;
			std::vector<BYTE> sink;
			if (!other.Init(otherKey)) {
				Fail("AEAD 自检：第二把密钥 Init 失败");
			}
			else if (!aead.Seal(iv, aad, sizeof(aad), nullptr, 0, sealedEmpty)) {
				Fail("AEAD 自检：空载荷 Seal 失败");
			}
			else if (other.Open(iv, aad, sizeof(aad), sealedEmpty.data(),
				sealedEmpty.size(), sink)) {
				Fail("AEAD：空载荷用错密钥也能解开 —— 零长度明文绕过验签");
			}
			else {
				Ok("AEAD：空载荷用错密钥被拒（零长度绕过已封）");
			}
		}

		// ④ 换 IV ⇒ 必须失败（IV 唯一性没被忽略）
		{
			BYTE iv2[ipc::kIvBytes] = {};
			memcpy(iv2, iv, sizeof(iv));
			iv2[0] ^= 0xFF;
			std::vector<BYTE> sink;
			if (aead.Open(iv2, aad, sizeof(aad), sealed.data(), sealed.size(), sink)) {
				Fail("AEAD：换 IV 后仍然解开");
			}
			else {
				Ok("AEAD：换 IV 被拒");
			}
		}
	}

	// ---------------------------------------------------------------------
	// 判据 2：管道 DACL 只给 SYSTEM + Administrators
	// ---------------------------------------------------------------------
	// 这一条不能靠"读代码觉得对"：`BuildPipeSecurity` 写错了的典型症状是
	// **默认 DACL 生效**（创建者 + 当前用户），于是同机任何用户都能连上来
	// 发 `StopEngine` —— 加密再强也挡不住"合法客户端"。
	bool SidsEqual(PSID a, PSID b)
	{
		return a && b && EqualSid(a, b) != FALSE;
	}

	PSID WellKnown(WELL_KNOWN_SID_TYPE t, std::vector<BYTE>& storage)
	{
		DWORD size = SECURITY_MAX_SID_SIZE;
		storage.assign(SECURITY_MAX_SID_SIZE, 0);
		if (!CreateWellKnownSid(t, nullptr, storage.data(), &size)) {
			return nullptr;
		}
		return storage.data();
	}

	void CheckPipeDacl(HANDLE pipe)
	{
		PACL pAcl = nullptr;
		PSECURITY_DESCRIPTOR pSd = nullptr;
		const DWORD rc = GetSecurityInfo(pipe, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
			nullptr, nullptr, &pAcl, nullptr, &pSd);
		if (rc != ERROR_SUCCESS || !pAcl) {
			char detail[128];
			_snprintf_s(detail, _countof(detail), _TRUNCATE,
				"GetSecurityInfo err=%lu", static_cast<unsigned long>(rc));
			Fail("管道 DACL：读不出安全描述符", detail);
			if (pSd) {
				LocalFree(pSd);
			}
			return;
		}

		std::vector<BYTE> worldStore, authStore, usersStore, systemStore, adminStore;
		PSID world = WellKnown(WinWorldSid, worldStore);
		PSID auth = WellKnown(WinAuthenticatedUserSid, authStore);
		PSID users = WellKnown(WinBuiltinUsersSid, usersStore);
		PSID system = WellKnown(WinLocalSystemSid, systemStore);
		PSID admins = WellKnown(WinBuiltinAdministratorsSid, adminStore);

		bool sawSystem = false;
		bool sawAdmins = false;
		bool sawWorld = false;
		bool sawAuth = false;
		bool sawUsers = false;

		ACL_SIZE_INFORMATION aclInfo = {};
		if (GetAclInformation(pAcl, &aclInfo, sizeof(aclInfo), AclSizeInformation)) {
			for (DWORD i = 0; i < aclInfo.AceCount; ++i) {
				LPVOID ace = nullptr;
				if (!GetAce(pAcl, i, &ace) || !ace) {
					continue;
				}
				const ACE_HEADER* hdr = static_cast<const ACE_HEADER*>(ace);
				if (hdr->AceType != ACCESS_ALLOWED_ACE_TYPE) {
					continue;
				}
				const ACCESS_ALLOWED_ACE* a = static_cast<const ACCESS_ALLOWED_ACE*>(ace);
				PSID sid = const_cast<PSID>(static_cast<const void*>(&a->SidStart));
				if (SidsEqual(sid, world)) {
					sawWorld = true;
				}
				if (SidsEqual(sid, auth)) {
					sawAuth = true;
				}
				if (SidsEqual(sid, users)) {
					sawUsers = true;
				}
				if (SidsEqual(sid, system)) {
					sawSystem = true;
				}
				if (SidsEqual(sid, admins)) {
					sawAdmins = true;
				}
			}
		}
		LocalFree(pSd);

		if (sawWorld || sawAuth || sawUsers) {
			char detail[256];
			_snprintf_s(detail, _countof(detail), _TRUNCATE,
				"存在过宽的 ACE（Everyone=%d AuthenticatedUsers=%d Users=%d）",
				sawWorld ? 1 : 0, sawAuth ? 1 : 0, sawUsers ? 1 : 0);
			Fail("管道 DACL：不是只给 SYSTEM + Administrators", detail);
		}
		else if (!sawSystem || !sawAdmins) {
			Fail("管道 DACL：缺 SYSTEM 或 Administrators 的显式授权",
				"两端可能都连不上（v81 踩过：恒定 ERROR_ACCESS_DENIED(5)）");
		}
		else {
			Ok("管道 DACL：只授 SYSTEM + Administrators（无 Everyone/Authenticated Users）");
		}
	}

	// ---------------------------------------------------------------------
	// 事件字段比对（五个易错点）
	// ---------------------------------------------------------------------
	bool Contains(const std::wstring& hay, const wchar_t* needle)
	{
		return hay.find(needle) != std::wstring::npos;
	}

	void CheckEventFields(const std::vector<Event>& events)
	{
		// ① 中文键路径 + 中文值名
		{
			const Event* hit = nullptr;
			for (const Event& e : events) {
				if (Contains(e.KeyPath, L"\u6D4B\u8BD5\u9879")) {   // 测试项
					hit = &e;
					break;
				}
			}
			if (!hit) {
				Fail("事件①：没有一条 KeyPath 含中文（UTF-16 汉字在编解码里丢了）");
			}
			else if (!Contains(hit->ValueName, L"\u9ED8\u8BA4\u542F\u52A8\u9879")) {  // 默认启动项
				Fail("事件①：中文值名对不上", U8(hit->ValueName).c_str());
			}
			else if (hit->KeyPathLength != wcslen(hit->KeyPath)) {
				Fail("事件①：KeyPathLength 与实际长度不一致");
			}
			else {
				char detail[512];
				_snprintf_s(detail, _countof(detail), _TRUNCATE, "KeyPath=%s",
					U8(hit->KeyPath).c_str());
				Ok("事件①：中文键路径/值名往返一致");
				Info("%s", detail);
			}
		}

		// ② 空字段（长度 0，不能"顺手"多写一个 NUL）
		{
			bool found = false;
			for (const Event& e : events) {
				if (e.KeyPathLength == 0 && e.ValueNameLength == 0
					&& e.KeyPath[0] == 0 && e.ValueName[0] == 0
					&& e.ObjectType == static_cast<ULONG>(R3ShieldCore::ObjectType::Thread)) {
					found = true;
					break;
				}
			}
			if (found) {
				Ok("事件②：全空字段往返正常（长度 0 没有错位）");
			}
			else {
				Fail("事件②：没找到全空字段的那条事件");
			}
		}

		// ③ 超长命令行（贴到 CommandLine[512] 边界）
		{
			bool found = false;
			size_t maxLen = 0;
			for (const Event& e : events) {
				const size_t n = wcslen(e.CommandLine);
				if (n > maxLen) {
					maxLen = n;
				}
				if (n >= 500) {
					found = true;
				}
			}
			if (!found) {
				char detail[128];
				_snprintf_s(detail, _countof(detail), _TRUNCATE,
					"最长命令行只有 %zu 字符", maxLen);
				Fail("事件③：超长命令行被截得太短或丢了", detail);
			}
			else if (maxLen > 511) {
				Fail("事件③：命令行越界（超过 511 字符 ⇒ 少了结尾 NUL）");
			}
			else {
				char detail[128];
				_snprintf_s(detail, _countof(detail), _TRUNCATE, "最长 %zu 字符", maxLen);
				Ok("事件③：超长命令行按 511 截断");
				Info("%s", detail);
			}
		}

		// ④ 夹在中间的端口字段（漏一个 ⇒ 整段错位）
		{
			const Event* hit = nullptr;
			for (const Event& e : events) {
				if (e.TargetPort == 4444) {
					hit = &e;
					break;
				}
			}
			if (!hit) {
				Fail("事件④：没有一条 TargetPort==4444（端口字段在编解码里错位/丢了）");
			}
			else if (hit->NetProtocol != 6 || hit->LocalPort != 51234) {
				char detail[256];
				_snprintf_s(detail, _countof(detail), _TRUNCATE,
					"proto=%lu localPort=%lu（应为 6/51234）",
					static_cast<unsigned long>(hit->NetProtocol),
					static_cast<unsigned long>(hit->LocalPort));
				Fail("事件④：网络字段错位", detail);
			}
			else if (wcscmp(hit->LocalAddress, L"192.168.1.20") != 0) {
				Fail("事件④：LocalAddress 错位", U8(hit->LocalAddress).c_str());
			}
			else {
				Ok("事件④：TargetPort/NetProtocol/LocalPort/LocalAddress 全部对齐");
			}
		}

		// ⑤ 尾部 Flags2（"只发固定区"的实现会静默丢掉它）
		{
			bool found = false;
			for (const Event& e : events) {
				if (e.Flags2 == 0x00000001) {
					found = true;
					break;
				}
			}
			if (found) {
				Ok("事件⑤：尾部 Flags2 往返正常");
			}
			else {
				Fail("事件⑤：Flags2 丢了（尾部字段没进线格式）");
			}
		}

		// ⑥ 固定区整数（Sequence/TimeStamp/Pid）—— 顺序错一个都会露馅
		{
			bool seqOk = false;
			bool tsOk = false;
			for (const Event& e : events) {
				if (e.Sequence > 0 && e.Sequence % 10 >= 1 && e.Sequence % 10 <= 4) {
					seqOk = true;
				}
				if (e.TimeStamp > 0) {
					tsOk = true;
				}
			}
			if (seqOk && tsOk) {
				Ok("事件⑥：固定区（Sequence/TimeStamp）往返正常");
			}
			else {
				Fail("事件⑥：固定区字段异常", "Sequence 或 TimeStamp 解出来是 0");
			}
		}
	}
}

int wmain(int argc, wchar_t** argv)
{
	SetConsoleOutputCP(CP_UTF8);

	std::filesystem::path engineExe;
	std::filesystem::path configDir;
	for (int i = 1; i < argc; ++i) {
		const std::wstring a = argv[i];
		if (a == L"--launch" && i + 1 < argc) {
			engineExe = argv[++i];
		}
		else if (a == L"--config-dir" && i + 1 < argc) {
			configDir = argv[++i];
		}
		else if (a == L"--neg") {
			g_negMode = true;
		}
		else if (a == L"--verbose") {
			g_verbose = true;
		}
		else {
			Out("unknown arg: %s", U8(a).c_str());
			return 2;
		}
	}

	Out("=== r3shieldcore engine ipc probe (v89) ===");
	Out("pipe = %s", U8(ipc::PipeName()).c_str());
	if (g_negMode) {
		Out("mode = NEGATIVE CONTROL (故意用错密钥，期望握手后第一帧就失败)");
	}
	if (!IsAdmin()) {
		Out("!! 当前不是管理员：管道 DACL 只授 SYSTEM + Administrators，");
		Out("   非提权连接必然 ERROR_ACCESS_DENIED(5)。请用 tools/run_elevated.exe 跑。");
		return 2;
	}

	// ------------------------------------------------------------------
	// 判据 1：AEAD 自检（不需要引擎）
	// ------------------------------------------------------------------
	CheckAeadSelfTest();

	// ------------------------------------------------------------------
	// 起引擎（可选）
	// ------------------------------------------------------------------
	HANDLE engineProc = nullptr;
	if (!engineExe.empty()) {
		std::wstring cmd = L"\"" + engineExe.wstring() + L"\" --dry-run --fake-events";
		if (!configDir.empty()) {
			cmd += L" --config-dir \"" + configDir.wstring() + L"\"";
		}
		STARTUPINFOW si = {};
		si.cb = sizeof(si);
		PROCESS_INFORMATION pi = {};
		std::wstring mutableCmd = cmd;
		if (!CreateProcessW(nullptr, &mutableCmd[0], nullptr, nullptr, FALSE,
			CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
			char detail[256];
			_snprintf_s(detail, _countof(detail), _TRUNCATE,
				"CreateProcess err=%lu cmd=%s",
				static_cast<unsigned long>(GetLastError()), U8(cmd).c_str());
			Out("!! %s", detail);
			return 2;
		}
		engineProc = pi.hProcess;
		CloseHandle(pi.hThread);
		Out("引擎已拉起：pid=%lu", static_cast<unsigned long>(pi.dwProcessId));
		Sleep(600);   // 给它一点时间建管道
	}
	else {
		Out("未指定 --launch：连接已经在跑的引擎");
	}

	// ------------------------------------------------------------------
	// 连接
	// ------------------------------------------------------------------
	const std::wstring pipeName = ipc::PipeName();
	HANDLE pipe = INVALID_HANDLE_VALUE;
	const ULONGLONG connectDeadline = GetTickCount64() + 15000;
	while (GetTickCount64() < connectDeadline) {
		pipe = CreateFileW(pipeName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
			OPEN_EXISTING, 0, nullptr);
		if (pipe != INVALID_HANDLE_VALUE) {
			break;
		}
		const DWORD e = GetLastError();
		if (e != ERROR_PIPE_BUSY && e != ERROR_FILE_NOT_FOUND) {
			char detail[256];
			_snprintf_s(detail, _countof(detail), _TRUNCATE,
				"CreateFile err=%lu（5=拒绝访问 ⇒ DACL 没授到本令牌；2=引擎没起）",
				static_cast<unsigned long>(e));
			Fail("连接管道", detail);
			if (engineProc) {
				TerminateProcess(engineProc, 9);
				CloseHandle(engineProc);
			}
			return 1;
		}
		Sleep(100);
	}
	if (pipe == INVALID_HANDLE_VALUE) {
		Fail("连接管道", "15 秒内没连上（引擎没起，或管道名不一致）");
		if (engineProc) {
			TerminateProcess(engineProc, 9);
			CloseHandle(engineProc);
		}
		return 2;
	}
	Ok("连接管道（DACL 已放行本令牌）");
	CheckPipeDacl(pipe);

	// ------------------------------------------------------------------
	// 握手
	// ------------------------------------------------------------------
	BYTE master[ipc::kKeyBytes] = {};
	std::wstring keyErr;
	if (!g_negMode) {
		// ★ createIfMissing = **false**：主密钥只由引擎生成。
		//   两侧都"没有就创建"会互相覆盖（后起的那个赢），症状是
		//   "偶尔能连上、偶尔连不上"，极难复现。
		if (!ipc::EnsureMasterKey(master, false, &keyErr)) {
			Fail("读主密钥（DPAPI）", U8(keyErr).c_str());
			CloseHandle(pipe);
			if (engineProc) {
				TerminateProcess(engineProc, 9);
				CloseHandle(engineProc);
			}
			return 1;
		}
		Ok("读主密钥（DPAPI，只读不建）");
	}
	else {
		// 反向对照：故意用一把**错**的密钥。
		BCryptGenRandom(nullptr, master, sizeof(master), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
		Out("       [neg] 使用随机错误主密钥（不是文件里那把）");
	}

	BYTE clientNonce[32] = {};
	BCryptGenRandom(nullptr, clientNonce, sizeof(clientNonce),
		BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (!ipc::WriteLine(pipe, ipc::MakeHello(clientNonce))) {
		Fail("发送 HELLO");
		CloseHandle(pipe);
		return 1;
	}

	std::string line;
	if (!ipc::ReadLine(pipe, line, ipc::kMaxHandshakeBytes)) {
		Fail("读 WELCOME", "对端没回（握手超时或直接断开）");
		CloseHandle(pipe);
		if (engineProc) {
			TerminateProcess(engineProc, 9);
			CloseHandle(engineProc);
		}
		return 1;
	}
	if (line.rfind("ERR|", 0) == 0) {
		Fail("引擎拒绝握手", line.c_str());
		CloseHandle(pipe);
		if (engineProc) {
			TerminateProcess(engineProc, 9);
			CloseHandle(engineProc);
		}
		return 1;
	}

	ipc::WelcomeInfo wi;
	if (!ipc::ParseWelcome(line, wi)) {
		Fail("解析 WELCOME", line.c_str());
		CloseHandle(pipe);
		if (engineProc) {
			TerminateProcess(engineProc, 9);
			CloseHandle(engineProc);
		}
		return 1;
	}
	const std::wstring compat = ipc::CheckPeerCompatible(wi.protocolVersion,
		wi.abiVersion, wi.eventBytes);
	if (!compat.empty()) {
		Fail("WELCOME 兼容性校验", U8(compat).c_str());
		CloseHandle(pipe);
		if (engineProc) {
			TerminateProcess(engineProc, 9);
			CloseHandle(engineProc);
		}
		return 1;
	}
	{
		char detail[256];
		_snprintf_s(detail, _countof(detail), _TRUNCATE,
			"proto=%d abi=%lu eventBytes=%lu enginePid=%lu",
			wi.protocolVersion, static_cast<unsigned long>(wi.abiVersion),
			static_cast<unsigned long>(wi.eventBytes),
			static_cast<unsigned long>(wi.enginePid));
		Ok("握手成功（WELCOME 已验 ABI + sizeof(Event)）");
		Info("%s", detail);
	}

	BYTE sessionKey[ipc::kKeyBytes] = {};
	if (!ipc::DeriveSessionKey(master, clientNonce, wi.nonce, sessionKey)) {
		Fail("派生会话密钥（HKDF-SHA256）");
		CloseHandle(pipe);
		return 1;
	}
	SecureZeroMemory(master, sizeof(master));

	{
		// 指纹（单向）：和引擎日志里那一行比对，立刻能区分
		// "密钥不同"和"密钥相同但帧坏了"。
		const std::string fp = ipc::KeyFingerprint(sessionKey);
		Out("       session-key fp = %s（引擎日志里应出现同一串）", fp.c_str());
	}

	ipc::Aead aead;
	if (!aead.Init(sessionKey)) {
		Fail("AES-256-GCM 初始化");
		CloseHandle(pipe);
		return 1;
	}
	SecureZeroMemory(sessionKey, sizeof(sessionKey));

	// ------------------------------------------------------------------
	// 读线程
	// ------------------------------------------------------------------
	std::atomic<bool> alive{ true };
	std::wstring readerWhy;
	// StopEngine 之后对端会正常关管道 ⇒ 读线程必然以"读帧头失败"收场。
	// 那不是故障，别把它当原因打出来（否则每次通过都跟着一句"失败"，
	// 看日志的人会以为有问题 —— 判据必须只表达一件事）。
	std::atomic<bool> stopRequested{ false };
	ipc::FrameWriter writer;
	std::thread reader([&]() {
		ipc::FrameReader fr;
		ipc::Msg type = ipc::Msg::Ping;
		std::vector<BYTE> payload;
		while (alive.load(std::memory_order_relaxed)) {
			std::wstring why;
			if (!fr.Read(pipe, aead, type, payload, &why)) {
				readerWhy = why;
				break;
			}
			if (g_verbose) {
				Out("       [frame] type=%u len=%zu", static_cast<unsigned>(type), payload.size());
			}
			PushFrame(type, payload);
		}
		alive.store(false, std::memory_order_relaxed);
	});

	std::mutex writeMutex;
	auto send = [&](ipc::Msg type, const void* data, size_t len) -> bool {
		std::lock_guard<std::mutex> lock(writeMutex);
		return writer.Write(pipe, aead, type, data, len);
	};

	// ------------------------------------------------------------------
	// 判据 3：Ping → Pong（加密帧真的能双向走）
	// ------------------------------------------------------------------
	std::vector<BYTE> reply;
	const bool sentPing = send(ipc::Msg::Ping, nullptr, 0);
	const bool gotPong = sentPing && TakeFrame(ipc::Msg::Pong, reply, 3000);

	if (g_negMode) {
		// 反向对照的判据是**必须失败**：错密钥派生出的会话密钥与引擎不同，
		// 第一帧要么解不开（引擎断开），要么我们的 Pong 解不开。
		// ★ 先把自己这一侧的事实全打出来：拿到 Pong 时最需要知道的是
		//   "这帧到底是什么"，否则只能在"密钥错了"和"判据错了"之间瞎猜。
		{
			std::lock_guard<std::mutex> lock(g_framesMutex);
			char line[512];
			int n = _snprintf_s(line, _countof(line), _TRUNCATE,
				"[neg] sentPing=%d frames=%zu types=", sentPing ? 1 : 0, g_frames.size());
			for (size_t i = 0; i < g_frames.size() && n > 0 && n < 480; ++i) {
				n += _snprintf_s(line + n, _countof(line) - n, _TRUNCATE, "%u,",
					static_cast<unsigned>(g_frames[i].type));
			}
			Out("%s", line);
		}
		// 关键对照：空载荷（Ping）与有载荷（SetMode）分别试一次。
		// 如果只有空载荷能过，说明"零长度明文"绕过了 GCM 验签；
		// 如果两者都能过，说明密钥根本没参与派生（比前者严重得多）。
		{
			const uint32_t mode = 2;
			std::vector<BYTE> r2;
			const bool sentMode = send(ipc::Msg::SetMode, &mode, sizeof(mode));
			const bool gotOk = sentMode && TakeFrame(ipc::Msg::Ok, r2, 3000);
			if (gotPong && gotOk) {
				Fail("[neg] 错密钥下 Ping 和 SetMode 都成功 —— 密钥没参与加密（最严重）");
			}
			else if (gotPong && !gotOk) {
				Fail("[neg] 空载荷（Ping）被接受、有载荷（SetMode）被拒 —— 零长度明文绕过 GCM 验签");
			}
			else if (!gotPong && gotOk) {
				Fail("[neg] Ping 被拒但 SetMode 被接受 —— 判据自相矛盾，先查协议");
			}
			else {
				Ok("[neg] 错密钥下 Ping 与 SetMode 都被拒（判据有分辨力）");
			}
		}
		alive.store(false, std::memory_order_relaxed);
		CancelIoEx(pipe, nullptr);
		if (reader.joinable()) {
			reader.join();
		}
		CloseHandle(pipe);
		if (engineProc) {
			TerminateProcess(engineProc, 9);
			CloseHandle(engineProc);
		}
		Out("");
		Out("RESULT: %s  (%d ok / %d fail)", g_fail == 0 ? "PASS" : "FAIL", g_pass, g_fail);
		return g_fail == 0 ? 0 : 1;
	}

	if (!gotPong) {
		Fail("Ping → Pong", "3 秒内没有收到 Pong（帧被拒/解密失败/seq 判错）");
	}
	else {
		Ok("Ping → Pong（加密帧双向可用）");
	}

	// ------------------------------------------------------------------
	// 判据 4：ReadStats → Stats（10 个 u32）
	// ------------------------------------------------------------------
	if (send(ipc::Msg::ReadStats, nullptr, 0)
		&& TakeFrame(ipc::Msg::Stats, reply, 3000)) {
		if (reply.size() != ipc::kStatsPayloadBytes) {
			char detail[128];
			_snprintf_s(detail, _countof(detail), _TRUNCATE, "收到 %zu 字节，应为 %zu",
				reply.size(), ipc::kStatsPayloadBytes);
			Fail("ReadStats → Stats 长度", detail);
		}
		else {
			ipc::StatsPayload s = {};
			memcpy(&s, reply.data(), sizeof(s));
			if (s.enginePid != wi.enginePid) {
				Fail("Stats.enginePid 与 WELCOME 里的不一致");
			}
			else {
				char detail[256];
				_snprintf_s(detail, _countof(detail), _TRUNCATE,
					"enginePid=%lu mode=%lu injected=%lu dropped=%lu",
					static_cast<unsigned long>(s.enginePid),
					static_cast<unsigned long>(s.mode),
					static_cast<unsigned long>(s.injectedTotal),
					static_cast<unsigned long>(s.droppedEvents));
				Ok("ReadStats → Stats（长度/pid 都对）");
				Info("%s", detail);
			}
		}
	}
	else {
		Fail("ReadStats → Stats", "3 秒内没有收到 Stats");
	}

	// ------------------------------------------------------------------
	// 判据 5：事件推送 + 编解码往返
	// ------------------------------------------------------------------
	// 假事件每秒 4 条，等 3.5 秒应当收到 ≥ 8 条（留一轮的余量）。
	std::vector<Event> events;
	Sleep(3500);
	const int badFrames = DrainEvents(events);
	if (badFrames > 0) {
		char detail[128];
		_snprintf_s(detail, _countof(detail), _TRUNCATE, "%d 个 Events 帧解不开", badFrames);
		Fail("事件编解码：有坏帧", detail);
	}
	if (events.size() < 8) {
		char detail[128];
		_snprintf_s(detail, _countof(detail), _TRUNCATE, "只收到 %zu 条", events.size());
		Fail("事件推送数量不足", detail);
	}
	else {
		char detail[128];
		_snprintf_s(detail, _countof(detail), _TRUNCATE, "%zu 条", events.size());
		Ok("事件推送（Events 帧解密 + DecodeEvents 成功）");
		Info("%s", detail);
	}
	CheckEventFields(events);

	// ------------------------------------------------------------------
	// 判据 6：SetMode（请求-应答，带业务返回值）
	// ------------------------------------------------------------------
	{
		const uint32_t mode = 2;
		std::vector<BYTE> r;
		if (send(ipc::Msg::SetMode, &mode, sizeof(mode)) && TakeFrame(ipc::Msg::Ok, r, 3000)) {
			if (r.size() < 1) {
				Fail("SetMode → Ok 载荷为空");
			}
			else {
				char detail[128];
				_snprintf_s(detail, _countof(detail), _TRUNCATE,
					"引擎返回 code=%u（dry-run 下恒 1：仅表示通道走通）",
					static_cast<unsigned>(r[0]));
				Ok("SetMode → Ok（请求-应答闭环）");
				Info("%s", detail);
			}
		}
		else {
			Fail("SetMode → Ok", "3 秒内没有应答");
		}
	}

	// ------------------------------------------------------------------
	// 判据 7：StopEngine → 引擎真的退出
	// ------------------------------------------------------------------
	{
		std::vector<BYTE> r;
		stopRequested.store(true, std::memory_order_relaxed);
		const bool sent = send(ipc::Msg::StopEngine, nullptr, 0);
		const bool acked = sent && TakeFrame(ipc::Msg::Ok, r, 3000);
		if (!acked) {
			Fail("StopEngine → Ok", "没有收到确认");
		}
		else {
			Ok("StopEngine → Ok（引擎答应收尾）");
		}

		alive.store(false, std::memory_order_relaxed);
		CancelIoEx(pipe, nullptr);
		if (reader.joinable()) {
			reader.join();
		}
		CloseHandle(pipe);

		// 引擎要反注入 + 销毁共享会话，给它 15 秒。
		// ★ dry-run 下没有会话要销毁，应该很快 —— 但判据按真实上限给。
		HANDLE waitOn = engineProc;
		bool ownHandle = false;
		if (!waitOn) {
			waitOn = OpenProcess(SYNCHRONIZE, FALSE, wi.enginePid);
			ownHandle = true;
		}
		if (!waitOn) {
			Info("拿不到引擎进程句柄，跳过退出判据");
		}
		else {
			const DWORD w = WaitForSingleObject(waitOn, 15000);
			if (w == WAIT_OBJECT_0) {
				Ok("引擎已退出（StopEngine 生效）");
			}
			else {
				Fail("引擎没有在 15 秒内退出", "StopEngine 只回了 Ok 但没真停？");
			}
			if (ownHandle) {
				CloseHandle(waitOn);
			}
			else {
				CloseHandle(waitOn);
			}
			engineProc = nullptr;
		}
	}

	if (engineProc) {
		TerminateProcess(engineProc, 9);
		CloseHandle(engineProc);
	}

	Out("");
	Out("RESULT: %s  (%d ok / %d fail)", g_fail == 0 ? "PASS" : "FAIL", g_pass, g_fail);
	if (!readerWhy.empty() && !stopRequested.load(std::memory_order_relaxed)) {
		Out("reader stopped: %s", U8(readerWhy).c_str());
	}
	return g_fail == 0 ? 0 : 1;
}

#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <string.h>

// 复制被测逻辑（与 r3shieldcore_rules.cpp 修正版一致）做最小复现。
static void NextSegment(const wchar_t*& cursor, const wchar_t*& start, size_t& len)
{
	start = nullptr;
	len = 0;
	if (!cursor || *cursor == L'\0') return;
	while (*cursor == L'\\' || *cursor == L'/') ++cursor;
	if (*cursor == L'\0') return;
	start = cursor;
	while (*cursor && *cursor != L'\\' && *cursor != L'/') ++cursor;
	len = (size_t)(cursor - start);
}

static bool IsControlSetSegment(const wchar_t* t, size_t len)
{
	if (len <= 10) return false;
	if (_wcsnicmp(t, L"ControlSet", 10) != 0) return false;
	for (size_t i = 10; i < len; ++i) if (t[i] < L'0' || t[i] > L'9') return false;
	return true;
}
static bool IsCurrentControlSetSegment(const wchar_t* t, size_t len)
{
	return len == 17 && _wcsnicmp(t, L"CurrentControlSet", 17) == 0;
}

static bool KeyPrefixMatchesNoCase(const wchar_t* text, const wchar_t* prefix)
{
	if (!text || !prefix) return false;
	if (prefix[0] == L'\0') return true;
	const wchar_t* t = text;
	const wchar_t* p = prefix;
	for (;;) {
		const wchar_t *tSeg = nullptr, *pSeg = nullptr;
		size_t tLen = 0, pLen = 0;
		NextSegment(t, tSeg, tLen);
		NextSegment(p, pSeg, pLen);
		if (pLen == 0) return true;
		if (tLen == 0) return false;
		if (tLen == pLen && _wcsnicmp(tSeg, pSeg, tLen) == 0) continue;
		bool eq = (IsCurrentControlSetSegment(pSeg, pLen) && IsControlSetSegment(tSeg, tLen)) ||
		          (IsCurrentControlSetSegment(tSeg, tLen) && IsControlSetSegment(pSeg, pLen));
		if (!eq) return false;
	}
}

static size_t CountSegments(const wchar_t* path)
{
	size_t n = 0; const wchar_t* c = path;
	for (;;) { const wchar_t* s; size_t l; NextSegment(c, s, l); if (!l) break; ++n; }
	return n;
}
static bool KeyPrefixIsDescendantNoCase(const wchar_t* text, const wchar_t* prefix)
{
	if (!text || !prefix || !text[0] || !prefix[0]) return false;
	if (!KeyPrefixMatchesNoCase(prefix, text)) return false;
	return CountSegments(prefix) > CountSegments(text);
}

static int g_fail = 0;
static void T(const char* note, bool got, bool expect)
{
	printf("%s  %-56s expect=%d got=%d\n", got == expect ? "OK  " : "FAIL", note, expect, got);
	if (got != expect) g_fail++;
}

int main()
{
	setlocale(LC_ALL, ".UTF-8");
	SetConsoleOutputCP(CP_UTF8);

	printf("=== 段匹配（CurrentControlSet 等价）===\n");
	T("SYSTEM\\CurrentControlSet\\Services\\Evil  vs  SYSTEM\\CurrentControlSet\\Services",
	  KeyPrefixMatchesNoCase(L"SYSTEM\\CurrentControlSet\\Services\\Evil",
	                         L"SYSTEM\\CurrentControlSet\\Services"), true);
	T("SYSTEM\\ControlSet001\\Services\\Evil  vs  SYSTEM\\CurrentControlSet\\Services",
	  KeyPrefixMatchesNoCase(L"SYSTEM\\ControlSet001\\Services\\Evil",
	                         L"SYSTEM\\CurrentControlSet\\Services"), true);
	T("SYSTEM\\ControlSet002\\Control\\Lsa  vs  SYSTEM\\CurrentControlSet\\Control\\Lsa",
	  KeyPrefixMatchesNoCase(L"SYSTEM\\ControlSet002\\Control\\Lsa",
	                         L"SYSTEM\\CurrentControlSet\\Control\\Lsa"), true);
	T("反向：SYSTEM\\CurrentControlSet\\... vs SYSTEM\\ControlSet001\\...",
	  KeyPrefixMatchesNoCase(L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
	                         L"SYSTEM\\ControlSet001\\Control\\Lsa"), true);

	printf("\n=== 段边界不得误判 ===\n");
	T("ControlSetX（非数字）不得等价",
	  KeyPrefixMatchesNoCase(L"SYSTEM\\ControlSetX\\Services",
	                         L"SYSTEM\\CurrentControlSet\\Services"), false);
	T("ControlSet 段必须是整段（ControlSettings 不算）",
	  KeyPrefixMatchesNoCase(L"SYSTEM\\ControlSettings\\Services",
	                         L"SYSTEM\\CurrentControlSet\\Services"), false);

	printf("\n=== 原有前缀语义不得回退 ===\n");
	// ⚠️ 段比对比旧的字符前缀**更严格**，这是有意的：
	//    `RunOnce` 不应被 `Run` 前缀命中（规则表里 RunOnce 有独立条目）。
	//    旧的 _wcsnicmp 会把 RunOnce 误判成命中 Run —— 反而是 bug。
	T("RunOnce 不得被 Run 前缀命中（段边界收紧，有意）",
	  KeyPrefixMatchesNoCase(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
	                         L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
	  false);
	T("Run\\Evil 应被 Run 前缀命中（子键仍覆盖）",
	  KeyPrefixMatchesNoCase(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil",
	                         L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
	  true);
	T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe vs 规则前缀",
	  KeyPrefixMatchesNoCase(
	      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe",
	      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"), true);
	T("大小写不敏感",
	  KeyPrefixMatchesNoCase(L"system\\controlset001\\services\\evil",
	                         L"SYSTEM\\CurrentControlSet\\Services"), true);

	printf("\n=== hive 祖先命中（拖 SAM）===\n");
	T("SAM  vs  SAM\\SAM  （hive：应命中）",
	  KeyPrefixIsDescendantNoCase(L"SAM", L"SAM\\SAM"), true);
	T("SAM\\SAM  vs  SAM\\SAM （相等，不算祖先，由前缀匹配负责）",
	  KeyPrefixIsDescendantNoCase(L"SAM\\SAM", L"SAM\\SAM"), false);
	T("SYSTEM  vs  SYSTEM\\CurrentControlSet\\Services （hive：应命中）",
	  KeyPrefixIsDescendantNoCase(L"SYSTEM", L"SYSTEM\\CurrentControlSet\\Services"), true);
	T("SECURITY  vs  SECURITY\\Policy\\Secrets （hive：应命中）",
	  KeyPrefixIsDescendantNoCase(L"SECURITY", L"SECURITY\\Policy\\Secrets"), true);
	T("SOFTWARE\\Microsoft  vs  SOFTWARE\\Microsoft\\Windows NT\\... （不相关，不应命中）",
	  KeyPrefixIsDescendantNoCase(L"SOFTWARE\\Other", L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"), false);

	printf("\n%s  失败 %d\n", g_fail ? "=== 存在失败 ===" : "=== 全部通过 ===", g_fail);
	return g_fail;
}

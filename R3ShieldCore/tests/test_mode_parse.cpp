// Offline check that the ini string -> Mode mapping matches the implementation.
// Build: cl /nologo /std:c++17 /EHsc /Fe:test_mode_parse.exe test_mode_parse.cpp
#include <cstdio>
#include <cstddef>
#include <cctype>
#include <string>
#include <algorithm>

// Mirrors ToLower + Trim + the mode branches in r3shieldcore_config.cpp,
// verifying only the "string -> Mode enum" mapping against the implementation.
static const unsigned kLog = 0, kBlock = 1, kAsk = 2, kBlockAll = 3, kBlockAllSafe = 4;

static std::string ToLower(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) { return (char)::tolower(c); });
    return s;
}
static std::string Trim(const std::string& s)
{
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

static unsigned ParseMode(const std::string& value)
{
    std::string lower = ToLower(Trim(value));
    if (lower == "block") return kBlock;
    if (lower == "ask") return kAsk;
    if (lower == "block_all" || lower == "blockall" || lower == "block-all") return kBlockAll;
    if (lower == "block_all_safe" || lower == "blockallsafe"
        || lower == "block-all-safe" || lower == "block_safe"
        || lower == "blocksafe") return kBlockAllSafe;
    return kLog;
}

// struct Case hoisted to file scope: an MSVC local struct inside main()
// combined with a range-for fails to parse (C2530/C2143/C2070).
struct ModeCase
{
    const char* in;
    unsigned    want;
};

static const ModeCase kCases[] = {
    { "log",               kLog },
    { "LOG",               kLog },
    { "  block  ",         kBlock },
    { "ask",               kAsk },
    { "block_all",         kBlockAll },
    { "blockall",          kBlockAll },
    { "block-all",         kBlockAll },
    // new in this change
    { "block_all_safe",    kBlockAllSafe },
    { "BLOCK_ALL_SAFE",    kBlockAllSafe },
    { "blockallsafe",      kBlockAllSafe },
    { "block-all-safe",    kBlockAllSafe },
    { "block_safe",        kBlockAllSafe },
    { "blocksafe",         kBlockAllSafe },
    { "  block_all_safe ", kBlockAllSafe },
    // must NOT be misread as BlockAllSafe
    { "block_all_x",       kLog },
    { "foo",               kLog },
};

int main()
{
    const size_t total = sizeof(kCases) / sizeof(kCases[0]);
    const char* names[] = { "Log", "Block", "Ask", "BlockAll", "BlockAllSafe" };

    int fail = 0;
    for (size_t i = 0; i < total; ++i)
    {
        const ModeCase& c = kCases[i];
        unsigned got = ParseMode(c.in);
        bool ok = (got == c.want);
        if (!ok) ++fail;
        printf("%-22s -> %-13s (want %-13s)  %s\n",
            c.in,
            (got < 5 ? names[got] : "??"),
            (c.want < 5 ? names[c.want] : "??"),
            ok ? "PASS" : "**FAIL**");
    }
    printf("\n%d/%zu PASS\n", (int)(total - (size_t)fail), total);
    return fail ? 1 : 0;
}

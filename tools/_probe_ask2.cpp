#include <cstdio>
#include <cstring>
typedef unsigned long ULONG;
bool ShouldAskInsteadOfBlockAll(const wchar_t* keyPath, const wchar_t* valueName, ULONG op);
bool IsHighRiskRegistry(const wchar_t* keyPath, const wchar_t* valueName, ULONG op, const wchar_t** reason);

int main(){
    struct T { const wchar_t* p; const wchar_t* v; ULONG op; } t[] = {
        { L"\\REGISTRY\\MACHINE\\SOFTWARE\\CLASSES", L"", 1 },
        { L"\\REGISTRY\\MACHINE\\SOFTWARE\\CLASSES", L"", 3 },
        { L"SOFTWARE\\CLASSES", L"", 1 },
        { L"CLASSES", L"", 1 },
        { L"System\\CurrentControlSet\\Services\\Tcpip\\Parameters", L"", 1 },
        { L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", L"", 1 },
        { L"Software", L"", 1 },
    };
    for (auto&c : t) {
        const wchar_t* why=nullptr;
        bool ask = ShouldAskInsteadOfBlockAll(c.p, c.v, c.op);
        bool hr  = IsHighRiskRegistry(c.p, c.v, c.op, &why);
        printf("op=%lu ask=%-5s high=%-5s  %ls\n", c.op, ask?"ASK":"BLOCK", hr?"HIGH":"-", c.p);
    }
    return 0;
}

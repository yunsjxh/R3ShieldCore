#include "r3shieldcore/r3shieldcore_shared.h"
// ⚠️ 本文件是 v10 时代的**手工**头文件自检（**不属于任何构建闸门** ——
//    `build_ut.sh` / `build_guard_ut.sh` / `build_verify_dist.sh` 都不引用它）。
//    当前 `AbiVersion = 20`（v49：`Policy` 尾部追加 `NeverInjectCount` /
//    `NeverInjectPaths`）。**别再把它写成硬编码的版本号断言** —— 那样每升一版
//    都得回来改，而它又不会被编译，只会变成一个"看着像真的"的假事实。
//    要查当前值请看 `r3shieldcore_shared.h` 的 `AbiVersion` 注释块（有完整历史）。
static_assert(sizeof(R3ShieldCore::ChannelHeader) == 32, "ch");
int main() {
    using namespace R3ShieldCore;
    const ULONG types[] = {9,10,11};
    for (ULONG t : types) { (void)ObjectTypeName(t); (void)AnyOpName(t, 1); (void)IsBlockableOp(t, 2); }
    (void)DllLoadOpName(1); (void)ClipboardOpName(2); (void)SpawnOpName(3);
    (void)sizeof(Event); (void)sizeof(Policy);
    return 0;
}

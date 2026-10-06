# 窗口操作 Hook — 技术预研

> 状态：纯预研，未改任何产品代码。文末附本次为取证新建的只读探针说明。
> 结论：可行，机制就是复用现有的 MinHook inline detour 挂 `user32.dll` 导出
> （`InputHookGuard` 已有先例）；但它是可见性能力，不是硬边界，且绝不能一刀切拦。

---

## 0. 结论速览（TL;DR）

| 问题 | 结论 |
|---|---|
| 能不能挂？ | **能**。同一套注入 + MinHook detour，挂 `user32.dll` 导出即可，**已有先例**（`InputHookGuard` 已挂 `user32` 的 13 个函数）。 |
| 覆盖什么？ | **应用层**的窗口生命周期 / 位置 / 前台 / 样式 / 桌面操作（创建、销毁、显隐、移动、置顶、抢前台、改扩展样式、切桌面…）。 |
| 覆盖不到什么？ | 直 `syscall`（`NtUserXxx` 自建桩）、**未注入进程**（`explorer`/`dwm`/`ctfmon`/`TextInputHost`）、内核 `win32k`、COM/UI Automation 路径。 |
| 最大风险？ | 窗口操作是**交互热路径**（拖窗口每秒几百次 `SetWindowPos`）——「调了就报」= 日志雪崩 + 卡 UI；**BLOCK 会直接把界面搞坏**。 |
| 推荐做法？ | **只读监控（LOG / ASK）**，按**特征 + 密度**过滤，分阶段先挂低频高信号的那批。 |
| 不建议？ | `SetWindowsHookEx(WH_CBT)` 全局钩子、hook `NtUserMessageCall`、拦窗口消息发送方（项目 §3.9 已论证否决）。 |

---

## 1. 背景：本项目的 Hook 架构（决定"能不能复用"）

现有机制（源码核对）：

1. **全局注入**：`AllProcessesInjector` 用 `NtGetNextProcess` 枚举所有进程，经 APC / 远程线程把
   `r3shieldcore-lib.dll` 注入进每个**非排除**进程（`ShouldSkipProcessInjection`）。
2. **进程内 detour**：注入后 `CustomizationSession::InitSession` 调 `MH_Initialize` +
   各 guard 的 `Install()`，用 **MinHook** 对目标导出做 **inline detour**（改函数头几字节跳走）。
3. **判定与上报**：每个 hook 里 `Evaluate()` 读共享内存里的 `Policy->Mode` →
   `Publish()` 把 `R3ShieldCore::Event` 写进无锁环形缓冲 → 引擎侧消费落盘/弹窗。
4. **卸载安全**：`MH_DisableHook` → `WaitForHooksToDrain` → `MH_Uninitialize`（三步不可换，见 HANDOVER §3.5）。

**关键先例**：`InputHookGuard` 与 `ScreenGuard` **已经**对 `user32.dll` / `gdi32.dll` 做 inline detour
（`SetWindowsHookEx`、`SendInput`、`BlockInput`、`ClipCursor`、`PrintWindow`…）。
所以「挂窗口操作」**不是新机制，是同一机制换一批目标函数** —— 工程风险大幅降低。

**注意两条独立的进程筛选**（HANDOVER 铁律 29）：
- `ShouldSkipProcessInjection`（`kNeverInject[]`）—— 决定「注不注入」；
- `ComputeBypass`（白名单 + 微软签名）—— 决定「挂不挂 hook」。
两者都会让 `explorer.exe` / `dwm.exe` / `ctfmon.exe` / `TextInputHost.exe` 等**看不到**。

---

## 2. 窗口操作的 API 版图（要挂谁）

### 2.1 分层

```
应用代码 (你的程序)
   │  调用 Win32 导出
   ▼
user32.dll!SetWindowPos          ← ① 应用导入点（可挂）
   │  FF 25 → 直接跳
   ▼
win32u.dll!NtUserSetWindowPos    ← ② 用户态最底层（可挂，但未文档化）
   │  syscall
   ▼
win32k.sys / win32kfull.sys      ← ③ 内核（用户态产品够不到）
```

### 2.2 实证：`user32` 的窗口函数分两类

用本次新建的只读探针 `tools/winmsg_stub_probe.exe`（解析本机 `user32.dll` / `win32u.dll`
导出首字节）实测，**12 个函数分三档**：

| user32 导出 | 首字节 | 性质 | 跳向 |
|---|---|---|---|
| `SetWindowPos` | `FF 25 …` | **纯壳** | `win32u!NtUserSetWindowPos` **精确命中** |
| `ShowWindow` | `FF 25 …` | **纯壳** | `win32u!NtUserShowWindow` **精确命中** |
| `DestroyWindow` | `FF 25 …` | **纯壳** | `win32u!NtUserDestroyWindow` **精确命中** |
| `MoveWindow` | `FF 25 …` | **纯壳** | `win32u!NtUserMoveWindow` **精确命中** |
| `SetForegroundWindow` | `48 FF 25 …` | **纯壳** | `win32u!NtUserSetForegroundWindow` **精确命中** |
| `EnableWindow` | `48 FF 25 …` | **纯壳** | `win32u!NtUserEnableWindow` **精确命中** |
| `SetWindowLongPtrW` | `45 33 C9 E9 …` | 短前导 + `jmp` | user32 内部（再转 win32u） |
| `CreateWindowExW` | `4C 8B DC …` | **真实实现** | 内部再调 `NtUserCreateWindowEx` |
| `SendMessageW` | `48 89 5C 24 …` | **真实实现** | 内部再走消息路径 |
| `PostMessageW` | `48 89 5C 24 …` | **真实实现** | 内部再走消息路径 |
| `SetWindowTextW` | `48 89 5C 24 …` | **真实实现** | — |
| `SetWindowsHookExW` | `48 83 EC …` | **真实实现** | — |

`win32u.dll` 实测导出 **753 个 `NtUser*`**，含 `NtUserCreateWindowEx` / `NtUserSetWindowPos` /
`NtUserShowWindow` / `NtUserSetForegroundWindow` / `NtUserMoveWindow` / `NtUserDestroyWindow` /
`NtUserSetWindowLongPtr` / `NtUserMessageCall` / `NtUserEnableWindow` 等。

**推论（决定挂点）**：
- 应用**导入的是 `user32`**，所以**挂 `user32` 导出就能覆盖应用面** —— 纯壳被替换后不会再跳 `win32u`，
  真实实现被替换后直接进我们的 detour。✅
- 挂 `win32u!NtUser*` 是**更低一层**：能多抓到「user32 内部绕过导出的调用」，但未文档化、更热、更易误伤。
- **直 `syscall`**（程序自带 `NtUserSetWindowPos` 桩）两条都拦不到 —— 这是**可见性**而非硬边界的根因。

### 2.3 值得监控的窗口操作清单（按威胁价值分组）

| 组 | API | 为什么值钱 |
|---|---|---|
| **窗口生命周期** | `CreateWindowExW/A`、`DestroyWindow`、`ShowWindow(Async)` | 新建/销毁/隐藏窗口 = overlay、无窗口进程「凭空长窗」 |
| **位置/尺寸** | `SetWindowPos`、`MoveWindow`、`DeferWindowPos` | **全屏置顶覆盖**（锁屏勒索 / 假 UAC / 假登录框）核心手法 |
| **前台/焦点** | `SetForegroundWindow`、`BringWindowToTop`、`SetActiveWindow`、`SetFocus` | **抢前台**（假弹窗、点击劫持） |
| **样式** | `SetWindowLongPtrW/A`（`GWL_EXSTYLE`：`WS_EX_TOPMOST` / `WS_EX_LAYERED` / `WS_EX_TRANSPARENT`） | **透明/穿透/置顶覆盖层**——最典型的 UI 攻击特征 |
| **可见性/文本** | `EnableWindow`、`SetWindowTextW` | 伪装系统窗口标题、禁用父窗口 |
| **桌面/窗口站** ★ | `CreateDesktopW`、`SwitchDesktop`、`SetThreadDesktop`、`OpenInputDesktop` | **建新桌面藏行为 / 假锁屏**，隐蔽性极高 |
| **消息（不建议挂）** | `SendMessageW`、`PostMessageW`、`NtUserMessageCall` | 太热、递归风险，§3.9 已否决 |

---

## 3. 可行机制对比

| 机制 | 覆盖面 | 代价/风险 | 本项目适配 | 结论 |
|---|---|---|---|---|
| **A. inline detour `user32` 导出** | 应用层 Win32 调用 | 低（既有模式）；热路径需过滤 | ★★★ 与 `InputHookGuard` 同构 | **推荐** |
| B. inline detour `win32u!NtUser*` | 更全（含 user32 内部） | 未文档化、更热、可能误伤内部调用 | ★★ 备选/二期 | 视需要 |
| C. `SetWindowsHookEx(WH_CBT)` 全局钩子 | 所有 GUI 线程的窗口事件 | 需独立 hook DLL、UIPI 限制、与 `InputHookGuard` 自监控冲突、注入足迹大 | ★ | **不建议** |
| D. 子类化 / 消息钩子 | **仅本进程自己的窗口** | 零 | ★ | 与产品无关（§3.9 已用在自己的窗口上） |
| E. 内核 `win32k` 过滤 | 最全 | 需驱动；`win32k` 受 PatchGuard 保护 | ✗ | **不可行**（用户态产品） |

C 不如 A 的原因：
- WH_CBT 全局钩子要求把回调 DLL 注入**所有 GUI 进程**，且**只能到同/低完整性**（UIPI 会把高完整性进程挡掉）；
- 我们的 `InputHookGuard` 正在监控 `SetWindowsHookEx` —— 自己装全局钩子会**自触发告警**；
- A 已经在我们注入的每个进程里了，**白嫖现有覆盖**，零额外注入足迹。

---

## 4. 可覆盖范围（能力边界）

| 能覆盖 ✅ | 覆盖不到 ❌ |
|---|---|
| 被注入进程（绝大多数应用：浏览器、Office、第三方程序）的 `user32` 窗口调用 | **未注入进程**：`explorer.exe`/`dwm.exe`/`ctfmon.exe`/`TextInputHost.exe`（在 `kNeverInject`） |
| 跨进程窗口操作**的调用方**（我们 hook 的是调用方进程；目标 hwnd 可用 `GetWindowThreadProcessId` 反查） | **直 `syscall`** 的调用方（自建 `NtUserXxx` 桩） |
| 纯壳 + 真实实现两类 `user32` 导出 | 内核 `win32k` 侧的窗口操作 |
| `GWL_EXSTYLE` 置顶/分层/穿透等覆盖层特征 | **COM / UI Automation**（`IWindowProvider`）路径 |
| 桌面 / 窗口站操作（`CreateDesktop`/`SwitchDesktop`…） | 通过 `win32u` 直调（少见） |

> 与产品既有定位一致：`ScreenGuard` 也明说「看不到 Desktop Duplication / WinRT 捕获」，
> 定位是**可见性**。窗口 Hook 同理。

---

## 5. 前提条件与依赖

1. **`user32.dll` 必须已加载**：`Install()` 里先 `GetModuleHandleW(L"user32.dll")`，
   为 `NULL` 就跳过（控制台/服务进程）—— `InputHookGuard` 已有此模式，直接照抄。
2. **引擎高完整性**：项目铁律 19 —— 执行清单必须 `requireAdministrator`。
   高完整性**对我们有利**：UIPI 只限制「低→高发消息」，不限制我们在**进程内**观测。
3. **注入覆盖**：目标进程要被注入（受 `kNeverInject` / `ComputeBypass` 约束）。
4. **ABI 变更**（若要新开一类，走 HANDOVER §二 的 **11 处清单**）：
   - `ObjectType += Window = 18`；
   - 新 `WindowOp` 枚举；
   - `Policy::Flags2 += FlagHookWindow = 0x08`（**当前 0x01/0x02/0x04 已用，0x08 是下一个空闲位**）；
   - `Event::Flags2 +=` 覆盖层/跨进程/桌面等位（**当前用到 0x00040000，0x00080000 起空闲**）；
   - 升 `AbiVersion`；改 `build.sh` **和** `.vcxproj` 两套清单。
   - ⚠️ 若**复用 `InputHook` 类**（只加 `HookOp` 值），则走轻量路径（改 2 处），但语义会混。
5. **开关**：`r3shieldcore_config.cpp` 的 ini 解析 + `app.cpp` 横幅。

---

## 6. 主要限制与风险（★ = 必须正面处理）

1. ★★★ **热路径 / 性能**：`SetWindowPos` / `MoveWindow` / `ShowWindow` / `EnableWindow` 在拖拽、
   重绘、布局时**每秒数百次**。**绝不能「调了就报」** —— 必须按项目铁律 5 用
   **「特征 + 密度（窗口 + 阈值 + 冷却）」**。否则日志雪崩 + 交互卡顿。
2. ★★★ **BLOCK 会毁 UI**：若在 `block_all` 下拒 `ShowWindow`/`SetWindowPos`，
   正常程序窗口**画不出来 / 拖不动** → 正是铁律 11 的「只能看不能用」。
   ⇒ 窗口 guard 应**只读监控**，或在**极窄的高危特征**（如全屏 topmost 覆盖层）上才 ASK。
3. ★★ **直 `syscall` 绕过**：自建 `NtUserXxx` 桩的调用方看不到 —— 诚实标注为可见性边界。
4. ★★ **未注入进程盲区**：`explorer`/`dwm` 等窗口操作不可见（它们本就在 `kNeverInject`）。
5. ★★ **递归 / 自触发**：hook 内**不得**再调 `user32` 会走同一 detour 的函数（如自己调
   `SetWindowPos` 去挪窗）—— 会递归。hook 内只用**无窗口**的纯查询 API。
6. ★ **`SendMessageW`/`PostMessageW` 特别危险**：消息泵内部大量调用，hook 它们易递归、
   且项目 §3.9 已论证「窗口消息路径极热、拦不住直 syscall 的发送方」→ **不挂**。
7. ★ **卸载安全**：新 guard 必须纳入 `MH_DisableHook → WaitForHooksToDrain → MH_Uninitialize` 序列，
   否则重演「trampoline 被释放、在飞线程野指针、宿主 `c0000005`」（HANDOVER §3.5）。
8. **UIPI（观测侧不阻塞）**：只影响「我们主动给别人窗口发消息去拦」这种方案（本方案不用）。
9. **噪音 vs 真信号**：窗口操作海量，判据稍宽就淹真信号（项目反复踩的坑，如 hosts 时间戳、PowerShell 235 条）。

---

## 7. 本项目中的可行性评估

| 维度 | 评级 | 说明 |
|---|---|---|
| 机制复用 | **高** | 与 `InputHookGuard` 完全同构，已有 `user32` detour 先例 |
| 覆盖价值 | **中高** | 覆盖「UI 攻击 / overlay / 锁屏 / 抢前台 / 切桌面」这一整类，现有 guard 无此面 |
| 工程改动 | **中** | 新开一类 = 11 处清单；复用类 = 2 处 |
| 性能风险 | **中高** | 取决于过滤设计；不做密度过滤会卡 UI |
| 破坏性风险 | **中** | 只要**不 block** 即可控 |
| 定位一致性 | **高** | 与产品「可见性」定位、既有隐私面（摄像头/输入/截屏）同族 |

总评：技术可行、工程可控、与产品契合；主要成本在「过滤判据的设计」而不是「能不能挂」。

---

## 8. 推荐方向（分阶段）

**Phase 1 — 只读监控（低风险、高价值）**
挂**低频高信号**子集，`user32` 导出：
- `CreateWindowExW`（窗口创建）、`ShowWindow`、`SetWindowLongPtrW`（EX 样式）、
  `SetForegroundWindow`、`CreateDesktopW` / `SwitchDesktop` / `SetThreadDesktop`。
- `SetWindowPos` / `MoveWindow` **仅按特征**上报（全屏 + `HWND_TOPMOST` + 无标题/工具窗样式 + 非本进程前台）。
- 全部 **LOG / ASK**，**不参与 block_all 的直接拒绝**。

**Phase 2 — 规则层特征判据（威胁语义）**
在 `r3shieldcore_rules.cpp` 加「UI 攻击」判据（照 `IsHighRiskInputInjection` 的形状）：
全屏 topmost 覆盖层、`WS_EX_LAYERED|WS_EX_TRANSPARENT` 穿透层、非前台进程抢前台、
新建桌面、跨进程改他人窗口样式。

**Phase 3（可选）— 加深到 `win32u!NtUser*`**
仅当发现「应用层壳被绕过」的真实需求时再做（未文档化，需单独验证）。

**明确不做**：`WH_CBT` 全局钩子；hook `SendMessageW`/`PostMessageW`/`NtUserMessageCall`；
在 block_all 下拦窗口操作；把窗口 Hook 当硬边界宣传。

---

## 9. 预研结论

1. **可行**：复用现有注入 + MinHook inline detour 机制，挂 `user32.dll` 导出即可，
   **`InputHookGuard` 已是同款先例**，不需要新机制、不需要驱动。
2. **挂点是 `user32` 而非 `win32u`**：实证表明应用导入的是 `user32`，挂它即覆盖应用面；
   `win32u` 是可选加深层。
3. **它是「可见性」能力，不是硬边界**：直 `syscall`、未注入进程、内核、COM/UIA 都是盲区 ——
   与 `ScreenGuard`/`DllLoadGuard` 的既有定位一致，需在文案里讲清。
4. **最大工程风险是过滤设计，不是可行性**：窗口操作是交互热路径，必须「特征 + 密度」过滤，
   且**只读/不拦**，否则会卡 UI 或毁界面。
5. **建议按 Phase 1 落地**（只读监控低频高信号子集），先拿到数据再谈 Phase 2 判据。

---

## 附：本次为取证新建的只读探针

- `tools/winmsg_stub_probe.cpp` / `.exe` —— **只读**解析本机 `user32.dll`/`win32u.dll` 导出首字节，
  证明「窗口函数是纯壳跳 win32u 还是 user32 内真实实现」。**未改任何产品代码**，
  仅新增一个独立诊断程序（与 `tools/` 下既有 90+ 探针同性质）。如不需要可直接删除。

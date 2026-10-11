# 拦截并替换 Hook 回传数据 — 技术预研

> 状态：**预研 + 已落地（v67 屏幕 / v70 剪贴板 / v71 注册表值 / v72 注册表枚举 /
> v73 摄像头）+ 端到端夹具升级为三面（v74）**。预研结论来自源码核对（已标注文件:行）。
> 2026-10-10 的落地次序：
> - **v67** Phase 1 屏幕面（黑帧），落地到 `ScreenGuard`（文末第 1 段落地记录）；
> - **v69** 限定注入范围（ini `test_inject_only=` / `mode=test`）+ 端到端夹具
>   （文末第 2 段；v68 的命令行版已被 v69 替换并删除）；
> - **v70** 剪贴板面（`GetClipboardData` 替换 + `CloseClipboard` 回收，文末第 3 段）；
> - **v71** 注册表「值替换」面（`NtQueryValueKey` 数据区清零，文末第 4 段）；
> - 同期 **摄像头面可行性探针**（真机 26/0 跑通；当时**规则要改、未接生产**，文末第 5 段）；
> - **v72** 注册表「枚举隐藏」面（`NtEnumerateKey` / `NtEnumerateValueKey` 索引重映射，文末第 6 段）；
> - **v73** 摄像头「帧替换」面（Media Foundation vtable patch，文末第 7 段）；
> - **v74** 决策档位 `Action` 收敛为共享枚举 + 端到端夹具升级为**三面**
>   （屏幕 / 剪贴板 / 注册表），文末第 8 段。
> 结论：机制可行（同一套 MinHook detour / vtable patch），但它是**与现有动作模型正交的
> 第二条决策轴**，且**比 Block 危险得多** —— Block 让程序"失败"，Spoof 让程序"带着假
> 数据继续跑"。建议只在高可控的窄面上做；定位是**提高成本**，不是硬边界。

---

## 0. 结论速览（TL;DR）

| 问题        | 结论                                                                                                                                         |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| 能不能做？     | **能**。out 参数指向的内存就在**调用者地址空间**，而 hook 运行在**同一进程内**，可直接改写。**已本机实测跑通**（自包含探针 9/9 PASS，见附录）。                                                                                  |
| 是新机制吗？    | **不是**。仍是 `MH_CreateHook` inline detour；改的是"detour 里做什么"，不是"怎么挂"。                                                                          |
| 那难点在哪？    | **不在能不能改，在改了之后的一致性**。同一个信息有 N 条获取路径，改一条 = 可被另一条戳穿。                                                                                         |
| 现有代码有先例吗？ | **有一半**。`NtOpenProcess_Hook` 已经在**改输入参数**（剥 `DesiredAccess` 危险位，`process_guard.cpp:1948-1963`）——证明"非拒绝式干预"这条路已经走通；但**改回传数据（out 参数）一处都没有**。 |
| 最大的风险？    | ★★★ **宿主崩溃**。`Block` 走的是程序的错误分支（程序都有错误处理）；`Spoof` 让程序按**假数据**继续跑（多数程序对"成功"返回值**不做校验**）⇒ 越界 / 空指针 / 逻辑错乱。                                   |
| 建议做哪一面？   | **Phase 1 只做屏幕（黑帧）与剪贴板**：单次调用、格式固定、无流式状态、无多路径强一致性要求。                                                                                       |
| 明确不做？     | 文件内容替换、进程/模块枚举隐藏、网络数据替换 —— 见 §6.2、§8。                                                                                                      |
| 定位一致吗？    | **不一致，要讲清**。现有产品是「可见性 + 拒绝」；替换是「**主动欺骗**」，属于蜜罐/反侦察语义。                                                                                      |

---

## 1. 背景：现有 Hook 架构与"动作模型"（决定能不能复用）

### 1.1 机制（与《窗口操作Hook-技术预研》同源，不再重复）

全局注入 `r3shieldcore-lib.dll` → `CustomizationSession::InitSession` 里 `MH_Initialize` +  
逐 guard `Install()`（`customization_session.cpp:60-77`，共 17 个 guard）→ 每个 guard 用  
MinHook 对目标导出做 inline detour → 判定结果 `Publish()` 进无锁环形缓冲。  
卸载序列 `MH_DisableHook → WaitForHooksToDrain → MH_Uninitialize`（`customization_session.cpp:391-398`）。

### 1.2 现有动作模型：**三档，且没有"替换"这一档**

每个 guard **各自定义**一份同样的枚举（17 份重复，例如 `file_guard.cpp:130-135`）：

```cpp
enum class Action { Pass, Record, Block };
```

它最终映射到共享 ABI 的 `Decision`（`shared/r3shieldcore/r3shieldcore_shared.h:911-916`）：

```cpp
enum class Decision : ULONG { Allowed = 0, Blocked = 1, WouldBlock = 2 };
```

**全部 17 个 guard 的 detour，返回路径只有两种**（实证）：

| 分支                    | 行为                        | 例                                                                                                                                |
| --------------------- | ------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `Action::Block`       | **不调原函数**，直接返回伪造的**失败**结果 | `file_guard.cpp:967-972` → `STATUS_ACCESS_DENIED`；`screen_guard.cpp:248-254` → `FALSE`；`clipboard_guard.cpp:236-241` → `nullptr` |
| `Action::Pass/Record` | 调原函数，**原样返回真实结果**         | `file_guard.cpp:973-982`                                                                                                         |

**没有任何一处改写返回值或输出缓冲区**（全仓 grep `spoof/fake/伪造/回填` 无一命中实现）。  
唯一的"改写"是 `NtOpenProcess_Hook` 改**输入**参数（剥权限），不是改回传数据。

### 1.3 关键架构判断：这是一个**正交的第二决策轴**

现有 `Action` 回答的是"**这次调用怎么办**"。替换回传数据回答的是"**结果内容是什么**"。  
二者不是同一个维度 —— 不能简单地"给 `Action` 加一个值"就完事，因为：

- `Block` 也是"返回非真实结果"（伪造的是**失败**）；
- `Spoof` 与 `Block` 同族，区别只在**伪造内容**（成功 + 假数据 vs 失败）；
- 而 `Spoof` 还要额外回答两个 Block 不需要回答的问题：**① 要不要先真调一次？② 假数据从哪来？**

所以本预研的产出**不是**"加个枚举"，而是下面这套设计问题。

---

## 2. "回传数据"的版图：要替换的是什么

### 2.1 三类"回传数据"（复杂度递增）

| 类型              | 说明                                                      | 改写位置                                                                    | 难度    |
| --------------- | ------------------------------------------------------- | ----------------------------------------------------------------------- | ----- |
| **A. 返回码**      | 只把 `NTSTATUS` / `BOOL` / `HRESULT` 翻转（如失败→成功），**不提供内容** | 函数返回值                                                                   | 低     |
| **B. 输出缓冲区**    | 改写 out 参数指向的内存（结构体 / 数组 / 字节流）                          | `IoStatusBlock->Information`、`PDWORD lpcbData`、`UNICODE_STRING`、`**out` | **中** |
| **C. 流式 / 有状态** | 内容按偏移推进，需维护影子状态与游标                                      | B + 影子状态机                                                               | **高** |

> **本项目真正有价值的是 B**。A 单独做价值有限（只是"假装成功"）；  
> C 是 B 的加强版，代价是必须维护影子数据。

### 2.2 可替换的数据面（按"难度 × 一致性风险"排序）

| 数据面        | 代表 API（现有 guard 已挂/可挂）                                                                    | 替换难度   | 一致性风险  | 多路径漏洞                               |
| ---------- | ----------------------------------------------------------------------------------------- | ------ | ------ | ----------------------------------- |
| **屏幕像素** ★ | `BitBlt` / `StretchBlt` / `GetDIBits` / `PrintWindow`（`screen_guard.cpp:230/264/301/359`） | 低      | 低      | Desktop Duplication / WinRT（既有已知盲区） |
| **剪贴板** ★  | `GetClipboardData`（`clipboard_guard.cpp:214`）                                             | 低      | 低      | OLE 拖放 / 直 `NtUserGetClipboardData` |
| 摄像头帧       | `MFCreateDeviceSource` 等（`camera_guard.cpp:364+`）                                         | 中      | 中      | 内核 / 新 MediaFoundation 路径           |
| 注册表值       | `NtQueryValueKey` / `NtEnumerateKey` / `NtEnumerateValueKey`                              | 中      | **中高** | hive 直读 / `NtQueryKey` 各变体          |
| 文件内容       | `NtReadFile` / `NtQueryInformationFile` / `NtQueryDirectoryFile`                          | 高      | **高**  | **内存映射 / 裸盘 / 备份 API**              |
| 进程·模块枚举    | `NtQuerySystemInformation` / `EnumProcesses` / `CreateToolhelp32Snapshot`                 | 高      | **高**  | 多套枚举 API + 句柄表 + 性能计数器              |
| 网络数据       | `recv` / `WSARecv` / `DnsQuery_W`                                                         | **极高** | 极高     | **TLS 加密 / 直 socket / 驱动**          |
| 系统时间       | `GetSystemTime` / `NtQuerySystemTime`                                                     | 低      | 低      | 中（多源校时）                             |

★ = 建议优先。理由：**单次调用、数据格式固定、无流式状态、不存在强"多路径必须一致"的要求**  
（屏幕截一次是黑的就是黑的，不会有第二条路把它变回真的 —— 除了既有的 Desktop Duplication 盲区）。

---

## 3. 可行机制对比

| 机制                         | 覆盖面                        | 代价/风险                                                               | 本项目适配               | 结论              |
| -------------------------- | -------------------------- | ------------------------------------------------------------------- | ------------------- | --------------- |
| **A. detour 内直接改写 out 参数** | 被注入进程的该 API 调用             | 低（同进程、同地址空间）；需 `__try` 保护                                           | ★★★ 与现有 guard 完全同构  | **推荐**          |
| B. detour 内先真调、再改结果        | 同上 + 保留真实对象状态              | 中（真实副作用 + 需重入保护）                                                    | ★★★ 推荐用于"需要句柄/对象"的面 | **推荐（B 的默认形态）** |
| C. 只翻转返回码（类型 A）            | 同上                         | 极低                                                                  | ★★ 价值有限             | 可选/过渡           |
| D. 内存映射层改写                 | 可覆盖 `CreateFileMapping` 路径 | 需挂 `NtCreateSection` + `NtMapViewOfSection`，映射后是**直接内存访问**，无 API 可拦 | ✗                   | **不可行**（见 §4）   |
| E. 内核过滤（minifilter / 回调）   | 最全                         | 需驱动；本项目用户态定位                                                        | ✗                   | 不适用             |

**为什么 A/B 在本项目是"低代价"**：`NtWriteFile_Hook` 已经直接拿到调用者的 `PVOID Buffer`  
（`file_guard.cpp:1038-1040`）——**读**得到就**写**得到，同一块内存、同一个地址空间。  
写与读的唯一区别是**必须假定目标页可能只读/已释放**，因此要 `__try/__except` 包住  
（现有 detour 已普遍使用 `__try`，如 `file_guard.cpp:941`）。

---

## 4. 能力边界（诚实标注）

| 能覆盖 ✅                | 覆盖不到 ❌                                                                             |
| -------------------- | ---------------------------------------------------------------------------------- |
| 被注入进程通过**被挂导出**获取的数据 | **内存映射**：`CreateFileMapping` + `MapViewOfFile` 之后是直接内存访问，**无 API 可拦**（文件内容替换的致命盲区） |
| 应用层的 Win32 / NT 导出调用 | **直 `syscall`**：自建 `NtXxx` 桩的调用方                                                   |
| 同进程内的 out 参数改写       | **未注入进程**（`kNeverInject`：`explorer`/`dwm`/`ctfmon`…）                               |
| 单次、格式固定的数据（屏幕/剪贴板）   | **内核 / 驱动**侧读取（`win32k`、minifilter 视角）                                             |
| —                    | **加密通道**：TLS 之上的网络数据在用户态已不可读                                                       |
| —                    | **多路径不一致**：隐藏了 `NtQuerySystemInformation`，句柄表/性能计数器仍有它                             |

> **核心边界结论**：替换数据是**可见性 / 欺骗性能力**，不是硬边界。  
> 一旦被替换的信息有**第二条获取路径**，一致性就可能被戳穿 —— 这比"拦截"脆弱得多  
> （拦截只是"这条路走不通"，替换是"这条路给了你错的东西"）。

---

## 5. 前提条件与依赖

1. **必须先定三个设计问题**（本文 §2.1 的 B 类，缺一不可）：
   - **① 要不要先真调原函数？**
     - *不调*：快、无副作用；但对象状态是假的（句柄无效 ⇒ 调用者后续操作失败 ⇒ 易暴露）。
     - *调了再改*（推荐）：真实对象状态 + 假内容；代价是真实副作用（如文件被真打开）。
     - ⚠️ **必须按 API 面分别决定**：文件读**必须**先真调（否则没有有效句柄）；  
       枚举类可以**不调**（自己构造数组）。
   - **② 假数据从哪来？** 静态常量 / ini 配置 / 影子文件 / 真数据变形（全零化、涂黑）。
   - **③ 一致性由谁保证？** 见 §6.2 —— 这是最难的部分，必须有明确答案才动手。
2. **重入保护**：若替换逻辑要"读真实数据"，必然再进自己的 detour。  
   现成模式已有：`__declspec(thread) bool g_inOpenProcessHook`（`process_guard.cpp:1844`）、  
   `__declspec(thread) int g_loaderDepth`（`dll_load_guard.cpp:417`）。**直接照抄，不要自创**。
3. **ABI 改动清单**（若新开一类，走 HANDOVER §二 的 11 处清单）：
   - `Action` 枚举加 `Spoof`（17 份要同步 —— **这是重复定义带来的成本，见 §6.6**）；
   - `Decision` 加 `Spoofed = 3`（**共享 ABI，必须升 `AbiVersion`**，当前 = 20，  
     `shared/r3shieldcore/r3shieldcore_shared.h:23`）；
   - `Policy::Flags2` 加开关位（**尾部追加**，且升 `AbiVersion`）；
   - `Event::Flags2` 加语义位（标注"本次结果是伪造的"，**可诊断性要求，见 §6.5**）；
   - `ObjectType += Spoof = 19`（若新开一类）；
   - 改 `build.sh` **和** `.vcxproj` 两套清单。
   - ⚠️ 若**复用某个已有类**（只加 `Action` 值），走轻量路径（改 2 处），但语义会混。
4. **开关**：`r3shieldcore_config.cpp` 的 ini 解析 + `app.cpp` 横幅（与既有开关同模式）。
5. **本机约束**：★ 本项目**禁止在本机运行引擎**（全局注入会 hook 编辑器 ⇒ 崩）。  
   因此本文的验证方案**不能靠跑引擎**，必须用**独立探针**（见文末附录）。

---

## 6. 主要限制与风险（★ = 必须正面处理）

1. ★★★ **宿主崩溃风险远高于 Block**：  
   `Block` 让调用失败 —— 程序走的是**它自己写好的错误分支**；`Spoof` 让调用成功并返回假数据 ——  
   程序**不会校验**（谁能想到 `NtQueryInformationFile` 返回的 `EndOfFile` 是假的？）⇒  
   按假长度分配 / 按假指针解引用 ⇒ **越界、空指针、静默数据损坏**。  
   ⇒ 任何替换面都必须先回答："**程序拿到这个假值之后会用它做什么？**"
2. ★★★ **一致性是多路径问题，不是单点问题**：  
   文件内容有 ReadFile / 内存映射 / 裸盘 / 备份 API 至少四条路；进程枚举有  
   `NtQuerySystemInformation` / `EnumProcesses` / Toolhelp / 句柄表 / 性能计数器多条路。  
   **改一条 ≠ 这件事被覆盖**（正是铁律 34 的翻版）。  
   ⇒ 替换面的选择**必须**先做"多路径盘点"，盘不出闭环就不要做。
3. ★★★ **可检测性（反欺骗）**：  
   伪造数据与真实世界存在矛盾 —— 隐藏进程后句柄表/性能计数器仍有它；涂黑屏幕后  
   Desktop Duplication 仍是真画面。攻击者/检测方**专挑这些矛盾点**。  
   ⇒ 替换**天然是"部分覆盖"**，必须按可见性能力标注，不能宣传成"隐藏"。
4. ★★ **结构体 / 长度字段的一致性**：  
   `UNICODE_STRING.Length` 与 `MaximumLength`、`IoStatusBlock->Information`、  
   `PULONG ReturnLength`、`REG_*` 的类型与 `cbData` —— **写多一个字节都可能让调用者越界**。  
   ⇒ 必须有"**写入前算长度、写入后回填长度**"的固定套路，且**每条 detour 单独测**。
5. ★★ **可诊断性（铁律 97 / 99 / 100）**：  
   "没替换成功"必须能分型：**① 没看见调用 / ② 看见了但没规则 / ③ 有规则但写错了**。  
   ⇒ 事件里必须带 `Spoofed` 标记位（否则"替换了"和"原样放行"在日志里长得一样）；  
   ⇒ 首行立即打、带原因 + 心跳。
6. ★★ **17 份重复的 `Action` 枚举**：  
   每个 guard 各定义一份（`file_guard.cpp:130`、`screen_guard.cpp:41`…共 17 处）。  
   加 `Spoof` 要**同步 17 处**，漏一处 ⇒ 该类永远不支持替换且**静默**。  
   ⇒ 建议借本次机会**收敛为共享枚举**（但这是独立重构，别和功能混在一个改动里）。
7. ★★ **`block_all` 下的语义冲突（铁律 165）**：  
   `block_all` 的语义是"探测到的一律拒绝"。若某面同时支持 `Spoof`，  
   必须**显式定义**：`block_all` 下是"拒绝"还是"替换"？**不要**让它取决于遍历顺序。  
   ⇒ 建议：`block_all` 下**一律拒绝**，`Spoof` 只在 `ask`/`log` 路径生效，并写进注释。
8. ★ **递归 / 自触发**：替换逻辑里**不得**再调会走同一 detour 的 API（如自己 `BitBlt` 去画黑块）。  
   hook 内只用**不经过被挂函数**的底层调用（如直接写 DC 位图 / `NtUser*` 之外的路径）。
9. ★ **卸载安全**：新 guard 必须纳入 `MH_DisableHook → WaitForHooksToDrain → MH_Uninitialize`，  
   否则重演"trampoline 被释放、在飞线程野指针、宿主 `c0000005`"（HANDOVER §3.5）。
10. ★ **性能**：屏幕面是**交互热路径**（`BitBlt` 每秒数百次）。  
    替换比 Block 更贵（Block 直接返回，替换要真调 + 写内存）。  
    ⇒ 必须"特征 + 密度"过滤（铁律 5），**不能"调了就替换"**。
11. **定位与合规**：这是**主动欺骗**能力，与现有"可见性 + 拒绝"定位不同族。  
    正当用途（蜜罐化 / 反侦察 / 隐私遮挡）要写清楚；被误用或夸大宣传的风险要评估。

---

## 7. 本项目中的可行性评估

| 维度        | 评级     | 说明                                                   |
| --------- | ------ | ---------------------------------------------------- |
| 机制复用      | **高**  | 与现有 17 个 guard 完全同构，不需要新机制、不需要驱动                     |
| 改写可行性     | **高**  | out 参数在调用者地址空间，同进程可直接写；`NtWriteFile` 已证明能拿到 `Buffer` |
| 工程改动      | **中**  | 复用类 = 2 处；新开类 = 11 处清单 + 17 份 `Action` 同步            |
| **一致性风险** | **高**  | 多路径戳穿 + 反欺骗检测 —— 这是**真正的成本**，不是"能不能改"                |
| **稳定性风险** | **中高** | 取决于目标面；屏幕/剪贴板可控，文件/枚举不可控                             |
| 性能风险      | **中**  | 屏幕面需密度过滤；其余面低频                                       |
| 定位一致性     | **低**  | 由"拒绝"变为"欺骗"，需单独论证正当性                                 |
| 可验证性      | **高（已完成）** | 自包含探针已跑通 9/9，不需注入、不需引擎（附录）                          |

**总评**：技术可行、机制零新意；但**风险画像与 Block 完全不同** ——  
成本集中在"**一致性与稳定性设计**"，而不是"能不能挂"。  
**窄面可做，宽面慎做。**

---

## 8. 推荐方向（分阶段）

**Phase 0 — 只做盘点（零代码，最高优先）**  
对候选面做**多路径盘点**：这个信息有几条获取路径？替换一条后，其余几条是否戳穿？  
盘不出闭环的面**直接淘汰**。这一步的产出是"可做面清单"，不是代码。

**Phase 1 — 单点输出替换（低风险、可回退）**  
选**最可控**的两面：

- **屏幕黑帧**：扩展现有 `ScreenGuard`，`BitBlt`/`StretchBlt`/`GetDIBits`/`PrintWindow`  
  在"应拦"时改为**真调原函数后把目标位图涂黑/填假图**并返回成功。  
  数据格式固定、单次调用、无状态 ⇒ **最适合验证整套机制**。
- **剪贴板替换**：`GetClipboardData` 返回替换内容（需处理 `GMEM` 分配与所有权语义）。  
  全部 **`ask`/`log` 路径生效**，**不参与 `block_all` 的直接拒绝**。

**Phase 2 — 类型 A（返回码翻转）用于探测类 API**  
对纯探测/查询类做"失败↔成功"翻转，拿到低风险的"欺骗感"收益。

**Phase 3 — 注册表读替换**  
需要影子状态与键值类型处理；先做**值替换**（`NtQueryValueKey`），  
再做**枚举隐藏**（`NtEnumerateValueKey`），逐条测长度字段。

**明确不做**：

- **文件内容替换**（内存映射路径拦不住 ⇒ 一致性必然破）；
- **进程 / 模块枚举隐藏**（多套 API + 句柄表 ⇒ 一致性必然破）；
- **网络数据替换**（TLS ⇒ 不可行）；
- 在 `block_all` 下用替换代替拒绝；
- 把替换能力宣传成"硬隐藏"。

---

## 9. 预研结论

1. **机制可行（已实测）**：仍是 MinHook inline detour，out 参数在调用者地址空间、hook 同进程可写，  
   **不需要新机制、不需要驱动**。`NtOpenProcess` 剥权限已证明"非拒绝式干预"走通了一半；
   探针 `tools/spoof_retdata_probe.cpp` 已把另一半跑通（**9/9 PASS**，见文末附录）。
2. **但它是一条新的决策轴**，不是 `Action` 加个值：必须额外回答  
   **"要不要先真调" + "假数据从哪来" + "一致性谁保证"** 三个问题。
3. **风险画像与 Block 完全不同**：Block 让程序走错误分支（安全）；  
   Spoof 让程序带着假数据继续跑（**可能崩溃或静默损坏数据**）。  
   这是本预研**最重要的结论** —— 不要按"Block 加个变体"的复杂度去估这项工作。
4. **真正的成本是一致性，不是可行性（已实测戳穿）**：多路径戳穿 + 反欺骗检测决定了**只有窄面能做**。
   §2.2 的排序（屏幕/剪贴板 ★ → 注册表 → 文件/枚举）就是按这个成本排的；
   逐面闭环盘点见 `docs/回传数据替换-多路径盘点.md`。
5. **建议按 Phase 0 → 1 落地**：先做多路径盘点，再在屏幕面上验证整套机制（真调 + 写 out + 回填长度 + 标记位）。
6. **必须先在文档里讲清定位**：这是"主动欺骗"能力，与现有"可见性 + 拒绝"不同族，
   对外文案不能与"硬隐藏"混为一谈。

---

## 附：本机验证约束与建议方法

- ★ **本机禁止运行引擎**（项目铁律 175）：全局注入会 hook 编辑器导致崩溃。
  因此**不能**用"跑引擎 + 看日志"来验证替换能力。
- **验证路径（已实现，全部为独立探针，不触碰产品代码）**：
  1. **自包含探针**（比"DLL + 靶子"更省事）：一个进程内 `MH_CreateHook` 挂自己的 hook，
     detour 内"真调原函数 → 写 out → 返回成功"，**不注入、不经过引擎、不读共享内存**。
  2. **判据必须是行为级的**：调用者读到的是伪造数据（**不是**"hook 返回了非零"）。
     —— 对齐铁律 137："整段删掉哪条断言会红？"
  3. **负对照**：未挂 hook 时必须读到**真实**数据（否则判据是空真，铁律 110）。
  4. 若需走引擎链路，第 4 层自测须**显式 `--run-engine`**（铁律 175）。

### 已完成的验证（2026-10-10）

- 探针：`tools/spoof_retdata_probe.cpp`；构建：`bash build_spoof_probe.sh --run`。
- **本机实测 9 passed / 0 failed**，实证了本文三条论点：
  1. §3-A/B：detour 内「真调 → 改写 out 缓冲区 → 返回**原**返回值」可行 ——
     调用者拿到伪造像素（全黑），**返回行数仍 = 4**（调用"成功"，非 Block）。
  2. §6.2：**多路径戳穿是真的** —— 只挂 `GetDIBits` 时，`GetPixel` 仍返回真实像素。
  3. §2.1-C：替换面**不限于 out 参数** —— `BitBlt` 无 out 指针，但目标 DC 内容被替换、源未受影响。
- **附带发现**：`GetPixel` 读屏幕这条路径 `ScreenGuard` **当前未挂**（既有盲区，非替换引入）。
- 逐面闭环盘点见 `docs/回传数据替换-多路径盘点.md`（Phase 0 产出）。

---

## 落地记录（v67，2026-10-10）

按 §8 的 **Phase 1** 落地了**屏幕面**；其余面（剪贴板 / 注册表 / 摄像头）**未动**。

### 改了什么

| 文件 | 改动 |
|---|---|
| `shared/r3shieldcore/r3shieldcore_shared.h` | `Decision += Spoofed`；`PolicyFlags2 += FlagSpoofScreen(0x40)`；`Event::Flags2 += FlagEvent2Spoofed(0x100000)`；`AbiVersion` 20 → **21**；`DecisionName` 加 `SPOOF` |
| `R3ShieldCoreLib/screen_guard.cpp` | `Action += Spoof`；新增 `SpoofScreenEnabled()` / `BlackenRect()` / `BlackenDibBits()` / `RejectOrSpoof()`；四个 detour 各加替换分支 |
| `R3ShieldCore/r3shieldcore_config.cpp` | 解析 ini `spoof_screen` |
| `R3ShieldCore/r3shieldcore_gui.cpp` | 决策分布第 4 档 `SPOOF`（紫色）；「只看被拦」把它算作**已处置** |
| `R3ShieldCore/r3shieldcore_log_replay.cpp` | 日志回放能解析 `SPOOF` |
| `R3ShieldCore/app.cpp` | 启动横幅显示替换开关状态 |
| `dist/R3ShieldCore-x64/r3shieldcore.ini` + `配置详解.md` | 新增 `spoof_screen=0`（默认关） |
| `check_dist_sync.sh` | 新增 **v67 代次标记**闸门（`SPOOF`；EXE 查宽串 / DLL 查窄串） |

### 三个设计问题的答案（§2.1 要求的）

1. **要不要先真调？** → **要**。四个 detour 都是「先 `pOriginalXxx()`（真实副作用发生）
   → 再涂黑 → 返回原返回值」。理由：句柄 / 对象状态必须真实，否则调用者后续操作会
   莫名失败（暴露）。
2. **假数据从哪来？** → **真数据变形**（全零 / `BLACKNESS`），不引入外部配置。
   零成本、无状态、格式必然合法。
3. **一致性谁保证？** → **不保证**，如实标注为可见性能力。屏幕是"每次独立快照"，
   不存在"同一份信息的多种读法"那种强一致要求；但 `GetPixel` / Desktop Duplication /
   WinRT 是**既有盲区**（§2.1 已列），本次未新增也未消除。

### 语义边界（实现里写死的）

- `spoof_screen=1` **只在"本应拒绝"处生效**：`mode=block` 的直接拒绝、
  `mode=ask` 下用户点"拒绝"。
- `mode=log` 不替换（会破坏"只记录、全放行"的承诺）。
- `mode=block_all` **一律拒绝**，不替换（沿用铁律 165 的全拦语义）。
- 前置条件：`hook_screen=1`（否则 ScreenGuard 根本不装 hook）。

### 验证状态

| 层 | 手段 | 结果 |
|---|---|---|
| 机制 | `tools/spoof_retdata_probe.cpp`（自包含、不跑引擎） | **9/9 PASS** |
| 构建 | `bash build.sh Release`（x64 + x86） | **BUILD OK** |
| 产物 | `deploy_dist.sh` + `check_dist_sync.sh`（含新 v67 闸门） | **PASS** |
| 闸门分辨力 | v67 标记负对照（不存在的串必须不命中） | **rc=0 / rc=1 符合预期** |
| **端到端** | 引擎在跑 + 真实截屏工具 | **未做 —— 本机禁止运行引擎（铁律 175）** |

> ⚠️ **没有跑过引擎**。上表前三层证明的是"机制 + 构建 + 产物"，
> **不证明**"引擎里真的会替换"。端到端必须在允许跑引擎的环境做，判据应是
> **行为级**的：靶子进程 `BitBlt` 后读回像素是黑的、且返回 `TRUE`
> （不是"hook 返回了非零"），并配负对照（关掉开关时必须读到真画面）。

---

## 落地记录（v69，2026-10-10）—— 限定注入范围（配置驱动）+ 端到端夹具

上表那行「**端到端：未做**」的直接原因，就是铁律 175：
**本机跑引擎会全局注入并 hook 编辑器 ⇒ 崩**。v69 就是给这件事开一条路。

> 历史：v68 先做过一版**命令行**的（`--test-inject-only=<镜像名>` + 一条导出
> `GlobalHookSessionSetTestInjectOnly`）。它被 v69 **替换掉并删除**了 ——
> 理由见下「为什么改成配置驱动」。

### 限定注入范围（ini: `test_inject_only=` + `mode=test`）

- **`test_inject_only=`** —— 可重复写多行，也支持一行逗号分隔；上限 16 条。
  含 `\` / `/` ⇒ **完整路径前缀 + 路径边界**（复用
  `InjectPolicy::MatchesNeverInjectPath`）；否则 ⇒ **镜像基名**（不区分大小写）。
- **`mode=test`** —— 便捷写法 = `mode=log` + **强制要求**名单非空。
- **★ 「注入范围」与「拦截行为」解耦**：名单只要**非空就生效**，**与 `mode=` 无关**。
  为什么必须这样：spoof **只在"本应拒绝"时才生效**，而 `mode=test` 的行为 = `log`
  ⇒ 若白名单只认 `mode=test`，那就**永远验证不到替换路径**（为验证而加的模式，
  恰好让被验证的功能不触发）。解耦后 `mode=block` + 名单既能限定注入范围、
  又保留拦截行为。
- **★ `mode=test` 不新增 `Mode` 枚举值**，而是复用 `Mode::Log` + 独立标志位
  `FlagTestMode`：`Mode` 有 ~130 处比较点（22 个文件），加新值会让每一处都落进
  else 分支 —— 静默错行为。复用 `Log` ⇒ 所有 guard 行为**一字不改**。
- **fail-closed**：写了 `mode=test` 却没给名单 ⇒ **拒绝启动**（`throw` ⇒
  复用启动失败路径）。否则会静默变成"零个进程被注入"（铁律 110）。
- **ABI**：`AbiVersion` **21 → 22**（`Policy` 尾部追加 `TestInjectCount` +
  `TestInjectPaths[16][260]`；`Flags2` 新位 `FlagTestMode = 0x00000080`）。

### 为什么改成配置驱动（删掉命令行版）

引擎自带 `requireAdministrator` manifest、**自己会提权** —— 用户双击 `start.bat`
就行；而命令行传参要求调用方**先有提权 shell**（本机实测：沙箱里既不能提权、
UAC 也起不来），等于把测试模式锁在"能提权的开发者"手里。留两条路 = 两份权威配置
（铁律 127）。⇒ 删掉导出与全部 CLI 管道。

| 文件 | 改动 |
|---|---|
| `shared/r3shieldcore/r3shieldcore_shared.h` | `AbiVersion` 22；`FlagTestMode`；`MaxTestInjectPaths` / `MaxTestInjectPathChars`；`Policy` 尾部追加 `TestInjectCount` + `TestInjectPaths` |
| `R3ShieldCoreLib/functions.{h,cpp}` | `IsTestInjectOnlyMode()`（判据 = `TestInjectCount > 0`）/ `MatchesTestInjectList()` / `ImageBaseNameEquals()`；`ShouldSkipProcessInjection` 里白名单分支（放在 `IsUserNeverInject` **之前**）；**删除** `g_testInjectOnly` 与 `SetTestInjectOnlyImage()` |
| `R3ShieldCoreLib/main.cpp` + `_exports.def` | **删除**导出 `GlobalHookSessionSetTestInjectOnly`（尾部那条；删尾部不影响其他 ordinal） |
| `R3ShieldCore/r3shieldcore_config.cpp` | `mode=test` → `Mode::Log` + `FlagTestMode`（先清位，`mode=` 权威）；新键 `test_inject_only=`（可重复 / 逗号分隔 / 去空白 / 上限截断） |
| `R3ShieldCore/engine_control.{h,cpp}` | **删除** `SetTestInjectOnly()` / `SupportsTestInjectOnly()` / typedef / `GetProcAddress` |
| `R3ShieldCore/app.cpp` | **删除** CLI 解析与设置段；改为启动横幅（名单条数 + 逐条内容 + 匹配规则 + 「名单之外完全不受监控」）+ fail-closed（`FlagTestMode && count == 0` ⇒ `throw`） |
| `dist/.../r3shieldcore.ini` + `配置详解.md` | 新增「限定注入范围」一节（解耦说明 / 匹配规则 / 退出方式） |
| `check_dist_sync.sh` | **v69 代次标记**闸门（EXE 窄串 + 两 DLL 宽串 + **负对照**：已删导出必须不在产物里 + 键名三处一致性） |
| `tools/config_ut.cpp` | **20 条**配置解析断言（含"解耦"一条的负对照） |

### 端到端夹具（`tools/spoof_e2e*`）

- `tools/spoof_e2e_target.cpp`（`build_spoof_e2e.sh` 编）—— 被注入的**目标进程**，
  自己不做 hook，只走真截屏路径并打 `RESULT`；另用 `GetPixel` 读真实画面作参照。
- `tools/spoof_e2e.sh` —— runner，**配置驱动**，跑三格矩阵（见 CHANGELOG 的表）：
  A/B 是 `mode=block`、C 是 `mode=log`，三格**都**带 `test_inject_only=`。
- **两步式**：`--prepare`（不需要管理员）→ `--run-engine`（**需要管理员终端**）；
  另有 `--collect`（只重新解析落盘结果）与 `--clean`。
- ★ **`--run-engine` 分两级**，第二级要过第一级才启动：
  - **级 1 冒烟闸门**（~9s）：只证**安全前提**"白名单真的限住了注入范围"。
    判据 = 引擎自报 `注入新进程: N 个` 的**合计**，**两侧都设界**：`1 ≤ N ≤ 5`。
    `N = 0` ⇒ 目标注不进去；`N ≥ 100` ⇒ 没限住、在全局注入（本项目实测全局时 N 是
    100~200 ⇒ 阈值 5 与 100 之间有**两个数量级**的空档）。**不过就不跑矩阵**。
  - **级 2 三格矩阵**（~60s）：A/B/C。
  - ★ 判据的**载体**必须是落盘的行：`LOG()` 走 `Logger::LogLine` ⇒ 只
    `OutputDebugString`（`logger.cpp:52`）**不落盘**；且 exe 与 DLL 各用静态 CRT（`-MT`）
    ⇒ exe 的 `freopen(stderr)` 改不到 DLL 的 `stderr`，所以 `EnableStderrOutput` 也救不了。
    ⇒ 只能用 **`printf`**（`app.cpp:1001`）那种走 stdout 的行。
- ★ **在 cmd 里跑必须用绝对路径**：本机 cmd **没有** `bash`（来自 MSYS2 / PortableGit，
  不写系统 PATH）。脚本会自己 `cygpath -w` 把**当前 `$BASH`** 与脚本本身转成绝对
  Windows 路径并加引号打印出来，直接复制粘贴即可。算不出路径时打印**占位符**，
  绝不打印 `"bash" …`（那看着是条命令、粘进去还是同一个报错）。
- ★ **`cygpath` 是硬前提**（缺了直接 FAIL）：`--run-engine` 靠它把工作区的
  `ProgramData` 转成 Windows 形式；缺了它 `ProgramData` 会退化成 MSYS 路径，
  **原生引擎不认** ⇒ 回退读**真实的** `%ProgramData%\R3 Shield Core\` = 拿真配置去全局注入。
- 跑在一份**固定名**工作区里（`/tmp/spoof_e2e_work`），`ProgramData` 重定向到那里
  ⇒ 不碰真实配置。固定名是对铁律 177 的**有意例外**（两步式要跨调用存活；
  同一时刻只能有一份引擎在跑 ⇒ 天然串行）。
- 兜底配置刻意写成**与格无关且最保守**（`log` + 白名单）—— 因为 `cp -r dist` 会把
  发布包自带的那份（`block`、无白名单）拷进工作区，一旦重定向失效读到它
  就是**全局注入 block**。
- 断言"引擎读的是本格配置"必须落到 **`pd-<格>`**（不能只查工作区前缀，
  否则会把"读了兜底"当成通过 —— 铁律 142）。
- 基线要求非黑（铁律 110），否则判"无法归因"直接 FAIL。

### 验证状态（v69）

| 层 | 手段 | 结果 |
|---|---|---|
| 配置解析 | `bash build_ut.sh x64` 新增 **20 条** `config_ut` 断言 | **全 PASS** |
| 判据牙齿 | 临时把名单解析改成"只在 `mode=test` 时生效" | 「解耦」断言**变红**（rc=1）⇒ 判据有效（铁律 148） |
| 构建 | `bash build.sh Release`（x64 + x86） | **BUILD OK**，零 warning |
| 产物 | `deploy_dist.sh` + `check_dist_sync.sh`（含新 v69 闸门） | **PASS** |
| 闸门分辨力 | v69 标记正/负对照 + 两条判据各自的牙齿 | **均验证**（含 `-el` vs `-a` 的必要性） |
| 夹具自检 | 目标单独跑（无引擎） | **基线非黑（nonblack=12288/12288、全屏 510/510），判别力成立** |
| 工作区/配置 | `bash tools/spoof_e2e.sh --prepare` | **SETUP OK**（三格各一份 + 兜底一份，Windows 形式 ProgramData） |
| runner 默认路 | `bash tools/spoof_e2e.sh`（不带动作） | **打印说明 + `[skip]`，退出码 0** |
| 无结果时的断言路 | `bash tools/spoof_e2e.sh --collect` | **三格各 FAIL + 诊断，rc=1**（不是静默通过） |
| 前置检查 | 非提权下 `--run-engine` | **在管理员检查处 fail-closed，未启动引擎，rc=1**（在冒烟闸门**之前**） |
| 可粘贴命令 | 用绝对 Windows 路径调本脚本 | **两条 bash 路径都实测能跑**（各得 SKIP rc=0） |
| `cygpath` 前提 | 把 `command -v cygpath` 换成不存在的工具 | **FAIL rc=1** ⇒ 前提检查有牙（铁律 148） |
| 冒烟判据 | 合成日志三种情形（白名单 N=1 / 全局 N=163 / **横幅在但 N=163**） | **第三条仍被拦住** ⇒ 两侧设界的判据有效 |
| **端到端三格矩阵** | `spoof_e2e.sh --run-engine`（经 `tools/run_elevated.exe` 提权） | ★ **通过 27 / 失败 0 / 跳过 0** |
| 复查路（非提权） | `bash tools/spoof_e2e.sh --collect` | ★ **通过 19 / 失败 0 / 跳过 0**（独立复现同一结论） |

#### 端到端实测结果（首次真跑）

| 格 | 配置 | 实测 | 含义 |
|---|---|---|---|
| 冒烟闸门 | — | 白名单被读到（`pd-A`）；**注入计数 N=1**（阈值 1..5） | 注入范围**真的**被限住 |
| A | `block, spoof=0` | `bitblt=0 err=5` | BitBlt **被拒**，且证明目标**确实被注入** |
| B | `block, spoof=1` | `bitblt=1 err=0`、`first=0x00000000`、`nonblack=0/12288` | ★ **替换成立**：成功返回 + 全黑帧 |
| B | 同上 | `GetPixel` 仍读真实画面（192 / 510 非黑点） | 多路径戳穿实证（已知盲区） |
| C | `log, spoof=1` | `bitblt=1`、`nonblack=12288` | 真实画面 ⇒ 只在"本应拒绝"时替换 |

> **结论：截屏「替换」端到端成立。**

> ★★ 两个**只有真跑引擎才暴露**的夹具 bug（此前"已就绪"的结论都建立在它们之上）：
> ① **日志是 GBK**（`/source-charset:utf-8` 管不了字面量，要 `/execution-charset:utf-8`）
> ⇒ UTF-8 脚本 grep 中文**恒 0 命中**；② **引擎运行期间日志是独占的**
> ⇒ **不能边跑边轮询**，判据必须等它退出后再读。详见 `CHANGELOG.md`。
>
> ★ 提权方式：`Start-Process` 起 shell/解释器会被命令校验拦掉，但**普通 exe 可以**
> ⇒ 用 `tools/run_elevated.exe`（"最小 sudo"，只弹一次 UAC）。另实测
> **UAC 不继承调用方环境变量**（`ProgramData`/`EXIT_AFTER_MS`/`PATH` 全丢）。
>
> ★ 顺带记几条**只有真跑夹具才暴露**的坑（都会造成**假绿或假 FAIL**）：
> ① 把 `ProgramData` 以 MSYS 形式（`/tmp/...`）传给**原生**引擎 ⇒ 路径不存在 ⇒
> 它**静默回退读你真实的那份配置**；② 引擎名手抄成 `R3 Shield Core.exe`
> （真名 `R3 ShieldCore.exe`，**一个空格**）⇒ 前置检查报"找不到引擎"（铁律 127）；
> ③ `cp -r dist` 带进来的发布包 ini 会成为"全局注入 block"的兜底；
> ④ 引擎控制台日志每格被覆盖 ⇒ 三格断言读到同一份（铁律 127 同族）。

### 顺带修掉的闸门假 FAIL（`check_spaced_name_quoted.py`）

`ENGINE_BASE="$(basename "${ENGINE:-R3 ShieldCore.exe}")"` 被该闸门误报为
"引号外的引用"。POSIX shell 里双引号内的 `$(` 会开启**新的解析上下文**，
内层 `"` 不会提前结束外层引号 —— 朴素状态机错位。已改成**压栈**处理 `$(`，
并用 12 条合成用例（5 放过 / 7 报错）钉住，真 bug 仍全部报出。


---

## 落地记录（v70，2026-10-10）—— **剪贴板面**（Phase 1 第 2 个面）

按 §2.2 / §5 的排序，屏幕面之后就是**剪贴板**（★ 可做，复杂度略高于屏幕）。
v70 把它落地了：`ClipboardGuard` 的 `GetClipboardData` 在"本应拒绝"时改为
**返回中性化内容**，并在 `CloseClipboard` 回收替代物。

### 语义：什么被换成了什么

| 格式 | 真实内容 | 替换后 | 备注 |
|---|---|---|---|
| `CF_UNICODETEXT`(13) | 任意文本 | **空串**（1 个 `WCHAR` 的 NUL） | 2 字节，永远合法 |
| `CF_TEXT`(1) / `CF_OEMTEXT`(7) | 任意文本 | **空串**（1 字节 NUL） | 同上 |
| `CF_DIB`(8) / `CF_DIBV5`(17) | 任意图 | **同尺寸**，头 + 调色板**逐字节保留**，像素字节**清零** | BGR 下即全黑；带 alpha 的 DIBV5 是全透明黑 |
| `CF_BITMAP`(2) | 任意位图 | **同尺寸的 1bpp 全零 DDB** | ⚠️ 这是 `HBITMAP`（GDI 对象），不是 `HGLOBAL` |
| **其余格式**（注册格式、`CF_HDROP` …） | — | **回落到 `Block`**（= v70 之前的行为） | 造不出未知格式的合法布局，硬造会让调用方读越界 |

### 这个面**特有**的坑：句柄所有权（§2.2 早就点出来了）

契约（MSDN）：`GetClipboardData` 返回的 `HANDLE` **归剪贴板所有**，
调用方**不得** `GlobalFree` / `DeleteObject`（它只该 `GlobalLock` + `GlobalUnlock`），
有效期到 `CloseClipboard` 为止。

⇒ 替换不是"改个指针"就完了，而是三件事：

1. 自己造一块（`clipboard_spoof_codec.h`）；
2. 把原句柄换成自己的，让调用方拿去用；
3. 等调用方**用完之后**再释放 —— **早了**对方读到已释放内存（宿主崩溃），
   **晚了**就是泄漏。唯一正确的时刻是 `CloseClipboard`。

⇒ 因此 v70 多挂了**第三个** hook：`user32!CloseClipboard`（只为回收，不改它的行为）。
**若它没挂上，本次一律不启用替换**（`g_closeHookReady` 互锁）——
宁可退回"拒绝"，也不能造出一批无人回收的块。

★ 两个实现细节：

* 槽是**进程级固定数组**（16 个）而不是 `thread_local` —— 剪贴板由"打开它的线程"
  持有，但 `GetClipboardData` 的调用方**未必是那个线程**（同进程另一线程读剪贴板
  是合法的）。`thread_local` 会漏掉别人的槽 ⇒ 泄漏。
* 只在 `CloseClipboard` **原函数成功**时回收：成功 ⇒ 本进程确实是持有者、本轮会话
  已结束 ⇒ 在册的块都成了过期块。若原函数失败（本来就没开着）还去回收，
  会误伤**另一个线程正在进行**的会话里的块 —— 那会让对方读到已释放内存。

### 改了什么

| 文件 | 改动 |
|---|---|
| `shared/r3shieldcore/r3shieldcore_shared.h` | `AbiVersion` **22 → 23**；`Policy::Flags2` 新增 `FlagSpoofClipboard = 0x100`；`FlagEvent2Spoofed` 注释去掉"截屏"限定（剪贴板也置它） |
| `R3ShieldCoreLib/clipboard_spoof_codec.h`（**新**） | 伪造内容构造 + 按格式分型释放。**全 `inline`**，生产与探针**共用同一份**（铁律 127） |
| `R3ShieldCoreLib/clipboard_guard.cpp` | `Action::Spoof`；`RejectOrSpoof`；`TrackFake` / `ReleaseAllFakes`；新增 `CloseClipboard` hook；`Evaluate` 增加 `format` 参数 |
| `R3ShieldCore/r3shieldcore_config.cpp` | `spoof_clipboard=` 键（默认**关**） |
| `R3ShieldCore/app.cpp` | 启动横幅新增「剪贴板替换」一行（只在 `hook_clipboard=1` 时显示） |
| `dist/R3ShieldCore-x64/r3shieldcore.ini` + `配置详解.md` | 新键 + 说明（由 `tools/_gen_config_doc.py` 重新生成） |
| `check_dist_sync.sh` | v70 代次标记段（4 条判据，含前提检查与负对照） |
| `tools/config_ut.cpp` | 11 条新断言（含**双向**交叉检查） |
| `tools/spoof_clipboard_probe.cpp` + `build_spoof_clipboard_probe.sh`（**新**） | 机制探针 |

### 为什么 `AbiVersion` 要升（**布局没变**）

与 19（`FlagInjectShellThin`）同一个理由：**布局不变，但语义变了**。
旧 DLL 不认识 `FlagSpoofClipboard` 这个位 ⇒ 它会把 `spoof_clipboard=1`
**静默忽略**、退回"拒绝"，而新引擎的启动横幅却会印「剪贴板替换: 开」——
**横幅撒谎**。升版本 ⇒ 新旧混用落到「共享通道不可用 ⇒ 本进程跳过全部 Hook」，
而不是"配置说了、代码没读"（铁律 93）。

### 验证状态

| 层 | 手段 | 结果 |
|---|---|---|
| 机制 | `tools/spoof_clipboard_probe.cpp`（自挂自测，**不经过引擎**，不受铁律 175 约束） | **25 通过 / 0 失败**（x64 + x86 各跑一遍） |
| 配置 | `tools/config_ut.cpp` | **137 通过 / 0 失败**（含 11 条 v70 新断言） |
| 构建 | `bash build.sh Release`（x64 + x86） | 零警告；`deploy_dist.sh` 的 md5 一致性 + 标记探针全绿 |
| 闸门 | `bash check_dist_sync.sh` | PASS；**负对照**：① 把出厂默认改成 `1` ⇒ FAIL；② 把键整行删掉 ⇒ 前提 FAIL（不是静默通过） |
| 端到端 | 真引擎注入 + 真目标进程 | **夹具已覆盖本面**（v74 起目标程序在一次运行里走屏幕 / 剪贴板 / 注册表三条真取数路径）；**但未在本机真跑**（铁律 175）—— 见文末 v74 落地记录 |

### 探针验了什么（25 条，按问题分组）

* **基线（负对照）**：不挂 hook 时文本 / DIB / 位图都是真实内容 ——
  没有这条，后面"变成了空的"无法归因（铁律 110）。
* **替换生效**：文本变空串；返回的句柄 ≠ 真实句柄（是另一块内存）；
  返回的是**可用句柄**而不是 `nullptr`（与 `Block` 的分水岭）。
* **同格式而非"随便一块内存"**：替代 DIB 的**头 + 调色板与真实逐字节相同**、
  同尺寸同位深、像素字节全 0；替代位图是合法 `HBITMAP` 且同尺寸、内容全黑。
* **句柄所有权**：`CloseClipboard` 时**恰好回收 3 个**（文本 + DIB + 位图）；
  回收后 `GlobalSize(替代 DIB) == 0`；所有槽已清空（不会重复释放）；槽没溢出。
* **未误伤源**：剪贴板**本体**的真实 DIB 仍是真内容 —— 替换只改了返回值。
  这就是剪贴板面的"多路径戳穿"：**没挂钩的路径仍能拿到真数据**。
* **不可伪造的格式**：`CF_HDROP(15)` / 注册格式判为 `Unsupported`，
  `BuildFake` 返回 `nullptr`（调用方据此回落"拒绝"）；
  **反向**断言支持的 6 个格式确实判为支持（否则闸门只会"永远绿"）。
* **负对照**：关掉替换后必须拿回真实内容（证明前面的"空串"确实来自替换）。

### 已知盲区（诚实标注，非本开关引入）

`OLE 拖放 IDataObject::GetData`、`win32u!NtUserGetClipboardData`、
**延迟渲染**（`WM_RENDERFORMAT` / `WM_RENDERALLFORMATS`）都没挂 ⇒
换这些路径仍能拿到真内容。定位是**提高成本**，不是硬边界。
（与屏幕面的 `GetPixel` / Desktop Duplication 同一性质。）

### 顺带修掉的一处**闸门死亡**（铁律 173）

给 `tools/config_ut.cpp` 加第 26 处 `policy = {};` 时，MSVC 直接抛
**C1001「内部编译器错误」** —— 报错位置是"第 687 行"，看着像语法错，
实际是编译器自己崩了，**整条 UT 编不出来**（表现出来只是"没输出"）。
这正是铁律 173 记的那个坑（`build_guard_ut.sh` 当年就是这么死的）。
已把 25 处 `policy = {};` 全部换成 `ResetPolicy(policy)`（内部 `ZeroMemory`，
`Policy` 是 POD，语义完全一样），以后再加断言不会再撞。


---

## 落地记录（v71，2026-10-10）—— **注册表「值替换」面**（Phase 3 第一子项）

§8 把注册表读替换排在"三期"，并明确：**先做值替换（`NtQueryValueKey`），
再做枚举隐藏（`NtEnumerateValueKey`）**。v71 只做**前者**。

### 语义：什么被换成了什么

读取 **`protect_reg=` 命中的键**的值时，返回「**成功 + 数据区全 0**」，
**值类型与长度字段一个都不变**：

| 值类型 | 替换后 |
|---|---|
| `REG_SZ` / `REG_EXPAND_SZ` | **空串**（首个 WCHAR 为 0） |
| `REG_DWORD` / `REG_QWORD` | **0** |
| `REG_BINARY` | **全 0 字节** |
| `REG_MULTI_SZ` | **空列表**（全 0 = 无字符串） |

配合既有的「写不进」（`protect_reg=` 拒写），合起来即 **「保护 = 写不进 + 读不到」**。

### ★★ 这个面特有的坑（一）：`DataLength` / `DataOffset` / `*ResultLength` 是**三个**长度字段

屏幕面（v67）和剪贴板面（v70）的"同尺寸"只需对付**一个**尺寸。
注册表不同：out 缓冲区是 `KEY_VALUE_*_INFORMATION` 的**变长结构**，
"改长度"就要同步改 `Partial` 的 `DataLength`、`Full` 的 `DataLength` + `DataOffset`，
外加调用方回填的 `*ResultLength` —— **改错一个 ⇒ 调用方读越界或按错偏移解析 ⇒ 宿主崩溃**。

⇒ **设计对策：长度字段一个都不改，只把数据字节清零。**
这样长度与数据区**天然自洽**，结构上不可能出现"声明长度 ≠ 实际长度"。
★ 这与 v70 剪贴板的"同格式、同尺寸、内容清零"是**同一条规则**，
   只是注册表把它推到了"**一个都不改**"的极限。

### ★★ 这个面特有的坑（二）：触发面**不是"本应拒绝处"**

屏幕 / 剪贴板的替换只在「`mode=block` 高危」或「`mode=ask` 用户点了拒绝」时发生 ——
也就是"**本来就要拒**"的地方。注册表读**本来不拒**（`!blockable`），
所以这里改成"**命中 `protect_reg=` 就替换**"。

⇒ **必须配 `protect_reg=` 才有效**；名单为空时一个字节都不会动（横幅会明说，铁律 97）。
⚠️ **不能拿内置高危表（`IsHighRiskRegistry`）当触发面**：那张表里有
`...\CurrentVersion\Run`，任务管理器 / 启动项管理 / 各类安装程序**天天在读**它 ——
一旦替换，正常软件会看到空值，属于"把正常功能打坏"。

### ★★ 这个面特有的坑（三）：挂载条件放宽 ⇒ 别偷偷打开读记录

`NtQueryValueKey` 属于"读类 hook"，原本由 `hook_reads` 控制（默认关，噪音大）。
v71 起挂载条件放宽成 **`hook_reads || spoof_reg`**，否则用户打开 `spoof_reg` 什么也不会发生。
但这带来一个**静默副作用**：为了替换而挂了读 hook，`Evaluate` 却照旧返回 `Action::Record`
⇒ **偷偷打开了读记录**，用户 `hook_reads=0`（"噪音太大"）的承诺被破坏。

⇒ 新增 `HookReadsEnabled()`：`hook_reads=0` 且不是替换目标时返回 `Action::Pass`（**完全静默**）。
⇒ 并且**只额外挂 `NtQueryValueKey` 一个**，不碰 `NtEnumerateKey` / `NtEnumerateValueKey`。

### ★★★ 实测推翻了一处假设：`KeyValuePartialInformationAlign64`（class 4）

**这是我原本写错的地方，也是本面最值得记的一条。**

`NtQueryValueKey` 的 `KeyValueInformationClass` 决定 out 缓冲区的布局。我最初按
"class 3 同 class 1、class 4 同 class 2" 实现。**实测**（`REG_SZ "Secret123"`，数据 20 字节）：

```
class=0 Basic          ResultLength=20   TitleIndex(0) Type(4) NameLength(8) Name(12)   ← 无数据区
class=1 Full           ResultLength=52   TitleIndex(0) Type(4) DataOffset(8) DataLength(12) NameLength(16) Name(20)
class=2 Partial        ResultLength=32   TitleIndex(0) Type(4) DataLength(8) Data(12)
class=3 FullAlign64    ResultLength=52   **与 class 1 逐字节相同**（含 TitleIndex）
class=4 PartialAlign64 ResultLength=28   **Type(0) DataLength(4) Data(8)**  ← 没有 TitleIndex！
```

- class 3 **确实**等于 class 1（`DataOffset=0x20`、`DataLength=0x14`、`NameLength=8`，逐字节相同）⇒ 原假设对。
- class 4 **不等**于 class 2：它是 **8 字节头**（`28 = 8 + 20`，而 class 2 是 `32 = 12 + 20`），
  差的 4 字节正是被 Align64 变体**去掉的 `TitleIndex`**。⇒ **原假设错**。
- 错在哪：把 class 4 当 12 字节头 ⇒ 数据偏移算成 12、`DataLength` 从 `+8` 读
  （读到的是**数据本身的前 4 字节**，例如 `"Se"` = `0x00650053`）⇒ 长度离谱。
- **幸好没出事**：`LocateDataRegion` 的"长度字段必须自洽（`offset+length ≤ available`，
  且用 64 位算防回绕）"校验把它挡成"**定位失败 ⇒ 不替换**"。
  否则会**零掉错误的位置**（`Type` / `DataLength` 被清零 ⇒ 调用方解析出乱码）。
- ⇒ 已修 codec（新增 `kPartialAlign64HeaderBytes = 8` 与 `IsPartialAlign64Class`），
  并把**实测布局钉成 7 条探针判据** —— 将来 Windows 改布局会**变红**，而不是悄悄改坏。

### 改了什么

| 文件 | 改动 |
|---|---|
| `shared/r3shieldcore/r3shieldcore_shared.h` | `AbiVersion` 23 → **24**；新增 `FlagSpoofRegistry = 0x00000200`（`Flags2`，默认**关**） |
| `R3ShieldCoreLib/registry_spoof_codec.h` | **新增**（全 `inline`）：`HasDataRegion` / `IsFullClass` / `IsPartialAlign64Class` / `LocateDataRegion` / `ZeroDataRegion` / `RegTypeName` |
| `R3ShieldCoreLib/r3shieldcore_rules.h` / `.cpp` | 抽出 `MatchesUserProtectRegistryBothForms`（**两个**调用点共用，铁律 127）+ 新增 `IsProtectedRegistryPathForSpoof`（**忽略操作类型**，与写入判据不同） |
| `R3ShieldCoreLib/registry_guard.cpp` | `Action::Spoof`；`SpoofRegEnabled()` / `HookReadsEnabled()`；`Evaluate` 新增 `spoofInfoClass` 参数与 `!blockable` 的替换分支；`NtQueryValueKey_Hook` 清零 + 失败日志 + Spoof 上报；`Install` 挂载条件放宽 |
| `R3ShieldCore/r3shieldcore_config.cpp` | 新增 `spoof_reg=` 解析（默认关） |
| `R3ShieldCore/app.cpp` | 横幅新增「注册表值替换」行（含**名单条数**；名单为空时明说"实际不生效"） |
| `dist/R3ShieldCore-x64/r3shieldcore.ini` | 在 `protect_reg=` 小节里加 `spoof_reg=0` + 说明（与名单强耦合，放一起） |
| `tools/config_ut.cpp` | 12 条新断言（默认关 / `=1` / `=0` / 别名 / 行内注释 / 双向交叉 / 位值两两不同） |
| `tools/spoof_reg_probe.cpp` + `build_spoof_reg_probe.sh` | **新增**：自包含探针（`#include` 生产同一份 codec） |
| `check_dist_sync.sh` | 新增 v71 段（EXE 窄串 + 双架构 DLL 宽串 + 3 条前提 + 出厂默认关负对照） |

### 为什么 `AbiVersion` 要升（**布局没变**）

与 v70 同一个理由：**语义变了**。旧 DLL 不认识新位 ⇒ 静默**不替换**，
而新引擎横幅却印「注册表值替换: 开」⇒ **横幅撒谎**（铁律 93）。
升 ABI 后旧 DLL 会被拒装/拒用，不会出现"看起来开了、实际没开"。

### 验证状态

| 层 | 命令 | 结果 |
|---|---|---|
| 机制探针 x64 | `bash build_spoof_reg_probe.sh --run` | **60 通过 / 0 失败** |
| 机制探针 x86 | `ARCH=x86 bash build_spoof_reg_probe.sh --run` | **60 通过 / 0 失败** |
| 负对照（故意把 class 4 当 12 字节头） | 同上 | **58 通过 / 2 失败**（class 4 变红） |
| 配置单测 | `bash build_ut.sh` | **149 通过 / 0 失败**（= v70 的 137 + 12 条新断言） |
| 双架构零警告构建 | `bash build.sh` | 通过 |
| dist 代次闸门 | `bash check_dist_sync.sh` | PASS（含 v71 段与负对照） |
| 端到端 | 真引擎注入 + 真目标进程 | **夹具已覆盖本面**（v74 起目标程序的注册表面 = `RegQueryValueExW` 读一个预置值）；**但未在本机真跑**（铁律 175）—— 见文末 v74 落地记录 |

### 探针验了什么（60 条，按问题分组）

* **0. 布局勘察（7 条）**：class 0 无数据区；class 2 头 12、Type 在 +4；
  **class 4 头 8、Type 在 +0（没有 TitleIndex）**；class 1 的 `DataOffset@8`/`DataLength@12`
  且 `DataOffset+DataLength == ResultLength`；**class 3 与 class 1 逐字节相同**。
* **A. 基线负对照（3 条）**：替换关着时拿到真值，且替换计数为 0。
* **B/C/D. 逐类型（5 类型 × 5 条 = 25 条）**：真值非空（非空真）→ 替换后数据区全 0 →
  **数据区之外逐字节相同**（长度/偏移/名字全没动）→ `*ResultLength` 不变。
* **D2. 归零后语义（3 条）**：`REG_SZ` 首 WCHAR 为 0（空串）、`REG_DWORD` 为 0、
  `REG_MULTI_SZ` 首 WCHAR 为 0（空列表）。
* **C2. Full / Align64 类（3 类 × 3 条 = 9 条）**：class 1 / 3 / 4 都只动数据区。
* **E. 边界（8 条）**：class 0 / class 5 判为无数据区；class 0 不替换（计数未增）；
  缓冲区短于结构头 / `dataLength==0` / `dataOffset+dataLength` **回绕** / `info==nullptr`
  ⇒ 一律**定位失败**。
* **F. 真实调用方（3 条）**：`RegQueryValueExW` 也读到空串 ⇒ 替换对**真实调用方**生效
  （不是"只有直接调 ntdll 才有效"）。
* **计数自检（2 条）**：发生过替换；`hits >= spoofed`（交叉恒等式）。

### 已知盲区（诚实标注，非本开关引入）

* `NtEnumerateValueKey` / `NtEnumerateKey` **不隐藏** ⇒ 枚举仍能看见值的**名字与类型**
  （只是拿到 0 值）。这是 §8 的"**枚举隐藏**"子项，属独立一步（游标语义）。
* `KeyValueBasicInformation`（class 0）**没有数据区** ⇒ 不动（它本来也不携带值的秘密）。
* `NtQueryMultipleValueKey` **没挂**。
* 直接读 hive 文件、事务注册表（KTM）**没覆盖**。
* `KeyValueLayerInformation`（class 5，Win8.1+ 分层键）**不认识 ⇒ 一律不替换**（宁可漏，不可崩）。

定位是**提高成本**，不是硬边界 —— 与屏幕面 / 剪贴板面同一性质。

---

## 可行性探针（2026-10-10）—— **摄像头面**（§8 Phase 2）：机制可行，但**规则要改**

用户要求「继续注册表值 / 摄像头」。注册表值已落地（v71，见上）。
摄像头按 §8 排在"二期"，本项目的纪律是**先勘察、再决定**，所以本轮**只做可行性探针，
不改生产代码**。探针 = `tools/spoof_camera_probe.cpp`（+ `build_spoof_camera_probe.sh`）。

### 结论（TL;DR）

| 问题 | 结论 |
|---|---|
| 帧数据能拦到吗？ | **能**。`IMFSourceReader::ReadSample` 不是导出函数 ⇒ 走 **vtable patch**（槽号 9）。 |
| 改完调用方看得见吗？ | **看得见**。`IMFSample` → `IMFMediaBuffer::Lock` 拿到的是**同一块内存**，原地改写即可。 |
| 真机跑通了吗？ | **跑通了**。本机有 2 个视频采集设备，`--use-camera` 模式下 **26 通过 / 0 失败**。 |
| 能直接套 v67/v70/v71 的"清零"规则吗？ | ★★ **不能**。见下面「最重要的差异」。 |
| 建议现在做吗？ | **暂不做生产版**。理由见「为什么建议缓一步」。 |

### ★★ 最重要的差异：**"全 0"在 YUV 里不是黑**

v67（屏幕）/ v70（剪贴板）/ v71（注册表值）共用同一条规则：
**同格式、同尺寸、内容清零**。对这三个面，"全 0"就是"空/黑"，语义自洽。

**摄像头面打破这条规则**：视频帧常见的 YUV 子类型里，`Y=0,U=0,V=0` **不是黑**，
而是一个**饱和色**（有限范围下黑是 `Y=16 / UV=128`）。

实测证据（探针 Part D，纯逻辑 + 反向对照）：

```
[D1] RGB32 的中性值 = 全 0（= 黑）                                PASS
[D2] NV12 的中性值 = Y16/UV128（**不是全 0**）                    PASS
[D3] YUY2 的中性值 = Y16/UV128                                    PASS
[D4] 不认识的子类型 -> 规划失败（回落「不替换」）                  PASS
[D6] 反向对照：老规则（全 0）在 YUV 下**不等于**黑（首字节 0 != 16） PASS
```

★ 安全目标（**不泄露真画面**）仍然达到 —— 全 0 也是一个合法图像。
★ 但**对外口径**不能说"黑帧"：那是撒谎（铁律 97 的同类）。
★ 两条路可选：① 按子类型填**中性值**（NV12/YUY2 → Y16/UV128）；
  ② 口径改成"**中性帧**"而不是"黑帧"。**建议 ①**，因为用户/日志看到的是"黑"。

### 实测：真实摄像头**默认不给 RGB32**

第一次真机跑（未开"高级视频处理"）时：

```
SetCurrentMediaType(RGB32) hr=0xC00D36B4      ← MF_E_INVALIDMEDIATYPE
视频帧: subtype=YUY2 尺寸=640x480
最后一帧字节数=614400                          ← 640*480*2（YUY2 是 2 字节/像素）
```

⇒ **很多真实摄像头不接受 RGB32 输出**。要让读取器替我们做色彩转换，
必须给 `MFCreateSourceReaderFromMediaSource` 传
**`MF_SOURCE_READER_ENABLE_ADVANCED_VIDEO_PROCESSING = TRUE`** 的属性包。
加上之后：

```
SetCurrentMediaType(RGB32) hr=0x00000000      ← 成功
视频帧: subtype=RGB32 尺寸=640x480（GUID.Data1=0x16）
最后一帧字节数=1228800                         ← 640*480*4
```

★ 这条对**生产版**很关键：不设这个属性，`SetCurrentMediaType` 会失败，
而"失败"看起来只是"设置没生效"（铁律 97）—— 实际拿到的是 YUY2，
于是"清零"就变成"填饱和色"。

### 探针验了什么（26 条，真机模式）

* **C. 设备勘察（报告，不计分）**：本机视频采集设备数 = 2。
* **A. 机制链前提（5 条）**：拿到 `IMFSourceReader`；媒体类型是音频（合成源）；
  `mfreadwrite.dll` 已加载；**vtable[9] 落在 `mfreadwrite.dll` 范围内**（槽号没记错）；
  patch 成功。
* **B/C. detour 与"调用方可见"（7 条）**：detour 被调用；真调返回 sample；
  **替换关着时拿到真数据**（负对照）；真数据里确实有非 0（非空真前提）；
  至少一个样本被改写；**调用方看到的是全 0**（不是我们自己的副本）；没有 Lock 失败。
* **D. 中性帧决策表（6 条）**：见上表。
* **E. 真摄像头帧（7 条）**：拿到类型与尺寸；子类型已知（前提）；
  帧字节数 == 宽×高×每像素（**子类型前提**）；真帧非 0；真帧被改写；
  **调用方看到的真实帧是全 0**；子类型家族 ⇒ 决定"全 0 是否等于黑"。

### ★ 探针的一个设计决定：真机测试**默认不开**

打开真实摄像头会点亮指示灯。本探针是"自包含、不注入"的（不属于铁律 175 约束的"跑引擎"），
但"开硬件"应当由使用者显式决定 ⇒ 做成 **`--use-camera`** 开关，
默认 `[SKIP]` **并计入结论行**（铁律 178：跳过必须可见、必须计数）。
⇒ 默认跑 **18 通过 / 0 失败 / 1 跳过**；加开关跑 **26 通过 / 0 失败 / 0 跳过**。

### 为什么建议**缓一步**做生产版（诚实标注）

1. **规则要改**：不能沿用"清零"，得引入"按子类型填中性值"的决策表
   （本探针的 Part D 已是雏形），并且**不认识的子类型必须回落"不替换"**（铁律 194/196）。
2. **流式 + 有状态**：与屏幕/剪贴板/注册表三个面不同，这里是**一帧一帧地来** ——
   涉及帧率、缓冲复用、`IMFMediaBuffer` 的生命周期、`IMF2DBuffer`（平面/stride）。
   本探针只验了"单帧可改写"，**没验**这些。
3. **多路径更强**：除了 `IMFSourceReader`，还有
   `avicap32`（VFW 老路）、DirectShow、WinRT `MediaCapture`、
   Media Foundation 的 `IMFMediaEngine`、以及**内核态**摄像头驱动接口。
   本项目的 `camera_guard.cpp` 只挂了**创建类** API（`MFCreateDeviceSource*` /
   `MFCreateSourceReaderFromMediaSource` / `MFEnumDeviceSources` / `avicap32` /
   `waveInOpen` / `IMMDevice::Activate`），**帧数据路径此前完全没碰** ——
   本探针证明了"帧路径可以碰"，但**没有**把它接进 guard。
4. **是否需要**：摄像头"替换"的产品语义（给个黑帧）不如屏幕/剪贴板常用，
   而风险（帧尺寸/stride 算错 ⇒ 花屏或崩溃）高于前三个面。

⇒ **建议**：先把"按子类型填中性值"的决策表抽成
`camera_spoof_codec.h`（全 `inline`，生产与探针共用，铁律 195），
再决定接不接进 `camera_guard.cpp`。本轮**不接**。

### 改了什么

| 文件 | 改动 |
|---|---|
| `tools/spoof_camera_probe.cpp` | **新增**（自包含可行性探针：合成源机制链 + 中性帧决策表 + 可选真机帧） |
| `build_spoof_camera_probe.sh` | **新增**（★ 链接要 `mfplat` + `mfreadwrite` + `mfuuid` + **`mf.lib`** —— `MFEnumDeviceSources` 在 `mf.lib`，漏了会 LNK2019） |
| `docs/摄像头帧替换-可行性探针-2026-10-10.txt` | 实测输出（两种模式各一段） |

**生产代码未改**（`camera_guard.cpp` / `AbiVersion` / ini 均未动）。

---

## 落地记录（v72，2026-10-10）—— **注册表「枚举隐藏」面**（Phase 3 第二子项）

§8 Phase 3 原文：「先做**值替换**（`NtQueryValueKey`），再做**枚举隐藏**（`NtEnumerateValueKey`），逐条测长度字段。」
v71 做完了前半句，v72 做后半句 —— 并且把 §2.2 里标为"有游标语义"的那个难点正面解决了。

### 语义：什么被藏起来了

枚举**受保护位置**（`protect_reg=` 前缀命中）的**子键 / 值**时，
把命中保护前缀的那些项**从列表里去掉**，返回 `Decision::Spoofed`。
配合 v71 的「值读不到」与既有的「写不进」，合起来即
**「保护 = 写不进 + 读不到 + 看不见」**。

### ★★★ 这个面特有的坑（一）：枚举有**游标语义**，「往后挪一格」会产生**重复项**

值替换是**单点取值**：调用方给个名字，我们改内容，一进一出，无状态。
枚举**不是**：调用方给的是**索引**（第 0 个、第 1 个……），我们自己维护"扫到哪了"。
于是"隐藏一项"最直觉的做法 —— *命中就跳过、返回下一项* —— 是**错的**：

```
列表 = [A(可见) B(隐藏) C(可见)]
调用方问索引 0 -> 返回 A（正确）
调用方问索引 1 -> 命中 B 是隐藏的，往后挪一格 -> 返回 C
调用方问索引 2 -> 返回 C   ← ★ 重复了！
```

`[A, C, C]` 里 C 出现两次，调用方（`RegEnumKeyEx` 那套循环）会看到**重复项**，
而且**少了一项**。凡是按"枚举出来再计数 / 去重 / 建映射"的软件都会出问题。

**正解 = 索引重映射**：调用方要第 N 个**可见**项，我们从 0 扫、跳过被隐藏项、
数到第 N 个可见项时记下其**原始索引 M**，再用调用方给的 `class` / 缓冲区
**真调一次原函数**取第 M 项。返回的每一项都是**真实、合法、结构完整**的项
（铁律 194：能造出合法替代物才替换；这里的"替代物"就是列表里的下一项）。

- 探针里有专门一条判据钉住**"无重复"**；
- 并且配了一个 `NaiveMap` **负对照**（故意实现成"挪一格"）证明它**确实会变红** ——
  否则"无重复"这条判据是**空真**（铁律 110：先问全零时是否也成立）。

### ★★ 这个面特有的坑（二）：探测名字**必须用 `class 0`**，不能借调用方的 class

`NtEnumerateValueKey` 有好几个 `InformationClass`：

| class | 结构 | **有名字吗** |
|---|---|---|
| 0 | `KEY_VALUE_BASIC_INFORMATION` | **有**（`NameLength` @ +8、`Name` @ +12） |
| 1 | `KEY_VALUE_FULL_INFORMATION` | 有 |
| 2 | `KEY_VALUE_PARTIAL_INFORMATION` | **没有！** |

而 `RegEnumValue`（最常用的那个 Win32 包装）内部用的**正是 class 2**。
如果我们的"这一项叫什么、要不要藏"的探测**借用调用方传进来的 class**，
那么在 class 2 这条**最常见路径**上我们**永远拿不到名字** ⇒ 判不出 ⇒ 不隐藏，
而且**不报错**（静默失效，铁律 97）。
⇒ 探测**一律用 class 0**，与调用方用的 class 无关。

（两个 enum 的 `class 0` 头长度**还不一样**：子键 `KEY_BASIC_INFORMATION` 头 **16** 字节
（`NameLength` @ +12、`Name` @ +16），值 `KEY_VALUE_BASIC_INFORMATION` 头 **12** 字节
（`NameLength` @ +8、`Name` @ +12）。探针的 §0 布局勘察把这四个偏移**实测钉死**，
不靠记忆。）

### ★★ 这个面特有的坑（三）：空名三态 —— "(默认)"项不能让整条路**静默失效**

注册表每个键都有一个**名字为空**的「(默认)」值，枚举时它 `NameLength == 0`。
如果把它当成"取不到名字 ⇒ 判不出 ⇒ 放弃隐藏"，那么**任何有默认值的键**
都会让整条枚举隐藏**静默失效**（而且看起来很"正常"，因为没报错）。
⇒ 探测必须返回**三态**：

| 三态 | 含义 | 处理 |
|---|---|---|
| `Parsed` | 拿到名字了 | 按 `protect_reg=` 判是否隐藏 |
| `Unnamed` | **空名**（"(默认)"项） | **按可见继续扫**（不能中止隐藏） |
| `Indeterminate` | 真判不出（探测失败 / 缓冲区不够） | 放弃隐藏，本次原样返回 |

### ★ 性能：不相关的键**一次都不扫**

枚举是**高频**操作（软件启动时天天枚举一大堆键）。如果每枚举一次都去和
`protect_reg=` 名单逐个比一遍，就是给**所有**正常枚举加 O(n) 开销。
⇒ 新增 `R3ShieldCoreRules::CouldHaveProtectedChildRegistry(keyPath)` 做**保守上界**：
只有当"被枚举的键**可能**有受保护的子项"（它在某个前缀**下面**，或某个前缀在它**下一层**）时，
才进入扫描。不相关的键直接原样调用原函数。
内部用带**路径边界**的前缀判定（挡 `SOFT` 误命中 `SOFTWARE`）。

### 改了什么

| 文件 | 改动 |
|---|---|
| `R3ShieldCore/shared/r3shieldcore/r3shieldcore_shared.h` | `AbiVersion` **24 → 25**；新增 `FlagSpoofRegistryEnum = 0x00000400`（默认关）+ 完整语义注释 |
| `R3ShieldCore/R3ShieldCore/r3shieldcore_config.cpp` | 新增 `spoof_reg_enum=` 解析分支 |
| `R3ShieldCore/R3ShieldCore/app.cpp` | 横幅新增「注册表枚举隐藏」状态行（含 `protect_reg` 名单条数） |
| `R3ShieldCore/R3ShieldCoreLib/registry_enum_codec.h` | **新增**（索引重映射 + 名字三态探测 + 子路径构造，全 `inline`，**连控制流一起抽**） |
| `R3ShieldCore/R3ShieldCoreLib/r3shieldcore_rules.h/.cpp` | 新增 `CouldHaveProtectedChildRegistry()` + 带边界的 `PrefixIsUnderPath()` |
| `R3ShieldCore/R3ShieldCoreLib/registry_guard.cpp` | 重写 `NtEnumerateKey_Hook` / `NtEnumerateValueKey_Hook`（三态判定 + 重映射）；挂载条件放宽 |
| `dist/R3ShieldCore-x64/r3shieldcore.ini` | 新增 `spoof_reg_enum=0` + 说明块 |
| `tools/v72_guard_ut.cpp` | **新增**（guard 层纯逻辑单测，54 通过 / 0 失败，x64+x86） |
| `tools/spoof_reg_enum_probe.cpp` | **新增**（自包含真 API 探针，36 通过 / 0 失败） |
| `tools/config_ut.cpp` | 补 `spoof_reg_enum=` 断言（双向交叉检查 + 四个位两两不同） |
| `check_dist_sync.sh` | 新增 v72 代次段；★ 把 v71/v72 两条标记**收紧成词边界匹配**（见下） |

### ★ 顺带修掉的一处**闸门假绿**：两条标记的**子串包含**关系

v72 的标记 `spoof_reg_enum` **包含** v71 的标记 `spoof_reg`。
`check_dist_sync.sh` 原本用 `grep -F`（裸子串）判 v71 标记 ⇒
「v71 的标记被删、v72 的标记还在」时，v71 那条判据会被 `spoof_reg_enum` 那一行**满足** ⇒ **假绿**。
修法 = 两条标记一律用 `grep -w`（词边界）：`-w` 把 `_` 算作词字符，
所以 `spoof_reg_enum` 里那个 `spoof_reg` 后面跟着 `_`，**不算**词边界，匹配不上。
（配了正 / 负对照：只有 v72 标记 ⇒ v71 判据**不匹配**；两者都在 ⇒ v71 判据**匹配**。）

### 为什么 `AbiVersion` 要升（**布局没变**）

同 v71 的理由：布局没变，但**语义变了**。旧 DLL 不认识 `FlagSpoofRegistryEnum` 这一位
⇒ 枚举**照原样返回完整列表**；而新引擎横幅却印「注册表枚举隐藏: 开」⇒ **横幅撒谎**（铁律 93）。
升到 25 之后，引擎与 DLL 的 `AbiVersion` 对不上会**显式报错**，而不是默默骗人。

### 验证状态

- **机制探针** `tools/spoof_reg_enum_probe.exe`：**36 通过 / 0 失败**
  （自包含、自挂 `NtEnumerateKey`/`NtEnumerateValueKey`、**不注入、不跑引擎**，铁律 175）。
- **纯逻辑单测** `tools/v72_guard_ut.cpp`：**54 通过 / 0 失败**（x64 + x86，零警告）。
- **配置单测** `tools/config_ut.cpp`：双架构各 **454 通过 / 0 失败**。
- **发布闸门** `check_dist_sync.sh`：PASS（含 v72 代次段 4 条判据）。
- **全量构建** `bash build.sh`（Release x86+x64）：OK（图标资源已编入）。
- 6 个源码闸门（含 `check_source_gbk.py`）：全 PASS。
- 端到端（真引擎注入）**仍未覆盖本面** —— v74 起的三面夹具走的是注册表**值替换**
  （`RegQueryValueExW` 读一个预置值），**不是**枚举隐藏
  （`NtEnumerateKey` / `NtEnumerateValueKey`）。枚举隐藏的端到端仍待做。

### 探针验了什么（36 条，按问题分组）

| 组 | 验的东西 |
|---|---|
| 0 | **布局勘察**：class 0 两个 enum 的头长度 / 四个偏移（实测钉死，不靠记忆）；值索引 0 是空名默认项 |
| A | 基线负对照：隐藏**关**时列表 = 原始列表 |
| B/C/D | 隐藏**开**：短列表正确、★**无重复**、越界语义（`NO_MORE_ENTRIES` + `*ResultLength=0`）、隐藏关时同索引确为被藏项 |
| C2 | ★ 可见索引拿到的项与**直接真调原始索引**的项**逐字节相同**（长度字段没被改） |
| E | 空名默认项**不让**隐藏失效 |
| F | 缓冲区太小 ⇒ `STATUS_BUFFER_TOO_SMALL`（**实测 0xC0000023**，不是 `BUFFER_OVERFLOW`）+ 什么都没写 |
| G | 负对照：与保护前缀**无关**的键 ⇒ 一项都不藏（列表与隐藏关时完全一致） |
| H | 真实调用方视角：`RegEnumKeyExW` / `RegEnumValueW` 也看到**短列表** |
| I | **诚实边界**：被隐藏的项仍能 `RegOpenKeyExW` / `RegQueryValueExW` **直接访问**（列表级隐藏，不是访问级） |

### 已知盲区（诚实标注，非本开关引入）

- 隐藏是**列表级**的，不是**访问级**的：被藏的键 / 值仍可按名字直接打开 / 读；
- `NtQueryKey` 返回的 `SubKeys` / `Values` **计数不变**（改它要同步改一堆字段，风险远大于收益）；
- 事务注册表（KTM）/ hive 文件直读 / WOW64 重定向路径**未覆盖**；
- **必须配 `protect_reg=`** 才有效；名单为空时本开关空转（横幅会明说）。

---

## 落地记录（v73，2026-10-10）—— **摄像头「帧替换」面**（§8 Phase 2）

v71 落地「值替换」、v72 落地「枚举隐藏」之后，v73 把「回传数据替换」接到
**第四个面：摄像头**。前三个面都是**单次调用**（一进一出、无状态）；
摄像头是**流式**（一帧一帧来）—— 这是它与前三个面**根本不同**的地方，
也是本节大部分篇幅在讲"为什么不能照搬"的原因。

### 语义：什么被换成了什么

| | |
|---|---|
| 触发点 | `MFCreateSourceReaderFromMediaSource` 的**判定**（本应拒绝的那一刻） |
| 被换的对象 | 该 reader **之后每一帧**的像素内容（`IMFSample` → `IMFMediaBuffer`） |
| 换成什么 | **中性帧**：RGB 家族 → 全 0（**恰好就是黑**）；YUV 家族 → **Y16 / UV128**（有限范围的黑） |
| 调用方看到 | 读取器**建成功**、`ReadSample` **返回成功**、帧长不变 —— 但内容是空白画面（`Decision::Spoofed`） |
| 生效条件 | `spoof_camera=1` **且** `hook_camera=1` **且** `mode=block` / `mode=ask`（用户点拒绝） |
| 不生效 | `mode=log`（本来就不拒）、`mode=block_all`（一律拒绝，铁律 165）、开关为 0（回落 `Block`） |

### ★★★ 这个面特有的坑（一）：帧路径**不是导出函数** ⇒ 只能 patch vtable

`IMFSourceReader::ReadSample` **不是导出函数**（`mfreadwrite.dll` 不导出它）
⇒ `MH_CreateHook(GetProcAddress(...))` **挂不上**。唯一出路是
**patch 对象的 vtable 槽**。

- 槽号 **9**（`IUnknown` 占 0~2，`ReadSample` 是第 10 个虚函数）。
  ★ 这个数字**不是"按文档数的"** —— 探针里有 **A4** 判据
  （`vt[9]` 必须落在 `mfreadwrite.dll` 的模块范围内），生产侧在 patch 前做
  **同一套检查**，不通过就**拒绝 patch**（宁可功能不生效，也不能把错误的
  函数指针换掉 —— 那会让调用方跳进别的函数，直接崩）。
- ⚠️ **成员函数指针不能转成整数**：最初想用
  `reinterpret_cast<size_t>(&IMFSourceReader::ReadSample) / sizeof(void*)`
  让编译器算槽号，结果 **C2440** —— 虚函数的成员指针在 MSVC 上不是"一个地址"，
  而是"槽号 + this 调整"的打包表示，大小也不是指针大小。
  ⇒ 老老实实用常量（**由探针实测钉死**）+ 运行时模块范围检查。

### ★★★ 这个面特有的坑（二）：vtable 是**模块级共享**的 ⇒ 必须**按对象**记标记

同一个 COM 类的所有实例指向**同一份 vtable 数组** ⇒ patch 一次，
进程内**所有** `IMFSourceReader` 都会经过我们的 detour。

⇒ 所以"要不要替换"**不能**靠"patch 过就算数"（那会把**别的** reader 也一起换了，
包括我们没打算管的那个）—— 必须**按对象**记在 `g_spoofReaders[]` 里，
detour 里先 `IsSpoofReader(self)` 再决定。

★ 同时**按 vtable 存原件**（`g_patchedReaderVtables[]`）：理论上不同来源的 reader
（`FromURL` / `FromMediaSource` / `FromByteStream` …）可能是**不同的类**
⇒ 不同 vtable ⇒ 不同原函数。存一份全局原件，第二个 vtable 的调用就会跳进
**第一个**的实现里 —— 那是极隐蔽的错。

### ★★★ 这个面特有的坑（三）：**异步路径不覆盖 = 静默泄露**

`MF_SOURCE_READER_ASYNC_CALLBACK` 模式下，帧**不从 `ReadSample` 的 out 参数回来**，
而是稍后从 `IMFSourceReaderCallback::OnReadSample`（槽 3）交付。

- 不覆盖它 ⇒ 异步模式**静默泄露真画面**（我们的 detour 只改了 `ReadSample`
  返回的那个 `IMFSample**`，而它是空的）。
- ⚠️ **回调签名里没有 reader** ⇒ 查不到媒体类型 ⇒ 没法解析中性化计划。
  ⇒ `ReadSample` detour 每次把解析结果存进一个 **seqlock** 保护的全局计划
  （写者两次自增：奇数=写入中、偶数=稳定；读者比对奇偶+序号），
  回调 detour 取用。跨线程读 POD，**无锁且不撕裂**。
- ⚠️ 回调的 vtable 属于**调用方自己的类**（不在 `mfreadwrite.dll` 里）
  ⇒ 做不了"落在某模块内"的检查 ⇒ 它是**唯一没有第二道保险**的一处，
  靠探针（Part C/D）覆盖。
- ★ **顺序不能反**：**先替换、再转交**。反了调用方就先看到真帧了。
- ★ 拿不到计划 / 改不动 ⇒ **回落拒绝**（把这次交付改成失败），
  而不是把真帧递出去（fail-closed，铁律 194）。

### ★★ 这个面特有的坑（四）：**只有一条入口能替换**

| 入口 | 能不能替换 | 为什么 |
|---|---|---|
| `MFCreateSourceReaderFromMediaSource` | ✅ **唯一** | 它有帧路径（`ReadSample`） |
| `capCreateCaptureWindowW/A`（VFW） | ❌ 回落 `Block` | 帧走 `WM_CAP_*` 消息 / 回调，没有我们能改的缓冲区 |
| `MFCreateDeviceSource(Activate)` | ❌ 回落 `Block` | 设备源本身没有帧，要再建 reader 才有 |
| `MFEnumDeviceSources` | ❌ 不拦 | 枚举只记录 |
| `waveInOpen` / MCI / `IAudioClient::Initialize` | ❌ 回落 `Block` | 中性内容是另一套语义 |

⇒ 所以 `Evaluate(..., canSpoof)` 的 `canSpoof` **由调用点决定**，不是全局 ——
只有那一条入口传 `true`。

### ★★ 这个面特有的坑（五）：MF 里**摄像头与麦克风共用同一套 API**

`MFCreateSourceReaderFromMediaSource` **也是麦克风采集的标准入口**。
不查"有没有视频流"就放行 ⇒ `spoof_camera=1` 会把**纯音频**读取器也放行
（我们造不出"中性音频"）= **"放宽一个开关顺带打开别的行为"**（铁律 199）。

⇒ 建读取器时先 `HasVideoStream()`（`GetNativeMediaType(FIRST_VIDEO_STREAM, 0)` 是否成功）；
不过 ⇒ **回落拒绝**。

### ★★ 这个面特有的坑（六）：`stride` 的负数是**行序**，不是"负步长"

`MF_MT_DEFAULT_STRIDE` 对**自下而上**的帧是**负数** —— 那是"行序"的表示。
⇒ 取绝对值；且 **`absStride < 名义步长` 时回落名义值**（比名义值小 = 一行装不下
⇒ **不猜**，铁律 117）。反过来 `absStride > 名义值`（驱动加了行 padding）则**采用**。

### 改了什么

| 文件 | 改动 |
|---|---|
| `R3ShieldCoreLib/camera_spoof_codec.h` | **新建**（~340 行，全 `inline`）：GUID 表 + `ClassifyFormat` / `NominalStride` / `PlanForFormat` / `ApplyNeutral` |
| `R3ShieldCoreLib/camera_guard.cpp` | 引 MF 头（顺序 `mfapi`→`mfidl`→`mfreadwrite`）+ v73 段（~500 行）：seqlock、按对象标记、`HasVideoStream`、`ResolveFramePlan`、`NeutralizeSample`、两个 detour、两个 vtable patch、`PatchAsyncCallbackIfAny`；`Action::Spoof` + `RejectOrSpoof` + `Evaluate(..., canSpoof)` |
| `shared/r3shieldcore/r3shieldcore_shared.h` | `AbiVersion` 25 → **26**；新增 `FlagSpoofCamera = 0x800` + 语义注释块；修掉一处**过时注释**（"只有 ScreenGuard 会产生 `Spoofed`"） |
| `R3ShieldCore/r3shieldcore_config.cpp` | 新增 `spoof_camera=` 解析（默认关） |
| `R3ShieldCore/app.cpp` | 新增三态状态行（开 / 关，铁律 97） |
| `tools/spoof_camera_probe.cpp` | 改成 `#include "camera_spoof_codec.h"`（删掉探针自己那份决策表）；Part D 扩到 25 条；Part E 的 E6 改成"调用方视角"判据 |
| `tools/v73_guard_ut.cpp` | **新建**：codec 纯逻辑单测（84 条） |
| `tools/config_ut.cpp` | 新增 v73 的 17 条断言 |
| `build.sh` | DLL 链接加 `mfuuid.lib` |
| `build_guard_ut.sh` | 单测清单加 `v73_guard_ut`（4 → 5 个） |
| `check_dist_sync.sh` | 新增 v73 代次段；结尾 PASS 行加 `/v73` |
| `dist/…/r3shieldcore.ini` + `配置详解.md` | 新增 `spoof_camera=0` 说明块（`配置详解.md` 由 `_gen_config_doc.py` **重新生成**，不手改） |

### 为什么 `AbiVersion` 要升（**布局没变**）

`Policy::Flags2` 只多了一个位，**结构体布局一个字节都没动**。但语义变了：

- 旧 DLL（v25）**不认识**这个位 ⇒ 它会在 `MFCreateSourceReaderFromMediaSource`
  上**直接拒绝**（= 没有本开关时的行为）；
- 而新引擎的横幅会印「摄像头帧替换: **开**」。

⇒ **横幅撒谎**（铁律 93）。升到 26 之后，引擎侧的一致性校验会拒掉旧 DLL，
宁可"功能整体不生效"，也不能出现"印着开、实际是拒绝"这种**不可诊断**的状态。

### 验证状态

- **机制探针** `tools/spoof_camera_probe.exe`：默认 **35 通过 / 0 失败 / 1 跳过**；
  `--use-camera` 真机 **43 通过 / 0 失败 / 0 跳过**（自包含、不注入、不跑引擎，铁律 175）。
- **纯逻辑单测** `tools/v73_guard_ut.cpp`：**84 通过 / 0 失败**（x64 + x86，零警告，**不链 MF 库**）。
- **配置单测** `tools/config_ut.cpp`：**180 通过 / 0 失败**（x64；x86 同）。
- **guard 层单测**：清单 4 → **5** 个，双架构全部跑完（覆盖恒等式自检通过）。
- **发布闸门** `check_dist_sync.sh`：PASS（含 v73 代次段 4 条判据 + 3 条源码前提）。
- **全量构建** `bash build.sh`（Release x86 + x64）：OK，**零警告**。
- 6 个源码闸门（含 `check_source_gbk.py`）：全 PASS。
- 其余四个 spoof 探针回归：`spoof_retdata_probe` 9/0、`spoof_clipboard_probe` 25/0、
  `spoof_reg_probe` 60/0、`spoof_reg_enum_probe` 36/0 —— **全部未回归**。
- 端到端（真引擎注入）**仍未覆盖本面** —— 摄像头需要真设备 + Media Foundation
  取帧路径，v74 的三面夹具（屏幕 / 剪贴板 / 注册表）**不含摄像头**。

### 探针验了什么（43 条，按问题分组）

| 组 | 验的东西 |
|---|---|
| A | 能不能拿到 `IMFSourceReader` 并 patch 它的 vtable；★ **A4：`vt[9]` 落在 `mfreadwrite.dll` 内**（槽号没记错） |
| B | 合成媒体源：同步 `ReadSample` 的帧被改掉、**调用方看得见** |
| C | 异步回调路径：`OnReadSample` 的帧也被改掉（不覆盖就是静默泄露） |
| D0a~D0i | ★ **9 条 SDK GUID 交叉校验**（`static_assert` 与 `MFVideoFormat_*` 逐一相等）—— 防手抄漂移 |
| D1~D4b | 分类 / 名义步长 / 计划三类填充 |
| D5 | NV12 640×480 按**真实平面**切分（Y 全 16、色度全 128） |
| D5b/D5c | YUY2 交错布局 [16,128,16,128]；★ **YUY2 ≠ UYVY**（顺序真按 `packedOrder` 走） |
| D6 | ★ **反向对照**：老规则（全 0）在 YUV 下**不等于**黑 |
| D7 | ★ **越界哨兵**：`len` 之后 32 字节未被改（"长度不变"是命门） |
| D8~D10 | stride 负数取绝对值 / 小于名义值回落 / 大于名义值采用 |
| E | 真摄像头：读到真帧、帧长自洽、★ **E6 调用方拿到的每一帧 == 计划的中性帧**（不是我们自己的副本） |

### 已知盲区（诚实标注，非本开关引入）

- 只覆盖 Media Foundation 的**同步 + 异步回调**两条取帧路；
  DirectShow / VFW / WinRT `MediaCapture` / 内核态摄像头驱动路径**未覆盖**；
- 帧**尺寸/步长**取自 `MF_MT_FRAME_SIZE` + `MF_MT_DEFAULT_STRIDE`；
  若驱动用了非标准步长，可能出现"右侧/底部若干字节没被中性化"的**残留**
  （**不是泄露整帧**，但也不是像素级干净）；
- 中性化是**原地改写调用方的缓冲区** ⇒ 若调用方在 `ReadSample` **之前**
  就拿到了同一块内存的别名（例如自己 `Lock` 过并缓存了指针），
  它看到的就是被改后的内容 —— 这一点**与预期一致**，但要注意
  "谁在什么时候读"决定了它看到真帧还是中性帧；
- 定位是**提高成本**，不是硬边界 —— 知道换路径的对手仍能绕过。

### 顺带记录：两处**构建/工具**上的坑（都不是本面引入，但这次踩到了）

1. **MSYS 会吞 `/FLAG`**：`dumpbin /SYMBOLS` 被 Git Bash 当成 POSIX 路径
   转换成 `<git 安装根>\SYMBOLS` ⇒ dumpbin 报 `LNK1181`。
   ★ 后果不是"报错"，而是**判据静默失效** —— 第一次跑"检查 obj 里有没有
   MF 未定义符号"，grep 出来是**空的**，看着像"干净"，实际是 dumpbin 根本没跑。
   ⇒ 必须写 `-SYMBOLS`（单个连字符）。**"判据先证明自己会失败"**（铁律 110 / 148）。
2. **`-Fo` 的路径**：给 MSYS 形式 `/d/...` 会被 cl 当成"当前盘根下的 d\…"
   （产物跑到 `D:\d\…`）；给 `D:/...` 也可能被 MSYS 转换掉盘符。
   ⇒ 用 `cygpath -w` 生成 `D:\…` 反斜杠形式。

### 链接依赖：`mfuuid.lib` 能加，`mfplat.lib` 不能加

- `MF_MT_MAJOR_TYPE` / `MF_MT_SUBTYPE` / `MF_MT_FRAME_SIZE` /
  `MF_MT_DEFAULT_STRIDE` / `MFMediaType_Video` 这 5 个 GUID 常量由
  **`mfuuid.lib`** 提供。它是**纯 GUID 数据**的静态库（与 `uuid.lib` 同类）
  ⇒ **不引入任何 DLL 导入** ⇒ 不会给"被注入到每个进程"的 DLL 添加载期依赖。**可以加**。
- `MFGetAttributeSize` 看着像 API，实测是 `mfapi.h` 里的 **`inline`**
  （`dumpbin -SYMBOLS` 看到它在 obj 里是**已定义**的 SECT 符号）
  ⇒ **不需要** `mfplat.lib`。而 `mfplat.lib` 是**导入库**（会拉 `mfplat.dll`）
  ⇒ **绝不能加**。
- ★ 顺带：`MF_SOURCE_READER_ANY_STREAM` / `MF_SOURCE_READER_FIRST_VIDEO_STREAM`
  是 **`enum` 值**（不是 GUID）⇒ 不产生链接依赖；
  `MF_SOURCE_READER_ASYNC_CALLBACK` 是 `DEFINE_GUID` 的 `selectany` 形式
  ⇒ 在 obj 里**已定义**，也不需要 lib。

---

## 落地记录（v74，2026-10-11）—— `Action` 收敛为共享枚举 + 端到端夹具升级为**三面**

这一段有两件事，都是"横切"性质的：**一件是代码结构**（决策档位收敛），
**一件是验证能力**（端到端夹具从"只截屏"扩到"屏幕 / 剪贴板 / 注册表"三条真取数路径）。

### 一、决策档位 `Action` 收敛为共享枚举

#### 改了什么

| 文件 | 改动 |
|---|---|
| `shared/r3shieldcore/r3shieldcore_shared.h` | 在 `Decision` 之前新增 `enum class Action { Pass, Record, Block, Spoof }`（含历史 / 命名冲突 / 与 `Decision` 的映射注释） |
| 17 个 guard 的 `.cpp` | 删掉各自的 `enum class Action`，改成 `using Action = R3ShieldCore::Action;` |
| `tools/check_action_enum_converged.py` | **新闸门**（三条检查 + `--selftest` 13 条负对照） |
| `check_dist_sync.sh` | 代次标记段补 v74 |

#### ★★ 为什么这不是"省几行"

v67 之前，**每一个** guard 都在自己文件顶部写一份
`enum class Action { Pass, Record, Block };`（例 `file_guard.cpp:130-135`）。
17 份重复看着像"代码风格问题"，其实不是 —— 真正的代价是
**同一个概念在 17 处独立演化**。事实也正是如此：

- **v67** 只给 `screen_guard` 加了 `Spoof`，其余 16 个**没有**；
- **v70 / v71 / v73** 又各自补一次（剪贴板 / 注册表 / 摄像头）。

⇒ 「到底哪个面支持替换」这件事，**只能靠翻源码数**，没有任何一处能回答。
收敛之后，"哪些面有 `Spoof`"变成"哪些 guard 的 `RejectOrSpoof()` 分支真的会返回 `Spoof`"，
是**一个可以被 grep 的问题**，不再依赖记忆。

#### ★ 故意**不合并**的两处（它们是**另一个概念**）

| 类型 | 位置 | 为什么不动 |
|---|---|---|
| `R3ShieldCoreToast::Action` | `r3shieldcore_toast.h` | 是 **UI 卡片的点击结论**（Allow / Deny / …），不是"这次调用放不放行" |
| `ArkActions::Action` | ark 工具 | 是**对被控进程的操作**（Suspend / ForceKill / …），又是另一维度 |

硬把它们合并只会制造一个"什么都装"的枚举 —— 与铁律 127（同一逻辑不能抄两份）
**不冲突**：那说的是"同一份逻辑别抄两处"，而这两处**本来就不是同一份逻辑**。

#### ★ `AbiVersion` **不升**（布局没变）

与 v70 / v71 / v72 / v73 都不同：那几次是**语义变了**（多了一个开关位），
旧 DLL 会把新位**静默忽略** ⇒ 横幅撒谎 ⇒ 必须升。

而 `Action` 是 **guard 内部**的决策档位：它**不进共享内存**、
**不跨 DLL 边界**（跨边界传的是 `Decision`，`Action → Decision` 的映射在各 guard 内部完成）。
所以共享结构的布局**一个字节都没变** ⇒ `AbiVersion` 保持 **26**。

#### 为什么需要一个**新闸门**（而不是靠 code review）

新加一个 guard 时，最省事的做法就是把老 guard 的头部**整段拷过来** ——
那份头部里原本就有 `enum class Action`。拷完：**编译照过、测试照绿**，
只有"概念又分叉了"这件事**没人知道**。这正是 v67~v73 那 4 次分叉的成因。
`check_action_enum_converged.py` 把这条钉死：

1. guard 的 `.cpp` 里**不得**再出现 `enum class Action` 定义
   （白名单只有 `r3shieldcore_toast.h`，且是**头文件**）；
2. 用了裸 `Action::` 的文件**必须**有 `using Action = R3ShieldCore::Action;`
   （含 `R3ShieldCoreToast::Action` 的文件豁免 —— 它的 `Action::` 指自己命名空间）；
3. 共享头里四个值**齐全**。

> ★ 实现上踩到两个**假 FAIL**（都记进 CHANGELOG）：
> ① 注释里的 `enum class Action { Pass, Record, Block };` 文本被正则当成真定义
> ⇒ 加 `strip_comments()`（保留行号、跳过字符串字面量）；
> ② `R3ShieldCoreToast::Action` 的裸 `Action::` 被当成"缺 `using`"
> ⇒ 改成**数据驱动**豁免（文件里出现 `R3ShieldCoreToast::Action` 才豁免），
> 不硬编码文件名。**假 FAIL 比漏报贵**（铁律 184）。

### 二、端到端夹具升级为三面

#### 改了什么

| 文件 | 改动 |
|---|---|
| `tools/spoof_e2e_target.cpp` | 193 → ~400 行：从"只截屏"扩成"一次运行走**三条真取数路径**" |
| `tools/spoof_e2e.sh` | 892 → ~1000 行：三面统一 runner（配置 / 断言 / 清理都按面组织） |
| `tools/spoof_e2e_selftest.sh` | **新增**：判据逻辑自测（不跑引擎），**14/0** |
| `build_spoof_e2e.sh` | 链接行加 `advapi32.lib`（注册表 API） |

目标程序现在在一次运行里做三件事，并打成**一行** `RESULT`：

| 面 | 走什么路径 | 判据字段 |
|---|---|---|
| 屏幕 | `BitBlt` → `GetDIBits`（+ `GetPixel` 参照） | `bitblt` / `lines` / `first` / `nonblack` / `getpixel*` |
| 剪贴板 | 放已知文本 → `GetClipboardData` 读回 | `clip_put` / `clip_read` / `clip_strlen` / `clip_match` |
| 注册表 | `RegQueryValueExW` 读一个**预置**值 | `reg_read` / `reg_strlen` / `reg_match` |

#### ★★ 三格矩阵不是"三个开关的组合"，是**三个语义位置**

| 格 | `mode` | `spoof` | 语义位置 | 期望 |
|---|---|---|---|---|
| **A** | `block` | `0` | **本应拒绝 + 不替换**（负对照） | 三面都被拒 / 读到真值 |
| **B** | `block` | `1` | 本应拒绝 + 替换 | 三面都"成功"但内容是假的 |
| **C** | `log` | `1` | **不拒绝 + 替换** | ★ 见下 |

★ **C 格专门证一条面间差异**：屏幕与剪贴板的替换**只在"本应拒绝"时生效**
（`RejectOrSpoof`：`log` 下恢复真实），而注册表的替换发生在**读路径**上、
**与 `mode` 无关**（`log` 下**仍**被清零）。不做这一格，
"注册表在 log 下也替换"很容易被当成 bug 去"修"。

#### ★★ 注册表测试值必须由夹具**在起引擎之前**建

`protect_reg=` 命中的路径被算作**高危写**（`r3shieldcore_rules.cpp:678`）
⇒ `mode=block` 下**被拒** ⇒ 目标进程自己**建不出来**那个值。
这不是 bug，正是"保护 = 写不进"这条设计。

⇒ 夹具在 `--prepare` 阶段用 `reg.exe` 在
`HKCU\Software\R3ShieldCoreE2E` 建一个 `Secret`（值 = `R3SC-E2E-REG-SECRET`），
引擎起来之后目标进程只**读**它；`--clean` 负责删掉。
（`REG_SUBKEY` / `REG_VALUE` / `REG_SECRET` 在脚本里是**单一来源**常量。）

#### ★ 前提检查（三面各自的 DLL 标记）

`for marker in test_inject_only spoof_clipboard spoof_reg` + `grep -qwF`：
先证**三面的逻辑都编进产物了**，再谈断言。用 `-w`（整词）是因为
`spoof_reg` 是 `spoof_reg_enum` 的**子串** —— 不加 `-w` 会让 v72 的标记
"满足" v71 的判据（**铁律 142：只查存在 ⇒ 假绿**）。
基线跑一遍要求**三面都读到真数据**，否则"变假"无法归因（**铁律 110**）。

#### 验证状态（v74）

| 层 | 手段 | 结果 |
|---|---|---|
| 结构闸门 | `python tools/check_action_enum_converged.py` | **OK**（扫 33 个 `.cpp` / 37 个 `.h`） |
| 结构闸门自测 | `--selftest`（13 条负对照） | **13 通过 / 0 失败** |
| 判据自测 | `bash tools/spoof_e2e_selftest.sh` | **14 通过 / 0 失败** |
| 全量构建 | `bash build.sh Release`（x64 + x86） | **BUILD OK，零警告** |
| 发布闸门 | `deploy_dist.sh` + `check_dist_sync.sh`（含 v74 段） | **PASS**（正 / 负对照都验） |
| 6 个源码闸门 | 含 `check_source_gbk.py` | 全 PASS |
| guard 单测 | `build_guard_ut.sh` x64 + x86 | **5 个全跑完，PASS** |
| 配置单测 | `build_ut.sh` x64 + x86 | **18 passed / 0 failed** |
| 五个 spoof 探针回归 | retdata / clipboard / reg / reg_enum / camera | 9/0、25/0、60/0、36/0、35/0/1skip —— **未回归** |
| 夹具空跑路 | `spoof_e2e.sh`（无动作）/ `--prepare` / `--collect` / `--clean` | SKIP rc=0 / SETUP OK / 诊断正确 / 清理正确 |
| **端到端三格矩阵（三面）** | `spoof_e2e.sh --run-engine` | ⚠️ **未在本机真跑**（铁律 175）—— 见下 |

> ⚠️ **必须讲清"验证到了哪一层"**：
> 上表证明的是 **"代码结构收敛" + "判据有判别力" + "构建/产物一致" + "既有能力未回归"**。
> 它**不证明**"引擎里真的会把剪贴板 / 注册表替换掉" —— 那一步要真跑引擎，
> 而本机**禁止**跑引擎（全局注入会 hook 编辑器 ⇒ 崩，铁律 175）。
> `tools/spoof_e2e_selftest.sh` 是这条约束下**唯一**能验证"判据到底会不会红"的途径；
> 它用合成 `result-*.txt` / `console-*.log` 喂给 `--collect`，先证"符合预期时 0 红"，
> 再对**每个面**做定向篡改，证"恰好红在对应断言上"。
>
> ★ 仅屏幕面的三格矩阵曾在 **2026-10-10 真跑通过（27 / 0 / 0）**（见第 2 段落地记录）；
> v74 扩面之后的三面版**尚未**在允许跑引擎的机器上跑过。**这个缺口如实标注。**

### 三、顺带修掉的三处问题（都不是本面引入）

1. **发布目录里的运行时残留日志**：`dist/R3ShieldCore-x64/` 里有
   `r3shieldcore-console.log`（8905 B）与 `r3shieldcore-events.log`（541 KB）——
   引擎跑起来会写在 **exe 同目录**，于是随 zip / 安装包**发出去**。
   后果两条：① **泄漏**开发机上的键路径 / 进程路径 / 事件；
   ② **骗人** —— 夹具 `read_console` 在"引擎还没跑"时会退到读这个文件，
   用户看到的是**上一次**的日志却以为是本次的（铁律 97）。
   ⇒ `deploy_dist.sh` 新增 **2b 步**清掉；`check_dist_sync.sh` 新增 **v74 闸门**
   验收"这两个已知名不存在"。**光有清理动作没有验收 = 死闸门。**
2. **`tools/spoof_reg_probe.cpp:327` 的 C4566**：窄字面量里有 `⇒`（U+21D2），
   CP936 编不出 ⇒ MSVC **静默丢掉那个字符**（注释里的 `⇒` 不受影响）。
   闸门 `check_source_gbk.py --all` 本来就在报它。改成 ASCII `->`。**v71 留下的**。
3. **`GetPixel` 采样没有预算**：实测本机 `GetPixel` 在屏幕 DC 上约 **17 ms/次**，
   目标程序原来两块采样合计 ~700 次 ⇒ **光这一项就 11.7 秒**（占整个 15s 的绝大部分）。
   `--prepare` / `--collect` 每次都要跑基线、自测要跑十几遍 ⇒ 6 分钟。
   ⇒ 给采样加**调用预算**（64）+ 步长按屏幕尺寸自适应 ⇒ 目标 **15s → 4.5s**、
   `--collect` **19s → 8.8s**。

### 已知边界（诚实标注）

- 三面夹具覆盖的是 **屏幕 / 剪贴板 / 注册表「值替换」**；
  **注册表「枚举隐藏」（v72）与摄像头（v73）仍无端到端**；
- 端到端**本机未真跑**（铁律 175），只有判据逻辑自测；
- 各面自身的已知盲区（屏幕 `GetPixel` / Desktop Duplication / WinRT、
  剪贴板 OLE 拖放 / 延迟渲染、注册表 KTM / hive 直读 / WOW64、
  摄像头 DirectShow / VFW / WinRT）**未因 v74 改变** —— 见各自章节。

---

## 落地记录（v75，2026-10-11）—— 注册表**事务（KTM）准入面** + 四条盲区探针结论

> 本轮范围（用户选定）：**「KTM 接生产 + 其余四个出探针结论」**。
> 即：`KTM` 真落进生产代码；`hive 直读 / DirectShow / VFW / WinRT` 只出
> **自包含探针 + go/no-go**，**不接生产**。

### 一、KTM：★★ 定性 —— 这不是"新面"，是"准入这一道门没管"

这是本轮**最重要的一句话**，它决定了改动范围：

- `NtXxxTransacted` 与对应的非事务版**签名只差一个 `TransactionHandle`**
  （Create 版还差位置：`TransactionHandle` 在 `Disposition` **之前**）。
- 值读 / 枚举 / 写三类操作在**事务句柄上复用同一个**
  `NtQueryValueKey` / `NtEnumerateKey` / `NtSetValueKey` —— 这些 API **只看句柄**，
  不区分句柄是不是事务的 ⇒ **v71 的值替换、v72 的枚举隐藏本来就在事务句柄上生效**。
- 真正缺的只有**"打开 / 创建"这一步的准入判据**：原来 `NtOpenKey` 的 detour
  **不经过**事务变体 ⇒ 用 `NtOpenKeyTransacted` 打开受保护键，
  能绕过"写不进 / 读不到 / 看不见"里的**第一道门**。一旦拿到句柄，
  后面的读 / 写 / 枚举都走已被 v71 / v72 覆盖的那几个 API。

⇒ 所以改动就是**三个"打开 / 创建"的事务变体**，判据与 `Op::CreateKey` /
`Op::OpenKey` **完全同源**，**没有新增任何决策逻辑**。

### 二、改了什么

| 位置 | 改动 |
|---|---|
| `registry_guard.cpp` 顶部 | 3 个 typedef（`NtCreateKeyTransactedPtr` / `NtOpenKeyTransactedPtr` / `NtOpenKeyTransactedExPtr`）+ 3 个 `pOriginal*` 全局 |
| 同文件 hook 区 | 3 个 detour（**与 `NtCreateKey_Hook` / `NtOpenKey_Hook` / `NtOpenKeyEx_Hook` 逐行同构**，只多 `TransactionHandle`；含 `InterlockedIncrement(&g_activeHooks)`、`__try/__except` → `ExceptionAction`、`RefineKeyPath`、`Publish`） |
| `QueueHooks` | 3 个 `QueueHook(..., **required=false**)` + 一条**宽串**挂载日志 |
| ini / ABI | **无新增 ini 键**；`AbiVersion` **不变（26）** |

#### ★★ 为什么**不给**独立开关（这是本轮第二个关键决定）

事务打开与普通打开是**同一个决策**（都是"要不要放行这次准入"）⇒
单独关掉它等于**人为开一个洞**（关掉就能绕过 v71 的读不到 / v72 的看不见）。
所以它**跟随主判据、无条件挂**。

★ 直接后果：`check_dist_sync.sh` 的 v75 段有一条**方向与 v70~v73 相反**的判据 ——
不是"ini 键存在且为**关**"，而是"ini 里**不得**出现 `spoof_reg_ktm` 键"。
这条判据如果红了，是**提醒**：要么有人把它做成了可关闭的（要重新评估），
要么只是命名撞车（那就改名）。**不能照着 v73 抄**。

#### ★ 为什么 `required=false`

这三个导出在**很老的系统**上可能没有；缺了只少一层覆盖，
**不能**让整个模块失败（与 `NtOpenKeyEx` / `NtSetInformationKey` 同一个处理）。

#### ★ 为什么需要一条新的**宽串**日志

v75 **没有新 ini 键、没有新 ABI 位** ⇒ 光看 v70~v73 那些标记，
**区分不出"这一版到底补没补这三个导出"**（改了源码没重编照样全绿）。
所以挂载时打一条日志，里面带 ASCII 子串 **`spoof_reg_ktm`** ——
`strings -el` 只输出 ASCII 可打印字符，**纯中文标记永远查不到**。

### 三、探针 `tools/spoof_reg_ktm_probe.cpp`：**42 通过 / 0 失败 / 0 跳过**

自包含（自己挂自己的 hook）、不注入、不跑引擎 ⇒ 不受铁律 175 约束。
输出见 `docs/注册表KTM事务-机制探针-2026-10-11.txt`。它把上面那两句定性
**从推理变成实测**：

| 节 | 断言 | 结果 |
|---|---|---|
| 0 | 三个事务导出**存在**、与对应非事务版是**不同的函数**、**syscall 号不同** | `NtOpenKey`=18 / `NtOpenKeyEx`=299 / `NtOpenKeyTransacted`=300 / `NtOpenKeyTransactedEx`=301 / `NtCreateKey`=29 / `NtCreateKeyTransacted`=182 |
| 0.5 | ★★ **坑位**：`RootDirectory` 吃不吃**预定义伪句柄** | 伪句柄 ⇒ `0xC0000008`；`NULL` + 绝对 NT 路径 ⇒ 成功 |
| A | 基线（负对照）：判据关着时事务路径能正常打开 | OK |
| B | ★★ **缺口成立**：关掉事务 detour ⇒ `NtOpenKeyTransacted(KEY_SET_VALUE)` **拿到受保护键句柄**；且**非事务 detour 没有被顺带触发**（hits 3→3） | OK |
| C | ★★ **修复生效**：三个事务导出对受保护键的写打开一律 `STATUS_ACCESS_DENIED`；**负对照**（不受保护的键）仍放行；三个 detour 都被调到过 | OK |
| D | ★★ **事务句柄上复用同一 API**：`NtQueryValueKey` / `NtEnumerateKey` / `NtSetValueKey` **全部走同一个 detour**；v71 值替换生效（数据区全 0）、v72 枚举隐藏生效（`HiddenChild` 被跳过：0→`Vis1`、1→`Vis2`、索引 2→`0x8000001A`）；与非事务句柄结果**逐字节相同** | OK |
| D0 | ★ **生产 v72 不会在事务句柄上静默降级**：`NtQueryKey(事务键句柄, KeyNameInformation)` **能拿到路径**（事务 91 字符 == 非事务 91 字符）⇒ `ResolveKeyPath` 照样通 | OK |
| E | 事务语义：**读己之写**（事务内写 `0x55667788`，事务内读回同值）；`RollbackTransaction` 后 `0xC0000034`（回滚干净）；对照 `CommitTransaction` 后 `0x0BADF00D` 读得到 | OK |

#### ★★ 探针踩到的新坑：`NtOpenKey` **不接受预定义伪句柄**

`NtOpenKey` / `NtOpenKeyTransacted` 把 `HKEY_CURRENT_USER` / `HKEY_LOCAL_MACHINE` /
`HKEY_USERS` 当 `RootDirectory` 传进去 ⇒ 一律 `0xC0000008 STATUS_INVALID_HANDLE`。

**为什么这个坑很难自己发现**：`RegOpenKeyExW(HKEY_CURRENT_USER, ...)` 能跑 ——
因为 **advapi32 自己把伪句柄换成了真句柄**。于是"用伪句柄当 root"这个写法在
`Reg*` 世界里天经地义，在 `Nt*` 世界里直接失败。

⇒ Nt* 这条路只能用两种形态之一：
1. `RootDirectory = 真键句柄`（`RegOpenKeyExW` 拿到）+ 相对名；
2. `RootDirectory = NULL` + **绝对 NT 路径**（`\REGISTRY\USER\<SID>\...`）。

★ 探针第一版**全部用例都报 `0xC0000008`**，就是栽在这里；
定位方式是加了一节"形态矩阵"逐组合打印状态码（铁律 97：别让失败只剩一个 FAIL）。
★ 生产 `registry_guard.cpp` **不构造** `ObjectAttributes`（只读调用方给的），
所以**不受影响**；但真实调用方（TxR / .NET `TransactionScope` / KTM 感知的程序）
会走这两种形态之一。

### 四、四条盲区探针结论（**只出结论，不接生产**）

| 盲区 | go / no-go | 关键证据 | 未做的事（诚实标注） |
|---|---|---|---|
| **hive 文件直读** | ✗ **no-go（淘汰）** | 提权（管理员 + `SeBackupPrivilege`）后活 hive 仍一律 `err=32` / `0xC0000043` ⇒ 系统**独占** | 无（已判死） |
| **DirectShow 取帧** | ★ **go（可替换）** | 帧 = `IMediaSample`，像素在 `GetPointer()`（**vtable 槽 3**）的缓冲区 ⇒ patch 槽 3 后调用方看到中性化数据；负对照证明 patch 前读到 `0xAB` | **真机建图**（需 `ISampleGrabber` + NullRenderer） |
| **VFW 帧路径** | ★ **原判要改**：借屏幕面**间接可替换** | 帧最终落在采集窗口的 DIB 里，调用方用 `GetDIBits` / `BitBlt` 读 —— 这两条**正是屏幕面已挂的 API** | **端到端**（本机 `capDriverConnect` 阻塞 ⇒ 25 秒有界等待后 `Skip`） |
| **WinRT `MediaCapture`** | ★ **go（挂点可挂）** | ① 注册表 `Windows.Media.Capture.MediaCapture` 的 `DllPath = Windows.Media.dll`；② `Windows.Media.dll` 含字符串 `MFCaptureEngine`；③ `MFCaptureEngine.dll` 导出 `MFCreateCaptureEngine` 且**实测可 `MH_CreateHook` 挂上** | **真机激活**（`InitializeAsync` 异步 + 相机权限） |

#### 逐条补充

**hive 直读（✗ 淘汰）** —— 与 §「文件内容」**同族**：走文件路径，
决定性问题只有"**活 hive 能不能被打开**"。探针 `tools/hive_read_probe.cpp`
（不挂 hook、不注入）实测：非提权下连 `GetFileAttributesW` 都 `err=5`；
**提权后 4 种组合 × 5 个目标（SYSTEM / SOFTWARE / SAM / SECURITY / NTUSER.DAT）
无一例外 `err=32` / `0xC0000043 STATUS_SHARING_VIOLATION`** ⇒ 系统独占 ⇒ 打不开
⇒ 映射 / `RegSaveKey` 都无从谈起。输出见
`docs/hive直读-可行性探针-2026-10-11.txt`。
★ 探针自身也踩过一个坑：`NtCreateFile` 的 `CreateDisposition` 与 `CreateOptions`
**传反了**，连环三次 `0xC000000D`；最终是**负对照变红**才定位到
（"判据先证明自己会失败"，铁律 110/148）。

**DirectShow（★ go）** —— 机制验证用 `CMemAllocator` 造的**真** `IMediaSample`，
**不需要摄像头**（铁律 204：默认不开硬件）。三条断言：
① patch 前读到真数据（`0xAB`）—— 负对照，否则后面"变 0"无法归因；
② patch 槽 3 后调用方读到全 0 ⇒ **帧可以在进程内中性化**；
③ detour **确实被调到**（不是"patch 了但没人走"）。
★★ **`IMediaSample` 的 vtable 是按类共享的**（探针实测两个实例 vtable 相同）⇒
与 MF 的 `IMFSourceReader` **同一个坑**：必须**按对象**记"要不要替换"（铁律 210）。
★ `ICreateDevEnum` + `CLSID_VideoInputDeviceCategory` 枚举到本机 3 个采集设备
⇒ 这条 API 面在进程内可达。

**VFW（★ 原判要改）** —— 盘点文档原表那句"**不可替换（没有我们能改的缓冲区）**"
**不成立**。VFW 的 `cap*` 全是 `SendMessage` 到采集窗口，帧最终落在窗口的 DIB 里；
调用方读帧用的是 `GetDIBits` / `BitBlt` —— **正是屏幕面已经挂了的 API**。
⇒ VFW 不是"不可替换"，而是"**借屏幕面间接可替换**"（前提：屏幕面替换开着）。
⚠️ 本机**未能实测**：`capDriverConnect` 会阻塞（不泵消息就卡死，
探针第一版在主线程裸调，跑 4 分钟无响应只能强杀）。正解 = 窗口建在**会泵消息的线程**
+ 主线程**有界等待**（铁律 117），超时如实 `Skip` 并报 `stage`。

**WinRT `MediaCapture`（★ go）** —— 路由 = `MediaCapture` → `Windows.Media.dll`
→ `MFCreateCaptureEngine`（注册表 + 字符串 + PE 导出表**三重实证**）。
挂点 = `MFCaptureEngine.dll!MFCreateCaptureEngine` + `IMFCaptureEngine` vtable。
★ **`MFCaptureEngine.dll` 是运行时加载的，不在静态导入表** ⇒
需要等它被加载（或用 `LoadLibrary` 主动拉）再挂。
⚠️ 真机 WinRT 激活（`RoGetActivationFactory` + `InitializeAsync`，异步 + 相机权限）
**未做** —— 本轮给的是"静态证据链 + 挂点可挂性"，**不是"真机替换成功"**。

### 五、验证状态（v75）

| 项 | 结果 |
|---|---|
| 双架构构建（`build.sh Release`） | **零警告 / 零错误** |
| 探针 `spoof_reg_ktm_probe` | **42 通过 / 0 失败 / 0 跳过** |
| 探针 `camera_paths_probe` | 默认 **10/0/2skip**；`--use-camera` **10/0/5skip** |
| 探针 `hive_read_probe` | 提权 / 非提权两段，25 处 `err=32` / `0xC0000043` |
| `check_dist_sync.sh` | **PASS**（v75 段 5 条判据 + **3 条负对照全红**：ini 加键 / 源码改名 / DLL 宽串抹掉） |
| 源码闸门 | `check_source_gbk` / `check_action_enum_converged` / `check_payload_manifest` / `check_spaced_name_quoted` / `check_env_switch_names` **全绿** |
| `deploy_dist.sh` | 重新部署，`dist/` 与 `Release/` 一致 |

⚠️ **诚实标注（本轮）**：
- 三个盲区（DirectShow 真机建图 / VFW 端到端 / WinRT 真机激活）**都没做**，
  探针里一律 `Skip` 并计数 ⇒ 上表是"**机制层 go**"，不是"真机替换成功"。
- 四条盲区**一条都没接生产**（本轮范围就是"只出结论"）。
- KTM 的**端到端**（真引擎 + 真事务程序）**未跑**（铁律 175），
  只有自包含探针 + 构建/闸门验证。
- 已知**未覆盖**：`NtQueryMultipleValueKey`、WOW64 重定向；
  摄像头面 VFW 真机、DirectShow 真机、WinRT 真机、内核驱动。

# R3 ShieldCore

**Windows 用户态行为拦截引擎（HIPS）** —— 把注入 DLL 挂进所有进程，hook
`ntdll` / `ws2_32` / `user32` / `advapi32` / `combase` 等**用户态出口**，
在行为真正发生之前决定 **放行 / 拒绝 / 询问**。

一个用 **C++20** 写的、**纯用户态**的安全代理：不联网、无云查杀、不收集数据，
判据全部在本地规则表里。它监控 **18 类行为对象**，提供 **5 种拦截模式**，
骨架是约 **110 处 inline hook + 2 组 COM vtable patch**，配一个纯 GDI 自绘的
五页签 GUI（概览 / 事件日志 / 进程 / 配置 / ARK）。

它的目标不是"装了就安全"，而是让用户**看见并决定**。

> ## ⚠️ 使用前必读
>
> **这是一个不成熟的项目。** 它 hook 的是未文档化的 `Nt*` 接口，依赖大量未公开
> ABI 细节，换个 Windows 版本就可能出问题。
>
> **它很容易被绕过。** 用户态 hook 有**固有能力上限** —— 直 syscall、手工映射
> DLL、复制令牌都能绕过它（仓库里附带的 `dskill.exe` 就是这条结论的实证工具）。
> 本项目的定位是**可见性与知情权**，不是一道墙。
>
> **请不要把本项目作为你电脑上唯一的终端防护软件。** 它与真正的杀毒软件 / EDR
> 不是同一类东西，也替代不了它们。
>
> **它可能产生很多误报。** 判据基于行为特征而非文件信誉，正常软件用到的
> 摄像头 / 麦克风 / 输入钩子 / 截屏 / 自动化脚本都可能被拦下 —— 这是设计取舍的
> 一部分，还请见谅。
>
> **仅用于学习、研究与自用防护。** 请勿用于生产环境或任何要求稳定性的场合。
> 详见 [已知边界](#10-已知边界) 与 [`SECURITY.md`](SECURITY.md)。

---

## 1. 这是什么

一个用 C++20 写的 Windows 用户态安全代理，由**三层**组成，各层职责刻意分得很开：

```
┌──────────────────────────────────────────────────────────────────────────┐
│ ① 内核驱动  r3shieldcore_kernel.sys          BOOT_START（可选）          │
│    只做两件事：证明"我真的在开机时加载了" + 提供一次状态查询。           │
│    ★ 不做任何拦截 —— 没有 ObRegisterCallbacks、没有进程回调、            │
│      没有注册表回调、没有 minifilter。它拦不住也不打算拦任何东西。       │
├──────────────────────────────────────────────────────────────────────────┤
│ ② 守候服务  r3shieldcore_svc.exe       LocalSystem / AUTO_START          │
│    把引擎拉进"有交互用户的会话"（同一会话只拉一次）；                    │
│    30 秒兜底 tick 重拉；安全模式下**不**拉引擎。                         │
├──────────────────────────────────────────────────────────────────────────┤
│ ③ 引擎      R3 ShieldCore.exe          用户会话 / requireAdministrator   │
│    ├─ 注入器：反射 shellcode + APC/远程线程，32 位与 64 位 DLL 各一份    │
│    ├─ Hook 层：17 个 guard 模块，约 110 处 MinHook inline hook，         │
│    │           外加 2 组 COM vtable patch                                │
│    ├─ 规则层：编译期定长规则表（`r3shieldcore_rules.cpp`，4400 行）      │
│    └─ GUI：概览 / 事件日志 / 进程 / 配置 / ARK —— 五个页签，全 GDI 自绘  │
└──────────────────────────────────────────────────────────────────────────┘
```

**为什么驱动不拦截？** 因为内核里做拦截意味着**每一条内核路径都是开机风险**
（蓝屏、死锁、与其它安全软件打架），而本项目的目标不是拿到最高权限，
而是让用户**看见并决定**。驱动留着是为了拿到"最早加载"这个位置，
以及给用户态一个可核对的加载证据（见 `driver/README.md`）。

## 2. 监控面：18 类对象 / 17 个 guard

`ObjectType` 枚举共 18 项（`r3shieldcore_shared.h:214`），由 17 个 guard 模块产出
—— 多出来的那一类是 **`Thread`**，由 `ProcessGuard` 一并处理（远程线程是注入的核心手法）。

| # | 对象类 | guard 模块 | 挂的主要 API |
|---|---|---|---|
| 0 | 注册表 | `registry_guard.cpp` | `NtCreateKey` `NtOpenKey(Ex)` `NtSetValueKey` `NtDeleteKey` `NtDeleteValueKey` `NtRenameKey` `NtSetInformationKey` `NtFlushKey` + hive 级 `NtLoadKey(Ex)` `NtUnloadKey(Ex)` `NtSaveKey(Ex)` `NtRestoreKey` `NtReplaceKey`（20 处） |
| 1 | 文件 | `file_guard.cpp` | `NtCreateFile` `NtWriteFile` `NtSetInformationFile` `NtOpenFile` `NtSetSecurityObject` `NtSetEaFile` |
| 2 | 进程 | `process_guard.cpp` | `NtOpenProcess` `NtCreateUserProcess` `NtCreateProcess(Ex)` `NtTerminateProcess` |
| 3 | 线程 | `process_guard.cpp` | `NtCreateThreadEx` `NtCreateThread` `NtTerminateThread` |
| 4 | 驱动 | `driver_guard.cpp` | `NtLoadDriver` `NtUnloadDriver` `CreateServiceW` `ChangeServiceConfigW` `StartServiceW` |
| 5 | 网络 | `network_guard.cpp` | `connect` `WSAConnect` `sendto` `WSASendTo` `NtDeviceIoControlFile` `gethostbyname` `getaddrinfo` `bind` `listen` `accept` `WSAAccept` |
| 6 | 摄像头/麦克风 | `camera_guard.cpp` | `capCreateCaptureWindowW/A` `MFCreateDeviceSource(Activate)` `MFEnumDeviceSources` `MFCreateSourceReaderFromMediaSource` `waveInOpen` `mciSendCommandW` + WASAPI `IAudioClient::Initialize`（COM vtable patch） |
| 7 | 输入钩子 | `input_hook_guard.cpp` | `SetWindowsHookExW/A` `UnhookWindowsHookEx` `RegisterRawInputDevices` `GetAsyncKeyState` `GetKeyState` `GetKeyboardState` `SetWinEventHook` `SendInput` `keybd_event` `mouse_event` `BlockInput` `ClipCursor` |
| 8 | 屏幕捕获 | `screen_guard.cpp` | `BitBlt` `StretchBlt` `GetDIBits` `PrintWindow` |
| 9 | DLL 加载 | `dll_load_guard.cpp` | `LdrLoadDll` `NtCreateSection` `NtMapViewOfSection` |
| 10 | 剪贴板 | `clipboard_guard.cpp` | `OpenClipboard` `GetClipboardData` |
| 11 | 进程创建旁路 | `spawn_guard.cpp` | `WinExec` `ShellExecuteExW/A` `CreateProcessWithTokenW` `CreateProcessWithLogonW` `CreateProcessAsUserW` |
| 12 | 服务安全描述符 | `service_config_guard.cpp` | `SetServiceObjectSecurity` `SetSecurityInfo` `SetNamedSecurityInfoW` `NtSetSecurityObject` |
| 13 | COM 激活劫持 | `com_hijack_guard.cpp` | `CoCreateInstance(Ex)` `CoGetClassObject`（combase + ole32 各一套） |
| 14 | 计划任务 | `scheduled_task_guard.cpp` | `ITaskService::GetFolder`、`ITaskFolder::RegisterTaskDefinition`（vtable patch） |
| 15 | 令牌窃取 | `token_theft_guard.cpp` | `OpenProcessToken` `OpenThreadToken` `DuplicateTokenEx` `ImpersonateLoggedOnUser` `SetThreadToken` `AdjustTokenPrivileges` |
| 16 | WMI 事件订阅 | `wmi_subscription_guard.cpp` | `IWbemLocator::ConnectServer`、`IWbemServices::PutInstance/ExecMethod/ExecNotificationQuery`（vtable patch） |
| 17 | 宿主劫持 | `host_hijack_guard.cpp` | `LoadLibraryExW` `LdrRegisterDllNotification` `NtQueueApcThread` `QueueUserAPC` |

> **6/7/8 三类**（摄像头、输入钩子、截屏）的共同点是：本身不破坏数据、不装东西，
> 但都是**窃听** —— 木马与间谍软件的标配三件套，同时也是正常软件会用到的东西。
> 所以对它们的判据不是"危险"，而是"**需要用户知情**"。

## 3. 拦截模式（`mode=`，5 种）

| 值 | ini 写法 | 行为 |
|---|---|---|
| 0 | `log` | 只记录，**全部放行**（不弹窗） |
| 1 | `block` | 命中高危规则 → **硬拒**；其余记录后放行 |
| 2 | `ask` | 命中高危规则 → **弹窗询问**，用户说了算 |
| 3 | `block_all` | 完全拦截：探测范围内一律拒 —— 不看豁免、不看高危、不询问 |
| 4 | `block_all_safe` | 同 `block_all`，但**放行「可信来源」的进程创建** |

### ⚠️ 三条容易搞错的语义（都是代码里的显式决定，不是实现疏漏）

1. **只有 `ask` 模式会弹窗。**
   `ModeAllowsAsk()` 只在 `mode == Ask` 时返回真（`process_guard.cpp:372`）。
   全拦模式下，进程创建 / 远程线程 / 跨进程内存这三类**一律直接拒**，
   **不弹窗、不问用户、也不看 `prompt_default`** —— 否则"全拦"能被一行配置放水。

2. **`block_all_safe` 的豁免只给「进程创建」。**
   远程线程与跨进程内存**不享受豁免**（`process_guard.cpp:605`、`:715`）。
   放行进程创建是为了让正常程序能起来；放行远程线程等于放行整条注入链。

3. **`inject_policy` 不是"询问/硬拒"的依据。**
   它是**注入分级**（Full / Thin / Skip），决定"这个进程要不要装 guard"。
   容易和"拦截策略"混淆，特此说明。

> `prompt_default` 只在 `ask` 模式下作为**超时兜底**生效，默认 `deny`。

## 4. 询问是怎么跨进程完成的

注入 DLL 跑在**别人的进程里**，而弹窗要画在引擎进程里。这条通道**不是**命名管道、
也不是窗口消息，而是 **命名共享内存 + 命名事件**：

| 环节 | 实现 |
|---|---|
| 共享内存 | `Global\R3ShieldCore-Prompt-pid=<引擎pid>`（`r3shieldcore_prompt.cpp:252`），布局 `PromptHeader` + `PromptSlot[8]` |
| 请求通知 | 命名事件 `R3ShieldCore-PromptReq-pid=N` |
| 每槽应答 | 命名事件 `R3ShieldCore-PromptSlot-...` |
| 并发 | 8 个槽，DLL 侧 CAS 抢槽 |
| 超时 | 默认 **30000 ms**（`prompt_timeout`，可 1..600 s）；按 250 ms 切片等待，以便及时响应 shutdown |
| 超时结论 | `prompt_default`，默认 **deny** |
| UI 线程 | 跑在**引擎进程内**（`R3ShieldCorePromptUi`），扫 Pending 槽 → 弹自绘 toast → 回填应答 |
| 通道不可用时 | `AskWithChannelGuard`：**只有 `log` 模式降级放行**，其余模式保持拒 |

## 5. 注入是怎么做的

- **投递原语**：DLL 路径 + 一段**位置无关的反射 shellcode**（靠 PEB 遍历 + 哈希
  自找 `LoadLibraryW` / `GetProcAddress`），写到目标进程后经两条路触发：
  - `NtQueueApcThread`（首选，尤其对"刚创建还没跑起来"的进程）
  - `NtCreateThreadEx`（Vista/7 起；否则回退 `CreateRemoteThread`）
- **新进程"创建时即注入"**（同步路，盲区≈0）：
  在**父进程**里 inline hook `CreateProcessInternalW`，强制加上 `CREATE_SUSPENDED`，
  建完进程后用 APC 注入**刚创建的挂起主线程**。
  注入失败就 `TerminateProcess` 杀掉子进程 —— 宁可杀错，不留盲区。
- **兜底轮询路**：`NtGetNextProcess` 枚举全机进程；若某进程只有一个线程且
  IP 停在 `RtlUserThreadStart`（判定"还没开始跑"）→ 走 APC，否则走远程线程。
- **32/64 位**：`64/` 与 `32/` 两个目录各放一份 DLL，按目标进程位数选；
  32 位侧依赖 `wow64ext` 做跨架构调用。

> **注入器自己也是被 hook 的对象**：守卫自身的注入由 hook 层的 `IsInjectingInto`
> 提前放行，否则同步注入路会把自己掐死。

## 6. 构建

### 6.1 依赖

| 依赖 | 用途 |
|---|---|
| **Visual Studio 2022+**（C++ 桌面工作负载） | `cl.exe` / `link.exe` |
| **Windows SDK 10** | 头文件、库、`rc.exe` |
| **WDK** | 仅构建内核驱动时需要（`km/` 头与库） |
| **Python 3**（纯标准库） | 生成图标、打包、字符集闸门 |
| **MSYS2 ucrt64** | 仅构建安装包时需要（`gcc` / `windres`） |
| **Git Bash / MSYS2** | 运行 `.sh` 脚本 |

路径全部**自动探测**（`scripts_env.sh`：vswhere 或扫常见路径 → MSVC、SDK 根与版本、
Python、MSYS2 gcc、`rc.exe`）。可用环境变量覆盖：
`MSVC_ROOT` `SDK_ROOT` `SDK_VERSION` `PYTHON` `GCC` `R3SC_PROJECT_ROOT`；
`R3SC_QUIET=1` 关掉探测摘要。

### 6.2 构建引擎

```bash
bash build.sh              # Release，x86 + x64
bash build.sh Debug        # Debug
bash build.sh Release x64  # 只编 x64
```

产物落在 `R3ShieldCore/Release/`：

```
R3 ShieldCore.exe            x64 引擎（requireAdministrator）
R3 ShieldCore-x86.exe        x86 引擎   ← 文件名带空格，引用时务必加引号
r3shieldcore_svc.exe         守候服务（只编 x64）
64/r3shieldcore-lib.dll      64 位注入 DLL
32/r3shieldcore-lib.dll      32 位注入 DLL
```

> 为什么直接调 `cl.exe` 而不用 MSBuild？本机 `devenv.com` 只会把 IDE 拉起来、
> 不执行命令行构建；`MSBuild.exe` 被安全策略按名字拦截。脚本用的是同一套编译器、
> 同样的参数，产物与 IDE 构建等价。详见 `build.sh` 顶部注释。

### 6.3 装配发布目录（打包前**必须先做**）

```bash
bash deploy_dist.sh        # -> dist/R3ShieldCore-x64/
bash deploy_dist.sh --check  # 只验收，不重新装配
```

`build.sh` 只写 `R3ShieldCore/Release/`，**不碰 `dist/`**。`deploy_dist.sh` 负责：

1. 校验 `Release/` 里 4 个引擎产物都在（缺了就明说"先跑 `build.sh`"）；
2. 编 `tools/dskill.cpp` → `dist/R3ShieldCore-x64/dskill.exe`（直 syscall 逃生门工具）；
3. 按约定布局拷贝 —— **exe 放根，DLL 必须进 `64/` 与 `32/`**
   （注入器按目录名选架构，放错位置等于 32 位进程完全没有防护）；
4. 调 `check_dist_sync.sh` 验收。

`check_dist_sync.sh` 的判据是**内容相等（md5）**，不是"文件存在"；另外还查
`32/r3shieldcore-lib.dll` 存在、两侧 DLL 都含 `WTSQueryUserToken` 与
`GlobalHookSessionSelfExit` 两个特性标记、以及 v66 代次标记（exe 含宽串
`R3 Shield Core`，DLL 含 `System32\consent.exe` 等整行）。

> 这一步以前是**手工 `cp`**，代价是出过一次真实事故：x86 DLL 停在旧代次构建，
> 发布包"文件都在、大小也对、闸门也全绿"，而 32 位进程一条事件都没有。
> 详见 `check_dist_sync.sh` 顶部注释。

### 6.4 构建内核驱动（可选）

```bash
bash driver/build_driver.sh          # -> driver/build/r3shieldcore_kernel.sys
bash driver/build_driver.sh Debug
```

驱动用**单独探测的 WDK 版本**（挑存在 `Include/*/km` 的那个，可 `WDK_SDK_VERSION` 覆盖），
`-SUBSYSTEM:NATIVE -ENTRY:DriverEntry -NODEFAULTLIB`。

> ⚠️ 64 位 Windows 要求内核驱动**有签名**才能加载。开发自测可以开测试签名模式，
> 正式发布需要 EV 证书 + 微软 attestation 签名。
> **实测（本机）**：自签驱动在 Secure Boot 关闭的机器上确实能加载，但那是
> 「有签名」+「本机 CI 处于审计模式」两个条件同时成立的结果，**换强制模式的机器会被拒**。
> 完整实测矩阵与结论见 [`driver/README.md`](driver/README.md) 第 1.2.1 节。

**「可选」的确切含义**：不编驱动也能跑完整条发布流程。差别只在安装包里：

| | 编了驱动 | 没编驱动 |
|---|---|---|
| 安装包 | **完整包** | **仅用户态包** |
| 装驱动那步 | 正常执行 | 自动跳过（引擎照常工作，只是没有"开机优先加载"） |
| 构建时 | 无提示 | 打印醒目警告 + 结论行写「**未包含**」 |
| `selftest_setup.py` | 驱动断言全跑 | 驱动断言标 `[SKIP]` 并**计数** |

驱动是构建产物，**不进版本库**（`.gitignore` 的 `build/` 规则），所以
`git clone` 下来默认就是「仅用户态包」。
★ **官方发布必须用完整包**：加 `--require-driver`，让驱动缺席变成硬失败。

### 6.5 构建安装包（单文件原生 GUI 安装器）

```bash
bash installer/build_setup.sh                    # -> dist/R3ShieldCore-Setup.exe
bash installer/build_setup.sh --require-driver   # 官方发布：驱动缺席即失败
bash installer/build_setup.sh --no-copy          # 只编不拷
```

需要 MSYS2 `ucrt64` 的 `gcc` + `windres`。payload 以 **zlib 压缩后作为 RCDATA**
内嵌（资源 ID：`1`=manifest，`2`=uninstall.bat，`1000+`=payload 文件）。
构建结尾打印 `内核驱动 : 已包含 / **未包含**` —— 这是两种产物之间**唯一**的实质差异，
所以它必须出现在结论里，而不是只躺在滚屏警告里。

安装器是原生 Win32 GUI，支持这些开关（`r3sc_setup.c:2452`）：

| 开关 | 作用 |
|---|---|
| `--verify` | 只校验内嵌资源完整性 |
| `--extract=<dir>` | 只解包，不安装 |
| `/S` `--silent` | 静默安装 |
| `/DEST=` `--dest=` | 指定安装目录（默认 `%ProgramFiles%\R3 Shield Core`） |
| `--drv-start=boot\|auto` | 驱动启动类型；不指定则跟随界面勾选（默认勾选 = `boot` 开机优先） |
| `--no-autostart` / `--autostart` | 是否注册开机自启服务 |
| `--report=` `--uicheck=` | 自测用的报告/界面探测 |

> `installer/build_installer.sh` 是**老路**（iexpress 自解压），仅作兼容保留，
> 产物固定叫 `dist/R3ShieldCore-Setup-iexpress.exe`，不会覆盖正式产物。

### 6.6 打包绿色版

```bash
bash build_dist_zip.sh     # -> dist/R3ShieldCore-x64.zip
```

打包前跑 `check_dist_sync.sh` 与 `fix_bat_encoding.sh verify` 两道闸门，
用 Python 固定时间戳做可复现打包并打印 sha256。

## 7. 目录结构

```
.
├── R3ShieldCore/
│   ├── R3ShieldCore/        引擎主程序（GUI / 配置 / 统计 / ARK / 覆盖层反制）
│   ├── R3ShieldCoreLib/     注入 DLL（17 个 guard + hook 层 + 注入器）
│   │   ├── inject-shellcode/  位置无关反射加载器
│   │   └── libraries/         MinHook、wow64ext
│   ├── shared/
│   │   ├── r3shieldcore/    跨进程 ABI（共享内存布局、事件、枚举）
│   │   └── libraries/wil/   WIL 头（vendored）
│   └── tests/               单元测试源码
├── service/                 守候服务（纯 C，1471 行）
├── driver/                  内核驱动 + 签名/安装脚本（见 driver/README.md）
├── installer/               安装器（原生 Win32 GUI，单文件）+ 自测
├── tools/                   探针 / 单测 / 诊断器 / 闸门脚本
├── docs/                    技术文档（CODE-REVIEW.md、窗口 Hook 预研）
├── demo/                    GUI 截图
├── dist/                    发布产物（构建生成；随包文档入库，见 .gitignore）
├── build.sh                 引擎构建入口
├── scripts_env.sh           ★ 工具链自动探测（所有脚本共用）
├── deploy_dist.sh           装配发布目录
├── README.md                本文档
├── LICENSE                  GPL-3.0 全文
├── THIRD-PARTY-NOTICES.md   ★ 第三方组件的许可原文（二进制分发必读）
├── SECURITY.md              安全模型边界 + 漏洞上报方式
├── CONTRIBUTING.md          贡献指南（构建前置 / 闸门要求 / 提交规范）
├── CHANGELOG.md             版本变更记录
└── .github/                 issue / PR 模板 + CI（跑 tools/ 下的闸门脚本）
```

## 8. 配置

### 8.1 配置文件在哪

```
%ProgramData%\R3 Shield Core\r3shieldcore.ini     ← 存在就用它（安装器装的）
<exe 同目录>\r3shieldcore.ini                     ← 否则回退到这里（绿色包）
```

判据是"**那个文件**在不在"，不是"目录在不在"（只看目录会让一个空目录把配置
整个顶掉、静默退回全默认值）。两处同时存在时**以 ProgramData 为准**，
而且引擎写回 `mode` 用的是同一个函数 ⇒ 读写永远是同一个文件。

安装器会创建 `%ProgramData%\R3 Shield Core` 并**只对该目录**授予
`Users:(OI)(CI)M`（SID `*S-1-5-32-545`），随包的 ini 铺过去但**已存在则不覆盖**。
所以装完之后，**普通用户可以直接编辑这份 ini**。

### 8.2 预设

仓库/发布目录自带 5 个预设，按用途选：

| 文件 | `mode` | 用途 |
|---|---|---|
| `r3shieldcore.ini` | `block` | **默认**：只拦高置信度高危行为，其余放行 |
| `r3shieldcore-safe-first.ini` | `log` | 先观察：只记录、全放行、不弹窗 |
| `r3shieldcore-block.ini` | `block` | 主动防御 |
| `r3shieldcore-blockall.ini` | `block_all` | 完全拦截 |
| `r3shieldcore-blockallsafe.ini` | `block_all_safe` | 全拦，但放行可信来源的进程创建 |

### 8.3 主要配置键

**总控 / 询问**

| 键 | 默认 | 含义 |
|---|---|---|
| `mode` | `log`（代码默认；随包 ini 设 `block`） | `log` / `block` / `ask` / `block_all` / `block_all_safe` |
| `prompt_timeout` | `30` | 询问超时（秒），1..600 |
| `prompt_default` | `deny` | 超时结论：`allow` / `deny`（仅 `ask` 模式生效） |
| `high_risk` | `on` | 高危规则总开关 |
| `self_protect` | `on` | 自我保护（剥权限），**不受 `mode` 影响** |

**各监控面的开关**（均为 `on`/`off`，默认 `on` 除注明外）

`hook_process` 进程创建/终止 · `hook_thread` 远程线程 · `hook_driver` 驱动加载 ·
`hook_net` 出站连接 · `hook_dns` 域名解析 · `hook_camera` 摄像头/麦克风 ·
`hook_input` 键鼠钩子 · `hook_screen` 截屏 · `hook_dll_load` DLL 加载 ·
`hook_clipboard` 剪贴板 · `hook_spawn` 进程创建旁路 · `hook_service_config` 服务权限 ·
`hook_com_hijack` COM 劫持 · `hook_scheduled_task` 计划任务 · `hook_audio` 音频采集 ·
`hook_token_theft` 令牌窃取 · `hook_wmi_subscription` WMI 订阅 · `hook_host_hijack` 宿主劫持 ·
`hook_memory_op` 跨进程内存/注入链 · `hook_input_inject` 合成输入 · `hook_terminate_contain` 终止收敛 ·
`hook_raw_disk` 裸盘写 · `inject_shell_thin` 瘦注入

默认 **`off`** 的几个（噪音或影响面大，需要时再开）：
`hook_file` 文件建/写/删/改名/ACL · `hook_reads` 连读操作也记录 ·
`hook_net_all` 连 `bind`/`listen`/`accept` 也监控 · `hook_self_thread` 含本进程线程 ·
`log_all_open` `NtOpenKey` 读写都记

**名单类**（可重复出现，按行累加）

`protect_process` 进程保护前缀 · `protect_file` 文件保护 · `protect_reg` 注册表保护 ·
`protect_net` 网络保护目标 · `protect_driver` 驱动保护 ·
`exclude` 文件操作白名单 · `never_inject` 绝不注入的进程

**其它**

`log` 事件日志路径（默认 `r3shieldcore-events.log`）·
`hook_hive` / `hook_set_info` hive 级操作与 `NtSetInformationKey`

**引擎侧（`LoadEngineSettings`）**

| 键 | 默认 | 含义 |
|---|---|---|
| `inject_interval_ms` | `10` | 注入轮询间隔，1..1000 |
| `neutralize_overlay` | `2` | 覆盖层反制级别 0/1/2 |
| `replay_history_log` | `1` | 启动时回放历史日志填界面 |
| `replay_history_limit` | `200` | 回放条数，1..5000 |
| `persist_stats` | `1` | 统计落盘到 `r3shieldcore-stats.json` |
| `high_risk_process_alert` | `2` | 高危进程提示级别 0/1/2 |
| `high_risk_process_scan_ms` | `1000` | 高危进程扫描间隔，200..60000 |
| `ark_enabled` | `1` | ARK 页开关 |
| `ark_scan_ms` | `2000` | ARK 扫描间隔，500..60000 |
| `ark_refresh_ms` | `1000` | ARK 界面刷新，200..60000 |

> 逐项详解见发布目录里的 `配置详解.md`（由 `tools/_gen_config_doc.py` 生成）。

## 9. 自测与探针

```bash
bash build_ut.sh             # 规则层单元测试（秒级）
bash build_guard_ut.sh       # guard 层单元测试（链 MinHook）
python installer/selftest_setup.py --no-gui --no-install   # 安装程序自测（★ 推荐）
```

> ⚠️ **安装程序自测的第 4 层会真的启动引擎。** 引擎的全局注入会 hook 本机
> **所有**进程（包括编辑器 / IDE）。所以第 4 层必须**显式**加 `--run-engine`
> 才会跑；不加时它报 `[SKIP]` 并计入结论行，**不会静默跳过**。
> **要跑第 4 层，请在虚拟机或另一台机器上跑。**
>
> 平时只需 `--no-gui --no-install`：第 1-2 层**只读**，验证内嵌资源完整性
> 并逐字节比对解出来的 payload。

`tools/` 下有 60+ 个**只读探针**（`*probe*`）与 30+ 个单元测试，用于验证 hook 是否
真的挂上、规则是否真的命中 —— 它们本身就是本项目"用实验代替猜测"工作方式的产物。
> ⚠️ 但 `tools/` 里的 `test_*.sh` / `acceptance_test.sh` / `accept_file_modes.sh` /
> `verify_log_mode.sh` 属于**验收脚本**，它们会启动引擎 —— 同样请在隔离环境跑。

## 10. 已知边界

- **用户态 hook 的固有上限**：直 syscall（自带 syscall 号，绕过 ntdll 导出）、
  手工映射 DLL、复制令牌 —— 都能绕过。`dskill.exe` 就是这条结论的实证工具，
  同时也是引擎自我保护生效后留给开发者的**逃生门**。
- **拦截第四道门是时间**：进程启动到注入完成之间有盲区。同步注入路已经把这个
  窗口压到≈0，但并非绝对。
- **只做用户态**：不拦内核态发起的操作；驱动层只负责开机加载与自证，不做拦截。
- **`requireAdministrator`**：引擎必须以管理员运行，否则大面积失效。
- **没有单实例互斥体**：不要同时跑两份引擎（两套 hook 会打架）。
  单实例靠 UIAccess 接管 + `--uiaccess-parent-pid=` 等待父引擎退出。
- **UI 是纯 GDI 自绘**（无原生控件、无托盘图标）：主题/DPI 适配靠手写，
  极端 DPI 组合下可能有布局问题。

## 11. 免责声明

本项目按 "AS IS" 提供，**不附带任何明示或暗示的担保**。它是一个
**教育 / 研究性质**的安全工具，作者不对因使用本软件造成的任何直接或间接损失
（包括但不限于系统损坏、数据丢失、业务中断）承担责任。

- 请在你**拥有或已获授权**的系统上使用。
- 本项目**不成熟**，且**能被轻易绕过**；**请勿将其作为你电脑上唯一的终端防护手段**，
  它不能替代杀毒软件 / EDR。
- 判据基于行为特征而非文件信誉，**误报较多**（见上）。
- 本项目**不**收集、上传任何用户数据。
- 二次分发请遵守 [GPL-3.0](LICENSE)。

## 12. 许可

[GNU General Public License v3.0](LICENSE)。
Copyright (C) 2026 yunsjxh。

本项目的注入/hook 框架派生自
[m417z/global-inject-demo](https://github.com/m417z/global-inject-demo)
（GPL-3.0，见 `R3ShieldCore/README.md`），遵循其原始许可。

`R3ShieldCore/R3ShieldCoreLib/inject-shellcode/` 又派生自
[stephenfewer/ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection)
（BSD 3-Clause，© 2012 Stephen Fewer / Harmony Security）。

其余第三方组件：

| 组件 | 许可 | 版权 | 位置 |
|---|---|---|---|
| MinHook | BSD 2-Clause | © 2009-2017 Tsuda Kageyu | `R3ShieldCore/R3ShieldCoreLib/libraries/MinHook/` |
| wow64ext | GNU LGPL-3.0 | © 2014 ReWolf | `R3ShieldCore/R3ShieldCoreLib/libraries/wow64ext/` |
| WIL（Windows Implementation Library） | MIT | © Microsoft | `R3ShieldCore/shared/libraries/wil/` |

各组件的**完整许可原文**、以及与二进制分发相关的义务说明，见
[`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md)。

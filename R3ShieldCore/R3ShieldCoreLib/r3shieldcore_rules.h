#pragma once

//
// 高危操作规则表。
//
// 为什么要单独一层：R3ShieldCore 原本只有"按 Mode 一刀切"——log 全放行、
// block 全拒绝、ask 全弹窗。但用户真正想防的是少数几个要害动作：
// 写自启动、改服务、映像劫持、动 hosts、往 System32 里放可执行文件……
// 这些操作无论当前是什么 Mode，都应该让用户过目。
//
// 所以规则层和模式层是正交的：
//   RiskLevel::High → 强制走询问路径（Ask），用户点了才放行
//   RiskLevel::Normal → 完全按 Mode 走（原行为不变）
//
// 判定来源有两种：内置规则表（下面）+ ini 的 protect_reg / protect_file 前缀。
//
#include <r3shieldcore/r3shieldcore_shared.h>

namespace R3ShieldCoreRules
{
	// 注册表高危判定。keyPath 形如 \REGISTRY\MACHINE\SOFTWARE\...。
	// 返回 true 表示"这是高危操作，必须询问用户"。
	bool IsHighRiskRegistry(PCWSTR keyPath, PCWSTR valueName, ULONG op) noexcept;

	// 文件高危判定。path 是归一化后的 DOS 路径（C:\...）。
	bool IsHighRiskFile(PCWSTR path, ULONG fileOp) noexcept;

	//
	// v39：裸盘 / 物理盘设备判定 —— 写 MBR / 引导扇区（bootkit）。
	//
	// 背景（真实绕过）：样本只用 `CreateFileA("\\.\PhysicalDrive0", ...)`
	//   + `WriteFile` 就改掉了引导区，block 模式没拦住。原因有二：
	//     ① 该路径根本不是"卷上的文件"，被 `IsNonFileObject` 当成
	//        管道/套接字一类的设备直接放行；
	//     ② 高危文件规则表里没有这一条。
	//   两者叠加 ⇒ 引导区写入在**任何**模式下都不产生事件。
	//
	// 本函数只判"这是不是一个裸盘/物理盘设备"，不判 op ——
	//   调用方（`FileRiskReason`）把它放在 `IsHighRiskFileOp` 门槛**之前**，
	//   这样 `NtOpenFile`（op=Open，不在高危 op 表里）也覆盖得到。
	//
	// ⚠️ 认得的形态（大小写不敏感，`\??\` / `\DosDevices\` 前缀会被跳过）：
	//     · `PhysicalDriveN`            —— Win32 `\\.\PhysicalDriveN` 归一化后的样子
	//     · `\Device\HarddiskN\DRN`     —— 对象管理器解析后的真名
	//     · `\Device\HarddiskN\PartitionN` —— 分区设备（N=0 即整盘）
	//
	// ⚠️ **必须不误伤** `\Device\HarddiskVolumeN`（正常卷，文件都挂在它下面）——
	//    `Harddisk` 后面要求跟**数字**，而 `Volume` 以 `V` 开头，天然区分开。
	//    `tools/file_rules_ut.cpp` 有专门的反例。
	//
	bool IsRawDiskDevicePath(PCWSTR path) noexcept;

	// 进程创建高危判定。imagePath 是归一化后的 DOS 路径（C:\...）。
	// parentPid 是发起这次创建的进程 pid（拿得到时）。
	bool IsHighRiskProcessImage(PCWSTR imagePath, ULONG processOp, ULONG parentPid) noexcept;

	// 可疑的父子进程关系（Office → cmd/powershell、svchost → powershell…）。
	// 需要父进程镜像路径，所以要单独调（查父进程比纯路径匹配贵）。
	// 返回规则说明，没命中返回 nullptr。
	const char* ProcessPairRiskReason(PCWSTR parentPath, PCWSTR childPath) noexcept;

	//
	// ★ v61 高危进程「存在」判定 —— 与上面的"进程创建"判据是两回事。
	//
	// 分工：
	//   `IsHighRiskProcessImage` 判"**这一次创建**该不该拦"。它的数据来自
	//     被注入进程里的 hook ⇒ **只看得见被监控进程发起、且落在引擎观测窗内**
	//     的创建。v60b 复盘暴露的正是这个盲区（病毒写症状键全日志 0 命中）。
	//   本组判据判"**这个进程本身是不是高危**"。引擎定期快照**全机**进程
	//     逐个过这里 ⇒ **不依赖注入覆盖、也不依赖观测窗**（引擎启动前就在
	//     跑的进程一样能看见）。
	//
	// 判据（只有这几条算高危，"度"是刻意收窄的 —— 理由见 .cpp 的大段说明）：
	//   ① 系统进程名伪装：文件名 == 受保护系统组件名，但路径不在其规范目录
	//      （规范目录 = System32 家族 **或** 该名字自己的额外目录：
	//       `explorer.exe` 在 `%SystemRoot%\`、UWP 宿主在 `%SystemRoot%\SystemApps\`）
	//   ② 形近伪装：剥离空白 + 视觉字符归一化 + 相邻字符交换后 == 系统组件名，
	//      但原串不等（`lsass .exe` / `svch0st.exe` / `scvhost.exe`）
	//   ③ 已知攻击工具：文件名（去扩展名）在攻击工具名单里
	//   ④ 命中 `protect_process=`（复用"自我保护"那份名单，与位置无关）
	//
	// imagePath 是完整 DOS 路径（`C:\...`）；systemRoot 形如 `C:\Windows`
	// （**不带**尾反斜杠），由调用方自己解析 —— 传空串时返回 nullptr
	// （判不出"在不在系统目录"就不猜，避免把真正的 svchost.exe 报成伪装）。
	//
	// 返回规则说明（静态字符串，生命周期同 DLL），没命中返回 nullptr。
	const char* HighRiskProcessReasonForRoot(PCWSTR imagePath, PCWSTR systemRoot) noexcept;

	// 同上，systemRoot 取本机真实值（`GetWindowsDirectoryW`）。
	const char* HighRiskProcessReason(PCWSTR imagePath) noexcept;

	bool IsHighRiskProcess(PCWSTR imagePath) noexcept;

	// 形近比对用的文件名归一化（小写 + 去空白 + 折叠视觉替换字符）。
	// 单独导出是为了让测试与诊断工具能复用同一份实现。
	void NormalizeImageNameForCompare(PCWSTR fileName, WCHAR* out, size_t cch) noexcept;

	//
	// 高危进程判据用的表 —— **只为测试穷举验证而暴露**。
	//
	// `tools/high_risk_process_ut.cpp` 要穷举"系统组件名的每一个相邻交换
	// 变体"，并断言它**要么被检出、要么在豁免表里**。测试不能自带一份
	// 拷贝（那会变成两份真相），所以这里开只读访问器。
	//
	// ⚠️ 正常代码不要用它们 —— 判据请走 `HighRiskProcessReason*`。
	//
	PCWSTR SystemCriticalImageAt(ULONG index) noexcept;
	ULONG SystemCriticalImageCount() noexcept;
	PCWSTR MasqueradeExemptAt(ULONG index) noexcept;
	ULONG MasqueradeExemptCount() noexcept;
	PCWSTR AttackToolNameAt(ULONG index) noexcept;
	ULONG AttackToolNameCount() noexcept;

	//
	// ★ v61 修：「额外规范目录」表（`explorer.exe` 在 `%SystemRoot%\`、
	// UWP 宿主在 `%SystemRoot%\SystemApps\<包名>\`）。
	//
	// 测试**穷举**每一条 `(名字, 目录, 深度)`：
	//   `<systemRoot><目录>` 后面**正好** `深度` 层目录 + 该名字 ⇒ 判成正常；
	//   再深一层 ⇒ 判成高危。
	// 以后加条目时忘配名字 / 目录写错 / 深度填错会立刻 FAIL。
	//
	ULONG SystemImageExtraDirCount() noexcept;
	bool SystemImageExtraDirAt(ULONG index, PCWSTR* name, PCWSTR* dir, ULONG* depth) noexcept;

	// 线程创建高危判定。remote 表示跨进程创建（注入）。
	bool IsHighRiskThread(ULONG targetPid, ULONG selfPid, ULONG threadOp) noexcept;

	//
	// 代码注入链高危判定（v14）。
	//
	// 覆盖 NtWriteVirtualMemory / NtProtectVirtualMemory / NtAllocateVirtualMemory
	// 三个跨进程内存操作。判据的基本形状：
	//
	//   · 本进程（targetPid == selfPid）→ **一律不算高危**。
	//     这是硬前提：JIT / GC / 任何托管运行时都在自己进程里
	//     Allocate + Write + Protect，判了就是全系统假 HIGH 雪崩。
	//   · 跨进程 → 再看风险等级（见 processOp 的细分说明）：
	//       - WriteMemory    跨进程写 = 最高（shellcode/路径落进别人内存）
	//       - ProtectMemory  跨进程改成可执行（有 PAGE_EXECUTE_*）= 高
	//       - AllocateMemory 跨进程申请（有 MEM_COMMIT + PAGE_EXECUTE_*）= 高
	//
	// allocateType / protect 是 NT 调用的原始值，用于排除"申请不可执行内存"
	// 这类常见但无害的跨进程操作（如调试器读内存、注入 DLL 路径字符串）。
	//
	bool IsHighRiskMemoryOp(ULONG targetPid, ULONG selfPid, ULONG processOp,
		ULONG protect, ULONG allocationType) noexcept;

	// 命中规则的名字。没命中返回 nullptr。
	const char* MemoryOpRiskReason(ULONG targetPid, ULONG selfPid, ULONG processOp,
		ULONG protect, ULONG allocationType) noexcept;

	// 驱动加载高危判定。driverPath 是归一化后的 .sys / 服务二进制路径。
	// kernelDriverService 为 true 表示这次操作针对的是内核驱动服务
	// （DriverOp 为 CreateService/ChangeServiceConfig/StartService 时才有意义）；
	// NtLoadDriver/NtUnloadDriver 传默认的 true。
	bool IsHighRiskDriverLoad(PCWSTR driverPath, ULONG driverOp, bool kernelDriverService = true) noexcept;

	//
	// 网络高危判定。
	//
	// remoteAddress 是远端地址的**文本形式**：IPv4/IPv6 字面量或域名
	//   （"192.168.1.1" / "2606:4700::1111" / "evil.example.com"）。
	// targetPort 是主机序端口，DnsQuery 时为 0。
	// protocol 是 IPPROTO_TCP(6) / IPPROTO_UDP(17) / 0=未知。
	// netOp 是 R3ShieldCore::NetOp。
	//
	// 判据（用户选定：敏感端口 + 内网地址）：
	//   - 目标是敏感服务端口 → 高危（横向移动：445/139/3389/1433/3306/6379…）
	//   - 目标是内网/保留地址段 → 高危（这是横向移动与 SSRF 的特征）
	//   - 监听（listen）无差别高危 —— 正常客户端程序不该开监听
	//   - 明文/无认证协议端口 → 高危（FTP/Telnet/POP3…）
	//
	bool IsHighRiskNetwork(PCWSTR remoteAddress, ULONG targetPort, ULONG protocol, ULONG netOp) noexcept;

	// 命中规则的名字。没命中返回 nullptr。
	const char* NetworkRiskReason(PCWSTR remoteAddress, ULONG targetPort, ULONG protocol, ULONG netOp) noexcept;

	// 远端地址是否属于内网 / 保留网段（10./172.16-31./192.168./169.254./
	// 127./100.64-127. 运营商级 NAT、IPv6 ULA fc00::/7、IPv6 链路本地 fe80::/10）。
	// 单独导出便于 UI 打标记和内网连通的展示。
	bool IsPrivateOrReservedAddress(PCWSTR address) noexcept;

	// 端口是否属于"敏感服务端口"（横向移动常用）。
	bool IsSensitivePort(ULONG port) noexcept;

	// 端口是否属于"基础设施端口"（DNS 53 / mDNS 5353 / DoT 853 / NTP 123）。
	// 全网程序都要打，一律不判高危（只记录）—— 否则开浏览器即弹窗机关枪。
	bool IsInfrastructurePort(ULONG port) noexcept;

	// 这个端口在敏感表里对应的服务名（用于日志/弹窗说明）。没有返回 nullptr。
	const char* SensitivePortServiceName(ULONG port) noexcept;

	// 这条高危规则的名字，用于日志和弹窗展示（如 "自启动项"）。
	// 返回静态字符串，无需释放。没命中返回 nullptr。
	const char* RegistryRiskReason(PCWSTR keyPath, PCWSTR valueName, ULONG op) noexcept;
	const char* FileRiskReason(PCWSTR path, ULONG fileOp) noexcept;
	const char* ProcessRiskReason(PCWSTR imagePath, ULONG processOp, ULONG parentPid) noexcept;
	const char* ThreadRiskReason(ULONG targetPid, ULONG selfPid, ULONG threadOp) noexcept;

	//
	// v36：终止进程收敛 —— 判「这次 NtTerminateProcess 该不该拦」。
	//
	// 语义：**放行"终止自己 / 自己的后代 / 同镜像路径的进程"，
	//       其余一律高危（"不许杀别人"）。**
	//
	// ⚠️ 本层是"唯一会查进程"的规则（其余规则都是纯标量判断）——
	//    这是**刻意**的：父链上溯与镜像比对是新逻辑里最容易错的部分，
	//    放在这里才能被 tools/*_rules_ut 直接驱动真实进程树验证
	//    （见 tools/terminate_contain_ut.cpp），而不是靠肉眼比对。
	//
	const char* TerminateRiskReason(ULONG targetPid, ULONG selfPid) noexcept;

	bool IsHighRiskTerminate(ULONG targetPid, ULONG selfPid) noexcept;

	// ---- 上面那条判据用到的"取事实"原语（单独暴露，便于探针直调）----

	// 由 pid 拿父进程 pid（ProcessBasicInformation.InheritedFromUniqueProcessId）。
	// 失败返回 0 —— 判不出父子关系时**不当作自己人**（偏保守：宁可少放行）。
	ULONG ParentPidOf(ULONG pid) noexcept;

	// targetPid 是不是 selfPid 的后代（整棵子树，含孙进程）—— 沿父链上溯。
	bool IsOwnDescendant(ULONG targetPid, ULONG selfPid) noexcept;

	// 目标进程的镜像路径是不是与**当前进程**相同（同程序多实例）。
	bool SameImageAsSelf(ULONG targetPid) noexcept;
	const char* DriverRiskReason(PCWSTR driverPath, ULONG driverOp, bool kernelDriverService = true) noexcept;

	// 是否命中用户自定义的 protect_reg / protect_file 前缀。
	bool MatchesUserProtectRegistry(PCWSTR keyPath) noexcept;
	bool MatchesUserProtectFile(PCWSTR path) noexcept;
	bool MatchesUserProtectProcess(PCWSTR imagePath) noexcept;
	bool MatchesUserProtectDriver(PCWSTR driverPath) noexcept;

	// 网络目标是否命中用户自定义 protect_net=（匹配 "IP:端口" 或域名）。
	bool MatchesUserProtectNetwork(PCWSTR address, ULONG port) noexcept;

	//
	// 摄像头 / 麦克风高危判定。
	//
	// 判据很简单：**打开就报**。cameraOp 是 R3ShieldCore::CameraOp，
	// EnumDevice 不算（枚举列表是正常行为），其余三个（VFW 打开、
	// MF 建设备源、MF 建读取器）一律高危。
	//
	// 为什么不看设备名：设备名由驱动提供（"Integrated Camera" 之类），
	// 没有任何可判别的特征，看了也没用。这里要的是"让用户知情"，
	// 不是"识别恶意摄像头"。
	//
	bool IsHighRiskCamera(ULONG cameraOp) noexcept;
	const char* CameraRiskReason(ULONG cameraOp) noexcept;

	//
	// 输入钩子高危判定。
	//
	// idHook 是 Win32 的 wh 值（WH_MOUSE_LL=14 / WH_KEYBOARD=2 …），
	// threadId 是 SetWindowsHookEx 的 dwThreadId（0 = 全局），
	// hookOp 是 R3ShieldCore::HookOp（RegisterRawInput 时 idHook 无效，
	// 改由 rawInputSink 说明是否带 RIDEV_INPUTSINK）。
	//
	bool IsHighRiskInputHook(ULONG idHook, ULONG threadId, ULONG hookOp, bool rawInputSink) noexcept;
	const char* InputHookRiskReason(ULONG idHook, ULONG threadId, ULONG hookOp, bool rawInputSink) noexcept;

	//
	// 屏幕捕获高危判定。
	//
	// screenOp 是 R3ShieldCore::ScreenOp。能走到这里的只可能是
	// "源为屏幕 DC 的 BitBlt/StretchBlt" 或 "PrintWindow"，
	// 所以三条一律高危 —— 过滤发生在 hook 层，不在规则层。
	//
	bool IsHighRiskScreen(ULONG screenOp) noexcept;
	const char* ScreenRiskReason(ULONG screenOp) noexcept;

	//
	// DLL 加载 / 劫持高危判定。
	//
	// dllPath 是归一化后的 DOS 路径（C:\...）。**只有非系统目录的 DLL
	// 才会走到这里** —— System32/SysWOW64/Program Files 的加载在 hook
	// 层就被过滤掉了（否则每个进程启动都是几百条事件）。
	//
	// 判据（**只有下面这些算高危**）：
	//   - 从用户可写目录加载（Temp/AppData/ProgramData/Downloads）→ 高危（白加黑）
	//   - 手工映射特征（manualMap=true）→ 高危（无 LdrLoadDll 的映像映射）
	//   - 命中用户 protect_file= 前缀 → 高危
	//   - 其余非系统目录（自装软件的安装目录）→ **不算高危**（nullptr）
	//     ⚠️ 这里刻意不把"非系统目录"一律判高危：实测 PowerShell 7 装在
	//        D:\Program Files 下，一次启动刷 235 条全 HIGH，99% 是正常 .NET 依赖。
	//        兜底必须是 nullptr，否则噪音淹没真信号（同 hosts 时间戳那次）。
	//
	bool IsHighRiskDllLoad(PCWSTR dllPath, ULONG dllOp, bool manualMap) noexcept;
	const char* DllLoadRiskReason(PCWSTR dllPath, ULONG dllOp, bool manualMap) noexcept;

	//
	// 轮询式输入读取判定（v11）。
	//
	// ⚠️ 这是个**两段式**判据，规则层只是第二段：
	//    第一段（InputHookGuard::PollingDetector）按**调用密度**决定
	//    "这次调用算不算键盘记录"，是了才调这里。
	//    规则层这里只表达"一旦认定就是高危"。
	//
	// 为什么不能只看单次调用：GetAsyncKeyState 的参数就是虚拟键码，
	// 没有任何可判别特征 —— 输入法、游戏、辅助工具都在高频调它。
	// 密度阈值见 InputHookGuard（单位线程、单位时间窗的调用次数）。
	//
	bool IsHighRiskInputPolling(ULONG hookOp) noexcept;

	//
	// 合成输入 / 阻断输入高危判定（v14）。
	//
	// ⚠️ 与上面的"轮询"一样是**两段式**，但分段逻辑不同：
	//
	//   SendInput / keybd_event / mouse_event
	//     —— 单次调用完全合法（屏幕键盘、自动化脚本、游戏宏）。
	//        规则层这里只表达"一旦被判为合成输入洪流就是高危"；
	//        "算不算洪流"由 InputHookGuard::SyntheticInputDetector
	//        按**单位时间内的合成事件数**决定。
	//
	//   BlockInput / ClipCursor
	//     —— 这两个 API **本身就是危害行为**，不需要密度：
	//        正常程序不会冻结用户输入，也不会把鼠标锁在一个矩形里。
	//        唯一的例外是"当前前台窗口就是自己"的合法场景（如远程桌面
	//        客户端、KVM 软件），所以附带前台窗口归属判断。
	//
	bool IsHighRiskInputInjection(ULONG hookOp, bool foregroundOwnedByCaller) noexcept;
	const char* InputInjectionRiskReason(ULONG hookOp, bool foregroundOwnedByCaller) noexcept;

	//
	// 剪贴板高危判定。
	//
	// 只有 Read（GetClipboardData）算高危。Open 只是敲门砖，
	// 拦它会让所有正常复制粘贴失败 —— 所以 Open 只记录。
	//
	bool IsHighRiskClipboard(ULONG clipboardOp) noexcept;
	const char* ClipboardRiskReason(ULONG clipboardOp) noexcept;

	//
	// 进程创建旁路高危判定。
	//
	// spawnOp 是 R3ShieldCore::SpawnOp。判据按 API 分档：
	//   WithToken / WithLogon → 高危（换 token / 凭据 = 提权与横向移动）
	//   WinExec / System      → 高危（shellcode 常用的一层）
	//   ShellExecute          → 高危（可能触发关联劫持）
	//
	bool IsHighRiskSpawn(ULONG spawnOp) noexcept;
	const char* SpawnRiskReason(ULONG spawnOp) noexcept;

	//
	// 服务 / 安全对象权限变更高危判定（v11）。
	//
	// serviceOp 是 R3ShieldCore::ServiceConfigOp。判据与驱动那类不同：
	// 这里**不看二进制路径**，只看"改了安全描述符"这件事本身。
	// 改服务 DACL（sc sdset）是把 SYSTEM 服务变成任意用户可控执行点的钥匙。
	//
	bool IsHighRiskServiceConfig(ULONG serviceOp) noexcept;
	const char* ServiceConfigRiskReason(ULONG serviceOp) noexcept;

	//
	// COM / OLE 激活劫持高危判定（v12）。
	//
	// ⚠️ 判据与其它类不同 —— 不看"是不是这个 API"，看**服务器路径**：
	//    comServerPath 是 CLSID 解析出来的 InprocServer32/LocalServer32 路径。
	//    只有"路径落在用户可写目录"才算劫持特征；系统 CLSID 走系统目录 → 不是高危。
	//
	// inproc 为 true 表示进程内服务器（DLL），false 表示本地服务器（EXE）。
	// 返回 nullptr 表示不算高危。
	//
	const char* ComHijackRiskReason(PCWSTR comServerPath, bool inproc) noexcept;
	bool IsHighRiskComHijack(PCWSTR comServerPath, bool inproc) noexcept;

	//
	// 计划任务持久化高危判定（v12）。
	//
	// taskOp 是 R3ShieldCore::ScheduledTaskOp。判据按操作分档：
	//   RegisterTaskDefinition → 高危（建立持久化，最核心）
	//   TaskCacheWrite         → 高危（绕过 COM 直写注册表）
	//   Run                    → 高危（立即执行，横向移动特征）
	//   CreateFolder           → 不算高危（只建目录）
	//
	bool IsHighRiskScheduledTask(ULONG taskOp) noexcept;
	const char* ScheduledTaskRiskReason(ULONG taskOp) noexcept;

	//
	// 音频采集 / 环回高危判定（v13）。
	//
	// cameraOp 是 R3ShieldCore::CameraOp，但**只接音频那几个值**
	// （WasapiCapture / WasapiLoopback / MicOpen）；摄像头侧的判据仍走
	// IsHighRiskCamera。
	//
	// 判据按"采集哪一路"分档：
	//   WasapiLoopback → 高危（录系统输出 = 录 VoIP/会议，意图明确）
	//   WasapiCapture  → 高危（录麦克风，同摄像头口径：用户应知情）
	//   MicOpen        → 高危（老式 waveIn 录音，同上）
	//   其余           → 不算高危
	//
	bool IsHighRiskAudio(ULONG cameraOp) noexcept;
	const char* AudioRiskReason(ULONG cameraOp) noexcept;

	//
	// 令牌窃取 / 冒充高危判定（v13）。
	//
	// tokenOp 是 R3ShieldCore::TokenTheftOp。**分三档**（用户选定的完整链）：
	//   一档 · 准备（可疑，不判高危）：
	//     OpenProcessToken / OpenThreadToken —— 只拿到"可被复制/被冒充"
	//     的句柄。拿句柄本身不产生任何身份变更，很多正常工具（进程
	//     管理器、调试器、备份软件）都会调它 → 单独出现不判高危。
	//     ⚠️ 但如果**同一进程在前一档之后又走到二档**，二档那次会带上
	//        FlagEvent2TokenUsed —— 组合信号由 guard 侧关联，规则层不管。
	//   二档 · 使用（高危）：
	//     DuplicateTokenEx / ImpersonateLoggedOnUser / CreateProcessWithToken /
	//     SetThreadToken —— 到这里身份已经真的被换掉了。
	//   三档 · 铺路（高危）：
	//     AdjustTokenPrivileges —— 开 SeDebug/SeImpersonate/SeTcb。
	//     ⚠️ 这一档在规则层拿不到"开的是哪个特权"（那是 API 参数），
	//        所以这里只表达"调了就是高危"；**精细判据在 guard 侧**：
	//        只有真的在 NewState 里启用了调试/冒充/内核特权才上报，
	//        单纯 DisableAllPrivileges 或开 SeShutdownPrivilege 不算。
	//
	bool IsHighRiskTokenTheft(ULONG tokenOp) noexcept;
	const char* TokenTheftRiskReason(ULONG tokenOp, ULONG*tierOut) noexcept;

	//
	// WMI 事件订阅持久化高危判定（v13）。
	//
	// wmiOp 是 R3ShieldCore::WmiSubscriptionOp，第三个参数说明这次操作落在
	// 哪个命名空间 / 哪个 WMI 类上（由 guard 侧从参数里提取，见下）：
	//   inSubscriptionNs —— 命名空间是不是 root\subscription
	//   wmiClass         —— 目标类名（"__EventFilter" / "__EventConsumer" /
	//                       "__FilterToConsumerBinding" / 其它）
	//
	// 判据（**必须同时满足"在 root\subscription" + "是那三个类之一"**）：
	//   其它命名空间上的 WMI 操作（正常软件监听设备变化）→ 直接 Pass，
	//   连事件都不产生（与 COM 判据同思路：非高危不进通道）。
	//
	// 分档：
	//   PutInstance + __EventConsumer          → 高危（执行体，最危险）
	//   PutInstance + __FilterToConsumerBinding→ 高危（绑定 = 激活整条链）
	//   PutInstance + __EventFilter            → 高危（触发条件）
	//   Subscribe / ExecMethod（root\subscription）→ 高危
	//   ConnectServer / ExecQuery              → 不算高危（只记录）
	//
	bool IsHighRiskWmiSubscription(ULONG wmiOp, bool inSubscriptionNs, PCWSTR wmiClass) noexcept;
	const char* WmiSubscriptionRiskReason(ULONG wmiOp, bool inSubscriptionNs, PCWSTR wmiClass) noexcept;

	//
	// 宿主劫持 / 加载器高危判定（v15）。
	//
	// 四个子面，两条不同的判据形状：
	//
	//   子面①（注册表全局注入键）——用 HostInjectionKeyRiskReason：
	//     键路径命中注入键表 **且** 值指向用户可写目录 才是高危。
	//     ⚠️ 值名/值内容才是关键，键本身往往是正常系统键。
	//
	//   子面②③④（加载器侧加载 / 远程映射 / 凭据宿主）——用
	//     HostHijackRiskReason：按 hostOp 分流。
	//       · 远程映射 / 远程 APC → **crossProcess 是硬门槛**，
	//         跨进程即高危（不看路径 —— 机制本身就是注入）
	//       · 凭据宿主 / 本地加载变体 → 回到"路径是否用户可写"
	//
	// ⚠️ 顺序约定：`*RiskReason` 必须声明在对应 `IsHighRisk*` 之前
	//    （单匿名 namespace，无前向声明；v14 踩过两次）。
	//
	const char* HostInjectionKeyRiskReason(PCWSTR keyPath, PCWSTR pathValue) noexcept;
	bool IsHighRiskHostInjectionKey(PCWSTR keyPath, PCWSTR pathValue) noexcept;

	const char* HostHijackRiskReason(ULONG hostOp, PCWSTR dllPath, bool crossProcess, bool manualMap) noexcept;
	bool IsHighRiskHostHijack(ULONG hostOp, PCWSTR dllPath, bool crossProcess, bool manualMap) noexcept;

	// 键路径是否命中"宿主注入键"表（不含值内容判断）。给 guard 侧做预筛用，
	// 命中才去读值内容。返回规则说明或 nullptr。
	const char* HostInjectionKeyReason(PCWSTR keyPath) noexcept;

	//
	// bypass 判据的纯函数部分（v16，给 registry_guard.cpp 的 ComputeBypass 用）。
	//
	// ⚠️ 为什么提到规则层：
	//    `ComputeBypass` 里的"签名 + 目录"双条件有一部分是**纯字符串判断**，
	//    放在 registry_guard.cpp 的匿名 namespace 里没法单测。提到这里之后
	//    规则单测（v16_rules_ut）可以覆盖，避免"改名单改错"导致 bypass 洞。
	//
	//    签名相关的两个（WinVerifyTrust / CryptQueryObject）仍留在
	//    registry_guard.cpp —— 它们要碰系统 API，不适合进纯函数单测。
	//

	// 路径是否落在 `%SystemRoot%\` 下**用户可写（或半可写）的子目录**里。
	//
	// ⚠️ 传进来的路径大小写不敏感（内部做不区分大小写的片段匹配），
	//    调用方不必预先转小写。
	bool IsInWritableWindowsSubdir(PCWSTR imagePath) noexcept;

	// 签名者名字是否为微软。取"以 Microsoft 开头"（主题名有多种写法，
	// 如 "Microsoft Windows" / "Microsoft Corporation" / "Microsoft Windows Publisher"）。
	bool IsMicrosoftSigner(PCWSTR signerName) noexcept;

	// bypass 判据 v20：镜像路径是否命中**具体文件白名单**（取代「整个 System32 目录」）。
	//
	// ⚠️ 传进来的路径大小写不敏感；`\SystemRoot\` / `/` 等形态会被归一化。
	//    只列**核心系统进程**（smss/csrss/wininit/winlogon/services/lsass/svchost/
	//    dwm/explorer 等），System32 下**未列出**的文件（哪怕微软签名）**不**命中。
	//
	// 调用方（registry_guard.cpp 的 ComputeBypass）三条全过才 bypass：
	//    ① 本函数为 true
	//    ② `!IsInWritableWindowsSubdir(imagePath)`
	//    ③ 微软签名（registry_guard.cpp 里做，需系统 API）
	bool IsWhitelistedSystemImage(PCWSTR imagePath) noexcept;

	// ------------------------------------------------------------------
	// block_all_safe 用：镜像是否属于"可信来源"，可以放行**进程创建**。
	// ------------------------------------------------------------------
	//
	// ⚠️ 与 `IsWhitelistedSystemImage` 的区别（**别混用**）：
	//
	//   | 判据 | 粒度 | 用途 |
	//   |---|---|---|
	//   | `IsWhitelistedSystemImage` | **具体文件**白名单（35 条） | 决定"这个进程要不要被挂 hook"（bypass） |
	//   | `IsTrustedLaunchImage` | **目录 + 签名**（宽得多） | 决定"要不要放行把一个进程创建出来" |
	//
	//   为什么后者必须更宽：一个正常程序（浏览器 / 办公软件 / 你自己的工具）
	//   也会去 `CreateProcess`。若按"具体文件白名单"放行，那些程序全被拦，
	//   等于回到 block_all 的老问题（正常程序打不开）。
	//   放行粒度定义在"目录可信 + 微软签名"这一层，正好把
	//   「系统目录里的可信程序」放进来，把
	//   「用户目录 / Temp / Downloads / 盘根」挡在外面。
	//
	// 判据（三条同时成立）：
	//   ① 路径落在 `%SystemRoot%\`、`%ProgramFiles%\`、`%ProgramFiles(x86)%\`
	//      三者之一（内部做 `\SystemRoot\` / `X:\Windows\` 归一化，大小写不敏感）
	//   ② 不在 `%SystemRoot%\` 下的用户可写子目录里（`IsInWritableWindowsSubdir`）
	//   ③ 微软签名有效（`IsSignatureTrusted` + `IsMicrosoftSigner`）
	//
	// ⚠️ imagePath 为 NULL / 空 → **false**（即"不可信"）。
	//    这是刻意的：`NtCreateProcess` / `NtCreateProcessEx` 拿不到镜像路径
	//    （无参数块），而它们恰恰是进程镂空 / 反射加载的特征手法。
	//    "路径查不到就放行"是 `ComputeBypass` 曾经那个洞的同款错误，不能再犯。
	//
	// ⚠️ 本函数会做签名校验（WinVerifyTrust，可能几十毫秒），
	//    **只允许在进程创建这条低频路径上调用**，绝不能进 hook 热路径。
	bool IsTrustedLaunchImage(PCWSTR imagePath) noexcept;

	// ------------------------------------------------------------------
	// 全拦模式用（v66）：这次**进程创建**是不是 UAC 提权链的"同意框本体"？
	// ------------------------------------------------------------------
	//
	// 背景：v66 起 `block_all` / `block_all_safe` 对「进程创建 / 远程线程 /
	//   跨进程内存」**恢复为直接拒**（v21 的"先问再拦"已撤销 —— 全拦就是全拦）。
	//   硬拒之后必须给 UAC 留一条缝，否则连"是否允许此应用对你的设备进行更改"
	//   这个框都起不来 ⇒ 用户彻底无法提权。
	//
	// 返回 true  → 放行（**不弹窗、不问用户**）
	// 返回 false → 交给调用方按全拦语义**直接拒**
	//
	// 放行范围（**仅此三个镜像**，且必须落在**真实** `%SystemRoot%\System32\` 下）：
	//   · `consent.exe`            —— UAC 同意框本体
	//   · `CredentialUIBroker.exe` —— 凭据输入 UI 代理
	//   · `LogonUI.exe`            —— 登录 / 锁屏界面
	//
	// ⚠️ 判据是**归一化后的全路径**（`%SystemRoot%\System32\consent.exe`），
	//    不是"文件名等于 consent.exe 就放" —— 后者会让
	//    `C:\Users\x\consent.exe` 蹭过去。
	//
	// ⚠️★ **不做盘符别名映射**（与 `IsTrustedLaunchImage` 的关键差别之二）：
	//    `IsTrustedLaunchImage` 走 `NormalizeForTrustedDir`，会把**任意盘符**
	//    的 `X:\Windows\` 折成 `%SystemRoot%\` —— 那对它安全，因为它后面还有
	//    一道**微软签名**校验兜底。
	//    本函数**不查签名**，所以必须用 `GetWindowsDirectoryW` 的**真实**目录
	//    比前缀；否则攻击者在可写卷上建 `D:\Windows\System32\consent.exe`
	//    就能蹭过白名单。
	//    ⇒ 含 `\\?\` / `\??\` / 非系统盘的 `X:\Windows\` **一律不放行**
	//      （保守是刻意的：这是"少拦一个系统进程"的兜底，不是便利开关）。
	//
	// ⚠️ 本函数**不查签名**（与 `IsTrustedLaunchImage` 的区别之一）：它只服务于
	//    "别把 UAC 框拦掉"这一个目的，而路径已经限定在受保护的系统目录里。
	//    ⇒ **不会跑 WinVerifyTrust**，可以放心在进程创建路径上调用。
	// ⚠️ 它**只放行同意框本身**，不放行"被提权的那个目标程序" ——
	//    目标是任意镜像（用户自己的程序），无法用路径判据安全识别。
	bool IsUacConsentImage(PCWSTR imagePath) noexcept;

	// ------------------------------------------------------------------
	// 全拦模式用（v22 引入；★ v66 起**引擎里已无调用点**，见下）
	// ------------------------------------------------------------------
	//
	// 返回 true  → 有人在前端点（双击 / 提权运行 / 从压缩包打开 / 从浏览器打开）
	// 返回 false → 不是人点的（服务 / 脚本 / 恶意子进程 / 父进程已退出）
	//
	// ★★ v66 现状：`process_guard.cpp` 的全拦分支已恢复为**一律直接拒**
	//    （撤销 v21 的"先问再拦"），所以**这个分档在引擎里不再被消费** ——
	//    无论返回什么，全拦模式下都是拒。函数本身**保留不删**，理由：
	//      ① `tools/probe_student.cpp` 与单测仍用它描述"人启动"语义；
	//      ② 判据表（`kUserLaunchParentExes`）是资产，将来若要恢复
	//         "只对可疑来源报警"这类分档，不必重新收集一遍。
	//    ⚠️ 若你正在读代码想改全拦行为：改的是 `process_guard.cpp` 的
	//       `IsAnyBlockAllMode` 分支，**不是**这里。
	//
	// 判据：**父进程镜像路径**是否命中「人操作中介」表：
	//   explorer.exe（桌面/开始菜单/任务栏/Win+R）
	//   svchost.exe（UAC 提权中介 —— 右键"以管理员身份运行"）
	//   WinRAR / 7zFM / Bandizip / WinZip32 / HaoZip / PeaZip（压缩包内双击）
	//   chrome / msedge / firefox / iexplore / brave（下载后点开）
	//   Everything / Listary / Wox / Flow Launcher / PowerToys（启动器）
	//   TotalCMD / DirectoryOpus（第三方文件管理器）
	//
	// ⚠️ **明确不含** `cmd.exe` / `powershell.exe` / `wscript.exe` /
	//   `cscript.exe` / `mshta.exe` / `rundll32.exe` / `regsvr32.exe` /
	//   `conhost.exe` / `services.exe` / `schtasks.exe` ——
	//   它们是恶意程序拉起子进程最常用的媒介。
	//
	// ⚠️ parentImagePath 为 NULL / 空 → **false**（fail-closed）。
	//   父进程可以在拉起子进程后立刻退出，此时拿不到路径。恶意程序完全可以
	//   利用这点（先退出父进程，让子进程看起来"没有父"）。这种"没人能确认
	//   有人在跟前"的情况，按不可信处理。
	//
	// ⚠️ 匹配是**纯文件名片段**（`\explorer.exe`，带前导反斜杠），
	//   避免 `D:\evil\myexplorer.exe` 蹭到。
	bool IsUserInitiatedLaunch(PCWSTR parentImagePath) noexcept;

	// ------------------------------------------------------------------
	// 全拦模式用（v25）：这次**注册表写**要不要"先问再拦"？
	// ------------------------------------------------------------------
	//
	// 背景：block_all / block_all_safe 下注册表写原来是"一律直接拒、不弹窗"，
	// 正常软件写自己的配置静默失败 → 系统弹「无法访问指定设备、路径或文件」
	// （`0xC0000022`）且无任何提示。v25 给用户一次放行机会。
	//
	// 返回 true  → 调用方**弹窗询问**（默认结论仍是拒绝，超时/无 UI 即拒）
	// 返回 false → 调用方**直接拦，连问都不问**
	//
	// ⚠️ 注册表比进程创建危险得多，「直接拦」的面必须够大。以下一律 false：
	//
	//   ① **高危规则表命中**（`IsHighRiskRegistry`）——
	//      Run / RunOnce / IFEO / 服务 / Winlogon / LSA / COM 劫持 /
	//      WMI 订阅 / 打印机驱动 / COM+ 目录 / 各类自启点，恶意样本的
	//      持久化落点全在册。
	//   ② **Windows 自身运行时基础设施键**——
	//      `SOFTWARE\Microsoft\Windows` / `Cryptography` / `COM3` /
	//      `SystemCertificates` / `OLE` / `AppModel` / `SYSTEM\ControlSet` /
	//      `SOFTWARE\Classes` / `MMDevices`。
	//      这些**本来就在豁免里**（"问了没意义 + 弹窗机关枪 + 点拒绝
	//      会诱发重试死循环"），而 block-all 分支抢在豁免之前执行，
	//      所以必须在这里显式再判一次。
	//   ③ **hive 级操作**（`IsHiveOp`）—— 加载 / 卸载 / 导出 / 还原配置单元，
	//      整棵子树的原子替换，不是"写一个值"。
	//   ④ **COM+ 目录**（`SOFTWARE\Microsoft\COM3\Catalog`）——
	//      可指定激活身份，写它 = 以高权限激活攻击者组件。
	//
	// ⚠️ keyPath / valueName 为空或拿不到路径 → **false**（fail-closed）。
	//
	// ⚠️ **只允许在 block-all 分支调用** —— `mode=log` / `mode=block` 各有
	//   自己的判定链，不要拿这个函数去放过它们。
	bool ShouldAskInsteadOfBlockAll(PCWSTR keyPath, PCWSTR valueName, ULONG op) noexcept;
}

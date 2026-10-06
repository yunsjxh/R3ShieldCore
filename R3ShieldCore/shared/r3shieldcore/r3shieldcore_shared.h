#pragma once

//
// 引擎进程与注入 DLL 之间共享的数据结构定义。
// 这个头文件不依赖 CRT，双方各自编译一份，因此所有成员都是 POD。
//
// 通道布局：
//   [ Policy  共享内存 ]  引擎写、各进程只读打开
//   [ Events  共享内存 ]  各进程写、引擎单消费者读（环形缓冲）
//
// 生产者发布协议：填好除 Sequence 外的字段 → MemoryBarrier() →
// InterlockedExchange(Sequence, 槽位序号 + 1)。消费者只在 Sequence 匹配时读取。
//

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

namespace R3ShieldCore
{
	constexpr ULONG PolicyMagic = 0x31504752;  // 'RGP1'
	constexpr ULONG ChannelMagic = 0x31454752; // 'RGE1'
	constexpr ULONG AbiVersion = 20;           // 20: ★ 绝不注入名单（v49）—— `Policy` **尾部追加**
	                                           //     `NeverInjectCount` + `NeverInjectPaths[16][260]`。
	                                           //     ★ 这是**布局改动**（`sizeof(Policy)` 变大）⇒ 必须
	                                           //     升版本，而且**两个方向都要挡**：
	                                           //       · 新 DLL + 旧引擎：旧引擎建的 section 更小，
	                                           //         新 DLL 的 `MapViewOfFile(sizeof(新 Policy))`
	                                           //         会**直接失败**（映射超过 section 大小）；
	                                           //       · 旧 DLL + 新引擎：旧 DLL 只映射自己那一段、
	                                           //         能成功，但它会读到**错误版本** ⇒ 靠这里的
	                                           //         版本校验挡住（否则它会把 `NeverInjectPaths`
	                                           //         当成别的东西读）。
	                                           //     两种都落到「共享通道不可用 ⇒ 本进程跳过全部
	                                           //     Hook」（r3shieldcore_channel.cpp 的版本校验），
	                                           //     而不是静默按错误布局读内存。
	                                           // 19: ★ 瘦注入（v42）—— `Policy::Flags2` 新增
	                                           //     `FlagInjectShellThin`（0x20）。**布局不变**，
	                                           //     但语义上改变了"哪些进程会被注入、以什么
	                                           //     强度注入"，所以**必须升版本**：
	                                           //     旧 DLL 被注入进 `explorer.exe` 会装**全量**
	                                           //     hook（它不认识新位）—— 那正是最危险的组合。
	                                           //     升版本后新旧混用会以
	                                           //     「共享通道不可用 ⇒ 本进程跳过全部 Hook」
	                                           //     失败（r3shieldcore_channel.cpp 的版本校验），
	                                           //     而不是悄悄装错 hook。
	                                           // 18: 老 API 补盲 —— ProcessOp 新增 CreateLegacy
	                                           //     （NtCreateProcess，无参数块）、ThreadOp 新增
	                                           //     CreateLegacy（NtCreateThread）、NetOp 新增
	                                           //     DeviceIo（\Device\Afd 直发）。
	                                           //     Event 布局不变，纯新增 Op 值。
	                                           // 17: 规则层 hive op 逐段匹配修复（IsHiveOp 补
	                                           //     SaveKeyEx / UnloadKey(Ex)）。Event 布局不变。
	                                           // 16: bypass 改「签名 + 目录」双条件。Event 布局不变。
	                                           //
	                                           // ⚠️ v19 **没有升 AbiVersion** ——
	                                           //     它只扩了 r3shieldcore_rules.cpp 的注册表规则表
	                                           //     （打印机 / WinRT / COM+ / 自启补盲），
	                                           //     没加 Op、没改枚举、没动 Event 布局。
	                                           //     规则表是纯用户态判据，不写进事件流，
	                                           //     所以新旧 DLL 之间没有 ABI 差异。
	                                           // 15: 宿主劫持 / 加载器面 —— 新增 HostHijack 一类，
	                                           //     覆盖注册表全局注入键 + 加载器侧加载变体 +
	                                           //     远程映射注入 + 凭据宿主劫持。
	                                           //     Event 布局不变（新语义走 HostHijackOp + Flags2）。
	                                           // 14: 防护面补强 —— ProcessOp 新增代码注入链三步
	                                           //     （WriteMemory/ProtectMemory/AllocateMemory），
	                                           //     HookOp 新增反向输入三项（SendInput/BlockInput/
	                                           //     ClipCursor）。Event 布局不变。
	                                           // 13: 隐私/凭据/订阅面扩展 —— Camera 类新增音频环回与麦克风
	                                           //     变体，新增 TokenTheft / WmiSubscription 两类。
	                                           //     Event 布局不变（仍靠 Flags2 承载新语义位）。
	                                           // 12: 持久化面扩展 —— 新增 ComHijack / ScheduledTask 两类，
	                                           //     Event 尾部追加 ULONG Flags2（Flags 32 位已满）

	// 引擎行为模式。
	enum class Mode : ULONG
	{
		Log = 0,          // 只记录，全部放行
		Block = 1,        // 记录并拒绝写类操作
		Ask = 2,          // 记录，并弹窗询问用户
		BlockAll = 3,     // 完全拦截：探测范围内一律拒绝 —— 不看豁免、不看高危、不询问
		BlockAllSafe = 4, // 完全拦截（安全版）：同上，但**放行可信来源的进程创建**
	};

	// ⚠️ 完全拦截模式（ini: mode=block_all）的语义边界，改动前务必读完：
	//
	//   「一律拒绝」的对象 = **所有会被上报的操作**（也就是平时能在那份事件日志里
	//   看到的一切）。判定链路里三层「探测边界」**仍然保留**，因为它们决定的是
	//   "这个操作算不算被探测到"，而不是"探测到了要不要放行"：
	//
	//     1. ComputeBypass —— 白名单进程、系统进程、引擎自身**根本不挂 hook**，
	//        所以它们的行为不在拦截范围内（也正因为如此，引擎自己还能写日志、
	//        系统服务还能跑，不会一开就把机器搞死）。
	//     2. IsNonFileObject —— 管道 / 套接字 / 控制台压根不是文件操作，不上报。
	//     3. 只读打开的早期过滤（如 hook_reads=0 时的 NtOpenKey 纯读）—— 不上报。
	//
	//   而被跳过的、属于「探测到了要不要放行」的那几层，全部不再生效：
	//     · IsExemptDiskPath（系统目录 / 临时目录 / 高频缓存豁免）
	//     · 高危规则表判定（不再区分高危与否）
	//     · 进程 / 线程的「高危才拦」
	//     · 网络的回环 / 基础设施端口豁免
	//     · 自定义 protect_* 路径（不需要了，本来就全拦）
	//
	//   ⚠️ 后果：所有被注入的进程（第三方程序）的注册表 / 文件 / 网络 / 进程创建
	//   行为会立刻开始失败，这些程序会卡死或崩溃。系统核心进程因为不在注入范围内
	//   而照常运行。这是**故意**的行为，也是可恢复的（改回 ini 或停引擎）。
	//
	// 写成一个函数是为了让各 guard 抄不出错，也方便将来改语义时只改一处。
	inline bool IsBlockAllMode(ULONG mode) noexcept
	{
		return mode == static_cast<ULONG>(Mode::BlockAll);
	}

	// ⚠️ 完全拦截模式（安全版，ini: mode=block_all_safe）—— 与 BlockAll 的唯一区别：
	//
	//   **进程创建（NtCreateUserProcess / NtCreateProcessEx / NtCreateProcess）
	//   在命中「可信来源」时放行。**
	//
	//   动机（实测驱动）：BlockAll 下样本 RunPE 的第一步 CreateProcess(notepad.exe)
	//   被无条件拒掉，看起来"防住了"，但代价是**所有**正常程序也起不来
	//   （桌面程序打不开、安装器失败）。而拦住创建并不等于防住注入 ——
	//   注入的真身在**下一步**（跨进程 WriteVirtualMemory / ProtectVirtualMemory
	//   / CreateRemoteThread / QueueApcThread）。
	//
	//   因此本模式把判据前移到"来源可信与否"：
	//     · 来源可信（%SystemRoot%\ / Program Files，且微软签名）→ 放行创建，
	//       但后续的跨进程内存 / 线程 / APC 操作**照样全拦** → 注入链仍断。
	//     · 来源不可信（用户目录 / Temp / Downloads / 盘根 …）→ 创建直接拒。
	//
	//   ★ 关键：**放行的只是"创建"**。memory / thread / APC 那五个 hook 的
	//     BlockAll 语义**必须原样保留**，否则本模式退化成 log，
	//     等于把整套拦截关掉（见 process_guard.cpp 各 Evaluate* 的注释）。
	//
	//   调用方约定：只有"进程创建"路径才应该问这个函数；
	//   注册表 / 文件 / 网络 / 内存 / 线程 / APC 一律仍走 IsBlockAllMode 的语义。
	inline bool IsBlockAllSafeMode(ULONG mode) noexcept
	{
		return mode == static_cast<ULONG>(Mode::BlockAllSafe);
	}

	// 两种"完全拦截"模式的合取 —— 用于非进程创建的那一大票 guard：
	// 它们不区分 Safe 与否，语义完全一致（一律 Block）。
	// 这样各处 guard 的 `if (IsBlockAllMode(mode))` 改成
	// `if (IsAnyBlockAllMode(mode))` 即可，不必各自认识 BlockAllSafe。
	inline bool IsAnyBlockAllMode(ULONG mode) noexcept
	{
		return IsBlockAllMode(mode) || IsBlockAllSafeMode(mode);
	}

	// 询问结果。
	enum class Verdict : ULONG
	{
		Deny = 0,
		Allow = 1,
		AllowAlways = 2, // 允许，并记住这个进程 + 这个键
		DenyAlways = 3,  // 拒绝，并记住
	};

	// 被监控的注册表操作。数值会写进事件流，改动需同步 AbiVersion。
	//
	// 分三类：
	//   [键级写操作]  CreateKey / OpenKey / SetValueKey / DeleteKey / DeleteValueKey
	//                 / RenameKey / SetInformationKey / FlushKey
	//                 参数里能拿到键句柄，可拦截。
	//   [键级读操作]  QueryValueKey / EnumerateKey / EnumerateValueKey / QueryKey
	//                 只记录，永不拦截。默认关闭。
	//   [Hive 级操作] LoadKey / UnloadKey / SaveKey / RestoreKey / ReplaceKey
	//                 操作对象是"注册表配置单元文件"而不是键，可拦截 ——
	//                 这是原版覆盖不到的真正缺口：NtLoadKey 能把任意 hive
	//                 挂到 HKLM\SYSTEM 下，NtSaveKey 能把 SAM 导出来。
	enum class Op : ULONG
	{
		CreateKey = 1,
		OpenKey = 2,
		SetValueKey = 3,
		DeleteKey = 4,
		DeleteValueKey = 5,
		RenameKey = 6,
		FlushKey = 7,
		QueryValueKey = 8,
		EnumerateKey = 9,
		EnumerateValueKey = 10,
		QueryKey = 11,
		SetInformationKey = 12,
		LoadKey = 13,
		UnloadKey = 14,
		SaveKey = 15,
		RestoreKey = 16,
		ReplaceKey = 17,
		LoadKeyEx = 18,
		UnloadKeyEx = 19,
		SaveKeyEx = 20,
	};

	// 操作的对象种类。Hive 级操作没有键句柄，只有文件路径，
	// 弹窗和日志都得知道该展示哪一份路径。
	enum class TargetKind : ULONG
	{
		Key = 0,  // 普通键操作，路径在 KeyPath
		Hive = 1, // hive 文件操作，文件路径在 KeyPath（复用同一段缓冲，不另开字段）
	};

	//
	// 事件作用在哪一类对象上。注册表和文件共用同一个 Event 结构、
	// 同一条通道、同一套统计与界面 —— Op 的数值空间分开，靠这个字段
	// 决定该用注册表语义还是文件语义去解释 Op。
	//
	// 为什么要合并而不是各开一条通道：
	//   通道、统计、日志页、询问弹窗、通知卡片这几层都是"按事件渲染"，
	//   开两条就是把这些逻辑整份复制一遍。用一个判别字段区分，
	//   每层只多一个分支，新增一类监控对象的成本就只在 hook 层。
	//
enum class ObjectType : ULONG
{
	Registry = 0,
	File = 1,
	Process = 2, // 进程创建 / 终止
	Thread = 3,  // 线程创建（重点是远程线程 —— 注入的核心手法）
	Driver = 4,  // 内核驱动加载 / 卸载（NtLoadDriver 服务方式）
	Network = 5, // 网络连接 / 发送 / 监听 / 域名解析（ws2_32 用户态层）
	//
	// 以下三类是"隐私采集面"。它们的共同点：本身不是破坏性操作
	// （不改数据、不装东西），但都是**窃听**——摄像头看你在干什么、
	// 钩子记录你的鼠标键盘、截屏拿走你的屏幕内容。木马/间谍软件的
	// 标配三件套，也是正常软件会用到的东西，所以判据不是"危险"
	// 而是"需要用户知情"。
	//
	Camera = 6,    // 摄像头 / 麦克风访问（VFW capCreateCaptureWindow + Media Foundation 设备源）
	InputHook = 7, // 鼠标 / 键盘钩子（SetWindowsHookEx + 原始输入）—— 记录输入 = 键盘记录器
	Screen = 8,    // 屏幕捕获（BitBlt/StretchBlt 源为屏幕 DC + PrintWindow）
	//
	// 以下三类是"绕过后门面"。命名沿用能力边界：挂的都是用户态出口，
	// 手工映射 DLL / 直 syscall / 复制 token 仍能绕过 —— 定位是可见性。
	//
	DllLoad = 9,     // DLL 加载 / 劫持（LdrLoadDll + NtMapViewOfSection + 已知白加黑路径）
	Clipboard = 10,  // 剪贴板读取（OpenClipboard + GetClipboardData）—— 密码/钱包的标准窃取面
	ProcessSpawn = 11, // 进程创建旁路（ShellExecuteEx / WinExec / CreateProcessWithToken/Logon）

	//
	// v11：服务安全描述符变更。
	//
	// ⚠️ 为什么单开一类而不并进 Driver：驱动那类挂的是"装/改/启服务"，
	//    判据是"二进制路径 + 服务类型"。而**改服务 DACL 不改二进制、
	//    更不是内核驱动** —— 它是纯提权手法：
	//        sc sdset <服务> "D:(A;;RPWPCR;;;WD)"   给 Everyone 加服务控制权
	//    → 普通用户从此能 "sc config <服务> binPath= ..." 或直接重启服务，
	//      把一个 SYSTEM 服务变成任意代码执行。
	//    这类操作在 Driver 那套枚举里没有合适的判据位，硬塞会污染
	//    "驱动安装"的语义，所以单列。
	//
	ServiceConfig = 12, // 服务 / 安全对象权限变更（SetServiceObjectSecurity / NtSetSecurityObject）

	//
	// v12：两条**持久化**路径。
	//
	// ⚠️ 为什么这两条要单开类，而不并进 Registry / DllLoad：
	//
	//   COM/OLE 劫持 —— 攻击面是 HKCR\CLSID\{guid}\InprocServer32 指向
	//     用户可写目录的 DLL。**注册表 hook 只看得到"写了那个键"**，
	//     看不到"某进程真的按这个 CLSID 加载了那个 DLL" ——
	//     而后者才是可以拦下来的动作（前者早已发生）。所以单列一类，
	//     判据落在**激活路径**上（CoCreateInstance / CoGetClassObject）。
	//
	//   计划任务持久化 —— schtasks / 任务计划程序最终都落到
	//     HKLM\...\Schedule\TaskCache\Tree\<任务名> 的写操作上，但
	//     **调用方是 svchost 里的 Task Scheduler 服务**，而它在白名单里
	//     （和 SCM 盲区同一个道理）。所以除了注册表规则表，还要在
	//     **调用方一侧**挂 COM 入口（ITaskService::RegisterTaskDefinition）。
	//
	//   两类判据都不看"路径敏不敏感"，看的是**"这次动作有没有建立持久化"** ——
	//   与"高危分级铁律②"一致。
	//
	ComHijack = 13,     // COM / OLE 激活劫持（CoCreateInstance / CoGetClassObject + CLSID 映射到用户可写 DLL）
	ScheduledTask = 14, // 计划任务持久化（TaskCache 注册表写 + ITaskService 注册入口）

	//
	// v13：两条"凭据窃取 / 事件订阅"路径。
	//
	// ⚠️ 为什么各单开一类，而不并进 ProcessSpawn / ComHijack：
	//
	//   令牌窃取 —— 攻击链是"拿句柄 → 复制 → 冒充/启动进程"，最终形态
	//     确实长得像 CreateProcessWithToken（已在 ProcessSpawn 里）。但
	//     **同一类里的判据是"创建了进程"**，而这条链上最关键的早期信号
	//     （SeDebugPrivilege 提权、OpenProcessToken 拿到可复制句柄）
	//     根本不创建任何进程 —— 塞进 SpawnOp 会丢信号。判据要分档
	//     （拿句柄=可疑 / 复制后使用=高危），所以单列。
	//
	//   WMI 事件订阅 —— 持久化 + 无文件执行。落到磁盘上是
	//     `__EventFilter` / `__EventConsumer` / `__FilterToConsumerBinding`
	//     三个 WMI 类的实例，走的是 IWbemServices COM 接口（纯虚函数，
	//     没有可挂的导出）。它既是**持久化**（重启后仍在），又是
	//     **无文件执行**（消费动作可以直接是 command line），与
	//     ScheduledTask 的定位互补但实现路径完全不同，所以单列。
	//
	TokenTheft = 15,      // 令牌窃取 / 冒充（OpenProcessToken → DuplicateTokenEx → Impersonate / CreateProcessAsUser）
	WmiSubscription = 16, // WMI 事件订阅持久化（__EventFilter + __EventConsumer + __FilterToConsumerBinding）

	//
	// v15：宿主劫持 / 加载器面。
	//
	// ⚠️ 为什么单开一类，而不并进 Registry / DllLoad / ProcessSpawn：
	//
	//   这一类的共同点是「**劫持一个可信宿主，让它替攻击者加载/执行我们的东西**」。
	//   攻击者自己不加载任何东西 —— 是别人（explorer、lsass、每个新进程、
	//   每个 COM 激活者）在按攻击者留下的配置去加载。所以：
	//
	//     · 注册表全局注入键（AppInit_DLLs / AppCertDlls / IFEO Debugger /
	//       LSA Authentication Packages / Winlogon Notify / ShellServiceObject）
	//       —— RegistryGuard 只能看到"写了那个键"，看不到"下次每个进程启动
	//       都会按它加载"。而且**值名**才是关键（AppInit_DLLs 的键本身
	//       是正常系统键，写的值才是注入），现有的 kRegistryRules 只按
	//       路径前缀匹配，粒度不够。
	//
	//     · 加载器侧加载变体 —— DllLoadGuard 只挂了 LdrLoadDll。但真实加载
	//       还有 LoadLibraryExW、LdrRegisterDllNotification 回调注册、
	//       以及跨进程 NtMapViewOfSection（反射式注入 / 手工映射不经过
	//       LdrLoadDll）。这些是"加载器"本身被用到的路径，语义是
	//       "加载动作"而不是"某个 DLL 的名字"。
	//
	//     · 远程映射注入 —— NtMapViewOfSection 把段映射进**别的进程**、
	//       QueueUserAPC 投递 APC 载荷 —— 是 v14 注入链（Allocate/Write/
	//       Protect/CreateThread）之外的**另一条注入路径**，形态完全不同
	//       （不写内存、不起线程，靠映射 + 劫持已有线程）。
	//
	//     · 凭据宿主劫持 —— Security Support Provider / Credential Provider
	//       注册到 LSASS / 登录界面，是"劫持凭据处理宿主"。与 TokenTheft
	//       不同：TokenTheft 是"偷现成的令牌"，这里是"让系统以后把凭据
	//       交给我们的组件"。判据落在注册点，不在运行时。
	//
	//   共用判据口径：**配置点本身可能合法，只有当它指向用户可写目录 /
	//   非系统路径 / 跨进程时才高危**（见各 RiskReason）。这与 v12 的
	//   COM 劫持、v14 的跨进程内存同一思路 —— 防止把正常软件判成劫持。
	//
	HostHijack = 17, // 宿主劫持 / 加载器（注册表全局注入键 + 加载器侧加载 + 远程映射 + 凭据宿主）
};

	// 文件的写类操作。数值从 1 开始，与注册表的 Op 各自独立
	// （靠 Event::ObjectType 区分是哪一个枚举）。
	//
	// 选点原则与注册表一致：拦截"改内容/改元数据/换名字"的动作，
	// 只读打开不拦（太热）。文件系统比注册表热得多，所以默认
	// 连写类也不挂，由 r3shieldcore.ini 的 hook_file 显式开启。
	enum class FileOp : ULONG
	{
		Create = 1,        // NtCreateFile —— 建/覆盖/打开，靠 disposition 判断是不是真创建
		Open = 2,          // NtOpenFile —— 只管打开，不带创建
		Write = 3,         // NtWriteFile —— 往已有句柄写数据
		Delete = 4,        // NtSetInformationFile(Disposition=1) —— 标记删除
		Rename = 5,        // NtSetInformationFile(FileName=10) —— 改名/移动
		SetBasicInfo = 6,  // NtSetInformationFile(BasicInformation=4) —— 时间戳伪造
		SetSecurity = 7,   // NtSetSecurityObject —— 改 ACL
		SetEa = 8,         // NtSetEaFile —— 扩展属性
		Truncate = 9,      // NtSetEndOfFileInformation —— 截断
	};

	//
	// 进程操作。数值从 1 开始，与 Op / FileOp 各自独立
	// （靠 Event::ObjectType 区分）。
	//
	// 用户态只能拦"创建"，拦不了"终止" —— NtTerminateProcess 一调用
	// 目标就没了，没有"先问一句"的余地。所以 Terminate 只记录。
	//
	enum class ProcessOp : ULONG
	{
		Create = 1,    // NtCreateUserProcess / NtCreateProcessEx —— 创建进程
		Terminate = 2, // NtTerminateProcess —— 终止（只记录，不可拦）
		Open = 3,      // NtOpenProcess —— 请求进程句柄；目标受保护时危险权限位被剥掉

		//
		// v14：代码注入链的前三步。
		//
		// ⚠️ 为什么必须补：只挂 NtCreateThreadEx（远程线程）等于只堵了
		//    注入的**最后一步**。完整的注入链是四步，前三步此前完全裸奔：
		//
		//      ① NtAllocateVirtualMemory  —— 在目标进程里申请可执行内存
		//      ② NtWriteVirtualMemory     —— 把 shellcode / DLL 路径写进去
		//      ③ NtProtectVirtualMemory   —— 把页改成可执行（PAGE_EXECUTE_*）
		//      ④ NtCreateThreadEx         —— 起远程线程，从①的内存开始跑
		//
		//    反射式 DLL 注入、shellcode 注入、进程镂空（process hollowing）、
		//    APC 注入全都走这条链，只是四步的先后/组合不同。
		//
		// ⚠️ 判据的**唯一关键**是"目标进程 ≠ 当前进程"：
		//    这几个 API 在每个进程里都被合法地高频调用 ——
		//    .NET/Java 的 JIT、浏览器的 JIT、任何带 GC 的运行时都在
		//    自己进程里 Allocate + Write + Protect。**对本进程一律放行**，
		//    否则整个系统立刻瘫掉（这是本类 hook 的存活前提）。
		//    跨进程再叠加"权限位是否齐全"才是真注入特征。
		//
		WriteMemory = 4,    // NtWriteVirtualMemory —— 往别的进程写内存（★ 最直接的铁证）
		ProtectMemory = 5,  // NtProtectVirtualMemory —— 改别的进程内存页权限为可执行
		AllocateMemory = 6, // NtAllocateVirtualMemory —— 在别的进程里申请可执行内存

		//
		// v18：老 API NtCreateProcess（不是 Ex 变体）。
		//
		// ⚠️ 为什么单独立一个 Op 而不是复用 Create：
		//    NtCreateProcess 与 NtCreateProcessEx / NtCreateUserProcess 的
		//    **参数语义完全不同**，判据也必须不同：
		//
		//      NtCreateProcessEx(ProcessHandle, DesiredAccess, ObjectAttributes,
		//                        ParentProcess, Flags, SectionHandle, DebugPort,
		//                        ExceptionPort, JobMemberLevel)
		//      NtCreateProcess  (ProcessHandle, DesiredAccess, ObjectAttributes,
		//                        ParentProcess, InheritObjectTable, SectionHandle,
		//                        DebugPort, ExceptionPort)   ← 8 参，不吃 Flags
		//
		//      关键差异：
		//        · **完全不接受 RTL_USER_PROCESS_PARAMETERS** —— 没有命令行、
		//          没有当前目录、没有环境块。NtCreateProcessEx 那套
		//          "从参数块取 ImagePath 再比进程路径规则"的判据在这里
		//          **一个字都用不上**（照抄 = 永远拿不到路径 = 永远非高危）。
		//        · 镜像来源**只能是 SectionHandle**（一个已映射的 image
		//          section）。调用方通常是手拿 NtCreateSection 先建段，
		//          再 NtCreateProcess 起进程 —— 这是**进程镂空 / 反射加载**
		//          的经典组合，正常程序几乎不用。
		//        · 因此判据只能靠**特征**，不能靠路径：
		//            ① SectionHandle 为 NULL（无镜像段 → 空进程，极小概率正常）；
		//            ② 传了 DebugPort / ExceptionPort（调试 / 劫持意图）；
		//            ③ ParentProcess 传入非 NULL 且打开的是**别人**的进程句柄
		//               （刻意伪造父进程，躲避父链关联检测）。
		//        · 反过来说：**这个 API 在正常系统上出现频率极低** ——
		//          Windows 自身的 CreateProcess 走的是 NtCreateUserProcess。
		//          所以这里宁可判得宽一点（出现即记高危），也不放过。
		//
		CreateLegacy = 7, // NtCreateProcess —— 无参数块的裸建进程（镂空/反射加载）
	};

	//
	// 线程操作。
	//
	// 重点是**远程线程**：target pid != 自己的进程。这是注入、外挂、
	// 大多数恶意代码横向移动的核心手法 —— 一个进程凭空在另一个进程里
	// 起了个线程，几乎总是可疑的。
	//
	enum class ThreadOp : ULONG
	{
		Create = 1,    // NtCreateThreadEx —— 创建线程（远程 / 本进程）
		Terminate = 2, // NtTerminateThread —— 终止（只记录）

		//
		// v18：老 API NtCreateThread（不是 Ex 变体）。
		//
		// ⚠️ 参数语义与 NtCreateThreadEx 不同，判据的**输入也不同**：
		//
		//      NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes,
		//                       ProcessHandle, StartRoutine, Argument, CreateFlags,
		//                       ZeroBits, StackSize, MaximumStackSize, AttributeList)
		//                        ← 显式传 ProcessHandle
		//      NtCreateThread  (ThreadHandle, DesiredAccess, ObjectAttributes,
		//                       ProcessHandle, ClientId, ThreadContext,
		//                       InitialTeb, CreateSuspended)
		//                        ← 也是显式传 ProcessHandle，但多一个
		//                          ClientId（可指定线程 id）
		//
		//      好消息：NtCreateThread 同样**收 ProcessHandle**，所以
		//      "目标进程 ≠ 当前进程"这条远程线程判据可以**原样复用**。
		//      唯一要单独处理的是 ClientId —— 传了非 NULL ClientId 意味着
		//      调用方在**指定线程 id**，正常代码不会这么做。
		//
		CreateLegacy = 3, // NtCreateThread —— 老式远程线程创建
	};

	//
	// 驱动操作。
	//
	// 用户态拿到的是"服务方式加载"（NtLoadDriver 吃的是注册表里
	// HKLM\SYSTEM\CurrentControlSet\Services\<名> 的 ImagePath）。
	// 这是用户态能观察到内核驱动加载的唯一入口，剩下的是真内核回调
	// （PsSetLoadImageNotifyRoutine）的活。
	//
	// ⚠️ **但只挂 NtLoadDriver 是远远不够的**（2026-09-25 实测发现）：
	//    驱动加载的正常路径是
	//      应用 → advapi32!CreateServiceW → RPC → services.exe(SCM)
	//                                            ├─ 写 Services\<名> 键
	//                                            └─ 调 NtLoadDriver
	//    也就是说**写服务键和调 NtLoadDriver 都发生在 services.exe 里**，
	//    而 services.exe 在 %SystemRoot%\ 下 → 命中 ComputeBypass → 一个 hook 都不挂。
	//    实测后果：全拦模式（block_all）下驱动服务照样装成功，自家日志里
	//    DRV 事件 0 条。所以必须**在调用方一侧**补挂 advapi32 的服务 API。
	//
	//    残余盲区（补了也拦不到）：
	//      · 走 System32 里的 LOLBin 装（sc.exe / powershell.exe / cmd.exe 都是
	//        %SystemRoot%\ → bypass）—— 除非把它们从白名单摘出来；
	//      · 直调 RPC / \Device\NtControlPipe 装；
	//      · 内核态直接调 ZwLoadDriver（真边界要 PsSetLoadImageNotifyRoutine）。
	//
	enum class DriverOp : ULONG
	{
		Load = 1,   // NtLoadDriver —— 把 .sys 加载进内核
		Unload = 2, // NtUnloadDriver

		// ---- 以下三个是 advapi32 服务 API（补 SCM 盲区，ABI v9）----
		CreateService = 3,        // CreateServiceW —— 装服务（含驱动服务，★ 最关键）
		ChangeServiceConfig = 4,  // ChangeServiceConfigW —— 改已有服务的 ImagePath
		StartService = 5,         // StartServiceW —— 启动服务（驱动加载的实际触发点）
	};

	//
	// 网络操作。数值从 1 开始，与其它 Op 枚举各自独立
	// （靠 Event::ObjectType 区分）。
	//
	// ⚠️ 能力边界：这里挂的是 **ws2_32.dll 用户态出口**。绕过它太容易了 ——
	//    静态链接 socket、直接 DeviceIoControl 打 \Device\Afd、WinHTTP/WinINet
	//    内部走自己的路径、或者干脆起个子进程传数据。所以网络 hook 是
	//    "可见性工具"而不是"防火墙"：能看得见大多数正常程序在连谁，
	//    拦不住铁了心要绕的东西。真正的网络执法在内核（WFP / NDIS / TDI）。
	//
	enum class NetOp : ULONG
	{
		Connect = 1, // connect / WSAConnect —— 主动外连（重点）
		SendTo = 2,  // sendto / WSASendTo —— 无连接发送（UDP 外发，被滥用于 C2 信标）
		Bind = 3,    // bind —— 绑定本地端口，含"监听前的准备"
		Listen = 4,  // listen —— 进入监听（后门/远控的标志）
		Accept = 5,  // accept / WSAAccept —— 接受入站连接
		DnsQuery = 6, // gethostbyname / getaddrinfo —— 域名解析（暴露 C2 域名）

		//
		// v18：绕开 ws2_32 的 AFD 直发路径。
		//
		// ⚠️ 为什么必须补：上面挂的全是 ws2_32.dll 的用户态出口。
		//    而 ws2_32 底下走的是 **\Device\Afd** —— 谁都可以自己
		//    CreateFile("\\.\Afd") 拿句柄，然后直接
		//      DeviceIoControl(h, IOCTL_AFD_SEND, ...)      0x1201F
		//      DeviceIoControl(h, IOCTL_AFD_RECV, ...)      0x1203F
		//      DeviceIoControl(h, IOCTL_AFD_SEND_DATAGRAM)  0x1207F
		//    把数据送出去 —— **一个 ws2_32 reload 都不需要**。
		//    这就是 file_guard.cpp:405 和 network_guard.h:13 注释里
		//    反复点名的绕过路径，此前完全裸奔。
		//
		//    挂点选 **ntdll!NtDeviceIoControlFile**（不是 DeviceIoControl，
		//    因为后者 → kernel32 → ntdll，挂 ntdll 层能同时覆盖直接调
		//    NtDeviceIoControlFile 的代码）。
		//
		// ⚠️ 性能红线：NtDeviceIoControlFile 是**全系统最高频**的 syscall
		//    之一 —— 每一次文件 IO、每一次 socket 收发、每一次驱动交互
		//    都走它。所以 hook 里**第一步必须只比对 IoControlCode**，
		//    不在 {0x1201F, 0x1203F, 0x1207F} 里就立刻原样透传，
		//    绝不做任何字符串/路径解析。
		//
		DeviceIo = 7, // NtDeviceIoControlFile —— \Device\Afd 直发（AFD_SEND/RECV）
	};

	//
	// 摄像头 / 麦克风操作。
	//
	// ⚠️ 能力边界：用户态只有两条路能看到"打开了摄像头"——
	//   ① VFW 老接口 avicap32!capCreateCaptureWindow（还有程序在用）
	//   ② Media Foundation：mfplat!MFCreateDeviceSource 建媒体源，
	//      再由 mfreadwrite!MFCreateSourceReaderFromMediaSource 包成读取器
	//
	//   看不到的：DirectShow（CoCreateInstance(CLSID_VideoInputDeviceCategory)
	//   之后全是 COM 虚函数，没有可 hook 的导出）、以及自带驱动的程序
	//   直连内核流（ks.sys / \Device\Video*）。定位同样是**可见性**，
	//   不是"保证摄像头打不开"。
	//
	// 判据：**打开就报**（OpenDevice / CreateSourceReader 一律高危）。
	// 摄像头不是"偶尔误伤"的东西 —— 正常程序开摄像头时用户应该在场，
	// 所以哪怕会烦一点也要问。枚举设备（EnumDevice）不算，只记录。
	//
	enum class CameraOp : ULONG
	{
		OpenDevice = 1,         // capCreateCaptureWindow —— VFW 打开摄像头
		CreateDeviceSource = 2, // MFCreateDeviceSource —— MF 建设备源（摄像头/麦克风）
		CreateSourceReader = 3, // MFCreateSourceReaderFromMediaSource —— 建读取器（开始取帧）
		EnumDevice = 4,         // MFEnumDeviceSources / capGetDriverDescription —— 只记录

		//
		// v13：音频采集与环回。
		//
		// ⚠️ 为什么并进 Camera 类而不单开一类：设备枚举、DeviceSource、
		//    SourceReader 这几条路径**完全共用**（MF 里摄像头和麦克风
		//    是同一套 API，靠 MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE 区分）。
		//    单开一类就要把设备枚举逻辑整份复制一遍，等于凭空多一份
		//    噪音源。这里只补"音频独有"的入口。
		//
		// 音频比摄像头更隐蔽，所以判据要更严：
		//   - 麦克风：录你说话。正常程序（会议软件/语音输入）会开，
		//     所以要报 —— 与摄像头同理"用户应知情"。
		//   - **环回（loopback）**：录**系统输出** —— 也就是把电脑
		//     正在播的声音全录下来。正常场景几乎只有"录音软件/直播"
		//     一种，而恶意场景是"录 VoIP 通话 / 录会议"。AUDCLNT_
		//     STREAMFLAGS_LOOPBACK 这个标志本身就很说明意图 → 高危。
		//
		WasapiCapture = 5,  // IAudioClient::Initialize —— WASAPI 采集（麦克风，非环回）
		WasapiLoopback = 6, // IAudioClient::Initialize + AUDCLNT_STREAMFLAGS_LOOPBACK —— 录系统输出
		MicOpen = 7,        // waveInOpen / mciSendCommand(MCI_OPEN, 录音设备) —— 老式波形录音
	};

	//
	// 输入钩子操作。
	//
	// 键盘记录器 / 鼠标记录器的标准手法，也是正常软件的常用功能
	// （输入法、快捷键、辅助工具）。所以判据要分层：
	//
	//   WH_MOUSE_LL(14) / WH_KEYBOARD_LL(13) —— **全局**低级钩子，
	//     不需要往别人进程里注入 DLL 就能拿到全系统输入 → 高危
	//   WH_MOUSE(7) / WH_KEYBOARD(2) + dwThreadId==0 —— 全局钩子，
	//     需要把 DLL 注入到所有 GUI 进程 → 高危
	//   WH_MOUSE / WH_KEYBOARD + dwThreadId!=0 —— 只作用于指定线程，
	//     通常是程序自己监听自己的窗口 → 只记录
	//   WH_JOURNALRECORD(0) / WH_JOURNALPLAYBACK(1) —— 录制/回放输入 → 高危
	//   其它 wh + dwThreadId==0 —— 同样是"注入所有 GUI 进程" → 高危
	//
	// RegisterRawInputDevices 是另一条路：不装钩子，直接读原始输入。
	// 普通用法（游戏读鼠标）只记录；带 RIDEV_INPUTSINK 表示**后台**
	// 也要收输入（窗口不在前台也收）→ 高危。
	//
	enum class HookOp : ULONG
	{
		SetMouseHook = 1,     // SetWindowsHookEx(WH_MOUSE / WH_MOUSE_LL)
		SetKeyboardHook = 2,  // SetWindowsHookEx(WH_KEYBOARD / WH_KEYBOARD_LL)
		SetInputJournal = 3,  // SetWindowsHookEx(WH_JOURNALRECORD / WH_JOURNALPLAYBACK)
		SetOtherHook = 4,     // 其它 wh —— 全局时等于往所有 GUI 进程注入
		RegisterRawInput = 5, // RegisterRawInputDevices —— 绕过消息钩子直接读原始输入
		Unhook = 6,           // UnhookWindowsHookEx —— 只记录（拆钩子不是攻击行为）

		//
		// v11：不装钩子的键盘记录路径。
		//
		// ⚠️ 前面挂的 SetWindowsHookEx / RegisterRawInputDevices 都要求
		//    "安装一个接收端"。**轮询式键盘记录器不装任何东西** —— 它
		//    就是在一个循环里反复问系统"某个键现在按着没有"：
		//        for (;;) for (VK in 0..255) if (GetAsyncKeyState(VK) & 1) Log(VK);
		//    这条路径完全绕开钩子，而且实现起来只有三行。
		//
		//    判据不能是"调了就报"：输入法、游戏、辅助工具都在高频轮询，
		//    无差别上报等于日志雪崩。这里用**调用密度**过滤 ——
		//    单线程在时间窗内轮询超过阈值才认作键盘记录器（见
		//    InputHookGuard 里的轮询检测器）。
		//
		PollAsyncKeyState = 7, // GetAsyncKeyState —— 轮询式键盘记录（按密度判）
		PollKeyState = 8,      // GetKeyState / GetKeyboardState —— 同上
		SetEventHook = 9,      // SetWinEventHook —— 监听前台窗口/焦点变化，用于行为画像

		//
		// v14：**反向**输入 —— 不是"读用户在按什么"，而是"代替用户去按"。
		//
		// ⚠️ 前面 1~9 全是"捕获面"（键盘记录器、截屏、摄像头那一类窃听）。
		//    这里补的是**输出面**：把合成的键鼠事件喂给系统。
		//
		//    为什么值得单独一类：
		//      · 远控木马（RAT）的核心动作就是远程代操作；
		//      · **UAC 绕过**的经典链是 SetForegroundWindow + SendInput
		//        自动去点那个"是"按钮（用户看到的是一闪而过的窗口）；
		//      · 自动化外挂 / 宏 / 脚本也走这条路 —— 所以**不能"调了就报"**，
		//        必须带危害判据（见 SendInput 的密度检测器）。
		//
		SendInputEvents = 10, // SendInput / keybd_event / mouse_event —— 合成键鼠输入
		BlockUserInput = 11,  // BlockInput —— 冻结用户输入（勒索软件锁屏的标配）
		ClipCursorLock = 12,  // ClipCursor —— 把鼠标锁在某个矩形内（伪造登录框骗密码）
	};

	//
	// 屏幕捕获操作。
	//
	// 截屏的 GDI 路径固定是三步：
	//   ① GetDC(NULL) / GetDC(GetDesktopWindow()) 拿屏幕 DC
	//   ② CreateCompatibleDC + CreateCompatibleBitmap 建内存 DC
	//   ③ BitBlt / StretchBlt 把屏幕 DC 拷进内存 DC，然后 GetDIBits 取像素
	//
	// 所以判据落在 ③ 的**源 DC 是不是屏幕/桌面 DC** 上 ——
	// 用 WindowFromDC(hdcSrc) 判断：内存 DC 返回 NULL，窗口 DC 返回该窗口，
	// 屏幕/桌面 DC 返回桌面窗口句柄。这一步把"程序自己画界面"和
	// "把屏幕拷走"彻底分开了 —— BitBlt 本身极高频，不加这层过滤
	// 日志会被重绘刷爆。
	//
	// PrintWindow 是另一条路：直接抓指定窗口的内容（包括被遮挡的），
	// 频率低、意图明确 → 无差别高危。
	//
	// ⚠️ 看不到的：Desktop Duplication API（dxgi!IDXGIOutputDuplication::
	//    AcquireNextFrame，COM 虚函数）、Windows.Graphics.Capture、
	//    以及 DirectX 全屏抓帧。现代截屏工具越来越多走这条路。
	//
	enum class ScreenOp : ULONG
	{
		BitBlt = 1,     // BitBlt 且源 DC 是屏幕/桌面 DC —— 全屏截取
		StretchBlt = 2, // StretchBlt 且源 DC 是屏幕/桌面 DC —— 缩放截取
		PrintWindow = 3, // PrintWindow —— 抓指定窗口（含被遮挡内容）

		//
		// v11：GDI 截屏的"第三条路"。
		//
		// ⚠️ 为什么前面挂 BitBlt 还不够：截屏不必经过 BitBlt。
		//    GetDC(NULL) 拿到屏幕 DC 后**直接** GetDIBits(screenDc, hbm, ...)
		//    就能把屏幕像素读出来 —— 少了"拷进内存 DC"那一步。
		//    实测（tools/dibprobe.cpp）：这条路径下 GetDIBits 的 hdc 参数
		//    仍然是屏幕 DC，WindowFromDC(hdc) == 桌面窗口 → 同一个判据可用。
		//    （hdc 传 NULL 会直接 err=87 ERROR_INVALID_PARAMETER，所以
		//      "真实调用一定带 DC"，判据不会漏。)
		//
		GetDIBits = 4, // GetDIBits 且 hdc 是屏幕/桌面 DC —— 绕过 BitBlt 直接读屏
	};

	//
	// DLL 加载 / 劫持操作。
	//
	// ⚠️ 能力边界：这是 ntdll 层的加载出口。直接手工映射 PE（自己解析重定位
	//    再调 NtMapViewOfSection 的"手动映射"变体）能绕过 LdrLoadDll。
	//    真正要抓的判据是"从哪加载的"（磁盘路径），不是"通过哪个 API"。
	//
	enum class DllLoadOp : ULONG
	{
		LoadLibrary = 1,   // LdrLoadDll —— 常规 LoadLibrary* 的底层出口
		MapSection = 2,    // NtMapViewOfSection(SEC_IMAGE) —— 映射 DLL 映像
		ManualMap = 3,     // 手工映射特征（无 LdrLoadDll，直接映射可执行 section）
	};

	//
	// 宿主劫持 / 加载器操作（v15）。
	//
	// ⚠️ 与 DllLoadOp 的区别：DllLoad 问的是"加载了哪个 DLL"，
	//    这里问的是"**动用了哪条加载/注入机制**"。同一次加载可能两者都报：
	//    DllLoad 记"加载了 C:\evil.dll"，HostHijack 记"用的是跨进程映射"。
	//
	// 四条子面（对应 ObjectType::HostHijack 的四类攻击）：
	//
	//   ① 注册表全局注入键 —— 写 AppInit_DLLs / AppCertDlls / IFEO Debugger /
	//      LSA Auth Packages / Winlogon Notify / ShellServiceObjectDelayLoad。
	//      这一组的特征是"**值名**才决定危害"，键本身往往是正常系统键。
	//      ⚠️ 所以判据函数签名要带 valueName（现有的 RegistryRule 只按前缀）。
	//
	//   ② 加载器侧加载变体 —— LoadLibraryExW / LdrRegisterDllNotification。
	//      LdrLoadDll 是底层出口已挂，但**通知回调注册**是另一条：
	//      注册一个回调，别人加载 DLL 时我来决定放不放行（劫持加载决策）。
	//
	//   ③ 远程映射注入 —— NtMapViewOfSection 把段映射进**别的进程**、
	//      QueueUserAPC 往别的进程投 APC。这是 v14 注入链之外的**第二条路**：
	//      不 Write 内存、不起线程，靠映射已有 section + 劫持别人线程。
	//      ⚠️ 判据的核心仍是"目标进程 ≠ 自己"（同 v14 内存操作）。
	//
	//   ④ 凭据宿主劫持 —— Security Packages / Credential Provider 注册，
	//      让 LSASS / 登录界面把凭据交给我们的组件。判据落在**注册点**。
	//
	enum class HostHijackOp : ULONG
	{
		// ---- ① 注册表全局注入键 ----
		// 值名区分子类型，Op 只需表达"这是一次宿主注入键写"。
		InjectionRegistryKey = 1, // 写上述任一全局注入键的**值**

		// ---- ② 加载器侧加载变体 ----
		LoadLibraryEx = 2,          // LoadLibraryExW —— 带 flags 的加载（可挂起加载 DONT_RESOLVE_DLL_REFERENCES）
		RegisterDllNotification = 3, // LdrRegisterDllNotification —— 注册加载通知回调（劫持加载决策）

		// ---- ③ 远程映射注入 ----
		MapSectionRemote = 4, // NtMapViewOfSection 目标是别的进程 —— 反射式 / 手工映射注入
		QueueApcRemote = 5,   // QueueUserAPC 目标是别的进程 —— APC 注入

		// ---- ④ 凭据宿主劫持 ----
		CredentialHost = 6, // Security Packages / Credential Provider 注册（LSASS / 登录宿主）
	};

	//
	// 剪贴板操作。
	//
	// ⚠️ 只有"读"值得报。写剪贴板（EmptyClipboard/SetClipboardData）是
	//    复制粘贴的常态，读剪贴板才是窃取（密码管理器、钱包、备忘录）。
	//
	enum class ClipboardOp : ULONG
	{
		Open = 1,  // OpenClipboard —— 打开剪贴板（读写的敲门砖）
		Read = 2,  // GetClipboardData —— 真正取走内容
	};

	//
	// 进程创建旁路。
	//
	// ⚠️ 为什么单列：NtCreateUserProcess（ProcessGuard 已挂）是最终出口，
	//    但这些应用层 API 走的是**不同的安全上下文**，信息价值不同：
	//      CreateProcessWithTokenW  → 换个 token 起进程（提权/横向）
	//      CreateProcessWithLogonW  → 用别人的凭据起进程
	//      ShellExecuteEx           → 走 shell，可能触发关联劫持
	//    而 WinExec / system 是"最容易被 shellcode 调用"的一层。
	//
	enum class SpawnOp : ULONG
	{
		ShellExecute = 1,  // ShellExecuteEx{A,W} —— 走 shell 关联
		WinExec = 2,       // WinExec —— 老 API，shellcode 常用
		WithToken = 3,     // CreateProcessWithTokenW —— 携带 token 起进程
		WithLogon = 4,     // CreateProcessWithLogonW —— 携带凭据起进程
		System = 5,        // _wsystem / system —— 拉起 cmd.exe

		//
		// v11：CreateProcessAsUserW —— "换用户身份"三兄弟里最常用的那个。
		//
		// ⚠️ 为什么必须补：CreateProcessWithToken/WithLogon 走的是
		//    Secondary Logon 服务（seclogon），需要该服务在跑；而
		//    CreateProcessAsUserW 直接用调用方**已经持有的 token** 起进程，
		//    不依赖 seclogon —— 服务型恶意代码（拿到 SYSTEM token 后
		//    用它起一个普通会话进程做落地）几乎都走这条，而且它由
		//    advapi32 导出、无服务依赖，比另两个更容易被利用。
		//
		AsUser = 6,        // CreateProcessAsUserW —— 用指定 token 起进程
	};

	//
	// 服务 / 安全对象权限操作（v11）。
	//
	// ⚠️ 判据与 Driver 那类不同：这里看的是"改安全描述符"，不看二进制。
	//    改服务 DACL 本身不改任何文件、不装任何东西，但它是把
	//    "SYSTEM 服务"变成"任意用户可控制的 SYSTEM 代码执行点"的钥匙。
	//
	enum class ServiceConfigOp : ULONG
	{
		SetServiceSecurity = 1, // SetServiceObjectSecurity —— 改服务对象 DACL（sc sdset）
		SetKernelObjectSecurity = 2, // NtSetSecurityObject —— 改任意内核对象 DACL
	};

	//
	// COM / OLE 激活操作（v12）。数值从 1 起，与其它枚举各自独立。
	//
	// ⚠️ 判据：**这次激活要加载的 COM 服务器 DLL/EXE 落在用户可写目录**。
	//    也就是说，光"创建了一个 COM 对象"不算 —— 那太常见（每个进程每秒
	//    都在 CoCreateInstance）。只有当解析出来的服务器路径满足
	//    "非系统目录 + 用户可写"时才上报，这就是"COM 劫持"的特征。
	//
	// 三条路径都要挂（"挂了一个 API ≠ 挂了这件事" 铁律 12）：
	//   CoCreateInstance        —— 最常用的高层入口
	//   CoCreateInstanceEx      —— 远程/多接口变体，还能指定服务器信息
	//   CoGetClassObject        —— 底层入口，拿到 IClassFactory 再 CreateInstance
	//
	enum class ComOp : ULONG
	{
		CreateInstance = 1,   // CoCreateInstance —— 按 CLSID 创建对象（最常用）
		CreateInstanceEx = 2, // CoCreateInstanceEx —— 可指定远程服务器 / 多接口
		GetClassObject = 3,   // CoGetClassObject —— 取 IClassFactory（之后自己 CreateInstance）
	};

	//
	// 计划任务持久化操作（v12）。
	//
	// ⚠️ 真正的执行者是 Task Scheduler 服务（svchost，白名单），
	//    所以调用方一侧的入口是这里唯一的可拦点。
	//
	//   RegisterTaskDefinition —— ITaskService 的注册入口，schtasks / 任务
	//                             计划程序 GUI 最终都走它。
	//   TaskCacheWrite         —— 注册表旁路（直接写 TaskCache 树），
	//                             由注册表 hook 侧识别后归到这一类。
	//
	enum class ScheduledTaskOp : ULONG
	{
		RegisterTaskDefinition = 1, // ITaskService::RegisterTaskDefinition —— 注册/覆盖任务
		CreateFolder = 2,           // ITaskService::GetFolder / CreateFolder —— 建任务目录
		Run = 3,                    // IRegisteredTask::Run —— 立即执行（横向移动常见）
		TaskCacheWrite = 4,         // 直接写 HKLM\...\Schedule\TaskCache（绕过 COM）
	};

	//
	// 令牌窃取 / 冒充操作（v13）。数值从 1 起，与其它枚举各自独立。
	//
	// ⚠️ 判据分档（用户选定的"完整链：拿句柄即可疑 + 复制/使用"）：
	//
	//   一档 · 准备 —— 拿到"可以被复制/被冒充"的令牌句柄。单独出现
	//     不解码任何东西，但它是整条链的起点，而且**几乎没有正常
	//     程序会去 OpenProcessToken 别人的进程**。所以判可疑不判高危
	//     —— 避免把进程管理器、调试器一类的合法需求打成高危。
	//
	//   二档 · 使用 —— 真正把令牌变成了"我现在是那个人"：
	//     DuplicateTokenEx（造可冒充令牌副本）、ImpersonateLoggedOnUser
	//     （本线程变身）、CreateProcessWithTokenW / CreateProcessAsUserW
	//     （用别人的身份起进程）、SetThreadToken（给线程换令牌）。
	//     这一步已经等价于"以该身份执行代码" → 高危。
	//
	//   三档 · 提权 —— AdjustTokenPrivileges 打开 SeDebugPrivilege /
	//     SeImpersonatePrivilege / SeTcbPrivilege。这不是窃取本身，
	//     而是**为窃取铺路**（SeDebug 才能 OpenProcess 高权限进程）。
	//     单独报一档，因为很多工具（Process Hacker 等）会开这些特权。
	//
	//   看不到的：直 syscall（NtOpenProcessToken/NtDuplicateToken）、
	//     以及内核态的令牌操作。定位是**可见性**。
	//
	enum class TokenTheftOp : ULONG
	{
		OpenProcessToken = 1,        // OpenProcessToken —— 拿某进程的令牌句柄（可疑）
		OpenThreadToken = 2,         // OpenThreadToken —— 拿某线程的令牌句柄（可疑）
		DuplicateTokenEx = 3,        // DuplicateTokenEx —— 造可冒充令牌副本（高危，链核心）
		ImpersonateLoggedOnUser = 4, // ImpersonateLoggedOnUser / RevertToSelf 族 —— 本线程变身（高危）
		CreateProcessWithToken = 5,  // CreateProcessWithTokenW —— 用他人令牌起进程（高危）
		SetThreadToken = 6,          // SetThreadToken —— 直接给线程换令牌（高危）
		AdjustTokenPrivileges = 7,   // AdjustTokenPrivileges —— 开 SeDebug/SeImpersonate/SeTcb（铺路）
	};

	//
	// WMI 事件订阅操作（v13）。
	//
	// ⚠️ 攻击链是"三件套"（缺一不可，这也是最强的判据）：
	//   ① 建 __EventFilter       —— 定义"什么事件触发"（如开机、进程启动）
	//   ② 建 __EventConsumer     —— 定义"触发后干什么"（CommandLineEventConsumer
	//                                直接跑命令行，完全无文件）
	//   ③ 建 __FilterToConsumerBinding —— 把 ① 和 ② 绑起来（不绑不生效）
	//   三条都落在 root\subscription 命名空间里。
	//
	// ⚠️ 判据不能只看"调了 PutInstance"：正常软件也会订阅 WMI 事件
	//    （比如监听设备变化）。关键区分是**命名空间 + 类名**：
	//    只有 root\subscription 下的 __EventFilter / __EventConsumer /
	//    __FilterToConsumerBinding 才报。其它命名空间直接 Pass。
	//
	// 实现限制：IWbemServices 是纯 COM 接口（无导出可挂），
	// 只能 vtable patch（同 ScheduledTaskGuard）。
	//
	enum class WmiSubscriptionOp : ULONG
	{
		ConnectServer = 1,  // IWbemLocator::ConnectServer —— 连接（看命名空间是不是 root\subscription）
		PutInstance = 2,    // IWbemServices::PutInstance —— 写 __EventFilter / __EventConsumer 实例
		ExecQuery = 3,      // IWbemServices::ExecQuery —— WQL 查询（可能是查已有订阅，低危）
		ExecMethod = 4,     // IWbemServices::ExecMethod —— 调 __EventConsumer 上的方法
		Subscribe = 5,      // IWbemServices::ExecNotificationQuery —— 订阅事件（不落盘，但要报）
	};

	enum class Decision : ULONG
	{
		Allowed = 0,    // 允许且无需关注
		Blocked = 1,    // 已拒绝
		WouldBlock = 2, // Log 模式下本应拒绝
	};

	//
	// 风险等级。与 Decision 正交 —— Decision 说"我们做了什么"，
	// RiskLevel 说"这个操作本身有多敏感"。
	//
	// 高危操作一律走询问路径（不看 Mode），因为像"写 Run 键自启动"
	// "改 hosts"这种事，用户就算开了 log 模式也不会想要它静默通过。
	//
	enum class RiskLevel : ULONG
	{
		Normal = 0, // 普通操作，按 Mode 处理
		High = 1,   // 高危：自启动 / 服务 / 劫持 / 系统可执行 / 凭据
	};

	constexpr ULONG FlagHookReads = 0x00000001;  // 连读操作一起挂，噪音大，默认关
	constexpr ULONG FlagLogAllOpen = 0x00000002; // NtOpenKey 无论读写意图都记录
	constexpr ULONG FlagHookHive = 0x00000004;   // 挂 hive 级操作（Load/Save/Restore/Replace），默认开
	constexpr ULONG FlagHookSetInfo = 0x00000008; // 挂 NtSetInformationKey，默认开
	constexpr ULONG FlagHookFile = 0x00000010;   // 挂文件写类操作，默认**关**（文件比注册表热得多）
	constexpr ULONG FlagHighRiskGuard = 0x00000020; // 高危规则总开关，默认**开**
	constexpr ULONG FlagHookProcess = 0x00000040; // 挂进程创建/终止，默认**开**（频率低，信息价值高）
	constexpr ULONG FlagHookThread = 0x00000080;  // 挂线程创建，默认**开**（但默认只报远程线程）
	constexpr ULONG FlagHookSelfThread = 0x00000100; // 连本进程的线程创建也记录，默认**关**（线程创建极高频）
	constexpr ULONG FlagHookDriver = 0x00000200;  // 挂驱动加载/卸载，默认**开**（频率极低）
	constexpr ULONG FlagHookNetwork = 0x00000400; // 挂网络连接/发送/监听，默认**开**（外连是核心情报）
	constexpr ULONG FlagHookDns = 0x00000800;     // 连域名解析一起挂，默认**开**（C2 域名只看这个）
	constexpr ULONG FlagHookNetAll = 0x00001000;  // 连 bind/listen/accept 也挂，默认**关**（服务端程序高频）
	constexpr ULONG FlagSelfProtect = 0x00002000; // 自我保护：NtOpenProcess 对受保护目标剥危险权限，默认**开**
	                                              // 注意这一项**不受 bypass 影响** —— 见 ProcessGuard::Install
	constexpr ULONG FlagHookCamera = 0x00004000;    // 摄像头/麦克风访问监控，默认**开**（打开就报，需用户知情）
	constexpr ULONG FlagHookInputHook = 0x00008000; // 鼠标/键盘钩子监控，默认**开**（键盘记录器只看这里）
	constexpr ULONG FlagHookScreen = 0x00010000;    // 屏幕捕获监控，默认**开**（截屏是隐私泄露面）
	constexpr ULONG FlagHookDllLoad = 0x00020000;   // DLL 加载/劫持监控，默认**开**（白加黑/DLL 侧加载）
	constexpr ULONG FlagHookClipboard = 0x00040000; // 剪贴板读取监控，默认**开**（密码/钱包窃取面）
	constexpr ULONG FlagHookSpawn = 0x00080000;     // 进程创建旁路监控，默认**开**（ShellExecute/WinExec/token）
	constexpr ULONG FlagHookServiceConfig = 0x00100000; // 服务/安全对象权限变更监控，默认**开**（v11：sc sdset 提权）
	constexpr ULONG FlagHookComHijack = 0x00200000;     // COM/OLE 激活劫持监控，默认**开**（v12：CLSID → 用户可写 DLL）
	constexpr ULONG FlagHookScheduledTask = 0x00400000; // 计划任务持久化监控，默认**开**（v12：TaskCache + ITaskService）
	constexpr ULONG FlagHookAudio = 0x00800000;         // 音频环回/麦克风监控，默认**开**（v13：WASAPI loopback + waveIn）
	constexpr ULONG FlagHookTokenTheft = 0x01000000;    // 令牌窃取/冒充监控，默认**开**（v13：OpenProcessToken → DuplicateTokenEx）
	constexpr ULONG FlagHookWmiSubscription = 0x02000000; // WMI 事件订阅持久化监控，默认**开**（v13：__EventFilter 三件套）

	//
	// v14：进程/线程类 Flags 32 位已用满（bit31 = 0x80000000 是最后一个），
	//      所以新增开关进 **PolicyFlags2**（尾部追加字段，见 Policy::Flags2）。
	//
	// ⚠️ 与 Event::Flags2 同理：ABI 改动一律尾部追加，且必须升 AbiVersion。
	//
	constexpr ULONG FlagHookMemoryOp = 0x00000001;    // 跨进程内存操作/代码注入链监控，默认**开**（v14）
	constexpr ULONG FlagHookInputInject = 0x00000002; // 合成输入/锁屏勒索监控，默认**开**（v14）
	constexpr ULONG FlagHookHostHijack = 0x00000004;  // 宿主劫持/加载器监控，默认**开**（v15）

	//
	// v36：终止进程收敛（ini: hook_terminate_contain，默认**开**）。
	//
	// 语义：把 NtTerminateProcess 从"只记录"升级为**按高危判据处置** ——
	//   放行：终止**自己** / **自己的后代**（整棵子树）/ **同镜像路径**的进程；
	//   高危：终止以上三者之外的任何进程（"不许杀别人"）。
	//
	// ⚠️ 为什么必须放行「自己」：ExitProcess 也走 NtTerminateProcess
	//    （`RtlExitUserProcess` → `NtTerminateProcess(NtCurrentProcess(), st)`）。
	//    实测（tools/terminate_block_probe.cpp）：**无差别拦会把干净退出
	//    破坏成异常退出**（退出码被改成 0xC0000005），且进程照样死。
	//    所以 self / 后代必须显式放行，否则整机不可用。
	//
	// ⚠️ 生效范围：hook 只在**非 bypass** 进程里装（见 ProcessGuard::Install），
	//    所以 System32 的任务管理器 / taskkill 不受这条约束 —— 这恰好是
	//    想要的边界（系统工具仍能正常管理进程）。
	//
	// ⚠️ 默认 mode=log ⇒ 本判据默认只**记录**（标 WouldBlock），不真拦。
	//    只有切到 block / ask / block_all 才生效。
	//
	constexpr ULONG FlagHookTerminateContain = 0x00000008; // 终止收敛：只允许终止自己/后代/同镜像（v36）

	//
	// v39：裸盘 / 物理盘写入监控（ini: hook_raw_disk，默认**开**）。
	//
	// 语义：把"带写意图打开裸盘/物理盘"（`\\.\PhysicalDrive0`、
	//   `\Device\Harddisk0\DR0`、`\Device\Harddisk0\Partition0`）判为高危
	//   —— 这是写 MBR / 引导扇区（bootkit）的第一步。
	//
	// ⚠️ 为什么**单独一位**、不复用 `FlagHookFile`：
	//    `hook_file` 默认**关**（文件系统太热，挂上就是几千条/秒）。
	//    如果裸盘保护挂在它下面，发布默认包里这条判据**永远不会生效**
	//    —— 真实绕过就发生在发布默认配置下（`hook_file=0`）。
	//    裸盘写入频率极低（正常机器几周都不一定有一次），单独挂几无成本。
	//
	// ⚠️ 生效条件（见 FileGuard::Install）：
	//    `FlagHookFile || FlagHookRawDisk` 任一开就装文件 hook；
	//    但 `hook_file=0` 时 `Evaluate` 对**普通文件**仍然完全放行
	//    （不记录、不判定），只保留裸盘这一条通道。
	//
	constexpr ULONG FlagHookRawDisk = 0x00000010; // 裸盘/物理盘写入（引导区）监控，默认**开**（v39）

	//
	// v42：**瘦注入**（ini: `inject_shell_thin`，默认**开**）。
	//
	// 语义：把"会当用户程序父进程"的宿主（`explorer.exe`、`svchost.exe`、
	//   `runtimebroker.exe`）从"绝不注入"名单挪到"**瘦注入**"名单 ——
	//   **注入它们**，但只装 `CreateProcessInternalW` 一个 hook，不装任何 guard。
	//
	// ★ 为什么：引擎的**同步注入路**（hook 父进程的 `CreateProcessInternalW`
	//   → 强制 `CREATE_SUSPENDED` → 注入 → `ResumeThread`）能让子进程
	//   **跑第一行代码之前**就挂好 hook ⇒ 盲区 ≈ 0。但它的前提是
	//   **父进程已被注入**。而"双击启动"的父进程是 `explorer.exe`、
	//   "UAC 提权启动"的父进程是 `svchost.exe`（AppInfo 服务）——
	//   这两个原来都在"绝不注入"名单里 ⇒ 那条链上**永远拿不到同步路**，
	//   只能靠轮询（盲区 = 间隔 + 注入耗时）。
	//   样本 `Windows XP Horror` 恰好在 `FormCreate`（启动后几十~几百 ms）
	//   里写 MBR，抢的就是这个窗口。
	//
	// ★ 为什么**只装一个 hook**、不给它们装 guard：`explorer.exe` 的文件 I/O
	//   极高频（每开一个目录、每张缩略图、每次拖放），全量 hook 在
	//   `block_all` 下必炸；而且 DLL 里任何 bug 都会让**桌面**死掉。
	//   瘦会话在行为上等价于"没被注入"，只是多了一个进程创建拦截点。
	//
	// ⚠️ 关掉（`inject_shell_thin=0`）即退回 v41 及以前的行为（不注入它们）。
	//    这是**逃生门**：万一某个环境里注入 shell 宿主引起异常，
	//    改 ini 一行即可，不必回滚版本。
	//
	// ⚠️ 本位只影响"**注不注入**"（`ShouldSkipProcessInjection`）；
	//    "注进去之后走瘦会话还是完整会话"由被注入进程**自己的镜像名**判定
	//    （见 `inject_policy.cpp` 的 `ClassifyCurrentProcess`）—— 两侧读同一张表。
	//
	// ⚠️ 纯新增**位**，不改 `Policy` 布局；但本版**升了 `AbiVersion`**：
	//    一个旧 DLL 被注入进 `explorer.exe` 会装**全量** hook（它不认识本位），
	//    那正是最危险的组合。升版本让"新旧混用"直接以
	//    「共享通道不可用 ⇒ 本进程跳过全部 Hook」失败，而不是悄悄装错。
	//
	constexpr ULONG FlagInjectShellThin = 0x00000020; // shell/服务宿主瘦注入，默认**开**（v42）

	constexpr size_t MaxKeyPathChars = 320;
	constexpr size_t MaxValueNameChars = 128;
	constexpr size_t MaxImagePathChars = 260; // 应用 hive 的目标镜像路径
	constexpr size_t MaxExcludePaths = 16;
	constexpr size_t MaxExcludePathChars = 260;
	constexpr size_t MaxLogPathChars = 320;

	// 用户自定义的保护路径（ini 的 protect_reg= / protect_file=）。
	// 前缀匹配，命中即视为高危。
	constexpr size_t MaxProtectPaths = 24;
	constexpr size_t MaxProtectPathChars = 260;

	// ★ v49：用户自定义的「绝不注入」名单（ini 的 never_inject=，可重复）。
	// 语义 = **完整镜像路径前缀 + 路径边界**，不区分大小写。
	constexpr size_t MaxNeverInjectPaths = 16;
	constexpr size_t MaxNeverInjectPathChars = 260;

	// 网络目标地址（IP、域名或 host:port）的最大字符数。
	// 单独一个常量是因为网络地址长度和文件路径完全不同 ——
	// 域名最长 253，IPv6 字面量最长 45，加 ":65535" 后 320 够得很。
	constexpr size_t MaxNetAddressChars = 320;
	constexpr size_t MaxNetAddressLength = 320;

	constexpr ULONG EventCapacity = 4096;
	constexpr size_t PrivateNamespaceNameChars = 96;

	// ---------------------------------------------------------------------
	// 策略块
	// ---------------------------------------------------------------------
	struct Policy
	{
		ULONG Magic;
		ULONG Version;
		ULONG Mode;      // R3ShieldCore::Mode
		ULONG Flags;     // Flag* 位或
		ULONG EngineProcessId;
		ULONG ExcludePathCount;
		ULONG PromptTimeoutMs;     // 询问超时，超时按 PromptDefaultVerdict 处理
		ULONG PromptDefaultVerdict; // R3ShieldCore::Verdict
		WCHAR ExcludePaths[MaxExcludePaths][MaxExcludePathChars];
		WCHAR LogPath[MaxLogPathChars];

		// ---- 用户自定义的高危保护路径（ini: protect_reg / protect_file）----
		// 前缀匹配（不区分大小写）。命中即视为高危，走询问路径。
		ULONG ProtectRegCount;
		ULONG ProtectFileCount;
		WCHAR ProtectRegPaths[MaxProtectPaths][MaxProtectPathChars];
		WCHAR ProtectFilePaths[MaxProtectPaths][MaxProtectPathChars];

		// 进程 / 驱动版本（ini: protect_process / protect_driver）。
		ULONG ProtectProcessCount;
		ULONG ProtectDriverCount;
		WCHAR ProtectProcessPaths[MaxProtectPaths][MaxProtectPathChars];
		WCHAR ProtectDriverPaths[MaxProtectPaths][MaxProtectPathChars];

		// 用户自定义的网络高危目标（ini: protect_net=）。
		// 匹配 "IP:端口" 或域名，命中即视为高危。
		ULONG ProtectNetCount;
		WCHAR ProtectNetTargets[MaxProtectPaths][MaxProtectPathChars];

		// ---- 运行期统计（引擎侧 UI 写入、GUI 读取）----
		// 放在末尾是为了兼容：新增字段不影响前面的偏移。
		// 这几个字段是"写多读多"的计数器，用 Interlocked 操作，不加锁。
		//
		// ⚠️ 只有引擎自己会写这里（它持有创建侧的读写句柄）。
		// 被注入进程映射 Policy 时用的是 FILE_MAP_READ，往这里写会崩 ——
		// 需要 hook 侧递增的计数（高危命中）放在 ChannelHeader 里。
		volatile LONG PromptShown;     // 弹出询问卡片的总次数
		volatile LONG PromptAllowed;   // 用户点了「允许」「始终允许」的次数
		volatile LONG PromptDenied;    // 用户点了「拒绝」「始终拒绝」的次数
		volatile LONG PromptTimedOut;  // 倒计时走完、按兜底结论处理的次数

		// ---- v14：Flags 已满（32 位用完），新增开关走这里 ----
		//
		// ⚠️ **尾部追加**是 ABI 兼容的铁律：前面所有字段偏移不动，
		//    老版本 DLL 读这个块不会错位（只是读不到新位）。
		//    Flags2 见 FlagHookMemoryOp / FlagHookInputInject / FlagHookHostHijack。
		ULONG Flags2;                  // PolicyFlags2 位或

		// The injector namespace is generated by the engine and copied to
		// injected processes through the read-only policy mapping.
		WCHAR PrivateNamespaceName[PrivateNamespaceNameChars];

		// ---- v49：用户自定义的「绝不注入」名单（ini: never_inject=，可重复）----
		//
		// 语义 = **完整镜像路径前缀 + 路径边界**，不区分大小写。
		// 命中 ⇒ 引擎**不注入**该进程：
		//   · 它自己不受任何监控（等价于"没被注入"）；
		//   · 它拉起的子进程也拿不到**同步路**，只能靠 `inject_interval_ms`
		//     轮询（盲区变大）。
		// ⇒ 这是一把**降低防护强度**的开关，只给"我确定安全、而且注入会把它
		//   弄坏 / 日志太吵"的程序用（典型：自己的开发工具、沙箱宿主）。
		//
		// ★ 必须用**完整路径**而不是"文件名"：按文件名匹配 = 给攻击者一张
		//   "改个名就免注入"的免死金牌（铁律 42 同族，`ClassifyImagePath`
		//   对内置名单也强制要求 %SystemRoot% 目录校验）。
		//
		// ⚠️ **尾部追加**是 ABI 兼容的铁律：前面所有字段偏移不动。
		// ★ 但"尾部追加"仍会让 `sizeof(Policy)` 变大 ⇒ **本版 AbiVersion 升到 20**。
		//   旧 DLL 只映射自己那一段、能映射成功，但版本校验会挡住它 ——
		//   否则它会按旧布局去读 `NeverInjectPaths` 所在的字节（越界/错读）。
		ULONG NeverInjectCount;
		WCHAR NeverInjectPaths[MaxNeverInjectPaths][MaxNeverInjectPathChars];
	};

	// ---------------------------------------------------------------------
	// 事件记录
	// ---------------------------------------------------------------------
	struct Event
	{
		LONG Sequence; // 0 = 空槽；槽位序号 + 1 = 已就绪
		ULONG ObjectType; // R3ShieldCore::ObjectType —— 决定 Op 按哪套枚举解释
		ULONG Op;
		ULONG Decision;
		ULONG RiskLevel; // R3ShieldCore::RiskLevel —— High 表示命中了高危规则
		ULONG Status; // 原始 NTSTATUS
		ULONG ProcessId;
		ULONG ThreadId;
		ULONG DesiredAccess;
		ULONG KeyPathLength; // 字符数，不含结尾 NUL
		ULONG ValueNameLength;
		ULONG TargetKind; // R3ShieldCore::TargetKind：KeyPath 是键路径还是 hive 文件路径
		ULONG Flags;      // 见 FlagEvent* 
		LONG64 TimeStamp; // FILETIME
		//
		// 进程/线程相关。KeyPath 里放目标镜像路径（进程）或驱动文件路径，
		// 下面两个字段放 pid：
		//   进程创建 → TargetProcessId = 新进程 pid，CreatorProcessId 不用
		//   远程线程 → TargetProcessId = 目标进程 pid（KeyPath 放目标镜像路径）
		//   驱动加载 → TargetProcessId = 0，KeyPath 放 .sys 路径
		//
		ULONG TargetProcessId;
		ULONG CreatorProcessId;
		WCHAR KeyPath[MaxKeyPathChars];
		WCHAR ValueName[MaxValueNameChars];

		//
		// 网络专用字段（ObjectType::Network 时有效）。
		//
		// 放在末尾是为了兼容既有偏移 —— Event 只在环形缓冲里按 sizeof 步进，
		// 没有外部 ABI 校验，尾部追加是安全的。
		//
		//   KeyPath   放远端地址（"1.2.3.4" 或 "example.com"；DnsQuery 时放域名）
		//   TargetPort 放端口（主机序）。未解析 / 不适用时为 0
		//   NetProtocol 放 IPPROTO_TCP(6) / IPPROTO_UDP(17) / 0=未知
		//
		// 为什么不把 "IP:Port" 拼一起：UI 要分列展示 IP 和端口，
		// 拼了就还得再切一次，且 IPv6 的 "::" 和端口分隔符容易混淆。
		//
		ULONG TargetPort;
		ULONG NetProtocol;

		//
		// 本地端点（bind/listen/accept 时关键 —— "谁在 0.0.0.0:4444 监听"）。
		// 对 connect/sendto 也填上，便于关联"这条外连从哪个本地端口发出"。
		//
		ULONG LocalPort;
		WCHAR LocalAddress[64];

		//
		// DLL 加载 / 进程创建旁路专用字段（v10 追加）。
		//
		//   DllLoad    → DllPath 放被加载的 DLL 完整路径（从 LdrLoadDll 的 DllName 归一化）
		//   ProcessSpawn → CommandLine 放被拉起进程的命令行
		//
		// 为什么单独开字段而不复用 ValueName：ValueName 只有 128 字符，
		// 命令行经常超过它；而且日志里这两类事件的第二字段语义完全不同。
		//
		WCHAR DllPath[MaxImagePathChars];
		WCHAR CommandLine[512];

		//
		// v12：Flags 位扩容器。
		//
		// ⚠️ Event::Flags 是 32 位且**已用满**（0x80000000 是 v10 的最后一个）。
		//    v11 靠"复用已有位组合"撑过了一轮，v12 新增两类语义再也塞不下，
		//    所以**尾部追加**这个字段 —— 尾部追加是安全的（Event 只在环形
		//    缓冲里按 sizeof 步进，没有外部 ABI 硬校验），但必须升 AbiVersion，
		//    否则新旧 DLL 混用会读到错位内存。
		//
		//    新语义一律用 Flags2，别再往 Flags 里挤。
		//
		ULONG Flags2; // 见 FlagEvent2*
	};

	//
	// Event::Flags2 位（v12 起）。语义与 FlagEvent* 同级，只是位空间不够用了。
	//
	constexpr ULONG FlagEvent2ComUserWritable = 0x00000001; // COM 事件：服务器 DLL/EXE 落在用户可写目录（劫持特征）
	constexpr ULONG FlagEvent2ComInproc = 0x00000002;       // COM 事件：进程内服务器（InprocServer32，DLL 注入到本进程）
	constexpr ULONG FlagEvent2ComLocalServer = 0x00000004;  // COM 事件：本地服务器（LocalServer32，起独立进程）
	constexpr ULONG FlagEvent2TaskCache = 0x00000008;       // 计划任务：走的是 TaskCache 注册表旁路（非 COM）
	constexpr ULONG FlagEvent2TaskActionExe = 0x00000010;   // 计划任务：动作是"运行程序"（vs 只记录事件）
	constexpr ULONG FlagEvent2TaskSystem = 0x00000020;      // 计划任务：以 SYSTEM / 高权限身份运行
	//
	// v13 新增位。
	//
	constexpr ULONG FlagEvent2AudioLoopback = 0x00000040;   // 音频事件：环回采集（录系统输出，非麦克风）
	constexpr ULONG FlagEvent2AudioMic = 0x00000080;        // 音频事件：麦克风采集
	constexpr ULONG FlagEvent2TokenPrepared = 0x00000100;   // 令牌事件：只是"拿到可复制句柄"（一档 · 可疑）
	constexpr ULONG FlagEvent2TokenUsed = 0x00000200;       // 令牌事件：已复制/已冒充/已用于起进程（二档 · 高危）
	constexpr ULONG FlagEvent2TokenPrivEscalation = 0x00000400; // 令牌事件：打开调试/冒充/内核特权（三档 · 铺路）
	constexpr ULONG FlagEvent2WmiFilter = 0x00000800;       // WMI 事件：写的是 __EventFilter（触发条件）
	constexpr ULONG FlagEvent2WmiConsumer = 0x00001000;     // WMI 事件：写的是 __EventConsumer（执行体）
	constexpr ULONG FlagEvent2WmiBinding = 0x00002000;      // WMI 事件：写的是 __FilterToConsumerBinding（绑定）
	constexpr ULONG FlagEvent2WmiFileless = 0x00004000;     // WMI 事件：消费体是无文件命令行（CommandLineEventConsumer）
	//
	// v15 新增位（宿主劫持 / 加载器）。
	//
	// ⚠️ ObjectType::HostHijack 的四个子面靠 HostHijackOp 已经能区分，
	//    这几位是"给 UI 看的附加语义"（同 v13 的 Token 三档）：
	//
	constexpr ULONG FlagEvent2HostUserWritable = 0x00008000; // 宿主劫持：配置/载荷指向用户可写目录（真劫持特征）
	constexpr ULONG FlagEvent2HostCrossProc = 0x00010000;    // 宿主劫持：目标是别的进程（远程映射 / APC 注入）
	constexpr ULONG FlagEvent2HostCredential = 0x00020000;   // 宿主劫持：涉及凭据宿主（LSASS / 登录界面）

	//
	// v26 新增位（全拦模式的"询问通道不可用"降级）。
	//
	// ★ 背景（VM 实测，2026-09-30 20:38）：
	//   block_all 下 `ShouldAskInsteadOfBlockAll` 判定为"可问"的注册表写，
	//   在 `R3ShieldCorePrompt::Ask` 拿不到询问通道时会**立刻返回 fallback**
	//   （`prompt_default=deny`）→ 表现为**静默直接拒**，
	//   用户看到「Windows 无法访问指定设备」而**没有任何弹窗**，
	//   与 v25 想修的老毛病**一模一样**（只是藏在判定层之后）。
	//
	//   实测证据：`OneDrive.exe` 写 `HKCU\Software` 等 17 条事件
	//   **时间戳完全相同**（`20:39:23.401`）→ 不可能经过弹窗等待
	//   （弹窗要等用户点或超时 30s）→ 只能是"通道不在、立即 fallback"。
	//
	//   v26 处置：`askable == true` 且**通道不可用**时 → **放行 + 打本位**。
	//     安全边界**不变**：`askable == false`（高危规则表 / Windows 基础设施 /
	//     hive 级 / COM+ 目录）**照样直接拒**，连通道都不看。
	//     本位置位时事件是 `Allowed`（放行），日志里打 `[ASK-UNAVAIL]`
	//     便于事后区分"真放行"与"该问没问成"。
	//
	constexpr ULONG FlagEvent2AskUnavailable = 0x00040000;   // 全拦模式：可问项因询问通道不可用而降级放行

	//
	// v37 新增位（终止收敛的"目标 pid 取不到"降级）。
	//
	// ★ 背景（e2e 实测，2026-10-03）：
	//   `NtTerminateProcess` 的第一个参数是**进程句柄**，要靠
	//   `NtQueryInformationProcess(ProcessBasicInformation)` 反查 pid。
	//   而该查询需要句柄带 `PROCESS_QUERY_LIMITED_INFORMATION` ——
	//   最常见的杀进程写法 `OpenProcess(PROCESS_TERMINATE)` 恰恰**没有**它，
	//   查询返回 `0xC0000022` ⇒ 反查得 0 ⇒ 收敛规则被绕过（实测 T3/T4 FAIL）。
	//
	//   v37 处置：在 `NtOpenProcess` 里给带 `PROCESS_TERMINATE` 的请求
	//   **补上** `PROCESS_QUERY_LIMITED_INFORMATION`（内核在句柄对象上强制），
	//   使后续反查必然成功。见 process_guard.cpp 的 NtOpenProcess_Hook。
	//
	//   但仍有**拿不到 pid** 的句柄来源：`DuplicateHandle` 复制来的、
	//   继承来的、注入前就已打开的。此时按项目一贯策略
	//   **降级放行 + 打本位**（绝不为"机制不可用"静默拒 —— 铁律 12/13），
	//   日志里打 `[PID-UNKNOWN]` 便于事后审计这条旁路。
	//
	constexpr ULONG FlagEvent2TerminatePidUnknown = 0x00080000; // 终止事件：目标句柄反查不到 pid，降级放行

	// Event::Flags 位。给日志和弹窗提供额外的语义提示。
	constexpr ULONG FlagEventImageName = 0x00000001; // KeyPath 里是目标镜像路径而非注册表路径
	constexpr ULONG FlagEventHiveFile = 0x00000002;  // 附带了一个 hive 文件路径（在 ValueName 里）
	constexpr ULONG FlagEventBlocked = 0x00000004;   // 由 R3ShieldCore 主动拒绝，而非由系统拒绝
	constexpr ULONG FlagEventCreate = 0x00000008;    // 文件操作：这次打开真的新建了对象（disposition 说了算）
	constexpr ULONG FlagEventOverwrite = 0x00000010; // 文件操作：带覆盖意图（FILE_OVERWRITE*）
	constexpr ULONG FlagEventHighRisk = 0x00000020;  // 命中了高危规则（内置表或用户自定义）
	constexpr ULONG FlagEventRemoteThread = 0x00000040; // 线程事件：跨进程创建线程（注入手法）
	constexpr ULONG FlagEventSelfThread = 0x00000080;   // 线程事件：在本进程内创建线程
	constexpr ULONG FlagEventNewProcess = 0x00000100;   // 进程事件：这次调用真的建成了新进程
	constexpr ULONG FlagEventDriverLoad = 0x00000200;   // 驱动事件：加载（vs 卸载）
	constexpr ULONG FlagEventFromRemote = 0x00000400;   // 进程事件：不是由父进程正常派生（如 NtCreateProcessEx 被外部调用）
	constexpr ULONG FlagEventListen = 0x00000800;        // 网络事件：进入监听状态（后门/远控标志）
	constexpr ULONG FlagEventInbound = 0x00001000;       // 网络事件：来自外部（bind/listen/accept 或收到连接）
	constexpr ULONG FlagEventLoopback = 0x00002000;      // 网络事件：目标是本机回环
	constexpr ULONG FlagEventPrivateNet = 0x00004000;    // 网络事件：目标是内网/保留地址段
	constexpr ULONG FlagEventSensitivePort = 0x00008000; // 网络事件：目标是敏感服务端口
	constexpr ULONG FlagEventDns = 0x00010000;           // 网络事件：域名解析（无端口语义）
	constexpr ULONG FlagEventUnresolved = 0x00020000;    // 网络事件：目标仍是未解析的域名/主机名
	constexpr ULONG FlagEventGlobalHook = 0x00040000;    // 输入钩子事件：全局钩子（需注入所有 GUI 进程）
	constexpr ULONG FlagEventLowLevelHook = 0x00080000;  // 输入钩子事件：低级钩子（LL，无需注入但全系统监听）
	constexpr ULONG FlagEventMouse = 0x00100000;         // 输入钩子事件：鼠标类
	constexpr ULONG FlagEventKeyboard = 0x00200000;      // 输入钩子事件：键盘类
	constexpr ULONG FlagEventRawInput = 0x00400000;      // 输入钩子事件：原始输入设备注册
	constexpr ULONG FlagEventScreenDC = 0x00800000;      // 屏幕事件：源是屏幕/桌面 DC（全屏截取）
	constexpr ULONG FlagEventWindowCapture = 0x01000000; // 屏幕事件：抓的是指定窗口
	constexpr ULONG FlagEventCameraOpen = 0x02000000;    // 摄像头事件：这是"打开设备"而非枚举
	constexpr ULONG FlagEventServiceInstall = 0x04000000; // 驱动事件：来自 SCM 服务 API（CreateService/ChangeServiceConfig/StartService），而非 NtLoadDriver
	constexpr ULONG FlagEventKernelDriver = 0x08000000;   // 驱动事件：服务类型是内核驱动（SERVICE_KERNEL_DRIVER / FILE_SYSTEM_DRIVER）
	//
	// v10：DLL 加载 / 剪贴板 / 进程创建旁路
	//
	constexpr ULONG FlagEventSystemDll = 0x10000000;   // DLL 事件：来自 System32/SysWOW64（正常依赖，通常不报）
	constexpr ULONG FlagEventNonSystemDll = 0x20000000; // DLL 事件：来自用户可写目录（白加黑特征）
	constexpr ULONG FlagEventManualMap = 0x40000000;   // DLL 事件：手工映射特征（无 LdrLoadDll 的映像映射）
	constexpr ULONG FlagEventClipboardRead = 0x80000000; // 剪贴板事件：真的取走了数据（GetClipboardData），非仅打开

	//
	// ⚠️ Flags 已经用满 32 位（0x80000000 是最后一个空位）。
	//
	//    v11 新增的语义无法再开新位，改用**已有的位做组合**表达：
	//
	//     截屏 GetDIBits      → FlagEventScreenDC（源是屏幕 DC）
	//     输入轮询            → FlagEventKeyboard（键盘类）+ FlagEventLowLevelHook（无需注入即全系统监听）
	//     进程 AsUser         → FlagEventNewProcess（真建成了进程）
	//     服务改权限          → FlagEventServiceInstall（来自 SCM 服务 API）
	//
	//    v12 起**不要再往 Flags 里挤** —— 新增语义一律用 Event::Flags2
	//    （已尾部追加）。Flags 保持原样、只服务既有语义。
	//

	struct alignas(16) ChannelHeader
	{
		ULONG Magic;
		ULONG Version;
		volatile LONG WriteIndex; // 生产者递增
		volatile LONG ReadIndex;  // 消费者递增
		volatile LONG DroppedCount;
		ULONG Capacity;
		// 运行期计数器，由被注入进程（hook 侧）递增、引擎读取。
		//
		// ⚠️ 为什么放这里而不是 Policy 里：Policy 是 FILE_MAP_READ 只读映射，
		// 往里写会直接 0xC0000005（访问违规）。Events 通道才是 READ|WRITE。
		// 这两个字段原先放 Policy 末尾，导致高危 CreateKey/SetValueKey 一命中
		// 就崩 —— 被 __except 吞掉变成"静默放行"，症状是"高危不拦截也不记录"。
		volatile LONG HighRiskAsked;
		volatile LONG HighRiskBlocked;
	};

	static_assert(sizeof(ChannelHeader) == 32, "ChannelHeader 必须是 32 字节");

	inline Event* ChannelEventBase(ChannelHeader* header)
	{
		return reinterpret_cast<Event*>(header + 1);
	}

	inline Event* ChannelEventAt(ChannelHeader* header, ULONG index)
	{
		return &ChannelEventBase(header)[index % header->Capacity];
	}

	inline size_t ChannelBytes()
	{
		return sizeof(ChannelHeader) + sizeof(Event) * EventCapacity;
	}

	// ---------------------------------------------------------------------
	// 询问通道（请求 / 应答）
	// ---------------------------------------------------------------------
	// DLL 在 hook 里同步阻塞，等引擎弹窗给出结论。协议：
	//
	//   生产者（任意进程的 hook 线程）
	//     1. 逐个槽 CAS(State, Claimed, Free) 抢槽
	//     2. InterlockedIncrement(Generation) —— 必须在发布之前，
	//        否则引擎可能读到上一次的世代号
	//     3. 填请求字段
	//     4. MemoryBarrier()，然后 InterlockedExchange(State, Pending) 发布
	//     5. SetEvent(请求事件)
	//     6. WaitForSingleObject(本槽应答事件, 超时)
	//        醒来后必须确认 State == Answered 且 AnsweredGeneration == 自己的世代号，
	//        否则是上一次请求的迟到答复，继续等
	//     7. 超时则 InterlockedExchange(State, Free) 释放槽，返回兜底结论
	//
	//   消费者（引擎 UI 线程）
	//     1. 扫描 State == Pending 的槽，快照出来
	//     2. 弹窗
	//     3. 写 Verdict、AnsweredGeneration = 快照的世代号
	//     4. CAS(State, Answered, Pending) —— 只在仍是"待处理"时才置为"已答复"。
	//        DLL 若已超时释放槽，CAS 失败，答复丢弃，不会串到新请求上
	//     5. 成功才 SetEvent(本槽应答事件)
	//
	constexpr ULONG PromptMagic = 0x31505250; // 'PRP1'
	constexpr ULONG PromptSlotCount = 8;
	constexpr size_t MaxProcessPathChars = 260;

	enum : LONG
	{
		PromptSlotFree = 0,
		PromptSlotClaimed = -1, // 已被占用、正在填字段；引擎不看这个状态
		PromptSlotPending = 1,  // 已发布，等引擎处理
		PromptSlotAnswered = 2,
	};

	struct PromptSlot
	{
		volatile LONG State;      // PromptSlotFree / Pending / Answered
		volatile LONG Generation; // 每次占用递增
		ULONG ObjectType; // R3ShieldCore::ObjectType
		ULONG Op;
		ULONG ProcessId;
		ULONG ThreadId;
		ULONG KeyPathLength;
		ULONG ValueNameLength;
		ULONG ProcessPathLength;
		ULONG TargetKind; // R3ShieldCore::TargetKind
		ULONG Flags;      // R3ShieldCore::FlagEvent*
		LONG64 TimeStamp;
		WCHAR KeyPath[MaxKeyPathChars];
		WCHAR ValueName[MaxValueNameChars];
		WCHAR ProcessPath[MaxProcessPathChars];
		volatile ULONG Verdict;
		volatile LONG AnsweredGeneration;

		// 网络事件专用（ObjectType::Network）。与 Event 的同名字段一致，
		// 尾部追加，不影响既有偏移。
		ULONG TargetPort;
		ULONG NetProtocol;
		ULONG LocalPort;
		WCHAR LocalAddress[64];

		// DLL 加载 / 进程创建旁路专用（v10 追加，与 Event 的同名字段一致）。
		//   DllLoad      → DllPath 放被加载的 DLL 完整路径
		//   ProcessSpawn → CommandLine 放被拉起进程的命令行
		// 尾部追加，不影响既有偏移。
		WCHAR DllPath[MaxImagePathChars];
		WCHAR CommandLine[512];
	};

	struct alignas(16) PromptHeader
	{
		ULONG Magic;
		ULONG Version;
		ULONG SlotCount;
		ULONG Reserved[5];
	};

	static_assert(sizeof(PromptHeader) == 32, "PromptHeader 必须是 32 字节");

	inline PromptSlot* PromptSlotBase(PromptHeader* header)
	{
		return reinterpret_cast<PromptSlot*>(header + 1);
	}

	inline size_t PromptBytes()
	{
		return sizeof(PromptHeader) + sizeof(PromptSlot) * PromptSlotCount;
	}

	// ---------------------------------------------------------------------
	// 命名对象。
	//
	// 优先用 Global\ 前缀（跨会话可见），但创建 Global\ 对象需要
	// SeCreateGlobalPrivilege —— 没提权时 CreateFileMapping 会直接以
	// ERROR_ACCESS_DENIED 失败。所以引擎先试 Global\，失败就退化成会话内命名。
	//
	// 退化是安全的：没有那个特权说明进程也没提权，本来就注入不到别的会话，
	// 会话内命名足够覆盖同会话的进程。
	//
	// 注入侧两条都试，谁建起来的就打开谁。
	// ---------------------------------------------------------------------
	constexpr PCWSTR GlobalNamePrefix = L"Global\\";
	constexpr PCWSTR SessionNamePrefix = L"";
	constexpr size_t ObjectNameCapacity = 64;

	inline int MakePolicyName(WCHAR* buffer, size_t cch, PCWSTR prefix, DWORD enginePid)
	{
		return swprintf_s(buffer, cch, L"%sR3ShieldCore-Policy-pid=%u", prefix, enginePid);
	}

	inline int MakeChannelName(WCHAR* buffer, size_t cch, PCWSTR prefix, DWORD enginePid)
	{
		return swprintf_s(buffer, cch, L"%sR3ShieldCore-Events-pid=%u", prefix, enginePid);
	}

	inline int MakePromptName(WCHAR* buffer, size_t cch, PCWSTR prefix, DWORD enginePid)
	{
		return swprintf_s(buffer, cch, L"%sR3ShieldCore-Prompt-pid=%u", prefix, enginePid);
	}

	inline int MakePromptRequestEventName(WCHAR* buffer, size_t cch, PCWSTR prefix, DWORD enginePid)
	{
		return swprintf_s(buffer, cch, L"%sR3ShieldCore-PromptReq-pid=%u", prefix, enginePid);
	}

	inline int MakePromptSlotEventName(WCHAR* buffer, size_t cch, PCWSTR prefix, DWORD enginePid, ULONG slot)
	{
		return swprintf_s(buffer, cch, L"%sR3ShieldCore-PromptSlot-pid=%u-%u", prefix, enginePid, slot);
	}

	// 供日志与调试使用的可读名称。
	inline const char* OpName(ULONG op)
	{
		switch (static_cast<Op>(op)) {
		case Op::CreateKey: return "CreateKey";
		case Op::OpenKey: return "OpenKey";
		case Op::SetValueKey: return "SetValueKey";
		case Op::DeleteKey: return "DeleteKey";
		case Op::DeleteValueKey: return "DeleteValueKey";
		case Op::RenameKey: return "RenameKey";
		case Op::FlushKey: return "FlushKey";
		case Op::QueryValueKey: return "QueryValueKey";
		case Op::EnumerateKey: return "EnumerateKey";
		case Op::EnumerateValueKey: return "EnumerateValueKey";
		case Op::QueryKey: return "QueryKey";
		case Op::SetInformationKey: return "SetInformationKey";
		case Op::LoadKey: return "LoadKey";
		case Op::UnloadKey: return "UnloadKey";
		case Op::SaveKey: return "SaveKey";
		case Op::RestoreKey: return "RestoreKey";
		case Op::ReplaceKey: return "ReplaceKey";
		case Op::LoadKeyEx: return "LoadKeyEx";
		case Op::UnloadKeyEx: return "UnloadKeyEx";
		case Op::SaveKeyEx: return "SaveKeyEx";
		default: return "Unknown";
		}
	}

	// 这个操作是否可拦截。读操作和 FlushKey 只记录。
	inline bool IsBlockableOp(ULONG op)
	{
		switch (static_cast<Op>(op)) {
		case Op::QueryValueKey:
		case Op::EnumerateKey:
		case Op::EnumerateValueKey:
		case Op::QueryKey:
		case Op::FlushKey:
			return false;
		default:
			return true;
		}
	}

	// 这个操作是否操作 hive 文件（路径语义不同，UI 要区别展示）。
	//
	// ⚠️ 新增 hive 级 Op 时必须同时加到这里（以及下方 IsHighRiskOp 的高危集），
	//    否则 TargetKind 会被判成 Key：下游日志/弹窗/统计全部按"普通键操作"
	//    解释，该升格的没升格，而且**不报错**（静默降级）。
	inline bool IsHiveOp(ULONG op)
	{
		switch (static_cast<Op>(op)) {
		case Op::LoadKey:
		case Op::UnloadKey:
		case Op::SaveKey:
		case Op::RestoreKey:
		case Op::ReplaceKey:
		case Op::LoadKeyEx:
		case Op::UnloadKeyEx:
		case Op::SaveKeyEx:
			return true;
		default:
			return false;
		}
	}

	// 文件操作的可读名。
	inline const char* FileOpName(ULONG op)
	{
		switch (static_cast<FileOp>(op)) {
		case FileOp::Create: return "CreateFile";
		case FileOp::Open: return "OpenFile";
		case FileOp::Write: return "WriteFile";
		case FileOp::Delete: return "DeleteFile";
		case FileOp::Rename: return "RenameFile";
		case FileOp::SetBasicInfo: return "SetFileTime";
		case FileOp::SetSecurity: return "SetFileSecurity";
		case FileOp::SetEa: return "SetFileEa";
		case FileOp::Truncate: return "TruncateFile";
		default: return "Unknown";
		}
	}

	// 进程操作的可读名。
	inline const char* ProcessOpName(ULONG op)
	{
		switch (static_cast<ProcessOp>(op)) {
		case ProcessOp::Create: return "CreateProcess";
		case ProcessOp::Terminate: return "TerminateProcess";
		case ProcessOp::Open: return "OpenProcess";
		case ProcessOp::WriteMemory: return "WriteVirtualMemory";
		case ProcessOp::ProtectMemory: return "ProtectVirtualMemory";
		case ProcessOp::AllocateMemory: return "AllocateVirtualMemory";
		case ProcessOp::CreateLegacy: return "CreateProcessLegacy";
		default: return "Unknown";
		}
	}

	// 线程操作的可读名。
	inline const char* ThreadOpName(ULONG op)
	{
		switch (static_cast<ThreadOp>(op)) {
		case ThreadOp::Create: return "CreateThread";
		case ThreadOp::Terminate: return "TerminateThread";
		case ThreadOp::CreateLegacy: return "CreateThreadLegacy";
		default: return "Unknown";
		}
	}

	// 驱动操作的可读名。
	inline const char* DriverOpName(ULONG op)
	{
		switch (static_cast<DriverOp>(op)) {
		case DriverOp::Load: return "LoadDriver";
		case DriverOp::Unload: return "UnloadDriver";
		case DriverOp::CreateService: return "CreateService";
		case DriverOp::ChangeServiceConfig: return "ChangeServiceConfig";
		case DriverOp::StartService: return "StartService";
		default: return "Unknown";
		}
	}

	// 网络操作的可读名。
	inline const char* NetOpName(ULONG op)
	{
		switch (static_cast<NetOp>(op)) {
		case NetOp::Connect: return "Connect";
		case NetOp::SendTo: return "SendTo";
		case NetOp::Bind: return "Bind";
		case NetOp::Listen: return "Listen";
		case NetOp::Accept: return "Accept";
		case NetOp::DnsQuery: return "DnsQuery";
		case NetOp::DeviceIo: return "AfdDeviceIo";
		default: return "Unknown";
		}
	}

	// 网络协议名。
	inline const char* NetProtocolName(ULONG protocol)
	{
		switch (protocol) {
		case 6: return "TCP";
		case 17: return "UDP";
		default: return "?";
		}
	}

	// 摄像头操作的可读名。
	inline const char* CameraOpName(ULONG op)
	{
		switch (static_cast<CameraOp>(op)) {
		case CameraOp::OpenDevice: return "OpenCamera";
		case CameraOp::CreateDeviceSource: return "CameraDeviceSource";
		case CameraOp::CreateSourceReader: return "CameraReader";
		case CameraOp::EnumDevice: return "EnumCamera";
		case CameraOp::WasapiCapture: return "WasapiCapture";    // v13
		case CameraOp::WasapiLoopback: return "WasapiLoopback";  // v13
		case CameraOp::MicOpen: return "MicOpen";                // v13
		default: return "Unknown";
		}
	}

	// 输入钩子操作的可读名。
	inline const char* HookOpName(ULONG op)
	{
		switch (static_cast<HookOp>(op)) {
		case HookOp::SetMouseHook: return "SetMouseHook";
		case HookOp::SetKeyboardHook: return "SetKeyboardHook";
		case HookOp::SetInputJournal: return "SetInputJournal";
		case HookOp::SetOtherHook: return "SetWindowsHook";
		case HookOp::RegisterRawInput: return "RegisterRawInput";
		case HookOp::Unhook: return "Unhook";
		case HookOp::PollAsyncKeyState: return "GetAsyncKeyState";
		case HookOp::PollKeyState: return "GetKeyState";
		case HookOp::SetEventHook: return "SetWinEventHook";
		case HookOp::SendInputEvents: return "SendInput";
		case HookOp::BlockUserInput: return "BlockInput";
		case HookOp::ClipCursorLock: return "ClipCursor";
		default: return "Unknown";
		}
	}

	// 屏幕捕获操作的可读名。
	inline const char* ScreenOpName(ULONG op)
	{
		switch (static_cast<ScreenOp>(op)) {
		case ScreenOp::BitBlt: return "ScreenBitBlt";
		case ScreenOp::StretchBlt: return "ScreenStretchBlt";
		case ScreenOp::PrintWindow: return "PrintWindow";
		case ScreenOp::GetDIBits: return "GetDIBits";
		default: return "Unknown";
		}
	}

	// DLL 加载 / 劫持操作的可读名。
	inline const char* DllLoadOpName(ULONG op)
	{
		switch (static_cast<DllLoadOp>(op)) {
		case DllLoadOp::LoadLibrary: return "LoadLibrary";
		case DllLoadOp::MapSection: return "MapSection";
		case DllLoadOp::ManualMap: return "ManualMap";
		default: return "Unknown";
		}
	}

	// 宿主劫持 / 加载器操作的可读名（v15）。
	inline const char* HostHijackOpName(ULONG op)
	{
		switch (static_cast<HostHijackOp>(op)) {
		case HostHijackOp::InjectionRegistryKey: return "HostInjectionKey";
		case HostHijackOp::LoadLibraryEx: return "LoadLibraryEx";
		case HostHijackOp::RegisterDllNotification: return "LdrRegisterDllNotification";
		case HostHijackOp::MapSectionRemote: return "MapSectionRemote";
		case HostHijackOp::QueueApcRemote: return "QueueApcRemote";
		case HostHijackOp::CredentialHost: return "CredentialHost";
		default: return "Unknown";
		}
	}

	// 剪贴板操作的可读名。
	inline const char* ClipboardOpName(ULONG op)
	{
		switch (static_cast<ClipboardOp>(op)) {
		case ClipboardOp::Open: return "OpenClipboard";
		case ClipboardOp::Read: return "GetClipboardData";
		default: return "Unknown";
		}
	}

	// 进程创建旁路操作的可读名。
	inline const char* SpawnOpName(ULONG op)
	{
		switch (static_cast<SpawnOp>(op)) {
		case SpawnOp::ShellExecute: return "ShellExecute";
		case SpawnOp::WinExec: return "WinExec";
		case SpawnOp::WithToken: return "CreateProcessWithToken";
		case SpawnOp::WithLogon: return "CreateProcessWithLogon";
		case SpawnOp::System: return "System";
		case SpawnOp::AsUser: return "CreateProcessAsUser";
		default: return "Unknown";
		}
	}

	// 服务 / 安全对象权限操作的可读名（v11）。
	inline const char* ServiceConfigOpName(ULONG op)
	{
		switch (static_cast<ServiceConfigOp>(op)) {
		case ServiceConfigOp::SetServiceSecurity: return "SetServiceObjectSecurity";
		case ServiceConfigOp::SetKernelObjectSecurity: return "NtSetSecurityObject";
		default: return "Unknown";
		}
	}

	// COM / OLE 激活操作的可读名（v12）。
	inline const char* ComOpName(ULONG op)
	{
		switch (static_cast<ComOp>(op)) {
		case ComOp::CreateInstance: return "CoCreateInstance";
		case ComOp::CreateInstanceEx: return "CoCreateInstanceEx";
		case ComOp::GetClassObject: return "CoGetClassObject";
		default: return "Unknown";
		}
	}

	// 计划任务操作的可读名（v12）。
	inline const char* ScheduledTaskOpName(ULONG op)
	{
		switch (static_cast<ScheduledTaskOp>(op)) {
		case ScheduledTaskOp::RegisterTaskDefinition: return "RegisterTaskDefinition";
		case ScheduledTaskOp::CreateFolder: return "CreateFolder";
		case ScheduledTaskOp::Run: return "TaskRun";
		case ScheduledTaskOp::TaskCacheWrite: return "TaskCacheWrite";
		default: return "Unknown";
		}
	}

	// 令牌窃取 / 冒充操作的可读名（v13）。
	inline const char* TokenTheftOpName(ULONG op)
	{
		switch (static_cast<TokenTheftOp>(op)) {
		case TokenTheftOp::OpenProcessToken: return "OpenProcessToken";
		case TokenTheftOp::OpenThreadToken: return "OpenThreadToken";
		case TokenTheftOp::DuplicateTokenEx: return "DuplicateTokenEx";
		case TokenTheftOp::ImpersonateLoggedOnUser: return "ImpersonateLoggedOnUser";
		case TokenTheftOp::CreateProcessWithToken: return "CreateProcessWithToken";
		case TokenTheftOp::SetThreadToken: return "SetThreadToken";
		case TokenTheftOp::AdjustTokenPrivileges: return "AdjustTokenPrivileges";
		default: return "Unknown";
		}
	}

	// WMI 事件订阅操作的可读名（v13）。
	inline const char* WmiSubscriptionOpName(ULONG op)
	{
		switch (static_cast<WmiSubscriptionOp>(op)) {
		case WmiSubscriptionOp::ConnectServer: return "WmiConnect";
		case WmiSubscriptionOp::PutInstance: return "WmiPutInstance";
		case WmiSubscriptionOp::ExecQuery: return "WmiExecQuery";
		case WmiSubscriptionOp::ExecMethod: return "WmiExecMethod";
		case WmiSubscriptionOp::Subscribe: return "WmiSubscribe";
		default: return "Unknown";
		}
	}

	//
	// 按对象类型把 Op 翻成可读名。UI / 日志一律走这个，
	// 不要直接调 OpName —— 否则文件事件的 op 会被当成注册表 op 解释出垃圾名字。
	//
	inline const char* AnyOpName(ULONG objectType, ULONG op)
	{
		switch (static_cast<ObjectType>(objectType)) {
		case ObjectType::File:
			return FileOpName(op);
		case ObjectType::Process:
			return ProcessOpName(op);
		case ObjectType::Thread:
			return ThreadOpName(op);
		case ObjectType::Driver:
			return DriverOpName(op);
		case ObjectType::Network:
			return NetOpName(op);
		case ObjectType::Camera:
			return CameraOpName(op);
		case ObjectType::InputHook:
			return HookOpName(op);
		case ObjectType::Screen:
			return ScreenOpName(op);
		case ObjectType::DllLoad:
			return DllLoadOpName(op);
		case ObjectType::Clipboard:
			return ClipboardOpName(op);
		case ObjectType::ProcessSpawn:
			return SpawnOpName(op);
		case ObjectType::ServiceConfig:
			return ServiceConfigOpName(op);
		case ObjectType::ComHijack:
			return ComOpName(op);
		case ObjectType::ScheduledTask:
			return ScheduledTaskOpName(op);
		case ObjectType::TokenTheft:
			return TokenTheftOpName(op);
		case ObjectType::WmiSubscription:
			return WmiSubscriptionOpName(op);
		case ObjectType::HostHijack:
			return HostHijackOpName(op);
		default:
			return OpName(op);
		}
	}

	inline const char* ObjectTypeName(ULONG objectType)
	{
		switch (static_cast<ObjectType>(objectType)) {
		case ObjectType::File: return "FILE";
		case ObjectType::Process: return "PROC";
		case ObjectType::Thread: return "THRD";
		case ObjectType::Driver: return "DRV";
		case ObjectType::Network: return "NET";
		case ObjectType::Camera: return "CAM";
		case ObjectType::InputHook: return "HOOK";
		case ObjectType::Screen: return "SCRN";
		case ObjectType::DllLoad: return "DLL";
		case ObjectType::Clipboard: return "CLIP";
		case ObjectType::ProcessSpawn: return "SPAWN";
		case ObjectType::ServiceConfig: return "SVCCFG";
		case ObjectType::ComHijack: return "COM";
		case ObjectType::ScheduledTask: return "TASK";
		case ObjectType::TokenTheft: return "TOKEN";
		case ObjectType::WmiSubscription: return "WMI";
		case ObjectType::HostHijack: return "HOST";
		default: return "REG";
		}
	}

	// 文件操作是否可拦截。全部可拦截 —— 文件这边没有"只记录"的读操作，
	// 光是把 NtOpenFile 挂上就够热了，不值得再往里加免拦截的例外。
	inline bool IsBlockableFileOp(ULONG /*op*/)
	{
		return true;
	}

	// 按对象类型判断可拦截性。
	inline bool IsBlockableOp(ULONG objectType, ULONG op)
	{
		switch (static_cast<ObjectType>(objectType)) {
		case ObjectType::File:
			return IsBlockableFileOp(op);
		case ObjectType::Process:
			// 只能拦创建；终止是"调用即生效"，没有询问的余地。
			return static_cast<ProcessOp>(op) == ProcessOp::Create;
		case ObjectType::Thread:
			return static_cast<ThreadOp>(op) == ThreadOp::Create;
		case ObjectType::Driver:
			// 加载/卸载都给拦 —— 加载危险，卸载是反取证（干掉别人的防护驱动）。
			return true;
		case ObjectType::Network:
			// 全部可拦。但"可拦"不等于"该拦"：listen/accept/bind 在正常服务端
			// 程序里极高频（一个 Web 服务每秒 accept 上百次），默认不挂。
			// 真正要拦的是 **出不去的**（connect/sendto）—— 那才是数据外泄的口子；
			// 以及"不该监听却监听了"（listen）。
			return true;
		case ObjectType::Camera:
			// 枚举设备只记录 —— 程序启动时列一下摄像头列表是正常的
			// （相机应用、会议软件、设备管理器都会枚举）。真正要问的是"打开"。
			// v13：音频侧同理，但 EnumDevice 这个 op 同时也覆盖音频设备枚举，
			// 所以音频的采集 op（WasapiCapture/Loopback/MicOpen）都保持可拦。
			return static_cast<CameraOp>(op) != CameraOp::EnumDevice;
		case ObjectType::InputHook:
			// 拆钩子（Unhook）不是攻击行为，只记录 —— 而且拦掉它反而
			// 会把别人的钩子链搞坏。
			return static_cast<HookOp>(op) != HookOp::Unhook;
		case ObjectType::Screen:
			// 三条路都可拦。但只有"源是屏幕 DC / 抓窗口"的事件才会走到
			// 判定层 —— 普通的窗口重绘 BitBlt 在 hook 里就被过滤掉了，
			// 根本不会产生事件。
			return true;
		case ObjectType::DllLoad:
			// 加载与映射都可拦（拦了 = 这个 DLL 没被加载上）。
			// 但**只有非系统目录的 DLL 才会走到判定层** —— System32 的
			// 依赖加载在 hook 里就被过滤掉了，否则每个进程启动都是几百条。
			return true;
		case ObjectType::Clipboard:
			// 只有 Read 有意义：Open 是敲门砖，拦 Open 会让所有正常
			// 复制粘贴失败。读才是窃取。
			return static_cast<ClipboardOp>(op) == ClipboardOp::Read;
		case ObjectType::ProcessSpawn:
			// 全部可拦 —— 这几个 API 的频率远低于 NtCreateUserProcess，
			// 而且本身就是"可疑度较高"的创建路径。
			return true;
		case ObjectType::ServiceConfig:
			// 改安全描述符全部可拦 —— 拦了 = 这次 ACL 变更没生效。
			return true;
		case ObjectType::ComHijack:
			// 全部可拦 —— 拦了 = 这次激活失败（进程内服务器 DLL 不会加载上，
			// 本地服务器进程不会起来）。判据已在 hook 层收窄到"用户可写目录"，
			// 正常程序创建系统 CLSID 对象不会被上报。
			return true;
		case ObjectType::ScheduledTask:
			// 全部可拦 —— 拦了 = 任务注册/覆盖/执行失败。
			// ⚠️ 但 CreateFolder 只记录不拦（建任务目录本身无害，
			// 而且很多正常安装器会建目录再放任务）。
			return static_cast<ScheduledTaskOp>(op) != ScheduledTaskOp::CreateFolder;
		case ObjectType::TokenTheft:
			// 全部可拦 —— 但拦的**不是令牌操作本身**，是"让这次调用失败"：
			// 拦 OpenProcessToken = 拿不到句柄（链在起点就断）；
			// 拦 DuplicateTokenEx = 造不出副本；拦 CreateProcessWithToken = 起不来进程。
			// ⚠️ ImpersonateLoggedOnUser / SetThreadToken 的"拦"只能是
			//    调用前返回失败，副作用是调用方线程未变身 —— 安全方向。
			// AdjustTokenPrivileges 也拦（拦了 = 特权没开上，链断在铺路阶段）。
			return true;
		case ObjectType::WmiSubscription:
			// 全部可拦 —— 拦了 = 实例没写进去 / 订阅没建立。
			// ⚠️ ExecQuery 只记录不拦（查订阅是审计行为，拦了会把正常
			// 的监控软件、管理工具搞坏）。
			return static_cast<WmiSubscriptionOp>(op) != WmiSubscriptionOp::ExecQuery;
		default:
			return IsBlockableOp(op);
		}
	}

	inline const char* DecisionName(ULONG decision)
	{
		switch (static_cast<Decision>(decision)) {
		case Decision::Allowed: return "ALLOW";
		case Decision::Blocked: return "BLOCK";
		case Decision::WouldBlock: return "WOULD-BLOCK";
		default: return "?";
		}
	}

	inline const char* RiskLevelName(ULONG risk)
	{
		switch (static_cast<RiskLevel>(risk)) {
		case RiskLevel::High: return "HIGH";
		default: return "normal";
		}
	}

	inline bool IsHighRisk(ULONG riskLevel)
	{
		return static_cast<RiskLevel>(riskLevel) == RiskLevel::High;
	}
}

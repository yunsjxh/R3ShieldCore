# R3ShieldCore 内核组件（R0）—— v1：只做「开机自启」

> **本次范围**：把"能编 → 能签 → 能被内核接受 → 开机自动加载"这条链打通。
> **明确不做**：`ObRegisterCallbacks`（引擎自保护）、`PsSetCreateProcessNotifyRoutineEx`
> （进程早发现）、`CmRegisterCallbackEx`（注册表回调）、minifilter（文件/裸盘）。
> 那些是后续按需逐层加的。

---

## 1. 先读这一节：三个绕不过去的前提

### 1.1 内核驱动必须有签名，这不是可选项

x64 的 Windows 从 Vista 起就要求内核驱动有签名。到 Win10 1607+，在**开启 Secure Boot**
的机器上，驱动必须由 **Microsoft 签名**（EV 证书 + 微软 attestation 签名服务，或 WHQL）。

只有三条路：

| 路径 | 能加载的条件 | 适用 |
|---|---|---|
| **A. 本机测试签名** | `bcdedit /set testsigning on` + 重启；**Secure Boot 必须关闭**；桌面出现"测试模式"水印 | 开发机 / 虚拟机。**绝不能分发** |
| **B. EV 证书 + 微软 attestation** | 买 EV 代码签名证书，通过 Microsoft Partner Center 提交做 attestation 签名 | 正式开发期分发 |
| **C. WHQL / MVI** | 走微软硬件认证，或加入 Microsoft Virus Initiative | 正式发布；**只有这条路能拿到 ELAM 证书** |

### 1.2 实测状态

| 项目 | 状态 | 影响 |
|---|---|---|
| WDK | ✅ 已装，在 **10.0.28000.0** | 能编（注意：**不是** `build.sh` 用的 26100） |
| Secure Boot | ✅ **已关闭**（`UEFISecureBootEnabled=0`） | 自签名驱动**可以**加载（实测，见 1.2.1） |
| HVCI / 内存完整性 | ✅ **关闭**（`Enabled=0`） | 同上 |
| testsigning | ❌ 未开启（实测**不需要**） | 只有换到强制机器上才需要 |
| **BitLocker** | ⚠️ **已启用**（启动项含 `FVEBOOT`） | **改启动配置会触发恢复密钥提示** |
| 当前用户 | 非管理员 | 安装/签名需提权 |

### 1.2.1 实测：自签驱动到底能不能加载（2026-10-06）

**别再靠 signtool 的结论推断** —— 直接建服务 + `StartService`，看内核实际返回什么。
工具：`tools/drvload_probe.cpp`（`bash build_drvload_probe.sh` 构建；
`--dump-config` 只读自检，`--start-type boot|system|demand`，默认自动回滚）。

**结果（2×2，两条腿都必须跑）：**

| 启动类型 | 镜像 | `StartService` | 关键证据 |
|---|---|---|---|
| `BOOT_START` | 已签名 | ✅ **成功**（状态 4 = RUNNING） | SCM 7045 `StartType=引导启动` |
| `DEMAND_START` | 已签名 | ✅ **成功**（状态 4 = RUNNING） | CI 3076 |
| `DEMAND_START` | **去掉签名**（同字节） | ❌ **失败 577 / 0xC0000428** | SCM 7000 `%%577`、CI 3004、App Popup 26 |
| `BOOT_START` | **去掉签名**（同字节） | ❌ **失败 577 / 0xC0000428** | 同上 |

**结论（两句话）：**

1. **签名是必要条件** —— 同一份字节只把 PE 安全目录清零，就从"成功"变成"被拒"。
2. **但它不是充分条件** —— CI 事件 3076 原文自己写着：*"...did not meet the
   Authenticode signing level requirements ... **However, due to code integrity
   auditing policy, the image was allowed to load.**"*
   也就是说，本机能跑是**「有签名」+「本机 CI 处于审计模式」**两个条件同时成立的结果
   （`CI\Policy`：`EmodePolicyRequired=0`）。

> ⚠️ **所以：本机能加载 ≠ 别的机器能加载。**
> 换到**强制模式**的机器（HVCI / 内存完整性开启、Secure Boot 开启且走 1607+ 引导策略、
> 或 WDAC enforce 策略）上，这个自签驱动**会被拒**。
> **分发必须走上面的 B / C 两条路**；A（testsigning）只是开发机自测。
>
> 好消息：**本机自测连 testsigning 都不用开**（实测如此），
> 也就**不用去动 `bcdedit`**，顺带避开了 1.2 里那个 BitLocker 恢复密钥的坑。

> ℹ️ 别被 CI 事件 3089 里的 `PublisherName` 带偏：它报的是**策略/交叉证书**数据
> （本项目实测报了某 2018 年的 VeriSign 交叉证书），**不是本文件签名者**。
> 想确认本文件签名者，看 `SHA1 Flat Hash`（= 文件哈希）并用
> `Get-AuthenticodeSignature` 回读。

> ### ⚠️ BitLocker 警告（最容易出事的一步）
>
> 本机 BitLocker 处于启用状态。`bcdedit /set testsigning on` 会改变启动环境度量值，
> 重启时系统**可能要求输入 48 位恢复密钥**。
>
> **动手前请先确认你拿得到恢复密钥**（`aka.ms/myrecoverykey`，或你自己的备份）。
> 拿不到就先别改启动配置 —— 那会把机器锁在恢复界面。

### 1.3 关于 ELAM —— "最快启动"的真实上限

真正最早的内核启动阶段叫 **ELAM**（Early Launch Anti-Malware）：需要
`SERVICE_BOOT_START` + `ELAM` 标志 + **微软 MVI 成员资格颁发的 ELAM 证书**。

**这个证书不是自己签个名就能拿到的**，必须通过微软审核。所以：

> **自签环境里，"最快"的上限就是 `SERVICE_BOOT_START`。**
> ELAM 拿不到（需要微软 MVI 颁发的 ELAM 证书），所以 `SERVICE_BOOT_START`
> 就是实际能到的最早一档。本项目**已经选定这一档**（2026-10-05，用户明确要求
> "最早启动"），代价与对策见第 3 节。

---

## 2. 快速上手

```bash
# ① 构建（产出 .sys + 取证探针）
bash driver/build_driver.sh
#   -> driver/build/r3shieldcore_kernel.sys
#   -> driver/build/driver_probe.exe
```

```powershell
# ② 建测试证书（只需一次，需管理员）
powershell -ExecutionPolicy Bypass -File driver\sign_driver.ps1 -MakeCert

# ③ 开测试签名（需管理员；★ 先确认 BitLocker 恢复密钥）
powershell -ExecutionPolicy Bypass -File driver\sign_driver.ps1 -EnableTestSigning

# ④ 重启（这一步必须做，testsigning 才生效）

# ⑤ 签名
powershell -ExecutionPolicy Bypass -File driver\sign_driver.ps1

# ⑥ 安装为开机自启（需管理员）
driver\install_driver.bat

# ⑦ ★ 重启系统，然后**什么都不要做**，等满 10 分钟再验证
powershell -ExecutionPolicy Bypass -File driver\verify_autostart.ps1
```

**为什么第 ⑦ 步要等 10 分钟**：`sc query` 显示 RUNNING **证明不了**"开机自启"——
你刚手动 `sc start` 过的状态和它一模一样。真正能区分两者的，是驱动自报的
`LoadSinceBootMs`（驱动被加载时系统已开机多少毫秒）：

- 开机自启 → 很小（几秒到几十秒）
- 手动启动 → ≈ 当前系统已运行时长

系统刚开机不到 10 分钟时，两个数都很小、**本来就分不开**，所以验证脚本会
**拒绝给结论**（报"前提不足"），而不是给一个假 PASS。

---

## 3. 启动类型：**已选定 `BOOT_START`**（2026-10-05 变更）

| | `AUTO_START` | `BOOT_START`（★ 本驱动用的） |
|---|---|---|
| 谁加载 | 内核初始化阶段（早于 SMSS / winlogon / **任何**用户态进程） | 引导加载器 |
| 安全模式 | **不加载**（安全模式的驱动集是白名单） | **照样加载** |
| 加载失败会怎样 | 该服务启动失败，**系统照常启动** | 可能进不去系统，**连安全模式都进不去** |
| 抢救方式 | 安全模式 / `uninstall_driver.bat` | 只能 WinRE 离线删文件 |
| 相对收益 | 早于**所有**用户态代码 | 比 AUTO_START 再早几百毫秒 |

**结论（2026-10-05 变更后）**：用户明确要求「最早启动」，所以选了 `BOOT_START`。
这一档换来的收益是「在用户态代码开始跑之前最早」，代价是上表后四行。
既然选了它，就必须靠**驱动自身足够克制**来抵消风险 —— 本驱动正是这么写的：

- 不挂任何回调（`ObRegisterCallbacks` / `PsSetCreateProcessNotifyRoutine` / minifilter 全无）；
- 不改任何别人的注册表项（只写自己服务键下的一个 `LoadSinceBootMs`）；
- **建设备失败也返回 `STATUS_SUCCESS`** —— 目的是"被加载"，不是"必须有设备"。

> **安全模式下的行为**：`BOOT_START` 的驱动**安全模式照样加载**（这是选它的固有代价，
> 改不了）。但 R3ShieldCore 在安全模式下**不会激活**：驱动自己不启动任何进程，
> 而"不拉起用户态引擎"这条由服务 `service/r3shieldcore_svc.c` 的 `IsSafeMode`
> 闸门保证（判据 `GetSystemMetrics(SM_CLEANBOOT) != 0`）。
>
> 想让它在 `BOOT_START` 这一档里**更靠前**，正路是给服务加 `Group` / `Tag`
> （见 `install_driver.bat` 里注释掉的那两行）。但 **`Group` 填错会导致服务
> 根本不被加载**，所以默认注释掉了，要用请先查清楚该 Group 存在。

---

## 4. 设计要点

### 4.1 三条互相独立的证据

只靠一条证据会分不清"没装 / 装了没跑 / 跑了但设备失败"。所以本组件提供三条：

| # | 证据 | 在哪里看 | 失败时能说明什么 |
|---|---|---|---|
| ① | 控制设备 IOCTL | `driver_probe.exe` | 驱动活着并自报状态（含 `LastError`） |
| ② | 注册表加载戳 | `HKLM\SYSTEM\CurrentControlSet\Services\R3ShieldCoreKernel\LoadSinceBootMs` | **不需要任何工具**就能看的落盘证据 |
| ③ | 服务配置 `Start` | 同一注册表键 | `0=Boot 1=System 2=Auto 3=Demand 4=Disabled` |

①与②是**同一个数字的两个来源**，`driver_probe.exe` 会交叉校验（不一致会报出来）。

### 4.2 关键设计决策

- **`LoadSinceBootMs` 用 `KeQueryInterruptTime()`**，在 `DriverEntry` 的**第一件事**里取
  —— 在任何可能失败的操作之前。这样即使后面建设备失败，"我什么时候被加载的"也已经拿到了。
  （顺带一提：`KeQueryInterruptTime` 在新 WDK 里是**宏**，直接读 `KUSER_SHARED_DATA`，
  所以它**不出现在导入表里**。这是正常的，也更快。）
- **建设备失败不返回错误**（仍返回 `STATUS_SUCCESS`）。本驱动存在的意义是"被加载"，
  因为设备名冲突这种小事让整个加载失败，是把手段当成了目的。失败原因会 `DbgPrint`
  出来并记进 `LastError`，用户态查得到。
- **实现了 `DriverUnload`** —— 否则 `sc stop` 无效，只能"禁用 + 重启"才能卸掉。
- **绝不碰系统其它部分**：不挂任何回调、不改任何注册表项（只写自己服务键下的一个值）。
- **结构体两侧布局钉死**：驱动与探针各有一个编译期断言（`sizeof == 40`）。
  布局不一致会读到错位的垃圾，而且**不会报错**。

### 4.3 反过来说：这些"没有"是刻意的

判据（直接跑一遍就能复现）：

```bash
# 真正的"注册调用"一处都没有 —— 这是本次范围的明确边界，不是遗漏
grep -nE "(=|\()\s*(ObRegisterCallbacks|PsSetCreateProcessNotifyRoutine|CmRegisterCallback|FltRegisterFilter)\s*\(" driver/*.c
# 期望输出: 0 处

# 注意：裸 grep 名字会命中 r3shieldcore_kernel.c 第 5 行 —— 那是**文件头的作用域注释**
# （"不做 ObRegisterCallbacks / 不做进程回调 / ..."），是刻意写下来划边界的。
# 所以判据要匹配"调用形式"，而不是"名字出现过"。
```

---

## 5. 安全与回滚

### 5.1 出事怎么办

```bat
rem 正常卸载（可逆：停服务 → 删服务 → 删文件）
driver\uninstall_driver.bat
```

如果进不去系统：

1. **安全模式**：★ `BOOT_START` 的驱动**在安全模式下照样加载**，所以安全模式
   **救不了**这种情况 —— 别再指望它（这是从 `AUTO_START` 改成 `BOOT_START`
   之后最重要的行为差异）。
2. **WinRE**（唯一出路）：删掉
   `%SystemRoot%\System32\drivers\r3shieldcore_kernel.sys`，并删除注册表键
   `HKLM\SYSTEM\CurrentControlSet\Services\R3ShieldCoreKernel`。

### 5.2 恢复干净状态

```powershell
bcdedit /set testsigning off     # ★ 同样会触发 BitLocker 恢复密钥提示
```

然后重启。

### 5.3 本驱动**没有**做的事（所以它不会导致这些问题）

- 不拦截任何系统调用 / 文件 / 注册表 / 进程
- 不保护任何进程
- 不在启动早期做任何决策

它当前的全部行为就是：**记录自己什么时候被加载 + 建一个可查询的设备**。

---

## 6. 构建说明（三个必须知道的坑）

### 6.1 WDK 版本和 `build.sh` **不是**同一个

```
Include/10.0.26100.0/  → 只有 cppwinrt shared ucrt um winrt（**没有 km**）
Include/10.0.28000.0/  → km/ 在这里 ← 内核头/库只在这个版本下
```

跟着 `build.sh` 用 26100 会报 `cannot open include file: 'ntddk.h'`
—— 看起来像"没装 WDK"，实际是版本指错了。

### 6.2 include 顺序和用户态完全不同

```
内核:   km ; km/crt ; shared ; ucrt      ← 绝不能把 um 放进来
用户态: ucrt ; shared ; um
```

把 `um` 混进内核构建会引入用户态原型（同名函数两套签名），报一堆
`conflicting types`，或者更糟 —— 静默按错误原型链接。

### 6.3 参数必须用 `-` 前缀，不能用 `/`

Git-Bash/MSYS 会把**以 `/` 开头的参数当成路径**做 POSIX→Windows 转换：
`/nologo` 变成 `C:/.../PortableGit/.../nologo`，`/D_AMD64_` 被吃掉后内核头直接
`#error "No Target Architecture"`。`cl.exe` / `link.exe` 两种前缀都认，所以统一写 `-`。

### 6.4 两道字符集闸门（都是踩过的坑换来的）

| 文件类型 | 要求 | 原因 | 工具 |
|---|---|---|---|
| `.c` | 不能有 CP936 编不出的字符 | C4566 只会**静默丢掉**那个字符（`"⚠ 失败"` → `" 失败"`） | `tools/check_source_gbk.py`（已接进 `build_driver.sh` 预检） |
| `.bat` | **CRLF + GBK + 无 BOM** | 中文 + 裸 LF 会让 `cmd` 解析失同步 → 脚本一闪而过 | `tools/bat_gbk_crlf.py` |
| `.ps1` | **UTF-8 + 有 BOM** | 无 BOM 时 PS 5.1 按 936 解码，注释末尾的中文会**吞掉换行**，把下一行并进注释 | `tools/ps1_add_bom.py` + `tools/ps1_ansi_swallow_check.py` |

> 顺带修了一个闸门自身的 bug：`ps1_ansi_swallow_check.py` 和 `ps1_add_bom.py`
> 原来只扫 `tools/*.ps1` 和 `*.ps1`，**新增的 `driver/` 目录根本不在扫描范围内**
> —— 闸门一直显示 PASS。已改成递归扫全仓。改完立刻抓到
> `driver/sign_driver.ps1` 里一处真实的"注释吞掉下一行"。

### 6.4b `dir` 通配符位置闸门（`tools/check_bat_dir_wildcard.py`）

`dir` **只支持最后一段**带通配符。写成中间段带 `*` / `?` 时它不报错、不提示，
就是 **exit=1 + 零输出**：

```
dir /b /s "D:\Windows Kits\10\bin\*\x64\signtool.exe"   -> exit=1，零输出
dir /b /s "D:\Windows Kits\10\bin\*.exe"                -> 正常
```

放进 `for /f` 里就变成**静默 0 次迭代**（`for /f` 对"命令失败"和
"命令成功但没输出"一视同仁），最后落到"找不到 X，跳过这一步"。

★ 这个坑**真踩过**：`install_driver.bat` 的签名预检就是这么坏的 ——
它从来没找到过 signtool，所以**签名预检从来没执行过**，而每次输出都是那句
无辜的"找不到 signtool.exe，跳过签名预检"。已改成 `for /d` + `if exist`，
并加闸门防复发（已接进 `build_driver.sh` 预检 0b，带 `--selftest` 负对照）。

### 6.5 产物校验（构建脚本会自动做）

```
8664 machine (x64)          ← 机器码对
1 subsystem (Native)        ← 内核映像必须走 native 子系统
characteristics = 0x22      ← 与 null.sys / Beep.sys / WdFilter.sys 一致
导入表只有 ntoskrnl.exe      ← 出现 kernel32/ucrtbase 就是坏的
```

---

## 7. 交付物

| 文件 | 作用 |
|---|---|
| `r3shieldcore_kernel.c` | 驱动源码（只做自启 + 三条证据） |
| `build_driver.sh` | 直驱 `cl.exe`/`link.exe` 构建（WDK 28000），产出 `.sys` + 探针 |
| `driver_probe.c` | 用户态取证：三条证据 + 交叉校验 + 前提门控 |
| `sign_driver.ps1` | 签名参考实现（`-MakeCert` / `-EnableTestSigning` / 签名 / `-Verify`） |
| `install_driver.bat` | `sc create type= kernel start= boot` + 启动（GBK+CRLF） |
| `uninstall_driver.bat` | 停 + 删 + 删文件（可逆） |
| `verify_autostart.ps1` | 重启后验证"开机自启"（含前提门控） |

---

## 8. 下一步（本次**未做**，按需逐层加）

| 想解决的问题 | 需要的内核机制 | 备注 |
|---|---|---|
| 引擎被 `TerminateProcess` 强杀 | `ObRegisterCallbacks` 去掉 `PROCESS_TERMINATE` | 收益/风险比最高，建议下一步做这个 |
| 进程启动有窗口期（"第四道门是时间"） | `PsSetCreateProcessNotifyRoutineEx` | 早于用户态注入 |
| 注册表拦截可被绕过 | `CmRegisterCallbackEx` | 不依赖 SSDT/Inline hook |
| XP Horror 写 MBR 失守 | minifilter `FltRegisterFilter` 拦 `IRP_MJ_WRITE` | 工程量最大 |

架构原则要守住：**驱动不做策略**。R0 只做"早发现 + 快速判据早阻断"，策略留在
用户态引擎，中间一条通信通道。真要做到这一步，就需要 `IoCreateDeviceSecure`
给设备加明确的 DACL、以及一条内核↔用户态通道 —— 这些等本层的加载链验证通过再谈。

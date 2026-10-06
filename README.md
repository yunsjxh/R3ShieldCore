# R3 ShieldCore

**Windows 用户态行为拦截引擎** —— 通过全局注入 + API Hook，在**系统调用进入内核之前**
拦下高危行为，并在弹窗中询问用户。

> ⚠️ **仅用于学习、研究与自用防护。** 本项目 hook 的是 Windows 未文档化内核接口
> （`ntdll.dll` 的 `Nt*` 系列），依赖大量未公开 ABI 细节。**请勿**用于生产环境、
> 商业分发或任何需要稳定性的场合。详见 [免责声明](#免责声明)。

---

## 这是什么

一个用 C++20 写的 Windows 用户态安全代理（HIPS）：

- **拦截**：把注入 DLL 挂进所有进程（新进程在创建时就被注入），hook `ntdll.dll`
  导出表里的关键 `Nt*` 函数，在**行为发生前**决定 放行 / 拒绝 / 询问。
- **询问**：高危操作弹出自绘卡片，用户点"允许一次 / 永久允许 / 拒绝"。
  询问通道不可用时按 `prompt_default` 降级（默认拒绝）。
- **三种模式**（`r3shieldcore.ini` 的 `mode`）：
  | 模式 | 行为 |
  |---|---|
  | `log` | 只记录，全部放行 |
  | `block` | 命中高危规则即硬拒绝 |
  | `ask` | 命中高危规则先询问，用户说了算 |
  | `block_all` | 除可信来源外全部拒绝 |
  | `block_all_safe` | 强隔离，但保住系统基本可用（与 `block_all` 仅差一组白名单） |

- **架构**：

```
┌────────────────────────────────────────────────────────────┐
│  内核驱动  r3shieldcore_kernel.sys   (BOOT_START, 可选)     │  ← 开机即加载
│    只负责"我加载了"，不启动任何用户态进程                    │
├────────────────────────────────────────────────────────────┤
│  守候服务  r3shieldcore_svc.exe      (LocalSystem, AUTO)    │  ← 开机即起
│    把引擎拉进"有交互用户的会话"（同一会话只拉一次）          │
├────────────────────────────────────────────────────────────┤
│  引擎      R3 ShieldCore.exe         (用户会话, 提权)        │  ← 真正干活
│    ├─ 注入器：把 32/64 位 DLL 挂进所有进程                  │
│    ├─ Hook 层：ntdll 的 Nt* + user32/advapi32 等            │
│    ├─ 规则层：17 类受监控对象的高危判定                     │
│    └─ GUI：日志页 / 统计页 / 询问弹窗 / 超级置顶面板        │
└────────────────────────────────────────────────────────────┘
```

## 监控面（17 类）

| 模块 | 拦截对象 |
|---|---|
| `registry_guard` | 注册表写（key 级 + hive 级：`NtLoadKey`/`NtSaveKey`/`NtRestoreKey`…） |
| `file_guard` | 文件写 / 删除 / 移动 |
| `process_guard` | 进程创建（**先问再拦**） |
| `thread_guard` / `inject_policy` | 远程线程、跨进程内存写（**先问再拦**） |
| `driver_guard` | 驱动/服务加载 |
| `network_guard` | 出站连接 / 监听 |
| `camera_guard` | 摄像头占用 |
| `clipboard_guard` | 剪贴板读写 |
| `screen_guard` | 截屏 |
| `input_hook_guard` | 全局键鼠钩子 |
| `dll_load_guard` | 模块加载 |
| `spawn_guard` | 进程派生面 |
| `service_config_guard` | 服务配置篡改 |
| `com_hijack_guard` | COM 劫持（`InprocServer32` 等） |
| `scheduled_task_guard` | 计划任务 |
| `token_theft_guard` | 令牌窃取 |
| `wmi_subscription_guard` | WMI 事件订阅持久化 |
| `host_hijack_guard` | hosts / 加载器劫持 |

> 进程创建、远程线程、跨进程内存这三类是**先问再拦**（`prompt_default=deny`），
> 其余为硬拒绝。原因：v20 的全硬拒把金山毒霸的 UAC 组件、VMware Tools
> 一起格杀了 —— 一刀切会把系统打死。

## 构建

### 依赖

| 依赖 | 说明 |
|---|---|
| **Visual Studio 2022+**（含 C++ 桌面开发工作负载） | 提供 `cl.exe` / `link.exe` |
| **Windows SDK 10** | 提供头文件、库、`rc.exe` |
| **WDK**（仅构建内核驱动时需要） | 提供 `km/` 头与库（`ntddk.h` 等） |
| **Python 3**（纯标准库） | 生成图标、打包、字符集闸门 |
| **MSYS2 ucrt64**（仅构建安装包时需要） | 提供 `gcc` / `windres` |
| **Git Bash / MSYS2** | 运行 `.sh` 构建脚本 |

所有工具的路径都是**自动探测**的（见 `scripts_env.sh`），可用环境变量覆盖：
`MSVC_ROOT` / `SDK_ROOT` / `SDK_VERSION` / `PYTHON` / `GCC`。

### 构建引擎（主程序 + 注入 DLL + 服务）

```bash
bash build.sh              # Release，x86 + x64
bash build.sh Debug        # Debug
bash build.sh Release x64  # 只编 x64
```

产物落在 `R3ShieldCore/Release/`（`R3 ShieldCore.exe` / `R3 ShieldCore-x86.exe` /
`r3shieldcore_svc.exe` / `32|64/r3shieldcore-lib.dll`）。

> 为什么直接调 `cl.exe` 而不用 MSBuild？本机 `devenv.com` 只会把 IDE 拉起来、
> 不执行命令行构建；`MSBuild.exe` 被安全策略按名字拦截。脚本用的是同一套编译器、
> 同样的参数，产物与 IDE 构建等价。详见 `build.sh` 顶部注释。

### 装配发布目录（打包前**必须先做**）

```bash
bash deploy_dist.sh                  # -> dist/R3ShieldCore-x64/
```

`build.sh` 只把产物写进 `R3ShieldCore/Release/`，**不会**碰 `dist/`。
`deploy_dist.sh` 负责搬运 + 编译 `dskill.exe` + 验收：

1. 校验 `Release/` 里 4 个引擎产物都在（缺了就明说"先跑 `build.sh`"）；
2. 编 `tools/dskill.cpp` → `dist/R3ShieldCore-x64/dskill.exe`（逃生门工具）；
3. 按约定布局拷贝 —— **exe 放根、DLL 必须放 `64/` 与 `32/`**
   （注入器按目录名选架构，放错位置等于 32 位进程完全没有防护）；
4. 调 `check_dist_sync.sh` 验收，判据是**内容相等（md5）**而不是"文件存在"。

> 这一步以前是**手工 `cp`**，代价是出过一次真实事故：x86 DLL 停在旧代次构建，
> 发布包"文件都在、大小也对、闸门也全绿"，而 32 位进程一条事件都没有。
> 详见 `check_dist_sync.sh` 顶部注释。

### 构建内核驱动（可选）

```bash
bash driver/build_driver.sh          # Release x64
bash driver/build_driver.sh Debug
```

> ⚠️ 内核驱动需要**签名**才能在主流的 64 位 Windows 上加载。开发自测可开启
> 测试签名模式（`bcdedit /set testsigning on`）；正式发布需 EV 代码签名证书。
> 详见 `driver/README.md`。
>
> **「可选」的确切含义**：不编驱动也能跑完整条发布流程
> （`build.sh` → `deploy_dist.sh` → `build_dist_zip.sh` → `installer/build_setup.sh`）。
> 差别只在安装包里：
>
> | | 编了驱动 | 没编驱动 |
> |---|---|---|
> | 安装包 | **完整包** | **仅用户态包** |
> | 装驱动那步 | 正常执行 | 自动跳过（引擎照常工作，只是没有「开机优先加载」） |
> | 构建时 | 无提示 | 打印醒目警告 + 结论行写「**未包含**」 |
> | `selftest_setup.py` | 驱动断言全跑 | 驱动断言标 `[SKIP]` 并计数 |
>
> 驱动是构建产物，**不进版本库**（`.gitignore` 的 `build/` 规则），所以
> `git clone` 下来默认就是「仅用户态包」。
>
> ★ **官方发布必须用完整包**：加 `--require-driver`，让驱动缺席变成硬失败，
> 避免误发一个少了组件的包。

### 构建安装包（单文件原生 GUI 安装器）

```bash
bash installer/build_setup.sh                    # -> dist/R3ShieldCore-Setup.exe
bash installer/build_setup.sh --require-driver   # 官方发布：驱动缺席即失败
```

> 需要 MSYS2 `ucrt64` 的 `gcc` + `windres`（payload 以 zlib 压缩后作为 RCDATA 内嵌）。
> 产物自检（**不碰系统**）：`python installer/selftest_setup.py`
> （`--verify` / `--extract` 只读；第 4 层"真机装→卸"需要管理员）。
> 构建结尾会打印 `内核驱动 : 已包含 / **未包含**` —— 这是两种产物之间**唯一**的实质差异，
> 所以它必须出现在结论里，而不是只在滚屏警告里。
>
> `installer/build_installer.sh` 是**老路**（iexpress 自解压），仅作兼容保留，
> 产物固定叫 `dist/R3ShieldCore-Setup-iexpress.exe`，不会覆盖上面的正式产物。

### 打包绿色版

```bash
bash build_dist_zip.sh               # -> dist/R3ShieldCore-x64.zip
```

## 目录结构

```
.
├── R3ShieldCore/            引擎源码（VS 工程 + 直接构建脚本两种入口）
│   ├── R3ShieldCore/        主程序（GUI / ARK / 配置 / 统计）
│   ├── R3ShieldCoreLib/     注入 DLL（17 个 guard + hook 层）
│   │   └── libraries/       第三方预编译库（MinHook / wow64ext）
│   ├── shared/              ABI 定义、共享代码
│   └── tests/               单元测试
├── service/                 开机启动服务（纯 C）
├── driver/                  内核驱动（WDM）+ 签名/安装脚本
├── installer/               安装程序（原生 Win32 GUI，单文件）
├── tools/                   探针 / 单测 / 诊断器 / 闸门脚本
├── docs/                    技术文档（代码评价、窗口 Hook 预研）
├── demo/                    GUI 截图
├── build.sh                 引擎构建入口
├── scripts_env.sh           ★ 工具链自动探测（所有脚本共用）
└── dist/                    发布产物（构建生成，不入版本库）
```

## 配置

引擎读同目录下的 `r3shieldcore.ini`（**硬编码在 exe 同目录，无 ProgramData 回退**）。
仓库自带 5 个预设：`r3shieldcore.ini`（默认）、`-safe-first`、`-block`、
`-blockall`、`-blockallsafe`。

> ⚠️ 如果装到 `Program Files` 下，**用户手动编辑 ini 会被父目录的标准 ACL
> （`Users:(I)(RX)`）挡住** —— 这是 Windows 的默认行为，安装器不加任何 ACL。
> 用户态引擎自己不受影响（它 `requireAdministrator` 提权，写得进）。
> 要放开：`icacls "<安装目录>" /grant *S-1-5-32-545:(OI)(CI)M`，或用管理员编辑，
> 或装到非 `Program Files` 目录。

## 自测

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

`tools/` 下还有大量**只读探针**（`*probe*`），用于验证 hook 是否真的挂上、
规则是否真的命中 —— 它们本身就是本项目"用实验代替猜测"工作方式的产物。
> ⚠️ 但 `tools/` 里的 `test_gui.sh` / `accept_file_modes.sh` / `test_ask_mode.sh` /
> `test_selfprotect.sh` 属于**验收脚本**，它们会启动引擎 —— 同样请在隔离环境跑。

## 已知边界

- **拦截第四道门是时间**：进程启动到注入完成之间有盲区，极短的启动窗口内
  行为可能漏过。
- **只做用户态**：不拦内核态发起的操作；驱动层只负责开机加载，不做拦截。
- **`requireAdministrator`**：引擎必须以管理员运行，否则大面积失效。
- 本项目**没有**单实例互斥体 —— 不要同时跑两份引擎（两套 hook 会打架）。

## 免责声明

本项目按 "AS IS" 提供，**不附带任何明示或暗示的担保**。它是一个
**教育 / 研究性质**的安全工具，作者不对因使用本软件造成的任何直接或间接损失
（包括但不限于系统损坏、数据丢失、业务中断）承担责任。

- 请在你**拥有或已获授权**的系统上使用。
- 本项目**不**收集、上传任何用户数据。
- 二次分发请遵守 [GPL-3.0](LICENSE)。

## 许可

[GNU General Public License v3.0](LICENSE)。

本项目的注入/hook 框架派生自
[m417z/global-inject-demo](https://github.com/m417z/global-inject-demo)
（见 `R3ShieldCore/README.md`），遵循其原始许可。
第三方组件：

- **MinHook** —— BSD 2-Clause，© 2009-2017 Tsuda Kageyu
  （`R3ShieldCore/R3ShieldCoreLib/libraries/MinHook/`）
- **wow64ext** —— GNU LGPL-3.0，© 2014 ReWolf
  （`R3ShieldCore/R3ShieldCoreLib/libraries/wow64ext/`）

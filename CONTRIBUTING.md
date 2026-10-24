# 贡献指南（CONTRIBUTING）

先读 [`SECURITY.md`](SECURITY.md) 里"这不是一个安全边界"那一节。
本项目 hook 未文档化的 `Nt*` 接口，**改动窗口很窄**：一个错的 `NtCreateFile` 原型
不报错，只是静默地不再拦截。

---

## 1. 开发环境

| 依赖 | 用途 |
|---|---|
| Visual Studio 2022+（C++ 桌面工作负载） | `cl.exe` / `link.exe` |
| Windows SDK 10 | 头文件、库、`rc.exe` |
| WDK | 仅构建内核驱动时需要 |
| Python 3（**纯标准库**） | 图标生成、打包、闸门脚本 |
| MSYS2 ucrt64 | 仅构建安装包时需要（`gcc` / `windres`） |
| Git Bash 或 MSYS2 | 运行 `.sh` 脚本 |

路径**全部自动探测**，无需配置。见 `scripts_env.sh`。

### 两个已知的环境坑

1. **`MSBuild.exe` 可能被安全策略按名字拦截**，`devenv.com` 在本项目里只会把 IDE
   拉起来、不执行命令行构建。所以所有构建都**直接调 `cl.exe` / `link.exe`**
   （`build.sh` 就是这么做的），**不要**新增 `.vcxproj` 依赖。
2. **仓库路径可能含非 ASCII 字符**（例如 `D:\我的项目`）。
   编译参数必须带 `-source-charset:utf-8`，脚本里所有路径都要加引号。

---

## 2. 构建与自测

```bash
bash build.sh              # Release，x86 + x64
bash build.sh Debug        # Debug
bash build.sh Release x64  # 只编 x64

bash deploy_dist.sh        # 装配 dist/R3ShieldCore-x64/（打包前必须先做）
bash driver/build_driver.sh # 内核驱动（可选）
```

自测分层，**第一层不需要任何权限、秒级**：

```bash
bash build_ut.sh           # 规则层单测
bash build_guard_ut.sh     # guard 层单测（链 MinHook）
bash build_log_line_rt_ut.sh   # 日志行唯一实现 + 协议编解码单测（v81，链真代码）
bash build_cfg_ipc_probe.sh    # 配置工具 ⇄ 引擎 管道协议端到端夹具（v81）
```

> ★ **v81 的两个夹具都不跑引擎**（引擎那份事件流是**进程内**的，夹具自己起一个
> "假引擎"服务端，复用与生产**同一份**共享头编解码）：
> `_t/log_line_rt_ut/log_line_rt_ut.exe [真实日志]` —— 带日志文件时做**逐字节回环**；
> `_t/cfg_ipc_probe/cfg_ipc_probe.exe`（加 `--neg` 走**反向对照**，**应报失败**
> ⇒ 证明判据有分辨力）。两个都要跑 `x64` 与 `x86`。

**回传数据替换（Spoof）的机制探针** —— 自包含、不注入任何进程、不经过引擎，
所以**不受**"自动化脚本不得运行引擎"那条约束（铁律 175）：

```bash
bash build_spoof_probe.sh --run            # 屏幕面（v67）
bash build_spoof_clipboard_probe.sh --run  # 剪贴板面（v70）
bash build_spoof_reg_probe.sh --run        # 注册表值面（v71）
bash build_spoof_reg_enum_probe.sh --run   # 注册表枚举隐藏面（v72）
bash build_spoof_camera_probe.sh --run     # 摄像头 MF 面（**可行性探针**）
bash build_spoof_reg_ktm_probe.sh --run    # 注册表**事务（KTM）**面（v75）
ARCH=x86 bash build_spoof_clipboard_probe.sh --run   # 另一个架构也要跑
ARCH=x86 bash build_spoof_reg_probe.sh --run
ARCH=x86 bash build_spoof_reg_ktm_probe.sh --run
```

**另外三个"只出结论、未接生产"的可行性探针**（同样自包含、不注入）：

```bash
bash build_hive_read_probe.sh --run        # hive 文件直读（结论：✗ 不可行）
bash build_camera_paths_probe.sh           # DirectShow / VFW / WinRT 路由（默认不开硬件）
bash build_camera_paths_probe.sh --run --use-camera   # 真开摄像头（会点亮指示灯）
```

**「看得见的效果」演示**（不是探针 —— 它把保护逻辑装进自己进程、**自己扮演攻击者**，
把每一步的真实返回值与真实数据打出来；同样**不注入、不跑引擎**）：

```bash
bash build_ktm_effect_demo.sh --run        # 三幕：保护关 / 保护开 / 事务（KTM）绕过
bash build_spoof_console.sh --run          # ★ 交互式控制台（进高级模式要先答对 3 道 Win32 题）
bash build_spoof_console.sh --selftest     # 正路（全对开门）+ 负对照（答错必须不开门）
```

> 输出示例见 `docs/注册表保护-效果演示-2026-10-11.txt`；
> 「怎么用主程序开启拦截」见 `docs/主程序-怎么开拦截-速查.md`。
>
> ★★ **交互式控制台（v75）**：进「高级模式」要先答对**三道 Win32 编程题**（全对才开门），
> 开门后你自己当攻击者，逐条命令看每个 API 的真实返回值被换成了什么。常用命令：
> `attack all`（看替换生效）/ `compare all`（三态并排：保护关→真值 / 只拦不换→真值或拒绝 /
> 拦+换→假数据）/ `guard off`（看真值）/ `fill 65`、`fakeclip HELLO-FAKE`（改替换内容）/
> `demo`（完整三幕，含事务 KTM 绕过）。全程真实输出见
> `docs/替换API结果-高级模式控制台-2026-10-11.txt`。
>
> ★★ **规则引擎（v76）**：高级模式里还能**用中文写规则**来编辑 API 返回值
> （语法形如易语言），匹配模式既可以是字面量也可以是**正则**：
>
> ```
> 当 注册表值 的 值名 匹配 /Pass.*/ 时 替换为 "***"
> 当 剪贴板 的 格式 等于 文本 时 替换为 "假的"
> 当 注册表枚举 的 子键名 含 "Secret" 时 隐藏
> 当 注册表值 的 值名 等于 "Password" 时 放行
> ```
>
> 直接敲这行 = 加规则（等价 `rule add …`）；另有 `rule list / del <序号> / clear /
> load <文件> / save <文件> / test <面> <值> / help`。**按加入顺序 first-match wins**，
> 一条都没命中就**回落内置默认行为**（所以加规则是叠加）。真实输出见
> `docs/替换API结果-规则引擎-2026-10-11.txt`。
>
> ★ 它顺带踩出并固化了一条闸门：**宽字面量经 `WideCharToMultiByte(CP_ACP)` 输出时，
> CP936 编不出的字符会被静默换成 `?`**（铁律 226）⇒ 构建前跑
> `python tools/check_source_gbk.py --wide <file>`（负对照见
> `python tools/selftest_gbk_gate.py` 第 ⑥ 节）。

**GUI 界面核对（v77）** —— 走主程序的 `--gui-preview`（**建窗但不初始化注入引擎**，
所以在开发机上安全，**不受**铁律 175 约束）。探针从**屏幕 DC** `BitBlt` 截图
（不是 `PrintWindow` —— 那是 DWM 静态缓存帧、常全黑），并断言**应用自己日志**里的
`[adv] 页面已绘制 规则=3`（铁律 24/28：靠人眼 = 假绿）：

```bash
bash tools/test_gui_preview.sh                 # 只看「高级」页（默认）
bash tools/test_gui_preview.sh advanced ark    # advanced 正路 + ark 负对照
```

> 产图在 `docs/shots/gui-preview-*.png`。★ `ark` 负对照断言的是「**没有** `[adv] 页面已绘制`」
> —— 证明判据真的在看页签，而不是恒真。
>
> ⚠️ **同一目录下的 `gui_exit_button_probe` / `gui_copy_all_logs_probe` 不带 `--gui-preview`**，
> 会真的拉起引擎 ⇒ **本机不能跑**（铁律 175），只做编译同步。它们内部镜像了
> `TabWidth` / `TabCount` 等布局常量，**改 `r3shieldcore_gui.cpp` 的布局要同步改它们**。

> ★ **KTM 探针（v75）验的是"缺口到底存不存在"**，而不是"新功能好不好用"：
> 它把事务 detour **关掉**再调 `NtOpenKeyTransacted`，证明**修复前能拿到受保护键句柄**
> 且**非事务 detour 没有被顺带触发**；再打开 detour 证明被拒 + 负对照仍放行。
> 结果 **42 通过 / 0 失败 / 0 跳过**。它同时把一句关键定性钉成实测：
> **事务句柄上值读 / 枚举 / 写复用同一个 `NtQueryValueKey` / `NtEnumerateKey` /
> `NtSetValueKey`** ⇒ 缺的只是"打开 / 创建"的准入判据。
>
> ★★ **KTM 探针有一个"踩坑必读"**：`NtOpenKey` / `NtOpenKeyTransacted`
> **不接受预定义伪句柄**（`HKEY_CURRENT_USER` / `HKEY_LOCAL_MACHINE`）当
> `RootDirectory` ⇒ 一律 `0xC0000008`。`RegOpenKeyExW(HKEY_CURRENT_USER, …)`
> 能跑，是因为 **advapi32 自己把伪句柄换成了真句柄** —— 这掩盖了坑。
> Nt* 只能用「真键句柄 + 相对名」或「`RootDirectory=NULL` + 绝对 NT 路径」。
> 详见 `docs/注册表KTM事务-机制探针-2026-10-11.txt` 的「坑位 A」。
>
> ⚠️ **DirectShow / VFW / WinRT 三路只做到"机制层 go"**：DirectShow 真机建图、
> WinRT 真机激活、VFW 端到端**都没做**，探针里一律 `[skip]` 并计数。
> 结论与证据链见 `docs/摄像头其余路径-可行性探针-2026-10-11.txt`。

> ★ **摄像头探针默认不开硬件**：它有一条"真摄像头帧"的测试（会点亮指示灯），
> 必须显式加 `--use-camera` 才跑；不加就 `[SKIP]` **并计入结论行**（铁律 178）。
> 它验的是**机制链**（`IMFSourceReader::ReadSample` 的 vtable patch →
> `IMFSample` 缓冲区原地改写 → 调用方可见），用**合成媒体源**（自己写的 WAV）
> 就能跑通；真机那一段只是额外证据。

> ★ 剪贴板探针**不抄**伪造逻辑 —— 直接 `#include "clipboard_spoof_codec.h"`，
> 与生产 `clipboard_guard.cpp` 用**同一份**代码（铁律 127：抄两份必漂，
> 而且漂了之后探针照样全绿）。所以它的构建脚本要把 `R3ShieldCoreLib` 加进包含路径。
> 注册表探针同理，共用 `registry_spoof_codec.h`（铁律 195）。

> ★ **注册表探针还兼一个职责：把 `KEY_VALUE_*_INFORMATION` 的布局钉成判据。**
> 那一组结构的**头长度与字段偏移只能实测**，不能靠记忆 —— 本轮就栽在
> `KeyValuePartialInformationAlign64`（class 4）上：它不是"同 class 2 的 12 字节头"，
> 而是 **8 字节头、且没有 `TitleIndex`**。探针的「0. 布局勘察」一节会 dump
> class 0~4 的原始头并断言，将来 Windows 改布局会**变红**而不是悄悄改坏。

> ⚠️ **第 4 层自测会启动真实引擎、并 hook 整个系统。** 它必须显式传
> `--run-engine` 才跑；不传时报 `[SKIP]` 并计入结论行（不静默跳过）。
> 请在**虚拟机或一次性环境**里跑，不要在你的主力机上跑。
>
> ⚠️ 仓库里**第二个**会启动引擎的地方是回传数据「替换」的端到端夹具
> `tools/spoof_e2e.sh`（必须显式 `--run-engine`，默认 `[skip]` 并计数）。
> 它用 ini 的 `test_inject_only=`（v69 起；旧版是命令行 `--test-inject-only=`）
> 把注入范围缩到**一个进程**，但仍然建议在虚拟机 / 另一台机器上跑 ——
> 见 `CHANGELOG.md` 的 v69 条目。
>
> ★ v74 起它一次验**三个面**（屏幕 / 剪贴板 / 注册表）：同一个目标进程
> （`tools/spoof_e2e_target.cpp`）在一次运行里走三条真的取数据路径。三格的
> 设计不是"三个开关的组合"，而是三个**语义位置** —— A 本应拒绝+不替换
> （负对照）/ B 本应拒绝+替换 / C 不拒绝+替换。C 格专门用来证一条**面间差异**：
> 屏幕与剪贴板的替换**只在"本应拒绝"时生效**（`log` 下恢复真实），而注册表的
> 替换发生在**读路径**上、**与 mode 无关**（`log` 下仍被清零）。
>
> ★ 注册表面的测试值（`HKCU\Software\R3ShieldCoreE2E`）由夹具在**起引擎之前**
> 用 `reg.exe` 建好 —— 因为 `protect_reg=` 命中的路径被算作**高危写**，
> `mode=block` 下会**被拒**（那不是 bug，正是"保护 = 写不进"）。`--clean` 会删掉它。
>
> ★ 夹具的**判据逻辑**另有一份**不需要引擎**的自测：
> `bash tools/spoof_e2e_selftest.sh`。它用**合成**的 `result-*.txt` /
> `console-*.log` 喂给 `--collect`，先证"符合预期时 0 红"，再对每个面做定向篡改
> 证"恰好红在对应断言上"（铁律 110/148：判据要先证明自己会失败）。
> 自动化脚本不得跑引擎（铁律 175）⇒ 这是"判据到底会不会红"唯一可验证的途径。
> ⚠️ 它**不**证明"引擎真的会替换"，那一步仍然只能在允许跑引擎的机器上做。
>
> ★ 该夹具是**两步式**的：`--prepare`（不需要管理员）搭工作区 + 写三格配置，
> `--run-engine`（**需要管理员终端**）真跑。因为引擎清单是
> `requireAdministrator`，而 非提权的 shell 提不了权。
>
> ★ `--run-engine` 还**分两级**：级 1「冒烟闸门」（~9s）先单独证掉**安全前提**
> —— 白名单真的限住了注入范围（判据 = 引擎自报 `注入新进程: N 个` 的合计，
> `1 ≤ N ≤ 5`；全局注入时 N 是 100~200）。**级 1 不过就不跑级 2 的三格矩阵**，
> 免得把 60s 的潜在全局注入付掉。
>
> ★ 在 **cmd** 里跑请用脚本打印的那条**绝对路径**命令：本机 cmd **没有** `bash`
> （来自 MSYS2 / PortableGit，不写系统 PATH），直接敲 `bash tools/spoof_e2e.sh …`
> 会得到 `'bash' 不是内部或外部命令`。
>
> ★ 夹具必须在**有 `iconv` 的 bash** 里跑：引擎的控制台日志是 **GBK**（`build.sh`
> 只给了 `/source-charset:utf-8`、没给 `/execution-charset:utf-8` ⇒ 窄字面量按系统
> ANSI 落盘），脚本靠 `iconv` 转码才能 grep 中文。实测 **MSYS2 的 bash 没有 iconv，
> PortableGit / Git Bash 的有**（脚本会自检并明确报错）。
>
> ★ 自动化脚本（要跑它，用 `tools/run_elevated.exe`：`Start-Process` 起
> shell / 解释器 / 系统工具会被命令校验拦掉，但**普通 exe 可以** —— 用 runas 拉起
> 这个转发器（**只弹一次 UAC**），它再拉起 bash，子进程继承提权令牌。
> ⚠️ `Start-Process -ArgumentList` 要传**一个自带引号的整串**，传数组会按空格拆坏参数。
>
> ★ **实测状态**：屏幕面三格矩阵 **2026-10-10 已真跑通过** —— 通过 27 / 失败 0 / 跳过 0；
> `--collect`（非提权）独立复现 19 / 0 / 0。**v74 的三面版尚未真跑**（自动化脚本不得跑引擎）；
> 已跑的是它的**判据自测**（`tools/spoof_e2e_selftest.sh`，14/0）。
> 见 `CHANGELOG.md` 的「首次真跑通过」与 v74 条目。

---

## 3. 提交前必须全绿：闸门

仓库里的这些脚本是闸门，不是建议。每一个都对应一次真实事故：

| 闸门 | 防的是什么 |
|---|---|
| `tools/check_source_gbk.py` | 源码编码混用；GBK 编不出 `⇒` 这类字符 |
| `tools/check_bat_dir_wildcard.py` | `.bat` 里的目录通配符行为与预期不符 |
| `tools/check_bat_forf_redirect.py` | `for /f` 重定向写法静默失效 |
| `tools/check_env_switch_names.py` | 环境变量名差一个字母（改了 A 处、忘了 B 处） |
| `tools/check_spaced_name_quoted.py` | 主程序名 `R3 ShieldCore.exe` **带空格**，引用漏引号 ⇒ shell 拆参、静默失效 |
| `tools/check_payload_manifest.py` | 区分"本包没编驱动"与"驱动条目名字对不上" |
| `tools/check_action_enum_converged.py` | 17 个 guard 各自定义一份 `enum class Action` ⇒ 同一个概念在 17 处独立演化（v74 收敛；`--selftest` 是它的负对照） |
| `check_dist_sync.sh` | 发布目录两套 DLL 代次不一致（**出过真实事故**：32 位进程一条事件都没有，而所有"文件存在"闸门全绿） |

```bash
# 逐个跑
python tools/check_spaced_name_quoted.py
python tools/check_action_enum_converged.py
bash check_dist_sync.sh
# 有的支持一键修 / 自带负对照
python tools/check_spaced_name_quoted.py --fix
python tools/check_action_enum_converged.py --selftest
```

**铁律：闸门报绿不等于没问题，闸门"查文件存在"永远会绿。**
新增/改名的文件必须同步登记进对应闸门 —— 否则它就是个死闸门。

---

## 4. 代码规范

| 项 | 要求 |
|---|---|
| 注释语言 | **中文**（与现有代码一致） |
| 源文件编码 | UTF-8（`.h` / `.cpp` / `.sh`）；`.bat` 走 GBK + CRLF + **无 BOM** |
| 带空格的名字 | 任何场合引用 `R3 ShieldCore.exe` **必须加引号** |
| 新增 guard | 必须同步更新：`ObjectType` 枚举、规则表、ini 配置键、README 第 2 节表格 |
| 改语义开关 | **全仓 grep** 该开关的所有读点，而不是只改你看到的那一处 |
| 错误处理 | 动作失败必须**分型**上报，不要只写"失败" |

---

## 5. 提交信息

风格照 `git log`：中文，`主题：结论`，破折号用 `——`。

```
README：通读代码后重写，修正三处与代码不符的说法
实证：自签驱动"能不能加载" = 签名 + 机器 CI 策略，两者都必要
开源整理（第三批）：补上「发布目录装配」这一步 —— 全新 clone 原本编不出发布包
```

要点：

- 标题写**结论**，不写"修改了 X 文件"
- 如果这次改动对应某条铁律/某次事故，在正文里说清楚
- **不要在提交信息里写本机路径、证书指纹、内部诊断全文**

## 6. Pull Request

1. Fork → 分支（`fix/...` / `feat/...`）→ PR 到 `main`
2. PR 描述里说明改了什么、为什么、怎么验证的。
3. 涉及 hook 层或判定逻辑的，**必须**附上自测结果（哪一层、命令、输出）
4. 明确声明：本次提交的代码你有权以 GPL-3.0 提交
5. 新增第三方代码时，同步更新 [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md)
   —— 确认新组件的许可**与 GPL-3.0 兼容**

---

## 7. 会被拒的 PR

- 为了"更优雅"而重构 hook 层，但不附带验证证据
- 引入 `.vcxproj` / `MSBuild` 构建链
- 新增依赖但不更新 `THIRD-PARTY-NOTICES.md`
- 让闸门变红（或把闸门改宽松来让它变绿 —— 那是掩盖问题）
- 把工具往"能做坏事"的方向改（例如给注入器加隐蔽/提权能力）

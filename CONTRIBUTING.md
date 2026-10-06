# 贡献指南（CONTRIBUTING）

先把 [`SECURITY.md`](SECURITY.md) 读完 —— 尤其是"这不是一个安全边界"那一节。
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
2. **仓库路径可能含非 ASCII 字符**（开发机就是 `D:\用户态杀软`）。
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
```

> ⚠️ **第 4 层自测会启动真实引擎、并 hook 整个系统。** 它必须显式传
> `--run-engine` 才跑；不传时报 `[SKIP]` 并计入结论行（不静默跳过）。
> 请在**虚拟机或一次性环境**里跑，不要在你的主力机上跑。

---

## 3. 提交前必须全绿：闸门

仓库里的这些脚本是**闸门**，不是"建议"。它们每一个都对应一次真实事故：

| 闸门 | 防的是什么 |
|---|---|
| `tools/check_source_gbk.py` | 源码编码混用；GBK 编不出 `⇒` 这类字符 |
| `tools/check_bat_dir_wildcard.py` | `.bat` 里的目录通配符行为与预期不符 |
| `tools/check_bat_forf_redirect.py` | `for /f` 重定向写法静默失效 |
| `tools/check_env_switch_names.py` | 环境变量名差一个字母（改了 A 处、忘了 B 处） |
| `tools/check_spaced_name_quoted.py` | 主程序名 `R3 ShieldCore.exe` **带空格**，引用漏引号 ⇒ shell 拆参、静默失效 |
| `tools/check_payload_manifest.py` | 区分"本包没编驱动"与"驱动条目名字对不上" |
| `check_dist_sync.sh` | 发布目录两套 DLL 代次不一致（**出过真实事故**：32 位进程一条事件都没有，而所有"文件存在"闸门全绿） |

```bash
# 逐个跑
python tools/check_spaced_name_quoted.py
bash check_dist_sync.sh
# 有的支持一键修
python tools/check_spaced_name_quoted.py --fix
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

看 `git log` 就明白风格了 —— 中文，`主题：结论`，破折号用 `——`：

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
2. PR 描述里说明：**改了什么**、**为什么**、**怎么验证的**
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

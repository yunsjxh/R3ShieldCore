# 变更记录（CHANGELOG）

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

> 代码里另外有两套**内部代次号**（跨进程 ABI `v18`、规则层 `v19`、
> 构建代次 `v66` 等），它们用于**跨进程/跨构建的一致性校验**，
> 与本文的版本号是两回事 —— 内部代次变了不等于对外发版。

---

## [未发布]

### 新增 — 主程序 GUI 第 6 个页签「高级」：规则引擎 + 生产同源 codec 并排看字节（v77）

- 主程序新增第 6 个页签**「高级」**（`概览 / 事件日志 / 进程 / 配置 / ARK / 高级`）。
  它是控制台「高级模式」那套**规则引擎**在 GUI 里的**只读预览**：左边列**本页规则表**里的
  中文规则（**打开时预置 3 条示例**，不是引擎的实时规则），右边用**改前 / 改后**两行字节
  **并排**显示三个面（注册表值 / 剪贴板文本 / 注册表枚举）的替换效果 —— 数据是**本页自带的
  演示数据**。判据与落地**全部与生产同源** —— 直接 `#include` 共享 codec（铁律 195）：
  `rules_codec.h`（规则求值 + `DescribeAt`）、`spoof_apply_codec.h`（判定→落地）、
  `registry_spoof_codec.h`、`clipboard_spoof_codec.h`。**这一页只读**：不改
  `r3shieldcore.ini`、不改引擎行为；页上的「重置为示例规则 / 清空规则」只动**本页的规则表**。
- 预置的 3 条示例规则：注册表值名匹配 `/Pass.*/` → 替换为 `****`、
  剪贴板格式 = 文本 → 替换为 `[已替换]`、注册表枚举子键名含 `Secret` → 隐藏。
  左侧同时把**语法速查**印出来（面 / 字段 / 算子 / 动作）。
- 启动页签可由环境变量 `R3SHIELDCORE_START_TAB=advanced` 直达（与 `overview|log|process|config|ark` 同一机制）。

### 新增 — `--gui-preview` 界面预览模式 + 可复现的界面核对链（v77）

- 主程序新增 `--gui-preview`：**建窗 + 一直跑着，不初始化注入引擎**
  （在 `app.cpp` 里和 `--topmost-selftest` 一样，分流在**引擎初始化之前**）。
  用途 = 在开发机上**安全地**看 / 截图核对界面 —— 不碰铁律 175（本机禁跑引擎）。
- 新增 `tools/gui_preview_probe.cpp` + `build_gui_preview_probe.sh`：拉起**免提权**
  的预览 exe（同完整性级别，否则 UIPI 静默丢输入），从**屏幕 DC** `BitBlt` 截图
  （不是 `PrintWindow` —— 那拿到的是 DWM 静态缓存帧、常全黑），取像素指纹，
  并断言**应用自己日志**里的 `[adv] 页面已绘制 规则=3`（铁律 24/28：靠人眼 = 假绿）。
- 新增 `tools/bmp_to_png.py`（零依赖，只用 `zlib`+`struct`）与
  `tools/test_gui_preview.sh`（一键：出免提权 exe → 编探针 → 逐页签截图断言 → 转 PNG）。
  实测 `bash tools/test_gui_preview.sh advanced ark`：**advanced 6/0 + ark 负对照 4/0 = PASS**
  （ark 页签必须**没有** `[adv] 页面已绘制` 那行）。产图 `docs/shots/gui-preview-*.png`。

### 变更 — 抽「判定→落地」共享头；控制台改用（无回归）（v77）

- 新增共享头 `shared/r3shieldcore/spoof_apply_codec.h`：「判定 → 字节怎么落地」这一层，
  与两个面的 codec 分工明确（**不 include 它们**，保持 `shared/` 分层）。
  含 `ApplyRegValue(...)`（拒绝/放行**先判**、越界一律不写）、`BuildClipText(...)`、
  `Effect` 枚举 + `EffectName`。
- `tools/spoof_console.cpp` 里手写的 `ReplaceText`/`fill` 落地逻辑与剪贴板 `HGLOBAL` 手拼
  改为调共享头；剪贴板的格式显示名改由 `clipboard_spoof_codec.h` 的 `FormatLabel()` 统一给出
  （**唯一真源**，各处不再各 switch 一遍 —— 铁律 127）。
  自测 `bash build_spoof_console.sh --selftest` **10 通过 / 0 失败**（抽取无回归）。
- `shared/r3shieldcore/rules_codec.h` 的 `SaveFile`/`LoadFile` 各加
  `#pragma warning(suppress: 4996)`：控制台构建带 `_CRT_SECURE_NO_WARNINGS`、主程序没有，
  共享头必须**就地**关掉，不能要求调用方改编译参数。

### 修复 — 高级页「改前」是释放后的野指针；第 6 个页签被按钮压住（v77）

- **野指针（use-after-free）**：剪贴板「改前」那格显示成 `70 2D 61 E5 5B 02 00 00 …`
  （两个堆指针），而不是真实 UTF-16 —— 因为 `AdvHex(realBytes, …)` 是在
  `GlobalFree(real)` **之后**才求值的。**程序不崩、自绘界面也不报错**，
  只有截图能看出来（铁律 24/28 又一例）。修法：提前算好 `beforeHex` 再释放。
- **页签被压住**：`TabWidth` 还是 5 页签时的 `84` ⇒ 页签条右缘 480，而「退出引擎」
  左缘 492（默认宽 1024）—— 截图上第 6 个页签被按钮盖住、点不到。
  改为 `TabWidth = 70`（6 页签 × 70 = 420，右缘留出 12px），并同步两个镜像探针
  （`gui_exit_button_probe.cpp` / `gui_copy_all_logs_probe.cpp` 的 `TabWidth`/`TabCount`）。

### 新增 — v77 发布代次标记 + dist 刷新（`check_dist_sync.sh`）

- v77 改的是**主程序 exe**（多了第 6 个页签 + 一个启动分流）⇒ 按项目惯例补一条代次标记：
  `check_dist_sync.sh` 新增 **v77 节**，断言 dist 的 `R3 Shield Core.exe` 含**宽**串
  `R3SHIELDCORE_START_TAB`（启动页签分流已编入）与**窄**串 `advanced`（第 6 页签键名），
  并先做**前提检查**（源码 `r3shieldcore_gui.cpp` 里这两个串还在，铁律 117）。
- ★ 与 v76 的区别：v76（规则引擎）只改 `tools/spoof_console.cpp` —— **开发工具，不进 dist**
  ⇒ v76 **刻意没有**标记（判据 = "改了源码" ≠ "要进发布物"）。
- 验证：`check_dist_sync.sh` **PASS**（带 `v66…v75/**v77**` 标记）；负对照（换一个不存在的
  标记串）**不命中** ⇒ 判据有判别力（铁律 128）。
- 顺带把 dist 刷新到与 `Release/` 同步（`bash deploy_dist.sh`）：随包 ini 闸门
  `verify_dist_ini` **58 passed / 0 failed → PASS**，`check_dist_sync` **PASS**。

### 新增 — 控制台「规则引擎」：中文规则 + 正则，编辑 API 返回值（v76）

- 进高级模式后，可以**用中文写规则**来编辑 API 的返回值。语法刻意做得像易语言：

  ```
  当 <面> [的 <字段>] <算子> <模式> 时 <动作>
  ```

  面 = `注册表值` / `注册表枚举` / `剪贴板`；字段 = `值名` / `键路径` / `子键名` / `格式`；
  算子 = `等于` / `含` / `匹配` / `开头` / `结尾`（**`匹配` 用 `/正则/`**）；
  动作 = `替换为 "文本"` / `替换为 全零|全FF|空` / `隐藏` / `拒绝` / `放行`。
- ★ 求值 = **first-match wins**（按加入顺序，第一条命中的生效）；一条都没命中
  ⇒ **回落内置默认行为**（fill / hide / fakeclip）⇒ 「加规则」是**叠加**，
  不会把之前调好的默认行为弄丢。
- ★ 加规则两种写法等价：**直接敲以「当」开头的一行**，或 `rule add <规则>`。
  另有 `rule list | del <序号> | clear | load <文件> | save <文件> | test <面> <值> | help`。
  `save` 写 UTF-8（带 BOM），存出来能直接 `load` 回去（闭环已验证）。
- ★ 语法错误**当场报错、不进规则表**（不是静默收下）。
- 接入点三处（规则只决定"该不该换 / 换成什么"，**怎么换**仍走生产 codec，铁律 195）：
  `NtQueryValueKey_Detour`（按值名 / 键路径 → 写文本 / 填字节 / 拒绝 / 放行）、
  `NtEnumerateKey_Detour`（隐藏判据改由规则决定）、
  `GetClipboardData_Detour`（按格式名 → 换文本 / 拒绝 / 放行）。
  命中时 attack 输出里会打 `[规则] 命中 #n：…`。
- 自测 `bash build_spoof_console.sh --selftest` 扩到 **10 通过 / 0 失败**：
  正路加了 4 条内容判据（规则命中 + 数据区真被写成 `RULE-FAKE` 的 UTF-16 +
  剪贴板拿到 `CLIP-FAKE` + 枚举规则生效），并新增 **3/3 负对照** ——
  4 条错规则（正则没加斜杠 / 隐藏用在值面 / 剪贴板面字节填充 / `替换为` 后面没内容）
  **必须全被挡下、一条都不进表、且不崩**。
- 真实输出见 `docs/替换API结果-规则引擎-2026-10-11.txt`（含 first-match 实证：
  `放行` 规则放前面 → 拿到真值 `hunter2`；删掉它 → 正则规则顶上 → 又变 `***`）。

### 新增 — 「替换 API 结果」交互式控制台（高级模式，v75）

- 新增 `tools/spoof_console.cpp` + `build_spoof_console.sh`：**自包含、不注入、
  不跑引擎**（铁律 175 不适用）的交互式控制台，功能就是**替换 API 结果（Spoof）**。
- **进「高级模式」要先答对三道 Win32 编程题**（全对才开门；答错只说"哪几题错"、
  不给答案，可以重做）。三题都是本项目**真踩过**的坑：
  1. `Nt*` 把预定义伪句柄（`HKEY_CURRENT_USER` 等）当 `RootDirectory` 传进去返回什么
     —— `STATUS_INVALID_HANDLE`（铁律 219）；
  2. `vtable` 模块级按类共享时，inline patch 的"要不要替换"按什么记、原件按什么存
     —— 标记按**实例**记、原件按 **vtable** 存（铁律 210）；
  3. 32 位进程 `RegOpenKeyExW(HKLM\SOFTWARE)` 不带 `KEY_WOW64_*` 读的是哪一份
     —— 默认读 `WOW6432Node`。
- 开门后**默认状态 = 保护开 + 三个替换全开 + `mode=block`** ⇒ 一进来 `attack all`
  就是"替换生效"的样子；`compare all` 把同一个面的**三种状态并排**打出来
  （保护关→真值 / 只拦不换→真值或拒绝 / 拦+换→假数据）；`guard off` 看真值。
  另有 `fill <字节>` / `fakeclip <文本>` 改替换内容，`demo` 跑完整三幕（含 KTM 绕过）。
- 替换判据**与生产同源** —— 直接 `#include` 三个 codec 头（铁律 195）。
  覆盖 9 个 hook：`NtOpenKey` / `NtOpenKeyTransacted` / `NtOpenKeyTransactedEx` /
  `NtCreateKeyTransacted` / `NtQueryValueKey` / `NtEnumerateKey` / `NtSetValueKey` /
  `GetClipboardData` / `CloseClipboard`。
- **自带正路 + 负对照自测**（铁律 128）：`bash build_spoof_console.sh --selftest`
  —— 正路（答案 C/B/A + 一串命令）期望退出码 0；负对照（故意答错一题）期望
  **不开门**、退出码非 0、输出里没有「已进入高级模式」。实测 **3 通过 / 0 失败**。
- 全程真实输出见 `docs/替换API结果-高级模式控制台-2026-10-11.txt`。

### 修复 — GBK 闸门补 `--wide` 模式：宽字面量的「运行时丢字」（v75）

- **现象**：控制台的一句提示 `Say(L"...（RejectOrSpoof）⇒ 不拒就不换。")`
  实际输出成了 `...（RejectOrSpoof）? 不拒就不换。` —— 箭头变 `?`。
- **根因**：宽字面量**不会** C4566（编译器不管它），但控制台所有用户可见文本
  都经 `WideCharToMultiByte(CP_ACP)` + `fputs` 输出 ⇒ CP936 **编不出**的字符
  在转换时被**静默换成 `?`**。**和 C4566 是一模一样的病症（静默少字），
  只是发生时机从编译期挪到了运行期。** 原有闸门只查**窄**字面量 ⇒ 整类漏掉。
- **修法**：`tools/check_source_gbk.py` 新增 `--wide` 模式 —— 同一个词法器、
  同一个判据（能不能 CP936 编码），只是选中的字面量类别相反。
  ★ 字面量其实是**三类**：`narrow`（空 / `R`）、`wide`（`L` / `LR`）、
  `other`（`u` / `U` / `u8` —— UTF-16/32/8 执行字符集，两类问题都不沾）。
  `--wide` 只查 `wide`，**不**把 `u8` 误当成宽字面量（否则是假 FAIL，铁律 127）。
- **负对照同步扩展**：`tools/selftest_gbk_gate.py` 加第 ⑥ 节，用**同一个夹具**
  断言方向相反 —— `--wide` 下 `W1`/`W2`（宽字面量）**必须**命中、
  `N1`/`N2`（窄字面量）与 `U1`/`E1` **必须**一处不报。实测 **39 通过 / 0 失败**。
- **接进构建**：`build_spoof_console.sh` 编译前跑**两道**闸门（①窄 / ②宽）。
  负对照实测：临时往宽字面量里塞一个 `⇒`，闸门②准确报
  `行 947 列 38 '⇒' U+21D2 [string 前缀=L]` 并 `exit 1`。

### 新增 — 「看得见的效果」演示 + 主程序开拦截速查（v75）

- 新增 `tools/ktm_effect_demo.cpp` + `build_ktm_effect_demo.sh`：
  **自包含、不注入、不跑引擎**（铁律 175 不适用）的效果演示。
  它把保护逻辑（**与生产同源**，直接 `#include` 两个 codec 头，铁律 195）
  装进自己进程，然后**自己扮演攻击者**去攻受保护键，把每一步的真实返回值
  与真实数据打印出来。三幕：保护关 / 保护开 / 事务（KTM）绕过
  （v75 前敞开 vs v75 后同一套判据挡住 + 负对照放行）。
  实测输出见 `docs/注册表保护-效果演示-2026-10-11.txt`。
- 新增 `docs/主程序-怎么开拦截-速查.md`：回答「拿到发布包之后怎么让它真的拦东西」
  —— 改哪份 ini（ProgramData 优先）/ 最小配置 / 怎么启动 / 怎么确认真在拦 / 怎么停，
  以及两条**不跑引擎**也能看效果的路径。

### 修复 — 随包 ini 的 `mode` 漂移成 `ask`；并把「死闸门」接进流水线（v75）

- **现象**：`dist/R3ShieldCore-x64/r3shieldcore.ini` 的生效行是 **`mode=ask`**，
  而同一份发布包里的**三处**都写着 `block`：
  `配置详解.md`（由 `_gen_config_doc.py` 从 ini 生成）、`部署指南.md`、
  `模式选择说明.md`；`tools/verify_dist_ini.cpp` 的断言也是
  「mode 解析为 block（发布默认 = 拦截）」。
- **后果**：绿色包拷过去双击 `start.bat` 会进 **ask 模式**（命中就弹窗等你点），
  与文档承诺的「开箱即拦」**不是同一件事**；用户按文档排查会越查越偏。
- **根因（两层）**：
  1. **单行手工漂移** —— 对比 git：HEAD 里是
     `mode=block   # 主动防御：...（本包默认）`，工作区被改成裸 `mode=ask`；
     时间戳也印证：`配置详解.md` 00:30 由 ini 重新生成（那时还是 `block`），
     ini 00:44 才被改（**改完没有重新生成文档**，所以三处文档仍写 block）。
  2. **闸门是死的** —— `tools/verify_dist_ini.cpp` + `build_verify_dist.sh`
     **早就存在、能编能跑，但没有任何脚本调用它**。
     它链的是**引擎侧同一个解析器**（`r3shieldcore_config.cpp`），
     本该是这条漂移的兜底，却从来没被跑过。
     ⇒ **闸门不接进流水线 = 没有闸门。**
- **修法**：
  - 把生效行还原成 `mode=block   # 主动防御：只拦高置信度高危行为，其余放行（本包默认）`；
  - `deploy_dist.sh` 新增 **2c 步**：装配完 dist 后跑 `build_verify_dist.sh`，
    不过就 `exit 1`（新增 `--no-verify-ini` 逃生门）；
  - `build_dist_zip.sh` 在 `check_dist_sync.sh` 之后**再补一道**同样的闸门
    —— 因为出包脚本是**直接调 `check_dist_sync.sh`** 的，不走 `deploy_dist.sh`。
- **验证**：`verify_dist_ini` 由 `57 passed / 1 failed -> FAIL` 变成
  **`58 passed / 0 failed -> PASS`**；负对照（把 ini 改回 `ask`）仍然
  `57/1 -> FAIL`，证明这道闸门**有判别力**，不是恒绿。

### 新增 — 注册表**事务（KTM）准入面**接生产（v75）

- **改了什么**：`registry_guard.cpp` 补挂三个**事务注册表**导出
  —— `NtCreateKeyTransacted` / `NtOpenKeyTransacted` / `NtOpenKeyTransactedEx`。
  判据与 `Op::CreateKey` / `Op::OpenKey` **完全同源**（三个 detour 与
  `NtCreateKey_Hook` / `NtOpenKey_Hook` / `NtOpenKeyEx_Hook` **逐行同构**，
  只多一个 `TransactionHandle`）。
- ★★ **定性：这不是"新面"，是"准入这一道门没管"。**
  `NtXxxTransacted` 与非事务版**签名只差一个 `TransactionHandle`**；
  值读 / 枚举 / 写三类操作在事务句柄上**复用同一个**
  `NtQueryValueKey` / `NtEnumerateKey` / `NtSetValueKey`（只看句柄、不区分事务）
  ⇒ **v71 的值替换、v72 的枚举隐藏本来就在事务句柄上生效**。
  缺的只有"打开 / 创建"这一步的准入：原来 `NtOpenKey` 的 detour **不经过**事务变体
  ⇒ 用 `NtOpenKeyTransacted` 打开受保护键能绕过"写不进 / 读不到 / 看不见"的**第一道门**。
- ★★ **故意不给独立开关**：事务打开与普通打开是**同一个决策**，
  给它一个开关等于**人为开一个洞**（关掉就能绕过 v71 / v72）⇒ 跟随主判据、无条件挂。
- ★ 三个导出**一律 `required=false`**：老系统上可能没有，缺了只少一层覆盖，
  **不能**让整个模块失败（与 `NtOpenKeyEx` / `NtSetInformationKey` 同一个处理）。
- ★ **`AbiVersion` 不变（26）**：没加新位、没改布局、没加 ini 键。
- ★ 新增一条**宽串**挂载日志（ASCII 子串 `spoof_reg_ktm`）—— 因为 v75
  **没有新 ini 键、没有新 ABI 位**，光看 v70~v73 的标记区分不出"补没补"。
- 新增探针 `tools/spoof_reg_ktm_probe.cpp` + `build_spoof_reg_ktm_probe.sh`：
  自包含、不注入、不跑引擎，**42 通过 / 0 失败 / 0 跳过**。它把上面两句定性
  从推理变成实测：缺口成立（关掉事务 detour 时 `NtOpenKeyTransacted(KEY_SET_VALUE)`
  **能拿到受保护键句柄**，且非事务 detour **没有被顺带触发**）；
  修复生效（三个导出被拒 + 负对照仍放行）；
  事务句柄上三个 API **全部走同一个 detour**（v71 / v72 都生效）；
  `NtQueryKey` **能吃事务键句柄** ⇒ 生产 v72 不会静默降级。
  实测输出见 `docs/注册表KTM事务-机制探针-2026-10-11.txt`。

### 新增 — 四条盲区探针结论：hive 直读 / DirectShow / VFW / WinRT（v75）

> 本轮只出**探针结论**（go / no-go + 挂点），**一条都没接生产**。

- **hive 文件直读 → ✗ 淘汰**。提权（管理员 + `SeBackupPrivilege`）后活 hive
  仍一律 `err=32` / `0xC0000043 STATUS_SHARING_VIOLATION` ⇒ 系统**独占** ⇒
  打不开，映射 / `RegSaveKey` 都无从谈起。与"文件内容"**同族**淘汰。
  探针 `tools/hive_read_probe.cpp`，输出见 `docs/hive直读-可行性探针-2026-10-11.txt`。
- **DirectShow 取帧 → ★ 可替换**。帧 = `IMediaSample`，像素在 `GetPointer()`
  （**vtable 槽 3**）的缓冲区里 ⇒ patch 槽 3 后调用方通过同一个 `GetPointer`
  看到中性化后的数据。★★ 与 MF 同一个坑：`IMediaSample` 的 vtable
  **按类共享**（实测两个实例 vtable 相同）⇒ 必须**按对象**记"要不要替换"。
- **VFW 帧路径 → ★ 原判要改**。盘点文档原写"**不可替换（没有我们能改的缓冲区）**"
  **不成立**：帧最终落在采集窗口的 DIB 里，调用方用 `GetDIBits` / `BitBlt` 读 ——
  这两条**正是屏幕面已挂的 API** ⇒ VFW 是"**借屏幕面间接可替换**"。
  ⚠️ 本机**未能实测**（`capDriverConnect` 会阻塞 ⇒ 25 秒有界等待后如实 `Skip`）。
- **WinRT `MediaCapture` → ★ 路由明确 + 挂点可挂**。三重实证：
  注册表 `Windows.Media.Capture.MediaCapture` 的 `DllPath = Windows.Media.dll`；
  `Windows.Media.dll` 含字符串 `MFCaptureEngine`；
  `MFCaptureEngine.dll` 导出 `MFCreateCaptureEngine` 且**实测可 `MH_CreateHook` 挂上**。
  ★ 该 DLL **运行时加载、不在静态导入表** ⇒ 需等加载或主动 `LoadLibrary`。
- 探针 `tools/camera_paths_probe.cpp` + `build_camera_paths_probe.sh`：
  默认 **10/0/2skip**、`--use-camera` **10/0/5skip**。
  ⚠️ **诚实标注**：DirectShow **真机建图**、WinRT **真机激活**、VFW **端到端**
  三件都**没做**（探针里一律 `Skip` 并计数）⇒ 结论是"**机制层 go**"，
  不是"真机替换成功"。
- ★★ **探针踩到一个新坑**：`NtOpenKey` / `NtOpenKeyTransacted` **不接受预定义伪句柄**
  （`HKEY_CURRENT_USER` / `HKEY_LOCAL_MACHINE` / `HKEY_USERS`）作为 `RootDirectory`
  ⇒ 一律 `0xC0000008 STATUS_INVALID_HANDLE`。`RegOpenKeyExW(HKEY_CURRENT_USER, ...)`
  能跑，是因为 **advapi32 自己把伪句柄换成了真句柄** —— 这掩盖了坑。
  Nt* 只能用：① `RootDirectory = 真键句柄` + 相对名；② `RootDirectory = NULL`
  + **绝对 NT 路径**。（生产 `registry_guard.cpp` 不构造 `ObjectAttributes` ⇒ 不受影响。）

### 新增 — 发布验收闸门新增 **v75 段**（`check_dist_sync.sh`）

- 5 条判据：源码前提（三个导出名 + 标记日志）/ 双架构 DLL 的**宽**串
  `spoof_reg_ktm` / 双架构 DLL 的三个导出名**窄**串 / 出厂性质。
- ★★ **出厂性质那条方向与 v70~v73 相反**：不是"ini 键存在且为**关**"，
  而是"ini 里**不得**出现 `spoof_reg_ktm` 键" —— 因为事务准入**故意不给开关**。
  红了是**提醒**（有人把它做成可关闭的了？还是命名撞车？），不是误报。
- ★ 三条**负对照**已验证判据会红：ini 加 `spoof_reg_ktm=1` / 源码里标记改名 /
  DLL 里宽串标记被字节级抹掉。
- 窄串判据一律 `grep -qwF`（词边界）—— `NtOpenKeyTransacted` 是
  `NtOpenKeyTransactedEx` 的**子串**。

### 重构 — **决策档位 `Action` 收敛为共享枚举**（v74）

- **改了什么**：`R3ShieldCore::Action { Pass, Record, Block, Spoof }` 定义
  收敛到 `shared/r3shieldcore/r3shieldcore_shared.h`（与 `Decision` 同处），
  17 个 guard 删掉各自的 `enum class Action`，改成
  `using Action = R3ShieldCore::Action;`。
- ★★ **为什么这不是"省几行"**：v67 之前每个 guard 各写一份 `Pass/Record/Block`
  （17 份重复，例 `file_guard.cpp:130-135`）。代价不是重复，而是
  **同一个概念在 17 处独立演化** —— 事实也正是如此：v67 只给 `screen_guard`
  加了 `Spoof`，其余 16 个没有；v70 / v71 / v73 又各自补一次。
  ⇒ 「哪个面支持替换」这件事**只能靠翻源码数**，没有任何一处能回答。
- ★ **故意不合并的两处**（它们是**另一个概念**，各有命名空间）：
  `R3ShieldCoreToast::Action`（UI 卡片的点击结论 Allow/Deny/…）、
  `ArkActions::Action`（ark 工具对被控进程的操作 Suspend/ForceKill/…）。
  它们与"这次调用放不放行"不是同一维度。
- ★ **`AbiVersion` 不变**：`Action` 是 **guard 内部**的决策档位，**不进共享内存**、
  **不跨 DLL 边界**（跨边界传的是 `Decision`）。所以布局没变 ⇒ 不升。
- ★ 新闸门 `tools/check_action_enum_converged.py`：钉住"guard 的 .cpp 里
  **不得**再出现 `enum class Action` 定义 / 用了裸 `Action::` 就必须有 `using` /
  共享头四个值齐全"。带 `--selftest` 负对照（13 条）。
  为什么需要：新加 guard 时最省事的做法就是把老 guard 的头部整段拷过来 ——
  那份头部里原本就有 `enum class Action`，拷完编译照过、测试照绿，
  **只有"概念又分叉了"没人知道**。

### 新增 — 端到端夹具升级为**三面**（屏幕 / 剪贴板 / 注册表）（v74）

- `tools/spoof_e2e_target.cpp` 从"只截屏"扩成"一次运行走**三条真的取数据路径**"：
  屏幕（BitBlt→GetDIBits + GetPixel 参照）/ 剪贴板（放已知文本→读回）/
  注册表（`RegQueryValueExW` 读一个预先存在的值）。
- ★★ **三格矩阵不是"三个开关的组合"，是三个语义位置**：
  A 本应拒绝+不替换（**负对照**）/ B 本应拒绝+替换 / C 不拒绝+替换。
- ★★ **C 格专门证一条面间差异**：屏幕与剪贴板的替换**只在"本应拒绝"时生效**
  （`log` 下恢复真实），而注册表的替换发生在**读路径**上、**与 mode 无关**
  （`log` 下**仍**被清零）。不做这一格，"注册表在 log 下也替换"会被当成 bug。
- ★ **注册表测试值由夹具在起引擎之前建**（`HKCU\Software\R3ShieldCoreE2E`）：
  `protect_reg=` 命中的路径被算作**高危写**，`mode=block` 下会被拒
  ⇒ 目标进程自己建不出来。那不是 bug，正是"保护 = 写不进"这条设计。
  `--clean` 会删掉它。
- ★ **前提检查**：三面各自的 DLL 标记（`test_inject_only` / `spoof_clipboard` /
  `spoof_reg`，双架构，`grep -qwF` 整词）**先证三面逻辑都编进去了**；
  基线跑一遍要求**三面都读到真数据**（否则"变假"无法归因，铁律 110）。
- ★ 新增 `tools/spoof_e2e_selftest.sh`：**不需要引擎**的**判据逻辑自测** ——
  用合成 `result-*.txt` / `console-*.log` 喂给 `--collect`，先证"符合预期时 0 红"，
  再对每个面做定向篡改证"恰好红在对应断言上"。**14/0 通过**。
  本机禁止跑引擎（铁律 175）⇒ 这是"判据到底会不会红"唯一可验证的途径。
  ⚠️ 它**不**证明"引擎真的会替换"；那一步仍需在允许跑引擎的机器上 `--run-engine`。

### 修复 — 三处**顺带发现**的问题（v74）

- **发布目录里的运行时残留日志**：`dist/R3ShieldCore-x64/` 里有
  `r3shieldcore-console.log`（8905 B）与 `r3shieldcore-events.log`（541 KB）——
  它们是**引擎跑起来之后写在 exe 同目录**的，会随 zip / 安装包发出去。
  后果两条：① **泄漏**开发机上的键路径 / 进程路径 / 事件；② **骗人** ——
  夹具的 `read_console` 在"引擎还没跑"时会退到读这个文件，
  用户看到的是**上一次**的日志却以为是本次的（铁律 97）。
  ⇒ `deploy_dist.sh` 新增 **2b 步**清掉它们；`check_dist_sync.sh` 新增
  **v74 闸门**验收"这两个已知名不存在"（光有清理动作没有验收 = 死闸门）。
- **`tools/spoof_reg_probe.cpp:327` 的 C4566**：窄字面量里有 `⇒`（U+21D2），
  CP936 编不出 ⇒ MSVC **静默丢掉那个字符**。闸门 `check_source_gbk.py --all`
  本来就在报它（红）。改成 ASCII `->`。**这是 v71 留下的**，非本轮引入。
- **`GetPixel` 采样没有预算**：实测本机 `GetPixel` 在屏幕 DC 上约 **17ms/次**，
  而目标程序原来两块采样合计 ~700 次 ⇒ **光这一项就 11.7 秒**
  （整个目标 15s 里占 11.7s）。`--prepare` / `--collect` 每次都要跑基线，
  自测要跑十几遍 ⇒ 6 分钟。⇒ 给采样加**调用预算**（64），步长按屏幕尺寸自适应
  ⇒ 目标 15s → **4.5s**，`--collect` 19s → **8.8s**。

### 新增 — **摄像头「帧替换」**（v73）：本应拒绝的摄像头取帧改为返回**中性帧**

v71 落地「值替换」、v72 落地「枚举隐藏」之后，v73 把「回传数据替换」接到
**第四个面：摄像头**。这一面与前三个面**根本不同** —— 前三个是**单次调用**
（一进一出、无状态），摄像头是**流式**（一帧一帧来）。

- 开关：ini `spoof_camera=`（默认**关**）。
- ★★ **为什么必须换机制**：真正出帧的是 `IMFSourceReader::ReadSample`，
  而它**不是导出函数**（`mfreadwrite.dll` 不导出它）⇒ `MH_CreateHook` 挂不上。
  只能 **patch 对象的 vtable 槽 9**。判据不是"按文档数的 9"——
  探针里有一条 **A4** 判据（`vt[9]` 必须落在 `mfreadwrite.dll` 的模块范围内），
  生产侧在 patch 前做**同一套检查**（不通过就**拒绝 patch**，铁律 117）。
- ★★ **vtable 是模块级共享的**（同一个 COM 类的所有实例指向同一份数组）
  ⇒ patch 一次，进程内**所有** reader 都走我们的 detour。
  ⇒ 所以"要不要替换"必须**按对象**记（`g_spoofReaders[]`），
  **不能**"patch 过就算数"—— 那会把别的 reader 也一起换了（铁律 210）。
  ★ 同时**按 vtable 存原件**：不同来源的 reader 可能是不同类 ⇒ 不同原函数。
- ★★ **中性值随子类型变**（这是本面与前三个面最大的分歧）：
  · RGB 家族（RGB32 / ARGB32 / RGB24）→ 全 0（**恰好就是黑**，与屏幕面口径一致）；
  · YUV 家族 → **有限范围（video range）的黑** = **Y16 / UV128**。
  ⚠️ **全 0 在 YUV 里不是黑**，是**饱和色**（不同色彩矩阵下偏绿/偏洋红）。
  ⇒ 对外口径一律说「**中性帧**」，**不说**「黑帧」（铁律 97：口径必须与实际一致；
    铁律 202 同族）。探针里有一条**反向对照**把这条钉死（D6：老规则"全 0"
    在 YUV 下**不等于**黑）。
- ★★ **不认识的子类型 ⇒ 回落「拒绝」**：压缩子类型（MJPG / H264 / HEVC …）
  的帧是**码流**不是像素，往里填 16/128 得到的是"一帧解不出来的垃圾"。
  ⇒ `PlanForFormat` 返回 false ⇒ 调用方**回落拒绝**（= 没有本开关时的行为），
  **绝不**"随便填点什么"（铁律 194 / 196）。
  支持面：RGB32 / ARGB32 / RGB24 / YUY2 / UYVY / NV12 / I420 / IYUV / YV12。
- ★★ **异步读取路径必须**单独覆盖，否则**静默泄露**：`MF_SOURCE_READER_ASYNC_CALLBACK`
  的帧不从 `ReadSample` 的 out 参数回来，而是稍后从
  `IMFSourceReaderCallback::OnReadSample`（槽 3）交付。
  ⚠️ 回调签名里**没有 reader** ⇒ 查不到媒体类型 ⇒
  `ReadSample` detour 每次把解析结果存进一个 **seqlock** 保护的全局计划，
  回调 detour 取用（跨线程读 POD，无锁且不撕裂）。
  ⚠️ 回调的 vtable 属于**调用方自己的类**（不在 mfreadwrite.dll 里），
  做不了模块范围检查 ⇒ 它是**唯一没有第二道保险**的一处，靠探针覆盖。
  顺序：**先替换、再转交**（反了调用方就先看到真帧了）。
- ★★ **只有一条路能替换**：`MFCreateSourceReaderFromMediaSource`。
  VFW（`capCreateCaptureWindowW/A`，帧走 `WM_CAP_*` 消息/回调）、
  设备源创建、以及**音频三路**（`waveInOpen` / MCI / `IAudioClient::Initialize`）
  一律 `canSpoof=false` ⇒ **回落 `Block`**（铁律 194：造不出合法替代物就拒绝）。
- ★★ **没有视频流 ⇒ 回落拒绝**（铁律 199）：MF 里**摄像头与麦克风共用同一套 API** ——
  `MFCreateSourceReaderFromMediaSource` 也是麦克风采集的标准入口。
  不查这一条，`spoof_camera=1` 会把**纯音频**读取器也放行（我们造不出"中性音频"）
  = "放宽一个开关顺带打开别的行为"。⇒ 建读取器时 `HasVideoStream()` 不过就拒绝。
- ★ **`block_all` 一律拒绝**（铁律 165）：全拦模式下不升级成替换。
  `mode=log` 本来就不拒 ⇒ 也不替换。只有 `mode=block` / `mode=ask`（用户点拒绝）时替换。
- ★ **`stride` 的负数语义**：`MF_MT_DEFAULT_STRIDE` 对**自下而上**的帧是**负数** ——
  那是**行序**的表示，**不是**"步长是负的"。取绝对值；且 **`absStride < 名义步长` 时
  回落名义值**（比名义值小 = 一行装不下 ⇒ 不猜，铁律 117）。
- ★ **"长度一个都不改"**（与 v70 / v71 同一条规则）：只写 `[0, len)`，
  `SetCurrentLength` / `maxLength` 一个都不动 ⇒ 长度与数据区天然自洽。
  判据 = **越界哨兵**（`len` 之后 32 字节必须一个都没改，且**先断言哨兵区填充前
  确实是哨兵值**，否则判据可能恒真）。
  ★ `PlanarYuv` 的 `yLen = stride × height` 用 **`ULONGLONG`** 算 ——
  32 位乘法在极端值下会回绕 ⇒ 色度被当亮度填。
- 中性帧决策表抽成 `R3ShieldCoreLib/camera_spoof_codec.h`（全 `inline`、不碰 COM、
  不链库），**生产与探针共用同一份**（铁律 195 / 127）。
  ★ 头里自带 9 个 `MFVideoFormat_*` GUID 的本地副本；**防漂**靠探针里的
  **static_assert** 与 SDK 逐一对齐（SDK 改了或我们抄错了，探针**编不过**）。
- `AbiVersion` **25 → 26**：`Policy::Flags2` 新增一个位 `FlagSpoofCamera`（0x800），
  **布局不变**。旧 DLL 不认识新位 ⇒ 会在 `MFCreateSourceReaderFromMediaSource`
  上**直接拒绝**，而新引擎横幅却印「摄像头帧替换: 开」（**横幅撒谎**，铁律 93）。
- ★ **链接**：新增 `mfuuid.lib`。它是**纯 GUID 数据**的静态库（与 `uuid.lib` 同类）
  —— **不引入任何 DLL 导入**，所以不会给"被注入到每个进程"的 DLL 添加载期依赖。
  ⚠️ **不能**加 `mfplat.lib`（那是**导入库**）：`MFGetAttributeSize` 实测是
  `mfapi.h` 里的 **inline**（`dumpbin -SYMBOLS` 看到它在 obj 里是**已定义**符号），
  所以压根不需要它。
- ★ 顺带修掉 `r3shieldcore_shared.h` 里一句**过时注释**（"只有 ScreenGuard 会产生
  `Decision::Spoofed`"）—— v73 起四个面都会产生（铁律 149：改了产品就全仓 grep 旧字面量）。
- 验证：
  · 机制探针 `spoof_camera_probe` —— 默认 **35 通过 / 0 失败 / 1 跳过**；
    `--use-camera` 真机 **43 通过 / 0 失败 / 0 跳过**（Part D 25 条：9 条 SDK GUID
    交叉校验 + 布局判据 + 反向对照 + 越界哨兵 + stride 规则；Part E 的 E6 改成
    "把计划写进副本再与**调用方拿到的字节** memcmp" —— 证的是**调用方视角**）。
  · 纯逻辑单测 `v73_guard_ut` —— **84 通过 / 0 失败**（x64 + x86，不链 MF 库）。
  · `config_ut` —— **180 通过 / 0 失败**（x64；x86 同），其中 v73 新增 **17** 条断言
    （含 `hook_camera=1` **不能**顺带点亮替换的负对照、以及"五个位两两不同"补齐到 **10 对**）。
    ⚠️ 口径说明：这里的数字 = `Check()` 的**运行次数**（= 输出里 `PASS` 行的条数，
    循环内的断言会各算一次）；`config_ut` **不打印汇总行**，只看 `FAIL` 行数 + 退出码。
  · guard 层单测清单从 4 个增到 **5 个**，双架构全部跑完（覆盖恒等式自检通过）。
  · `build.sh` 双架构零警告；`deploy_dist.sh` + `check_dist_sync.sh` PASS
    （新增 v73 代次段：EXE 窄串 + 双架构 DLL 宽串 + 3 条前提 + 出厂默认关负对照）；
    6 个源码闸门全绿。
- ⚠️ **诚实标注的边界**：
  · 只覆盖 Media Foundation 的**同步 + 异步回调**两条取帧路；
    DirectShow / VFW / WinRT `MediaCapture` / 内核态驱动路径**未覆盖**；
  · 帧**尺寸/步长**取自 `MF_MT_FRAME_SIZE` + `MF_MT_DEFAULT_STRIDE`，
    若驱动用了非标准步长，可能出现"右侧/底部若干字节没被中性化"的**残留**
    （**不是泄露整帧**，但也不是像素级干净）；
  · 定位是**提高成本**，不是硬边界 —— 知道换路径的对手仍能绕过。
- 端到端（真引擎注入）**未做** —— 现有夹具只覆盖屏幕面。
- ★ 新增铁律 **210~216**（vtable 按对象记标记 / 回调路径必须覆盖 /
  MF 头 include 顺序 / `stride` 负数是行序 / 成员函数指针不能转整数 /
  MSYS 会吞 `/FLAG` / `mfuuid.lib` 可加而 `mfplat.lib` 不可加）。

### 新增 — **注册表枚举「隐藏」**（v72）：受保护位置的枚举看不到那些项

v71 落地「值替换」（读**不到**内容），v72 落地 **Phase 3 的第二个子项：注册表「枚举隐藏」**。
配合既有的「写不进」（`protect_reg=` 拒写）与 v71 的「读不到」，
合起来即 **「保护 = 写不进 + 读不到 + 看不见」**。

- 开关：ini `spoof_reg_enum=`（默认**关**）。
- ★★ **实现方式 = 索引重映射，不是伪造项**：调用方要第 N 个**可见**项，
  我们从 0 扫、跳过被隐藏项、数到第 N 个可见项时记下其**原始索引 M**，
  再用调用方给的 `class` / 缓冲区**真调一次原函数**取第 M 项。
  ⇒ 返回的每一项都是**真实、合法、结构完整**的项（铁律 194：能造出合法替代物才替换；
  这里的"替代物"就是列表里的下一项）。**不做**任何伪造名字 / 伪造类型 ——
  那才会造出调用方解析不了的项。
- ★★ **「命中就往后挪一格」是错的**：`[A(可见) B(隐藏) C(可见)]` 那种挪法会返回
  `[A, C, C]` —— **产生重复项**。索引重映射不会。探针里有专门一条判据钉住"无重复"，
  并用一个 `NaiveMap` 负对照证明"挪一格"确实会变红。
- ★ **必须用 `class 0` 探测名字**：`KeyValuePartialInformation`（class 2）**没有名字字段**，
  而它正是 `RegEnumValue` 内部用的那个 ⇒ 借调用方的 `class` 探测会让**最常见路径
  永远取不到名字且不报错**（静默失效）。所以探测一律用 class 0。
- ★ **空名三态**：值的「(默认)」项 `NameLength == 0` ⇒ 必须按 **Unnamed（可见）继续扫**，
  不能当成"判不出 ⇒ 放弃隐藏"（否则任何有默认值的键都让整条路**静默失效**）。
  三态 = `Parsed`（拿到名字）/ `Unnamed`（空名，按可见继续）/ `Indeterminate`（真判不出，放弃隐藏）。
- ★ **性能**：新增 `R3ShieldCoreRules::CouldHaveProtectedChildRegistry()` 做**保守上界**——
  与所有 `protect_reg=` 前缀都不相关的键**一次都不扫**（避免给正常枚举加 O(n) 开销）。
  内部用带**路径边界**的前缀判定（挡 `SOFT` 误命中 `SOFTWARE`）。
- ★ **三个前置条件（缺一不可，横幅会吵）**：① 配了 `protect_reg=`（否则空转）；
  ② 挂上 `NtEnumerateKey` / `NtEnumerateValueKey`（挂载条件放宽成
  `hook_reads || spoof_reg || spoof_reg_enum`）；③ 被枚举的键与某个前缀**相关**。
- ★ **与 `spoof_reg` 是两个独立的位**（铁律 199 同族）：值替换只改内容（列表长度不变），
  枚举隐藏改的是**列表长度与顺序**，风险画像不同 ⇒ 必须能单独关掉。
  闸门里两条标记一律用 `grep -w`（词边界）—— 否则 v72 的 `spoof_reg_enum`
  **包含** v71 的 `spoof_reg`，会让 v71 的判据在"v71 被删、v72 还在"时**假绿**。
- 重映射逻辑抽成 `R3ShieldCoreLib/registry_enum_codec.h`（全 `inline`，**连控制流一起抽**），
  **生产与探针共用同一份**（铁律 195 / 127）。
- `AbiVersion` **24 → 25**：布局没变，但语义变了 —— 旧 DLL 不认识新位会把枚举**照原样返回完整列表**，
  而新引擎横幅却印「注册表枚举隐藏: 开」（**横幅撒谎**，铁律 93）。
- 验证：机制探针 **36 通过 / 0 失败**（x64，自包含、不经过引擎；含 7 条**布局判据** +
  "无重复" + "可见索引项与直接真调原始索引项**逐字节相同**" + 无关键负对照 +
  `RegEnumKeyExW`/`RegEnumValueW` 真实调用方视角）；纯逻辑单测 `v72_guard_ut`
  **54 通过 / 0 失败**（x64 + x86）；`config_ut` 双架构各 **454 通过 / 0 失败**
  （含 `spoof_reg_enum` 双向交叉检查与"四个位两两不同"）。
- ⚠️ **诚实标注的边界**：隐藏是**列表级**的，不是**访问级**的 ——
  被隐藏的键 / 值仍可被 `RegOpenKeyExW` / `NtQueryValueKey` 直接按名字访问
  （值还会被 v71 清零）；`NtQueryKey` 返回的 `SubKeys` / `Values` **计数不变**；
  事务注册表 / hive 文件直读 / WOW64 重定向路径**未覆盖**。
- 端到端（真引擎注入）**未做** —— 现有夹具只覆盖屏幕面。

### 新增 — **注册表值「替换」**（v71）：受保护位置的读返回全 0

v67 落地**屏幕**面、v70 落地**剪贴板**面，v71 落地 **Phase 3 的第一个子项：注册表「值替换」**。
配合既有的「写不进」（`protect_reg=` 拒写），合起来即 **「保护 = 写不进 + 读不到」**。

| 值类型 | 替换后 |
|---|---|
| `REG_SZ` / `REG_EXPAND_SZ` | **空串** |
| `REG_DWORD` / `REG_QWORD` | **0** |
| `REG_BINARY` | **全 0 字节** |
| `REG_MULTI_SZ` | **空列表** |

- 开关：ini `spoof_reg=`（默认**关**）。
- ★★ **长度字段一个都不改**，只把数据字节清零 —— `DataLength` / `DataOffset` /
  `*ResultLength` / `Type` / `NameLength` 全部保持原值。这是整个设计的命门：
  要"改长度"就得同步改**三处**，改错一处 ⇒ 调用方**读越界或按错偏移解析** ⇒ 宿主崩溃；
  "长度不动、只清零"⇒ 长度与数据区天然自洽，结构上不可能出现"声明长度 ≠ 实际长度"。
  （与 v70 剪贴板的"同格式、同尺寸、内容清零"是**同一条规则**。）
- ★ **触发面与截屏 / 剪贴板不同**：那两个只在"**本应拒绝**"时替换；注册表读**本来不拒**
  （`!blockable`），所以这里是"**命中 `protect_reg=` 就替换**"。
  ⇒ **必须配 `protect_reg=` 才有效**，名单为空时一个字节都不会动（横幅会明说）。
  ⚠️ **不能拿内置高危表当触发面**：那张表含 `...\CurrentVersion\Run`，
  任务管理器 / 启动项管理 / 安装程序**天天在读**它，替换会打坏正常软件。
- 挂载条件放宽成 `hook_reads || spoof_reg`（否则打开 `spoof_reg` 什么也不会发生），
  但**只额外挂 `NtQueryValueKey` 一个**，不偷偷打开 `NtEnumerateKey` /
  `NtEnumerateValueKey` 的读记录 —— 用户 `hook_reads=0` 的承诺不被破坏（新增 `HookReadsEnabled()`）。
- 清零逻辑抽成 `R3ShieldCoreLib/registry_spoof_codec.h`（全 `inline`），
  **生产与探针共用同一份**（铁律 195 / 127）。
- `AbiVersion` **23 → 24**：布局没变，但**语义变了** —— 旧 DLL 不认识新位会静默不替换，
  而新引擎横幅却印「注册表值替换: 开」（**横幅撒谎**，铁律 93）。
- ★★ **实测推翻了关于 `KeyValuePartialInformationAlign64` 的假设**（详见下条）。
- 验证：机制探针 **60 通过 / 0 失败**（x64 + x86，自包含、不经过引擎；含 7 条**布局判据**）；
  负对照（故意把 class 4 当 12 字节头）⇒ **58 通过 / 2 失败**（class 4 变红）；
  `config_ut` **149 通过 / 0 失败**（= v70 的 137 + 12 条新断言；含双向交叉检查）。
- 端到端（真引擎注入）**未做** —— 现有夹具只覆盖屏幕面。

### 记录 — **`KEY_VALUE_PARTIAL_INFORMATION_ALIGN64` 的头是 8 字节，且没有 `TitleIndex`**

`NtQueryValueKey` 的 `KeyValueInformationClass` 决定了 out 缓冲区的**变长结构布局**。
本轮**实测**（不是查文档）得到：

```
class=0 Basic         ResultLength=12+名字   TitleIndex(0) Type(4) NameLength(8) Name[12]  ← 无数据区
class=1 Full          ResultLength=52        TitleIndex(0) Type(4) DataOffset(8) DataLength(12) NameLength(16) Name(20)
class=2 Partial       ResultLength=32        TitleIndex(0) Type(4) DataLength(8) Data(12)
class=3 FullAlign64   ResultLength=52        **与 class 1 逐字节相同**（含 TitleIndex）
class=4 PartialAlign64 ResultLength=28       **Type(0) DataLength(4) Data(8)** ← 没有 TitleIndex！
```

（示例值 `REG_SZ "Secret123"`，数据 20 字节。`class 4` 的 28 = **8** + 20，
同值用 `class 2` 是 32 = 12 + 20 —— 差的 4 字节正是被 Align64 变体去掉的 `TitleIndex`。）

- 我最初按"class 4 同 class 2"实现 ⇒ 数据偏移算成 12、长度从 `+8` 读
  （读到的是**数据本身的前 4 字节**）⇒ 长度离谱。
- 幸好 `LocateDataRegion` 的"长度字段必须自洽"校验把它挡成"**定位失败 ⇒ 不替换**"。
  否则会**零掉错误的位置**（`Type` / `DataLength` 被清零 ⇒ 调用方解析出乱码）。
- ⇒ 已修 codec，并把**实测布局钉成探针判据**（7 条）：将来 Windows 改了布局，
  探针会**变红**，而不是"悄悄改坏"。

### 记录 — `build.sh x64` **不是**"只编 x64"，而是把 `x64` 当成**配置名**

`build.sh` 的签名是 `build.sh [配置] [架构]`（`CONFIG="${1:-Release}"`、
`ONLY_ARCH="${2:-}"`）。所以：

```
bash build.sh x64          # ← 错！CONFIG="x64" ⇒ 产物落进 R3ShieldCore/x64/
bash build.sh Release x64  # ← 对
bash build.sh              # ← 对（Release，x86 + x64）
```

★ 危险点：`x64/` `x86/` 都在 `.gitignore` 里，**产物看起来"正常生成了"、
构建也打印 BUILD OK** —— 而 `Release/` **静默保持着上一次的旧构建**。
下游 `deploy_dist.sh` 从 `Release/` 取货 ⇒ 会**把旧引擎打进安装包**，
且一路绿灯（铁律 142：只查"构建成功"证明不了"装进去的是新的"）。

### 新增 — **剪贴板「替换」**（v70）：本应拒绝读取剪贴板时返回中性内容

v67 落地了**屏幕**面的回传数据替换（黑帧），v70 落地 **Phase 1 的第 2 个面：剪贴板**。

| 格式 | 替换后 |
|---|---|
| `CF_UNICODETEXT`(13) / `CF_TEXT`(1) / `CF_OEMTEXT`(7) | **空串** |
| `CF_DIB`(8) / `CF_DIBV5`(17) | **同尺寸**，头 + 调色板逐字节保留，像素字节**清零** |
| `CF_BITMAP`(2) | **同尺寸的 1bpp 全零 DDB**（⚠️ 这是 `HBITMAP`，不是 `HGLOBAL`） |
| 其余格式（注册格式、`CF_HDROP` …） | **回落到 `Block`**（= v70 之前的行为） |

- 开关：ini `spoof_clipboard=`（默认**关**），只在 `mode=block` / `ask` 的**拒绝路径**上生效；
  `mode=log` 本来就不拒、`mode=block_all` 一律拒绝（铁律 165）。
- ★★ **这个面特有的坑：句柄所有权**。`GetClipboardData` 返回的句柄**归剪贴板所有**，
  调用方不得释放，有效期到 `CloseClipboard` 为止 ⇒ 替代物必须由我们在**那个时刻**回收：
  - 新挂 `user32!CloseClipboard`（**只为回收**，不改它的行为），且只在**原函数成功**时回收
    （失败时回收会误伤另一个线程正在进行的会话）；
  - 槽用**进程级固定数组**（16 个）而不是 `thread_local` —— 调用方未必是持有剪贴板的那个线程；
  - `CloseClipboard` 没挂上 ⇒ **本次不启用替换**（互锁）：宁可退回"拒绝"，
    也不能造出一批无人回收的块。
- ★ **造不出合法布局的格式必须回落 `Block`**：硬造一个长度不对的块会让调用方
  **读越界** —— 那是"替换"**新引入**的崩溃面。
- 伪造逻辑抽成 `R3ShieldCoreLib/clipboard_spoof_codec.h`（全 `inline`），
  **生产与探针共用同一份**（铁律 127：抄两份必漂）。
- `AbiVersion` **22 → 23**：布局没变，但**语义变了** —— 旧 DLL 不认识新位会静默退回
  "拒绝"，而新引擎横幅却印「剪贴板替换: 开」（**横幅撒谎**，铁律 93）。
- 验证：机制探针 **25 通过 / 0 失败**（x64 + x86，自包含、不经过引擎）；
  `config_ut` **137 通过 / 0 失败**（含 11 条新断言 + 双向交叉检查）；
  闸门 `check_dist_sync.sh` 新增 v70 段并带**负对照**（出厂默认改成开 ⇒ FAIL；
  键整行删掉 ⇒ 前提 FAIL 而不是静默通过）。
- 端到端（真引擎注入）**未做** —— 现有夹具只覆盖屏幕面。

### 探针 — **摄像头「帧替换」可行性**（v71 同期；**已在 v73 接入生产**）：机制可行，但**"清零"规则不成立**

> ⚠️ **本节是历史记录**：这里的"建议缓一步"已在 **v73** 执行完毕 ——
> `camera_spoof_codec.h` 已抽出、`camera_guard.cpp` 的帧路径已接上（见本文档最上面的 v73 段）。
> 本节保留当时的结论与实测数据，作为"为什么这么设计"的依据。

用户要求「继续注册表值 / 摄像头」。注册表值已落地（v71，见上）；
摄像头按 §8 排在"二期"，所以本轮**只做可行性探针，不改生产代码**。

- 探针：`tools/spoof_camera_probe.cpp` + `build_spoof_camera_probe.sh`（自包含、不注入、不经过引擎）。
- 机制链（真机实证）：
  `IMFSourceReader::ReadSample` **不是导出函数** ⇒ 走 **vtable patch（槽号 9）**；
  `IMFSample` → `IMFMediaBuffer::Lock` 拿到的是**同一块内存** ⇒ 原地改写，
  **调用方看得见**（不是我们的副本）。
- 验证：默认（不开硬件）**18 通过 / 0 失败 / 1 跳过**；
  本机有 2 个视频采集设备 ⇒ `--use-camera` 真机 **26 通过 / 0 失败 / 0 跳过**（640×480）。
  ★ 真机测试**默认不开**（会点亮摄像头指示灯）⇒ 做成 `--use-camera` 开关，
  默认 `[SKIP]` **并计入结论行**（铁律 178）。
- ★★ **最重要的差异 —— "全 0"在 YUV 里不是黑**：v67/v70/v71 共用的"同长度、内容清零"
  规则**不能套到视频帧上**。`Y=0,U=0,V=0` 是一个**饱和色**（有限范围下黑是 `Y=16 / UV=128`）。
  安全目标（不泄露真画面）仍达到，但**对外口径不能说"黑帧"**。
  决策表已进探针（RGB → 全 0；NV12/YUY2 → Y16/UV128；**不认识的子类型 ⇒ 不替换**）。
- ★ 实测：真实摄像头**默认不给 RGB32**（`SetCurrentMediaType` 返回
  `0xC00D36B4 = MF_E_INVALIDMEDIATYPE`，实际给 **YUY2**，640×480 ⇒ 614400 字节）；
  必须给 `MFCreateSourceReaderFromMediaSource` 传
  `MF_SOURCE_READER_ENABLE_ADVANCED_VIDEO_PROCESSING = TRUE` 才能拿到 RGB32
  （加上后 ⇒ 1228800 字节）。不设它，"设置没生效"会伪装成"已生效"。
- ⇒ **建议缓一步**：先抽 `camera_spoof_codec.h`（全 `inline`，生产与探针共用，铁律 195），
  再决定接不接进 `camera_guard.cpp`（那里此前只挂了**创建类** API，帧路径完全没碰）。

### 修复 — `config_ut` 撞上 MSVC **C1001**（闸门整条编不出来，铁律 173）

给 `tools/config_ut.cpp` 加第 26 处 `policy = {};` 时，MSVC 抛
**C1001「内部编译器错误」**，报错位置是"第 687 行"，看着像语法错，实际是编译器自己崩了
⇒ **整条 UT 编不出来**（表现出来只是"没输出"）。已把 25 处 `policy = {};`
全部换成 `ResetPolicy(policy)`（内部 `ZeroMemory`；`Policy` 是 POD，语义完全一样），
以后再加断言不会再撞。

### 记录 — `strings -a` 与 `strings -el` 是**两个互不相通的世界**

闸门的代次标记如果选错编码世界，会变成**恒 FAIL** 或**恒绿**。实测（同一份 DLL）：

```
64 位 DLL: strings -a 命中=0   strings -el 命中=1
只含宽串的合成文件: -a=0  -el=1
只含窄串的合成文件: -a=1  -el=0
```

⇒ 宽串标记**只能**用 `-el` 查；而且 GNU `strings -el` 只输出 **ASCII 可打印**字符
⇒ **纯中文标记永远查不到**。所以 v70 的 DLL 标记选了日志里的 ASCII 子串
`spoof_clipboard`（写在 `LOG(L"…（spoof_clipboard，格式 %u …")` 里）。

### ★ 端到端三格矩阵**首次真跑通过**：27 通过 / 0 失败 / 0 跳过

用真引擎、真目标进程、真配置跑完 A/B/C 三格：

| 格 | 配置 | 实测 | 含义 |
|---|---|---|---|
| 冒烟闸门 | — | 白名单被读到（`pd-A`）；**注入计数 N=1**（阈值 1..5） | 注入范围**真的**被限住 ⇒ 可以安全跑矩阵 |
| A | `block, spoof=0` | `bitblt=0 err=5` | BitBlt **被拒** —— 同时证明目标**确实被注入了** |
| B | `block, spoof=1` | `bitblt=1 err=0`，`first=0x00000000`，`nonblack=0/12288` | ★ **替换成立**：调用**成功返回**但拿到的是**全黑帧** |
| B | 同上 | `GetPixel` 仍读真实画面（块内 192 / 全屏 510 个非黑点） | 多路径戳穿实证（已知盲区） |
| C | `log, spoof=1` | `bitblt=1`，`nonblack=12288` | 真实画面 ⇒ 替换**只在"本应拒绝"时**生效 |

`--collect`（**非提权**）独立复现同一结论：19 通过 / 0 失败 / 0 跳过。

### 新增 — `tools/run_elevated.exe`（"最小 sudo"）：让自动化能提权跑夹具

自动化侧禁止用 `Start-Process` 起 shell / 解释器 / 系统工具（会被命令校验直接拦掉），
但**普通 exe 可以**。所以加了一个转发器：调用方用 runas 拉起它（**只弹一次 UAC**），
它再 `CreateProcess` 目标命令，子进程**继承提权令牌**。配套 `build_run_elevated.sh`。

- ★ 坑 1：`Start-Process -ArgumentList` 传**数组**会按空格 join 且**不加引号**
  ⇒ 路径里的空格直接把参数拆坏（实测 `CreateProcessW err=2`，看着像"文件不存在"）。
  必须传**一个**自己带引号的整串。
- ★ 坑 2：转发器**把最终拼出来的命令行打进日志** —— 否则传参错位时只有一个光秃秃的
  `err=2`，完全不知道该怪谁。
- ★ 坑 3：`cl` 必须给 `-source-charset:utf-8`（源码 UTF-8 无 BOM，默认按 936 读会把
  中文注释拆坏 ⇒ 报一堆 C2447/C3861，看着像代码写错了）。

### 修复 — 夹具**两个"根本跑不通"的 bug**（只有真跑引擎才暴露）

> 此前所有"夹具已就绪"的结论，都建立在这两个跑不通的读法之上。

**① 引擎日志是 GBK，脚本是 UTF-8 ⇒ 所有中文 grep 恒 0 命中。**
`build.sh` 给 `cl` 的是 `/source-charset:utf-8`，但**没给** `/execution-charset:utf-8`
⇒ 窄字面量按**系统 ANSI 代码页**（中文机 = CP936/GBK）落盘。
实测 `注入范围已被限定` / `配置文件` / `模式 ` / `注入新进程` **四个模式全部未命中**
⇒ 夹具每格都会 FAIL，而报出来的话是"引擎没进限定模式"，**与真实根因差了十万八千里**。
修法 = **单点转码**：`decode_engine_log()`（`iconv -f GBK -t UTF-8`），所有读日志的地方
统一走它，拷走的那份也顺手转好。判据用"转出来非空"而**不是** iconv 返回码
（有个别非法字节时 iconv 返非 0 但已转好绝大部分）。
★ 顺带发现：**MSYS2 的 bash 没有 iconv**，PortableGit / Git Bash 的**有**
⇒ 已加前提检查，缺了直接 FAIL 并说清去哪找。

**② 引擎运行期间它的控制台日志是"独占"的 ⇒ 不能边跑边轮询。**
`cat` 报 `Device or resource busy`；PowerShell 的 `FileShare.Read` 与 `FileShare.ReadWrite`
**都**报 SharingViolation；引擎一退出立刻可读。
⇒ `run_cell` 原本"边跑边轮询日志等横幅"**这条路根本不存在**。改成**定时等待**，
日志一律等引擎**退出后**再读；"白名单是否生效"由**冒烟闸门**用
"短跑 + 退出后读日志"单独证掉。

### 记录 — UAC 提权**不继承调用方的环境变量**（实测）

`ProgramData` / `R3SHIELDCORE_EXIT_AFTER_MS` / `PATH` **全部丢失**：

- 引擎自报的 `配置文件 :` 是 **exe 同目录的兜底 ini**，不是指定的 `pd-A`
  ⇒ 靠环境变量给提权进程传配置是**假生效**，而且**看起来是生效的**（进程起来了、界面也在）；
- `EXIT_AFTER_MS` 没生效 ⇒ 引擎**不会自己退**（本次跑了两分多钟，最后用 `dskill.exe` 终止）；
- 提权起来的 bash 里 `/usr/bin` **不在 PATH**（`dirname: command not found`）⇒ 必须 `bash --login`。

⇒ 判据必须让**被传方自己回读并打印**它实际用的配置路径（本夹具的 `配置文件 :` 断言
正是干这个的），而不是断言"我设了环境变量所以它一定读到了"。

### 修复 — 端到端夹具在管理员终端里**根本跑不起来**（`bash` 不在 cmd 的 PATH 上）

现象：在**管理员 cmd** 里敲文档里写的

```
bash tools/spoof_e2e.sh --run-engine
```

得到 `'bash' 不是内部或外部命令` —— 因为本机的 `bash` 来自 MSYS2 / PortableGit，
它们**默认不往系统 PATH 里写**。用户于是卡在"我该用哪个 bash"。

修法：脚本自己算出**一条可直接粘贴**的命令 —— 把**当前正在跑的** `$BASH` 与本脚本
都用 `cygpath -w` 转成**绝对 Windows 路径**并加引号（路径含空格）：

```
"D:\...\PortableGit\usr\bin\bash.exe" "D:\用户态杀软\tools\spoof_e2e.sh" --run-engine
```

- 新增 `bash_line()`（**单点维护**，避免各处各写一份）与 `admin_hint()`，
  接到**三处**提示：默认 SKIP 闸门 / `--prepare` 的"下一步" / 非管理员失败分支。
- 用 `$BASH` 而不是硬编码路径：那是**已知能跑**的那一个（脚本此刻就跑在它上面）。
- 若 `D:\msys64\usr\bin\bash.exe` 存在，额外给一条备选（构建链用的就是那套）。
- ★ **降级必须诚实**：算不出完整路径时打印占位符，**绝不**打印 `"bash" …`
  —— 那看着是条命令、粘进去还是同一个报错。

顺带补上 **`cygpath` 前提检查**（硬 FAIL）：它不只是为了打印提示 —— `--run-engine`
要靠它把工作区的 `ProgramData` 转成 Windows 形式；缺了它 `ProgramData` 会退化成
MSYS 路径（`/tmp/...`），**原生引擎根本不认**，于是回退去读用户**真实的**
`%ProgramData%\R3 Shield Core\` —— 也就是拿真配置去**全局注入**。

### 新增 — `--run-engine` 分两级跑：**冒烟闸门**先证"白名单真的限住了"

原来只有"跑起来看结果"一条路：白名单若没生效，引擎在 60s 里**全局注入**
（编辑器与宿主工具都可能被 hook 崩）。现在第二级要过第一级才启动：

| 级 | 内容 | 时长 | 判据 |
|---|---|---|---|
| 1 | 冒烟闸门 | ~9s | 引擎自报 `注入新进程: N 个` 的**合计**，**两侧都设界**：`1 ≤ N ≤ 5` |
| 2 | 三格矩阵 A/B/C | ~60s | 每格 BitBlt/GetDIBits/PrintWindow 的期望行为 |

- `N = 0` ⇒ 目标注不进去（矩阵会三格全"没被注入"）；`N ≥ 100` ⇒ 没限住、在全局注入
  （本项目实测全局时 N 是 100~200 ⇒ 阈值 5 与 100 之间有**两个数量级**的空档）。
- 级 1 不过 ⇒ 直接 `FAIL` 并**跳过矩阵**。
- ★ 判据必须**两侧都设界**：只查 `N ≥ 1` 会被"全局注入"骗过（那时 N 也是 100+）；
  只查 `N ≤ 5` 会被"一个都没注入"骗过（`N = 0` 也"小"）。

**★ 过程中差点写进一个"恒 FAIL"的判据**：第一版用
`grep 跳过非白名单进程` / `grep 命中白名单`（`functions.cpp:416/419` 的 `LOG(...)`）。
**这两条永远 0 命中** —— `LOG()` 走 `Logger::LogLine` ⇒ 只 `OutputDebugString`
（`logger.cpp:52`），**不落盘**。更隐蔽的是"看着有救"的那半句：`logger.cpp:56` 的
`EnableStderrOutput` 会写 `stderr`，`app.cpp:104` 又把 `stderr` 重定向到了
`r3shieldcore-console.log` —— 看着闭环了；**但 exe 与 DLL 各用静态 CRT（`-MT`）**，
是两个 `stderr` 对象，exe 的 `freopen` 改不到 DLL 的 ⇒ 还是落不了盘。
⇒ 改用 **`printf`**（`app.cpp:1001`）的计数行：走 stdout、`_IONBF` 无缓冲、**一定**在文件里。

**验证**：用合成日志覆盖三种情形 —— 白名单（N=1，横幅在）/ 全局（N=163，横幅不在）/
**横幅在但 N=163**（仍被第三断言拦住 ⇒ 判据有牙）。

### 修复 — 闸门 `check_spaced_name_quoted.py` 的**假 FAIL**（嵌套命令替换）

`tools/spoof_e2e.sh` 里这一行被闸门误报为"引号外的引用"：

```bash
ENGINE_BASE="$(basename "${ENGINE:-R3 ShieldCore.exe}")"
```

**这是完全正确的写法** —— POSIX shell 里，双引号内的 `$(` 会**开启一个新的解析
上下文**，里面再出现的 `"` 只关闭内层那个，**不会**提前结束外层双引号。

根因：检查器的引号状态机是"见到 `"` 就翻转"的**朴素**实现，遇到嵌套 `$()` 就错位。
⇒ 改为**压栈**：进 `$(` 时把当前引号状态压栈并清空，遇到配对的 `)`（且当时不在任何
引号里）再弹回。只对 `$(` 做这件事，**不**对裸 `(` 做（裸括号出现在普通文本里的概率
高得多，乱压栈会引入**漏报**，而漏报 = 静默失效）。

**验证**（12 条合成用例，含负对照）：

| 用例 | 期望 | 实得 |
|---|---|---|
| `ENGINE_BASE="$(basename "${ENGINE:-R3 ShieldCore.exe}")"` | 放过 | 放过 |
| `X="$(basename "${V:-R3 ShieldCore.exe}")"` | 放过 | 放过 |
| `taskkill //F //IM "R3 ShieldCore.exe"` / `'…'` | 放过 | 放过 |
| `taskkill //F //IM R3 ShieldCore.exe` | **报错** | 报错 |
| `for name in R3 ShieldCore.exe R3 ShieldCore-x86.exe; …` | **报错** | 报错 |
| `X=$(ls R3 ShieldCore.exe)` | **报错** | 报错 |
| `X="$(ls R3 ShieldCore.exe)"` | **报错** | 报错 |
| `a="x" b=R3 ShieldCore.exe` | **报错** | 报错 |
| `echo "$(echo R3 ShieldCore.exe)"` | **报错** | 报错 |

⇒ 修的是**假 FAIL**，真 bug 仍然全部报出（负对照 7 条全红）。全仓重跑：**PASS**
（108 个脚本）。

### 新增 — 限定注入范围：`test_inject_only=` + `mode=test`（v69）

给引擎加了一个**开发/验证用**的能力，让"全局注入会 hook 编辑器 ⇒ 本机不能跑引擎"
（铁律 175）这件事在**做端到端验证**时有个出路。

- **配置驱动**（ini，不再是命令行）：
  - `test_inject_only=<镜像基名 或 完整路径前缀>` —— 可重复写多行，也支持一行
    逗号分隔（`a.exe, b.exe`）；上限 16 条。含 `\` / `/` ⇒ **完整路径前缀 +
    路径边界**（复用 `InjectPolicy::MatchesNeverInjectPath`，连 `/`↔`\` 归一化一并继承）；
    否则 ⇒ **镜像基名**，不区分大小写。
  - `mode=test` —— 便捷写法，等价于 `mode=log` + **强制要求** `test_inject_only=` 非空。
- **★ 关键设计：「注入范围」与「拦截行为」解耦**。白名单只要**非空就生效**，
  **与 `mode=` 无关**。为什么必须这样：spoof（截屏替换）**只在"本应拒绝"时才生效**，
  而 `mode=test` 的决策行为 = `log`（全部放行）⇒ 若白名单只认 `mode=test`，那就
  **永远验证不到替换路径**（为验证而加的模式，恰好让被验证的功能不触发）。
  解耦后 `mode=block` + `test_inject_only=<目标>` 既能限定注入范围、又保留拦截行为，
  端到端三格矩阵都能在开发机上安全地跑。
- **★ 为什么 `mode=test` 不新增 `Mode` 枚举值**，而是复用 `Mode::Log` + 独立标志位
  `FlagTestMode`：`Mode` 在 22 个文件里有 ~130 处 `mode == Mode::Xxx` 分支，加一个新值
  会让**每一处**都落进"不是 log、不是 block、不是 ask"的 else 分支 —— 那是"往共享枚举
  里加值然后指望 130 处都想到它"，正是本项目踩过的那类静默错行为。复用 `Log`
  ⇒ 所有 guard 的行为**一字不改**，零风险。`FlagTestMode` 于是只承担两件事：
  ① 让引擎在启动时要求白名单非空；② 在横幅里吵出来。
- **fail-closed**：写了 `mode=test` 却没给名单 ⇒ **拒绝启动**（`throw` ⇒ 复用既有启动
  失败路径：startup-failure 日志 + 弹框 + 退出码 1）。否则会静默变成"零个进程被注入"，
  引擎看着在跑、实际全盲（铁律 110：别让"全零"也算成立）。
- **可诊断**（铁律 97 / 99 / 178）：命中与跳过**都打日志**
  （`测试模式(test_inject_only)：命中白名单，注入 image=...` / `…跳过非白名单进程…`）；
  启动横幅在名单非空时打印**条数 + 逐条内容 + 匹配规则**，并明说
  「名单之外的进程完全不受监控」。
- **ABI**：`AbiVersion` **21 → 22**。`Policy` 尾部追加 `ULONG TestInjectCount` +
  `WCHAR TestInjectPaths[16][260]`，并新增 `Flags2` 位 `FlagTestMode = 0x00000080`。
  尾部追加不改前面字段偏移；但 `sizeof(Policy)` 变大 ⇒ 两个方向都要挡
  （新 DLL + 旧引擎：`MapViewOfFile` 因旧 section 更小而失败；旧 DLL + 新引擎：
  映射成功但版本校验挡住，否则会按旧布局错读 `TestInjectPaths`）。

**移除了 v68 的命令行版**（同一个能力，换交付方式）：

- 删掉导出 `GlobalHookSessionSetTestInjectOnly`（`_exports.def` 尾部那条）、
  `R3ShieldCoreLib/functions.cpp` 的模块级变量 `g_testInjectOnly` 与
  `SetTestInjectOnlyImage()`、`engine_control.{h,cpp}` 的
  `SetTestInjectOnly()` / `SupportsTestInjectOnly()` / typedef / `GetProcAddress`、
  `app.cpp` 的 `--test-inject-only=` 解析与 fail-closed 段。
- **为什么删而不是留两条路**：引擎自带 `requireAdministrator` manifest、**自己会提权**，
  用户双击 `start.bat` 就行；而命令行传参要求调用方**先有提权 shell**（本机实测：
  沙箱里既不能提权、UAC 也起不来），等于把测试模式锁在"能提权的开发者"手里。
  留两条路 = 两份权威配置（铁律 127）。

**验证**：

| 层 | 手段 | 结果 |
|---|---|---|
| 配置解析（**不需要提权**） | `bash build_ut.sh x64` 里新增 **20 条** `config_ut` 断言 | **全 PASS** |
| 其中「解耦」一条的**负对照** | 临时把名单解析改成"只在 `mode=test` 时生效" | 断言**变红**（`FAIL 解耦：mode=block + 名单 -> …`，rc=1）⇒ 判据有牙齿（铁律 148） |
| 构建 | `bash build.sh Release`（双架构） | **BUILD OK**，零 warning |
| 闸门 | `bash deploy_dist.sh` / `check_dist_sync.sh` | **PASS**（含 v69 标记 + 负对照，见下） |
| 端到端三格矩阵 | `bash tools/spoof_e2e.sh --run-engine` | **未执行**（本机无法提权，见下） |

`config_ut` 新增断言覆盖：`mode=test` → `Mode::Log` + `FlagTestMode`；`mode=` 是权威的
（`mode=block` 覆盖 `mode=test` 时标志位被清掉）；**解耦**（`mode=block` + 名单照样读进来）；
可重复 / 逗号分隔 / 空值忽略 / 行内注释切掉 / 路径原样保留；超上限**截断而不越界**；
白名单与 `never_inject` **各自独立、内容不串**。

**闸门（`check_dist_sync.sh` 的 v69 节）**：

- ① EXE 含**窄**串 `test_inject_only=`（横幅 / fail-closed 报错里的字面量）；
- ② 两个架构的 DLL 都含**宽**串 `test_inject_only`（`functions.cpp` 的 LOG 字面量，
  用 `strings -el` 查 —— 中文是宽串，`-a` 查的是另一个世界）；
- ③ **负对照**：已删除的 `GlobalHookSessionSetTestInjectOnly` 必须**不在**任何产物里
  —— 若还在，说明"删了源码但没重编"（铁律 148：闸门要有负对照）。
- ④ 前提检查（铁律 117）：`test_inject_only` 这个**键名**必须同时出现在
  **三个**源文件里（解析器 `r3shieldcore_config.cpp` / 横幅 `app.cpp` / 日志
  `functions.cpp`）—— 任何一处改名，另两处都会静默漂移（铁律 127：跨语言收敛不了就建闸门）。
- 两条判据**各自的牙齿**都做过验证：构造含该符号的文件证明 `grep -qxF` 真能命中；
  构造 UTF-16LE 文件证明 `strings -el` 能命中而 `-a` **不能**（⇒ 用 `-el` 是必要的）。

### 新增 — 截屏「替换」端到端验证夹具（`tools/spoof_e2e*`）

配套 v67 的截屏替换，补齐"**真引擎注入真进程**"这一层（原来只做到机制层探针）。

- `tools/spoof_e2e_target.cpp`（`build_spoof_e2e.sh` 编）—— 被注入的**目标进程**：
  自己不做任何 hook，只报告 `READY`、等一个注入窗口，然后走**真的截屏路径**
  （`BitBlt` 屏幕 DC → 内存 DC → `GetDIBits` 读回）打一行机器可解析的 `RESULT`；
  再用 **`GetPixel` 直接读屏幕**（这条路径 ScreenGuard 没挂）作为真实画面的参照。
- `tools/spoof_e2e.sh` —— runner，**配置驱动**（v69 起不再用命令行开关），
  跑**三格矩阵**（同一份引擎、同一个目标，只改 `mode` / `spoof_screen`；
  三格**都**带 `test_inject_only=spoof_e2e_target.exe`）：

  | 格 | mode | spoof_screen | 期望 |
  |---|---|---|---|
  | A | block | 0 | `BitBlt` **失败** err=5（同时证明目标确实被注入了） |
  | B | block | 1 | `BitBlt` **成功但像素全黑**；`GetPixel` 路仍非黑（**多路径戳穿实证**） |
  | C | log   | 1 | `BitBlt` 成功且像素**非黑**（替换只在"本应拒绝"时生效） |

  > ★ A/B 两格是 `mode=block` 而不是 `mode=test` —— 正因为 v69 把注入范围与拦截行为
  > **解耦**了。否则这两格要么验不了替换、要么只能全局注入 block（会 hook 编辑器）。

- **两步式**（因为引擎清单是 `requireAdministrator`，而 非提权的 shell 提不了权）：
  - `--prepare`：**不需要管理员** —— 查产物 / 验基线 / 搭工作区 / 写三格配置，打印下一步。
  - `--run-engine`：**需要管理员终端** —— 真跑三格 + 出结论。
  - `--collect`：只重新解析上一次的落盘结果（`--run-engine` 跑完也调同一份断言）。
  - `--clean`：删掉工作区。
- **默认不跑**：不带动作时打印说明 + `[skip]`，**并把跳过数写进结论行**
  （沿用 `selftest_setup.py` 第 4 层的约定，铁律 175 / 178）。
- **不碰真实环境**：整个测试跑在一份**固定名**工作区里（`/tmp/spoof_e2e_work`），
  并把**子进程的** `ProgramData` 重定向到那里 ⇒ 不读也不写你真实的
  `%ProgramData%\R3 Shield Core\`。
  > ⚠️ 固定名是对铁律 177（临时路径带 PID）的**有意例外**：两步式要求工作区跨两次调用
  > 存活，而"同一时刻只能有一份引擎在跑"是硬约束（脚本自己会拒绝第二份）⇒ 天然串行。
- **前置检查 fail-closed**：产物缺失 / 不是管理员 / 已有别的引擎在跑 / **DLL 缺 v69 宽串标记**
  —— 任何一条不满足都**不启动引擎**。
- **断言"引擎读的是本格配置"**：引擎自己会打印 `配置文件 : ...`，runner 断言它含
  **`pd-<格>`**（每格一份的那条路径）。★ 只查工作区前缀是不够的 —— 兜底配置也在工作区里，
  那样会把"读了兜底"当成通过（铁律 142：只查存在 ⇒ 假绿）。
- **基线防空真**（铁律 110）：先让目标单独跑一次，要求拿到**非黑**画面；
  否则"变黑"无法归因，直接 FAIL 而不是报绿。

**★ 夹具开发中抓出的三个真问题**（都会让端到端**假绿或假 FAIL**）：

1. **`ProgramData` 传了 MSYS 形式**（`/tmp/...`）—— 引擎是原生 Windows 进程，
   拼出来的路径不存在 ⇒ 静默回退去读**你真实的那份配置**，测试结果整个失去意义。
   修法：`cygpath -w` 转成 Windows 形式。
2. **`cp -r dist` 把发布包自带的 `r3shieldcore.ini` 拷进工作区**（`mode=block`、
   **没有白名单**）。一旦 ProgramData 重定向失效，引擎读到它 = **全局注入 block**
   —— 正是这个脚本要防的事。修法：兜底配置写成**与格无关且最保守**的
   `mode=log` + 白名单，并且断言必须落到 `pd-<格>` 才算通过。
3. **引擎的控制台日志会被下一格覆盖** ⇒ 三格断言读到的都是最后一格。修法：每格跑完
   **拷走**成 `console-<格>.log`。
4. 附带：引擎名手抄错了（真名 `R3 ShieldCore.exe`，`R3` 与 `ShieldCore` 之间
   **只有一个空格**）⇒ 前置检查报"找不到引擎"。★ 这正是**铁律 127**。修法：
   **从目录里 glob 派生**（`ls "$DIST_DIR"/R3*.exe`），不再手写。

**验证状态**（夹具层，**未启动引擎**）：

| 项 | 手段 | 结果 |
|---|---|---|
| 目标进程判别力 | `spoof_e2e_target.exe --wait-ms=0`（单独跑，无 hook） | 基线 **nonblack=12288/12288**、`getpixel_full_nonblack=510/510` |
| 工作区/配置搭建 | `bash tools/spoof_e2e.sh --prepare` | **SETUP OK**（三格各一份 + 兜底一份，Windows 形式 ProgramData） |
| runner 默认路 | `bash tools/spoof_e2e.sh` | 打印说明 + `[skip]`，**rc=0** |
| 无结果时的断言路 | `bash tools/spoof_e2e.sh --collect` | 三格各 FAIL 并给出诊断，**rc=1**（不是静默通过） |
| 前置检查 | 非提权下 `--run-engine` | 在管理员检查处 **fail-closed**，未启动引擎，**rc=1** |
| **三格矩阵（真引擎）** | `bash tools/spoof_e2e.sh --run-engine` | **未执行** —— 见下 |

> ⚠️ **端到端三格矩阵仍未跑过**：本机非提权环境**无法提权**
> （`net session` 非管理员；Windows `sudo` 在本机被禁用），而引擎清单是
> `requireAdministrator`。夹具已就绪，请在**管理员终端**里跑：
> `bash tools/spoof_e2e.sh --prepare` 然后 `bash tools/spoof_e2e.sh --run-engine`
> （或到虚拟机 / 另一台机器上跑，那不需要额外确认。）

### 新增 — 截屏「替换」（回传数据替换，v67）

产品原有的处置只有两档：**放行**（调用成功、返回真实数据）与**拒绝**（调用失败）。
本次新增第三档 —— **替换**：调用**成功**返回，但回传数据被换成伪造内容
（`Decision::Spoofed`）。

- **开关**：ini `spoof_screen`，**默认关**。开启后，ScreenGuard 在**本应拒绝**截屏时
  改为「真调原函数 → 把目标 DC / 像素缓冲区涂黑 → **返回成功**」——
  调用方以为截到了，其实拿到一张黑图（日志记 `SPOOF`）。
- **覆盖四个截屏出口**：`BitBlt` / `StretchBlt` / `GetDIBits`（按**位深算行距**清零
  像素缓冲区）/ `PrintWindow`（按目标 DC 范围涂黑）。
- **生效范围**：只在 `mode=block` 的直接拒绝、`mode=ask` 下用户点"拒绝"这两处。
  `mode=log` 本来就不拒（替换会破坏"只记录、全放行"）；`mode=block_all` 下
  **一律拒绝**，不做替换（沿用全拦语义）。
- **前置条件**：必须同时 `hook_screen=1`，否则 ScreenGuard 根本不装 hook。
- **ABI**：`Decision` 新增 `Spoofed`，`Policy::Flags2` 新增 `FlagSpoofScreen`，
  `Event::Flags2` 新增 `FlagEvent2Spoofed` ⇒ **`AbiVersion` 20 → 21**
  （新旧混用会以"共享通道不可用"失败，而不是悄悄按旧语义跑）。
- **引擎侧**：日志 `DecisionName` 输出 `SPOOF`；GUI 决策分布新增 `SPOOF` 一档（紫色）、
  「只看被拦」过滤把它算作**已处置**；启动横幅显示替换开关状态；日志回放能解析 `SPOOF`。
- **已知盲区（非本次引入，诚实标注）**：`GetPixel` 逐像素读屏、Desktop Duplication、
  WinRT 屏幕捕获都没挂 ⇒ 换这些路径仍能拿到真画面。定位是**提高成本**，不是硬边界。

**验证**（本机**不运行引擎**，见铁律 175）：

- 机制层：`tools/spoof_retdata_probe.cpp` 自包含探针（自己挂自己的 hook，不注入、
  不经过引擎）实测 **9 passed / 0 failed** —— 证明「真调 → 改写 out 缓冲区 →
  返回**原**返回值」可行、返回码完好，并**实测到「多路径戳穿」**（只挂 `GetDIBits`
  时 `GetPixel` 仍返回真实像素）。
- 构建层：`bash build.sh Release` 双架构通过（x64 + x86）；
  `deploy_dist.sh` + `check_dist_sync.sh` 验收通过（含新增的 v67 代次标记）。
- **未做**：引擎在跑时的端到端验证（本机禁止运行引擎）。
- 逐面闭环盘点见 `docs/回传数据替换-多路径盘点.md`，技术预研见
  `docs/回传数据替换Hook-技术预研.md`。

### 新增 — 独立「配置编辑 + 日志观察」工具

随包附带 `r3shieldcore-cfg.exe`（`tools/r3shieldcore_cfg.cpp`，单文件 Win32 GUI）。
它**不注入、不挂钩、不依赖引擎或服务在跑**，也**不要求管理员**：

- **配置页**：把 `r3shieldcore.ini` 的键做成表单（勾选 / 下拉 / 数值 / 多行列表），
  带类型与范围校验；保存时**逐行改值、其余字节原样保留**（中文注释、空行、
  被注释掉的示例都不动）；分组切换时改动累计，不丢。
- **日志页**：实时 tail 事件 / 控制台 / 服务日志，支持暂停、关键字过滤、
  只看高危、只看被拦；高危标品红、被拦标红。

读写路径与引擎的 `ResolveConfigPath` 一致（`%ProgramData%\R3 Shield Core\`
优先，回退 exe 同目录）。构建时强制跑一遍无界面自检（`--selftest`，25 项断言，
含"写到不存在的目录必须失败"的负对照）；`deploy_dist.sh` / `build_dist_zip.sh` /
安装包 payload 清单均已收录它。

**外观与引擎主窗口一致**：同一套配色与字体（`Microsoft YaHei UI` -17/-14/-13、
`Consolas` -12）、同样的 62px 标题区 + 圆角页签栏（`TabBarTop=62 / TabBarHeight=38 /
TabWidth=84`）、同样的圆角 8px 自绘按钮（三态：常态白底中性描边 / 悬停浅蓝 /
按下加深）与圆角白面板。按钮与复选框都是 `BS_OWNERDRAW` 自绘；输入框/下拉框
仍用原生控件（自绘文本输入的成本与风险都不划算），但去掉 3D 边框、改由父窗口
补 1px 描边，并统一字体与底色。

> ⚠️ 两边的配色/字体/几何常量是**同一份值的两处拷贝**（本工具的
> `k*` 常量 ↔ 主窗口的 `Color*`/`Padding`/`TabBar*`）。改一边必须同步改另一边，
> 否则又会分叉 —— 见 `tools/r3shieldcore_cfg.cpp` 顶部注释。

---

## [1.0.0] - 2026-10-06

首个公开版本。

### 定位

Windows **用户态**行为拦截引擎（HIPS）。把注入 DLL 挂进所有进程，
hook `ntdll` / `ws2_32` / `user32` / `advapi32` / `combase` 等用户态出口，
在行为发生前决定 **放行 / 拒绝 / 询问**。

> ⚠️ 定位是**可见性与知情权**，不是安全边界。直 syscall、手工映射 DLL、
> 复制令牌都能绕过。**不适合生产环境。**

### 新增 — 监控面（18 类对象 / 17 个 guard）

注册表、文件、进程、线程、驱动加载、网络、摄像头/麦克风、输入钩子、屏幕捕获、
DLL 加载、剪贴板、进程创建旁路、服务安全描述符、COM 激活劫持、计划任务、
令牌窃取、WMI 事件订阅、宿主劫持。

其中 **6/7/8 三类**（摄像头、输入钩子、截屏）的判据不是"危险"而是"需要用户知情"
—— 它们本身不破坏数据，但都是窃听三件套。

### 新增 — 拦截模式（5 种）

| 值 | ini 写法 | 行为 |
|---|---|---|
| 0 | `log` | 只记录，全部放行 |
| 1 | `block` | 命中高危规则 → 硬拒 |
| 2 | `ask` | 命中高危规则 → 弹窗询问 |
| 3 | `block_all` | 一律拒（不看豁免、不看高危、不询问） |
| 4 | `block_all_safe` | 同 `block_all`，但放行"可信来源"的进程创建 |

### 新增 — 三层架构

- **内核驱动**（`r3shieldcore_kernel.sys`，`BOOT_START`，可选）：
  **不做任何拦截**，只负责"证明开机时加载了"并提供状态查询。
  刻意不注册 `ObRegisterCallbacks` / 进程回调 / 注册表回调 / minifilter
  —— 内核里每条分支都是开机风险。
- **守候服务**（LocalSystem / `AUTO_START`）：把引擎拉进有交互用户的会话，
  30 秒兜底 tick 重拉，安全模式下不拉。
- **引擎**（用户会话 / `requireAdministrator`）：注入器 + hook 层
  （约 110 处 MinHook inline hook + 2 组 COM vtable patch）+ 规则层 +
  纯 GDI 自绘 GUI（概览 / 事件日志 / 进程 / 配置 / ARK 五个页签）。

### 新增 — 跨进程询问通道

不是命名管道也不是窗口消息，而是**命名共享内存 + 命名事件**：
`Global\R3ShieldCore-Prompt-pid=<引擎pid>` + 8 个并发槽（DLL 侧 CAS 抢槽），
超时默认 30000 ms，超时结论默认 `deny`。
**通道不可用时只有 `log` 模式降级放行，其余模式保持拒。**

### 新增 — 构建与发布链

- `build.sh`：直接驱动 `cl.exe` / `link.exe`（不走 MSBuild），x86 + x64
- `deploy_dist.sh`：装配 `dist/R3ShieldCore-x64/`，含"x86 DLL 代次陈旧"
  这一类事故的防护（按内容 md5 校验，而非"文件存在"）
- `driver/build_driver.sh`：内核驱动，单独探测带 `km/` 的 WDK 版本
- `installer/`：单文件原生 Win32 GUI 安装器 + 自查
- Windows 与 MSYS2 双路打包

### 新增 — 测试与探针

`tools/` 下 60+ 个**只读探针**与 30+ 个单元测试，用于验证"hook 是否真的挂上、
规则是否真的命中"。以及 7 个上面提到的**构建闸门脚本**。

### 修复 — 开源化过程中发现并修掉的问题

- **x86 构建**：库路径导出误用未定义的 `ARCH` 变量
- **发布阻断**：全新 clone 原本编不出发布包（发布目录的 `.ini` / `.bat` / 文档
  被 `.gitignore` 整目录吞掉，而闸门自己也在被忽略的一侧，永远是绿的）
- **驱动可选**：让"驱动可选"真的可选 —— 全新 clone 现在能出安装包
- **两个死闸门**：闸门判据失效但仍报绿
- **本机痕迹**：清除开发机路径、证书信息、内部诊断全文
- **`.bat` 通配符闸门**：补齐缺失的检查
- **`LICENSE` 被 GitHub 判成 `Other`**：文件与官方 GPL-3.0 文本有两处偏差
  （顶部多加的 20 行版权声明 + 上游把 GPL 附录占位符换成了自己的名字），
  相似度掉到阈值下。已用 `gh api licenses/gpl-3.0` 的权威文本整份替换，
  项目版权声明改由 README §12 与 `THIRD-PARTY-NOTICES.md` 承载
- **CI 在全新 clone 上必红**：两条判据依赖"本机已构建过"
  （`check_payload_manifest.py` 的判据 E 与它自己的 `--selftest`）。
  后者**本来就是坏的** —— 注入锚点写死的文本早已改过，9 条负对照一条都没跑过

### 文档

- README 顶部改为「使用前必读」，明确写出**项目不成熟 / 容易被绕过 /
  请勿作为唯一终端防护软件 / 误报较多**；§11 免责声明与 `SECURITY.md` 同步
- README 顶部补**项目简介**（监控哪 18 类行为、有几种拦截选择、规模、隐私姿态）
- README 新增「下载」节与末尾 **Star History** 图表
- 新增 `SECURITY.md`（安全模型边界 + 私有漏洞上报 + 不接受为漏洞的类别清单）、
  `CONTRIBUTING.md`、`CHANGELOG.md`、`THIRD-PARTY-NOTICES.md`
- 新增 `.github/`：issue 表单、PR 模板、CI（6 个源码闸门 + 3 条负对照）
- 修复 `R3ShieldCore/README.md` 指向内部开发笔记的死链

### 安全

- 仓库**不含**任何本机路径、凭据、证书指纹或开发者身份信息
- 本项目**不**收集、不上传任何用户数据（无遥测、无更新回连）
- 第三方组件许可原文见 [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md)

### 已知边界

见 [`README.md`](README.md) 第 10 节 与 [`SECURITY.md`](SECURITY.md)。
要点：用户态 hook 有固有能力上限；进程启动到注入完成之间存在盲区；
不拦内核态发起的操作；没有单实例互斥体；UI 极端 DPI 下可能有布局问题。

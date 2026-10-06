# -*- coding: utf-8 -*-
"""把 MEMORY.md 按主题拆分（该文件自己一直在警告要被截断）。

策略：MEMORY.md 保留「索引 + 核心铁律 + 每条一行结论」；
完整正文按主题落到 MEMORY-1..4-*.md。
铁律编号**保持不变**（其它文档/HANDOVER 都按编号引用）。
"""
import io
import os
import re

import os
MEM_DIR = os.environ.get("R3SC_MEM_DIR", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", ".workbuddy-ai", "memory"))
SRC = os.path.join(MEM_DIR, "MEMORY.md")

with io.open(SRC, "r", encoding="utf-8") as f:
    lines = f.read().split("\n")

# 铁律 N 在第 N+4 行（1-based）-> 索引 N+3（0-based）
rules = {}
for m in re.finditer(r"^(\d+)\. \*\*", "\n".join(lines), re.M):
    n = int(m.group(1))
    idx = n + 3
    if idx < len(lines):
        rules[n] = lines[idx]

assert len(rules) == 35, f"期望 35 条，实际 {len(rules)}"
assert set(rules) == set(range(1, 36)), sorted(set(range(1, 36)) - set(rules))

# ---- 新增铁律（v41）----
rules[36] = (
    "36. **★★★ 拦截有「四道门」，第四道是**时间**（v41）**：① hook 装了 ② 路径/对象认得出 "
    "③ 访问掩码译对了 —— 这三道全通**照样拦不住**，因为「进程启动 → 注入完成」之间有**盲区**，"
    "落进去的行为**一律不记录、不拦截**。样本 `Windows XP Horror` 就是赢在时间上（Delphi `FormCreate` "
    "里无条件写 MBR）。★ **盲区 = 轮询间隔 + 注入耗时，必须当成可测、可配的量**："
    "`inject_interval_ms`（默认 10，范围 1..1000）**必须进发布包并被闸门断言**（否则和 v39 的 "
    "`hook_file=0` 同一个坑）。★ `inject_interval_ms < 16` 时**必须 `NtSetTimerResolution(10000,TRUE)`** "
    "（默认时钟粒度 15.6 ms，不抬粒度 `Sleep(10)` 实际睡 ~15.6 ms = 自欺欺人）。"
    "★★ **`kNeverInject[]` 这类「安全名单」会**决定**走哪条注入路**：`explorer.exe`/`svchost.exe` 在里面 "
    "⇒ **双击启动（父 explorer）与 UAC 提权启动（父 svchost）都只能走轮询**，同步路（父进程 hook "
    "`CreateProcessInternalW` + `CREATE_SUSPENDED`，子进程跑第一行代码前就挂好）**永远用不上** —— "
    "而样本恰好 `requireAdministrator`。改这类名单前必问「这会让哪些场景从同步路掉到轮询路」。"
    "★ 轮询路**也能**做到「第一行代码之前」：`InjectIntoNewProcess` 判「只有 1 个线程且 "
    "`Rip==RtlUserThreadStart`」⇒ 走 **APC 注入**；扫得够勤就能抢到。★ 残留边界必须对用户讲清："
    "用户态**没有零盲区**，要硬保证只能上内核过滤驱动。探针 `inject_race_probe.cpp`"
    "（**必须双击运行**：父进程是 `bash`/`cmd` 时它已被注入 ⇒ 走同步路 ⇒ 盲区恒 0、测不出问题）。"
)

rules[37] = (
    "37. **★★★ 探针选的操作必须在「被测配置」下真的会命中（v41）**：`inject_race_probe` 第 1 组"
    "原本用「启动目录建 .txt」当判据 —— `\\Startup\\` **确实**在高危规则表里，但它属于**普通文件操作**，"
    "而发布默认 `hook_file=0` ⇒ `Evaluate` 在 `FlagHookFile` 没开时**直接 `Pass`** ⇒ "
    "hook 明明装好了，探针却报「没被拦」= **结构性假阳性**。**修法**：改用 "
    "`HKCU\\...\\CurrentVersion\\Run` 写一个值再立刻删（注册表写入**不受 `hook_file` 影响**）。"
    "★ 教训是铁律 34 的变体：**「这个路径是高危规则」≠「当前配置会拦它」**。"
    "选判据前先问「**发布默认的那几个开关，会不会让这条判据提前 `Pass` 掉？**」"
    "★ 探针要**自证无害**：只做打开/写测试值，成功路径**立刻清理**（并用独立手段复核残留，如 Python `winreg`）。"
)

GROUP = {
    1: "core", 2: "f1", 3: "f4", 4: "f1", 5: "f1", 6: "f1", 7: "f1", 8: "f2", 9: "f1",
    10: "f4", 11: "f2", 12: "f2", 13: "f2", 14: "f2", 15: "f4", 16: "f2", 17: "f4",
    18: "f1", 19: "f4", 20: "f3", 21: "f3", 22: "f3", 23: "f3", 24: "f3", 25: "f3",
    26: "f4", 27: "f3", 28: "f3", 29: "f2", 30: "f3", 31: "f3", 32: "f2", 33: "f4",
    34: "f1", 35: "f3", 36: "f2", 37: "f4",
}
assert set(GROUP) == set(rules), sorted(set(GROUP) ^ set(rules))

HEADERS = {
    "f1": (
        "MEMORY-1-interception.md",
        "# 铁律·文件/注册表/裸盘拦截类\n"
        "> 从 `MEMORY.md` 拆出（原文照录，编号不变）。入口仍是 `MEMORY.md`。\n"
        "> 相关细节：`NOTES.md`、`docs/HANDOVER.md` §3.16 / §3.18。\n",
    ),
    "f2": (
        "MEMORY-2-injection.md",
        "# 铁律·注入/进程/终止/询问通道类\n"
        "> 从 `MEMORY.md` 拆出（原文照录，编号不变）。入口仍是 `MEMORY.md`。\n"
        "> 相关细节：`NOTES.md`（注入判据）、`docs/HANDOVER.md` §3.10k/§3.10l/§3.15/§3.18。\n",
    ),
    "f3": (
        "MEMORY-3-window-ui.md",
        "# 铁律·窗口/UI/置顶/覆盖层反制类\n"
        "> 从 `MEMORY.md` 拆出（原文照录，编号不变）。入口仍是 `MEMORY.md`。\n"
        "> 相关细节：`docs/HANDOVER.md` §3.10m/§3.10n/§3.12/§3.13/§3.17、附录 B。\n",
    ),
    "f4": (
        "MEMORY-4-build-test.md",
        "# 铁律·构建/发布/测试/环境坑类\n"
        "> 从 `MEMORY.md` 拆出（原文照录，编号不变）。入口仍是 `MEMORY.md`。\n"
        "> 相关细节：`NOTES.md`（环境坑/构建）、`docs/HANDOVER.md` 第四/七/八章。\n",
    ),
}

# ---- 写主题文件 ----
for key in ("f1", "f2", "f3", "f4"):
    fname, header = HEADERS[key]
    nums = [n for n in sorted(GROUP) if GROUP[n] == key]
    body = "\n".join(rules[n] for n in nums)
    content = header + "\n" + body + "\n"
    path = os.path.join(MEM_DIR, fname)
    with io.open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    print(f"写入 {fname}: {len(content.encode('utf-8'))} 字节, 铁律 {nums}")

# ---- 重写 MEMORY.md：索引 + 核心铁律 + 每条一行 ----
STARS = {n: rules[n].count("\u2605") for n in rules}

def oneliner(n):
    """从完整正文里抽「一句话结论」：取第一个句末标点前的部分，去掉序号/星标/加粗标记。"""
    t = rules[n]
    t = re.sub(r"^\d+\.\s*", "", t)
    t = t.replace("**", "")
    t = re.sub(r"^[\u2605\s]+", "", t)   # 去掉行首的 ★ 与空白
    # 截到第一个句末标点
    m = re.search(r"[。；]", t)
    if m:
        t = t[: m.start()]
    # 再硬截到 kMax 字，防止个别规则第一句就极长
    kMax = 150
    if len(t) > kMax:
        t = t[:kMax] + "…"
    return t

index_lines = []
index_lines.append("# R3ShieldCore 记忆（索引）")
index_lines.append(
    "> ★★ **本文件已按主题拆分**（原 12.6KB 逼近 16.2KB 截断点）。"
    "完整正文在下面 4 个文件里，**编号不变**（其它文档按编号引用）："
)
index_lines.append(">")
index_lines.append("> | 主题 | 文件 | 铁律编号 |")
index_lines.append("> |---|---|---|")
index_lines.append(
    "> | 文件/注册表/裸盘拦截 | `MEMORY-1-interception.md` | "
    + "、".join(str(n) for n in sorted(GROUP) if GROUP[n] == "f1")
    + " |"
)
index_lines.append(
    "> | 注入/进程/终止/询问通道 | `MEMORY-2-injection.md` | "
    + "、".join(str(n) for n in sorted(GROUP) if GROUP[n] == "f2")
    + " |"
)
index_lines.append(
    "> | 窗口/UI/置顶/覆盖层 | `MEMORY-3-window-ui.md` | "
    + "、".join(str(n) for n in sorted(GROUP) if GROUP[n] == "f3")
    + " |"
)
index_lines.append(
    "> | 构建/发布/测试/环境坑 | `MEMORY-4-build-test.md` | "
    + "、".join(str(n) for n in sorted(GROUP) if GROUP[n] == "f4")
    + " |"
)
index_lines.append(">")
index_lines.append(
    "> 环境坑 / 构建命令 / 监控判据 / 注入判据 / 窗口置顶 / 输入失效诊断 ⇒ `NOTES.md`；"
    "每个版本的完整来龙去脉 ⇒ `docs/HANDOVER.md`。"
)
index_lines.append(
    "> ★ 再加铁律：**先写进对应主题文件**，再在下面加**一行结论**。"
    "本文件只留「一句话」，防止被截断。"
)
index_lines.append("")
index_lines.append("## 铁律（一句话速查）")
index_lines.append("")
index_lines.append("> ★ 数 = 重要度（★ 越多越容易忘、代价越大）。**要看全文请打开对应主题文件。**")
index_lines.append("")

# 一行速查表：按编号顺序，带 ★ 数标记
for n in sorted(rules):
    star = "\u2605" * STARS[n]
    index_lines.append(f"{n}. {star} {oneliner(n)}")

index_lines.append("")
index_lines.append("## 两条不可忘的总纲（全文）")
index_lines.append("")
for n in (1, 2):
    index_lines.append(rules[n])
index_lines.append("")

content = "\n".join(index_lines) + "\n"
with io.open(SRC, "w", encoding="utf-8", newline="\n") as f:
    f.write(content)
print(f"重写 MEMORY.md: {len(content.encode('utf-8'))} 字节")

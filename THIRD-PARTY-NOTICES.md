# 第三方组件声明（THIRD-PARTY-NOTICES）

本文件汇集 R3 ShieldCore 中**全部第三方代码**的版权与许可信息。

MinHook 与 ReflectiveDLLInjection 都属 BSD 系列，其条款要求：**以二进制形式再分发**
时，必须把版权声明、条件列表和免责声明"**随文档或其他随附材料**"复现出来。
README 里的一句话列表不构成"随附材料"，而本仓库发布的是
`R3ShieldCore-Setup.exe` / `R3ShieldCore-x64.zip`，所以本文件必须随包发出。

---

## 总览

| 组件 | 许可 | 版权人 | 引入方式 | 位置 |
|---|---|---|---|---|
| MinHook | BSD 2-Clause | © 2009-2017 Tsuda Kageyu | 预编译 `.lib` + 头文件 | `R3ShieldCore/R3ShieldCoreLib/libraries/MinHook/` |
| wow64ext | LGPL-3.0 | © 2014 ReWolf | 源码 | `R3ShieldCore/R3ShieldCoreLib/libraries/wow64ext/` |
| WIL | MIT | © Microsoft Corporation | 头文件（vendored） | `R3ShieldCore/shared/libraries/wil/` |
| ReflectiveDLLInjection | BSD 3-Clause | © 2012 Stephen Fewer / Harmony Security | 源码（改写） | `R3ShieldCore/R3ShieldCoreLib/inject-shellcode/` |
| global-inject-demo | GPL-3.0 | © 2022 m417z | 派生基础（fork） | 整个项目 |

本项目的许可为 **GPL-3.0**（见 [`LICENSE`](LICENSE)），Copyright (C) 2026 yunsjxh。

---

## 1. MinHook

- 项目：<https://github.com/TsudaKageyu/minhook>
- 版权：Copyright (C) 2009-2017 Tsuda Kageyu. All rights reserved.
- 许可：BSD 2-Clause
- 本项目用法：以**预编译静态库**形式 vendored（`libMinHook.x64.lib` / `.x86.lib` /
  `.d.x64.lib` / `.d.x86.lib`）+ `MinHook.h`。是整个 hook 层（约 110 处 inline hook）的底座。

### 二进制分发义务

> 以二进制形式再分发时，**必须**在本文件（或随包文档）中复现下述版权声明、
> 条件列表与免责声明。

### 许可原文

```
MinHook - The Minimalistic API Hooking Library for x64/x86
Copyright (C) 2009-2017 Tsuda Kageyu.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

> MinHook 在 `libraries/MinHook/` 下只有 `MinHook.h` 和四个 `.lib`，上游的
> `LICENSE.txt` 没有一起 vendored。上面这段原文是从 `MinHook.h` 头部逐字复制的，
> 也是满足条款 2 的唯一依据。上游发新补丁版本时，重新拉取后要同步这一节。

---

## 2. wow64ext

- 项目：<http://blog.rewolf.pl/blog/?page_id=1100>（作者站点）
- 版权：Copyright (c) 2014 ReWolf
- 许可：GNU Lesser General Public License v3.0（LGPL-3.0）
- 本项目用法：源码 vendored，用于从 32 位进程跨架构读写 64 位目标进程的内存
  （`GetNt64Header` / `ReadProcessMemory64` 一类）。

### 许可原文

LGPL-3.0 的正文**不在本仓库单独存放**，原因是：LGPL-3.0 第 0 条明确规定
"本版本嵌入了 GPL-3.0 的条款与条件，并以下列附加许可为补充"——
即 **GPL-3.0 正文是 LGPL-3.0 的组成部分**，而它已经完整包含在 [`LICENSE`](LICENSE) 中。
附加许可条款原文见 <https://www.gnu.org/licenses/lgpl-3.0.txt>。

### 分发义务

| 场景 | 义务 | 本项目是否满足 |
|---|---|---|
| 分发源码 | 保留 `wow64ext.h` / `.cpp` / `internal.h` 头部的版权与许可声明 | ✅ 声明原样保留，未改动 |
| 分发二进制（静态链接） | LGPL-3.0 §4(d)(0)：随目标码提供 "Corresponding Source" | ✅ 本项目整体为 GPL-3.0 开源，源码即随包提供 |
| 用户可重新链接 | LGPL-3.0 §4(d)(1)：允许用户用自己的修改版库重新链接 | ✅ 完整构建脚本在库，用户可自编替换 |

> `wow64ext` 是本文档中唯一的 copyleft（弱）组件。它并入 GPL-3.0 项目是允许的
> （LGPL-3.0 §4 许可与 GPL-3.0 组合），但不能单独摘出去放进闭源产品。

---

## 3. WIL（Windows Implementation Library）

- 项目：<https://github.com/microsoft/wil>
- vendored 版本：commit `5ea390f863512848b78cb2cbbe2dccb28c87400a`
  （记录于 `R3ShieldCore/shared/libraries/wil/_version.txt`）
- 版权：Copyright (c) Microsoft Corporation
- 许可：MIT
- 本项目用法：纯头文件（`wil::unique_handle`、`com_ptr`、`registry` 等）。

### 许可原文

```
MIT License

Copyright (c) Microsoft Corporation.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 4. ReflectiveDLLInjection（`inject-shellcode/` 的来源）

- 项目：<https://github.com/stephenfewer/ReflectiveDLLInjection>
- 版权：Copyright (c) 2012, Stephen Fewer of Harmony Security
  (www.harmonysecurity.com). All rights reserved.
- 许可：**BSD 3-Clause**（注意：含"不得以 Harmony Security 名义背书"的第三条，
  与 MinHook 的 2-Clause 不同）
- 本项目用法：`R3ShieldCore/R3ShieldCoreLib/inject-shellcode/main.cpp` 的位置无关
  反射加载器（PEB 遍历 + 哈希自找 `LoadLibraryW` / `GetProcAddress`）基于该项目改写。

### 二进制分发义务

> 以二进制形式再分发时，**必须**在本文件（或随包文档）中复现下述版权声明、
> 条件列表与免责声明；且**不得**以 Harmony Security 或本项目名义暗示背书。

### 许可原文

```
Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.

    * Neither the name of Harmony Security nor the names of its contributors may
      be used to endorse or promote products derived from this software without
      specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

---

## 5. global-inject-demo（本项目的派生基础）

- 项目：<https://github.com/m417z/global-inject-demo>
- 博客：<https://m417z.com/Implementing-Global-Injection-and-Hooking-in-Windows/>
- 版权：Copyright (C) 2022 m417z
- 许可：GPL-3.0
- 本项目用法：整个项目的**上游 fork**。原始的"hook 注册表 API + `MessageBoxW` 演示"
  已被 R3ShieldCore 的 18 类对象 / 17 个 guard 取代，但注入框架、hook 骨架与
  `CreateProcessInternalW` 新进程注入路径源自该项目。
- 详见 [`R3ShieldCore/README.md`](R3ShieldCore/README.md)（上游 README 原样保留）。

> 上游许可为 GPL-3.0，与本项目一致 —— **不存在**许可冲突。本项目的 GPL-3.0
> 选择由此派生关系决定。

---

## 附：本项目自身的二进制分发

本项目以 GPL-3.0 发布。分发 `R3ShieldCore-Setup.exe` 或
`R3ShieldCore-x64.zip` 时，一并满足：

1. 随包提供或用显著方式指明**本仓库地址**（GPL-3.0 §6(d)：Corresponding Source）；
2. 随包提供 [`LICENSE`](LICENSE) 全文；
3. 随包提供**本文件**（承接上述 BSD / MIT 条款的"文档或其他随附材料"要求）；
4. 不得附加任何进一步限制（GPL-3.0 §10）。

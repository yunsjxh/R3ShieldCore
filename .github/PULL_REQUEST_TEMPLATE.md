## 改了什么

<!-- 一段话说清。不要写"修改了 N 个文件"。 -->

## 为什么

<!-- 解决什么问题？对应哪条铁律 / 哪次事故？ -->

## 怎么验证的

<!-- 必填。写清跑了哪一层、什么命令、关键输出。 -->

- [ ] `bash build_ut.sh` 通过（规则层单测，秒级、无需权限）
- [ ] `bash build_guard_ut.sh` 通过
- [ ] 涉及 hook 层 / 判定逻辑：附上了**探针**或**真机**的验证证据
- [ ] **x86 与 x64 都验证过**（两份独立 DLL，只测一边等于没测）
- [ ] 涉及发布目录：跑过 `bash deploy_dist.sh` + `bash check_dist_sync.sh`

## 闸门

- [ ] `python tools/check_source_gbk.py`
- [ ] `python tools/check_spaced_name_quoted.py`
- [ ] `python tools/check_bat_dir_wildcard.py`
- [ ] `python tools/check_bat_forf_redirect.py`
- [ ] `python tools/check_env_switch_names.py`
- [ ] `python tools/check_payload_manifest.py`

> 闸门报红**不要**改成宽松来变绿 —— 每一个闸门都对应一次真实事故，
> 见 `CONTRIBUTING.md` 第 3 节。

## 清单

- [ ] 新增/改名/删除的文件已**同步登记进对应闸门**（否则它就是个死闸门）
- [ ] 新增 guard 已同步更新：`ObjectType` 枚举、规则表、ini 配置键、README 第 2 节表格
- [ ] 改语义开关时已**全仓 grep** 该开关的所有读点
- [ ] 新增第三方代码：已更新 [`THIRD-PARTY-NOTICES.md`](../THIRD-PARTY-NOTICES.md)，且许可与 GPL-3.0 兼容
- [ ] 提交内容**不含**本机路径、证书指纹、凭据、内部诊断全文
- [ ] 我不打算把工具往"能做坏事"的方向改（隐蔽 / 提权 / 反检测）

## 声明

- [ ] 本次提交的代码我有权以 **GPL-3.0** 提交

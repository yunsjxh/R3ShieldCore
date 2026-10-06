#!/usr/bin/env bash
#
# build_dist_zip.sh —— 把 `dist/R3ShieldCore-x64/` 打成发布 zip（可复现）。
#
# 为什么单独写一个脚本：**zip 的条目列表本身就是交付物的一部分**。
# 手工拖拽容易漏文件（比如新加的 64/ 子目录），而且事后无法复现
# "这一版到底打了哪些文件"。这里把列表**显式写死**，少一个就报错。
#
# 用法:
#   bash build_dist_zip.sh            # 打包 + 列条目 + 打印 sha256
#   bash build_dist_zip.sh --check    # 只校验 dist 目录里的必备文件在不在
#
set -u

# ---- 工具链/路径统一由仓库根的 scripts_env.sh 自动探测 ----
#   本脚本可能位于仓库根或子目录（driver/ installer/ tools/），
#   所以向上找到含 scripts_env.sh 的目录（= 仓库根）。
R3SC_ENV=""; _d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
while [ "$_d" != "/" ] && [ -n "$_d" ]; do
    if [ -f "$_d/scripts_env.sh" ]; then R3SC_ENV="$_d/scripts_env.sh"; break; fi
    _d="$(dirname "$_d")"
done
if [ -z "$R3SC_ENV" ]; then echo "scripts_env.sh 未找到（应在仓库根）"; exit 1; fi
# shellcheck source=scripts_env.sh
. "$R3SC_ENV"
PROJECT_ROOT="$R3SC_PROJECT_ROOT"
SRC_DIR="dist/R3ShieldCore-x64"
OUT_ZIP="dist/R3ShieldCore-x64.zip"

# 可选：显式指定源目录（用于给候选版本出包，比如 dist/R3ShieldCore-x64-v46）。
# 给了目录就据此推导 zip 名；`--check` 之类的开关不受影响。
if [ -n "${1:-}" ] && [ "${1#--}" = "${1}" ]; then
    SRC_DIR="$1"
    OUT_ZIP="${SRC_DIR%/}.zip"
    shift
fi

cd "$PROJECT_ROOT" || exit 1

PY="$PYTHON"   # 由 scripts_env.sh 自动探测（见文件头）
# ★ 显式清单：少一个就失败（防止"打包漏文件"这种最难发现的发布事故）。
ENTRIES=(
    "R3 ShieldCore.exe"
    "r3shieldcore_svc.exe"
    "64/r3shieldcore-lib.dll"
    "32/r3shieldcore-lib.dll"
    "r3shieldcore.ini"
    "r3shieldcore-block.ini"
    "r3shieldcore-blockall.ini"
    "r3shieldcore-blockallsafe.ini"
    "r3shieldcore-safe-first.ini"
    "start.bat"
    "stop.bat"
    "unlock-acl.bat"
    "dskill.exe"
    "netcheck-diag.bat"
    "verify-v26.bat"
    "配置详解.md"
    "模式选择说明.md"
    "部署指南.md"
    "预设说明.txt"
)

missing=0
for e in "${ENTRIES[@]}"; do
    if [ ! -f "$SRC_DIR/$e" ]; then
        echo "!! 缺少必备文件: $SRC_DIR/$e"
        missing=1
    fi
done

if [ "$missing" -ne 0 ]; then
    echo "打包中止：发布目录不完整。"
    exit 1
fi

echo "必备文件检查: OK（${#ENTRIES[@]} 项）"

# ★ 闸门：dist 里的二进制必须 == 刚构建出来的二进制（内容相等，不是"文件存在"）。
#   理由见 check_dist_sync.sh 头部：v57 实测事故 —— 发布包里的 x86 DLL
#   停留在 v55 之前的代次，肉眼完全看不出来（文件在、大小也像），
#   后果是 32 位目标进程在超级置顶下**一条事件都不产生**。
echo ""
if ! bash check_dist_sync.sh "$SRC_DIR"; then
    echo ""
    echo "打包中止：发布目录与构建产物不同步。"
    exit 1
fi

# ★ 闸门：.bat/.cmd 必须是 cmd.exe 能正确解析的形态（CRLF + GBK，且没有
#   GBK 第二字节撞 cmd 元字符的字符）。
#   理由见 fix_bat_encoding.sh 头部：LF-only 的非 ASCII 批处理会让 cmd.exe
#   的解析器失同步，现象就是"窗口一闪而过" —— 而"一闪而过"在部署现场
#   会被误读成"引擎起来了但没拦住"，代价极高。
echo ""
echo "=== 检查 .bat/.cmd 编码（cmd.exe 可解析性）==="
if ! bash fix_bat_encoding.sh verify "$SRC_DIR"; then
    echo ""
    echo "打包中止：有 .bat/.cmd 不能被 cmd.exe 正确解析。"
    echo "          修复：bash fix_bat_encoding.sh fix $SRC_DIR"
    exit 1
fi

if [ "${1:-}" = "--check" ]; then
    exit 0
fi

echo "=== 生成 $OUT_ZIP ==="
"$PY" - "$SRC_DIR" "$OUT_ZIP" "${ENTRIES[@]}" <<'PYEOF'
import os
import sys
import zipfile
import hashlib

src_dir, out_zip = sys.argv[1], sys.argv[2]
entries = sys.argv[3:]

# 稳定打包：固定时间戳 + 排序，保证同内容 -> 同字节（可复现）。
FIXED_DATE = (2026, 1, 1, 0, 0, 0)

with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for name in entries:
        path = os.path.join(src_dir, name)
        zi = zipfile.ZipInfo(name, date_time=FIXED_DATE)
        zi.compress_type = zipfile.ZIP_DEFLATED
        # 保留可执行位（Linux 解压时有用；Windows 忽略）
        zi.external_attr = (0o755 if name.endswith((".exe", ".bat", ".dll")) else 0o644) << 16
        with open(path, "rb") as f:
            z.writestr(zi, f.read())

total = sum(os.path.getsize(os.path.join(src_dir, n)) for n in entries)
size = os.path.getsize(out_zip)
with open(out_zip, "rb") as f:
    digest = hashlib.sha256(f.read()).hexdigest()

print(f"条目数     : {len(entries)}")
print(f"原始总大小 : {total} 字节")
print(f"zip 大小   : {size} 字节（压缩率 {100.0 * (1 - size / total):.1f}%）")
print(f"sha256     : {digest}")
PYEOF

echo ""
echo "=== zip 条目 ==="
"$PY" - "$OUT_ZIP" <<'PYEOF'
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
for i in z.infolist():
    print(f"  {i.file_size:>10}  {i.filename}")
PYEOF

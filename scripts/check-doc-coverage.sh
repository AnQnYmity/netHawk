#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# 文档覆盖率检查脚本
#
# 检查项：
#   1. cargo doc --no-deps 零 warning
#   2. 统计公开项文档注释覆盖率（目标 ≥ 85%）
# ---------------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=== netHawk 文档覆盖率检查 ==="
echo ""

# -----------------------------------------------------------------------
# 1. 严格模式 cargo doc（missing_docs 视为错误）
# -----------------------------------------------------------------------
echo "[1/3] 严格模式 cargo doc 检查..."
if RUSTDOCFLAGS="-D warnings --deny missing_docs" cargo doc --no-deps 2>&1; then
    echo "  ✓ cargo doc 零 warning（含 missing_docs 检查）"
else
    echo "  ✗ cargo doc 存在 warning，请修复"
    exit 1
fi
echo ""

# -----------------------------------------------------------------------
# 2. 统计公开项文档覆盖率
# -----------------------------------------------------------------------
echo "[2/3] 统计文档覆盖率..."

# 统计所有 pub fn / pub struct / pub enum / pub trait 等声明
TOTAL_PUB=$(grep -rPn '^\s*pub\s+(fn|struct|enum|trait|mod|type)\s+' src/ | grep -v 'cfg(test)' | wc -l)
# 统计缺失文档注释的公开项（前面不是 /// 注释的行）
UNDOCUMENTED=$(grep -rPzo '(?s)(?<!\n[[:space:]]*///[^\n]*\n)[[:space:]]*pub\s+(fn|struct|enum|trait|mod|type)\s+' src/ 2>/dev/null | tr '\0' '\n' | grep -c 'pub ' || true)

if [ "$TOTAL_PUB" -eq 0 ]; then
    echo "  未找到公开项"
    exit 0
fi

DOCUMENTED=$((TOTAL_PUB - UNDOCUMENTED))
COVERAGE=$((DOCUMENTED * 100 / TOTAL_PUB))

echo "  公开项总数: $TOTAL_PUB"
echo "  已文档化:   $DOCUMENTED"
echo "  覆盖率:     ${COVERAGE}%"

if [ "$COVERAGE" -ge 85 ]; then
    echo "  ✓ 文档覆盖率 ≥ 85%"
else
    echo "  ✗ 文档覆盖率不足 85%"
    exit 1
fi
echo ""

# -----------------------------------------------------------------------
# 3. CHANGELOG.md 存在性检查
# -----------------------------------------------------------------------
echo "[3/3] CHANGELOG.md 存在性检查..."
if [ -f "CHANGELOG.md" ]; then
    echo "  ✓ CHANGELOG.md 存在"
else
    echo "  ✗ 缺少 CHANGELOG.md"
    exit 1
fi

echo ""
echo "=== 文档覆盖率检查通过 ==="

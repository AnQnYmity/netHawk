#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# 测试覆盖率检查脚本
#
# 检查项：
#   1. cargo-llvm-cov 行覆盖率（目标 ≥ 80%）
#   2. 测试用例数统计
# ---------------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=== netHawk 测试覆盖率检查 ==="
echo ""

# -----------------------------------------------------------------------
# 1. 运行覆盖率分析
# -----------------------------------------------------------------------
echo "[1/3] 运行 cargo-llvm-cov..."
COVERAGE_OUTPUT=$(cargo llvm-cov --summary-only 2>&1) || {
    echo "  ✗ cargo-llvm-cov 运行失败"
    exit 1
}
echo "$COVERAGE_OUTPUT"
echo ""

# -----------------------------------------------------------------------
# 2. 提取行覆盖率
# -----------------------------------------------------------------------
echo "[2/3] 提取行覆盖率..."
LINE_COV=$(echo "$COVERAGE_OUTPUT" | grep -oP 'lines[^:]*:\s*\K[\d.]+' | head -1)

if [ -z "$LINE_COV" ]; then
    # 尝试另一种格式
    LINE_COV=$(echo "$COVERAGE_OUTPUT" | grep -oP '[\d.]+%' | head -1 | grep -oP '[\d.]+')
fi

if [ -z "$LINE_COV" ]; then
    echo "  ⚠ 无法自动解析覆盖率数值，请手动确认"
    echo ""
    echo "  执行以下命令查看详细覆盖率报告："
    echo "    cargo llvm-cov --html"
    echo "  然后在浏览器中打开 target/llvm-cov/html/index.html"
else
    echo "  行覆盖率: ${LINE_COV}%"

    # 使用 awk 进行浮点数比较
    if awk "BEGIN {exit !($LINE_COV >= 80)}"; then
        echo "  ✓ 覆盖率 ≥ 80%"
    else
        echo "  ✗ 覆盖率不足 80%（当前: ${LINE_COV}%）"
        exit 1
    fi
fi
echo ""

# -----------------------------------------------------------------------
# 3. 统计测试用例数
# -----------------------------------------------------------------------
echo "[3/3] 统计测试用例数..."
TEST_COUNT=$(cargo test -- --list 2>/dev/null | grep -c 'test ' || echo "0")
echo "  测试用例总数: $TEST_COUNT"

echo ""
echo "=== 测试覆盖率检查完毕 ==="

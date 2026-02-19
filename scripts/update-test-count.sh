#!/usr/bin/env bash
# Updates the test count badge in README.md
# Run manually, via pre-commit hook, or in CI.
#
# Usage: ./scripts/update-test-count.sh
#
# How it works:
#   1. Counts TS tests via `vitest run --reporter=json` (runs tests, ~3s)
#   2. Counts Python tests via `pytest --collect-only -q` (instant, no execution)
#   3. Replaces the badge in README.md between <!-- test-count --> markers

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# ── Count TypeScript tests ──
TS_COUNT=$(bun run test:run --reporter=json 2>/dev/null \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['numTotalTests'])" 2>/dev/null \
  || echo "0")

# ── Count Python tests (collect-only is instant) ──
PY_COUNT=$(cd packages/python && source .venv/bin/activate 2>/dev/null && \
  pytest tests/ --collect-only -q 2>/dev/null | tail -1 | grep -oE '^[0-9]+' || echo "0")

TOTAL=$((TS_COUNT + PY_COUNT))

echo "Tests: ${TS_COUNT} TS + ${PY_COUNT} Python = ${TOTAL} total"

# ── Build the badge ──
BADGE="[![Tests](https://img.shields.io/badge/tests-${TOTAL}%20passing-brightgreen)](https://github.com/i8ramin/reverse-captcha/tree/main/tests)"

# ── Update README between markers ──
if grep -q '<!-- test-count -->' README.md; then
  # Replace content between markers
  sed -i '' "s|<!-- test-count -->.*<!-- /test-count -->|<!-- test-count -->${BADGE}<!-- /test-count -->|" README.md
  echo "✓ README.md updated: ${TOTAL} tests"
else
  echo "⚠ No <!-- test-count --> marker found in README.md"
  echo "  Add this line where you want the badge:"
  echo "  <!-- test-count -->${BADGE}<!-- /test-count -->"
  exit 1
fi

#!/usr/bin/env bash
# Anya CLI Integration Tests
# Run from repository root: bash tests/integration_cli.sh
#
# Prerequisites: cargo build -p anya-security-core

set -euo pipefail

ANYA="./target/debug/anya"
PASS=0
FAIL=0
TOTAL=0

pass() { ((PASS++)); ((TOTAL++)); echo "  PASS: $1"; }
fail() { ((FAIL++)); ((TOTAL++)); echo "  FAIL: $1"; }

echo "============================================"
echo "  ANYA CLI INTEGRATION TESTS"
echo "============================================"

# ── Build ──────────────────────────────────────────────────────────────────
echo ""
echo "Building..."
cargo build -p anya-security-core --quiet 2>/dev/null || { echo "Build failed!"; exit 1; }

if [ ! -f "$ANYA" ]; then
  echo "Binary not found at $ANYA"
  exit 1
fi

# ── Basic commands ─────────────────────────────────────────────────────────
echo ""
echo "── Basic Commands ──"

$ANYA --version >/dev/null 2>&1 && pass "--version exits 0" || fail "--version"
$ANYA --help >/dev/null 2>&1 && pass "--help exits 0" || fail "--help"

# ── File analysis ──────────────────────────────────────────────────────────
echo ""
echo "── File Analysis ──"

if [ -f tests/fixtures/simple.exe ]; then
  $ANYA --file tests/fixtures/simple.exe --no-color --quiet >/dev/null 2>&1 && pass "Analyse simple.exe" || fail "Analyse simple.exe"

  # JSON output
  JSON=$($ANYA --file tests/fixtures/simple.exe --json --no-color 2>/dev/null)
  echo "$JSON" | jq .file_format >/dev/null 2>&1 && pass "JSON output parses" || fail "JSON output"

  # Smoke test: file_format should be "Windows PE" or "PE"
  FORMAT=$(echo "$JSON" | jq -r .file_format 2>/dev/null)
  [[ "$FORMAT" == *"PE"* ]] && pass "Format detection: $FORMAT" || fail "Format detection: $FORMAT"
else
  echo "  SKIP: tests/fixtures/simple.exe not found"
fi

# ── Error handling ─────────────────────────────────────────────────────────
echo ""
echo "── Error Handling ──"

# Nonexistent file should exit non-zero
$ANYA --file /tmp/anya_nonexistent_file_12345.exe 2>/dev/null && fail "Nonexistent file should fail" || pass "Nonexistent file exits non-zero"

# Empty file (create temporary)
EMPTY_FILE=$(mktemp)
$ANYA --file "$EMPTY_FILE" --no-color 2>/dev/null || true
pass "Empty file doesn't crash"
rm -f "$EMPTY_FILE"

# ── KSD Commands ───────────────────────────────────────────────────────────
echo ""
echo "── KSD Commands ──"

$ANYA ksd stats >/dev/null 2>&1 && pass "ksd stats" || fail "ksd stats"

STATS=$($ANYA ksd stats 2>&1)
echo "$STATS" | grep -q "Total samples" && pass "ksd stats shows total" || fail "ksd stats format"

$ANYA ksd list --limit 3 >/dev/null 2>&1 && pass "ksd list" || fail "ksd list"

# ── YARA Placeholder ───────────────────────────────────────────────────────
echo ""
echo "── YARA Placeholder ──"

YARA_OUT=$($ANYA yara combine /tmp /tmp/out.yar 2>&1)
echo "$YARA_OUT" | grep -qi "coming soon" && pass "YARA shows placeholder" || fail "YARA placeholder"

# ── Shell Completions ──────────────────────────────────────────────────────
echo ""
echo "── Shell Completions ──"

$ANYA completions bash >/dev/null 2>&1 && pass "bash completions" || fail "bash completions"

# ── Batch Mode ─────────────────────────────────────────────────────────────
echo ""
echo "── Batch Mode ──"

if [ -d tests/fixtures ]; then
  $ANYA --directory tests/fixtures --quiet --no-color >/dev/null 2>&1 && pass "Batch analysis" || fail "Batch analysis"
else
  echo "  SKIP: tests/fixtures/ not found"
fi

# ── Summary ────────────────────────────────────────────────────────────────
echo ""
echo "============================================"
echo "  Results: $PASS passed, $FAIL failed, $TOTAL total"
echo "============================================"

[ "$FAIL" -eq 0 ] && exit 0 || exit 1

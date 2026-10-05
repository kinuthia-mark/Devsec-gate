#!/usr/bin/env bash
# scripts/opa-debug.sh
#
# Validates Rego syntax and runs a raw OPA query against the test fixture.
# Useful for isolating policy bugs from the Python wrapper.
set -euo pipefail

POLICIES_DIR="policies"
TEST_DATA="${1:-fixtures/scan-blocked.json}"

OPA_CMD="opa"
if ! command -v opa &> /dev/null; then
  if [ -f "./opa.exe" ]; then
    OPA_CMD="./opa.exe"
  elif [ -f "$HOME/bin/opa.exe" ]; then
    OPA_CMD="$HOME/bin/opa.exe"
  fi
fi

echo "OPA Policy Debugging Tool"
echo ""

echo "Test 1: Syntax validation"
$OPA_CMD check "$POLICIES_DIR/policy.rego" && echo "  policy.rego: valid"
$OPA_CMD check "$POLICIES_DIR/sla_gate.rego" && echo "  sla_gate.rego: valid"
echo ""
echo "Unit tests"
$OPA_CMD test "$POLICIES_DIR"
echo ""

echo "Test 2: Allow decision"
$OPA_CMD eval --data "$POLICIES_DIR" --input "$TEST_DATA" "data.devsecops.allow" --format json
echo ""

echo "Test 3: Full triage bundle"
$OPA_CMD eval --data "$POLICIES_DIR" --input "$TEST_DATA" "data.devsecops" --format json
echo ""

echo "Debug session complete."

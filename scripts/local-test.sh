#!/usr/bin/env bash
# scripts/local-test.sh
#
# End-to-end local dry run of the governance gate: OPA evaluation +
# Python triage report, writing artifacts to scan-results/.
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$PROJECT_ROOT"

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE} DevSecOps Governance Gate - Local Test Pipeline ${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

echo -e "${BLUE}[1/3] Validating Rego syntax...${NC}"
bash scripts/opa-debug.sh > /tmp/opa-debug.log 2>&1 && echo -e "${GREEN}  OK${NC}" || {
  echo -e "${RED}  FAILED - see /tmp/opa-debug.log${NC}"; exit 1;
}

echo -e "${BLUE}[2/3] Running policy triage against test fixture...${NC}"
set +e
python3 scripts/process-results.py fixtures/scan-blocked.json
GATE_RESULT=$?
set -e

echo -e "${BLUE}[3/3] Result${NC}"
if [ $GATE_RESULT -eq 0 ]; then
  echo -e "${GREEN}Gate PASSED.${NC}"
else
  echo -e "${RED}Gate BLOCKED (expected for the bundled test fixture, which contains an unmitigated CRITICAL CVE).${NC}"
fi

exit 0

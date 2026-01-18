#!/bin/bash
#
# Master Test Runner for Native IR Scripts
# Runs all bash and PowerShell tests
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                                                               ║"
    echo "║     Native IR Scripts - Comprehensive Test Suite              ║"
    echo "║                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_section() {
    echo ""
    echo -e "${MAGENTA}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${MAGENTA}│ $1${NC}"
    echo -e "${MAGENTA}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""
}

# Track results
BASH_UNIT_RESULT=0
BASH_SCENARIO_RESULT=0
PS_RESULT=0

print_banner

# Make test scripts executable
chmod +x "$SCRIPT_DIR/bash/test_runner.sh" 2>/dev/null || true
chmod +x "$SCRIPT_DIR/bash/test_scenarios.sh" 2>/dev/null || true

#
# ═══════════════════════════════════════════════════════════════
# BASH UNIT TESTS
# ═══════════════════════════════════════════════════════════════
#

print_section "Running Bash Unit Tests"

if [[ -f "$SCRIPT_DIR/bash/test_runner.sh" ]]; then
    if "$SCRIPT_DIR/bash/test_runner.sh"; then
        BASH_UNIT_RESULT=0
        echo -e "\n${GREEN}Bash unit tests: PASSED${NC}"
    else
        BASH_UNIT_RESULT=1
        echo -e "\n${RED}Bash unit tests: FAILED${NC}"
    fi
else
    echo -e "${YELLOW}Bash unit tests not found${NC}"
    BASH_UNIT_RESULT=2
fi

#
# ═══════════════════════════════════════════════════════════════
# BASH SCENARIO TESTS
# ═══════════════════════════════════════════════════════════════
#

print_section "Running Bash Scenario Tests"

if [[ -f "$SCRIPT_DIR/bash/test_scenarios.sh" ]]; then
    if "$SCRIPT_DIR/bash/test_scenarios.sh"; then
        BASH_SCENARIO_RESULT=0
        echo -e "\n${GREEN}Bash scenario tests: PASSED${NC}"
    else
        BASH_SCENARIO_RESULT=1
        echo -e "\n${RED}Bash scenario tests: FAILED${NC}"
    fi
else
    echo -e "${YELLOW}Bash scenario tests not found${NC}"
    BASH_SCENARIO_RESULT=2
fi

#
# ═══════════════════════════════════════════════════════════════
# POWERSHELL TESTS
# ═══════════════════════════════════════════════════════════════
#

print_section "Running PowerShell Tests"

if command -v pwsh &> /dev/null; then
    if [[ -f "$SCRIPT_DIR/powershell/Test-AllScripts.ps1" ]]; then
        if pwsh -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_DIR/powershell/Test-AllScripts.ps1"; then
            PS_RESULT=0
            echo -e "\n${GREEN}PowerShell tests: PASSED${NC}"
        else
            PS_RESULT=1
            echo -e "\n${RED}PowerShell tests: FAILED${NC}"
        fi
    else
        echo -e "${YELLOW}PowerShell tests not found${NC}"
        PS_RESULT=2
    fi
else
    echo -e "${YELLOW}PowerShell Core (pwsh) not installed - skipping PowerShell tests${NC}"
    echo -e "${YELLOW}Install with: apt install powershell${NC}"
    PS_RESULT=2
fi

#
# ═══════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════
#

echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                    FINAL TEST SUMMARY                         ║${NC}"
echo -e "${CYAN}╠═══════════════════════════════════════════════════════════════╣${NC}"

# Bash Unit Tests
echo -ne "${CYAN}║${NC}  Bash Unit Tests:       "
if [[ $BASH_UNIT_RESULT -eq 0 ]]; then
    echo -e "${GREEN}PASSED${NC}                            ${CYAN}║${NC}"
elif [[ $BASH_UNIT_RESULT -eq 2 ]]; then
    echo -e "${YELLOW}SKIPPED${NC}                           ${CYAN}║${NC}"
else
    echo -e "${RED}FAILED${NC}                            ${CYAN}║${NC}"
fi

# Bash Scenario Tests
echo -ne "${CYAN}║${NC}  Bash Scenario Tests:   "
if [[ $BASH_SCENARIO_RESULT -eq 0 ]]; then
    echo -e "${GREEN}PASSED${NC}                            ${CYAN}║${NC}"
elif [[ $BASH_SCENARIO_RESULT -eq 2 ]]; then
    echo -e "${YELLOW}SKIPPED${NC}                           ${CYAN}║${NC}"
else
    echo -e "${RED}FAILED${NC}                            ${CYAN}║${NC}"
fi

# PowerShell Tests
echo -ne "${CYAN}║${NC}  PowerShell Tests:      "
if [[ $PS_RESULT -eq 0 ]]; then
    echo -e "${GREEN}PASSED${NC}                            ${CYAN}║${NC}"
elif [[ $PS_RESULT -eq 2 ]]; then
    echo -e "${YELLOW}SKIPPED${NC}                           ${CYAN}║${NC}"
else
    echo -e "${RED}FAILED${NC}                            ${CYAN}║${NC}"
fi

echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"

# Calculate overall result
TOTAL_FAILED=0
[[ $BASH_UNIT_RESULT -eq 1 ]] && ((TOTAL_FAILED++))
[[ $BASH_SCENARIO_RESULT -eq 1 ]] && ((TOTAL_FAILED++))
[[ $PS_RESULT -eq 1 ]] && ((TOTAL_FAILED++))

echo ""
if [[ $TOTAL_FAILED -eq 0 ]]; then
    echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                    ALL TEST SUITES PASSED!                      ${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
    exit 0
else
    echo -e "${RED}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}                 $TOTAL_FAILED TEST SUITE(S) FAILED                        ${NC}"
    echo -e "${RED}════════════════════════════════════════════════════════════════${NC}"
    exit 1
fi

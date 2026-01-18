#!/bin/bash
#
# Scenario-Based Tests for Native Bash IR Scripts
# Tests detection of realistic attack techniques against synthetic data
#

set -uo pipefail
# Note: not using -e to allow tests to continue on failures

# Test directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LINUX_SCRIPTS="$PROJECT_DIR/linux"
FIXTURES_DIR="$SCRIPT_DIR/../fixtures"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

print_header() {
    echo -e "\n${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}\n"
}

print_suite() {
    echo -e "\n${BLUE}▶ Scenario: $1${NC}"
    echo -e "${BLUE}─────────────────────────────────────────${NC}"
}

print_test() {
    echo -ne "  ${YELLOW}○${NC} $1... "
}

pass() {
    ((TESTS_PASSED++)) || true
    ((TESTS_RUN++)) || true
    echo -e "${GREEN}✓ PASS${NC}"
}

fail() {
    ((TESTS_FAILED++)) || true
    ((TESTS_RUN++)) || true
    echo -e "${RED}✗ FAIL${NC}"
    if [[ -n "${1:-}" ]]; then
        echo -e "    ${RED}→ $1${NC}"
    fi
}

# Load fixtures
BASELINE_FILE="$FIXTURES_DIR/linux_process_baseline.json"
COMPROMISED_FILE="$FIXTURES_DIR/linux_process_compromised.json"
FILE_BASELINE="$FIXTURES_DIR/linux_file_baseline.json"
FILE_COMPROMISED="$FIXTURES_DIR/linux_file_compromised.json"

#
# ═══════════════════════════════════════════════════════════════
# FIXTURE DATA ANALYSIS TESTS
# ═══════════════════════════════════════════════════════════════
#

test_fixture_process_count_difference() {
    print_test "Compromised has more processes than baseline"
    local baseline_count compromised_count
    baseline_count=$(grep -c '"pid":' "$BASELINE_FILE")
    compromised_count=$(grep -c '"pid":' "$COMPROMISED_FILE")

    if [[ $compromised_count -gt $baseline_count ]]; then
        pass
    else
        fail "Baseline: $baseline_count, Compromised: $compromised_count"
    fi
}

test_fixture_missing_processes() {
    print_test "Compromised is missing fail2ban and postgres"
    local has_fail2ban has_postgres
    has_fail2ban=$(grep -c "fail2ban" "$COMPROMISED_FILE" 2>/dev/null) || has_fail2ban=0
    has_postgres=$(grep -c '"name":"postgres"' "$COMPROMISED_FILE" 2>/dev/null) || has_postgres=0

    # Baseline should have them
    local baseline_fail2ban baseline_postgres
    baseline_fail2ban=$(grep -c "fail2ban" "$BASELINE_FILE" 2>/dev/null) || baseline_fail2ban=0
    baseline_postgres=$(grep -c '"name":"postgres"' "$BASELINE_FILE" 2>/dev/null) || baseline_postgres=0

    if [[ $baseline_fail2ban -gt 0 && $has_fail2ban -eq 0 ]] || \
       [[ $baseline_postgres -gt 0 && $has_postgres -lt $baseline_postgres ]]; then
        pass
    else
        fail "Missing process detection failed"
    fi
}

test_fixture_new_malicious_processes() {
    print_test "Compromised has 12 new malicious PIDs (15001-15012)"
    local malicious_count
    malicious_count=$(grep -oP '"pid":150[0-1][0-9]' "$COMPROMISED_FILE" | wc -l)

    if [[ $malicious_count -ge 10 ]]; then
        pass
    else
        fail "Only found $malicious_count malicious PIDs"
    fi
}

#
# ═══════════════════════════════════════════════════════════════
# WEB SHELL DETECTION SCENARIO (T1505.003)
# ═══════════════════════════════════════════════════════════════
#

test_webshell_php_spawns_shell() {
    print_test "Web shell: PHP-FPM spawning sh process"
    # PID 15001 (sh) should have PPID 1002 (php-fpm)
    local shell_proc
    shell_proc=$(grep '"pid":15001' "$COMPROMISED_FILE")

    if [[ "$shell_proc" =~ \"ppid\":1002 ]] && [[ "$shell_proc" =~ \"name\":\"sh\" ]]; then
        pass
    else
        fail "Web shell parent-child not detected"
    fi
}

test_webshell_working_directory() {
    print_test "Web shell runs from uploads directory"
    local shell_proc
    shell_proc=$(grep '"pid":15001' "$COMPROMISED_FILE")

    if [[ "$shell_proc" =~ uploads ]]; then
        pass
    else
        fail "Working directory not uploads"
    fi
}

test_webshell_cmdline_recon() {
    print_test "Web shell executes reconnaissance commands"
    local shell_proc
    shell_proc=$(grep '"pid":15001' "$COMPROMISED_FILE")

    if [[ "$shell_proc" =~ whoami ]] || [[ "$shell_proc" =~ "id" ]] || [[ "$shell_proc" =~ "uname" ]]; then
        pass
    else
        fail "No recon commands in cmdline"
    fi
}

#
# ═══════════════════════════════════════════════════════════════
# REVERSE SHELL DETECTION SCENARIO (T1059.004)
# ═══════════════════════════════════════════════════════════════
#

test_reverse_shell_bash_dev_tcp() {
    print_test "Bash reverse shell via /dev/tcp"
    local rev_shell
    rev_shell=$(grep '"pid":15002' "$COMPROMISED_FILE")

    if [[ "$rev_shell" =~ /dev/tcp/ ]] && [[ "$rev_shell" =~ \"name\":\"bash\" ]]; then
        pass
    else
        fail "Bash /dev/tcp shell not detected"
    fi
}

test_reverse_shell_attacker_ip() {
    print_test "Reverse shell connects to attacker IP"
    local rev_shell
    rev_shell=$(grep '"pid":15002' "$COMPROMISED_FILE")

    if [[ "$rev_shell" =~ 203.0.113.66 ]]; then
        pass
    else
        fail "Attacker IP not found"
    fi
}

test_reverse_shell_python() {
    print_test "Python reverse shell from cron"
    local py_shell
    py_shell=$(grep '"pid":15005' "$COMPROMISED_FILE")

    if [[ "$py_shell" =~ socket ]] && [[ "$py_shell" =~ subprocess ]] && [[ "$py_shell" =~ \"ppid\":1456 ]]; then
        pass
    else
        fail "Python reverse shell not detected"
    fi
}

#
# ═══════════════════════════════════════════════════════════════
# PROCESS MASQUERADING SCENARIO (T1036)
# ═══════════════════════════════════════════════════════════════
#

test_masquerade_fake_kernel_thread() {
    print_test "Fake kernel thread [kworker] from /tmp"
    local fake_kworker
    fake_kworker=$(grep '"pid":15003' "$COMPROMISED_FILE")

    if [[ "$fake_kworker" =~ \[kworker ]] && [[ "$fake_kworker" =~ /tmp/ ]]; then
        pass
    else
        fail "Fake kworker not detected"
    fi
}

test_masquerade_kworker_has_exe() {
    print_test "Fake kworker has executable path (real kernel threads don't)"
    local fake_kworker
    fake_kworker=$(grep '"pid":15003' "$COMPROMISED_FILE")

    if [[ "$fake_kworker" =~ \"exe\":\"/tmp/ ]]; then
        pass
    else
        fail "Fake kworker exe path not suspicious"
    fi
}

test_masquerade_fake_systemd() {
    print_test "Fake systemd-helper in /var/tmp"
    local fake_systemd
    fake_systemd=$(grep '"pid":15006' "$COMPROMISED_FILE")

    if [[ "$fake_systemd" =~ systemd ]] && [[ "$fake_systemd" =~ /var/tmp/ ]]; then
        pass
    else
        fail "Fake systemd not detected"
    fi
}

#
# ═══════════════════════════════════════════════════════════════
# CRYPTOMINER DETECTION SCENARIO (T1496)
# ═══════════════════════════════════════════════════════════════
#

test_cryptominer_in_dev_shm() {
    print_test "Cryptominer running from /dev/shm"
    local miner
    miner=$(grep '"pid":15004' "$COMPROMISED_FILE")

    if [[ "$miner" =~ /dev/shm/ ]]; then
        pass
    else
        fail "Miner not in /dev/shm"
    fi
}

test_cryptominer_stratum_pool() {
    print_test "Cryptominer connects to stratum pool"
    local miner
    miner=$(grep '"pid":15004' "$COMPROMISED_FILE")

    if [[ "$miner" =~ stratum ]] && [[ "$miner" =~ pool ]]; then
        pass
    else
        fail "No pool connection detected"
    fi
}

test_cryptominer_hidden_directory() {
    print_test "Miner uses triple-dot hidden directory"
    local miner
    miner=$(grep '"pid":15004' "$COMPROMISED_FILE")

    if [[ "$miner" =~ \.\.\. ]]; then
        pass
    else
        fail "Hidden directory not used"
    fi
}

#
# ═══════════════════════════════════════════════════════════════
# NETCAT BACKDOOR SCENARIO (T1095)
# ═══════════════════════════════════════════════════════════════
#

test_netcat_backdoor_listener() {
    print_test "Netcat backdoor with -e flag"
    local nc_proc
    nc_proc=$(grep '"pid":15007' "$COMPROMISED_FILE")

    if [[ "$nc_proc" =~ \"name\":\"nc\" ]] && [[ "$nc_proc" =~ -e ]]; then
        pass
    else
        fail "Netcat backdoor not detected"
    fi
}

test_netcat_spawns_bash() {
    print_test "Netcat -e spawns /bin/bash"
    local nc_proc
    nc_proc=$(grep '"pid":15007' "$COMPROMISED_FILE")

    if [[ "$nc_proc" =~ /bin/bash ]]; then
        pass
    else
        fail "Netcat not spawning bash"
    fi
}

#
# ═══════════════════════════════════════════════════════════════
# ENCODED PAYLOAD SCENARIO (T1027)
# ═══════════════════════════════════════════════════════════════
#

test_base64_pipe_bash() {
    print_test "Base64 decode piped to bash"
    local b64_proc
    b64_proc=$(grep '"pid":15008' "$COMPROMISED_FILE")

    if [[ "$b64_proc" =~ base64 ]] && [[ "$b64_proc" =~ "| bash" ]]; then
        pass
    else
        fail "Base64 pipe to bash not detected"
    fi
}

test_curl_pipe_bash() {
    print_test "Curl download piped to bash"
    local curl_proc
    curl_proc=$(grep '"pid":15009' "$COMPROMISED_FILE")

    if [[ "$curl_proc" =~ curl ]] && [[ "$curl_proc" =~ "| bash" ]]; then
        pass
    else
        fail "Curl pipe to bash not detected"
    fi
}

#
# ═══════════════════════════════════════════════════════════════
# DELETED EXECUTABLE SCENARIO (T1070.004)
# ═══════════════════════════════════════════════════════════════
#

test_deleted_executable() {
    print_test "Process with deleted executable"
    local deleted_proc
    deleted_proc=$(grep '"pid":15010' "$COMPROMISED_FILE")

    if [[ "$deleted_proc" =~ \(deleted\) ]]; then
        pass
    else
        fail "Deleted executable not detected"
    fi
}

test_deleted_has_null_hash() {
    print_test "Deleted executable has null hash"
    local deleted_proc
    deleted_proc=$(grep '"pid":15010' "$COMPROMISED_FILE")

    if [[ "$deleted_proc" =~ \"exe_hash\":null ]]; then
        pass
    else
        fail "Hash should be null"
    fi
}

#
# ═══════════════════════════════════════════════════════════════
# FILE ANOMALY SCENARIOS
# ═══════════════════════════════════════════════════════════════
#

test_file_new_malicious_count() {
    print_test "Compromised has 10+ new malicious files"
    local new_files
    new_files=$(grep -c "NEW MALICIOUS" "$FILE_COMPROMISED" || echo "0")

    if [[ $new_files -ge 10 ]]; then
        pass
    else
        fail "Only $new_files malicious files found"
    fi
}

test_file_hidden_miner() {
    print_test "Hidden cryptominer in /tmp/.hidden/"
    if grep -q "/tmp/.hidden/miner" "$FILE_COMPROMISED"; then
        pass
    else
        fail "Hidden miner not found"
    fi
}

test_file_webshell_php() {
    print_test "Web shell PHP file detected"
    if grep -q "shell.php" "$FILE_COMPROMISED"; then
        pass
    else
        fail "Web shell not found"
    fi
}

test_file_cron_persistence() {
    print_test "Hidden cron persistence file"
    if grep -q "/etc/cron.d/.update" "$FILE_COMPROMISED"; then
        pass
    else
        fail "Cron persistence not found"
    fi
}

test_file_ssh_backdoor() {
    print_test "SSH authorized_keys backdoor"
    if grep -q "authorized_keys2" "$FILE_COMPROMISED"; then
        pass
    else
        fail "SSH backdoor not found"
    fi
}

test_file_modified_crontab() {
    print_test "Modified root crontab detected"
    local modified
    modified=$(grep -A2 "crontabs/root" "$FILE_COMPROMISED" | grep -c "MODIFIED" || echo "0")

    if [[ $modified -gt 0 ]]; then
        pass
    else
        fail "Modified crontab not detected"
    fi
}

test_file_exe_masquerade() {
    print_test "Executable masquerading as text file"
    if grep -q "readme.txt" "$FILE_COMPROMISED" && grep -q '"type":"executable"' "$FILE_COMPROMISED"; then
        pass
    else
        fail "EXE masquerade not detected"
    fi
}

#
# ═══════════════════════════════════════════════════════════════
# RUN ALL SCENARIO TESTS
# ═══════════════════════════════════════════════════════════════
#

run_all_scenarios() {
    print_header "Scenario-Based Detection Tests"

    print_suite "Fixture Data Analysis"
    test_fixture_process_count_difference
    test_fixture_missing_processes
    test_fixture_new_malicious_processes

    print_suite "Web Shell Detection (T1505.003)"
    test_webshell_php_spawns_shell
    test_webshell_working_directory
    test_webshell_cmdline_recon

    print_suite "Reverse Shell Detection (T1059.004)"
    test_reverse_shell_bash_dev_tcp
    test_reverse_shell_attacker_ip
    test_reverse_shell_python

    print_suite "Process Masquerading (T1036)"
    test_masquerade_fake_kernel_thread
    test_masquerade_kworker_has_exe
    test_masquerade_fake_systemd

    print_suite "Cryptominer Detection (T1496)"
    test_cryptominer_in_dev_shm
    test_cryptominer_stratum_pool
    test_cryptominer_hidden_directory

    print_suite "Netcat Backdoor (T1095)"
    test_netcat_backdoor_listener
    test_netcat_spawns_bash

    print_suite "Encoded Payload (T1027)"
    test_base64_pipe_bash
    test_curl_pipe_bash

    print_suite "Deleted Executable (T1070.004)"
    test_deleted_executable
    test_deleted_has_null_hash

    print_suite "File Anomaly Scenarios"
    test_file_new_malicious_count
    test_file_hidden_miner
    test_file_webshell_php
    test_file_cron_persistence
    test_file_ssh_backdoor
    test_file_modified_crontab
    test_file_exe_masquerade

    # Summary
    print_header "Scenario Test Summary"
    echo -e "Tests run:    ${BLUE}$TESTS_RUN${NC}"
    echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
    echo ""

    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}════════════════════════════════════════${NC}"
        echo -e "${GREEN}  ALL SCENARIO TESTS PASSED!${NC}"
        echo -e "${GREEN}════════════════════════════════════════${NC}"
        exit 0
    else
        echo -e "${RED}════════════════════════════════════════${NC}"
        echo -e "${RED}  SOME SCENARIO TESTS FAILED${NC}"
        echo -e "${RED}════════════════════════════════════════${NC}"
        exit 1
    fi
}

run_all_scenarios

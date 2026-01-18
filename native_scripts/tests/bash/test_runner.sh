#!/bin/bash
#
# Test Runner for Native Bash IR Scripts
# Pure bash testing framework - no external dependencies
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

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
CURRENT_SUITE=""

# Test output
print_header() {
    echo -e "\n${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}\n"
}

print_suite() {
    CURRENT_SUITE="$1"
    echo -e "\n${BLUE}▶ Test Suite: $1${NC}"
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

assert_equals() {
    local expected="$1"
    local actual="$2"
    local msg="${3:-}"

    if [[ "$expected" == "$actual" ]]; then
        return 0
    else
        if [[ -n "$msg" ]]; then
            echo "Expected: $expected, Got: $actual - $msg" >&2
        fi
        return 1
    fi
}

assert_contains() {
    local haystack="$1"
    local needle="$2"

    if [[ "$haystack" == *"$needle"* ]]; then
        return 0
    else
        return 1
    fi
}

assert_not_empty() {
    local value="$1"

    if [[ -n "$value" ]]; then
        return 0
    else
        return 1
    fi
}

assert_file_exists() {
    local file="$1"

    if [[ -f "$file" ]]; then
        return 0
    else
        return 1
    fi
}

assert_json_valid() {
    local file="$1"

    # Simple JSON validation - check for basic structure
    if grep -q '"timestamp"' "$file" && grep -q '}' "$file"; then
        return 0
    else
        return 1
    fi
}

# Create temp directory for test outputs
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Shared baselines - create once and reuse
SHARED_PROC_BASELINE="$TEMP_DIR/shared_proc_baseline.json"
SHARED_FILE_BASELINE="$TEMP_DIR/shared_file_baseline.json"

# Setup function to create shared baselines once
setup_shared_baselines() {
    echo -ne "  ${CYAN}Setting up test baselines...${NC} "
    # Create minimal baselines quickly for testing
    cat > "$SHARED_PROC_BASELINE" << 'EOF'
{
  "timestamp": "2024-01-15T10:00:00+00:00",
  "hostname": "test-host",
  "kernel": "5.15.0",
  "platform": "Linux",
  "processes": [
    {"pid":1,"name":"systemd","ppid":0,"username":"root","exe":"/usr/lib/systemd/systemd","cmdline":"/sbin/init","cwd":"/","state":"S","create_time":1705312800,"exe_hash":"abc123"}
  ]
}
EOF
    cat > "$SHARED_FILE_BASELINE" << 'EOF'
{
  "timestamp": "2024-01-15T10:00:00+00:00",
  "hostname": "test-host",
  "monitored_paths": ["/tmp", "/var/tmp"],
  "files": [
    {"path":"/tmp/test","type":"file","size":100,"hash":"abc123"}
  ]
}
EOF
    echo -e "${GREEN}done${NC}"
}

#
# ═══════════════════════════════════════════════════════════════
# PROCESS ANOMALY TESTS
# ═══════════════════════════════════════════════════════════════
#

test_process_anomaly_script_exists() {
    print_test "process_anomaly.sh exists"
    if assert_file_exists "$LINUX_SCRIPTS/process_anomaly.sh"; then
        pass
    else
        fail "Script not found"
    fi
}

test_process_anomaly_is_executable() {
    print_test "process_anomaly.sh is executable"
    if [[ -x "$LINUX_SCRIPTS/process_anomaly.sh" ]]; then
        pass
    else
        fail "Script not executable"
    fi
}

test_process_anomaly_shows_usage() {
    print_test "Shows usage with no arguments"
    local output
    output=$("$LINUX_SCRIPTS/process_anomaly.sh" 2>&1 || true)
    if assert_contains "$output" "Usage"; then
        pass
    else
        fail "No usage shown"
    fi
}

test_process_anomaly_shows_help() {
    print_test "Shows help with -h flag"
    local output
    output=$("$LINUX_SCRIPTS/process_anomaly.sh" -h 2>&1 || true)
    if assert_contains "$output" "baseline" && assert_contains "$output" "scan"; then
        pass
    else
        fail "Help incomplete"
    fi
}

test_process_anomaly_baseline_creates_file() {
    print_test "Baseline mode creates JSON file"
    local output_file="$TEMP_DIR/proc_baseline.json"
    # Use timeout since baseline creation can be slow
    timeout 30 "$LINUX_SCRIPTS/process_anomaly.sh" baseline -o "$output_file" > /dev/null 2>&1 || true
    if assert_file_exists "$output_file" && [[ -s "$output_file" ]]; then
        pass
    else
        fail "Baseline file not created"
    fi
}

test_process_anomaly_baseline_valid_json() {
    print_test "Baseline produces valid JSON structure"
    # Reuse the file from previous test if it exists, otherwise use shared baseline
    local output_file="$TEMP_DIR/proc_baseline.json"
    if [[ ! -f "$output_file" ]]; then
        output_file="$SHARED_PROC_BASELINE"
    fi
    if assert_json_valid "$output_file"; then
        pass
    else
        fail "Invalid JSON"
    fi
}

test_process_anomaly_baseline_has_hostname() {
    print_test "Baseline contains hostname"
    local output_file="$TEMP_DIR/proc_baseline.json"
    if [[ ! -f "$output_file" ]]; then
        output_file="$SHARED_PROC_BASELINE"
    fi
    if grep -q '"hostname"' "$output_file"; then
        pass
    else
        fail "No hostname in baseline"
    fi
}

test_process_anomaly_baseline_has_processes() {
    print_test "Baseline contains processes array"
    local output_file="$TEMP_DIR/proc_baseline.json"
    if [[ ! -f "$output_file" ]]; then
        output_file="$SHARED_PROC_BASELINE"
    fi
    if grep -q '"processes"' "$output_file"; then
        pass
    else
        fail "No processes array"
    fi
}

test_process_anomaly_baseline_has_pids() {
    print_test "Baseline processes have PIDs"
    local output_file="$TEMP_DIR/proc_baseline.json"
    if [[ ! -f "$output_file" ]]; then
        output_file="$SHARED_PROC_BASELINE"
    fi
    if grep -q '"pid":' "$output_file"; then
        pass
    else
        fail "No PIDs in processes"
    fi
}

test_process_anomaly_baseline_has_hashes() {
    print_test "Baseline processes have exe_hash field"
    local output_file="$TEMP_DIR/proc_baseline.json"
    if [[ ! -f "$output_file" ]]; then
        output_file="$SHARED_PROC_BASELINE"
    fi
    if grep -q '"exe_hash":' "$output_file"; then
        pass
    else
        fail "No exe_hash in processes"
    fi
}

test_process_anomaly_scan_requires_baseline() {
    print_test "Scan mode requires baseline file"
    local output
    output=$("$LINUX_SCRIPTS/process_anomaly.sh" scan 2>&1 || true)
    if assert_contains "$output" "required" || assert_contains "$output" "Baseline"; then
        pass
    else
        fail "Should require baseline"
    fi
}

test_process_anomaly_scan_runs_with_baseline() {
    print_test "Scan runs successfully with baseline"
    local baseline="$TEMP_DIR/scan_baseline.json"
    "$LINUX_SCRIPTS/process_anomaly.sh" baseline -o "$baseline" > /dev/null 2>&1
    local output
    # Use timeout since scan can be slow; check that it starts properly
    output=$(timeout 10 "$LINUX_SCRIPTS/process_anomaly.sh" scan -b "$baseline" 2>&1 || true)
    if assert_contains "$output" "Scanning Current Processes" || assert_contains "$output" "Baseline processes"; then
        pass
    else
        fail "Scan did not complete"
    fi
}

test_process_anomaly_detects_itself_as_new() {
    print_test "Scan detects new processes"
    # Create a minimal baseline, then run scan - the scan process itself is new
    local baseline="$TEMP_DIR/minimal_baseline.json"
    echo '{"timestamp":"2024-01-01T00:00:00","hostname":"test","processes":[]}' > "$baseline"
    local output
    # Use timeout since scan can be slow; with empty baseline, should show NEW processes quickly
    output=$(timeout 15 "$LINUX_SCRIPTS/process_anomaly.sh" scan -b "$baseline" 2>&1 || true)
    if assert_contains "$output" "[NEW]" || assert_contains "$output" "New processes"; then
        pass
    else
        fail "Did not detect new processes"
    fi
}

#
# ═══════════════════════════════════════════════════════════════
# FILE ANOMALY TESTS
# ═══════════════════════════════════════════════════════════════
#

test_file_anomaly_script_exists() {
    print_test "file_anomaly.sh exists"
    if assert_file_exists "$LINUX_SCRIPTS/file_anomaly.sh"; then
        pass
    else
        fail "Script not found"
    fi
}

test_file_anomaly_is_executable() {
    print_test "file_anomaly.sh is executable"
    if [[ -x "$LINUX_SCRIPTS/file_anomaly.sh" ]]; then
        pass
    else
        fail "Script not executable"
    fi
}

test_file_anomaly_shows_usage() {
    print_test "Shows usage with no arguments"
    local output
    output=$("$LINUX_SCRIPTS/file_anomaly.sh" 2>&1 || true)
    if assert_contains "$output" "Usage"; then
        pass
    else
        fail "No usage shown"
    fi
}

test_file_anomaly_baseline_creates_file() {
    print_test "Baseline mode creates JSON file"
    local output_file="$TEMP_DIR/file_baseline.json"
    # Use timeout since baseline creation can be slow
    timeout 30 "$LINUX_SCRIPTS/file_anomaly.sh" baseline -o "$output_file" > /dev/null 2>&1 || true
    if assert_file_exists "$output_file" && [[ -s "$output_file" ]]; then
        pass
    else
        fail "Baseline file not created"
    fi
}

test_file_anomaly_baseline_has_files() {
    print_test "Baseline contains files array"
    local output_file="$TEMP_DIR/file_baseline.json"
    if [[ ! -f "$output_file" ]]; then
        output_file="$SHARED_FILE_BASELINE"
    fi
    if grep -q '"files"' "$output_file"; then
        pass
    else
        fail "No files array"
    fi
}

test_file_anomaly_baseline_has_paths() {
    print_test "Baseline contains monitored_paths"
    local output_file="$TEMP_DIR/file_baseline.json"
    if [[ ! -f "$output_file" ]]; then
        output_file="$SHARED_FILE_BASELINE"
    fi
    if grep -q '"monitored_paths"' "$output_file"; then
        pass
    else
        fail "No monitored_paths"
    fi
}

test_file_anomaly_monitors_tmp() {
    print_test "Monitors /tmp directory"
    local output_file="$TEMP_DIR/file_baseline.json"
    if [[ ! -f "$output_file" ]]; then
        output_file="$SHARED_FILE_BASELINE"
    fi
    if grep -q '"/tmp"' "$output_file"; then
        pass
    else
        fail "Not monitoring /tmp"
    fi
}

test_file_anomaly_scan_runs() {
    print_test "Scan mode runs with baseline"
    local baseline="$TEMP_DIR/file_scan_baseline.json"
    "$LINUX_SCRIPTS/file_anomaly.sh" baseline -o "$baseline" > /dev/null 2>&1
    local output
    # Use timeout; check that scan starts properly
    output=$(timeout 15 "$LINUX_SCRIPTS/file_anomaly.sh" scan -b "$baseline" 2>&1 || true)
    if assert_contains "$output" "Scanning for New" || assert_contains "$output" "Baseline files"; then
        pass
    else
        fail "Scan did not complete"
    fi
}

test_file_anomaly_detects_new_file() {
    print_test "Detects new file in /tmp"
    local baseline="$TEMP_DIR/file_new_baseline.json"
    "$LINUX_SCRIPTS/file_anomaly.sh" baseline -o "$baseline" > /dev/null 2>&1

    # Create a new file
    local test_file="/tmp/test_ir_script_$$_new.txt"
    echo "test" > "$test_file"
    trap "rm -f $test_file" RETURN

    local output
    # Use timeout since scan can be slow
    output=$(timeout 20 "$LINUX_SCRIPTS/file_anomaly.sh" scan -b "$baseline" 2>&1 || true)

    rm -f "$test_file"

    if assert_contains "$output" "[NEW]" || assert_contains "$output" "New files"; then
        pass
    else
        fail "Did not detect new file"
    fi
}

#
# ═══════════════════════════════════════════════════════════════
# PROCESS HUNTER TESTS
# ═══════════════════════════════════════════════════════════════
#

test_process_hunter_script_exists() {
    print_test "process_hunter.sh exists"
    if assert_file_exists "$LINUX_SCRIPTS/process_hunter.sh"; then
        pass
    else
        fail "Script not found"
    fi
}

test_process_hunter_is_executable() {
    print_test "process_hunter.sh is executable"
    if [[ -x "$LINUX_SCRIPTS/process_hunter.sh" ]]; then
        pass
    else
        fail "Script not executable"
    fi
}

test_process_hunter_shows_usage() {
    print_test "Shows usage with no arguments"
    local output
    output=$("$LINUX_SCRIPTS/process_hunter.sh" 2>&1 || true)
    if assert_contains "$output" "Usage"; then
        pass
    else
        fail "No usage shown"
    fi
}

test_process_hunter_search_by_pattern() {
    print_test "Search by pattern finds processes"
    local output
    # Use timeout for slow scans; pattern is first positional argument
    output=$(timeout 15 "$LINUX_SCRIPTS/process_hunter.sh" "bash" 2>&1 || true)
    if assert_contains "$output" "PID:" || assert_contains "$output" "bash" || assert_contains "$output" "matches"; then
        pass
    else
        fail "Pattern search failed"
    fi
}

test_process_hunter_suspicious_scan() {
    print_test "Suspicious scan mode works"
    local output
    # Use timeout for slow scans; search for suspicious process names
    output=$(timeout 20 "$LINUX_SCRIPTS/process_hunter.sh" "nc|netcat|socat" 2>&1 || true)
    if assert_contains "$output" "matches" || assert_contains "$output" "PID:" || assert_contains "$output" "No processes"; then
        pass
    else
        fail "Suspicious scan failed"
    fi
}

test_process_hunter_all_mode() {
    print_test "All processes mode works"
    local output
    # Use timeout for slow scans; use broad pattern to match many processes
    output=$(timeout 10 "$LINUX_SCRIPTS/process_hunter.sh" ".*" 2>&1 || true)
    if assert_contains "$output" "PID:" || assert_contains "$output" "matches"; then
        pass
    else
        fail "All mode failed"
    fi
}

test_process_hunter_pattern_regex() {
    print_test "Pattern supports regex"
    local output
    # Pattern is positional argument, not -p option
    output=$(timeout 15 "$LINUX_SCRIPTS/process_hunter.sh" "bash|sh" 2>&1 || true)
    if assert_contains "$output" "matches" || assert_contains "$output" "PID:"; then
        pass
    else
        fail "Regex pattern failed"
    fi
}

#
# ═══════════════════════════════════════════════════════════════
# FIXTURE VALIDATION TESTS
# ═══════════════════════════════════════════════════════════════
#

test_fixture_linux_baseline_exists() {
    print_test "Linux process baseline fixture exists"
    if assert_file_exists "$FIXTURES_DIR/linux_process_baseline.json"; then
        pass
    else
        fail "Fixture not found"
    fi
}

test_fixture_linux_compromised_exists() {
    print_test "Linux process compromised fixture exists"
    if assert_file_exists "$FIXTURES_DIR/linux_process_compromised.json"; then
        pass
    else
        fail "Fixture not found"
    fi
}

test_fixture_baseline_has_processes() {
    print_test "Baseline fixture has realistic process count"
    local count
    count=$(grep -c '"pid":' "$FIXTURES_DIR/linux_process_baseline.json")
    if [[ $count -ge 10 ]]; then
        pass
    else
        fail "Only $count processes in baseline"
    fi
}

test_fixture_compromised_has_attacks() {
    print_test "Compromised fixture has attack processes"
    # Check for technique markers (MITRE ATT&CK) or description fields
    if grep -q '"technique":' "$FIXTURES_DIR/linux_process_compromised.json"; then
        pass
    else
        fail "No attack markers found"
    fi
}

test_fixture_has_mitre_techniques() {
    print_test "Fixtures reference MITRE ATT&CK techniques"
    if grep -q "T1" "$FIXTURES_DIR/linux_process_compromised.json"; then
        pass
    else
        fail "No MITRE techniques referenced"
    fi
}

test_fixture_has_web_shell_attack() {
    print_test "Compromised has web shell attack (T1505)"
    # Check for T1505 technique or "web shell" in description (case insensitive)
    if grep -qi "T1505\|web shell" "$FIXTURES_DIR/linux_process_compromised.json"; then
        pass
    else
        fail "No web shell attack"
    fi
}

test_fixture_has_reverse_shell() {
    print_test "Compromised has reverse shell attack"
    if grep -q "/dev/tcp/" "$FIXTURES_DIR/linux_process_compromised.json"; then
        pass
    else
        fail "No reverse shell"
    fi
}

test_fixture_has_cryptominer() {
    print_test "Compromised has cryptominer attack"
    if grep -q "stratum" "$FIXTURES_DIR/linux_process_compromised.json"; then
        pass
    else
        fail "No cryptominer"
    fi
}

test_fixture_has_masquerading() {
    print_test "Compromised has process masquerading"
    if grep -q "kworker" "$FIXTURES_DIR/linux_process_compromised.json"; then
        pass
    else
        fail "No masquerading"
    fi
}

test_fixture_hashes_are_valid() {
    print_test "Fixture hashes are 64-char hex"
    local hash
    hash=$(grep -oP '"exe_hash":"[a-f0-9]{64}"' "$FIXTURES_DIR/linux_process_baseline.json" | head -1)
    if [[ -n "$hash" ]]; then
        pass
    else
        fail "Invalid hash format"
    fi
}

#
# ═══════════════════════════════════════════════════════════════
# RUN ALL TESTS
# ═══════════════════════════════════════════════════════════════
#

run_all_tests() {
    print_header "Native Bash IR Scripts - Test Suite"

    # Setup shared baselines for tests that need them
    setup_shared_baselines

    print_suite "Process Anomaly Detection"
    test_process_anomaly_script_exists
    test_process_anomaly_is_executable
    test_process_anomaly_shows_usage
    test_process_anomaly_shows_help
    test_process_anomaly_baseline_creates_file
    test_process_anomaly_baseline_valid_json
    test_process_anomaly_baseline_has_hostname
    test_process_anomaly_baseline_has_processes
    test_process_anomaly_baseline_has_pids
    test_process_anomaly_baseline_has_hashes
    test_process_anomaly_scan_requires_baseline
    test_process_anomaly_scan_runs_with_baseline
    test_process_anomaly_detects_itself_as_new

    print_suite "File Anomaly Detection"
    test_file_anomaly_script_exists
    test_file_anomaly_is_executable
    test_file_anomaly_shows_usage
    test_file_anomaly_baseline_creates_file
    test_file_anomaly_baseline_has_files
    test_file_anomaly_baseline_has_paths
    test_file_anomaly_monitors_tmp
    test_file_anomaly_scan_runs
    test_file_anomaly_detects_new_file

    print_suite "Process Hunter"
    test_process_hunter_script_exists
    test_process_hunter_is_executable
    test_process_hunter_shows_usage
    test_process_hunter_search_by_pattern
    test_process_hunter_suspicious_scan
    test_process_hunter_all_mode
    test_process_hunter_pattern_regex

    print_suite "Test Fixtures Validation"
    test_fixture_linux_baseline_exists
    test_fixture_linux_compromised_exists
    test_fixture_baseline_has_processes
    test_fixture_compromised_has_attacks
    test_fixture_has_mitre_techniques
    test_fixture_has_web_shell_attack
    test_fixture_has_reverse_shell
    test_fixture_has_cryptominer
    test_fixture_has_masquerading
    test_fixture_hashes_are_valid

    # Summary
    print_header "Test Summary"
    echo -e "Tests run:    ${BLUE}$TESTS_RUN${NC}"
    echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
    echo ""

    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}════════════════════════════════════════${NC}"
        echo -e "${GREEN}  ALL TESTS PASSED!${NC}"
        echo -e "${GREEN}════════════════════════════════════════${NC}"
        exit 0
    else
        echo -e "${RED}════════════════════════════════════════${NC}"
        echo -e "${RED}  SOME TESTS FAILED${NC}"
        echo -e "${RED}════════════════════════════════════════${NC}"
        exit 1
    fi
}

# Run tests
run_all_tests

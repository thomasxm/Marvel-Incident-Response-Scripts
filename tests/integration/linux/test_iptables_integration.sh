#!/bin/bash
#
# Integration Tests for iptables Network Isolation Script
#
# These tests verify that the network_isolate_iptables.sh script
# correctly applies firewall rules to the system.
#
# WARNING: These tests modify system firewall rules. Run only on test systems.
# REQUIRES: Root privileges
#
# Usage: sudo ./test_iptables_integration.sh
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Script location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PATH="${SCRIPT_DIR}/../../../network_isolation/linux/network_isolate_iptables.sh"

# Test IP/Port values (non-routable for safety)
TEST_IP="203.0.113.1"  # TEST-NET-3 (RFC 5737)
TEST_IP2="203.0.113.2"
TEST_IP_CIDR="203.0.113.0/24"
TEST_PORT="19999"
TEST_PORT2="19998"

# =============================================================================
# Helper Functions
# =============================================================================

log_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
}

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
    ((TESTS_SKIPPED++))
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}ERROR: This script must be run as root${NC}"
        exit 1
    fi
}

# Check if iptables is available
check_iptables() {
    if ! command -v iptables &> /dev/null; then
        echo -e "${RED}ERROR: iptables not found${NC}"
        exit 1
    fi
}

# Check if script exists
check_script() {
    if [[ ! -f "$SCRIPT_PATH" ]]; then
        echo -e "${RED}ERROR: Script not found at $SCRIPT_PATH${NC}"
        exit 1
    fi
}

# Save current iptables rules for restoration
save_rules() {
    log_info "Saving current iptables rules..."
    SAVED_RULES=$(mktemp)
    iptables-save > "$SAVED_RULES"
}

# Restore original rules
restore_rules() {
    log_info "Restoring original iptables rules..."
    if [[ -f "$SAVED_RULES" ]]; then
        iptables-restore < "$SAVED_RULES"
        rm -f "$SAVED_RULES"
    fi
}

# Clean up IR-created rules
cleanup_ir_rules() {
    log_info "Cleaning up IR-created rules..."
    # Remove rules with "IR_" comments
    iptables -S INPUT 2>/dev/null | grep -E 'IR_|test_' | while read -r rule; do
        # Convert -A to -D for deletion
        delete_rule=$(echo "$rule" | sed 's/^-A/-D/')
        iptables $delete_rule 2>/dev/null || true
    done
    iptables -S OUTPUT 2>/dev/null | grep -E 'IR_|test_' | while read -r rule; do
        delete_rule=$(echo "$rule" | sed 's/^-A/-D/')
        iptables $delete_rule 2>/dev/null || true
    done
}

# Check if a rule exists in iptables
rule_exists() {
    local chain="$1"
    local pattern="$2"
    iptables -S "$chain" 2>/dev/null | grep -q "$pattern"
}

# =============================================================================
# Test Cases
# =============================================================================

test_block_port_inbound() {
    log_info "Test: Block inbound port via CLI"

    # Run script with CLI flag
    "$SCRIPT_PATH" --block-port-in "$TEST_PORT" 2>/dev/null

    # Verify rule exists
    if rule_exists "INPUT" "dport $TEST_PORT.*DROP"; then
        log_pass "Block inbound port - rule applied correctly"
    else
        log_fail "Block inbound port - rule not found"
    fi

    # Cleanup
    cleanup_ir_rules
}

test_block_port_outbound() {
    log_info "Test: Block outbound port via CLI"

    "$SCRIPT_PATH" --block-port-out "$TEST_PORT" 2>/dev/null

    if rule_exists "OUTPUT" "dport $TEST_PORT.*DROP"; then
        log_pass "Block outbound port - rule applied correctly"
    else
        log_fail "Block outbound port - rule not found"
    fi

    cleanup_ir_rules
}

test_allow_port_from_ip() {
    log_info "Test: Allow port from specific IP"

    "$SCRIPT_PATH" --allow-port-from "$TEST_PORT" "$TEST_IP" 2>/dev/null

    # Should have ACCEPT rule for specific IP
    if rule_exists "INPUT" "tcp.*$TEST_IP.*dport $TEST_PORT.*ACCEPT"; then
        log_pass "Allow port from IP - TCP rule applied"
    else
        log_fail "Allow port from IP - TCP rule not found"
    fi

    cleanup_ir_rules
}

test_block_port_except_from_ips() {
    log_info "Test: Block port except from whitelisted IPs"

    "$SCRIPT_PATH" --block-port-except-from "$TEST_PORT" "$TEST_IP,$TEST_IP2" 2>/dev/null

    # Should have ACCEPT rules for whitelisted IPs
    local accept1=$(rule_exists "INPUT" "$TEST_IP.*dport $TEST_PORT.*ACCEPT" && echo "yes")
    local accept2=$(rule_exists "INPUT" "$TEST_IP2.*dport $TEST_PORT.*ACCEPT" && echo "yes")
    # Should have DROP rule for all others
    local drop=$(rule_exists "INPUT" "dport $TEST_PORT.*DROP" && echo "yes")

    if [[ "$accept1" == "yes" && "$accept2" == "yes" && "$drop" == "yes" ]]; then
        log_pass "Block port except from IPs - whitelist rules applied correctly"
    else
        log_fail "Block port except from IPs - missing rules (accept1=$accept1, accept2=$accept2, drop=$drop)"
    fi

    cleanup_ir_rules
}

test_allow_port_to_ip() {
    log_info "Test: Allow outbound port to specific IP"

    "$SCRIPT_PATH" --allow-port-to "$TEST_PORT" "$TEST_IP" 2>/dev/null

    if rule_exists "OUTPUT" "tcp.*$TEST_IP.*dport $TEST_PORT.*ACCEPT"; then
        log_pass "Allow port to IP - rule applied correctly"
    else
        log_fail "Allow port to IP - rule not found"
    fi

    cleanup_ir_rules
}

test_block_port_except_to_ips() {
    log_info "Test: Block outbound port except to whitelisted IPs"

    "$SCRIPT_PATH" --block-port-except-to "$TEST_PORT" "$TEST_IP,$TEST_IP2" 2>/dev/null

    local accept1=$(rule_exists "OUTPUT" "$TEST_IP.*dport $TEST_PORT.*ACCEPT" && echo "yes")
    local accept2=$(rule_exists "OUTPUT" "$TEST_IP2.*dport $TEST_PORT.*ACCEPT" && echo "yes")
    local drop=$(rule_exists "OUTPUT" "dport $TEST_PORT.*DROP" && echo "yes")

    if [[ "$accept1" == "yes" && "$accept2" == "yes" && "$drop" == "yes" ]]; then
        log_pass "Block port except to IPs - whitelist rules applied correctly"
    else
        log_fail "Block port except to IPs - missing rules"
    fi

    cleanup_ir_rules
}

test_restrict_dns() {
    log_info "Test: Restrict outbound DNS to specific resolvers"

    "$SCRIPT_PATH" --restrict-dns "$TEST_IP,$TEST_IP2" 2>/dev/null

    # Check for UDP DNS rules
    local accept_udp1=$(rule_exists "OUTPUT" "udp.*$TEST_IP.*dport 53.*ACCEPT" && echo "yes")
    local accept_udp2=$(rule_exists "OUTPUT" "udp.*$TEST_IP2.*dport 53.*ACCEPT" && echo "yes")
    local drop_udp=$(rule_exists "OUTPUT" "udp.*dport 53.*DROP" && echo "yes")

    # Check for TCP DNS rules
    local accept_tcp1=$(rule_exists "OUTPUT" "tcp.*$TEST_IP.*dport 53.*ACCEPT" && echo "yes")
    local accept_tcp2=$(rule_exists "OUTPUT" "tcp.*$TEST_IP2.*dport 53.*ACCEPT" && echo "yes")
    local drop_tcp=$(rule_exists "OUTPUT" "tcp.*dport 53.*DROP" && echo "yes")

    if [[ "$accept_udp1" == "yes" && "$accept_udp2" == "yes" && "$drop_udp" == "yes" ]]; then
        log_pass "Restrict DNS - UDP rules applied correctly"
    else
        log_fail "Restrict DNS - UDP rules missing"
    fi

    if [[ "$accept_tcp1" == "yes" && "$accept_tcp2" == "yes" && "$drop_tcp" == "yes" ]]; then
        log_pass "Restrict DNS - TCP rules applied correctly"
    else
        log_fail "Restrict DNS - TCP rules missing"
    fi

    cleanup_ir_rules
}

test_restrict_smtp() {
    log_info "Test: Restrict outbound SMTP to specific servers"

    "$SCRIPT_PATH" --restrict-smtp "$TEST_IP" 2>/dev/null

    # Check SMTP port 25
    local accept_25=$(rule_exists "OUTPUT" "tcp.*$TEST_IP.*dport 25.*ACCEPT" && echo "yes")
    local drop_25=$(rule_exists "OUTPUT" "tcp.*dport 25.*DROP" && echo "yes")

    # Check SMTP port 465
    local accept_465=$(rule_exists "OUTPUT" "tcp.*$TEST_IP.*dport 465.*ACCEPT" && echo "yes")
    local drop_465=$(rule_exists "OUTPUT" "tcp.*dport 465.*DROP" && echo "yes")

    # Check SMTP port 587
    local accept_587=$(rule_exists "OUTPUT" "tcp.*$TEST_IP.*dport 587.*ACCEPT" && echo "yes")
    local drop_587=$(rule_exists "OUTPUT" "tcp.*dport 587.*DROP" && echo "yes")

    if [[ "$accept_25" == "yes" && "$drop_25" == "yes" ]]; then
        log_pass "Restrict SMTP - port 25 rules applied"
    else
        log_fail "Restrict SMTP - port 25 rules missing"
    fi

    if [[ "$accept_465" == "yes" && "$drop_465" == "yes" ]]; then
        log_pass "Restrict SMTP - port 465 rules applied"
    else
        log_fail "Restrict SMTP - port 465 rules missing"
    fi

    if [[ "$accept_587" == "yes" && "$drop_587" == "yes" ]]; then
        log_pass "Restrict SMTP - port 587 rules applied"
    else
        log_fail "Restrict SMTP - port 587 rules missing"
    fi

    cleanup_ir_rules
}

test_enable_logging() {
    log_info "Test: Enable firewall drop logging"

    "$SCRIPT_PATH" --enable-logging 2>/dev/null

    # Check for LOG rules
    if rule_exists "INPUT" "LOG.*IPTABLES_DROPPED_IN" || rule_exists "INPUT" "LOG"; then
        log_pass "Enable logging - INPUT LOG rule applied"
    else
        log_fail "Enable logging - INPUT LOG rule not found"
    fi

    if rule_exists "OUTPUT" "LOG.*IPTABLES_DROPPED_OUT" || rule_exists "OUTPUT" "LOG"; then
        log_pass "Enable logging - OUTPUT LOG rule applied"
    else
        log_fail "Enable logging - OUTPUT LOG rule not found"
    fi

    cleanup_ir_rules
}

test_disable_logging() {
    log_info "Test: Disable firewall drop logging"

    # First enable, then disable
    "$SCRIPT_PATH" --enable-logging 2>/dev/null
    "$SCRIPT_PATH" --disable-logging 2>/dev/null

    # LOG rules should be removed
    if ! rule_exists "INPUT" "LOG.*IPTABLES_DROPPED_IN"; then
        log_pass "Disable logging - INPUT LOG rule removed"
    else
        log_fail "Disable logging - INPUT LOG rule still present"
    fi

    cleanup_ir_rules
}

test_rule_ordering() {
    log_info "Test: Rule ordering (ACCEPT before DROP for whitelists)"

    "$SCRIPT_PATH" --block-port-except-from "$TEST_PORT" "$TEST_IP" 2>/dev/null

    # Get rule positions
    local accept_line=$(iptables -S INPUT | grep -n "$TEST_IP.*dport $TEST_PORT.*ACCEPT" | head -1 | cut -d: -f1)
    local drop_line=$(iptables -S INPUT | grep -n "dport $TEST_PORT.*DROP" | head -1 | cut -d: -f1)

    if [[ -n "$accept_line" && -n "$drop_line" && "$accept_line" -lt "$drop_line" ]]; then
        log_pass "Rule ordering - ACCEPT comes before DROP"
    else
        log_fail "Rule ordering - ACCEPT should come before DROP (accept=$accept_line, drop=$drop_line)"
    fi

    cleanup_ir_rules
}

test_cidr_notation() {
    log_info "Test: CIDR notation support"

    "$SCRIPT_PATH" --allow-port-from "$TEST_PORT" "$TEST_IP_CIDR" 2>/dev/null

    if rule_exists "INPUT" "203.0.113.0/24.*dport $TEST_PORT.*ACCEPT"; then
        log_pass "CIDR notation - rule with /24 applied correctly"
    else
        log_fail "CIDR notation - rule not found"
    fi

    cleanup_ir_rules
}

test_invalid_port_rejected() {
    log_info "Test: Invalid port number rejected"

    # Should fail with invalid port
    if ! "$SCRIPT_PATH" --block-port-in "99999" 2>/dev/null; then
        log_pass "Invalid port - rejected correctly"
    else
        log_fail "Invalid port - should have been rejected"
    fi

    cleanup_ir_rules
}

test_invalid_ip_rejected() {
    log_info "Test: Invalid IP address rejected"

    if ! "$SCRIPT_PATH" --allow-port-from "$TEST_PORT" "invalid.ip" 2>/dev/null; then
        log_pass "Invalid IP - rejected correctly"
    else
        log_fail "Invalid IP - should have been rejected"
    fi

    cleanup_ir_rules
}

test_enterprise_hardening_scenario() {
    log_info "Test: Enterprise hardening scenario (SSH + DNS + SMB/RDP)"

    # Restrict SSH to management IP
    "$SCRIPT_PATH" --block-port-except-from 22 "$TEST_IP" 2>/dev/null

    # Restrict DNS
    "$SCRIPT_PATH" --restrict-dns "$TEST_IP,$TEST_IP2" 2>/dev/null

    # Block outbound SMB and RDP
    "$SCRIPT_PATH" --block-port-out 445 2>/dev/null
    "$SCRIPT_PATH" --block-port-out 3389 2>/dev/null

    # Verify all rules
    local ssh_ok=$(rule_exists "INPUT" "dport 22.*ACCEPT" && rule_exists "INPUT" "dport 22.*DROP" && echo "yes")
    local dns_ok=$(rule_exists "OUTPUT" "dport 53.*ACCEPT" && rule_exists "OUTPUT" "dport 53.*DROP" && echo "yes")
    local smb_ok=$(rule_exists "OUTPUT" "dport 445.*DROP" && echo "yes")
    local rdp_ok=$(rule_exists "OUTPUT" "dport 3389.*DROP" && echo "yes")

    if [[ "$ssh_ok" == "yes" && "$dns_ok" == "yes" && "$smb_ok" == "yes" && "$rdp_ok" == "yes" ]]; then
        log_pass "Enterprise hardening - all rules applied correctly"
    else
        log_fail "Enterprise hardening - missing rules (ssh=$ssh_ok, dns=$dns_ok, smb=$smb_ok, rdp=$rdp_ok)"
    fi

    cleanup_ir_rules
}

# =============================================================================
# Main
# =============================================================================

main() {
    echo "========================================"
    echo " iptables Integration Tests"
    echo "========================================"
    echo ""

    # Pre-flight checks
    check_root
    check_iptables
    check_script

    # Save current rules
    save_rules

    # Trap to restore rules on exit
    trap restore_rules EXIT

    # Clean up any existing IR rules
    cleanup_ir_rules

    echo ""
    echo "Running tests..."
    echo ""

    # Run all tests
    test_block_port_inbound
    test_block_port_outbound
    test_allow_port_from_ip
    test_block_port_except_from_ips
    test_allow_port_to_ip
    test_block_port_except_to_ips
    test_restrict_dns
    test_restrict_smtp
    test_enable_logging
    test_disable_logging
    test_rule_ordering
    test_cidr_notation
    test_invalid_port_rejected
    test_invalid_ip_rejected
    test_enterprise_hardening_scenario

    echo ""
    echo "========================================"
    echo " Test Results"
    echo "========================================"
    echo -e "${GREEN}Passed:${NC} $TESTS_PASSED"
    echo -e "${RED}Failed:${NC} $TESTS_FAILED"
    echo -e "${YELLOW}Skipped:${NC} $TESTS_SKIPPED"
    echo ""

    if [[ $TESTS_FAILED -gt 0 ]]; then
        exit 1
    fi
    exit 0
}

main "$@"

#!/bin/bash
#
# Integration Tests for UFW Network Isolation Script
#
# These tests verify that the network_isolate_ufw.sh script
# correctly applies firewall rules to the system via UFW.
#
# WARNING: These tests modify system firewall rules. Run only on test systems.
# REQUIRES: Root privileges, UFW installed and enabled
#
# Usage: sudo ./test_ufw_integration.sh
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
SCRIPT_PATH="${SCRIPT_DIR}/../../../network_isolation/linux/network_isolate_ufw.sh"

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

# Check if UFW is available
check_ufw() {
    if ! command -v ufw &> /dev/null; then
        echo -e "${RED}ERROR: UFW not found. Install with: apt install ufw${NC}"
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

# Save UFW status for restoration
save_ufw_state() {
    log_info "Saving UFW state..."
    SAVED_UFW_STATUS=$(ufw status verbose)
    SAVED_UFW_RULES=$(mktemp)
    # Export rules by copying user rules file if it exists
    if [[ -f /etc/ufw/user.rules ]]; then
        cp /etc/ufw/user.rules "$SAVED_UFW_RULES"
    fi
}

# Restore original UFW state
restore_ufw_state() {
    log_info "Restoring UFW state..."
    # Delete all IR-created rules first
    cleanup_ir_rules

    if [[ -f "$SAVED_UFW_RULES" && -f /etc/ufw/user.rules ]]; then
        cp "$SAVED_UFW_RULES" /etc/ufw/user.rules
        ufw reload 2>/dev/null || true
        rm -f "$SAVED_UFW_RULES"
    fi
}

# Clean up IR-created rules
cleanup_ir_rules() {
    log_info "Cleaning up test rules..."
    # UFW rules are deleted by rule number, so we need to find and delete
    # Delete rules containing test IPs/ports
    while ufw status numbered 2>/dev/null | grep -q "$TEST_IP\|$TEST_IP2\|$TEST_PORT"; do
        local rule_num=$(ufw status numbered 2>/dev/null | grep -E "$TEST_IP|$TEST_IP2|$TEST_PORT" | head -1 | grep -oP '\[\s*\K\d+')
        if [[ -n "$rule_num" ]]; then
            echo "y" | ufw delete "$rule_num" 2>/dev/null || break
        else
            break
        fi
    done

    # Also delete any rules for test ports 19999, 19998
    while ufw status numbered 2>/dev/null | grep -qE "199(99|98)"; do
        local rule_num=$(ufw status numbered 2>/dev/null | grep -E "199(99|98)" | head -1 | grep -oP '\[\s*\K\d+')
        if [[ -n "$rule_num" ]]; then
            echo "y" | ufw delete "$rule_num" 2>/dev/null || break
        else
            break
        fi
    done

    # Delete DNS/SMTP restriction rules
    while ufw status numbered 2>/dev/null | grep -qE " (53|25|465|587)/"; do
        local rule_num=$(ufw status numbered 2>/dev/null | grep -E " (53|25|465|587)/" | head -1 | grep -oP '\[\s*\K\d+')
        if [[ -n "$rule_num" ]]; then
            echo "y" | ufw delete "$rule_num" 2>/dev/null || break
        else
            break
        fi
    done
}

# Check if a UFW rule exists
rule_exists() {
    local pattern="$1"
    ufw status 2>/dev/null | grep -qi "$pattern"
}

# Get UFW status output
get_ufw_rules() {
    ufw status verbose 2>/dev/null
}

# =============================================================================
# Test Cases
# =============================================================================

test_block_port_inbound() {
    log_info "Test: Block inbound port via CLI"

    "$SCRIPT_PATH" --block-port-in "$TEST_PORT" 2>/dev/null

    if rule_exists "$TEST_PORT.*DENY IN"; then
        log_pass "Block inbound port - rule applied correctly"
    else
        log_fail "Block inbound port - rule not found"
    fi

    cleanup_ir_rules
}

test_block_port_outbound() {
    log_info "Test: Block outbound port via CLI"

    "$SCRIPT_PATH" --block-port-out "$TEST_PORT" 2>/dev/null

    if rule_exists "$TEST_PORT.*DENY OUT"; then
        log_pass "Block outbound port - rule applied correctly"
    else
        log_fail "Block outbound port - rule not found"
    fi

    cleanup_ir_rules
}

test_allow_port_from_ip() {
    log_info "Test: Allow port from specific IP"

    "$SCRIPT_PATH" --allow-port-from "$TEST_PORT" "$TEST_IP" 2>/dev/null

    # UFW syntax: "ALLOW IN" from specific IP to port
    if rule_exists "$TEST_PORT.*ALLOW IN.*$TEST_IP"; then
        log_pass "Allow port from IP - rule applied correctly"
    else
        log_fail "Allow port from IP - rule not found"
    fi

    cleanup_ir_rules
}

test_block_port_except_from_ips() {
    log_info "Test: Block port except from whitelisted IPs"

    "$SCRIPT_PATH" --block-port-except-from "$TEST_PORT" "$TEST_IP,$TEST_IP2" 2>/dev/null

    # Should have ALLOW rules for whitelisted IPs
    local accept1=$(rule_exists "$TEST_PORT.*ALLOW IN.*$TEST_IP" && echo "yes")
    local accept2=$(rule_exists "$TEST_PORT.*ALLOW IN.*$TEST_IP2" && echo "yes")
    # Should have DENY rule for all others
    local deny=$(rule_exists "$TEST_PORT.*DENY IN" && echo "yes")

    if [[ "$accept1" == "yes" && "$accept2" == "yes" && "$deny" == "yes" ]]; then
        log_pass "Block port except from IPs - whitelist rules applied correctly"
    else
        log_fail "Block port except from IPs - missing rules (accept1=$accept1, accept2=$accept2, deny=$deny)"
    fi

    cleanup_ir_rules
}

test_allow_port_to_ip() {
    log_info "Test: Allow outbound port to specific IP"

    "$SCRIPT_PATH" --allow-port-to "$TEST_PORT" "$TEST_IP" 2>/dev/null

    if rule_exists "$TEST_PORT.*ALLOW OUT.*$TEST_IP"; then
        log_pass "Allow port to IP - rule applied correctly"
    else
        log_fail "Allow port to IP - rule not found"
    fi

    cleanup_ir_rules
}

test_block_port_except_to_ips() {
    log_info "Test: Block outbound port except to whitelisted IPs"

    "$SCRIPT_PATH" --block-port-except-to "$TEST_PORT" "$TEST_IP,$TEST_IP2" 2>/dev/null

    local accept1=$(rule_exists "$TEST_PORT.*ALLOW OUT.*$TEST_IP" && echo "yes")
    local accept2=$(rule_exists "$TEST_PORT.*ALLOW OUT.*$TEST_IP2" && echo "yes")
    local deny=$(rule_exists "$TEST_PORT.*DENY OUT" && echo "yes")

    if [[ "$accept1" == "yes" && "$accept2" == "yes" && "$deny" == "yes" ]]; then
        log_pass "Block port except to IPs - whitelist rules applied correctly"
    else
        log_fail "Block port except to IPs - missing rules"
    fi

    cleanup_ir_rules
}

test_restrict_dns() {
    log_info "Test: Restrict outbound DNS to specific resolvers"

    "$SCRIPT_PATH" --restrict-dns "$TEST_IP,$TEST_IP2" 2>/dev/null

    # Check for DNS allow rules (port 53)
    local accept1=$(rule_exists "53.*ALLOW OUT.*$TEST_IP" && echo "yes")
    local accept2=$(rule_exists "53.*ALLOW OUT.*$TEST_IP2" && echo "yes")
    local deny=$(rule_exists "53.*DENY OUT" && echo "yes")

    if [[ "$accept1" == "yes" && "$accept2" == "yes" && "$deny" == "yes" ]]; then
        log_pass "Restrict DNS - rules applied correctly"
    else
        log_fail "Restrict DNS - missing rules (accept1=$accept1, accept2=$accept2, deny=$deny)"
    fi

    cleanup_ir_rules
}

test_restrict_smtp() {
    log_info "Test: Restrict outbound SMTP to specific servers"

    "$SCRIPT_PATH" --restrict-smtp "$TEST_IP" 2>/dev/null

    # Check SMTP port rules (25, 465, 587)
    local accept=$(ufw status 2>/dev/null | grep -c "$TEST_IP" || echo "0")
    local deny=$(ufw status 2>/dev/null | grep -cE "2[5]|465|587.*DENY OUT" || echo "0")

    if [[ "$accept" -gt 0 && "$deny" -gt 0 ]]; then
        log_pass "Restrict SMTP - rules applied"
    else
        log_fail "Restrict SMTP - rules missing (accept_count=$accept, deny_count=$deny)"
    fi

    cleanup_ir_rules
}

test_enable_logging() {
    log_info "Test: Enable firewall logging"

    "$SCRIPT_PATH" --enable-logging 2>/dev/null

    # Check UFW logging status
    if ufw status verbose 2>/dev/null | grep -qi "Logging: on"; then
        log_pass "Enable logging - UFW logging enabled"
    else
        log_fail "Enable logging - UFW logging not enabled"
    fi

    # Restore default
    ufw logging off 2>/dev/null || true
}

test_disable_logging() {
    log_info "Test: Disable firewall logging"

    # First enable, then disable
    "$SCRIPT_PATH" --enable-logging 2>/dev/null
    "$SCRIPT_PATH" --disable-logging 2>/dev/null

    if ufw status verbose 2>/dev/null | grep -qi "Logging: off"; then
        log_pass "Disable logging - UFW logging disabled"
    else
        log_fail "Disable logging - UFW logging still on"
    fi
}

test_cidr_notation() {
    log_info "Test: CIDR notation support"

    "$SCRIPT_PATH" --allow-port-from "$TEST_PORT" "$TEST_IP_CIDR" 2>/dev/null

    if rule_exists "203.0.113.0/24"; then
        log_pass "CIDR notation - rule with /24 applied correctly"
    else
        log_fail "CIDR notation - rule not found"
    fi

    cleanup_ir_rules
}

test_invalid_port_rejected() {
    log_info "Test: Invalid port number rejected"

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

test_rule_ordering() {
    log_info "Test: Rule ordering (ALLOW before DENY for whitelists)"

    "$SCRIPT_PATH" --block-port-except-from "$TEST_PORT" "$TEST_IP" 2>/dev/null

    # In UFW numbered output, ALLOW should come before DENY for same port
    local rules=$(ufw status numbered 2>/dev/null | grep "$TEST_PORT")
    local allow_line=$(echo "$rules" | grep -n "ALLOW" | head -1 | cut -d: -f1)
    local deny_line=$(echo "$rules" | grep -n "DENY" | head -1 | cut -d: -f1)

    if [[ -n "$allow_line" && -n "$deny_line" && "$allow_line" -lt "$deny_line" ]]; then
        log_pass "Rule ordering - ALLOW comes before DENY"
    else
        log_fail "Rule ordering - ALLOW should come before DENY"
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

    # Verify all rules exist
    local ssh_allow=$(rule_exists "22.*ALLOW.*$TEST_IP" && echo "yes")
    local ssh_deny=$(rule_exists "22.*DENY" && echo "yes")
    local dns_rule=$(rule_exists "53" && echo "yes")
    local smb_deny=$(rule_exists "445.*DENY OUT" && echo "yes")
    local rdp_deny=$(rule_exists "3389.*DENY OUT" && echo "yes")

    if [[ "$ssh_allow" == "yes" && "$dns_rule" == "yes" && "$smb_deny" == "yes" && "$rdp_deny" == "yes" ]]; then
        log_pass "Enterprise hardening - all rules applied correctly"
    else
        log_fail "Enterprise hardening - missing rules"
    fi

    cleanup_ir_rules
}

# =============================================================================
# Main
# =============================================================================

main() {
    echo "========================================"
    echo " UFW Integration Tests"
    echo "========================================"
    echo ""

    # Pre-flight checks
    check_root
    check_ufw
    check_script

    # Check if UFW is enabled
    if ! ufw status 2>/dev/null | grep -q "Status: active"; then
        log_info "UFW is not active. Enabling for tests..."
        echo "y" | ufw enable 2>/dev/null || {
            echo -e "${RED}ERROR: Could not enable UFW${NC}"
            exit 1
        }
        UFW_WAS_DISABLED=true
    fi

    # Save current state
    save_ufw_state

    # Trap to restore state on exit
    trap 'restore_ufw_state; if [[ "$UFW_WAS_DISABLED" == "true" ]]; then ufw disable 2>/dev/null || true; fi' EXIT

    # Clean up any existing test rules
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
    test_cidr_notation
    test_invalid_port_rejected
    test_invalid_ip_rejected
    test_rule_ordering
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

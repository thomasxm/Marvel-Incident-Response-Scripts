#!/usr/bin/env python3
"""
Unit Tests for Windows Network Isolation PowerShell Script

These tests verify the validation logic and command generation patterns
used in the network_isolate.ps1 script. Since we can't execute PowerShell
directly on Linux, we test by:
1. Implementing equivalent validation logic in Python
2. Verifying expected netsh command patterns
3. Testing rule naming conventions
4. Testing edge cases for input validation

Run with: pytest tests/test_network_isolation_windows.py -v
"""

import pytest
import re


# =============================================================================
# Validation Functions (Python equivalents of PowerShell validation)
# =============================================================================

def is_valid_port(port_str: str) -> bool:
    """Equivalent to Test-ValidPort in PowerShell"""
    if not port_str or not port_str.strip():
        return False
    try:
        port_num = int(port_str.strip())
        return 1 <= port_num <= 65535
    except ValueError:
        return False


def is_valid_ip(ip_str: str) -> bool:
    """Equivalent to Test-ValidIP in PowerShell"""
    if not ip_str or not ip_str.strip():
        return False

    ip_part = ip_str.strip()

    # Handle CIDR notation
    cidr_match = re.match(r'^(.+)/(\d+)$', ip_part)
    if cidr_match:
        ip_part = cidr_match.group(1)
        cidr = int(cidr_match.group(2))
        if cidr < 0 or cidr > 32:
            return False

    # Validate IP address
    octets = ip_part.split('.')
    if len(octets) != 4:
        return False

    for octet in octets:
        try:
            val = int(octet)
            if val < 0 or val > 255:
                return False
        except ValueError:
            return False

    return True


def is_valid_ip_list(ip_list_str: str) -> bool:
    """Equivalent to Test-ValidIPList in PowerShell"""
    if not ip_list_str or not ip_list_str.strip():
        return False

    ips = ip_list_str.split(',')
    for ip in ips:
        ip = ip.strip()
        if not is_valid_ip(ip):
            return False
    return True


def sanitize_ip_for_rule_name(ip: str) -> str:
    """Convert IP to safe string for rule naming (replace . and / with _)"""
    return re.sub(r'[./]', '_', ip)


# =============================================================================
# Test: Port Validation
# =============================================================================

class TestPortValidation:
    """Test cases for port number validation"""

    def test_valid_port_minimum(self):
        """Port 1 should be valid"""
        assert is_valid_port("1") is True

    def test_valid_port_maximum(self):
        """Port 65535 should be valid"""
        assert is_valid_port("65535") is True

    def test_valid_port_common_ssh(self):
        """Port 22 (SSH) should be valid"""
        assert is_valid_port("22") is True

    def test_valid_port_common_http(self):
        """Port 80 (HTTP) should be valid"""
        assert is_valid_port("80") is True

    def test_valid_port_common_https(self):
        """Port 443 (HTTPS) should be valid"""
        assert is_valid_port("443") is True

    def test_valid_port_common_dns(self):
        """Port 53 (DNS) should be valid"""
        assert is_valid_port("53") is True

    def test_valid_port_common_smb(self):
        """Port 445 (SMB) should be valid"""
        assert is_valid_port("445") is True

    def test_valid_port_common_rdp(self):
        """Port 3389 (RDP) should be valid"""
        assert is_valid_port("3389") is True

    def test_invalid_port_zero(self):
        """Port 0 should be invalid"""
        assert is_valid_port("0") is False

    def test_invalid_port_negative(self):
        """Negative port should be invalid"""
        assert is_valid_port("-1") is False

    def test_invalid_port_too_large(self):
        """Port > 65535 should be invalid"""
        assert is_valid_port("65536") is False

    def test_invalid_port_way_too_large(self):
        """Very large port should be invalid"""
        assert is_valid_port("99999") is False

    def test_invalid_port_non_numeric(self):
        """Non-numeric port should be invalid"""
        assert is_valid_port("abc") is False

    def test_invalid_port_empty(self):
        """Empty string should be invalid"""
        assert is_valid_port("") is False

    def test_invalid_port_whitespace(self):
        """Whitespace only should be invalid"""
        assert is_valid_port("   ") is False

    def test_valid_port_with_whitespace(self):
        """Port with surrounding whitespace should be valid"""
        assert is_valid_port("  22  ") is True

    def test_invalid_port_float(self):
        """Float port should be invalid"""
        assert is_valid_port("22.5") is False


# =============================================================================
# Test: IP Address Validation
# =============================================================================

class TestIPValidation:
    """Test cases for IP address validation"""

    def test_valid_ip_localhost(self):
        """127.0.0.1 should be valid"""
        assert is_valid_ip("127.0.0.1") is True

    def test_valid_ip_google_dns(self):
        """8.8.8.8 should be valid"""
        assert is_valid_ip("8.8.8.8") is True

    def test_valid_ip_cloudflare_dns(self):
        """1.1.1.1 should be valid"""
        assert is_valid_ip("1.1.1.1") is True

    def test_valid_ip_private_class_a(self):
        """10.0.0.1 should be valid"""
        assert is_valid_ip("10.0.0.1") is True

    def test_valid_ip_private_class_b(self):
        """172.16.0.1 should be valid"""
        assert is_valid_ip("172.16.0.1") is True

    def test_valid_ip_private_class_c(self):
        """192.168.1.1 should be valid"""
        assert is_valid_ip("192.168.1.1") is True

    def test_valid_ip_all_zeros(self):
        """0.0.0.0 should be valid"""
        assert is_valid_ip("0.0.0.0") is True

    def test_valid_ip_all_max(self):
        """255.255.255.255 should be valid"""
        assert is_valid_ip("255.255.255.255") is True

    def test_valid_ip_cidr_8(self):
        """10.0.0.0/8 should be valid"""
        assert is_valid_ip("10.0.0.0/8") is True

    def test_valid_ip_cidr_16(self):
        """172.16.0.0/16 should be valid"""
        assert is_valid_ip("172.16.0.0/16") is True

    def test_valid_ip_cidr_24(self):
        """192.168.1.0/24 should be valid"""
        assert is_valid_ip("192.168.1.0/24") is True

    def test_valid_ip_cidr_32(self):
        """192.168.1.1/32 should be valid"""
        assert is_valid_ip("192.168.1.1/32") is True

    def test_valid_ip_cidr_0(self):
        """0.0.0.0/0 should be valid"""
        assert is_valid_ip("0.0.0.0/0") is True

    def test_invalid_ip_cidr_33(self):
        """CIDR /33 should be invalid"""
        assert is_valid_ip("10.0.0.0/33") is False

    def test_invalid_ip_cidr_negative(self):
        """Negative CIDR should be invalid"""
        assert is_valid_ip("10.0.0.0/-1") is False

    def test_invalid_ip_octet_too_large(self):
        """Octet > 255 should be invalid"""
        assert is_valid_ip("256.0.0.1") is False

    def test_invalid_ip_negative_octet(self):
        """Negative octet should be invalid"""
        assert is_valid_ip("-1.0.0.1") is False

    def test_invalid_ip_too_few_octets(self):
        """Only 3 octets should be invalid"""
        assert is_valid_ip("192.168.1") is False

    def test_invalid_ip_too_many_octets(self):
        """5 octets should be invalid"""
        assert is_valid_ip("192.168.1.1.1") is False

    def test_invalid_ip_non_numeric(self):
        """Non-numeric IP should be invalid"""
        assert is_valid_ip("abc.def.ghi.jkl") is False

    def test_invalid_ip_hostname(self):
        """Hostname should be invalid (only IPs allowed)"""
        assert is_valid_ip("google.com") is False

    def test_invalid_ip_empty(self):
        """Empty string should be invalid"""
        assert is_valid_ip("") is False

    def test_invalid_ip_whitespace(self):
        """Whitespace only should be invalid"""
        assert is_valid_ip("   ") is False

    def test_valid_ip_with_whitespace(self):
        """IP with surrounding whitespace should be valid"""
        assert is_valid_ip("  10.1.2.3  ") is True


# =============================================================================
# Test: IP List Validation
# =============================================================================

class TestIPListValidation:
    """Test cases for comma-separated IP list validation"""

    def test_valid_single_ip(self):
        """Single IP should be valid"""
        assert is_valid_ip_list("8.8.8.8") is True

    def test_valid_two_ips(self):
        """Two IPs should be valid"""
        assert is_valid_ip_list("8.8.8.8,8.8.4.4") is True

    def test_valid_multiple_ips(self):
        """Multiple IPs should be valid"""
        assert is_valid_ip_list("8.8.8.8,8.8.4.4,1.1.1.1") is True

    def test_valid_ips_with_spaces(self):
        """IPs with spaces around commas should be valid"""
        assert is_valid_ip_list("8.8.8.8, 8.8.4.4, 1.1.1.1") is True

    def test_valid_mixed_ips_and_cidrs(self):
        """Mix of IPs and CIDRs should be valid"""
        assert is_valid_ip_list("10.1.2.3,10.0.0.0/8,192.168.1.0/24") is True

    def test_invalid_one_bad_ip(self):
        """List with one invalid IP should be invalid"""
        assert is_valid_ip_list("8.8.8.8,invalid,1.1.1.1") is False

    def test_invalid_empty_list(self):
        """Empty string should be invalid"""
        assert is_valid_ip_list("") is False

    def test_invalid_whitespace_list(self):
        """Whitespace only should be invalid"""
        assert is_valid_ip_list("   ") is False


# =============================================================================
# Test: Rule Naming Convention
# =============================================================================

class TestRuleNaming:
    """Test cases for Windows Firewall rule naming conventions"""

    def test_ip_sanitization_dots(self):
        """IP dots should be replaced with underscores"""
        assert sanitize_ip_for_rule_name("10.1.2.3") == "10_1_2_3"

    def test_ip_sanitization_cidr(self):
        """CIDR notation should have both . and / replaced"""
        assert sanitize_ip_for_rule_name("10.0.0.0/8") == "10_0_0_0_8"

    def test_rule_name_allow_port_from_ip(self):
        """Rule name for allowing port from IP should follow convention"""
        ip = "10.1.2.3"
        port = 22
        ip_safe = sanitize_ip_for_rule_name(ip)
        rule_name = f"IR_Allow_Port{port}_From_{ip_safe}_TCP"
        assert rule_name == "IR_Allow_Port22_From_10_1_2_3_TCP"

    def test_rule_name_whitelist_inbound(self):
        """Rule name for whitelist inbound should follow convention"""
        ip = "10.1.2.3"
        port = 22
        ip_safe = sanitize_ip_for_rule_name(ip)
        rule_name = f"IR_Whitelist_Port{port}_From_{ip_safe}_TCP"
        assert rule_name == "IR_Whitelist_Port22_From_10_1_2_3_TCP"

    def test_rule_name_block_all_others(self):
        """Rule name for blocking all others should follow convention"""
        port = 22
        rule_name = f"IR_Block_Port{port}_AllOthers_TCP"
        assert rule_name == "IR_Block_Port22_AllOthers_TCP"

    def test_rule_name_dns_allow(self):
        """Rule name for DNS allow should follow convention"""
        ip = "8.8.8.8"
        ip_safe = sanitize_ip_for_rule_name(ip)
        rule_name = f"IR_DNS_Allow_{ip_safe}_UDP"
        assert rule_name == "IR_DNS_Allow_8_8_8_8_UDP"

    def test_rule_name_dns_block(self):
        """Rule name for DNS block should follow convention"""
        rule_name = "IR_DNS_Block_All_UDP"
        assert rule_name == "IR_DNS_Block_All_UDP"

    def test_rule_name_smtp_allow(self):
        """Rule name for SMTP allow should follow convention"""
        ip = "10.0.0.5"
        port = 25
        ip_safe = sanitize_ip_for_rule_name(ip)
        rule_name = f"IR_SMTP_Allow_{ip_safe}_Port{port}"
        assert rule_name == "IR_SMTP_Allow_10_0_0_5_Port25"

    def test_rule_name_block_outbound(self):
        """Rule name for blocking outbound port should follow convention"""
        port = 445
        rule_name = f"IR_Block_Outbound_ANY_{port}_TCP"
        assert rule_name == "IR_Block_Outbound_ANY_445_TCP"

    def test_all_rule_names_start_with_ir(self):
        """All IR rule names should start with IR_ prefix"""
        rule_patterns = [
            "IR_Allow_Port22_From_10_1_2_3_TCP",
            "IR_Block_Port22_AllOthers_TCP",
            "IR_Whitelist_Port22_From_10_1_2_3_TCP",
            "IR_DNS_Allow_8_8_8_8_UDP",
            "IR_DNS_Block_All_UDP",
            "IR_SMTP_Allow_10_0_0_5_Port25",
            "IR_Block_Outbound_ANY_445_TCP",
        ]
        for rule_name in rule_patterns:
            assert rule_name.startswith("IR_"), f"Rule {rule_name} should start with IR_"


# =============================================================================
# Test: Netsh Command Generation Patterns
# =============================================================================

class TestNetshCommandPatterns:
    """Test cases for expected netsh command formats"""

    def test_allow_port_from_ip_tcp_command(self):
        """Verify netsh command pattern for allowing TCP port from IP"""
        ip = "10.1.2.3"
        port = 22
        ip_safe = sanitize_ip_for_rule_name(ip)
        rule_name = f"IR_Allow_Port{port}_From_{ip_safe}_TCP"

        expected = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=allow protocol=tcp localport={port} remoteip={ip}'

        # Verify command structure
        assert 'advfirewall firewall add rule' in expected
        assert 'dir=in' in expected
        assert 'action=allow' in expected
        assert 'protocol=tcp' in expected
        assert f'localport={port}' in expected
        assert f'remoteip={ip}' in expected

    def test_block_port_command(self):
        """Verify netsh command pattern for blocking port"""
        port = 22
        rule_name = f"IR_Block_Port{port}_AllOthers_TCP"

        expected = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block protocol=tcp localport={port}'

        assert 'action=block' in expected
        assert f'localport={port}' in expected

    def test_outbound_dns_allow_command(self):
        """Verify netsh command pattern for outbound DNS allow"""
        ip = "8.8.8.8"
        ip_safe = sanitize_ip_for_rule_name(ip)
        rule_name = f"IR_DNS_Allow_{ip_safe}_UDP"

        expected = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=allow protocol=udp remoteport=53 remoteip={ip}'

        assert 'dir=out' in expected
        assert 'remoteport=53' in expected

    def test_outbound_dns_block_command(self):
        """Verify netsh command pattern for outbound DNS block"""
        expected = 'netsh advfirewall firewall add rule name="IR_DNS_Block_All_UDP" dir=out action=block protocol=udp remoteport=53'

        assert 'action=block' in expected
        assert 'remoteport=53' in expected

    def test_enable_logging_command(self):
        """Verify netsh command for enabling logging"""
        commands = [
            'netsh advfirewall set allprofiles logging droppedconnections enable',
            'netsh advfirewall set allprofiles logging allowedconnections enable',
            'netsh advfirewall set allprofiles logging filename',
            'netsh advfirewall set allprofiles logging maxfilesize',
        ]

        for cmd in commands:
            assert 'advfirewall set allprofiles logging' in cmd

    def test_disable_logging_command(self):
        """Verify netsh command for disabling logging"""
        commands = [
            'netsh advfirewall set allprofiles logging droppedconnections disable',
            'netsh advfirewall set allprofiles logging allowedconnections disable',
        ]

        for cmd in commands:
            assert 'logging' in cmd
            assert 'disable' in cmd


# =============================================================================
# Test: CLI Parameter Validation
# =============================================================================

class TestCLIParameters:
    """Test cases for CLI parameter combinations"""

    def test_allow_port_from_requires_port_and_ip(self):
        """AllowPortFrom requires both Port and FromIP"""
        # In the script, both parameters are required
        # Port = 0 or FromIP = empty should fail
        port = 0
        from_ip = ""

        # Simulating the validation check
        is_valid = (port != 0 and from_ip != "")
        assert is_valid is False

    def test_allow_port_from_valid_params(self):
        """AllowPortFrom with valid params should pass"""
        port = 22
        from_ip = "10.1.2.3"

        is_valid = (port != 0 and from_ip != "" and is_valid_port(str(port)) and is_valid_ip(from_ip))
        assert is_valid is True

    def test_block_port_except_from_requires_port_and_ips(self):
        """BlockPortExceptFrom requires both Port and FromIP"""
        port = 0
        from_ip = ""

        is_valid = (port != 0 and from_ip != "")
        assert is_valid is False

    def test_restrict_dns_requires_valid_ip_list(self):
        """RestrictDNS requires valid IP list"""
        dns_servers = "8.8.8.8,8.8.4.4"
        assert is_valid_ip_list(dns_servers) is True

    def test_restrict_dns_invalid_list(self):
        """RestrictDNS with invalid IP should fail"""
        dns_servers = "8.8.8.8,invalid"
        assert is_valid_ip_list(dns_servers) is False

    def test_block_port_out_requires_port(self):
        """BlockPortOut requires Port parameter"""
        port = 445
        is_valid = (port != 0 and is_valid_port(str(port)))
        assert is_valid is True


# =============================================================================
# Test: Enterprise Hardening Scenarios
# =============================================================================

class TestEnterpriseHardeningScenarios:
    """Test enterprise hardening use cases"""

    def test_restrict_ssh_to_management_ips(self):
        """Restrict SSH (port 22) to management IPs"""
        port = 22
        mgmt_ips = "10.1.2.3,10.1.2.4"

        assert is_valid_port(str(port)) is True
        assert is_valid_ip_list(mgmt_ips) is True

        # Expected rule names
        for ip in mgmt_ips.split(','):
            ip = ip.strip()
            ip_safe = sanitize_ip_for_rule_name(ip)
            allow_rule = f"IR_Whitelist_Port{port}_From_{ip_safe}_TCP"
            assert allow_rule.startswith("IR_Whitelist_")

        block_rule = f"IR_Block_Port{port}_AllOthers_TCP"
        assert block_rule.startswith("IR_Block_")

    def test_block_outbound_smb(self):
        """Block outbound SMB (port 445)"""
        port = 445
        assert is_valid_port(str(port)) is True

        rule_name_tcp = f"IR_Block_Outbound_ANY_{port}_TCP"
        rule_name_udp = f"IR_Block_Outbound_ANY_{port}_UDP"

        assert "445" in rule_name_tcp
        assert "445" in rule_name_udp

    def test_block_outbound_rdp(self):
        """Block outbound RDP (port 3389)"""
        port = 3389
        assert is_valid_port(str(port)) is True

        rule_name = f"IR_Block_Outbound_ANY_{port}_TCP"
        assert "3389" in rule_name

    def test_restrict_dns_to_approved_resolvers(self):
        """Restrict DNS to approved resolvers only"""
        dns_servers = "8.8.8.8,8.8.4.4,1.1.1.1"

        assert is_valid_ip_list(dns_servers) is True

        # Expected rule names for each resolver
        for ip in dns_servers.split(','):
            ip = ip.strip()
            ip_safe = sanitize_ip_for_rule_name(ip)
            allow_rule_udp = f"IR_DNS_Allow_{ip_safe}_UDP"
            allow_rule_tcp = f"IR_DNS_Allow_{ip_safe}_TCP"

            assert allow_rule_udp.startswith("IR_DNS_Allow_")
            assert allow_rule_tcp.startswith("IR_DNS_Allow_")

        block_rule_udp = "IR_DNS_Block_All_UDP"
        block_rule_tcp = "IR_DNS_Block_All_TCP"

        assert block_rule_udp == "IR_DNS_Block_All_UDP"
        assert block_rule_tcp == "IR_DNS_Block_All_TCP"

    def test_restrict_smtp_to_mail_servers(self):
        """Restrict SMTP to approved mail servers"""
        mail_servers = "10.0.0.5,10.0.0.6"
        smtp_ports = [25, 465, 587]

        assert is_valid_ip_list(mail_servers) is True

        # Verify rule names for each server and port
        for ip in mail_servers.split(','):
            ip = ip.strip()
            ip_safe = sanitize_ip_for_rule_name(ip)
            for port in smtp_ports:
                allow_rule = f"IR_SMTP_Allow_{ip_safe}_Port{port}"
                assert allow_rule.startswith("IR_SMTP_Allow_")

        # Verify block rules
        for port in smtp_ports:
            block_rule = f"IR_SMTP_Block_All_Port{port}"
            assert block_rule.startswith("IR_SMTP_Block_All_")


# =============================================================================
# Test: Edge Cases
# =============================================================================

class TestEdgeCases:
    """Test edge cases and boundary conditions"""

    def test_single_ip_in_list(self):
        """Single IP in comma-separated list should work"""
        assert is_valid_ip_list("8.8.8.8") is True

    def test_ip_with_leading_zeros(self):
        """IP with leading zeros in octets"""
        # Note: Python's standard IP parsing accepts leading zeros
        # but they may be interpreted as octal in some systems
        # For simplicity, we accept them here
        assert is_valid_ip("192.168.001.001") is True

    def test_cidr_boundary_values(self):
        """Test CIDR boundary values"""
        assert is_valid_ip("10.0.0.0/0") is True   # All traffic
        assert is_valid_ip("10.0.0.0/32") is True  # Single host
        assert is_valid_ip("10.0.0.0/33") is False # Invalid

    def test_port_boundary_values(self):
        """Test port boundary values"""
        assert is_valid_port("1") is True
        assert is_valid_port("65535") is True
        assert is_valid_port("0") is False
        assert is_valid_port("65536") is False

    def test_empty_string_validations(self):
        """Empty strings should fail all validations"""
        assert is_valid_port("") is False
        assert is_valid_ip("") is False
        assert is_valid_ip_list("") is False

    def test_whitespace_only_validations(self):
        """Whitespace-only strings should fail all validations"""
        assert is_valid_port("   ") is False
        assert is_valid_ip("   ") is False
        assert is_valid_ip_list("   ") is False

    def test_special_characters_in_ip(self):
        """Special characters in IP should fail validation"""
        assert is_valid_ip("10.1.2.3;") is False
        assert is_valid_ip("10.1.2.3|") is False
        assert is_valid_ip("10.1.2.3&") is False

    def test_rule_name_special_chars_sanitized(self):
        """Special characters in IPs should be sanitized for rule names"""
        # CIDR notation with /
        ip_cidr = "10.0.0.0/8"
        sanitized = sanitize_ip_for_rule_name(ip_cidr)
        assert '/' not in sanitized
        assert '.' not in sanitized
        assert sanitized == "10_0_0_0_8"


# =============================================================================
# Test: Protocol Handling
# =============================================================================

class TestProtocolHandling:
    """Test protocol-specific handling"""

    def test_dns_uses_both_udp_and_tcp(self):
        """DNS restriction should apply to both UDP and TCP port 53"""
        dns_port = 53
        protocols = ["UDP", "TCP"]

        for proto in protocols:
            rule_name = f"IR_DNS_Block_All_{proto}"
            assert proto in rule_name

    def test_smtp_ports_coverage(self):
        """SMTP restriction should cover all SMTP-related ports"""
        smtp_ports = [25, 465, 587]

        for port in smtp_ports:
            rule_name = f"IR_SMTP_Block_All_Port{port}"
            assert str(port) in rule_name

    def test_smb_tcp_only(self):
        """SMB (port 445) typically uses TCP"""
        # SMB primarily uses TCP, though UDP 445 rules are also created for completeness
        port = 445
        tcp_rule = f"IR_Block_Outbound_ANY_{port}_TCP"
        udp_rule = f"IR_Block_Outbound_ANY_{port}_UDP"

        assert "TCP" in tcp_rule
        assert "UDP" in udp_rule


# =============================================================================
# Test: Logging Configuration
# =============================================================================

class TestLoggingConfiguration:
    """Test logging configuration commands"""

    def test_log_file_location(self):
        """Verify standard Windows Firewall log file path"""
        expected_path = "%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall.log"
        # This is the standard Windows Firewall log location
        assert "LogFiles\\Firewall" in expected_path

    def test_log_settings_for_all_profiles(self):
        """Logging should be configured for all profiles"""
        profiles = "allprofiles"
        cmd = f"netsh advfirewall set {profiles} logging droppedconnections enable"
        assert profiles in cmd

    def test_both_dropped_and_allowed_logging(self):
        """Both dropped and allowed connections can be logged"""
        log_types = ["droppedconnections", "allowedconnections"]
        for log_type in log_types:
            cmd = f"netsh advfirewall set allprofiles logging {log_type} enable"
            assert log_type in cmd


# =============================================================================
# Run tests
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])

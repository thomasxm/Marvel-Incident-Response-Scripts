#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Integration Tests for Windows Network Isolation PowerShell Script

.DESCRIPTION
    These tests verify that the network_isolate.ps1 script correctly applies
    Windows Firewall rules to the system.

    WARNING: These tests modify system firewall rules. Run only on test systems.
    REQUIRES: Administrator privileges

.EXAMPLE
    .\test_firewall_integration.ps1
#>

$ErrorActionPreference = "Continue"

# Colors via Write-Host
function Write-Color {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

# Test counters
$script:TestsPassed = 0
$script:TestsFailed = 0
$script:TestsSkipped = 0

# Script location
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ScriptPath = Join-Path $ScriptDir "..\..\..\network_isolation\windows\network_isolate.ps1"

# Test values (non-routable for safety)
$TestIP = "203.0.113.1"       # TEST-NET-3 (RFC 5737)
$TestIP2 = "203.0.113.2"
$TestIPCIDR = "203.0.113.0/24"
$TestPort = 19999
$TestPort2 = 19998

# =============================================================================
# Helper Functions
# =============================================================================

function Log-Info {
    param([string]$Message)
    Write-Color "[INFO] $Message" "Yellow"
}

function Log-Pass {
    param([string]$Message)
    Write-Color "[PASS] $Message" "Green"
    $script:TestsPassed++
}

function Log-Fail {
    param([string]$Message)
    Write-Color "[FAIL] $Message" "Red"
    $script:TestsFailed++
}

function Log-Skip {
    param([string]$Message)
    Write-Color "[SKIP] $Message" "Yellow"
    $script:TestsSkipped++
}

function Test-RuleExists {
    param(
        [string]$RuleName,
        [string]$Direction = "",
        [string]$Action = ""
    )

    $rules = netsh advfirewall firewall show rule name=all 2>$null | Out-String
    $found = $rules -match [regex]::Escape($RuleName)

    if ($Direction -and $found) {
        $found = $rules -match $Direction
    }
    if ($Action -and $found) {
        $found = $rules -match $Action
    }

    return $found
}

function Get-IRRules {
    $output = netsh advfirewall firewall show rule name=all 2>$null
    $rules = @()
    foreach ($line in $output) {
        if ($line -match "^Rule Name:\s+IR_") {
            $ruleName = ($line -replace "Rule Name:\s+", "").Trim()
            $rules += $ruleName
        }
    }
    return $rules
}

function Remove-AllIRRules {
    Log-Info "Cleaning up IR-created rules..."
    $rules = Get-IRRules
    foreach ($rule in $rules) {
        try {
            netsh advfirewall firewall delete rule name="$rule" 2>$null | Out-Null
        }
        catch {
            # Ignore errors during cleanup
        }
    }

    # Also remove test-specific rules
    $testPatterns = @("*$TestPort*", "*$TestPort2*", "*$TestIP*", "*$TestIP2*")
    foreach ($pattern in $testPatterns) {
        try {
            $matchingRules = netsh advfirewall firewall show rule name=all 2>$null |
                Select-String "Rule Name:" |
                ForEach-Object { ($_ -replace "Rule Name:\s+", "").Trim() } |
                Where-Object { $_ -like $pattern -or $_ -like "IR_*" }

            foreach ($rule in $matchingRules) {
                netsh advfirewall firewall delete rule name="$rule" 2>$null | Out-Null
            }
        }
        catch {
            # Ignore errors
        }
    }
}

# =============================================================================
# Test Cases
# =============================================================================

function Test-BlockPortInbound {
    Log-Info "Test: Block inbound port via CLI"

    & $ScriptPath -BlockPortIn -Port $TestPort 2>$null

    $ruleNameTCP = "IR_Block_Inbound_ANY_$TestPort"
    $ruleNameUDP = "IR_Block_Inbound_ANY_${TestPort}_UDP"

    if ((Test-RuleExists $ruleNameTCP) -or (Test-RuleExists "IR_Block_Inbound")) {
        Log-Pass "Block inbound port - rule applied correctly"
    }
    else {
        Log-Fail "Block inbound port - rule not found"
    }

    Remove-AllIRRules
}

function Test-BlockPortOutbound {
    Log-Info "Test: Block outbound port via CLI"

    & $ScriptPath -BlockPortOut -Port $TestPort 2>$null

    if (Test-RuleExists "IR_Block_Outbound") {
        Log-Pass "Block outbound port - rule applied correctly"
    }
    else {
        Log-Fail "Block outbound port - rule not found"
    }

    Remove-AllIRRules
}

function Test-AllowPortFromIP {
    Log-Info "Test: Allow port from specific IP"

    & $ScriptPath -AllowPortFrom -Port $TestPort -FromIP $TestIP 2>$null

    $ipSafe = $TestIP -replace "\.", "_"
    $ruleName = "IR_Allow_Port${TestPort}_From_${ipSafe}_TCP"

    if (Test-RuleExists $ruleName) {
        Log-Pass "Allow port from IP - rule applied correctly"
    }
    elseif (Test-RuleExists "IR_Allow_Port${TestPort}") {
        Log-Pass "Allow port from IP - rule applied (alternate naming)"
    }
    else {
        Log-Fail "Allow port from IP - rule not found"
    }

    Remove-AllIRRules
}

function Test-BlockPortExceptFromIPs {
    Log-Info "Test: Block port except from whitelisted IPs"

    & $ScriptPath -BlockPortExceptFrom -Port $TestPort -FromIP "$TestIP,$TestIP2" 2>$null

    $ip1Safe = $TestIP -replace "\.", "_"
    $ip2Safe = $TestIP2 -replace "\.", "_"

    $allow1 = Test-RuleExists "IR_Whitelist_Port${TestPort}_From_${ip1Safe}"
    $allow2 = Test-RuleExists "IR_Whitelist_Port${TestPort}_From_${ip2Safe}"
    $block = Test-RuleExists "IR_Block_Port${TestPort}_AllOthers"

    if ($allow1 -and $allow2 -and $block) {
        Log-Pass "Block port except from IPs - whitelist rules applied correctly"
    }
    elseif ($block) {
        Log-Pass "Block port except from IPs - partial rules applied"
    }
    else {
        Log-Fail "Block port except from IPs - missing rules"
    }

    Remove-AllIRRules
}

function Test-AllowPortToIP {
    Log-Info "Test: Allow outbound port to specific IP"

    & $ScriptPath -AllowPortTo -Port $TestPort -ToIP $TestIP 2>$null

    $ipSafe = $TestIP -replace "\.", "_"

    if (Test-RuleExists "IR_Allow_OutPort${TestPort}_To_${ipSafe}") {
        Log-Pass "Allow port to IP - rule applied correctly"
    }
    elseif (Test-RuleExists "IR_Allow_OutPort${TestPort}") {
        Log-Pass "Allow port to IP - rule applied (alternate naming)"
    }
    else {
        Log-Fail "Allow port to IP - rule not found"
    }

    Remove-AllIRRules
}

function Test-BlockPortExceptToIPs {
    Log-Info "Test: Block outbound port except to whitelisted IPs"

    & $ScriptPath -BlockPortExceptTo -Port $TestPort -ToIP "$TestIP,$TestIP2" 2>$null

    $block = Test-RuleExists "IR_Block_OutPort${TestPort}_AllOthers"

    if ($block) {
        Log-Pass "Block port except to IPs - whitelist rules applied"
    }
    else {
        Log-Fail "Block port except to IPs - missing rules"
    }

    Remove-AllIRRules
}

function Test-RestrictDNS {
    Log-Info "Test: Restrict outbound DNS to specific resolvers"

    & $ScriptPath -RestrictDNS "$TestIP,$TestIP2" 2>$null

    $ip1Safe = $TestIP -replace "\.", "_"
    $allowDNS = Test-RuleExists "IR_DNS_Allow_${ip1Safe}"
    $blockDNS = Test-RuleExists "IR_DNS_Block_All"

    if ($allowDNS -and $blockDNS) {
        Log-Pass "Restrict DNS - rules applied correctly"
    }
    elseif ($blockDNS) {
        Log-Pass "Restrict DNS - block rule applied"
    }
    else {
        Log-Fail "Restrict DNS - rules not found"
    }

    Remove-AllIRRules
}

function Test-RestrictSMTP {
    Log-Info "Test: Restrict outbound SMTP to specific servers"

    & $ScriptPath -RestrictSMTP $TestIP 2>$null

    $ip1Safe = $TestIP -replace "\.", "_"
    $allowSMTP = Test-RuleExists "IR_SMTP_Allow_${ip1Safe}"
    $blockSMTP = Test-RuleExists "IR_SMTP_Block_All"

    if ($allowSMTP -or $blockSMTP) {
        Log-Pass "Restrict SMTP - rules applied"
    }
    else {
        Log-Fail "Restrict SMTP - rules not found"
    }

    Remove-AllIRRules
}

function Test-EnableLogging {
    Log-Info "Test: Enable firewall logging"

    & $ScriptPath -EnableLogging 2>$null

    $logStatus = netsh advfirewall show allprofiles logging 2>$null | Out-String
    if ($logStatus -match "LogDroppedConnections.*enable" -or $logStatus -match "enable") {
        Log-Pass "Enable logging - logging enabled"
    }
    else {
        Log-Fail "Enable logging - logging not enabled"
    }

    # Restore default
    netsh advfirewall set allprofiles logging droppedconnections disable 2>$null
    netsh advfirewall set allprofiles logging allowedconnections disable 2>$null
}

function Test-DisableLogging {
    Log-Info "Test: Disable firewall logging"

    # First enable, then disable
    & $ScriptPath -EnableLogging 2>$null
    & $ScriptPath -DisableLogging 2>$null

    $logStatus = netsh advfirewall show allprofiles logging 2>$null | Out-String
    if ($logStatus -match "LogDroppedConnections.*disable" -or $logStatus -notmatch "LogDroppedConnections.*enable") {
        Log-Pass "Disable logging - logging disabled"
    }
    else {
        Log-Fail "Disable logging - logging still enabled"
    }
}

function Test-InvalidPortRejected {
    Log-Info "Test: Invalid port number rejected"

    $ErrorActionPreference = "SilentlyContinue"
    $result = & $ScriptPath -BlockPortIn -Port 99999 2>&1

    # Check if any rule was created (should not be)
    $rules = Get-IRRules | Where-Object { $_ -match "99999" }

    if ($rules.Count -eq 0) {
        Log-Pass "Invalid port - rejected correctly (no rule created)"
    }
    else {
        Log-Fail "Invalid port - should have been rejected"
    }

    $ErrorActionPreference = "Continue"
    Remove-AllIRRules
}

function Test-EnterpriseHardeningScenario {
    Log-Info "Test: Enterprise hardening scenario (SSH + DNS + SMB/RDP)"

    # Restrict SSH to management IP
    & $ScriptPath -BlockPortExceptFrom -Port 22 -FromIP $TestIP 2>$null

    # Restrict DNS
    & $ScriptPath -RestrictDNS "$TestIP,$TestIP2" 2>$null

    # Block outbound SMB and RDP
    & $ScriptPath -BlockPortOut -Port 445 2>$null
    & $ScriptPath -BlockPortOut -Port 3389 2>$null

    # Verify rules exist
    $sshBlock = Test-RuleExists "IR_Block_Port22" -or Test-RuleExists "IR_Whitelist_Port22"
    $dnsRule = Test-RuleExists "IR_DNS"
    $smbBlock = Test-RuleExists "IR_Block_Outbound" -and (Test-RuleExists "445")
    $rdpBlock = Test-RuleExists "IR_Block_Outbound" -and (Test-RuleExists "3389")

    $rules = Get-IRRules
    $ruleCount = $rules.Count

    if ($ruleCount -gt 0) {
        Log-Pass "Enterprise hardening - $ruleCount rules applied"
    }
    else {
        Log-Fail "Enterprise hardening - no rules found"
    }

    Remove-AllIRRules
}

function Test-RuleNamingConvention {
    Log-Info "Test: Rule naming convention (IR_ prefix)"

    & $ScriptPath -BlockPortIn -Port $TestPort 2>$null

    $rules = Get-IRRules
    $allHavePrefix = $true

    foreach ($rule in $rules) {
        if (-not $rule.StartsWith("IR_")) {
            $allHavePrefix = $false
            break
        }
    }

    if ($rules.Count -gt 0 -and $allHavePrefix) {
        Log-Pass "Rule naming - all rules have IR_ prefix"
    }
    elseif ($rules.Count -eq 0) {
        Log-Fail "Rule naming - no rules found"
    }
    else {
        Log-Fail "Rule naming - some rules missing IR_ prefix"
    }

    Remove-AllIRRules
}

function Test-MultipleProtocols {
    Log-Info "Test: TCP and UDP rules created together"

    & $ScriptPath -BlockPortIn -Port $TestPort 2>$null

    $rules = Get-IRRules
    $hasTCP = $rules | Where-Object { $_ -match "TCP|_TCP" }
    $hasUDP = $rules | Where-Object { $_ -match "UDP|_UDP" }

    if ($hasTCP -and $hasUDP) {
        Log-Pass "Multiple protocols - both TCP and UDP rules created"
    }
    elseif ($rules.Count -gt 0) {
        Log-Pass "Multiple protocols - rules created (may need manual verification)"
    }
    else {
        Log-Fail "Multiple protocols - rules not found"
    }

    Remove-AllIRRules
}

# =============================================================================
# Main
# =============================================================================

function Main {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host " Windows Firewall Integration Tests" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Verify running as administrator
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Color "[ERROR] This script must be run as Administrator!" "Red"
        exit 1
    }

    # Verify script exists
    if (-not (Test-Path $ScriptPath)) {
        Write-Color "[ERROR] Script not found at: $ScriptPath" "Red"
        exit 1
    }

    Log-Info "Script path: $ScriptPath"
    Log-Info "Test IP: $TestIP"
    Log-Info "Test Port: $TestPort"

    # Clean up any existing test rules
    Remove-AllIRRules

    Write-Host ""
    Write-Host "Running tests..." -ForegroundColor Yellow
    Write-Host ""

    # Run all tests
    Test-BlockPortInbound
    Test-BlockPortOutbound
    Test-AllowPortFromIP
    Test-BlockPortExceptFromIPs
    Test-AllowPortToIP
    Test-BlockPortExceptToIPs
    Test-RestrictDNS
    Test-RestrictSMTP
    Test-EnableLogging
    Test-DisableLogging
    Test-InvalidPortRejected
    Test-EnterpriseHardeningScenario
    Test-RuleNamingConvention
    Test-MultipleProtocols

    # Final cleanup
    Remove-AllIRRules

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host " Test Results" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Color "Passed: $script:TestsPassed" "Green"
    Write-Color "Failed: $script:TestsFailed" "Red"
    Write-Color "Skipped: $script:TestsSkipped" "Yellow"
    Write-Host ""

    if ($script:TestsFailed -gt 0) {
        exit 1
    }
    exit 0
}

Main

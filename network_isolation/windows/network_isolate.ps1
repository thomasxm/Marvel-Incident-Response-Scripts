#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Network Isolation Script for Incident Response

.DESCRIPTION
    Interactive PowerShell script for network isolation using Windows Firewall.
    Provides comprehensive firewall management, network adapter control,
    advanced access control, and service restrictions.

.PARAMETER AllowPortFrom
    Allow inbound port from specific IP (use with -Port and -FromIP)

.PARAMETER BlockPortExceptFrom
    Block inbound port except from specific IPs (use with -Port and -FromIP)

.PARAMETER AllowPortTo
    Allow outbound to port on specific IP (use with -Port and -ToIP)

.PARAMETER BlockPortExceptTo
    Block outbound port except to specific IPs (use with -Port and -ToIP)

.PARAMETER BlockPortIn
    Block inbound port (TCP+UDP)

.PARAMETER BlockPortOut
    Block outbound port (TCP+UDP)

.PARAMETER RestrictDNS
    Restrict outbound DNS to specified resolvers (comma-separated IPs)

.PARAMETER RestrictSMTP
    Restrict outbound SMTP to specified mail servers (comma-separated IPs)

.PARAMETER EnableLogging
    Enable Windows Firewall logging

.PARAMETER DisableLogging
    Disable Windows Firewall logging

.PARAMETER Port
    Port number for port-based rules

.PARAMETER FromIP
    Source IP address(es) for inbound rules (comma-separated)

.PARAMETER ToIP
    Destination IP address(es) for outbound rules (comma-separated)

.EXAMPLE
    .\network_isolate.ps1
    Runs in interactive mode

.EXAMPLE
    .\network_isolate.ps1 -AllowPortFrom -Port 22 -FromIP 10.1.2.3
    Allow SSH from management IP

.EXAMPLE
    .\network_isolate.ps1 -BlockPortExceptFrom -Port 22 -FromIP "10.1.2.3,10.1.2.4"
    Allow SSH only from specified IPs

.EXAMPLE
    .\network_isolate.ps1 -RestrictDNS "8.8.8.8,8.8.4.4,1.1.1.1"
    Restrict DNS to Google and Cloudflare resolvers

.EXAMPLE
    .\network_isolate.ps1 -BlockPortOut 445 -BlockPortOut 3389
    Block outbound SMB and RDP

.NOTES
    Author: IR Toolkit
    Version: 2.0
    Requires: Administrator privileges
#>

[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    [Parameter(ParameterSetName = 'AllowPortFrom')]
    [switch]$AllowPortFrom,

    [Parameter(ParameterSetName = 'BlockPortExceptFrom')]
    [switch]$BlockPortExceptFrom,

    [Parameter(ParameterSetName = 'AllowPortTo')]
    [switch]$AllowPortTo,

    [Parameter(ParameterSetName = 'BlockPortExceptTo')]
    [switch]$BlockPortExceptTo,

    [Parameter(ParameterSetName = 'BlockPortIn')]
    [switch]$BlockPortIn,

    [Parameter(ParameterSetName = 'BlockPortOut')]
    [switch]$BlockPortOut,

    [Parameter(ParameterSetName = 'RestrictDNS')]
    [string]$RestrictDNS,

    [Parameter(ParameterSetName = 'RestrictSMTP')]
    [string]$RestrictSMTP,

    [Parameter(ParameterSetName = 'EnableLogging')]
    [switch]$EnableLogging,

    [Parameter(ParameterSetName = 'DisableLogging')]
    [switch]$DisableLogging,

    [Parameter(ParameterSetName = 'AllowPortFrom')]
    [Parameter(ParameterSetName = 'BlockPortExceptFrom')]
    [Parameter(ParameterSetName = 'AllowPortTo')]
    [Parameter(ParameterSetName = 'BlockPortExceptTo')]
    [Parameter(ParameterSetName = 'BlockPortIn')]
    [Parameter(ParameterSetName = 'BlockPortOut')]
    [int]$Port,

    [Parameter(ParameterSetName = 'AllowPortFrom')]
    [Parameter(ParameterSetName = 'BlockPortExceptFrom')]
    [string]$FromIP,

    [Parameter(ParameterSetName = 'AllowPortTo')]
    [Parameter(ParameterSetName = 'BlockPortExceptTo')]
    [string]$ToIP
)

$ErrorActionPreference = "Stop"
$script:InteractiveMode = $true

# ============================================================================
# Color-coded output functions
# ============================================================================

function Write-Header {
    param([string]$Message)
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " $Message" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Err {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Write-MenuOption {
    param(
        [string]$Number,
        [string]$Description
    )
    Write-Host "  [$Number] " -ForegroundColor Yellow -NoNewline
    Write-Host $Description -ForegroundColor White
}

# ============================================================================
# Input validation functions
# ============================================================================

function Test-ValidPort {
    param([string]$Port)

    if ([string]::IsNullOrWhiteSpace($Port)) {
        return $false
    }

    $portNum = 0
    if ([int]::TryParse($Port, [ref]$portNum)) {
        return ($portNum -ge 1 -and $portNum -le 65535)
    }
    return $false
}

function Test-ValidIP {
    param([string]$IP)

    if ([string]::IsNullOrWhiteSpace($IP)) {
        return $false
    }

    # Handle CIDR notation
    $ipPart = $IP
    if ($IP -match "^(.+)/(\d+)$") {
        $ipPart = $Matches[1]
        $cidr = [int]$Matches[2]
        if ($cidr -lt 0 -or $cidr -gt 32) {
            return $false
        }
    }

    try {
        $null = [System.Net.IPAddress]::Parse($ipPart)
        return $true
    }
    catch {
        return $false
    }
}

function Test-ValidIPList {
    param([string]$IPList)

    if ([string]::IsNullOrWhiteSpace($IPList)) {
        return $false
    }

    $ips = $IPList -split ","
    foreach ($ip in $ips) {
        $ip = $ip.Trim()
        if (-not (Test-ValidIP $ip)) {
            Write-Err "Invalid IP address: $ip"
            return $false
        }
    }
    return $true
}

function Get-Confirmation {
    param(
        [string]$Message,
        [switch]$Dangerous
    )

    if (-not $script:InteractiveMode) {
        return $true
    }

    if ($Dangerous) {
        Write-Warn "DANGEROUS OPERATION: $Message"
        Write-Host ""
        $confirm = Read-Host "Type 'YES' to confirm"
        return ($confirm -eq "YES")
    }
    else {
        $confirm = Read-Host "$Message (y/n)"
        return ($confirm -eq "y" -or $confirm -eq "Y")
    }
}

function Pause-ForUser {
    if ($script:InteractiveMode) {
        Write-Host ""
        Read-Host "Press Enter to continue"
    }
}

# ============================================================================
# Original Menu Option Functions
# ============================================================================

function Show-FirewallStatus {
    Write-Header "Firewall Status and Profiles"

    try {
        Write-Info "Querying firewall status..."
        Write-Host ""

        # Show profile status using netsh
        Write-Host "--- Firewall Profile Status ---" -ForegroundColor Magenta
        $output = netsh advfirewall show allprofiles state
        Write-Host $output

        Write-Host ""
        Write-Host "--- Detailed Profile Settings ---" -ForegroundColor Magenta

        # Domain Profile
        Write-Host "`nDomain Profile:" -ForegroundColor Yellow
        netsh advfirewall show domainprofile

        # Private Profile
        Write-Host "`nPrivate Profile:" -ForegroundColor Yellow
        netsh advfirewall show privateprofile

        # Public Profile
        Write-Host "`nPublic Profile:" -ForegroundColor Yellow
        netsh advfirewall show publicprofile

        Write-Success "Firewall status retrieved successfully"
    }
    catch {
        Write-Err "Failed to retrieve firewall status: $_"
    }

    Pause-ForUser
}

function Show-OpenPortsConnections {
    Write-Header "Open Ports and Connections"

    try {
        Write-Info "Retrieving network connections..."
        Write-Host ""

        # Using Get-NetTCPConnection for PowerShell native approach
        Write-Host "--- Active TCP Connections (Get-NetTCPConnection) ---" -ForegroundColor Magenta
        Get-NetTCPConnection |
            Where-Object { $_.State -eq "Listen" -or $_.State -eq "Established" } |
            Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
            Sort-Object State, LocalPort |
            Format-Table -AutoSize

        Write-Host ""
        Write-Host "--- Active UDP Listeners ---" -ForegroundColor Magenta
        Get-NetUDPEndpoint |
            Select-Object LocalAddress, LocalPort, OwningProcess |
            Sort-Object LocalPort |
            Format-Table -AutoSize

        Write-Host ""
        Write-Host "--- Netstat Output (Traditional View) ---" -ForegroundColor Magenta
        netstat -ano | Select-Object -First 50

        Write-Host ""
        Write-Info "Showing first 50 lines of netstat. Use 'netstat -ano' for full output."

        Write-Success "Connection information retrieved"
    }
    catch {
        Write-Err "Failed to retrieve connections: $_"
    }

    Pause-ForUser
}

function Enable-AllFirewallProfiles {
    Write-Header "Enable Windows Firewall (All Profiles)"

    if (-not (Get-Confirmation "Enable Windows Firewall for all profiles?")) {
        Write-Info "Operation cancelled"
        Pause-ForUser
        return
    }

    try {
        Write-Info "Enabling firewall for all profiles..."

        netsh advfirewall set allprofiles state on

        Write-Success "Windows Firewall enabled for all profiles"

        # Verify
        Write-Host ""
        netsh advfirewall show allprofiles state
    }
    catch {
        Write-Err "Failed to enable firewall: $_"
    }

    Pause-ForUser
}

function Disable-AllFirewallProfiles {
    Write-Header "Disable Windows Firewall (All Profiles)"

    Write-Warn "Disabling the firewall will remove all protection!"

    if (-not (Get-Confirmation "This will disable ALL firewall protection" -Dangerous)) {
        Write-Info "Operation cancelled"
        Pause-ForUser
        return
    }

    try {
        Write-Info "Disabling firewall for all profiles..."

        netsh advfirewall set allprofiles state off

        Write-Success "Windows Firewall disabled for all profiles"

        # Verify
        Write-Host ""
        netsh advfirewall show allprofiles state
    }
    catch {
        Write-Err "Failed to disable firewall: $_"
    }

    Pause-ForUser
}

function Block-InboundPort {
    Write-Header "Block Specific Port (Inbound)"

    $port = Read-Host "Enter port number to block (1-65535)"

    if (-not (Test-ValidPort $port)) {
        Write-Err "Invalid port number. Must be between 1 and 65535."
        Pause-ForUser
        return
    }

    $protocol = Read-Host "Enter protocol (TCP/UDP/Any) [default: TCP]"
    if ([string]::IsNullOrWhiteSpace($protocol)) {
        $protocol = "TCP"
    }
    $protocol = $protocol.ToUpper()

    if ($protocol -notin @("TCP", "UDP", "ANY")) {
        Write-Err "Invalid protocol. Must be TCP, UDP, or Any."
        Pause-ForUser
        return
    }

    $ruleName = "IR_Block_Inbound_${protocol}_${port}"

    if (-not (Get-Confirmation "Block inbound $protocol port $port?")) {
        Write-Info "Operation cancelled"
        Pause-ForUser
        return
    }

    try {
        Write-Info "Creating firewall rule to block inbound $protocol port $port..."

        if ($protocol -eq "ANY") {
            netsh advfirewall firewall add rule name="$ruleName" dir=in action=block protocol=tcp localport=$port
            netsh advfirewall firewall add rule name="${ruleName}_UDP" dir=in action=block protocol=udp localport=$port
        }
        else {
            netsh advfirewall firewall add rule name="$ruleName" dir=in action=block protocol=$protocol localport=$port
        }

        Write-Success "Inbound $protocol port $port blocked successfully"
        Write-Info "Rule name: $ruleName"
    }
    catch {
        Write-Err "Failed to create rule: $_"
    }

    Pause-ForUser
}

function Block-OutboundPort {
    param(
        [int]$PortNum = 0
    )

    if ($script:InteractiveMode -and $PortNum -eq 0) {
        Write-Header "Block Specific Port (Outbound)"

        $port = Read-Host "Enter port number to block (1-65535)"

        if (-not (Test-ValidPort $port)) {
            Write-Err "Invalid port number. Must be between 1 and 65535."
            Pause-ForUser
            return
        }

        $protocol = Read-Host "Enter protocol (TCP/UDP/Any) [default: TCP]"
        if ([string]::IsNullOrWhiteSpace($protocol)) {
            $protocol = "TCP"
        }
        $protocol = $protocol.ToUpper()

        if ($protocol -notin @("TCP", "UDP", "ANY")) {
            Write-Err "Invalid protocol. Must be TCP, UDP, or Any."
            Pause-ForUser
            return
        }

        if (-not (Get-Confirmation "Block outbound $protocol port $port?")) {
            Write-Info "Operation cancelled"
            Pause-ForUser
            return
        }
    }
    else {
        $port = $PortNum
        $protocol = "ANY"
    }

    $ruleName = "IR_Block_Outbound_${protocol}_${port}"

    try {
        Write-Info "Creating firewall rule to block outbound port $port..."

        if ($protocol -eq "ANY") {
            netsh advfirewall firewall add rule name="${ruleName}_TCP" dir=out action=block protocol=tcp remoteport=$port
            netsh advfirewall firewall add rule name="${ruleName}_UDP" dir=out action=block protocol=udp remoteport=$port
        }
        else {
            netsh advfirewall firewall add rule name="$ruleName" dir=out action=block protocol=$protocol remoteport=$port
        }

        Write-Success "Outbound port $port blocked successfully"
        Write-Info "Rule name: $ruleName"
    }
    catch {
        Write-Err "Failed to create rule: $_"
    }

    if ($script:InteractiveMode) { Pause-ForUser }
}

function Block-IPAddress {
    Write-Header "Block Specific IP Address"

    $ip = Read-Host "Enter IP address to block"

    if (-not (Test-ValidIP $ip)) {
        Write-Err "Invalid IP address format."
        Pause-ForUser
        return
    }

    $direction = Read-Host "Block direction (in/out/both) [default: both]"
    if ([string]::IsNullOrWhiteSpace($direction)) {
        $direction = "both"
    }
    $direction = $direction.ToLower()

    if ($direction -notin @("in", "out", "both")) {
        Write-Err "Invalid direction. Must be in, out, or both."
        Pause-ForUser
        return
    }

    $ipSafe = $ip -replace "\.", "_"

    if (-not (Get-Confirmation "Block IP address $ip (direction: $direction)?")) {
        Write-Info "Operation cancelled"
        Pause-ForUser
        return
    }

    try {
        Write-Info "Creating firewall rule to block IP $ip..."

        if ($direction -eq "in" -or $direction -eq "both") {
            $ruleName = "IR_Block_IP_In_$ipSafe"
            netsh advfirewall firewall add rule name="$ruleName" dir=in action=block remoteip=$ip
            Write-Success "Inbound traffic from $ip blocked (Rule: $ruleName)"
        }

        if ($direction -eq "out" -or $direction -eq "both") {
            $ruleName = "IR_Block_IP_Out_$ipSafe"
            netsh advfirewall firewall add rule name="$ruleName" dir=out action=block remoteip=$ip
            Write-Success "Outbound traffic to $ip blocked (Rule: $ruleName)"
        }
    }
    catch {
        Write-Err "Failed to create rule: $_"
    }

    Pause-ForUser
}

function Allow-Port {
    Write-Header "Allow Specific Port"

    $port = Read-Host "Enter port number to allow (1-65535)"

    if (-not (Test-ValidPort $port)) {
        Write-Err "Invalid port number. Must be between 1 and 65535."
        Pause-ForUser
        return
    }

    $protocol = Read-Host "Enter protocol (TCP/UDP) [default: TCP]"
    if ([string]::IsNullOrWhiteSpace($protocol)) {
        $protocol = "TCP"
    }
    $protocol = $protocol.ToUpper()

    if ($protocol -notin @("TCP", "UDP")) {
        Write-Err "Invalid protocol. Must be TCP or UDP."
        Pause-ForUser
        return
    }

    $direction = Read-Host "Direction (in/out/both) [default: in]"
    if ([string]::IsNullOrWhiteSpace($direction)) {
        $direction = "in"
    }
    $direction = $direction.ToLower()

    if ($direction -notin @("in", "out", "both")) {
        Write-Err "Invalid direction. Must be in, out, or both."
        Pause-ForUser
        return
    }

    if (-not (Get-Confirmation "Allow $protocol port $port (direction: $direction)?")) {
        Write-Info "Operation cancelled"
        Pause-ForUser
        return
    }

    try {
        Write-Info "Creating firewall rule to allow $protocol port $port..."

        if ($direction -eq "in" -or $direction -eq "both") {
            $ruleName = "IR_Allow_In_${protocol}_${port}"
            netsh advfirewall firewall add rule name="$ruleName" dir=in action=allow protocol=$protocol localport=$port
            Write-Success "Inbound $protocol port $port allowed (Rule: $ruleName)"
        }

        if ($direction -eq "out" -or $direction -eq "both") {
            $ruleName = "IR_Allow_Out_${protocol}_${port}"
            netsh advfirewall firewall add rule name="$ruleName" dir=out action=allow protocol=$protocol localport=$port
            Write-Success "Outbound $protocol port $port allowed (Rule: $ruleName)"
        }
    }
    catch {
        Write-Err "Failed to create rule: $_"
    }

    Pause-ForUser
}

function Allow-IPAddress {
    Write-Header "Allow Specific IP Address"

    $ip = Read-Host "Enter IP address to allow"

    if (-not (Test-ValidIP $ip)) {
        Write-Err "Invalid IP address format."
        Pause-ForUser
        return
    }

    $direction = Read-Host "Allow direction (in/out/both) [default: both]"
    if ([string]::IsNullOrWhiteSpace($direction)) {
        $direction = "both"
    }
    $direction = $direction.ToLower()

    if ($direction -notin @("in", "out", "both")) {
        Write-Err "Invalid direction. Must be in, out, or both."
        Pause-ForUser
        return
    }

    $ipSafe = $ip -replace "\.", "_"

    if (-not (Get-Confirmation "Allow IP address $ip (direction: $direction)?")) {
        Write-Info "Operation cancelled"
        Pause-ForUser
        return
    }

    try {
        Write-Info "Creating firewall rule to allow IP $ip..."

        if ($direction -eq "in" -or $direction -eq "both") {
            $ruleName = "IR_Allow_IP_In_$ipSafe"
            netsh advfirewall firewall add rule name="$ruleName" dir=in action=allow remoteip=$ip
            Write-Success "Inbound traffic from $ip allowed (Rule: $ruleName)"
        }

        if ($direction -eq "out" -or $direction -eq "both") {
            $ruleName = "IR_Allow_IP_Out_$ipSafe"
            netsh advfirewall firewall add rule name="$ruleName" dir=out action=allow remoteip=$ip
            Write-Success "Outbound traffic to $ip allowed (Rule: $ruleName)"
        }
    }
    catch {
        Write-Err "Failed to create rule: $_"
    }

    Pause-ForUser
}

function Remove-FirewallRule {
    Write-Header "Delete Firewall Rule"

    Write-Info "Listing IR-created firewall rules..."
    Write-Host ""

    try {
        $rules = netsh advfirewall firewall show rule name=all | Select-String "Rule Name:" | ForEach-Object {
            ($_ -replace "Rule Name:\s+", "").Trim()
        } | Where-Object { $_ -like "IR_*" }

        if ($rules.Count -eq 0) {
            Write-Warn "No IR-created rules found."
            Write-Host ""
            Write-Info "To delete other rules, enter the exact rule name."
        }
        else {
            Write-Host "IR-created rules:" -ForegroundColor Magenta
            $rules | ForEach-Object { Write-Host "  - $_" -ForegroundColor White }
        }

        Write-Host ""
        $ruleName = Read-Host "Enter rule name to delete (or 'cancel' to abort)"

        if ($ruleName -eq "cancel" -or [string]::IsNullOrWhiteSpace($ruleName)) {
            Write-Info "Operation cancelled"
            Pause-ForUser
            return
        }

        if (-not (Get-Confirmation "Delete firewall rule '$ruleName'?")) {
            Write-Info "Operation cancelled"
            Pause-ForUser
            return
        }

        Write-Info "Deleting firewall rule..."
        netsh advfirewall firewall delete rule name="$ruleName"

        Write-Success "Firewall rule '$ruleName' deleted"
    }
    catch {
        Write-Err "Failed to delete rule: $_"
    }

    Pause-ForUser
}

function Block-AllInbound {
    Write-Header "Block All Inbound (Emergency Isolation)"

    Write-Warn "This will block ALL inbound connections!"
    Write-Warn "You may lose remote access to this machine!"
    Write-Host ""

    if (-not (Get-Confirmation "Block ALL inbound traffic (Emergency Isolation)" -Dangerous)) {
        Write-Info "Operation cancelled"
        Pause-ForUser
        return
    }

    try {
        Write-Info "Configuring firewall to block all inbound traffic..."

        # Set default inbound policy to block
        netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound

        Write-Success "All inbound traffic is now blocked"
        Write-Warn "Remote access may be unavailable!"

        # Show current policy
        Write-Host ""
        netsh advfirewall show allprofiles firewallpolicy
    }
    catch {
        Write-Err "Failed to configure firewall: $_"
    }

    Pause-ForUser
}

function Block-AllOutbound {
    Write-Header "Block All Outbound (Emergency Isolation)"

    Write-Warn "This will block ALL outbound connections!"
    Write-Warn "The system will be completely network isolated!"
    Write-Host ""

    if (-not (Get-Confirmation "Block ALL outbound traffic (Emergency Isolation)" -Dangerous)) {
        Write-Info "Operation cancelled"
        Pause-ForUser
        return
    }

    try {
        Write-Info "Configuring firewall to block all outbound traffic..."

        # Set default outbound policy to block
        netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound

        Write-Success "All outbound traffic is now blocked"
        Write-Warn "System is now fully isolated from the network!"

        # Show current policy
        Write-Host ""
        netsh advfirewall show allprofiles firewallpolicy
    }
    catch {
        Write-Err "Failed to configure firewall: $_"
    }

    Pause-ForUser
}

function Reset-FirewallDefaults {
    Write-Header "Reset Firewall to Defaults"

    Write-Warn "This will reset Windows Firewall to its default configuration!"
    Write-Warn "All custom rules will be deleted!"
    Write-Host ""

    if (-not (Get-Confirmation "Reset Windows Firewall to default settings" -Dangerous)) {
        Write-Info "Operation cancelled"
        Pause-ForUser
        return
    }

    try {
        Write-Info "Resetting Windows Firewall to defaults..."

        netsh advfirewall reset

        Write-Success "Windows Firewall has been reset to defaults"

        # Show current status
        Write-Host ""
        netsh advfirewall show allprofiles state
    }
    catch {
        Write-Err "Failed to reset firewall: $_"
    }

    Pause-ForUser
}

function Disable-NetworkAdapter {
    Write-Header "Disable Network Adapter"

    try {
        Write-Info "Listing network adapters..."
        Write-Host ""

        $adapters = Get-NetAdapter | Select-Object Name, Status, InterfaceDescription, MacAddress
        $adapters | Format-Table -AutoSize

        $adapterName = Read-Host "Enter adapter name to disable"

        if ([string]::IsNullOrWhiteSpace($adapterName)) {
            Write-Err "No adapter name provided."
            Pause-ForUser
            return
        }

        $adapter = Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue
        if (-not $adapter) {
            Write-Err "Adapter '$adapterName' not found."
            Pause-ForUser
            return
        }

        Write-Warn "Disabling network adapter will disconnect network connectivity!"

        if (-not (Get-Confirmation "Disable network adapter '$adapterName'" -Dangerous)) {
            Write-Info "Operation cancelled"
            Pause-ForUser
            return
        }

        Write-Info "Disabling adapter '$adapterName'..."
        Disable-NetAdapter -Name $adapterName -Confirm:$false

        Write-Success "Network adapter '$adapterName' disabled"
    }
    catch {
        Write-Err "Failed to disable adapter: $_"
    }

    Pause-ForUser
}

function Enable-NetworkAdapter {
    Write-Header "Enable Network Adapter"

    try {
        Write-Info "Listing network adapters..."
        Write-Host ""

        $adapters = Get-NetAdapter | Select-Object Name, Status, InterfaceDescription, MacAddress
        $adapters | Format-Table -AutoSize

        $adapterName = Read-Host "Enter adapter name to enable"

        if ([string]::IsNullOrWhiteSpace($adapterName)) {
            Write-Err "No adapter name provided."
            Pause-ForUser
            return
        }

        $adapter = Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue
        if (-not $adapter) {
            Write-Err "Adapter '$adapterName' not found."
            Pause-ForUser
            return
        }

        if (-not (Get-Confirmation "Enable network adapter '$adapterName'?")) {
            Write-Info "Operation cancelled"
            Pause-ForUser
            return
        }

        Write-Info "Enabling adapter '$adapterName'..."
        Enable-NetAdapter -Name $adapterName -Confirm:$false

        Write-Success "Network adapter '$adapterName' enabled"
    }
    catch {
        Write-Err "Failed to enable adapter: $_"
    }

    Pause-ForUser
}

function Show-NetworkAdapters {
    Write-Header "Network Adapters"

    try {
        Write-Info "Retrieving network adapter information..."
        Write-Host ""

        Write-Host "--- Network Adapter Status ---" -ForegroundColor Magenta
        Get-NetAdapter | Format-Table Name, Status, LinkSpeed, MacAddress, InterfaceDescription -AutoSize

        Write-Host ""
        Write-Host "--- IP Configuration ---" -ForegroundColor Magenta
        Get-NetIPAddress | Where-Object { $_.AddressFamily -eq "IPv4" } |
            Format-Table InterfaceAlias, IPAddress, PrefixLength, AddressState -AutoSize

        Write-Host ""
        Write-Host "--- Default Gateway ---" -ForegroundColor Magenta
        Get-NetRoute | Where-Object { $_.DestinationPrefix -eq "0.0.0.0/0" } |
            Format-Table InterfaceAlias, NextHop, RouteMetric -AutoSize

        Write-Success "Network adapter information retrieved"
    }
    catch {
        Write-Err "Failed to retrieve adapter information: $_"
    }

    Pause-ForUser
}

# ============================================================================
# NEW: Combined IP+Port Functions
# ============================================================================

function Allow-PortFromIP {
    param(
        [int]$PortNum = 0,
        [string]$SourceIP = ""
    )

    if ($script:InteractiveMode -and $PortNum -eq 0) {
        Write-Header "Allow Port from Specific IP (Admin Access Control)"

        $port = Read-Host "Enter port number"
        if (-not (Test-ValidPort $port)) {
            Write-Err "Invalid port number. Must be between 1 and 65535."
            Pause-ForUser
            return
        }

        $ip = Read-Host "Enter source IP address (e.g., 10.1.2.3 or 10.1.2.0/24)"
        if (-not (Test-ValidIP $ip)) {
            Write-Err "Invalid IP address format."
            Pause-ForUser
            return
        }

        if (-not (Get-Confirmation "Allow port $port from IP $ip?")) {
            Write-Info "Operation cancelled"
            Pause-ForUser
            return
        }
    }
    else {
        $port = $PortNum
        $ip = $SourceIP
    }

    $ipSafe = $ip -replace "[\.\/]", "_"

    try {
        Write-Info "Allowing port $port from IP $ip..."

        # TCP rule
        $ruleName = "IR_Allow_Port${port}_From_${ipSafe}_TCP"
        netsh advfirewall firewall add rule name="$ruleName" dir=in action=allow protocol=tcp localport=$port remoteip=$ip
        Write-Success "Allowed TCP port $port from $ip (Rule: $ruleName)"

        # UDP rule
        $ruleName = "IR_Allow_Port${port}_From_${ipSafe}_UDP"
        netsh advfirewall firewall add rule name="$ruleName" dir=in action=allow protocol=udp localport=$port remoteip=$ip
        Write-Success "Allowed UDP port $port from $ip (Rule: $ruleName)"
    }
    catch {
        Write-Err "Failed to create rule: $_"
    }

    if ($script:InteractiveMode) { Pause-ForUser }
}

function Block-PortExceptFromIP {
    param(
        [int]$PortNum = 0,
        [string]$SourceIPs = ""
    )

    if ($script:InteractiveMode -and $PortNum -eq 0) {
        Write-Header "Block Port Except from IPs (Whitelist Inbound)"

        $port = Read-Host "Enter port number to restrict"
        if (-not (Test-ValidPort $port)) {
            Write-Err "Invalid port number. Must be between 1 and 65535."
            Pause-ForUser
            return
        }

        $ipList = Read-Host "Enter allowed source IPs (comma-separated, e.g., 10.1.2.3,10.1.2.4)"
        if (-not (Test-ValidIPList $ipList)) {
            Pause-ForUser
            return
        }

        if (-not (Get-Confirmation "Allow port $port only from: $ipList ?")) {
            Write-Info "Operation cancelled"
            Pause-ForUser
            return
        }
    }
    else {
        $port = $PortNum
        $ipList = $SourceIPs
    }

    try {
        Write-Info "Allowing port $port only from: $ipList"
        Write-Info "All other sources will be blocked..."

        # First, add ALLOW rules for whitelisted IPs
        $ips = $ipList -split ","
        foreach ($ip in $ips) {
            $ip = $ip.Trim()
            $ipSafe = $ip -replace "[\.\/]", "_"

            # TCP allow
            $ruleName = "IR_Whitelist_Port${port}_From_${ipSafe}_TCP"
            netsh advfirewall firewall add rule name="$ruleName" dir=in action=allow protocol=tcp localport=$port remoteip=$ip
            Write-Success "Allowed TCP port $port from $ip"

            # UDP allow
            $ruleName = "IR_Whitelist_Port${port}_From_${ipSafe}_UDP"
            netsh advfirewall firewall add rule name="$ruleName" dir=in action=allow protocol=udp localport=$port remoteip=$ip
            Write-Success "Allowed UDP port $port from $ip"
        }

        # Then, add BLOCK rules for all others
        $ruleName = "IR_Block_Port${port}_AllOthers_TCP"
        netsh advfirewall firewall add rule name="$ruleName" dir=in action=block protocol=tcp localport=$port
        Write-Success "Blocked TCP port $port from all other sources"

        $ruleName = "IR_Block_Port${port}_AllOthers_UDP"
        netsh advfirewall firewall add rule name="$ruleName" dir=in action=block protocol=udp localport=$port
        Write-Success "Blocked UDP port $port from all other sources"
    }
    catch {
        Write-Err "Failed to create rules: $_"
    }

    if ($script:InteractiveMode) { Pause-ForUser }
}

function Allow-PortToIP {
    param(
        [int]$PortNum = 0,
        [string]$DestIP = ""
    )

    if ($script:InteractiveMode -and $PortNum -eq 0) {
        Write-Header "Allow Outbound Port to Specific IP"

        $port = Read-Host "Enter destination port number"
        if (-not (Test-ValidPort $port)) {
            Write-Err "Invalid port number. Must be between 1 and 65535."
            Pause-ForUser
            return
        }

        $ip = Read-Host "Enter destination IP address (e.g., 8.8.8.8 or 10.0.0.0/8)"
        if (-not (Test-ValidIP $ip)) {
            Write-Err "Invalid IP address format."
            Pause-ForUser
            return
        }

        if (-not (Get-Confirmation "Allow outbound port $port to IP $ip?")) {
            Write-Info "Operation cancelled"
            Pause-ForUser
            return
        }
    }
    else {
        $port = $PortNum
        $ip = $DestIP
    }

    $ipSafe = $ip -replace "[\.\/]", "_"

    try {
        Write-Info "Allowing outbound port $port to IP $ip..."

        # TCP rule
        $ruleName = "IR_Allow_OutPort${port}_To_${ipSafe}_TCP"
        netsh advfirewall firewall add rule name="$ruleName" dir=out action=allow protocol=tcp remoteport=$port remoteip=$ip
        Write-Success "Allowed outbound TCP port $port to $ip"

        # UDP rule
        $ruleName = "IR_Allow_OutPort${port}_To_${ipSafe}_UDP"
        netsh advfirewall firewall add rule name="$ruleName" dir=out action=allow protocol=udp remoteport=$port remoteip=$ip
        Write-Success "Allowed outbound UDP port $port to $ip"
    }
    catch {
        Write-Err "Failed to create rule: $_"
    }

    if ($script:InteractiveMode) { Pause-ForUser }
}

function Block-PortExceptToIP {
    param(
        [int]$PortNum = 0,
        [string]$DestIPs = ""
    )

    if ($script:InteractiveMode -and $PortNum -eq 0) {
        Write-Header "Block Outbound Port Except to IPs (Whitelist Outbound)"

        $port = Read-Host "Enter destination port number to restrict"
        if (-not (Test-ValidPort $port)) {
            Write-Err "Invalid port number. Must be between 1 and 65535."
            Pause-ForUser
            return
        }

        $ipList = Read-Host "Enter allowed destination IPs (comma-separated, e.g., 8.8.8.8,8.8.4.4)"
        if (-not (Test-ValidIPList $ipList)) {
            Pause-ForUser
            return
        }

        if (-not (Get-Confirmation "Allow outbound port $port only to: $ipList ?")) {
            Write-Info "Operation cancelled"
            Pause-ForUser
            return
        }
    }
    else {
        $port = $PortNum
        $ipList = $DestIPs
    }

    try {
        Write-Info "Allowing outbound port $port only to: $ipList"
        Write-Info "All other destinations will be blocked..."

        # First, add ALLOW rules for whitelisted IPs
        $ips = $ipList -split ","
        foreach ($ip in $ips) {
            $ip = $ip.Trim()
            $ipSafe = $ip -replace "[\.\/]", "_"

            # TCP allow
            $ruleName = "IR_Whitelist_OutPort${port}_To_${ipSafe}_TCP"
            netsh advfirewall firewall add rule name="$ruleName" dir=out action=allow protocol=tcp remoteport=$port remoteip=$ip
            Write-Success "Allowed outbound TCP port $port to $ip"

            # UDP allow
            $ruleName = "IR_Whitelist_OutPort${port}_To_${ipSafe}_UDP"
            netsh advfirewall firewall add rule name="$ruleName" dir=out action=allow protocol=udp remoteport=$port remoteip=$ip
            Write-Success "Allowed outbound UDP port $port to $ip"
        }

        # Then, add BLOCK rules for all others
        $ruleName = "IR_Block_OutPort${port}_AllOthers_TCP"
        netsh advfirewall firewall add rule name="$ruleName" dir=out action=block protocol=tcp remoteport=$port
        Write-Success "Blocked outbound TCP port $port to all other destinations"

        $ruleName = "IR_Block_OutPort${port}_AllOthers_UDP"
        netsh advfirewall firewall add rule name="$ruleName" dir=out action=block protocol=udp remoteport=$port
        Write-Success "Blocked outbound UDP port $port to all other destinations"
    }
    catch {
        Write-Err "Failed to create rules: $_"
    }

    if ($script:InteractiveMode) { Pause-ForUser }
}

# ============================================================================
# NEW: Service Restriction Functions
# ============================================================================

function Restrict-OutboundDNS {
    param(
        [string]$DNSServers = ""
    )

    if ($script:InteractiveMode -and [string]::IsNullOrWhiteSpace($DNSServers)) {
        Write-Header "Restrict Outbound DNS to Approved Resolvers"

        Write-Info "Enter DNS resolver IPs that should be allowed."
        Write-Info "Common options: 8.8.8.8, 8.8.4.4 (Google), 1.1.1.1 (Cloudflare)"
        Write-Host ""

        $ipList = Read-Host "Enter allowed DNS server IPs (comma-separated)"
        if (-not (Test-ValidIPList $ipList)) {
            Pause-ForUser
            return
        }

        if (-not (Get-Confirmation "Restrict DNS to: $ipList ?")) {
            Write-Info "Operation cancelled"
            Pause-ForUser
            return
        }
    }
    else {
        $ipList = $DNSServers
    }

    try {
        Write-Info "Restricting outbound DNS (port 53) to: $ipList"
        Write-Warn "All other DNS queries will be blocked!"

        # Add ALLOW rules for each DNS server (both UDP and TCP)
        $ips = $ipList -split ","
        foreach ($ip in $ips) {
            $ip = $ip.Trim()
            $ipSafe = $ip -replace "[\.\/]", "_"

            # UDP DNS
            $ruleName = "IR_DNS_Allow_${ipSafe}_UDP"
            netsh advfirewall firewall add rule name="$ruleName" dir=out action=allow protocol=udp remoteport=53 remoteip=$ip

            # TCP DNS
            $ruleName = "IR_DNS_Allow_${ipSafe}_TCP"
            netsh advfirewall firewall add rule name="$ruleName" dir=out action=allow protocol=tcp remoteport=53 remoteip=$ip

            Write-Success "Allowed DNS to $ip"
        }

        # Block all other DNS
        netsh advfirewall firewall add rule name="IR_DNS_Block_All_UDP" dir=out action=block protocol=udp remoteport=53
        netsh advfirewall firewall add rule name="IR_DNS_Block_All_TCP" dir=out action=block protocol=tcp remoteport=53
        Write-Success "Blocked DNS to all other destinations"
    }
    catch {
        Write-Err "Failed to create DNS rules: $_"
    }

    if ($script:InteractiveMode) { Pause-ForUser }
}

function Restrict-OutboundSMTP {
    param(
        [string]$MailServers = ""
    )

    if ($script:InteractiveMode -and [string]::IsNullOrWhiteSpace($MailServers)) {
        Write-Header "Restrict Outbound SMTP to Mail Servers"

        Write-Info "Enter mail server IPs that should be allowed for SMTP."
        Write-Info "This will restrict ports 25 (SMTP), 465 (SMTPS), and 587 (Submission)."
        Write-Host ""

        $ipList = Read-Host "Enter allowed mail server IPs (comma-separated)"
        if (-not (Test-ValidIPList $ipList)) {
            Pause-ForUser
            return
        }

        if (-not (Get-Confirmation "Restrict SMTP to: $ipList ?")) {
            Write-Info "Operation cancelled"
            Pause-ForUser
            return
        }
    }
    else {
        $ipList = $MailServers
    }

    $smtpPorts = @(25, 465, 587)

    try {
        Write-Info "Restricting outbound SMTP (ports 25, 465, 587) to: $ipList"
        Write-Warn "All other SMTP connections will be blocked!"

        # Add ALLOW rules for each mail server
        $ips = $ipList -split ","
        foreach ($ip in $ips) {
            $ip = $ip.Trim()
            $ipSafe = $ip -replace "[\.\/]", "_"

            foreach ($port in $smtpPorts) {
                $ruleName = "IR_SMTP_Allow_${ipSafe}_Port${port}"
                netsh advfirewall firewall add rule name="$ruleName" dir=out action=allow protocol=tcp remoteport=$port remoteip=$ip
            }
            Write-Success "Allowed SMTP to $ip"
        }

        # Block all other SMTP
        foreach ($port in $smtpPorts) {
            netsh advfirewall firewall add rule name="IR_SMTP_Block_All_Port${port}" dir=out action=block protocol=tcp remoteport=$port
        }
        Write-Success "Blocked SMTP to all other destinations"
    }
    catch {
        Write-Err "Failed to create SMTP rules: $_"
    }

    if ($script:InteractiveMode) { Pause-ForUser }
}

# ============================================================================
# NEW: Logging Functions
# ============================================================================

function Enable-FirewallLogging {
    if ($script:InteractiveMode) {
        Write-Header "Enable Firewall Logging"
        Write-Info "This will enable Windows Firewall logging for dropped packets."
        Write-Host ""
    }

    try {
        Write-Info "Enabling Windows Firewall logging..."

        # Enable logging for all profiles
        netsh advfirewall set allprofiles logging droppedconnections enable
        netsh advfirewall set allprofiles logging allowedconnections enable
        netsh advfirewall set allprofiles logging filename "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
        netsh advfirewall set allprofiles logging maxfilesize 32767

        Write-Success "Firewall logging enabled."
        Write-Info "Log file: %systemroot%\system32\LogFiles\Firewall\pfirewall.log"
        Write-Info "View with: Get-Content `$env:systemroot\system32\LogFiles\Firewall\pfirewall.log -Tail 50"
    }
    catch {
        Write-Err "Failed to enable logging: $_"
    }

    if ($script:InteractiveMode) { Pause-ForUser }
}

function Disable-FirewallLogging {
    if ($script:InteractiveMode) {
        Write-Header "Disable Firewall Logging"
        Write-Host ""
    }

    try {
        Write-Info "Disabling Windows Firewall logging..."

        netsh advfirewall set allprofiles logging droppedconnections disable
        netsh advfirewall set allprofiles logging allowedconnections disable

        Write-Success "Firewall logging disabled."
    }
    catch {
        Write-Err "Failed to disable logging: $_"
    }

    if ($script:InteractiveMode) { Pause-ForUser }
}

# ============================================================================
# Main Menu
# ============================================================================

function Show-MainMenu {
    Clear-Host
    Write-Host ""
    Write-Host "  ================================================================" -ForegroundColor Cyan
    Write-Host "       Windows Network Isolation Script - Incident Response" -ForegroundColor Cyan
    Write-Host "  ================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  FIREWALL STATUS" -ForegroundColor Green
    Write-MenuOption "1" "Show firewall status and profiles"
    Write-MenuOption "2" "Show open ports and connections"
    Write-Host ""
    Write-Host "  FIREWALL CONTROL" -ForegroundColor Green
    Write-MenuOption "3" "Enable Windows Firewall (all profiles)"
    Write-MenuOption "4" "Disable Windows Firewall (all profiles)"
    Write-Host ""
    Write-Host "  BLOCK RULES" -ForegroundColor Green
    Write-MenuOption "5" "Block a specific port (inbound)"
    Write-MenuOption "6" "Block a specific port (outbound)"
    Write-MenuOption "7" "Block a specific IP address"
    Write-Host ""
    Write-Host "  ALLOW RULES" -ForegroundColor Green
    Write-MenuOption "8" "Allow a specific port"
    Write-MenuOption "9" "Allow a specific IP address"
    Write-Host ""
    Write-Host "  RULE MANAGEMENT" -ForegroundColor Green
    Write-MenuOption "10" "Delete a firewall rule"
    Write-Host ""
    Write-Host "  EMERGENCY ISOLATION" -ForegroundColor Red
    Write-MenuOption "11" "Block all inbound (emergency isolation)"
    Write-MenuOption "12" "Block all outbound (emergency isolation)"
    Write-MenuOption "13" "Reset firewall to defaults"
    Write-Host ""
    Write-Host "  NETWORK ADAPTERS" -ForegroundColor Green
    Write-MenuOption "14" "Disable network adapter"
    Write-MenuOption "15" "Enable network adapter"
    Write-MenuOption "16" "Show network adapters"
    Write-Host ""
    Write-Host "  ADVANCED ACCESS CONTROL" -ForegroundColor Magenta
    Write-MenuOption "17" "Allow port from specific IP (admin access)"
    Write-MenuOption "18" "Block port except from IPs (whitelist inbound)"
    Write-MenuOption "19" "Allow port to specific IP (outbound control)"
    Write-MenuOption "20" "Block port except to IPs (whitelist outbound)"
    Write-Host ""
    Write-Host "  SERVICE RESTRICTIONS" -ForegroundColor Magenta
    Write-MenuOption "21" "Restrict outbound DNS to approved resolvers"
    Write-MenuOption "22" "Restrict outbound SMTP to mail servers"
    Write-Host ""
    Write-Host "  LOGGING" -ForegroundColor Magenta
    Write-MenuOption "23" "Enable firewall logging"
    Write-MenuOption "24" "Disable firewall logging"
    Write-Host ""
    Write-MenuOption "0" "Exit"
    Write-Host ""
    Write-Host "  ================================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Main {
    # Verify running as administrator
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Err "This script must be run as Administrator!"
        exit 1
    }

    # Check if running in CLI mode
    if ($PSCmdlet.ParameterSetName -ne 'Interactive') {
        $script:InteractiveMode = $false

        # Process CLI parameters
        if ($AllowPortFrom) {
            if ($Port -eq 0 -or [string]::IsNullOrWhiteSpace($FromIP)) {
                Write-Err "-AllowPortFrom requires -Port and -FromIP parameters"
                exit 1
            }
            Allow-PortFromIP -PortNum $Port -SourceIP $FromIP
        }
        elseif ($BlockPortExceptFrom) {
            if ($Port -eq 0 -or [string]::IsNullOrWhiteSpace($FromIP)) {
                Write-Err "-BlockPortExceptFrom requires -Port and -FromIP parameters"
                exit 1
            }
            Block-PortExceptFromIP -PortNum $Port -SourceIPs $FromIP
        }
        elseif ($AllowPortTo) {
            if ($Port -eq 0 -or [string]::IsNullOrWhiteSpace($ToIP)) {
                Write-Err "-AllowPortTo requires -Port and -ToIP parameters"
                exit 1
            }
            Allow-PortToIP -PortNum $Port -DestIP $ToIP
        }
        elseif ($BlockPortExceptTo) {
            if ($Port -eq 0 -or [string]::IsNullOrWhiteSpace($ToIP)) {
                Write-Err "-BlockPortExceptTo requires -Port and -ToIP parameters"
                exit 1
            }
            Block-PortExceptToIP -PortNum $Port -DestIPs $ToIP
        }
        elseif ($BlockPortIn) {
            if ($Port -eq 0) {
                Write-Err "-BlockPortIn requires -Port parameter"
                exit 1
            }
            netsh advfirewall firewall add rule name="IR_Block_Inbound_ANY_$Port" dir=in action=block protocol=tcp localport=$Port
            netsh advfirewall firewall add rule name="IR_Block_Inbound_ANY_${Port}_UDP" dir=in action=block protocol=udp localport=$Port
            Write-Success "Blocked inbound port $Port (TCP+UDP)"
        }
        elseif ($BlockPortOut) {
            if ($Port -eq 0) {
                Write-Err "-BlockPortOut requires -Port parameter"
                exit 1
            }
            Block-OutboundPort -PortNum $Port
        }
        elseif (-not [string]::IsNullOrWhiteSpace($RestrictDNS)) {
            if (-not (Test-ValidIPList $RestrictDNS)) {
                exit 1
            }
            Restrict-OutboundDNS -DNSServers $RestrictDNS
        }
        elseif (-not [string]::IsNullOrWhiteSpace($RestrictSMTP)) {
            if (-not (Test-ValidIPList $RestrictSMTP)) {
                exit 1
            }
            Restrict-OutboundSMTP -MailServers $RestrictSMTP
        }
        elseif ($EnableLogging) {
            Enable-FirewallLogging
        }
        elseif ($DisableLogging) {
            Disable-FirewallLogging
        }

        exit 0
    }

    # Interactive mode
    Write-Info "Windows Network Isolation Script initialized"
    Write-Info "Running with Administrator privileges"
    Start-Sleep -Seconds 1

    while ($true) {
        Show-MainMenu

        $choice = Read-Host "Select an option"

        switch ($choice) {
            "1"  { Show-FirewallStatus }
            "2"  { Show-OpenPortsConnections }
            "3"  { Enable-AllFirewallProfiles }
            "4"  { Disable-AllFirewallProfiles }
            "5"  { Block-InboundPort }
            "6"  { Block-OutboundPort }
            "7"  { Block-IPAddress }
            "8"  { Allow-Port }
            "9"  { Allow-IPAddress }
            "10" { Remove-FirewallRule }
            "11" { Block-AllInbound }
            "12" { Block-AllOutbound }
            "13" { Reset-FirewallDefaults }
            "14" { Disable-NetworkAdapter }
            "15" { Enable-NetworkAdapter }
            "16" { Show-NetworkAdapters }
            "17" { Allow-PortFromIP }
            "18" { Block-PortExceptFromIP }
            "19" { Allow-PortToIP }
            "20" { Block-PortExceptToIP }
            "21" { Restrict-OutboundDNS }
            "22" { Restrict-OutboundSMTP }
            "23" { Enable-FirewallLogging }
            "24" { Disable-FirewallLogging }
            "0"  {
                Write-Info "Exiting Network Isolation Script..."
                exit 0
            }
            default {
                Write-Err "Invalid option. Please select 0-24."
                Start-Sleep -Seconds 1
            }
        }
    }
}

# Run main function
Main

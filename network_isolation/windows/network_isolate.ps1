#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Network Isolation Script for Incident Response

.DESCRIPTION
    Interactive PowerShell script for network isolation using Windows Firewall.
    Provides comprehensive firewall management and network adapter control.

.NOTES
    Author: IR Toolkit
    Version: 1.0
    Requires: Administrator privileges
#>

$ErrorActionPreference = "Stop"

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

    try {
        $null = [System.Net.IPAddress]::Parse($IP)
        return $true
    }
    catch {
        return $false
    }
}

function Get-Confirmation {
    param(
        [string]$Message,
        [switch]$Dangerous
    )

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
    Write-Host ""
    Read-Host "Press Enter to continue"
}

# ============================================================================
# Menu Option Functions
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

    $ruleName = "IR_Block_Outbound_${protocol}_${port}"

    if (-not (Get-Confirmation "Block outbound $protocol port $port?")) {
        Write-Info "Operation cancelled"
        Pause-ForUser
        return
    }

    try {
        Write-Info "Creating firewall rule to block outbound $protocol port $port..."

        if ($protocol -eq "ANY") {
            netsh advfirewall firewall add rule name="$ruleName" dir=out action=block protocol=tcp localport=$port
            netsh advfirewall firewall add rule name="${ruleName}_UDP" dir=out action=block protocol=udp localport=$port
        }
        else {
            netsh advfirewall firewall add rule name="$ruleName" dir=out action=block protocol=$protocol localport=$port
        }

        Write-Success "Outbound $protocol port $port blocked successfully"
        Write-Info "Rule name: $ruleName"
    }
    catch {
        Write-Err "Failed to create rule: $_"
    }

    Pause-ForUser
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
            "0"  {
                Write-Info "Exiting Network Isolation Script..."
                exit 0
            }
            default {
                Write-Err "Invalid option. Please select 0-16."
                Start-Sleep -Seconds 1
            }
        }
    }
}

# Run main function
Main

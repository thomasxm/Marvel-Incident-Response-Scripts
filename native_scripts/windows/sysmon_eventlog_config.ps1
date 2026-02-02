#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sysmon & Windows Event Log Configuration Tool for Elastic Agent Ingestion
    No external dependencies - uses native cmdlets only

.DESCRIPTION
    Interactive tool to:
    - Install/configure/uninstall Sysmon with SwiftOnSecurity config
    - Enable Windows Event Log channels for security monitoring
    - Test logging to verify Elastic Agent can ingest events
    - Support offline/air-gapped environments

.PARAMETER LocalSysmonPath
    Optional: Path to local Sysmon.zip for offline install

.PARAMETER LocalConfigPath
    Optional: Path to local Sysmon config XML

.PARAMETER NonInteractive
    Run in non-interactive mode (requires additional parameters)

.PARAMETER Action
    Action to perform in non-interactive mode:
    - InstallSysmon: Install Sysmon with SwiftOnSecurity config
    - EnableLogs: Enable all event log channels
    - Status: Show current status
    - TestAll: Test all logging

.PARAMETER LogSizeMB
    Max log size in MB for event log channels (default: 100, range: 10-1000)

.EXAMPLE
    .\sysmon_eventlog_config.ps1
    Run in interactive mode with menu

.EXAMPLE
    .\sysmon_eventlog_config.ps1 -LocalSysmonPath "C:\Tools\Sysmon.zip" -LocalConfigPath "C:\Tools\sysmonconfig.xml"
    Run in interactive mode with local files for offline/air-gapped environments

.EXAMPLE
    .\sysmon_eventlog_config.ps1 -NonInteractive -Action InstallSysmon
    Install Sysmon non-interactively

.EXAMPLE
    .\sysmon_eventlog_config.ps1 -NonInteractive -Action EnableLogs -LogSizeMB 200
    Enable all event logs with 200MB max size

.NOTES
    Author: IR Toolkit
    Requires: Administrator privileges
    Sysmon download: https://download.sysinternals.com/files/Sysmon.zip
    Config source: SwiftOnSecurity sysmon-config
#>

param(
    [Parameter()]
    [string]$LocalSysmonPath,

    [Parameter()]
    [string]$LocalConfigPath,

    [Parameter()]
    [switch]$NonInteractive,

    [Parameter()]
    [ValidateSet("InstallSysmon", "EnableLogs", "Status", "TestAll", "VerifyEvents")]
    [string]$Action,

    [Parameter()]
    [ValidateRange(10, 1000)]
    [int]$LogSizeMB = 100
)

# Strict mode and error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Configuration variables
$SysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$SwiftOnSecurityConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
$WorkingDirectory = Join-Path $env:TEMP "SysmonSetup"
$ConfigBackupDirectory = Join-Path $WorkingDirectory "ConfigBackups"
$DefaultLogSizeMB = 100

# ============================================================================
# EVENT LOG CHANNEL DEFINITIONS - Organized by Tier and Category
# ============================================================================
# Tier: Essential (default), Recommended, Server
# Each channel has: Name, Description, Category, Tier, MITRE techniques covered
# ============================================================================

# TIER 1: ESSENTIAL CHANNELS (29 channels) - Core IR & Threat Hunting
# These should ALWAYS be enabled for security monitoring
$EssentialChannels = @(
    # === CRITICAL - Core Security Logs ===
    @{ Name = "Security"; Description = "Authentication (4624/4625), Process creation (4688), Privilege use (4672), Account mgmt"; Category = "Critical"; Tier = "Essential"; MITRE = "All tactics" }
    @{ Name = "System"; Description = "Service installs (7045), Driver loads (6), System events"; Category = "Critical"; Tier = "Essential"; MITRE = "T1543, T1068" }
    @{ Name = "Application"; Description = "Application errors, MSI installs, crashes"; Category = "Critical"; Tier = "Essential"; MITRE = "T1204" }

    # === Sysmon ===
    @{ Name = "Microsoft-Windows-Sysmon/Operational"; Description = "Process/Network/File/Registry/DNS events - MOST VALUABLE"; Category = "Sysmon"; Tier = "Essential"; MITRE = "All tactics" }

    # === PowerShell ===
    @{ Name = "Windows PowerShell"; Description = "PowerShell classic engine logging"; Category = "PowerShell"; Tier = "Essential"; MITRE = "T1059.001" }
    @{ Name = "Microsoft-Windows-PowerShell/Operational"; Description = "Script block (4104), Module logging - malicious scripts"; Category = "PowerShell"; Tier = "Essential"; MITRE = "T1059.001" }

    # === Remote Access / Lateral Movement ===
    @{ Name = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"; Description = "RDP session events (21/22/23/24/25)"; Category = "RemoteAccess"; Tier = "Essential"; MITRE = "T1021.001" }
    @{ Name = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"; Description = "RDP connection attempts (1149)"; Category = "RemoteAccess"; Tier = "Essential"; MITRE = "T1021.001" }
    @{ Name = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"; Description = "RDP core transport events"; Category = "RemoteAccess"; Tier = "Essential"; MITRE = "T1021.001" }
    @{ Name = "Microsoft-Windows-SMBServer/Security"; Description = "SMB share access - file server lateral movement"; Category = "RemoteAccess"; Tier = "Essential"; MITRE = "T1021.002" }
    @{ Name = "Microsoft-Windows-SMBClient/Security"; Description = "Outbound SMB connections"; Category = "RemoteAccess"; Tier = "Essential"; MITRE = "T1021.002" }

    # === Network Security ===
    @{ Name = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"; Description = "Firewall rule changes, blocked connections"; Category = "Network"; Tier = "Essential"; MITRE = "T1562.004" }
    @{ Name = "Microsoft-Windows-DNS-Client/Operational"; Description = "DNS queries - C2 detection, tunneling"; Category = "Network"; Tier = "Essential"; MITRE = "T1071.004" }

    # === Authentication ===
    @{ Name = "Microsoft-Windows-NTLM/Operational"; Description = "NTLM auth events - pass-the-hash detection"; Category = "Authentication"; Tier = "Essential"; MITRE = "T1550.002" }

    # === Defense Evasion / Code Integrity ===
    @{ Name = "Microsoft-Windows-Windows Defender/Operational"; Description = "Defender detections (1116/1117), Exclusions (5007)"; Category = "AntiMalware"; Tier = "Essential"; MITRE = "T1562.001" }
    @{ Name = "Microsoft-Windows-CodeIntegrity/Operational"; Description = "Driver/code signing violations"; Category = "CodeIntegrity"; Tier = "Essential"; MITRE = "T1553" }
    @{ Name = "Microsoft-Windows-Security-Mitigations/KernelMode"; Description = "Kernel exploit mitigations triggered"; Category = "CodeIntegrity"; Tier = "Essential"; MITRE = "T1068" }
    @{ Name = "Microsoft-Windows-Security-Mitigations/UserMode"; Description = "User-mode exploit mitigations"; Category = "CodeIntegrity"; Tier = "Essential"; MITRE = "T1203" }

    # === Persistence / Execution ===
    @{ Name = "Microsoft-Windows-TaskScheduler/Operational"; Description = "Scheduled task events (106/140/141/200/201)"; Category = "Persistence"; Tier = "Essential"; MITRE = "T1053.005" }
    @{ Name = "Microsoft-Windows-WMI-Activity/Operational"; Description = "WMI events (5857-5861) - persistence/execution"; Category = "Persistence"; Tier = "Essential"; MITRE = "T1546.003" }
    @{ Name = "Microsoft-Windows-Bits-Client/Operational"; Description = "BITS job abuse for download/persistence"; Category = "Persistence"; Tier = "Essential"; MITRE = "T1197" }
    @{ Name = "Microsoft-Windows-PrintService/Operational"; Description = "Print spooler - PrintNightmare detection"; Category = "Persistence"; Tier = "Essential"; MITRE = "T1547.012" }

    # === AppLocker / Application Control ===
    @{ Name = "Microsoft-Windows-AppLocker/EXE and DLL"; Description = "AppLocker exe/dll allow/block (8002-8007)"; Category = "AppLocker"; Tier = "Essential"; MITRE = "T1562.001" }
    @{ Name = "Microsoft-Windows-AppLocker/MSI and Script"; Description = "AppLocker script/MSI events"; Category = "AppLocker"; Tier = "Essential"; MITRE = "T1059" }
    @{ Name = "Microsoft-Windows-AppLocker/Packaged app-Deployment"; Description = "AppLocker UWP app deployment events"; Category = "AppLocker"; Tier = "Essential"; MITRE = "T1204" }
    @{ Name = "Microsoft-Windows-AppLocker/Packaged app-Execution"; Description = "AppLocker UWP app execution events"; Category = "AppLocker"; Tier = "Essential"; MITRE = "T1204" }

    # === Device / USB / Plug-and-Play ===
    @{ Name = "Microsoft-Windows-Kernel-PnP/Configuration"; Description = "USB/device connections (400/410)"; Category = "Device"; Tier = "Essential"; MITRE = "T1091, T1052" }
    @{ Name = "Microsoft-Windows-DriverFrameworks-UserMode/Operational"; Description = "USB device operations"; Category = "Device"; Tier = "Essential"; MITRE = "T1091" }

    # === Group Policy / Configuration Changes ===
    @{ Name = "Microsoft-Windows-GroupPolicy/Operational"; Description = "GPO application and changes"; Category = "Configuration"; Tier = "Essential"; MITRE = "T1484" }
    @{ Name = "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational"; Description = "Certificate enrollment events"; Category = "Configuration"; Tier = "Essential"; MITRE = "T1553.004" }
)

# TIER 2: RECOMMENDED ADDITIONAL CHANNELS (15 channels) - Enhanced Detection
# High-value channels for advanced threat hunting
$RecommendedChannels = @(
    # === Enhanced Lateral Movement ===
    @{ Name = "Microsoft-Windows-WinRM/Operational"; Description = "PowerShell Remoting/WinRM sessions - PSExec alternative"; Category = "RemoteAccess"; Tier = "Recommended"; MITRE = "T1021.006" }
    @{ Name = "Microsoft-Windows-TerminalServices-RDPClient/Operational"; Description = "OUTBOUND RDP connections - pivoting detection"; Category = "RemoteAccess"; Tier = "Recommended"; MITRE = "T1021.001" }

    # === Enhanced Authentication / Credential Access ===
    @{ Name = "Microsoft-Windows-Kerberos/Operational"; Description = "Kerberos events - Kerberoasting, Golden Ticket"; Category = "Authentication"; Tier = "Recommended"; MITRE = "T1558" }
    @{ Name = "Microsoft-Windows-LSA/Operational"; Description = "LSA operations - credential theft attempts"; Category = "Authentication"; Tier = "Recommended"; MITRE = "T1003" }
    @{ Name = "Microsoft-Windows-Crypto-DPAPI/Operational"; Description = "DPAPI operations - Mimikatz targets this"; Category = "Authentication"; Tier = "Recommended"; MITRE = "T1555" }
    @{ Name = "Microsoft-Windows-CAPI2/Operational"; Description = "Certificate operations - code signing, TLS"; Category = "Authentication"; Tier = "Recommended"; MITRE = "T1553.002" }

    # === Enhanced Defense Evasion ===
    @{ Name = "Microsoft-Windows-DeviceGuard/Operational"; Description = "Device Guard/HVCI events"; Category = "CodeIntegrity"; Tier = "Recommended"; MITRE = "T1562" }
    @{ Name = "Microsoft-Windows-AppID/Operational"; Description = "AppLocker/AppID service events"; Category = "CodeIntegrity"; Tier = "Recommended"; MITRE = "T1562.001" }
    @{ Name = "Microsoft-Windows-Shell-Core/Operational"; Description = "Shell execution, file associations"; Category = "Execution"; Tier = "Recommended"; MITRE = "T1546.001" }
    @{ Name = "Microsoft-Windows-UAC/Operational"; Description = "UAC prompts and bypasses"; Category = "Execution"; Tier = "Recommended"; MITRE = "T1548.002" }
    @{ Name = "Microsoft-Windows-Kernel-ShimEngine/Operational"; Description = "Application shim events - persistence"; Category = "Persistence"; Tier = "Recommended"; MITRE = "T1546.011" }
    @{ Name = "Microsoft-Windows-Kernel-Boot/Operational"; Description = "Boot configuration changes"; Category = "Persistence"; Tier = "Recommended"; MITRE = "T1542" }

    # === Enhanced Network ===
    @{ Name = "Microsoft-Windows-NetworkProfile/Operational"; Description = "Network profile changes"; Category = "Network"; Tier = "Recommended"; MITRE = "T1016" }
    @{ Name = "Microsoft-Windows-WLAN-AutoConfig/Operational"; Description = "WiFi connections - rogue AP detection"; Category = "Network"; Tier = "Recommended"; MITRE = "T1557" }
    @{ Name = "Microsoft-Windows-Dhcp-Client/Admin"; Description = "DHCP client events"; Category = "Network"; Tier = "Recommended"; MITRE = "T1557.003" }

    # === Additional Defender ===
    @{ Name = "Microsoft-Windows-Windows Defender/WHC"; Description = "Defender health/configuration changes"; Category = "AntiMalware"; Tier = "Recommended"; MITRE = "T1562.001" }

    # === Event Forwarding ===
    @{ Name = "ForwardedEvents"; Description = "Windows Event Forwarding collector"; Category = "Collection"; Tier = "Recommended"; MITRE = "N/A" }
)

# TIER 3: SERVER-SPECIFIC CHANNELS - For specific server roles
# Enable based on server role (DC, DNS, Web, Hyper-V, etc.)
$ServerChannels = @(
    # === Domain Controller ===
    @{ Name = "Directory Service"; Description = "Active Directory operations - DC only"; Category = "ActiveDirectory"; Tier = "Server-DC"; MITRE = "T1484, T1003.006" }
    @{ Name = "Microsoft-Windows-Kerberos-Key-Distribution-Center/Operational"; Description = "KDC events - DC only"; Category = "ActiveDirectory"; Tier = "Server-DC"; MITRE = "T1558" }
    @{ Name = "Microsoft-Windows-ActiveDirectory_DomainService/Diagnostic"; Description = "AD DS diagnostic - DC only"; Category = "ActiveDirectory"; Tier = "Server-DC"; MITRE = "T1003.006" }
    @{ Name = "DFS Replication"; Description = "DFS-R events - DC/File servers"; Category = "ActiveDirectory"; Tier = "Server-DC"; MITRE = "T1039" }

    # === DNS Server ===
    @{ Name = "DNS Server"; Description = "DNS Server events - DNS server only"; Category = "DNSServer"; Tier = "Server-DNS"; MITRE = "T1071.004" }
    @{ Name = "Microsoft-Windows-DNSServer/Audit"; Description = "DNS Server audit - DNS server only"; Category = "DNSServer"; Tier = "Server-DNS"; MITRE = "T1071.004" }

    # === DHCP Server ===
    @{ Name = "Microsoft-Windows-DHCP-Server/Operational"; Description = "DHCP Server events"; Category = "DHCPServer"; Tier = "Server-DHCP"; MITRE = "T1557.003" }

    # === Web Server (IIS) ===
    @{ Name = "Microsoft-Windows-IIS-Logging/Logs"; Description = "IIS access logs - web servers"; Category = "WebServer"; Tier = "Server-Web"; MITRE = "T1190" }
    @{ Name = "Microsoft-Windows-HttpService/Log"; Description = "HTTP.sys logs - web servers"; Category = "WebServer"; Tier = "Server-Web"; MITRE = "T1190" }

    # === Remote Desktop Gateway ===
    @{ Name = "Microsoft-Windows-TerminalServices-Gateway/Operational"; Description = "RD Gateway events"; Category = "RemoteAccess"; Tier = "Server-RDG"; MITRE = "T1021.001" }

    # === Hyper-V ===
    @{ Name = "Microsoft-Windows-Hyper-V-Hypervisor-Operational"; Description = "Hyper-V hypervisor events"; Category = "Virtualization"; Tier = "Server-HyperV"; MITRE = "T1564.006" }
    @{ Name = "Microsoft-Windows-Hyper-V-VMMS-Operational"; Description = "Hyper-V VM management"; Category = "Virtualization"; Tier = "Server-HyperV"; MITRE = "T1564.006" }
    @{ Name = "Microsoft-Windows-Hyper-V-Worker-Operational"; Description = "Hyper-V worker process"; Category = "Virtualization"; Tier = "Server-HyperV"; MITRE = "T1564.006" }

    # === Failover Clustering ===
    @{ Name = "Microsoft-Windows-FailoverClustering/Operational"; Description = "Failover cluster events"; Category = "Clustering"; Tier = "Server-Cluster"; MITRE = "T1489" }

    # === File Server ===
    @{ Name = "Microsoft-Windows-SMBServer/Audit"; Description = "SMB Server detailed audit"; Category = "FileServer"; Tier = "Server-File"; MITRE = "T1021.002" }

    # === Certificate Services ===
    @{ Name = "Microsoft-Windows-CertificationAuthority/Operational"; Description = "CA operations - PKI servers"; Category = "PKI"; Tier = "Server-PKI"; MITRE = "T1649" }
)

# Combine all channels for backward compatibility
$EventLogChannels = $EssentialChannels

# All channels combined for reference
$AllChannels = $EssentialChannels + $RecommendedChannels + $ServerChannels

#region Output Functions

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
}

function Write-SubHeader {
    param([string]$Text)
    Write-Host ""
    Write-Host ("-" * 60) -ForegroundColor DarkCyan
    Write-Host "  $Text" -ForegroundColor DarkCyan
    Write-Host ("-" * 60) -ForegroundColor DarkCyan
    Write-Host ""
}

function Write-Info {
    param([string]$Text)
    Write-Host "[*] $Text" -ForegroundColor Blue
}

function Write-Success {
    param([string]$Text)
    Write-Host "[+] $Text" -ForegroundColor Green
}

function Write-Warning2 {
    param([string]$Text)
    Write-Host "[!] $Text" -ForegroundColor Yellow
}

function Write-Error2 {
    param([string]$Text)
    Write-Host "[-] $Text" -ForegroundColor Red
}

function Write-Status {
    param(
        [string]$Label,
        [string]$Value,
        [string]$Color = "White"
    )
    Write-Host "  $($Label.PadRight(20)): " -NoNewline -ForegroundColor Gray
    Write-Host $Value -ForegroundColor $Color
}

function Write-MenuOption {
    param(
        [string]$Key,
        [string]$Description
    )
    Write-Host "  [$Key] " -NoNewline -ForegroundColor Yellow
    Write-Host $Description -ForegroundColor White
}

#endregion

#region Utility Functions

function Initialize-WorkingDirectory {
    if (-not (Test-Path $WorkingDirectory)) {
        New-Item -ItemType Directory -Path $WorkingDirectory -Force | Out-Null
        Write-Info "Created working directory: $WorkingDirectory"
    }
    if (-not (Test-Path $ConfigBackupDirectory)) {
        New-Item -ItemType Directory -Path $ConfigBackupDirectory -Force | Out-Null
    }
}

function Get-UserConfirmation {
    param(
        [string]$Message,
        [string]$RequiredInput = "yes"
    )

    Write-Host ""
    Write-Host $Message -ForegroundColor Yellow
    Write-Host "Type '$RequiredInput' to confirm: " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
    return $response -eq $RequiredInput
}

function Get-UserInput {
    param(
        [string]$Prompt,
        [string]$Default = "",
        [scriptblock]$Validator = $null
    )

    $displayPrompt = if ($Default) { "$Prompt [$Default]" } else { $Prompt }

    do {
        Write-Host "$displayPrompt`: " -NoNewline -ForegroundColor Cyan
        $input = Read-Host

        if ([string]::IsNullOrWhiteSpace($input) -and $Default) {
            $input = $Default
        }

        if ($Validator) {
            $valid = & $Validator $input
            if (-not $valid) {
                Write-Warning2 "Invalid input. Please try again."
                continue
            }
        }

        return $input
    } while ($true)
}

function Get-LogSizeFromUser {
    Write-Host ""
    Write-Info "Enter max log size in MB (10-1000)"

    $validator = {
        param($val)
        $num = 0
        if ([int]::TryParse($val, [ref]$num)) {
            return $num -ge 10 -and $num -le 1000
        }
        return $false
    }

    $size = Get-UserInput -Prompt "Log size MB" -Default $DefaultLogSizeMB.ToString() -Validator $validator
    return [int]$size
}

function Test-InternetConnectivity {
    try {
        $null = Invoke-WebRequest -Uri "https://www.microsoft.com" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

#endregion

#region Sysmon Functions

function Get-SysmonStatus {
    $status = @{
        Installed = $false
        ServiceRunning = $false
        ServiceName = ""
        Version = ""
        ConfigHash = ""
        DriverLoaded = $false
        SchemaVersion = ""
        BinaryPath = ""
    }

    # Check for Sysmon service (could be Sysmon or Sysmon64)
    $sysmonService = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($sysmonService) {
        $status.Installed = $true
        $status.ServiceName = $sysmonService.Name
        $status.ServiceRunning = $sysmonService.Status -eq "Running"

        # Get binary path from service
        $serviceInfo = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($sysmonService.Name)'" -ErrorAction SilentlyContinue
        if ($serviceInfo) {
            $status.BinaryPath = $serviceInfo.PathName -replace '"', ''
        }

        # Try to get version using sysmon -s
        $sysmonExe = $null
        $possiblePaths = @(
            "C:\Windows\Sysmon64.exe",
            "C:\Windows\Sysmon.exe",
            "$env:SystemRoot\Sysmon64.exe",
            "$env:SystemRoot\Sysmon.exe"
        )

        foreach ($path in $possiblePaths) {
            if (Test-Path $path) {
                $sysmonExe = $path
                break
            }
        }

        if ($sysmonExe) {
            try {
                $schemaOutput = & $sysmonExe -s 2>&1
                if ($schemaOutput -match "Schema Version:\s+(\d+\.\d+)") {
                    $status.SchemaVersion = $Matches[1]
                }
            }
            catch { }

            # Get config hash
            try {
                $configOutput = & $sysmonExe -c 2>&1
                if ($configOutput -match "hash=([A-Fa-f0-9]+)") {
                    $status.ConfigHash = $Matches[1].Substring(0, 16) + "..."
                }
            }
            catch { }

            # Get version from file
            try {
                $fileVersion = (Get-Item $sysmonExe).VersionInfo.FileVersion
                $status.Version = $fileVersion
            }
            catch { }
        }

        # Check if driver is loaded using fltmc (filter manager)
        try {
            $fltmcOutput = & fltmc 2>$null
            if ($fltmcOutput -match "SysmonDrv") {
                $status.DriverLoaded = $true
            }
        }
        catch {
            # Fallback to CIM
            $driver = Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name='SysmonDrv'" -ErrorAction SilentlyContinue
            $status.DriverLoaded = $null -ne $driver -and $driver.State -eq "Running"
        }
    }

    return $status
}

function Show-SysmonStatus {
    Write-SubHeader "Sysmon Status"

    $status = Get-SysmonStatus

    if ($status.Installed) {
        Write-Status "Installed" "Yes" "Green"
        Write-Status "Service" $status.ServiceName "Cyan"

        if ($status.ServiceRunning) {
            Write-Status "Service Status" "Running" "Green"
        }
        else {
            Write-Status "Service Status" "Stopped" "Red"
        }

        if ($status.DriverLoaded) {
            Write-Status "Driver Status" "Loaded" "Green"
        }
        else {
            Write-Status "Driver Status" "Not Loaded" "Red"
        }

        if ($status.Version) {
            Write-Status "Version" $status.Version "Cyan"
        }

        if ($status.SchemaVersion) {
            Write-Status "Schema Version" $status.SchemaVersion "Cyan"
        }

        if ($status.ConfigHash) {
            Write-Status "Config Hash" $status.ConfigHash "Cyan"
        }

        if ($status.BinaryPath) {
            Write-Status "Binary Path" $status.BinaryPath "Gray"
        }
    }
    else {
        Write-Status "Installed" "No" "Yellow"
        Write-Info "Sysmon is not installed on this system"
    }
}

function Get-SysmonBinary {
    # Return the appropriate Sysmon binary based on architecture
    $is64Bit = [Environment]::Is64BitOperatingSystem

    $extractPath = Join-Path $WorkingDirectory "Sysmon"

    if ($is64Bit) {
        $binary = Join-Path $extractPath "Sysmon64.exe"
        $altBinary = Join-Path $extractPath "Sysmon64a.exe"
    }
    else {
        $binary = Join-Path $extractPath "Sysmon.exe"
        $altBinary = $null
    }

    # Check for ARM64 variant
    if ($is64Bit -and (Test-Path $altBinary)) {
        # Check if running on ARM
        $arch = $env:PROCESSOR_ARCHITECTURE
        if ($arch -eq "ARM64") {
            return $altBinary
        }
    }

    if (Test-Path $binary) {
        return $binary
    }

    return $null
}

function Download-SysmonFiles {
    param(
        [switch]$DownloadConfig
    )

    Initialize-WorkingDirectory

    $extractPath = Join-Path $WorkingDirectory "Sysmon"
    $zipPath = Join-Path $WorkingDirectory "Sysmon.zip"
    $configPath = Join-Path $WorkingDirectory "sysmonconfig.xml"

    # Download Sysmon
    Write-Info "Downloading Sysmon from Sysinternals..."
    try {
        Invoke-WebRequest -Uri $SysmonUrl -OutFile $zipPath -UseBasicParsing
        Write-Success "Downloaded Sysmon.zip"
    }
    catch {
        Write-Error2 "Failed to download Sysmon: $($_.Exception.Message)"
        return $null
    }

    # Extract
    Write-Info "Extracting Sysmon..."
    try {
        if (Test-Path $extractPath) {
            Remove-Item -Path $extractPath -Recurse -Force
        }
        Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
        Write-Success "Extracted Sysmon files"
    }
    catch {
        Write-Error2 "Failed to extract Sysmon: $($_.Exception.Message)"
        return $null
    }

    # Download config if requested
    if ($DownloadConfig) {
        Write-Info "Downloading SwiftOnSecurity Sysmon config..."
        try {
            Invoke-WebRequest -Uri $SwiftOnSecurityConfigUrl -OutFile $configPath -UseBasicParsing
            Write-Success "Downloaded SwiftOnSecurity config"
        }
        catch {
            Write-Error2 "Failed to download config: $($_.Exception.Message)"
            return $null
        }
    }

    return @{
        ExtractPath = $extractPath
        ConfigPath = if ($DownloadConfig) { $configPath } else { $null }
        ZipPath = $zipPath
    }
}

function Use-LocalSysmonFiles {
    param(
        [string]$SysmonZipPath,
        [string]$ConfigXmlPath
    )

    Initialize-WorkingDirectory

    $extractPath = Join-Path $WorkingDirectory "Sysmon"

    # Validate Sysmon zip
    if (-not (Test-Path $SysmonZipPath)) {
        Write-Error2 "Sysmon zip not found: $SysmonZipPath"
        return $null
    }

    # Extract
    Write-Info "Extracting Sysmon from local file..."
    try {
        if (Test-Path $extractPath) {
            Remove-Item -Path $extractPath -Recurse -Force
        }
        Expand-Archive -Path $SysmonZipPath -DestinationPath $extractPath -Force
        Write-Success "Extracted Sysmon files"
    }
    catch {
        Write-Error2 "Failed to extract Sysmon: $($_.Exception.Message)"
        return $null
    }

    # Validate config if provided
    $configPath = $null
    if ($ConfigXmlPath) {
        if (-not (Test-Path $ConfigXmlPath)) {
            Write-Error2 "Config file not found: $ConfigXmlPath"
            return $null
        }
        # Copy config to working directory (skip if already there)
        $configPath = Join-Path $WorkingDirectory "sysmonconfig.xml"
        $sourceFullPath = (Resolve-Path $ConfigXmlPath).Path
        $destFullPath = $configPath
        if ($sourceFullPath -ne $destFullPath) {
            Copy-Item -Path $ConfigXmlPath -Destination $configPath -Force
            Write-Success "Copied config file"
        }
        else {
            Write-Info "Using existing config in working directory"
        }
    }

    return @{
        ExtractPath = $extractPath
        ConfigPath = $configPath
        ZipPath = $SysmonZipPath
    }
}

function Install-Sysmon {
    param(
        [switch]$UseLocalFiles,
        [string]$LocalSysmonZip,
        [string]$LocalConfigXml,
        [string]$CustomConfigPath
    )

    Write-Header "Install Sysmon"

    # Check if already installed
    $status = Get-SysmonStatus
    if ($status.Installed) {
        Write-Warning2 "Sysmon is already installed"
        if (-not (Get-UserConfirmation "Do you want to reinstall Sysmon? This will uninstall the current version first." "yes")) {
            return $false
        }
        Uninstall-Sysmon -SkipConfirmation
    }

    # Get files
    $files = $null
    if ($UseLocalFiles) {
        $files = Use-LocalSysmonFiles -SysmonZipPath $LocalSysmonZip -ConfigXmlPath $LocalConfigXml
    }
    else {
        $files = Download-SysmonFiles -DownloadConfig:(-not $CustomConfigPath)
    }

    if (-not $files) {
        Write-Error2 "Failed to prepare Sysmon files"
        return $false
    }

    # Determine config path
    $configToUse = $null
    if ($CustomConfigPath) {
        if (-not (Test-Path $CustomConfigPath)) {
            Write-Error2 "Custom config not found: $CustomConfigPath"
            return $false
        }
        $configToUse = $CustomConfigPath
        Write-Info "Using custom config: $CustomConfigPath"
    }
    elseif ($files.ConfigPath) {
        $configToUse = $files.ConfigPath
        Write-Info "Using SwiftOnSecurity config"
    }
    else {
        Write-Error2 "No configuration file available"
        return $false
    }

    # Get binary
    $sysmonExe = Get-SysmonBinary
    if (-not $sysmonExe) {
        Write-Error2 "Sysmon binary not found in extracted files"
        return $false
    }

    Write-Info "Using: $(Split-Path $sysmonExe -Leaf)"

    # Backup config for reset functionality
    $backupPath = Join-Path $ConfigBackupDirectory "initial_config_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"
    Copy-Item -Path $configToUse -Destination $backupPath -Force
    Write-Info "Backed up initial config to: $backupPath"

    # Install Sysmon
    Write-Info "Installing Sysmon..."
    try {
        $installArgs = @("-accepteula", "-i", $configToUse)
        $process = Start-Process -FilePath $sysmonExe -ArgumentList $installArgs -Wait -PassThru -NoNewWindow

        if ($process.ExitCode -eq 0) {
            Write-Success "Sysmon installed successfully"

            # Verify installation
            Start-Sleep -Seconds 2
            $newStatus = Get-SysmonStatus
            if ($newStatus.ServiceRunning) {
                Write-Success "Sysmon service is running"
            }
            else {
                Write-Warning2 "Sysmon service may not be running. Check Event Viewer for details."
            }

            return $true
        }
        else {
            Write-Error2 "Sysmon installation failed with exit code: $($process.ExitCode)"
            return $false
        }
    }
    catch {
        Write-Error2 "Failed to install Sysmon: $($_.Exception.Message)"
        return $false
    }
}

function Uninstall-Sysmon {
    param(
        [switch]$SkipConfirmation
    )

    Write-Header "Uninstall Sysmon"

    $status = Get-SysmonStatus
    if (-not $status.Installed) {
        Write-Warning2 "Sysmon is not installed"
        return $false
    }

    if (-not $SkipConfirmation) {
        Write-Host ""
        Write-Host "WARNING: This will completely remove Sysmon from the system." -ForegroundColor Red
        Write-Host "All Sysmon event logging will stop immediately." -ForegroundColor Red
        Write-Host ""

        if (-not (Get-UserConfirmation "Are you absolutely sure you want to uninstall Sysmon?" "YES")) {
            Write-Info "Uninstall cancelled"
            return $false
        }
    }

    # Find Sysmon executable
    $sysmonExe = $null
    $possiblePaths = @(
        "C:\Windows\Sysmon64.exe",
        "C:\Windows\Sysmon.exe",
        "$env:SystemRoot\Sysmon64.exe",
        "$env:SystemRoot\Sysmon.exe"
    )

    foreach ($path in $possiblePaths) {
        if (Test-Path $path) {
            $sysmonExe = $path
            break
        }
    }

    # Also check working directory
    if (-not $sysmonExe) {
        $sysmonExe = Get-SysmonBinary
    }

    if (-not $sysmonExe) {
        Write-Error2 "Cannot find Sysmon executable to uninstall"
        return $false
    }

    Write-Info "Uninstalling Sysmon..."
    try {
        $process = Start-Process -FilePath $sysmonExe -ArgumentList "-u", "force" -Wait -PassThru -NoNewWindow

        if ($process.ExitCode -eq 0) {
            Write-Success "Sysmon uninstalled successfully"
            return $true
        }
        else {
            Write-Error2 "Sysmon uninstall failed with exit code: $($process.ExitCode)"
            return $false
        }
    }
    catch {
        Write-Error2 "Failed to uninstall Sysmon: $($_.Exception.Message)"
        return $false
    }
}

function Update-SysmonConfig {
    param(
        [string]$ConfigPath
    )

    Write-Header "Update Sysmon Configuration"

    $status = Get-SysmonStatus
    if (-not $status.Installed) {
        Write-Error2 "Sysmon is not installed"
        return $false
    }

    if (-not $ConfigPath) {
        Write-Info "Enter path to new configuration file"
        $ConfigPath = Get-UserInput -Prompt "Config path"
    }

    if (-not (Test-Path $ConfigPath)) {
        Write-Error2 "Config file not found: $ConfigPath"
        return $false
    }

    # Backup current config
    Initialize-WorkingDirectory
    $backupPath = Join-Path $ConfigBackupDirectory "config_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"

    # Find Sysmon executable
    $sysmonExe = $null
    $possiblePaths = @(
        "C:\Windows\Sysmon64.exe",
        "C:\Windows\Sysmon.exe"
    )

    foreach ($path in $possiblePaths) {
        if (Test-Path $path) {
            $sysmonExe = $path
            break
        }
    }

    if (-not $sysmonExe) {
        Write-Error2 "Cannot find Sysmon executable"
        return $false
    }

    Write-Info "Updating Sysmon configuration..."
    try {
        $process = Start-Process -FilePath $sysmonExe -ArgumentList "-c", $ConfigPath -Wait -PassThru -NoNewWindow

        if ($process.ExitCode -eq 0) {
            Write-Success "Sysmon configuration updated"
            return $true
        }
        else {
            Write-Error2 "Config update failed with exit code: $($process.ExitCode)"
            return $false
        }
    }
    catch {
        Write-Error2 "Failed to update config: $($_.Exception.Message)"
        return $false
    }
}

function Reset-SysmonConfig {
    Write-Header "Reset Sysmon Configuration"

    $status = Get-SysmonStatus
    if (-not $status.Installed) {
        Write-Error2 "Sysmon is not installed"
        return $false
    }

    # Look for initial config backup
    $backups = Get-ChildItem -Path $ConfigBackupDirectory -Filter "initial_config_*.xml" -ErrorAction SilentlyContinue |
               Sort-Object LastWriteTime -Descending

    $configToUse = $null

    if ($backups) {
        $configToUse = $backups[0].FullName
        Write-Info "Found initial config backup: $($backups[0].Name)"
    }
    else {
        Write-Warning2 "No initial config backup found"
        Write-Info "Downloading fresh SwiftOnSecurity config..."

        if (-not (Test-InternetConnectivity)) {
            Write-Error2 "No internet connectivity and no backup config available"
            return $false
        }

        Initialize-WorkingDirectory
        $configToUse = Join-Path $WorkingDirectory "sysmonconfig_reset.xml"

        try {
            Invoke-WebRequest -Uri $SwiftOnSecurityConfigUrl -OutFile $configToUse -UseBasicParsing
            Write-Success "Downloaded SwiftOnSecurity config"
        }
        catch {
            Write-Error2 "Failed to download config: $($_.Exception.Message)"
            return $false
        }
    }

    return Update-SysmonConfig -ConfigPath $configToUse
}

function Test-SysmonLogging {
    Write-Header "Test Sysmon Logging"

    $status = Get-SysmonStatus
    if (-not $status.Installed) {
        Write-Error2 "Sysmon is not installed"
        return $false
    }

    if (-not $status.ServiceRunning) {
        Write-Error2 "Sysmon service is not running"
        return $false
    }

    Write-Info "Checking Sysmon event log..."

    try {
        $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 -ErrorAction Stop

        Write-Success "Sysmon is generating events"
        Write-Host ""
        Write-Status "Total events queried" $events.Count.ToString() "Cyan"

        if ($events.Count -gt 0) {
            $latestEvent = $events[0]
            Write-Status "Latest event time" $latestEvent.TimeCreated.ToString() "Cyan"
            Write-Status "Latest event ID" $latestEvent.Id.ToString() "Cyan"

            # Count event types
            $eventTypes = $events | Group-Object -Property Id
            Write-Host ""
            Write-Info "Event types in sample:"
            foreach ($type in $eventTypes) {
                $eventName = switch ($type.Name) {
                    1 { "Process Create" }
                    2 { "File creation time changed" }
                    3 { "Network connection" }
                    5 { "Process terminated" }
                    7 { "Image loaded" }
                    8 { "CreateRemoteThread" }
                    9 { "RawAccessRead" }
                    10 { "ProcessAccess" }
                    11 { "FileCreate" }
                    12 { "Registry object added/deleted" }
                    13 { "Registry value set" }
                    14 { "Registry key/value renamed" }
                    15 { "FileCreateStreamHash" }
                    17 { "Pipe created" }
                    18 { "Pipe connected" }
                    22 { "DNS query" }
                    23 { "FileDelete (archived)" }
                    24 { "Clipboard capture" }
                    25 { "Process tampering" }
                    26 { "FileDeleteDetected" }
                    default { "Event $($type.Name)" }
                }
                Write-Host "    Event $($type.Name) ($eventName): $($type.Count)" -ForegroundColor Gray
            }
        }

        return $true
    }
    catch [System.Exception] {
        if ($_.Exception.Message -match "No events were found") {
            Write-Warning2 "No Sysmon events found in the log"
            Write-Info "This could mean:"
            Write-Host "    - Sysmon was just installed and no events generated yet" -ForegroundColor Gray
            Write-Host "    - The Sysmon configuration is filtering all events" -ForegroundColor Gray
            Write-Host "    - There's an issue with the Sysmon service" -ForegroundColor Gray
        }
        else {
            Write-Error2 "Failed to query Sysmon events: $($_.Exception.Message)"
        }
        return $false
    }
}

function Test-SysmonEventGeneration {
    <#
    .SYNOPSIS
        Generates test activities and verifies Sysmon captures them
    .DESCRIPTION
        Creates controlled test activities to verify Sysmon event capture:
        - Event ID 1: Process Create (runs whoami)
        - Event ID 3: Network Connection (HTTP request)
        - Event ID 11: File Create (creates temp file)
        - Event ID 12/13: Registry modification
        - Event ID 22: DNS Query (resolves hostname)
    #>

    Write-Header "Sysmon Event Generation Test"

    $status = Get-SysmonStatus
    if (-not $status.Installed -or -not $status.ServiceRunning) {
        Write-Error2 "Sysmon must be installed and running for this test"
        return $false
    }

    # Record start time for filtering
    $testStartTime = Get-Date
    Write-Info "Test start time: $testStartTime"
    Write-Host ""

    # Define test activities
    $testResults = @()

    # Test 1: Process Create (Event ID 1)
    Write-Info "Generating Event ID 1 (Process Create)..."
    try {
        $null = & whoami 2>$null
        $testResults += @{ EventId = 1; Name = "Process Create"; Generated = $true; Activity = "Executed whoami.exe" }
        Write-Success "  Executed test process (whoami)"
    }
    catch {
        $testResults += @{ EventId = 1; Name = "Process Create"; Generated = $false; Activity = "Failed" }
        Write-Error2 "  Failed to execute test process"
    }

    # Test 2: Network Connection (Event ID 3)
    Write-Info "Generating Event ID 3 (Network Connection)..."
    try {
        $null = Test-NetConnection -ComputerName "www.microsoft.com" -Port 443 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        $testResults += @{ EventId = 3; Name = "Network Connection"; Generated = $true; Activity = "TCP connection to microsoft.com:443" }
        Write-Success "  Made test network connection"
    }
    catch {
        # Fallback: try simple HTTP request
        try {
            $null = Invoke-WebRequest -Uri "https://www.microsoft.com" -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
            $testResults += @{ EventId = 3; Name = "Network Connection"; Generated = $true; Activity = "HTTPS request to microsoft.com" }
            Write-Success "  Made test network connection (HTTP)"
        }
        catch {
            $testResults += @{ EventId = 3; Name = "Network Connection"; Generated = $false; Activity = "Network test failed" }
            Write-Warning2 "  Network connection test failed (may be blocked)"
        }
    }

    # Test 3: File Create (Event ID 11)
    Write-Info "Generating Event ID 11 (File Create)..."
    $testFilePath = Join-Path $env:TEMP "sysmon_test_$([guid]::NewGuid().ToString('N').Substring(0,8)).txt"
    try {
        "Sysmon test file - $(Get-Date)" | Out-File -FilePath $testFilePath -Force
        $testResults += @{ EventId = 11; Name = "File Create"; Generated = $true; Activity = "Created $testFilePath" }
        Write-Success "  Created test file"
        # Clean up
        Remove-Item -Path $testFilePath -Force -ErrorAction SilentlyContinue
    }
    catch {
        $testResults += @{ EventId = 11; Name = "File Create"; Generated = $false; Activity = "Failed" }
        Write-Error2 "  Failed to create test file"
    }

    # Test 4: Registry modification (Event ID 12/13)
    Write-Info "Generating Event ID 12/13 (Registry Set)..."
    $testRegPath = "HKCU:\Software\SysmonTest"
    try {
        # Create key (Event 12)
        New-Item -Path $testRegPath -Force -ErrorAction Stop | Out-Null
        # Set value (Event 13)
        Set-ItemProperty -Path $testRegPath -Name "TestValue" -Value "SysmonTest_$(Get-Date -Format 'yyyyMMddHHmmss')" -ErrorAction Stop
        $testResults += @{ EventId = 12; Name = "Registry Create"; Generated = $true; Activity = "Created $testRegPath" }
        $testResults += @{ EventId = 13; Name = "Registry Set"; Generated = $true; Activity = "Set TestValue" }
        Write-Success "  Modified test registry key"
        # Clean up
        Remove-Item -Path $testRegPath -Force -Recurse -ErrorAction SilentlyContinue
    }
    catch {
        $testResults += @{ EventId = 12; Name = "Registry Create"; Generated = $false; Activity = "Failed" }
        Write-Warning2 "  Registry test failed: $($_.Exception.Message)"
    }

    # Test 5: DNS Query (Event ID 22)
    Write-Info "Generating Event ID 22 (DNS Query)..."
    try {
        $null = Resolve-DnsName -Name "sysmontest.microsoft.com" -ErrorAction SilentlyContinue
        $testResults += @{ EventId = 22; Name = "DNS Query"; Generated = $true; Activity = "Queried sysmontest.microsoft.com" }
        Write-Success "  Performed DNS query"
    }
    catch {
        # Even failed queries should be logged
        $testResults += @{ EventId = 22; Name = "DNS Query"; Generated = $true; Activity = "DNS query (may have failed)" }
        Write-Success "  DNS query attempted"
    }

    # Wait for events to be logged
    Write-Host ""
    Write-Info "Waiting 3 seconds for events to be logged..."
    Start-Sleep -Seconds 3

    # Verify events were captured
    Write-Host ""
    Write-SubHeader "Verifying Captured Events"

    $verificationResults = @()
    $eventIdsToCheck = @(1, 3, 11, 12, 13, 22)

    foreach ($eventId in $eventIdsToCheck) {
        $eventName = switch ($eventId) {
            1 { "Process Create" }
            3 { "Network Connection" }
            11 { "File Create" }
            12 { "Registry Add/Delete" }
            13 { "Registry Set" }
            22 { "DNS Query" }
            default { "Event $eventId" }
        }

        try {
            # Query for events of this type since test started using FilterHashtable
            $filterHash = @{
                LogName = "Microsoft-Windows-Sysmon/Operational"
                Id = $eventId
                StartTime = $testStartTime
            }
            $events = Get-WinEvent -FilterHashtable $filterHash -MaxEvents 10 -ErrorAction SilentlyContinue

            if ($events -and @($events).Count -gt 0) {
                $eventCount = @($events).Count
                $verificationResults += @{ EventId = $eventId; Name = $eventName; Captured = $true; Count = $eventCount }
                Write-Success "  Event ID $eventId ($eventName): $eventCount events captured"
            }
            else {
                $verificationResults += @{ EventId = $eventId; Name = $eventName; Captured = $false; Count = 0 }
                Write-Warning2 "  Event ID $eventId ($eventName): No events captured (may be filtered by config)"
            }
        }
        catch {
            $verificationResults += @{ EventId = $eventId; Name = $eventName; Captured = $false; Count = 0 }
            Write-Warning2 "  Event ID $eventId ($eventName): No events captured (may be filtered by config)"
        }
    }

    # Summary
    Write-Host ""
    Write-SubHeader "Test Summary"

    $capturedCount = ($verificationResults | Where-Object { $_.Captured }).Count
    $totalTests = $verificationResults.Count

    Write-Host ""
    Write-Host ("{0,-8} {1,-25} {2,-10} {3,-10}" -f "EventID", "Event Type", "Captured", "Count") -ForegroundColor Cyan
    Write-Host ("{0,-8} {1,-25} {2,-10} {3,-10}" -f "-------", "----------", "--------", "-----") -ForegroundColor DarkGray

    foreach ($result in $verificationResults) {
        $capturedText = if ($result.Captured) { "Yes" } else { "No" }
        $color = if ($result.Captured) { "Green" } else { "Yellow" }
        Write-Host ("{0,-8} {1,-25} " -f $result.EventId, $result.Name) -NoNewline
        Write-Host ("{0,-10} " -f $capturedText) -NoNewline -ForegroundColor $color
        Write-Host ("{0,-10}" -f $result.Count) -ForegroundColor Gray
    }

    Write-Host ""
    if ($capturedCount -eq $totalTests) {
        Write-Success "All $totalTests event types are being captured"
        return $true
    }
    elseif ($capturedCount -gt 0) {
        Write-Warning2 "$capturedCount of $totalTests event types captured"
        Write-Info "Some events may be filtered by the Sysmon configuration"
        Write-Info "This is normal - SwiftOnSecurity config filters low-value events"
        return $true
    }
    else {
        Write-Error2 "No events were captured - check Sysmon configuration"
        return $false
    }
}

#endregion

#region Event Log Functions

function Get-EventLogChannelStatus {
    param(
        [string]$ChannelName
    )

    $status = @{
        Name = $ChannelName
        Exists = $false
        Enabled = $false
        MaxSize = 0
        MaxSizeMB = 0
        RecordCount = 0
        LastEvent = $null
        Status = "Unknown"
    }

    # Use wevtutil to get channel info
    $ErrorActionPreference = "SilentlyContinue"
    $output = & wevtutil gl $ChannelName 2>&1
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = "Stop"
    $outputString = if ($output) { ($output | Where-Object { $_ -is [string] }) -join "`n" } else { "" }

    if ($exitCode -eq 0) {
        $status.Exists = $true

        # Parse enabled status
        $enabledMatch = [regex]::Match($outputString, "enabled:\s*(true|false)", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($enabledMatch.Success) {
            $status.Enabled = $enabledMatch.Groups[1].Value -eq "true"
        }

        # Parse max size
        $sizeMatch = [regex]::Match($outputString, "maxSize:\s*(\d+)")
        if ($sizeMatch.Success) {
            $status.MaxSize = [long]$sizeMatch.Groups[1].Value
            $status.MaxSizeMB = [math]::Round($status.MaxSize / 1MB, 2)
        }

        # Get total count first (this doesn't fail if no events)
        try {
            $logInfo = Get-WinEvent -ListLog $ChannelName -ErrorAction SilentlyContinue
            if ($logInfo) {
                $status.RecordCount = $logInfo.RecordCount
            }
        }
        catch {
            # Access denied or other error
        }

        # Try to get last event time
        try {
            $events = Get-WinEvent -LogName $ChannelName -MaxEvents 1 -ErrorAction Stop
            if ($events -and $events.Count -gt 0) {
                $status.LastEvent = $events[0].TimeCreated
            }
        }
        catch {
            # No events or access denied
        }

        $status.Status = if ($status.Enabled) { "Enabled" } else { "Disabled" }
    }
    else {
        # Check if it's a Sysmon channel - will only exist when Sysmon is installed
        if ($ChannelName -like "*Sysmon*") {
            $status.Status = "Not Installed"
        }
        else {
            $status.Status = "Not Found"
        }
    }

    return $status
}

function Show-EventLogStatus {
    Write-SubHeader "Event Log Channel Status"

    $results = @()

    foreach ($channel in $EventLogChannels) {
        $status = Get-EventLogChannelStatus -ChannelName $channel.Name
        $results += $status
    }

    # Display as table
    Write-Host ""
    Write-Host ("{0,-55} {1,-10} {2,-10} {3,-15}" -f "Channel", "Status", "Size (MB)", "Events") -ForegroundColor Cyan
    Write-Host ("{0,-55} {1,-10} {2,-10} {3,-15}" -f "-------", "------", "---------", "------") -ForegroundColor DarkGray

    foreach ($result in $results) {
        $statusColor = switch ($result.Status) {
            "Enabled" { "Green" }
            "Disabled" { "Yellow" }
            "Not Found" { "Red" }
            default { "Gray" }
        }

        $displayName = if ($result.Name.Length -gt 52) {
            $result.Name.Substring(0, 49) + "..."
        } else {
            $result.Name
        }

        Write-Host ("{0,-55} " -f $displayName) -NoNewline
        Write-Host ("{0,-10} " -f $result.Status) -NoNewline -ForegroundColor $statusColor
        Write-Host ("{0,-10} " -f $result.MaxSizeMB) -NoNewline -ForegroundColor Cyan
        Write-Host ("{0,-15}" -f $result.RecordCount) -ForegroundColor Gray
    }

    Write-Host ""

    # Summary
    $enabledChannels = @($results | Where-Object { $_.Enabled })
    $enabledCount = $enabledChannels.Count
    $totalCount = $results.Count

    if ($enabledCount -eq $totalCount) {
        Write-Success "All $totalCount channels are enabled"
    }
    else {
        Write-Warning2 "$enabledCount of $totalCount channels are enabled"
    }

    return $results
}

function Enable-EventLogChannel {
    param(
        [string]$ChannelName,
        [int]$MaxSizeMB
    )

    Write-Info "Configuring: $ChannelName"

    # Classic logs that use Limit-EventLog API
    $classicLogs = @("Security", "System", "Application", "Windows PowerShell")

    if ($ChannelName -in $classicLogs) {
        try {
            # Classic logs use different API - use Limit-EventLog
            $maxSizeKB = $MaxSizeMB * 1024
            Limit-EventLog -LogName $ChannelName -MaximumSize ($maxSizeKB * 1KB) -ErrorAction Stop
            Write-Success "  Configured classic log with max size: ${MaxSizeMB}MB"
            return $true
        }
        catch {
            # If Limit-EventLog fails, try wevtutil for max size only
            $ErrorActionPreference = "SilentlyContinue"
            $maxSizeBytes = $MaxSizeMB * 1048576
            $null = & wevtutil sl $ChannelName /ms:$maxSizeBytes 2>&1
            $ErrorActionPreference = "Stop"
            Write-Success "  Classic log already enabled, set max size: ${MaxSizeMB}MB"
            return $true
        }
    }

    # Check if channel exists
    $status = Get-EventLogChannelStatus -ChannelName $ChannelName

    if (-not $status.Exists) {
        # Special message for Sysmon
        if ($ChannelName -like "*Sysmon*") {
            Write-Warning2 "Sysmon channel not available (install Sysmon first)"
        }
        else {
            Write-Warning2 "Channel does not exist: $ChannelName"
        }
        return $false
    }

    $success = $true
    $ErrorActionPreference = "SilentlyContinue"

    # Enable the channel
    $output = & wevtutil sl $ChannelName /e:true 2>&1
    if ($LASTEXITCODE -ne 0) {
        $errorStr = ($output | Where-Object { $_ -is [string] }) -join " "
        Write-Warning2 "Failed to enable channel: $errorStr"
        $success = $false
    }

    # Set max size
    $maxSizeBytes = $MaxSizeMB * 1048576
    $output = & wevtutil sl $ChannelName /ms:$maxSizeBytes 2>&1
    if ($LASTEXITCODE -ne 0) {
        $errorStr = ($output | Where-Object { $_ -is [string] }) -join " "
        Write-Warning2 "Failed to set max size: $errorStr"
        $success = $false
    }

    $ErrorActionPreference = "Stop"

    if ($success) {
        Write-Success "  Enabled with max size: ${MaxSizeMB}MB"
    }

    return $success
}

function Enable-AllEventLogs {
    param(
        [int]$MaxSizeMB
    )

    Write-Header "Enable All Event Log Channels"

    if (-not $MaxSizeMB) {
        $MaxSizeMB = Get-LogSizeFromUser
    }

    Write-Info "Configuring channels with max size: ${MaxSizeMB}MB"
    Write-Host ""

    $successCount = 0
    $failCount = 0

    foreach ($channel in $EventLogChannels) {
        $result = Enable-EventLogChannel -ChannelName $channel.Name -MaxSizeMB $MaxSizeMB
        if ($result) {
            $successCount++
        }
        else {
            $failCount++
        }
    }

    Write-Host ""
    Write-Success "Successfully configured: $successCount channels"
    if ($failCount -gt 0) {
        Write-Warning2 "Failed to configure: $failCount channels"
    }

    return $failCount -eq 0
}

function Enable-SingleEventLog {
    Write-Header "Enable Individual Event Log Channel"

    Write-Host ""
    for ($i = 0; $i -lt $EventLogChannels.Count; $i++) {
        Write-MenuOption ($i + 1).ToString() "$($EventLogChannels[$i].Name)"
        Write-Host "      $($EventLogChannels[$i].Description)" -ForegroundColor Gray
    }

    Write-Host ""
    $selection = Get-UserInput -Prompt "Select channel (1-$($EventLogChannels.Count))"

    $index = 0
    if ([int]::TryParse($selection, [ref]$index) -and $index -ge 1 -and $index -le $EventLogChannels.Count) {
        $channel = $EventLogChannels[$index - 1]
        $maxSize = Get-LogSizeFromUser

        return Enable-EventLogChannel -ChannelName $channel.Name -MaxSizeMB $maxSize
    }
    else {
        Write-Warning2 "Invalid selection"
        return $false
    }
}

function Enable-RecommendedChannels {
    param([int]$MaxSizeMB)

    Write-Header "Enable Recommended Additional Channels"

    Write-Info "These channels provide enhanced threat detection capabilities"
    Write-Host ""

    if (-not $MaxSizeMB) {
        $MaxSizeMB = Get-LogSizeFromUser
    }

    Write-Info "Configuring recommended channels with max size: ${MaxSizeMB}MB"
    Write-Host ""

    $successCount = 0
    $failCount = 0
    $skippedCount = 0

    foreach ($channel in $RecommendedChannels) {
        $result = Enable-EventLogChannel -ChannelName $channel.Name -MaxSizeMB $MaxSizeMB
        if ($result -eq $true) {
            $successCount++
        }
        elseif ($result -eq $false) {
            $failCount++
        }
        else {
            $skippedCount++
        }
    }

    Write-Host ""
    Write-Success "Successfully configured: $successCount channels"
    if ($failCount -gt 0) {
        Write-Warning2 "Failed/unavailable: $failCount channels"
    }

    return $failCount -eq 0
}

function Enable-ServerChannels {
    param([int]$MaxSizeMB)

    Write-Header "Enable Server-Specific Channels"

    Write-Info "Select server role(s) to enable appropriate channels:"
    Write-Host ""

    # Group channels by server role
    $serverRoles = @{
        "1" = @{ Name = "Domain Controller"; Tier = "Server-DC"; Description = "AD DS, Kerberos KDC, DFS-R" }
        "2" = @{ Name = "DNS Server"; Tier = "Server-DNS"; Description = "DNS Server audit and logging" }
        "3" = @{ Name = "DHCP Server"; Tier = "Server-DHCP"; Description = "DHCP Server operations" }
        "4" = @{ Name = "Web Server (IIS)"; Tier = "Server-Web"; Description = "IIS logging, HTTP.sys" }
        "5" = @{ Name = "RD Gateway"; Tier = "Server-RDG"; Description = "Remote Desktop Gateway" }
        "6" = @{ Name = "Hyper-V Host"; Tier = "Server-HyperV"; Description = "Hyper-V hypervisor and VM management" }
        "7" = @{ Name = "Failover Cluster"; Tier = "Server-Cluster"; Description = "Failover clustering" }
        "8" = @{ Name = "File Server"; Tier = "Server-File"; Description = "SMB Server detailed audit" }
        "9" = @{ Name = "PKI/Certificate Authority"; Tier = "Server-PKI"; Description = "Certificate Services" }
        "A" = @{ Name = "ALL Server Channels"; Tier = "ALL"; Description = "Enable all server channels" }
    }

    foreach ($key in ($serverRoles.Keys | Sort-Object)) {
        $role = $serverRoles[$key]
        Write-MenuOption $key "$($role.Name)"
        Write-Host "      $($role.Description)" -ForegroundColor Gray
    }
    Write-Host ""
    Write-MenuOption "0" "Back"
    Write-Host ""

    $selection = Get-UserInput -Prompt "Select server role"

    if ($selection -eq "0") {
        return $false
    }

    if (-not $serverRoles.ContainsKey($selection.ToUpper())) {
        Write-Warning2 "Invalid selection"
        return $false
    }

    if (-not $MaxSizeMB) {
        $MaxSizeMB = Get-LogSizeFromUser
    }

    $selectedRole = $serverRoles[$selection.ToUpper()]
    $channelsToEnable = @()

    if ($selectedRole.Tier -eq "ALL") {
        $channelsToEnable = $ServerChannels
        Write-Info "Enabling ALL server channels..."
    }
    else {
        $channelsToEnable = $ServerChannels | Where-Object { $_.Tier -eq $selectedRole.Tier }
        Write-Info "Enabling channels for: $($selectedRole.Name)..."
    }

    Write-Host ""

    $successCount = 0
    $failCount = 0

    foreach ($channel in $channelsToEnable) {
        $result = Enable-EventLogChannel -ChannelName $channel.Name -MaxSizeMB $MaxSizeMB
        if ($result) {
            $successCount++
        }
        else {
            $failCount++
        }
    }

    Write-Host ""
    Write-Success "Successfully configured: $successCount channels"
    if ($failCount -gt 0) {
        Write-Warning2 "Failed/unavailable: $failCount channels (normal if role not installed)"
    }

    return $true
}

function Export-ElasticAgentConfig {
    Write-Header "Export Elastic Agent Configuration"

    Write-Info "This generates a YAML snippet for Elastic Agent policy"
    Write-Host ""

    # Determine output file
    $defaultPath = Join-Path (Get-Location) "elastic_windows_channels.yml"
    Write-Host "Output file [$defaultPath]: " -NoNewline -ForegroundColor Cyan
    $outputPath = Read-Host
    if ([string]::IsNullOrWhiteSpace($outputPath)) {
        $outputPath = $defaultPath
    }

    # Ask which tiers to include
    Write-Host ""
    Write-Info "Select which channel tiers to include:"
    Write-MenuOption "1" "Essential only (29 channels)"
    Write-MenuOption "2" "Essential + Recommended (44 channels)"
    Write-MenuOption "3" "All channels including Server-specific (60+ channels)"
    Write-Host ""

    $tierSelection = Get-UserInput -Prompt "Select tier"

    $channelsToExport = @()
    switch ($tierSelection) {
        "1" { $channelsToExport = $EssentialChannels }
        "2" { $channelsToExport = $EssentialChannels + $RecommendedChannels }
        "3" { $channelsToExport = $EssentialChannels + $RecommendedChannels + $ServerChannels }
        default {
            Write-Warning2 "Invalid selection, using Essential only"
            $channelsToExport = $EssentialChannels
        }
    }

    # Generate YAML content
    $yamlContent = @"
# ============================================================================
# Elastic Agent - Windows Event Log Channels Configuration
# Generated by: sysmon_eventlog_config.ps1
# Generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
# Total channels: $($channelsToExport.Count)
# ============================================================================
#
# USAGE:
# 1. Copy this into your Elastic Agent policy (Fleet) under Windows integration
# 2. Or use in standalone elastic-agent.yml configuration
#
# For Fleet: Go to Integrations > Windows > Add Windows
#            Then add each channel under "Event Log Channels"
#
# For Standalone: Add under inputs section
# ============================================================================

# Elastic Agent Windows Integration - Custom Channels
# Add these to your Windows integration in Fleet or elastic-agent.yml

inputs:
  - type: winlog
    id: winlog-security-ir
    enabled: true
    data_stream:
      namespace: default
    # Essential Security Channels for IR & Threat Hunting
    streams:
"@

    # Group channels by category for better organization
    # Convert hashtables to PSObjects for proper grouping
    $channelObjects = $channelsToExport | ForEach-Object { [PSCustomObject]$_ }
    $groupedChannels = $channelObjects | Group-Object -Property Category

    foreach ($group in $groupedChannels | Sort-Object Name) {
        $yamlContent += "`n      # === $($group.Name) ===`n"
        foreach ($channel in $group.Group) {
            $yamlContent += @"
      - name: "$($channel.Name)"
        # $($channel.Description)
        # MITRE: $($channel.MITRE)
        # Tier: $($channel.Tier)

"@
        }
    }

    # Add simple list format for quick reference
    $yamlContent += @"

# ============================================================================
# QUICK REFERENCE - Channel Names Only (for copy/paste)
# ============================================================================
# Copy these channel names directly into Elastic Agent configuration:
#
"@

    foreach ($channel in $channelsToExport) {
        $yamlContent += "# - $($channel.Name)`n"
    }

    $yamlContent += @"

# ============================================================================
# CHANNEL SUMMARY BY TIER
# ============================================================================
# Essential Channels: $($EssentialChannels.Count)
# Recommended Channels: $($RecommendedChannels.Count)
# Server-Specific Channels: $($ServerChannels.Count)
# Total Available: $(($EssentialChannels + $RecommendedChannels + $ServerChannels).Count)
# ============================================================================
"@

    # Write to file
    try {
        $yamlContent | Out-File -FilePath $outputPath -Encoding UTF8 -Force
        Write-Host ""
        Write-Success "Configuration exported to: $outputPath"
        Write-Host ""
        Write-Info "Next steps:"
        Write-Host "  1. Review the generated YAML file" -ForegroundColor Gray
        Write-Host "  2. Copy channel names to your Elastic Agent policy" -ForegroundColor Gray
        Write-Host "  3. Or import into Fleet Windows integration" -ForegroundColor Gray
        return $true
    }
    catch {
        Write-Error2 "Failed to write file: $($_.Exception.Message)"
        return $false
    }
}

function Show-AllChannelStatus {
    Write-Header "All Available Event Log Channels"

    $allChannels = $EssentialChannels + $RecommendedChannels + $ServerChannels

    # Group by tier
    $tiers = @("Essential", "Recommended", "Server-DC", "Server-DNS", "Server-DHCP", "Server-Web", "Server-RDG", "Server-HyperV", "Server-Cluster", "Server-File", "Server-PKI")

    foreach ($tier in $tiers) {
        $tierChannels = $allChannels | Where-Object { $_.Tier -eq $tier }
        if ($tierChannels.Count -eq 0) { continue }

        Write-SubHeader "$tier Channels ($($tierChannels.Count))"

        Write-Host ("{0,-55} {1,-12} {2,-8}" -f "Channel", "Status", "Events") -ForegroundColor Cyan
        Write-Host ("{0,-55} {1,-12} {2,-8}" -f "-------", "------", "------") -ForegroundColor DarkGray

        foreach ($channel in $tierChannels) {
            $status = Get-EventLogChannelStatus -ChannelName $channel.Name

            $statusText = $status.Status
            $statusColor = switch ($status.Status) {
                "Enabled" { "Green" }
                "Disabled" { "Yellow" }
                default { "Red" }
            }

            $displayName = if ($channel.Name.Length -gt 52) {
                $channel.Name.Substring(0, 49) + "..."
            } else {
                $channel.Name
            }

            Write-Host ("{0,-55} " -f $displayName) -NoNewline
            Write-Host ("{0,-12} " -f $statusText) -NoNewline -ForegroundColor $statusColor
            Write-Host ("{0,-8}" -f $status.RecordCount) -ForegroundColor Gray
        }
        Write-Host ""
    }
}

function Test-EventLogChannels {
    Write-Header "Test Event Log Channels"

    $results = @()

    foreach ($channel in $EventLogChannels) {
        Write-Info "Testing: $($channel.Name)"

        $status = Get-EventLogChannelStatus -ChannelName $channel.Name

        $testResult = @{
            Channel = $channel.Name
            Description = $channel.Description
            Status = $status.Status
            HasEvents = $status.RecordCount -gt 0
            EventCount = $status.RecordCount
            LastEvent = $status.LastEvent
            Working = $false
        }

        if ($status.Enabled -and $status.RecordCount -gt 0) {
            $testResult.Working = $true
            Write-Success "  OK - $($status.RecordCount) events, last: $($status.LastEvent)"
        }
        elseif ($status.Enabled) {
            Write-Warning2 "  Enabled but no events recorded"
        }
        elseif ($status.Exists) {
            Write-Warning2 "  Channel exists but is disabled"
        }
        else {
            Write-Error2 "  Channel not found"
        }

        $results += $testResult
    }

    Write-Host ""

    # Summary
    $workingChannels = @($results | Where-Object { $_.Working })
    $enabledChannels = @($results | Where-Object { $_.Status -eq "Enabled" })
    $workingCount = $workingChannels.Count
    $enabledCount = $enabledChannels.Count

    Write-SubHeader "Summary"
    Write-Status "Channels tested" $results.Count.ToString() "Cyan"
    Write-Status "Enabled" $enabledCount.ToString() "Cyan"
    Write-Status "With events" $workingCount.ToString() "Green"

    if ($workingCount -eq $results.Count) {
        Write-Host ""
        Write-Success "All channels are working and have events"
    }
    elseif ($enabledCount -eq $results.Count) {
        Write-Host ""
        Write-Success "All channels are enabled"
        Write-Info "Some channels may not have events yet (this is normal)"
    }
    else {
        Write-Host ""
        Write-Warning2 "Some channels need attention"
    }

    return $results
}

#endregion

#region Combined Functions

function Show-CurrentStatus {
    Write-Header "Current System Status"

    Show-SysmonStatus
    $null = Show-EventLogStatus
}

function Test-AllLogging {
    Write-Header "Complete Logging Test"

    Write-Info "This will verify all logging is ready for Elastic Agent ingestion"
    Write-Host ""

    # Test Sysmon basic logging
    $sysmonOk = Test-SysmonLogging

    # If Sysmon is working, run event generation test
    $sysmonStatus = Get-SysmonStatus
    if ($sysmonStatus.ServiceRunning) {
        Write-Host ""
        $eventGenOk = Test-SysmonEventGeneration
    }

    Write-Host ""

    # Test Event Logs
    $eventLogResults = Test-EventLogChannels

    Write-Host ""
    Write-Header "Final Assessment"

    $sysmonStatus = Get-SysmonStatus
    $enabledLogs = @($eventLogResults | Where-Object { $_.Status -eq "Enabled" })
    $eventLogsEnabled = $enabledLogs.Count
    $totalChannels = $eventLogResults.Count

    if ($sysmonStatus.ServiceRunning -and $eventLogsEnabled -eq $totalChannels) {
        Write-Success "System is READY for Elastic Agent ingestion"
        Write-Host ""
        Write-Host "  - Sysmon is running and generating events" -ForegroundColor Green
        Write-Host "  - All $totalChannels event log channels are enabled" -ForegroundColor Green
        Write-Host ""
        Write-Info "Configure your Elastic Agent policy to ingest these log channels"
    }
    else {
        Write-Warning2 "System needs configuration"
        Write-Host ""

        if (-not $sysmonStatus.Installed) {
            Write-Host "  - Sysmon is not installed" -ForegroundColor Red
        }
        elseif (-not $sysmonStatus.ServiceRunning) {
            Write-Host "  - Sysmon service is not running" -ForegroundColor Red
        }

        if ($eventLogsEnabled -lt $totalChannels) {
            Write-Host "  - $($totalChannels - $eventLogsEnabled) event log channels need to be enabled" -ForegroundColor Yellow
        }

        Write-Host ""
        Write-Info "Use the menu options to configure missing components"
    }
}

#endregion

#region Interactive Menu

function Show-MainMenu {
    Write-Header "Sysmon & Event Log Configuration Tool"

    Write-MenuOption "1" "Show Current Status (Sysmon + Event Logs)"
    Write-MenuOption "2" "Sysmon Management >"
    Write-MenuOption "3" "Event Log Configuration >"
    Write-MenuOption "4" "Test All Logging (verify Elastic ingestion readiness)"
    Write-Host ""
    Write-MenuOption "0" "Exit"
    Write-Host ""
}

function Show-SysmonMenu {
    Write-SubHeader "Sysmon Management"

    Write-MenuOption "1" "Install Sysmon (SwiftOnSecurity config - download)"
    Write-MenuOption "2" "Install Sysmon (SwiftOnSecurity config - local files)"
    Write-MenuOption "3" "Install Sysmon (custom config file)"
    Write-MenuOption "4" "Update Sysmon Configuration"
    Write-MenuOption "5" "Reset Sysmon to Initial Config"
    Write-MenuOption "6" "Test Sysmon Logging (quick check)"
    Write-MenuOption "7" "Generate & Verify Events (comprehensive test)"
    Write-MenuOption "8" "Uninstall Sysmon (safe removal)"
    Write-Host ""
    Write-MenuOption "0" "Back to Main Menu"
    Write-Host ""
}

function Show-EventLogMenu {
    Write-SubHeader "Event Log Configuration"

    Write-Host "  --- Channel Tiers ---" -ForegroundColor DarkCyan
    Write-MenuOption "1" "Enable Essential Channels (29 - core IR/threat hunting)"
    Write-MenuOption "2" "Enable Recommended Additional (15 - enhanced detection)"
    Write-MenuOption "3" "Enable Server-Specific (DC, DNS, IIS, Hyper-V, etc.)"
    Write-MenuOption "4" "Enable ALL Channels (Essential + Recommended)"
    Write-Host ""
    Write-Host "  --- Status & Export ---" -ForegroundColor DarkCyan
    Write-MenuOption "5" "Show All Channel Status (by tier)"
    Write-MenuOption "6" "Test Event Log Channels"
    Write-MenuOption "7" "Export Elastic Agent Config (YAML)"
    Write-Host ""
    Write-MenuOption "0" "Back to Main Menu"
    Write-Host ""
}

function Handle-SysmonMenu {
    while ($true) {
        Show-SysmonMenu
        $choice = Read-Host "Select option"

        switch ($choice) {
            "1" {
                # Download and install with SwiftOnSecurity config
                if (-not (Test-InternetConnectivity)) {
                    Write-Error2 "No internet connectivity. Use option 2 for local files."
                }
                else {
                    $null = Install-Sysmon
                }
            }
            "2" {
                # Install with local files
                Write-Info "Enter path to local Sysmon.zip file"
                $sysmonZip = Get-UserInput -Prompt "Sysmon zip path"

                Write-Info "Enter path to config XML (or press Enter to download SwiftOnSecurity)"
                Write-Host "Config path [download]: " -NoNewline -ForegroundColor Cyan
                $configXml = Read-Host

                if ([string]::IsNullOrWhiteSpace($configXml)) {
                    if (Test-InternetConnectivity) {
                        $null = Install-Sysmon -UseLocalFiles -LocalSysmonZip $sysmonZip
                    }
                    else {
                        Write-Error2 "No internet connectivity and no config provided"
                    }
                }
                else {
                    $null = Install-Sysmon -UseLocalFiles -LocalSysmonZip $sysmonZip -LocalConfigXml $configXml
                }
            }
            "3" {
                # Install with custom config
                Write-Info "Enter path to custom config XML"
                $customConfig = Get-UserInput -Prompt "Custom config path"

                if (Test-InternetConnectivity) {
                    $null = Install-Sysmon -CustomConfigPath $customConfig
                }
                else {
                    Write-Info "Enter path to local Sysmon.zip file"
                    $sysmonZip = Get-UserInput -Prompt "Sysmon zip path"
                    $null = Install-Sysmon -UseLocalFiles -LocalSysmonZip $sysmonZip -CustomConfigPath $customConfig
                }
            }
            "4" {
                $null = Update-SysmonConfig
            }
            "5" {
                $null = Reset-SysmonConfig
            }
            "6" {
                $null = Test-SysmonLogging
            }
            "7" {
                $null = Test-SysmonEventGeneration
            }
            "8" {
                $null = Uninstall-Sysmon
            }
            "0" {
                return
            }
            default {
                Write-Warning2 "Invalid selection"
            }
        }

        Write-Host ""
        Write-Host "Press Enter to continue..." -ForegroundColor Gray
        Read-Host | Out-Null
    }
}

function Handle-EventLogMenu {
    while ($true) {
        Show-EventLogMenu
        $choice = Read-Host "Select option"

        switch ($choice) {
            "1" {
                # Enable Essential Channels
                $null = Enable-AllEventLogs
            }
            "2" {
                # Enable Recommended Additional Channels
                $null = Enable-RecommendedChannels
            }
            "3" {
                # Enable Server-Specific Channels
                $null = Enable-ServerChannels
            }
            "4" {
                # Enable ALL (Essential + Recommended)
                Write-Header "Enable All Channels (Essential + Recommended)"
                $maxSize = Get-LogSizeFromUser
                Write-Info "Enabling Essential channels..."
                $null = Enable-AllEventLogs -MaxSizeMB $maxSize
                Write-Host ""
                Write-Info "Enabling Recommended channels..."
                $null = Enable-RecommendedChannels -MaxSizeMB $maxSize
            }
            "5" {
                # Show all channel status
                $null = Show-AllChannelStatus
            }
            "6" {
                # Test channels
                $null = Test-EventLogChannels
            }
            "7" {
                # Export Elastic Agent config
                $null = Export-ElasticAgentConfig
            }
            "0" {
                return
            }
            default {
                Write-Warning2 "Invalid selection"
            }
        }

        Write-Host ""
        Write-Host "Press Enter to continue..." -ForegroundColor Gray
        Read-Host | Out-Null
    }
}

function Start-InteractiveMode {
    # Check for local files provided via parameters
    if ($LocalSysmonPath -or $LocalConfigPath) {
        Write-Info "Local files detected:"
        if ($LocalSysmonPath) { Write-Host "  Sysmon: $LocalSysmonPath" -ForegroundColor Cyan }
        if ($LocalConfigPath) { Write-Host "  Config: $LocalConfigPath" -ForegroundColor Cyan }
        Write-Host ""
    }

    while ($true) {
        Show-MainMenu
        $choice = Read-Host "Select option"

        switch ($choice) {
            "1" {
                Show-CurrentStatus
            }
            "2" {
                Handle-SysmonMenu
            }
            "3" {
                Handle-EventLogMenu
            }
            "4" {
                Test-AllLogging
            }
            "0" {
                Write-Info "Exiting..."
                return
            }
            default {
                Write-Warning2 "Invalid selection"
            }
        }

        Write-Host ""
        Write-Host "Press Enter to continue..." -ForegroundColor Gray
        Read-Host | Out-Null
    }
}

#endregion

#region Non-Interactive Mode

function Start-NonInteractiveMode {
    switch ($Action) {
        "InstallSysmon" {
            if ($LocalSysmonPath) {
                $null = Install-Sysmon -UseLocalFiles -LocalSysmonZip $LocalSysmonPath -LocalConfigXml $LocalConfigPath
            }
            else {
                $null = Install-Sysmon
            }
        }
        "EnableLogs" {
            $null = Enable-AllEventLogs -MaxSizeMB $LogSizeMB
        }
        "Status" {
            Show-CurrentStatus
        }
        "TestAll" {
            Test-AllLogging
        }
        "VerifyEvents" {
            $null = Test-SysmonEventGeneration
        }
        default {
            Write-Error2 "Invalid action: $Action"
            Write-Info "Valid actions: InstallSysmon, EnableLogs, Status, TestAll, VerifyEvents"
        }
    }
}

#endregion

#region Main Entry Point

# Main execution
if ($NonInteractive) {
    if (-not $Action) {
        Write-Error2 "Action parameter required in non-interactive mode"
        Write-Info "Valid actions: InstallSysmon, EnableLogs, Status, TestAll"
        exit 1
    }
    Start-NonInteractiveMode
}
else {
    Start-InteractiveMode
}

#endregion

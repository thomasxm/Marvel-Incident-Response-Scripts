<#
.SYNOPSIS
    Process Anomaly Detection - Pure PowerShell Implementation
    No external dependencies - uses native cmdlets only

.DESCRIPTION
    Creates process baselines and detects anomalies by comparing
    current state against baseline. Detects:
    - New processes not in baseline
    - Missing processes from baseline
    - Modified executables (hash changes)
    - Reconnaissance commands executed recently (recon mode)
    - Suspicious parent-child process relationships

.PARAMETER Mode
    baseline - Create a baseline of current processes
    scan - Scan for anomalies against baseline
    recon - Scan for reconnaissance activity in past N hours

.PARAMETER OutputFile
    Output file for baseline (default: process_baseline.json)

.PARAMETER BaselineFile
    Baseline file for scan mode

.PARAMETER Hours
    Hours to look back for recon mode (default: 4)

.EXAMPLE
    .\process_anomaly.ps1 baseline -OutputFile baseline.json
    .\process_anomaly.ps1 scan -BaselineFile baseline.json
    .\process_anomaly.ps1 recon -Hours 4
#>

param(
    [Parameter(Position=0, Mandatory=$true)]
    [ValidateSet("baseline", "scan", "show", "recon")]
    [string]$Mode,

    [Parameter()]
    [string]$OutputFile = "process_baseline.json",

    [Parameter()]
    [string]$BaselineFile,

    [Parameter()]
    [int]$Hours = 4,

    [Parameter()]
    [switch]$All,

    [Parameter()]
    [int]$Limit = 5
)

# Strict mode
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Colors for output
function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
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

function Write-New {
    param([string]$Text)
    Write-Host "[NEW] $Text" -ForegroundColor Red
}

function Write-Missing {
    param([string]$Text)
    Write-Host "[MISSING] $Text" -ForegroundColor Yellow
}

function Write-Modified {
    param([string]$Text)
    Write-Host "[MODIFIED] $Text" -ForegroundColor Magenta
}

function Write-Recon {
    param([string]$Text)
    Write-Host "[RECON] $Text" -ForegroundColor Yellow -BackgroundColor DarkRed
}

function Write-Critical {
    param([string]$Text)
    Write-Host "[CRITICAL] $Text" -ForegroundColor White -BackgroundColor DarkRed
}

function Write-HighRisk {
    param([string]$Text)
    Write-Host "[HIGH] $Text" -ForegroundColor Red -BackgroundColor Black
}

function Write-MediumRisk {
    param([string]$Text)
    Write-Host "[MEDIUM] $Text" -ForegroundColor Yellow
}

function Write-LowRisk {
    param([string]$Text)
    Write-Host "[LOW] $Text" -ForegroundColor Cyan
}

# System processes to whitelist (cannot be malicious injection targets)
$SystemProcesses = @(
    "System",
    "Registry",
    "smss",
    "csrss",
    "wininit",
    "services",
    "lsass",
    "svchost",
    "dwm",
    "winlogon",
    "fontdrvhost",
    "LogonUI",
    "sihost",
    "taskhostw",
    "RuntimeBroker",
    "SearchIndexer",
    "SecurityHealthService",
    "MsMpEng",
    "NisSrv",
    "spoolsv",
    "SearchHost",
    "StartMenuExperienceHost",
    "TextInputHost",
    "ctfmon",
    "dllhost",
    "conhost",
    "WmiPrvSE"
)

# Reconnaissance commands (MITRE ATT&CK: Discovery techniques)
# These are commonly used by attackers for enumeration
$ReconCommands = @{
    # T1082 - System Information Discovery
    "hostname"    = @{ Technique = "T1082"; Description = "System hostname discovery" }
    "systeminfo"  = @{ Technique = "T1082"; Description = "Detailed system information" }

    # T1016 - System Network Configuration Discovery
    "ipconfig"    = @{ Technique = "T1016"; Description = "Network configuration discovery" }
    "nslookup"    = @{ Technique = "T1016"; Description = "DNS lookup" }
    "netstat"     = @{ Technique = "T1016"; Description = "Network connections" }
    "route"       = @{ Technique = "T1016"; Description = "Routing table" }
    "arp"         = @{ Technique = "T1016"; Description = "ARP cache" }

    # T1033 - System Owner/User Discovery
    "whoami"      = @{ Technique = "T1033"; Description = "Current user identity" }
    "quser"       = @{ Technique = "T1033"; Description = "Logged-on users" }
    "qwinsta"     = @{ Technique = "T1033"; Description = "Remote Desktop sessions" }
    "query"       = @{ Technique = "T1033"; Description = "User/session queries" }

    # T1057 - Process Discovery
    "tasklist"    = @{ Technique = "T1057"; Description = "Running processes" }
    "wmic"        = @{ Technique = "T1057"; Description = "WMI queries (process/system)" }

    # T1007 - System Service Discovery
    "sc"          = @{ Technique = "T1007"; Description = "Service control queries" }

    # T1018 - Remote System Discovery / T1087 - Account Discovery
    "net"         = @{ Technique = "T1087"; Description = "Network/user enumeration" }
    "dsquery"     = @{ Technique = "T1087"; Description = "Active Directory queries" }
    "nltest"      = @{ Technique = "T1087"; Description = "Domain trust enumeration" }
    "cmdkey"      = @{ Technique = "T1087"; Description = "Stored credentials listing" }

    # T1083 - File and Directory Discovery
    "dir"         = @{ Technique = "T1083"; Description = "Directory listing" }
    "tree"        = @{ Technique = "T1083"; Description = "Directory tree structure" }

    # Command interpreters often used in attack chains
    "cmd"         = @{ Technique = "T1059.003"; Description = "Windows Command Shell" }
    "powershell"  = @{ Technique = "T1059.001"; Description = "PowerShell execution" }
    "pwsh"        = @{ Technique = "T1059.001"; Description = "PowerShell Core execution" }
}

# SC.exe specific suspicious flags
$ScSuspiciousFlags = @("query", "queryex", "qc", "qdescription", "qfailure", "qtriggerinfo")

# System-level parent processes that should NOT normally spawn recon tools
# If these spawn reconnaissance commands, it's highly suspicious
$SuspiciousSystemParents = @{
    "services"    = @{ Risk = "CRITICAL"; Description = "Service Control Manager - should not spawn recon" }
    "svchost"     = @{ Risk = "HIGH"; Description = "Service Host - rarely spawns CLI recon tools" }
    "lsass"       = @{ Risk = "CRITICAL"; Description = "LSASS should NEVER spawn processes" }
    "csrss"       = @{ Risk = "CRITICAL"; Description = "Client/Server Runtime should not spawn recon" }
    "smss"        = @{ Risk = "CRITICAL"; Description = "Session Manager should not spawn recon" }
    "wininit"     = @{ Risk = "CRITICAL"; Description = "Windows Init should not spawn recon" }
    "winlogon"    = @{ Risk = "HIGH"; Description = "Winlogon rarely spawns recon tools" }
    "spoolsv"     = @{ Risk = "HIGH"; Description = "Print Spooler - common exploitation target" }
    "SearchIndexer" = @{ Risk = "MEDIUM"; Description = "Search Indexer spawning recon is unusual" }
    "WmiPrvSE"    = @{ Risk = "MEDIUM"; Description = "WMI Provider - may indicate lateral movement" }
    "taskhost"    = @{ Risk = "MEDIUM"; Description = "Task Host spawning recon is unusual" }
    "taskhostw"   = @{ Risk = "MEDIUM"; Description = "Task Host spawning recon is unusual" }
    "dllhost"     = @{ Risk = "MEDIUM"; Description = "COM Surrogate spawning recon is unusual" }
    "mmc"         = @{ Risk = "LOW"; Description = "Management Console - may be legitimate" }
    "wsmprovhost" = @{ Risk = "HIGH"; Description = "WinRM Provider - may indicate remote execution" }
    "mshta"       = @{ Risk = "CRITICAL"; Description = "HTML Application Host - common LOLBin" }
    "regsvr32"    = @{ Risk = "CRITICAL"; Description = "RegSvr32 - common LOLBin for proxy execution" }
    "rundll32"    = @{ Risk = "HIGH"; Description = "RunDLL32 - common LOLBin" }
    "msiexec"     = @{ Risk = "HIGH"; Description = "MSI Installer spawning recon is suspicious" }
    "wscript"     = @{ Risk = "HIGH"; Description = "Windows Script Host" }
    "cscript"     = @{ Risk = "HIGH"; Description = "Console Script Host" }
}

# Compute SHA256 hash of file
function Get-SafeFileHash {
    param([string]$FilePath)

    if ([string]::IsNullOrEmpty($FilePath)) {
        return $null
    }

    if (-not (Test-Path -Path $FilePath -PathType Leaf)) {
        return $null
    }

    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction SilentlyContinue
        if ($hash) {
            return $hash.Hash.ToLower()
        }
    }
    catch {
        return $null
    }

    return $null
}

# Get detailed process information
function Get-ProcessDetails {
    param([System.Diagnostics.Process]$Process)

    $info = @{
        pid = $Process.Id
        name = $Process.ProcessName
        ppid = 0
        username = ""
        exe = ""
        cmdline = ""
        start_time = $null
        exe_hash = $null
        working_set = 0
        cpu_time = 0
    }

    try {
        # Get parent PID using WMI
        $wmiProc = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction SilentlyContinue
        if ($wmiProc) {
            $info.ppid = [int]$wmiProc.ParentProcessId
            $info.cmdline = $wmiProc.CommandLine
            $info.exe = $wmiProc.ExecutablePath

            # Get owner
            try {
                $owner = Invoke-CimMethod -InputObject $wmiProc -MethodName GetOwner -ErrorAction SilentlyContinue
                if ($owner -and $owner.User) {
                    if ($owner.Domain) {
                        $info.username = "$($owner.Domain)\$($owner.User)"
                    } else {
                        $info.username = $owner.User
                    }
                }
            }
            catch {
                $info.username = "UNKNOWN"
            }
        }

        # Get start time
        if ($Process.StartTime) {
            $info.start_time = $Process.StartTime.ToString("o")
        }

        # Get memory and CPU
        $info.working_set = $Process.WorkingSet64
        try {
            $info.cpu_time = $Process.TotalProcessorTime.TotalSeconds
        }
        catch {
            $info.cpu_time = 0
        }

        # Get executable hash
        if (-not [string]::IsNullOrEmpty($info.exe)) {
            $info.exe_hash = Get-SafeFileHash -FilePath $info.exe
        }
    }
    catch {
        # Process may have exited
    }

    return $info
}

# Create baseline
function New-ProcessBaseline {
    param([string]$OutputPath)

    Write-Header "Creating Process Baseline"

    $hostname = $env:COMPUTERNAME
    $timestamp = Get-Date -Format "o"
    $osVersion = [System.Environment]::OSVersion.VersionString

    Write-Info "Hostname: $hostname"
    Write-Info "Timestamp: $timestamp"
    Write-Info "OS Version: $osVersion"

    $processes = @()
    $count = 0

    $allProcesses = Get-Process -ErrorAction SilentlyContinue
    $total = $allProcesses.Count

    foreach ($proc in $allProcesses) {
        $count++

        if ($count % 50 -eq 0) {
            Write-Host "`r[*] Processing $count / $total processes..." -NoNewline -ForegroundColor Blue
        }

        # Skip system idle process
        if ($proc.Id -eq 0) {
            continue
        }

        $details = Get-ProcessDetails -Process $proc
        $processes += $details
    }

    Write-Host ""

    $baseline = @{
        timestamp = $timestamp
        hostname = $hostname
        os_version = $osVersion
        platform = "Windows"
        processes = $processes
    }

    # Convert to JSON and save
    $json = $baseline | ConvertTo-Json -Depth 10
    $json | Out-File -FilePath $OutputPath -Encoding UTF8

    Write-Success "Baseline created: $OutputPath"
    Write-Info "Total processes: $($processes.Count)"
}

# Run anomaly scan
function Invoke-ProcessScan {
    param([string]$BaselinePath)

    Write-Header "Process Anomaly Scan"

    if (-not (Test-Path -Path $BaselinePath)) {
        Write-Error2 "Baseline file not found: $BaselinePath"
        exit 1
    }

    Write-Info "Loading baseline: $BaselinePath"

    $baseline = Get-Content -Path $BaselinePath -Raw | ConvertFrom-Json

    # Build lookup tables
    $baselineByName = @{}
    $baselineHashes = @{}

    foreach ($proc in $baseline.processes) {
        $key = $proc.name
        if (-not $baselineByName.ContainsKey($key)) {
            $baselineByName[$key] = @()
        }
        $baselineByName[$key] += $proc

        if ($proc.exe_hash) {
            $baselineHashes[$proc.name] = $proc.exe_hash
        }
    }

    Write-Info "Baseline processes: $($baseline.processes.Count)"

    $currentNames = @{}
    $newCount = 0
    $missingCount = 0
    $modifiedCount = 0

    Write-Header "Scanning Current Processes"

    $allProcesses = Get-Process -ErrorAction SilentlyContinue

    foreach ($proc in $allProcesses) {
        if ($proc.Id -eq 0) { continue }

        $name = $proc.ProcessName
        $currentNames[$name] = $true

        $details = Get-ProcessDetails -Process $proc

        # Check if new process
        if (-not $baselineByName.ContainsKey($name)) {
            $newCount++

            Write-Host ""
            Write-New "Process: $name (PID: $($proc.Id))"
            Write-Host "    User:     $($details.username)" -ForegroundColor Cyan
            Write-Host "    Exe:      $($details.exe)" -ForegroundColor Cyan
            Write-Host "    Cmdline:  $($details.cmdline)" -ForegroundColor Cyan

            # Check for suspicious indicators
            if ($details.exe -match "\\Temp\\|\\tmp\\|\\AppData\\Local\\Temp") {
                Write-Host "    [!] SUSPICIOUS: Executable in temp directory" -ForegroundColor Red
            }
            if ($details.cmdline -match "powershell.*-enc|-encodedcommand|frombase64") {
                Write-Host "    [!] SUSPICIOUS: Encoded PowerShell command" -ForegroundColor Red
            }
            if ($details.cmdline -match "Invoke-Expression|IEX|downloadstring|webclient") {
                Write-Host "    [!] SUSPICIOUS: Download and execute pattern" -ForegroundColor Red
            }
            if ($name -match "^(nc|ncat|netcat|socat)$") {
                Write-Host "    [!] SUSPICIOUS: Network tool" -ForegroundColor Red
            }
            if ($details.exe -match "\\Users\\Public\\|\\ProgramData\\") {
                Write-Host "    [!] SUSPICIOUS: Executable in world-writable location" -ForegroundColor Red
            }
        }
        else {
            # Check for hash modification
            if ($details.exe_hash -and $baselineHashes.ContainsKey($name)) {
                $baselineHash = $baselineHashes[$name]
                if ($baselineHash -and $details.exe_hash -ne $baselineHash) {
                    $modifiedCount++

                    Write-Host ""
                    Write-Modified "Process: $name (PID: $($proc.Id))"
                    Write-Host "    Exe:           $($details.exe)" -ForegroundColor Cyan
                    Write-Host "    Baseline Hash: $baselineHash" -ForegroundColor Cyan
                    Write-Host "    Current Hash:  $($details.exe_hash)" -ForegroundColor Red
                }
            }
        }
    }

    # Check for missing processes
    Write-Header "Checking for Missing Processes"

    foreach ($name in $baselineByName.Keys) {
        if (-not $currentNames.ContainsKey($name)) {
            # Skip common system processes that may not always be running
            if ($name -in $SystemProcesses) {
                continue
            }

            $missingCount++
            Write-Missing "Process no longer running: $name"
        }
    }

    # Summary
    Write-Header "Scan Summary"

    if ($newCount -gt 0) {
        Write-Host "[!] New processes:      $newCount" -ForegroundColor Red
    } else {
        Write-Host "[+] New processes:      $newCount" -ForegroundColor Green
    }

    if ($missingCount -gt 0) {
        Write-Host "[!] Missing processes:  $missingCount" -ForegroundColor Yellow
    } else {
        Write-Host "[+] Missing processes:  $missingCount" -ForegroundColor Green
    }

    if ($modifiedCount -gt 0) {
        Write-Host "[!] Modified processes: $modifiedCount" -ForegroundColor Magenta
    } else {
        Write-Host "[+] Modified processes: $modifiedCount" -ForegroundColor Green
    }

    $totalAnomalies = $newCount + $missingCount + $modifiedCount
    Write-Host ""

    if ($totalAnomalies -gt 0) {
        Write-Warning2 "Total anomalies detected: $totalAnomalies"
    } else {
        Write-Success "No anomalies detected"
    }
}

# Reconnaissance activity scan
function Invoke-ReconScan {
    param([int]$LookbackHours = 4)

    Write-Header "Reconnaissance Activity Scan"

    $cutoffTime = (Get-Date).AddHours(-$LookbackHours)
    Write-Info "Scanning for recon commands in the past $LookbackHours hours"
    Write-Info "Cutoff time: $($cutoffTime.ToString('yyyy-MM-dd HH:mm:ss'))"

    # Track findings
    $findings = @{
        Critical = @()
        High = @()
        Medium = @()
        Low = @()
        Info = @()
    }

    $reconCount = 0
    $suspiciousParentCount = 0

    # Build process tree for parent lookup
    Write-Info "Building process tree..."
    $processTree = @{}
    $allWmiProcesses = Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue

    foreach ($wmiProc in $allWmiProcesses) {
        $processTree[$wmiProc.ProcessId] = @{
            Name = $wmiProc.Name
            ProcessId = $wmiProc.ProcessId
            ParentProcessId = $wmiProc.ParentProcessId
            CommandLine = $wmiProc.CommandLine
            ExecutablePath = $wmiProc.ExecutablePath
            CreationDate = $wmiProc.CreationDate
        }
    }

    Write-Header "Scanning for Reconnaissance Commands"

    # Also check Windows Event Log for process creation (Event ID 4688) if available
    $useEventLog = $false
    try {
        $testEvent = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = 4688
            StartTime = $cutoffTime
        } -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($testEvent) {
            $useEventLog = $true
            Write-Info "Security event log available - will include historical process creation"
        }
    }
    catch {
        Write-Info "Security event log not accessible - scanning running processes only"
    }

    # Scan running processes first
    foreach ($wmiProc in $allWmiProcesses) {
        $procName = $wmiProc.Name -replace '\.exe$', ''
        $procNameLower = $procName.ToLower()

        # Check if this is a recon command
        $isReconCmd = $false
        $reconInfo = $null

        foreach ($reconCmd in $ReconCommands.Keys) {
            if ($procNameLower -eq $reconCmd.ToLower()) {
                $isReconCmd = $true
                $reconInfo = $ReconCommands[$reconCmd]
                break
            }
        }

        if (-not $isReconCmd) { continue }

        # Check process creation time
        $createTime = $null
        if ($wmiProc.CreationDate) {
            try {
                $createTime = [Management.ManagementDateTimeConverter]::ToDateTime($wmiProc.CreationDate)
            }
            catch {
                try {
                    $createTime = $wmiProc.CreationDate
                }
                catch {
                    $createTime = $null
                }
            }
        }

        # Skip if older than lookback period
        if ($createTime -and $createTime -lt $cutoffTime) {
            continue
        }

        $reconCount++

        # Get parent process info
        $parentName = "Unknown"
        $parentPath = ""
        $suspiciousParent = $false
        $parentRisk = "LOW"
        $parentDesc = ""

        if ($wmiProc.ParentProcessId -and $processTree.ContainsKey($wmiProc.ParentProcessId)) {
            $parent = $processTree[$wmiProc.ParentProcessId]
            $parentName = $parent.Name -replace '\.exe$', ''
            $parentPath = $parent.ExecutablePath

            # Check if parent is a suspicious system process
            foreach ($susParent in $SuspiciousSystemParents.Keys) {
                if ($parentName.ToLower() -eq $susParent.ToLower()) {
                    $suspiciousParent = $true
                    $parentRisk = $SuspiciousSystemParents[$susParent].Risk
                    $parentDesc = $SuspiciousSystemParents[$susParent].Description
                    $suspiciousParentCount++
                    break
                }
            }
        }

        # Get owner
        $owner = "UNKNOWN"
        try {
            $ownerInfo = Invoke-CimMethod -InputObject $wmiProc -MethodName GetOwner -ErrorAction SilentlyContinue
            if ($ownerInfo -and $ownerInfo.User) {
                $owner = if ($ownerInfo.Domain) { "$($ownerInfo.Domain)\$($ownerInfo.User)" } else { $ownerInfo.User }
            }
        }
        catch {}

        # Check for SC.exe with suspicious flags
        $scSuspicious = $false
        if ($procNameLower -eq "sc") {
            foreach ($flag in $ScSuspiciousFlags) {
                if ($wmiProc.CommandLine -match "\b$flag\b") {
                    $scSuspicious = $true
                    break
                }
            }
            if (-not $scSuspicious) {
                continue  # Skip SC commands without suspicious flags
            }
        }

        # Build finding object
        $finding = @{
            ProcessName = $procName
            PID = $wmiProc.ProcessId
            CommandLine = $wmiProc.CommandLine
            ExecutablePath = $wmiProc.ExecutablePath
            Owner = $owner
            CreateTime = $createTime
            ParentName = $parentName
            ParentPID = $wmiProc.ParentProcessId
            ParentPath = $parentPath
            SuspiciousParent = $suspiciousParent
            ParentRisk = $parentRisk
            ParentDescription = $parentDesc
            Technique = $reconInfo.Technique
            Description = $reconInfo.Description
        }

        # Categorize by risk
        if ($suspiciousParent -and $parentRisk -eq "CRITICAL") {
            $findings.Critical += $finding
        }
        elseif ($suspiciousParent -and $parentRisk -eq "HIGH") {
            $findings.High += $finding
        }
        elseif ($suspiciousParent -and $parentRisk -eq "MEDIUM") {
            $findings.Medium += $finding
        }
        else {
            $findings.Info += $finding
        }
    }

    # Check Windows Event Log for historical process creation
    if ($useEventLog) {
        Write-Header "Checking Security Event Log (4688)"

        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                Id = 4688
                StartTime = $cutoffTime
            } -ErrorAction SilentlyContinue

            foreach ($event in $events) {
                $xml = [xml]$event.ToXml()
                $eventData = @{}
                foreach ($data in $xml.Event.EventData.Data) {
                    $eventData[$data.Name] = $data.'#text'
                }

                $newProcName = $eventData['NewProcessName']
                if (-not $newProcName) { continue }

                $procBaseName = [System.IO.Path]::GetFileNameWithoutExtension($newProcName).ToLower()

                # Check if recon command
                $isReconCmd = $false
                $reconInfo = $null

                foreach ($reconCmd in $ReconCommands.Keys) {
                    if ($procBaseName -eq $reconCmd.ToLower()) {
                        $isReconCmd = $true
                        $reconInfo = $ReconCommands[$reconCmd]
                        break
                    }
                }

                if (-not $isReconCmd) { continue }

                # SC.exe check
                if ($procBaseName -eq "sc") {
                    $cmdLine = $eventData['CommandLine']
                    $scSuspicious = $false
                    foreach ($flag in $ScSuspiciousFlags) {
                        if ($cmdLine -match "\b$flag\b") {
                            $scSuspicious = $true
                            break
                        }
                    }
                    if (-not $scSuspicious) { continue }
                }

                $reconCount++

                # Get parent info
                $parentName = "Unknown"
                $parentProcPath = $eventData['ParentProcessName']
                $suspiciousParent = $false
                $parentRisk = "LOW"
                $parentDesc = ""

                if ($parentProcPath) {
                    $parentName = [System.IO.Path]::GetFileNameWithoutExtension($parentProcPath)

                    foreach ($susParent in $SuspiciousSystemParents.Keys) {
                        if ($parentName.ToLower() -eq $susParent.ToLower()) {
                            $suspiciousParent = $true
                            $parentRisk = $SuspiciousSystemParents[$susParent].Risk
                            $parentDesc = $SuspiciousSystemParents[$susParent].Description
                            $suspiciousParentCount++
                            break
                        }
                    }
                }

                $finding = @{
                    ProcessName = $procBaseName
                    PID = $eventData['NewProcessId']
                    CommandLine = $eventData['CommandLine']
                    ExecutablePath = $newProcName
                    Owner = $eventData['SubjectUserName']
                    CreateTime = $event.TimeCreated
                    ParentName = $parentName
                    ParentPID = $eventData['ProcessId']
                    ParentPath = $parentProcPath
                    SuspiciousParent = $suspiciousParent
                    ParentRisk = $parentRisk
                    ParentDescription = $parentDesc
                    Technique = $reconInfo.Technique
                    Description = $reconInfo.Description
                    Source = "EventLog"
                }

                if ($suspiciousParent -and $parentRisk -eq "CRITICAL") {
                    $findings.Critical += $finding
                }
                elseif ($suspiciousParent -and $parentRisk -eq "HIGH") {
                    $findings.High += $finding
                }
                elseif ($suspiciousParent -and $parentRisk -eq "MEDIUM") {
                    $findings.Medium += $finding
                }
                else {
                    $findings.Info += $finding
                }
            }
        }
        catch {
            Write-Warning2 "Could not read Security event log: $_"
        }
    }

    # Display findings by risk level
    if ($findings.Critical.Count -gt 0) {
        Write-Header "CRITICAL RISK - Suspicious Parent Process Spawning Recon"

        foreach ($f in $findings.Critical) {
            Write-Host ""
            Write-Critical "$($f.ProcessName) spawned by $($f.ParentName) (PID: $($f.PID))"
            Write-Host "    " -NoNewline
            Write-Host "MITRE ATT&CK: " -ForegroundColor DarkGray -NoNewline
            Write-Host "$($f.Technique)" -ForegroundColor Red -NoNewline
            Write-Host " - $($f.Description)" -ForegroundColor DarkGray
            Write-Host "    Time:       " -ForegroundColor Cyan -NoNewline
            Write-Host "$($f.CreateTime)" -ForegroundColor White
            Write-Host "    User:       " -ForegroundColor Cyan -NoNewline
            Write-Host "$($f.Owner)" -ForegroundColor White
            Write-Host "    Command:    " -ForegroundColor Cyan -NoNewline
            Write-Host "$($f.CommandLine)" -ForegroundColor Yellow
            Write-Host "    Parent:     " -ForegroundColor Cyan -NoNewline
            Write-Host "$($f.ParentName) " -ForegroundColor Red -NoNewline
            Write-Host "(PID: $($f.ParentPID))" -ForegroundColor DarkGray
            Write-Host "    Parent Path:" -ForegroundColor Cyan -NoNewline
            Write-Host " $($f.ParentPath)" -ForegroundColor Red
            Write-Host "    Risk:       " -ForegroundColor Cyan -NoNewline
            Write-Host "$($f.ParentDescription)" -ForegroundColor Red -BackgroundColor Black
        }
    }

    if ($findings.High.Count -gt 0) {
        Write-Header "HIGH RISK - Unusual Parent Process Spawning Recon"

        foreach ($f in $findings.High) {
            Write-Host ""
            Write-HighRisk "$($f.ProcessName) spawned by $($f.ParentName) (PID: $($f.PID))"
            Write-Host "    MITRE ATT&CK: $($f.Technique) - $($f.Description)" -ForegroundColor DarkGray
            Write-Host "    Time:       $($f.CreateTime)" -ForegroundColor Cyan
            Write-Host "    User:       $($f.Owner)" -ForegroundColor Cyan
            Write-Host "    Command:    " -ForegroundColor Cyan -NoNewline
            Write-Host "$($f.CommandLine)" -ForegroundColor Yellow
            Write-Host "    Parent:     " -ForegroundColor Cyan -NoNewline
            Write-Host "$($f.ParentName) (PID: $($f.ParentPID))" -ForegroundColor Red
            Write-Host "    Risk:       $($f.ParentDescription)" -ForegroundColor Red
        }
    }

    if ($findings.Medium.Count -gt 0) {
        Write-Header "MEDIUM RISK - Somewhat Unusual Parent Process"

        foreach ($f in $findings.Medium) {
            Write-Host ""
            Write-MediumRisk "$($f.ProcessName) spawned by $($f.ParentName) (PID: $($f.PID))"
            Write-Host "    MITRE ATT&CK: $($f.Technique) - $($f.Description)" -ForegroundColor DarkGray
            Write-Host "    Time:       $($f.CreateTime)" -ForegroundColor Cyan
            Write-Host "    User:       $($f.Owner)" -ForegroundColor Cyan
            Write-Host "    Command:    $($f.CommandLine)" -ForegroundColor Yellow
            Write-Host "    Parent:     $($f.ParentName) (PID: $($f.ParentPID))" -ForegroundColor Yellow
        }
    }

    if ($findings.Info.Count -gt 0) {
        Write-Header "Reconnaissance Commands Detected (Normal Parent Processes)"

        # Group by command for cleaner output
        $grouped = $findings.Info | Group-Object ProcessName

        foreach ($group in $grouped) {
            Write-Host ""
            Write-Recon "$($group.Name) - $($group.Count) execution(s)"

            foreach ($f in $group.Group) {
                Write-Host "    " -NoNewline
                Write-Host "[" -ForegroundColor DarkGray -NoNewline
                Write-Host "$($f.CreateTime)" -ForegroundColor Cyan -NoNewline
                Write-Host "]" -ForegroundColor DarkGray -NoNewline
                Write-Host " User: " -ForegroundColor DarkGray -NoNewline
                Write-Host "$($f.Owner)" -ForegroundColor White -NoNewline
                Write-Host " Parent: " -ForegroundColor DarkGray -NoNewline
                Write-Host "$($f.ParentName)" -ForegroundColor Green
                if ($f.CommandLine) {
                    Write-Host "        Cmd: $($f.CommandLine)" -ForegroundColor DarkGray
                }
            }
        }
    }

    # Summary
    Write-Header "Reconnaissance Scan Summary"

    Write-Host "Time Window:           Past $LookbackHours hours" -ForegroundColor Cyan
    Write-Host "Total Recon Commands:  $reconCount" -ForegroundColor $(if ($reconCount -gt 0) { "Yellow" } else { "Green" })

    Write-Host ""
    if ($findings.Critical.Count -gt 0) {
        Write-Host "[!!!] CRITICAL findings: $($findings.Critical.Count)" -ForegroundColor White -BackgroundColor DarkRed
    }
    if ($findings.High.Count -gt 0) {
        Write-Host "[!!]  HIGH findings:     $($findings.High.Count)" -ForegroundColor Red
    }
    if ($findings.Medium.Count -gt 0) {
        Write-Host "[!]   MEDIUM findings:   $($findings.Medium.Count)" -ForegroundColor Yellow
    }
    if ($findings.Info.Count -gt 0) {
        Write-Host "[*]   INFO findings:     $($findings.Info.Count)" -ForegroundColor Cyan
    }

    $totalSuspicious = $findings.Critical.Count + $findings.High.Count + $findings.Medium.Count
    Write-Host ""

    if ($totalSuspicious -gt 0) {
        Write-Host "========================================" -ForegroundColor Red
        Write-Host "  ALERT: $totalSuspicious suspicious parent-child relationships detected!" -ForegroundColor Red
        Write-Host "  Review CRITICAL and HIGH findings immediately." -ForegroundColor Red
        Write-Host "========================================" -ForegroundColor Red
    }
    elseif ($reconCount -gt 0) {
        Write-Warning2 "Reconnaissance activity detected but from normal parent processes"
        Write-Info "Review the commands to ensure they are expected administrative activity"
    }
    else {
        Write-Success "No reconnaissance activity detected in the past $LookbackHours hours"
    }
}

# Show baseline results with detailed information
function Show-BaselineResults {
    param(
        [string]$BaselinePath,
        [bool]$ShowAll = $false,
        [int]$ShowLimit = 5
    )

    Write-Header "Process Baseline Summary"

    if (-not (Test-Path -Path $BaselinePath)) {
        Write-Error2 "Baseline file not found: $BaselinePath"
        exit 1
    }

    $baseline = Get-Content -Path $BaselinePath -Raw | ConvertFrom-Json

    # Metadata
    Write-Host "Baseline File:  " -ForegroundColor Cyan -NoNewline
    Write-Host "$BaselinePath" -ForegroundColor White
    Write-Host "Hostname:       " -ForegroundColor Cyan -NoNewline
    Write-Host "$($baseline.hostname)" -ForegroundColor White
    Write-Host "Created:        " -ForegroundColor Cyan -NoNewline
    Write-Host "$($baseline.timestamp)" -ForegroundColor White
    Write-Host "Total Entries:  " -ForegroundColor Cyan -NoNewline
    Write-Host "$($baseline.processes.Count)" -ForegroundColor Green
    Write-Host "Output Mode:    " -ForegroundColor Cyan -NoNewline
    if ($ShowAll) {
        Write-Host "Showing all entries" -ForegroundColor White
    } else {
        Write-Host "Showing up to $ShowLimit entries per group (use -All for full output)" -ForegroundColor Yellow
    }
    Write-Host ""

    # Group by user
    $byUser = $baseline.processes | Group-Object username

    Write-Header "Processes by User"
    foreach ($group in ($byUser | Sort-Object Count -Descending)) {
        $userName = if ([string]::IsNullOrEmpty($group.Name)) { "SYSTEM/Unknown" } else { $group.Name }
        Write-Host "  $userName" -ForegroundColor Yellow -NoNewline
        Write-Host " ($($group.Count) processes)" -ForegroundColor DarkGray
    }
    Write-Host ""

    # Suspicious locations
    Write-Header "Processes with Executables in Suspicious Locations"
    $suspiciousCount = 0
    foreach ($proc in $baseline.processes) {
        if ($proc.exe -match "\\Temp\\|\\tmp\\|\\AppData\\Local\\Temp|\\Users\\Public\\|\\ProgramData\\|\\Downloads\\") {
            $suspiciousCount++
            Write-Host ""
            Write-Host "  Process: " -ForegroundColor Cyan -NoNewline
            Write-Host "$($proc.name)" -ForegroundColor Yellow
            Write-Host "  PID:     " -ForegroundColor Cyan -NoNewline
            Write-Host "$($proc.pid)" -ForegroundColor White
            Write-Host "  Exe:     " -ForegroundColor Cyan -NoNewline
            Write-Host "$($proc.exe)" -ForegroundColor Red
            Write-Host "  Cmdline: " -ForegroundColor Cyan -NoNewline
            $cmdDisplay = if ($proc.cmdline.Length -gt 100) { "$($proc.cmdline.Substring(0, 100))..." } else { $proc.cmdline }
            Write-Host "$cmdDisplay" -ForegroundColor DarkGray
            Write-Host "  User:    " -ForegroundColor Cyan -NoNewline
            Write-Host "$($proc.username)" -ForegroundColor White
        }
    }
    if ($suspiciousCount -eq 0) {
        Write-Host "  (none found)" -ForegroundColor Green
    }
    Write-Host ""

    # Detailed process listing
    Write-Header "All Processes (Detailed)"

    # Group by executable path directory for organization
    $byDirectory = @{}
    foreach ($proc in $baseline.processes) {
        $dir = if ($proc.exe) {
            try { [System.IO.Path]::GetDirectoryName($proc.exe) } catch { "Unknown" }
        } else { "Unknown" }
        if (-not $byDirectory.ContainsKey($dir)) {
            $byDirectory[$dir] = @()
        }
        $byDirectory[$dir] += $proc
    }

    foreach ($dir in ($byDirectory.Keys | Sort-Object)) {
        $procs = $byDirectory[$dir]
        $totalInDir = $procs.Count
        Write-Host ""
        Write-Host "[$dir]" -ForegroundColor Yellow
        Write-Host "  ($totalInDir processes)" -ForegroundColor DarkGray

        # Apply limit unless ShowAll
        $displayProcs = if ($ShowAll) { $procs | Sort-Object name } else { ($procs | Sort-Object name) | Select-Object -First $ShowLimit }
        $skipped = $totalInDir - @($displayProcs).Count

        foreach ($proc in $displayProcs) {
            Write-Host ""
            Write-Host "    Name:       " -ForegroundColor Cyan -NoNewline
            Write-Host "$($proc.name)" -ForegroundColor White
            Write-Host "    PID:        " -ForegroundColor Cyan -NoNewline
            Write-Host "$($proc.pid)" -ForegroundColor White
            Write-Host "    PPID:       " -ForegroundColor Cyan -NoNewline
            Write-Host "$($proc.ppid)" -ForegroundColor White
            Write-Host "    Exe:        " -ForegroundColor Cyan -NoNewline
            Write-Host "$($proc.exe)" -ForegroundColor White
            Write-Host "    Cmdline:    " -ForegroundColor Cyan -NoNewline
            $cmdDisplay = if ($proc.cmdline -and $proc.cmdline.Length -gt 80) { "$($proc.cmdline.Substring(0, 80))..." } else { $proc.cmdline }
            Write-Host "$cmdDisplay" -ForegroundColor DarkGray
            Write-Host "    User:       " -ForegroundColor Cyan -NoNewline
            Write-Host "$($proc.username)" -ForegroundColor White
            Write-Host "    Start Time: " -ForegroundColor Cyan -NoNewline
            Write-Host "$($proc.start_time)" -ForegroundColor White
            Write-Host "    Memory:     " -ForegroundColor Cyan -NoNewline
            $memMB = [math]::Round($proc.working_set / 1MB, 2)
            Write-Host "$memMB MB" -ForegroundColor White
            Write-Host "    CPU Time:   " -ForegroundColor Cyan -NoNewline
            Write-Host "$($proc.cpu_time) seconds" -ForegroundColor White
            if ($proc.exe_hash) {
                Write-Host "    SHA256:     " -ForegroundColor Cyan -NoNewline
                Write-Host "$($proc.exe_hash)" -ForegroundColor DarkGray
            }
        }

        # Show skipped count
        if ($skipped -gt 0) {
            Write-Host ""
            Write-Host "    ... and $skipped more processes in this directory (use -All to see all)" -ForegroundColor Yellow
        }
    }

    # Summary statistics
    Write-Header "Summary Statistics"
    Write-Host "Total Processes:           " -ForegroundColor Cyan -NoNewline
    Write-Host "$($baseline.processes.Count)" -ForegroundColor Green
    Write-Host "Unique Users:              " -ForegroundColor Cyan -NoNewline
    Write-Host "$($byUser.Count)" -ForegroundColor White
    Write-Host "Unique Executable Dirs:    " -ForegroundColor Cyan -NoNewline
    Write-Host "$($byDirectory.Count)" -ForegroundColor White
    Write-Host "Suspicious Locations:      " -ForegroundColor Cyan -NoNewline
    Write-Host "$suspiciousCount" -ForegroundColor $(if ($suspiciousCount -gt 0) { "Yellow" } else { "Green" })

    # Processes with hashes
    $withHash = ($baseline.processes | Where-Object { $_.exe_hash }).Count
    Write-Host "Processes with Hash:       " -ForegroundColor Cyan -NoNewline
    Write-Host "$withHash" -ForegroundColor White
}

# Main
switch ($Mode) {
    "baseline" {
        New-ProcessBaseline -OutputPath $OutputFile
    }
    "scan" {
        if ([string]::IsNullOrEmpty($BaselineFile)) {
            Write-Error2 "Baseline file required for scan mode (-BaselineFile)"
            exit 1
        }
        Invoke-ProcessScan -BaselinePath $BaselineFile
    }
    "show" {
        if ([string]::IsNullOrEmpty($BaselineFile)) {
            Write-Error2 "Baseline file required for show mode (-BaselineFile)"
            exit 1
        }
        Show-BaselineResults -BaselinePath $BaselineFile -ShowAll $All.IsPresent -ShowLimit $Limit
    }
    "recon" {
        Invoke-ReconScan -LookbackHours $Hours
    }
}

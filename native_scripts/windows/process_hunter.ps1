<#
.SYNOPSIS
    Process Hunter - Pure PowerShell Implementation
    No external dependencies - uses native cmdlets only

.DESCRIPTION
    Searches for processes matching patterns and detects suspicious indicators.
    Supports regex search on process names, command lines, and paths.
    Can terminate processes interactively or in bulk.

.PARAMETER Pattern
    Regex pattern to search for (searches name, cmdline, path)

.PARAMETER ListSuspicious
    List all processes with suspicious indicators

.PARAMETER Kill
    Terminate matching processes (prompts for confirmation)

.PARAMETER Force
    Skip confirmation when killing processes

.PARAMETER All
    Show all processes (no filtering)

.EXAMPLE
    .\process_hunter.ps1 -Pattern "powershell.*-enc"
    .\process_hunter.ps1 -ListSuspicious
    .\process_hunter.ps1 -Pattern "nc\.exe" -Kill
#>

param(
    [Parameter(Position=0)]
    [string]$Pattern,

    [Parameter()]
    [switch]$ListSuspicious,

    [Parameter()]
    [switch]$Kill,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [switch]$All
)

# Strict mode
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Colors for output
function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
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

function Write-Suspicious {
    param([string]$Text)
    Write-Host "[SUSPICIOUS] $Text" -ForegroundColor Red
}

# Suspicious patterns for detection
$SuspiciousCmdlinePatterns = @(
    @{ Pattern = "powershell.*-enc"; Description = "Encoded PowerShell command" }
    @{ Pattern = "-encodedcommand"; Description = "Encoded PowerShell command" }
    @{ Pattern = "frombase64string"; Description = "Base64 decoding" }
    @{ Pattern = "invoke-expression|iex\s"; Description = "Dynamic code execution" }
    @{ Pattern = "downloadstring|downloadfile"; Description = "Remote download" }
    @{ Pattern = "webclient|webrequest"; Description = "Web request (possible download)" }
    @{ Pattern = "bypass|unrestricted|hidden"; Description = "Execution policy bypass" }
    @{ Pattern = "net\s+user|net\s+localgroup"; Description = "User/group enumeration" }
    @{ Pattern = "whoami|hostname|systeminfo"; Description = "System reconnaissance" }
    @{ Pattern = "mimikatz|sekurlsa|lsadump"; Description = "Credential theft tool" }
    @{ Pattern = "psexec|wmic.*process"; Description = "Remote execution" }
    @{ Pattern = "nc\.exe|ncat|netcat"; Description = "Netcat network tool" }
    @{ Pattern = "certutil.*-decode"; Description = "Certutil decode (LOLBin)" }
    @{ Pattern = "bitsadmin.*transfer"; Description = "BITS transfer (LOLBin)" }
    @{ Pattern = "mshta.*http"; Description = "MSHTA remote execution" }
    @{ Pattern = "regsvr32.*\/s.*\/u.*\/i:"; Description = "Regsvr32 script execution" }
    @{ Pattern = "rundll32.*javascript"; Description = "Rundll32 script execution" }
    @{ Pattern = "wscript.*http|cscript.*http"; Description = "Script engine remote execution" }
)

$SuspiciousProcessNames = @(
    "nc", "ncat", "netcat", "socat",
    "mimikatz", "procdump", "psexec",
    "wce", "fgdump", "pwdump",
    "lazagne", "empire", "covenant",
    "meterpreter", "beacon"
)

$SuspiciousPathPatterns = @(
    "\\Temp\\",
    "\\tmp\\",
    "\\AppData\\Local\\Temp\\",
    "\\Users\\Public\\",
    "\\ProgramData\\",
    "\\Windows\\Temp\\",
    "\\Recycle",
    "\\.exe$"  # exe directly in root of suspicious paths
)

# Check for suspicious indicators
function Get-SuspiciousIndicators {
    param(
        [string]$Name,
        [string]$Cmdline,
        [string]$Exe
    )

    $indicators = @()

    # Check process name
    if ($Name -in $SuspiciousProcessNames) {
        $indicators += "Suspicious process name: $Name"
    }

    # Check cmdline patterns
    foreach ($pattern in $SuspiciousCmdlinePatterns) {
        if ($Cmdline -match $pattern.Pattern) {
            $indicators += $pattern.Description
        }
    }

    # Check executable path
    foreach ($pathPattern in $SuspiciousPathPatterns) {
        if ($Exe -match $pathPattern) {
            $indicators += "Executable in suspicious location: $Exe"
            break
        }
    }

    # Check for deleted/missing executable
    if ($Exe -and -not (Test-Path -Path $Exe -ErrorAction SilentlyContinue)) {
        $indicators += "Executable not found on disk (deleted?)"
    }

    # Check for hidden window
    # (Cannot easily detect without P/Invoke, skip for pure PowerShell)

    return $indicators
}

# Get process details via WMI
function Get-ProcessDetailsWmi {
    param([int]$ProcessId)

    $info = @{
        pid = $ProcessId
        name = ""
        ppid = 0
        username = ""
        exe = ""
        cmdline = ""
        start_time = $null
        working_set = 0
        suspicious = @()
    }

    try {
        $wmiProc = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue

        if ($wmiProc) {
            $info.name = $wmiProc.Name
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

            # Get start time
            if ($wmiProc.CreationDate) {
                $info.start_time = $wmiProc.CreationDate
            }
        }

        # Get working set from Process object
        $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($proc) {
            $info.working_set = $proc.WorkingSet64
            if (-not $info.name) {
                $info.name = $proc.ProcessName
            }
        }

        # Check for suspicious indicators
        $info.suspicious = Get-SuspiciousIndicators -Name $info.name -Cmdline $info.cmdline -Exe $info.exe
    }
    catch {
        # Process may have exited
    }

    return $info
}

# Display process details
function Show-ProcessDetails {
    param($ProcessInfo)

    $p = $ProcessInfo

    Write-Host ""
    Write-Host "─" * 70 -ForegroundColor DarkGray

    if ($p.suspicious.Count -gt 0) {
        Write-Host "PID: $($p.pid) | $($p.name)" -ForegroundColor Red
    } else {
        Write-Host "PID: $($p.pid) | $($p.name)" -ForegroundColor Green
    }

    Write-Host "─" * 70 -ForegroundColor DarkGray
    Write-Host "  User:       $($p.username)" -ForegroundColor Cyan
    Write-Host "  PPID:       $($p.ppid)" -ForegroundColor Cyan
    Write-Host "  Exe:        $($p.exe)" -ForegroundColor Cyan

    # Truncate long cmdlines
    $cmdDisplay = if ($p.cmdline.Length -gt 200) {
        $p.cmdline.Substring(0, 200) + "..."
    } else {
        $p.cmdline
    }
    Write-Host "  Cmdline:    $cmdDisplay" -ForegroundColor Cyan

    if ($p.start_time) {
        Write-Host "  Started:    $($p.start_time)" -ForegroundColor Cyan
    }

    $memMB = [math]::Round($p.working_set / 1MB, 2)
    Write-Host "  Memory:     $memMB MB" -ForegroundColor Cyan

    # Show suspicious indicators
    if ($p.suspicious.Count -gt 0) {
        Write-Host ""
        foreach ($indicator in $p.suspicious) {
            Write-Host "  [!] $indicator" -ForegroundColor Red
        }
    }
}

# Search processes
function Search-Processes {
    param([string]$SearchPattern)

    Write-Header "Process Hunt: $SearchPattern"

    $matches = @()
    $allProcs = Get-Process -ErrorAction SilentlyContinue

    foreach ($proc in $allProcs) {
        if ($proc.Id -eq 0) { continue }

        $details = Get-ProcessDetailsWmi -ProcessId $proc.Id

        # Search in name, cmdline, and exe path
        $searchText = "$($details.name) $($details.cmdline) $($details.exe)"

        if ($searchText -match $SearchPattern) {
            $matches += $details
        }
    }

    if ($matches.Count -eq 0) {
        Write-Info "No processes matching '$SearchPattern'"
        return @()
    }

    Write-Info "Found $($matches.Count) matching processes"

    foreach ($match in $matches) {
        Show-ProcessDetails -ProcessInfo $match
    }

    return $matches
}

# List all suspicious processes
function Get-SuspiciousProcesses {
    Write-Header "Suspicious Process Scan"

    $suspicious = @()
    $allProcs = Get-Process -ErrorAction SilentlyContinue
    $total = $allProcs.Count
    $count = 0

    foreach ($proc in $allProcs) {
        $count++

        if ($count % 50 -eq 0) {
            Write-Host "`r[*] Scanning $count / $total processes..." -NoNewline -ForegroundColor Blue
        }

        if ($proc.Id -eq 0) { continue }

        $details = Get-ProcessDetailsWmi -ProcessId $proc.Id

        if ($details.suspicious.Count -gt 0) {
            $suspicious += $details
        }
    }

    Write-Host ""

    if ($suspicious.Count -eq 0) {
        Write-Success "No suspicious processes detected"
        return @()
    }

    Write-Warning2 "Found $($suspicious.Count) suspicious processes"

    foreach ($proc in $suspicious) {
        Show-ProcessDetails -ProcessInfo $proc
    }

    return $suspicious
}

# List all processes
function Get-AllProcesses {
    Write-Header "All Processes"

    $allProcs = Get-Process -ErrorAction SilentlyContinue | Sort-Object -Property Id
    $results = @()

    foreach ($proc in $allProcs) {
        if ($proc.Id -eq 0) { continue }

        $details = Get-ProcessDetailsWmi -ProcessId $proc.Id
        $results += $details
        Show-ProcessDetails -ProcessInfo $details
    }

    Write-Info "Total processes: $($results.Count)"
    return $results
}

# Kill processes
function Stop-TargetProcesses {
    param(
        [array]$Processes,
        [switch]$NoConfirm
    )

    if ($Processes.Count -eq 0) {
        Write-Info "No processes to terminate"
        return
    }

    Write-Header "Process Termination"

    Write-Warning2 "The following processes will be terminated:"
    foreach ($p in $Processes) {
        Write-Host "  - PID $($p.pid): $($p.name)" -ForegroundColor Yellow
    }

    if (-not $NoConfirm) {
        Write-Host ""
        $confirm = Read-Host "Are you sure you want to terminate these processes? (yes/no)"

        if ($confirm -ne "yes") {
            Write-Info "Termination cancelled"
            return
        }
    }

    Write-Host ""

    foreach ($p in $Processes) {
        try {
            Stop-Process -Id $p.pid -Force -ErrorAction Stop
            Write-Success "Terminated PID $($p.pid): $($p.name)"
        }
        catch {
            Write-Error2 "Failed to terminate PID $($p.pid): $($_.Exception.Message)"
        }
    }
}

# Show usage
function Show-Usage {
    Write-Host "Process Hunter - Pure PowerShell"
    Write-Host ""
    Write-Host "Usage: .\process_hunter.ps1 [options]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Pattern <regex>    Search for processes matching pattern"
    Write-Host "  -ListSuspicious     List all suspicious processes"
    Write-Host "  -All                Show all processes"
    Write-Host "  -Kill               Terminate matching processes"
    Write-Host "  -Force              Skip confirmation when killing"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\process_hunter.ps1 -Pattern 'powershell.*-enc'"
    Write-Host "  .\process_hunter.ps1 -ListSuspicious"
    Write-Host "  .\process_hunter.ps1 -Pattern 'nc\.exe' -Kill"
    Write-Host "  .\process_hunter.ps1 -ListSuspicious -Kill -Force"
    Write-Host ""
    Write-Host "Suspicious Patterns Detected:"
    Write-Host "  - Encoded PowerShell commands"
    Write-Host "  - Base64 decoding operations"
    Write-Host "  - Remote download operations"
    Write-Host "  - Execution policy bypasses"
    Write-Host "  - Known malicious tools (mimikatz, etc.)"
    Write-Host "  - LOLBins (certutil, mshta, etc.)"
    Write-Host "  - Executables in temp directories"
    Write-Host "  - Deleted executables"
}

# Main
if (-not $Pattern -and -not $ListSuspicious -and -not $All) {
    Show-Usage
    exit 0
}

$targetProcesses = @()

if ($All) {
    $targetProcesses = Get-AllProcesses
}
elseif ($ListSuspicious) {
    $targetProcesses = Get-SuspiciousProcesses
}
elseif ($Pattern) {
    $targetProcesses = Search-Processes -SearchPattern $Pattern
}

if ($Kill -and $targetProcesses.Count -gt 0) {
    Stop-TargetProcesses -Processes $targetProcesses -NoConfirm:$Force
}

# Summary
Write-Host ""
Write-Header "Hunt Complete"

$suspiciousCount = ($targetProcesses | Where-Object { $_.suspicious.Count -gt 0 }).Count

if ($suspiciousCount -gt 0) {
    Write-Warning2 "Processes with suspicious indicators: $suspiciousCount"
} else {
    Write-Success "No suspicious indicators detected"
}

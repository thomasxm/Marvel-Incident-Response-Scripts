<#
.SYNOPSIS
    Persistence Anomaly Detection - Pure PowerShell Implementation
    No external dependencies - uses native cmdlets only

.DESCRIPTION
    Creates persistence mechanism baselines and detects anomalies by comparing
    current state against baseline. Supports MITRE ATT&CK mapping and risk scoring.

    Categories covered:
    Level 1 (Essential): run-keys, scheduled-tasks, services, startup-folder
    Level 2 (Comprehensive): winlogon, appinit-dlls, image-hijacks, browser-helpers, com-hijacks
    Level 3 (Exhaustive): wmi-subscriptions, boot-execute, lsa-packages, print-monitors, netsh-helpers, office-addins, bits-jobs

.PARAMETER Mode
    baseline - Create a baseline of persistence mechanisms
    scan - Scan for anomalies against baseline
    show - Display baseline/scan results in formatted table

.PARAMETER OutputFile
    Output file for baseline/scan results

.PARAMETER BaselineFile
    Baseline file for scan mode comparison

.PARAMETER File
    File to display (show mode)

.PARAMETER Level
    Scan level: 1=Essential, 2=Comprehensive, 3=Exhaustive (default: 2)

.PARAMETER Category
    Specific categories to scan (comma-separated)

.EXAMPLE
    .\persistence_anomaly.ps1 baseline -Level 2 -OutputFile baseline.json
    .\persistence_anomaly.ps1 scan -BaselineFile baseline.json -Level 2 -OutputFile results.json
    .\persistence_anomaly.ps1 show -File results.json
#>

param(
    [Parameter(Position=0, Mandatory=$true)]
    [ValidateSet("baseline", "scan", "show")]
    [string]$Mode,

    [Parameter()]
    [string]$OutputFile,

    [Parameter()]
    [string]$BaselineFile,

    [Parameter()]
    [string]$File,

    [Parameter()]
    [ValidateRange(1, 3)]
    [int]$Level = 2,

    [Parameter()]
    [string]$Category,

    [Parameter()]
    [switch]$All,

    [Parameter()]
    [int]$Limit = 5
)

# Strict mode
Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# MITRE ATT&CK Mappings and Category Definitions
$CategoryInfo = @{
    "run-keys"          = @{ Level = 1; Technique = "T1547.001"; Description = "Registry Run Keys" }
    "scheduled-tasks"   = @{ Level = 1; Technique = "T1053.005"; Description = "Scheduled Tasks" }
    "services"          = @{ Level = 1; Technique = "T1543.003"; Description = "Windows Services" }
    "startup-folder"    = @{ Level = 1; Technique = "T1547.001"; Description = "Startup Folder" }
    "winlogon"          = @{ Level = 2; Technique = "T1547.004"; Description = "Winlogon Helper DLL" }
    "appinit-dlls"      = @{ Level = 2; Technique = "T1546.010"; Description = "AppInit DLLs" }
    "image-hijacks"     = @{ Level = 2; Technique = "T1546.012"; Description = "Image File Execution Options" }
    "browser-helpers"   = @{ Level = 2; Technique = "T1176"; Description = "Browser Helper Objects" }
    "com-hijacks"       = @{ Level = 2; Technique = "T1546.015"; Description = "COM Object Hijacking" }
    "wmi-subscriptions" = @{ Level = 3; Technique = "T1546.003"; Description = "WMI Event Subscription" }
    "boot-execute"      = @{ Level = 3; Technique = "T1547.012"; Description = "Boot Execute" }
    "lsa-packages"      = @{ Level = 3; Technique = "T1547.002"; Description = "LSA Authentication Packages" }
    "print-monitors"    = @{ Level = 3; Technique = "T1547.010"; Description = "Print Monitors" }
    "netsh-helpers"     = @{ Level = 3; Technique = "T1546.007"; Description = "Netsh Helper DLLs" }
    "office-addins"     = @{ Level = 3; Technique = "T1137"; Description = "Office Application Addins" }
    "bits-jobs"         = @{ Level = 3; Technique = "T1197"; Description = "BITS Jobs" }
}

# Color output functions
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

function Write-Suspicious {
    param([string]$Text)
    Write-Host "    [!] SUSPICIOUS: $Text" -ForegroundColor Red
}

# Utility functions
function Get-SHA256Hash {
    param([string]$Content)
    if ([string]::IsNullOrEmpty($Content)) {
        return "empty"
    }
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
    $hash = $sha256.ComputeHash($bytes)
    return [BitConverter]::ToString($hash).Replace("-", "").ToLower()
}

function Get-FileHashSafe {
    param([string]$FilePath)
    if (Test-Path $FilePath -PathType Leaf) {
        try {
            $hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop
            return $hash.Hash.ToLower()
        } catch {
            return "inaccessible"
        }
    }
    return "not_found"
}

function Get-ContentPreview {
    param([string]$Content, [int]$MaxLength = 200)
    if ([string]::IsNullOrEmpty($Content)) { return "" }
    $cleaned = $Content -replace "`r`n|`n|`r", " " -replace "\s+", " "
    if ($cleaned.Length -gt $MaxLength) {
        return $cleaned.Substring(0, $MaxLength) + "..."
    }
    return $cleaned
}

function Get-RiskIndicators {
    param(
        [string]$Path,
        [string]$Content,
        [string]$Value,
        [datetime]$ModTime
    )

    $indicators = @()
    $checkString = "$Content $Value $Path"

    # Path-based indicators
    $suspiciousPaths = @(
        "\\temp\\", "\\tmp\\", "\$env:TEMP", "\$env:TMP",
        "\\appdata\\local\\temp", "\\users\\public\\",
        "\\programdata\\", "\\downloads\\"
    )
    foreach ($sp in $suspiciousPaths) {
        if ($Path -like "*$sp*") {
            $indicators += "Suspicious path location"
            break
        }
    }

    # Encoded/obfuscated content
    if ($checkString -match "-enc|-encodedcommand|frombase64|convert.*base64") {
        $indicators += "Base64/encoded content"
    }

    # Network commands
    if ($checkString -match "invoke-webrequest|wget|curl|downloadstring|downloadfile|net\.webclient|bitstransfer") {
        $indicators += "Network download capability"
    }

    # Execution patterns
    if ($checkString -match "iex|invoke-expression|cmd\.exe\s*/c|powershell.*-nop|-windowstyle\s*hidden|-w\s+hidden") {
        $indicators += "Suspicious execution pattern"
    }

    # Hidden execution
    if ($checkString -match "-windowstyle\s*hidden|-w\s+h|/b\s+/wait|minimized|start-process.*-nonewwindow") {
        $indicators += "Hidden execution"
    }

    # Script files in unusual locations
    if ($Path -match "\.(ps1|bat|cmd|vbs|js|hta)$" -and $Path -match "(temp|tmp|appdata|public)") {
        $indicators += "Script in unusual location"
    }

    # Recently modified (within 24 hours)
    if ($ModTime -and ((Get-Date) - $ModTime).TotalHours -lt 24) {
        $indicators += "Recently modified (<24h)"
    }

    # Obfuscated names
    if ($Path -match "^[a-z0-9]{8,}\.(exe|dll|ps1)$" -or $Path -match "[^\x00-\x7F]") {
        $indicators += "Obfuscated/random filename"
    }

    return $indicators
}

function Get-RiskScore {
    param([array]$Indicators)

    $count = $Indicators.Count

    # Critical conditions
    $criticalPatterns = @("Network download capability", "Suspicious execution pattern")
    $hasCritical = $false
    foreach ($pattern in $criticalPatterns) {
        if ($Indicators -contains $pattern -and
            ($Indicators -contains "Hidden execution" -or $Indicators -contains "Base64/encoded content")) {
            $hasCritical = $true
            break
        }
    }

    if ($count -ge 3 -or $hasCritical) { return "CRITICAL" }
    if ($count -ge 2 -or ($Indicators -contains "Base64/encoded content")) { return "HIGH" }
    if ($count -ge 1) { return "MEDIUM" }
    return "LOW"
}

function Get-CategoriesToScan {
    param(
        [int]$ScanLevel,
        [string]$CategoryFilter
    )

    $categories = @()

    if ($CategoryFilter) {
        $requested = $CategoryFilter.Split(',') | ForEach-Object { $_.Trim().ToLower() }
        foreach ($cat in $requested) {
            if ($CategoryInfo.ContainsKey($cat)) {
                $categories += $cat
            } else {
                Write-Warning2 "Unknown category: $cat"
            }
        }
    } else {
        foreach ($cat in $CategoryInfo.Keys) {
            if ($CategoryInfo[$cat].Level -le $ScanLevel) {
                $categories += $cat
            }
        }
    }

    return $categories | Sort-Object { $CategoryInfo[$_].Level }
}

# Scanning functions for each category
function Scan-RunKeys {
    $entries = @()

    $runKeyPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    foreach ($keyPath in $runKeyPaths) {
        if (Test-Path $keyPath) {
            Write-Info "Scanning: $keyPath"
            try {
                $key = Get-Item -Path $keyPath -ErrorAction SilentlyContinue
                if ($key) {
                    foreach ($valueName in $key.GetValueNames()) {
                        if ([string]::IsNullOrEmpty($valueName)) { continue }
                        $value = $key.GetValue($valueName)
                        $entry = @{
                            category = "run-keys"
                            path = "$keyPath\$valueName"
                            name = $valueName
                            value = $value
                            content_hash = Get-SHA256Hash -Content "$valueName=$value"
                            mitre_technique = "T1547.001"
                            command_preview = Get-ContentPreview -Content $value
                        }
                        $entries += $entry
                    }
                }
            } catch {
                # Access denied or other error
            }
        }
    }

    return $entries
}

function Scan-ScheduledTasks {
    $entries = @()

    Write-Info "Scanning: Scheduled Tasks"

    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne "Disabled" }

        foreach ($task in $tasks) {
            try {
                $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                $actions = $task.Actions | ForEach-Object {
                    if ($_.Execute) {
                        "$($_.Execute) $($_.Arguments)"
                    }
                }
                $actionStr = $actions -join "; "

                $entry = @{
                    category = "scheduled-tasks"
                    path = "$($task.TaskPath)$($task.TaskName)"
                    name = $task.TaskName
                    state = $task.State.ToString()
                    author = $task.Author
                    actions = $actionStr
                    content_hash = Get-SHA256Hash -Content "$($task.TaskName)$actionStr"
                    mitre_technique = "T1053.005"
                    command_preview = Get-ContentPreview -Content $actionStr
                }

                if ($taskInfo.LastRunTime) {
                    $entry.last_run = $taskInfo.LastRunTime.ToString("o")
                }

                $entries += $entry
            } catch {
                # Skip tasks we can't read
            }
        }
    } catch {
        Write-Warning2 "Could not enumerate scheduled tasks: $_"
    }

    return $entries
}

function Scan-Services {
    $entries = @()

    Write-Info "Scanning: Services"

    try {
        $services = Get-WmiObject -Class Win32_Service -ErrorAction SilentlyContinue

        foreach ($svc in $services) {
            # Skip services with empty paths
            if ([string]::IsNullOrEmpty($svc.PathName)) { continue }

            $entry = @{
                category = "services"
                path = "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)"
                name = $svc.Name
                display_name = $svc.DisplayName
                state = $svc.State
                start_mode = $svc.StartMode
                path_name = $svc.PathName
                account = $svc.StartName
                content_hash = Get-SHA256Hash -Content "$($svc.Name)$($svc.PathName)"
                mitre_technique = "T1543.003"
                command_preview = Get-ContentPreview -Content $svc.PathName
            }
            $entries += $entry
        }
    } catch {
        Write-Warning2 "Could not enumerate services: $_"
    }

    return $entries
}

function Scan-StartupFolder {
    $entries = @()

    $startupFolders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )

    foreach ($folder in $startupFolders) {
        if (Test-Path $folder) {
            Write-Info "Scanning: $folder"
            $files = Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                $hash = Get-FileHashSafe -FilePath $file.FullName
                $entry = @{
                    category = "startup-folder"
                    path = $file.FullName
                    name = $file.Name
                    size = $file.Length
                    mtime = $file.LastWriteTime.ToString("o")
                    content_hash = $hash
                    mitre_technique = "T1547.001"
                    command_preview = $file.Name
                }
                $entries += $entry
            }
        }
    }

    return $entries
}

function Scan-Winlogon {
    $entries = @()

    $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $valuesToCheck = @("Shell", "Userinit", "Taskman", "AppSetup")

    if (Test-Path $winlogonPath) {
        Write-Info "Scanning: $winlogonPath"
        foreach ($valueName in $valuesToCheck) {
            try {
                $value = Get-ItemProperty -Path $winlogonPath -Name $valueName -ErrorAction SilentlyContinue
                if ($value -and $value.$valueName) {
                    $entry = @{
                        category = "winlogon"
                        path = "$winlogonPath\$valueName"
                        name = $valueName
                        value = $value.$valueName
                        content_hash = Get-SHA256Hash -Content "$valueName=$($value.$valueName)"
                        mitre_technique = "T1547.004"
                        command_preview = Get-ContentPreview -Content $value.$valueName
                    }
                    $entries += $entry
                }
            } catch { }
        }
    }

    return $entries
}

function Scan-AppInitDLLs {
    $entries = @()

    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
    )

    foreach ($keyPath in $paths) {
        if (Test-Path $keyPath) {
            Write-Info "Scanning: $keyPath"
            try {
                $appInit = Get-ItemProperty -Path $keyPath -Name "AppInit_DLLs" -ErrorAction SilentlyContinue
                $loadAppInit = Get-ItemProperty -Path $keyPath -Name "LoadAppInit_DLLs" -ErrorAction SilentlyContinue

                if ($appInit -and $appInit.AppInit_DLLs) {
                    $entry = @{
                        category = "appinit-dlls"
                        path = "$keyPath\AppInit_DLLs"
                        name = "AppInit_DLLs"
                        value = $appInit.AppInit_DLLs
                        load_enabled = if ($loadAppInit) { $loadAppInit.LoadAppInit_DLLs } else { 0 }
                        content_hash = Get-SHA256Hash -Content $appInit.AppInit_DLLs
                        mitre_technique = "T1546.010"
                        command_preview = Get-ContentPreview -Content $appInit.AppInit_DLLs
                    }
                    $entries += $entry
                }
            } catch { }
        }
    }

    return $entries
}

function Scan-ImageHijacks {
    $entries = @()

    $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"

    if (Test-Path $ifeoPath) {
        Write-Info "Scanning: $ifeoPath"
        $subkeys = Get-ChildItem -Path $ifeoPath -ErrorAction SilentlyContinue

        foreach ($key in $subkeys) {
            try {
                $debugger = Get-ItemProperty -Path $key.PSPath -Name "Debugger" -ErrorAction SilentlyContinue
                if ($debugger -and $debugger.Debugger) {
                    $entry = @{
                        category = "image-hijacks"
                        path = $key.PSPath
                        name = $key.PSChildName
                        debugger = $debugger.Debugger
                        content_hash = Get-SHA256Hash -Content "$($key.PSChildName)=$($debugger.Debugger)"
                        mitre_technique = "T1546.012"
                        command_preview = Get-ContentPreview -Content $debugger.Debugger
                    }
                    $entries += $entry
                }
            } catch { }
        }
    }

    return $entries
}

function Scan-BrowserHelpers {
    $entries = @()

    $bhoPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"

    if (Test-Path $bhoPath) {
        Write-Info "Scanning: $bhoPath"
        $subkeys = Get-ChildItem -Path $bhoPath -ErrorAction SilentlyContinue

        foreach ($key in $subkeys) {
            $clsid = $key.PSChildName
            $clsidPath = "HKCR:\CLSID\$clsid\InprocServer32"

            $dllPath = ""
            if (Test-Path $clsidPath) {
                $dll = Get-ItemProperty -Path $clsidPath -Name "(default)" -ErrorAction SilentlyContinue
                if ($dll) { $dllPath = $dll.'(default)' }
            }

            $entry = @{
                category = "browser-helpers"
                path = $key.PSPath
                name = $clsid
                dll_path = $dllPath
                content_hash = Get-SHA256Hash -Content "$clsid$dllPath"
                mitre_technique = "T1176"
                command_preview = Get-ContentPreview -Content $dllPath
            }
            $entries += $entry
        }
    }

    return $entries
}

function Scan-COMHijacks {
    $entries = @()

    Write-Info "Scanning: COM Objects (limited scan)"

    # Scan specific high-value COM objects often abused
    $suspiciousCLSIDs = @(
        "{BCDE0395-E52F-467C-8E3D-C4579291692E}",  # MMDeviceEnumerator
        "{F5078F35-C551-11D3-89B9-0000F81FE221}",  # MSXML2.FreeThreadedDOMDocument
        "{0002DF01-0000-0000-C000-000000000046}"   # Internet Explorer
    )

    foreach ($clsid in $suspiciousCLSIDs) {
        $clsidPath = "HKCR:\CLSID\$clsid\InprocServer32"
        $treatAsPath = "HKCR:\CLSID\$clsid\TreatAs"

        if (Test-Path $clsidPath) {
            try {
                $dll = Get-ItemProperty -Path $clsidPath -Name "(default)" -ErrorAction SilentlyContinue
                if ($dll -and $dll.'(default)') {
                    $entry = @{
                        category = "com-hijacks"
                        path = $clsidPath
                        name = $clsid
                        dll_path = $dll.'(default)'
                        content_hash = Get-SHA256Hash -Content "$clsid$($dll.'(default)')"
                        mitre_technique = "T1546.015"
                        command_preview = Get-ContentPreview -Content $dll.'(default)'
                    }
                    $entries += $entry
                }
            } catch { }
        }
    }

    return $entries
}

function Scan-WMISubscriptions {
    $entries = @()

    Write-Info "Scanning: WMI Event Subscriptions"

    try {
        $filters = Get-WmiObject -Namespace "root\subscription" -Class __EventFilter -ErrorAction SilentlyContinue
        $consumers = Get-WmiObject -Namespace "root\subscription" -Class __EventConsumer -ErrorAction SilentlyContinue
        $bindings = Get-WmiObject -Namespace "root\subscription" -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue

        foreach ($filter in $filters) {
            $entry = @{
                category = "wmi-subscriptions"
                path = "WMI:root\subscription\__EventFilter\$($filter.Name)"
                name = $filter.Name
                query = $filter.Query
                query_language = $filter.QueryLanguage
                type = "EventFilter"
                content_hash = Get-SHA256Hash -Content "$($filter.Name)$($filter.Query)"
                mitre_technique = "T1546.003"
                command_preview = Get-ContentPreview -Content $filter.Query
            }
            $entries += $entry
        }

        foreach ($consumer in $consumers) {
            $consumerType = $consumer.__CLASS
            $commandLine = ""

            if ($consumer.CommandLineTemplate) {
                $commandLine = $consumer.CommandLineTemplate
            } elseif ($consumer.ScriptText) {
                $commandLine = $consumer.ScriptText
            } elseif ($consumer.ScriptFileName) {
                $commandLine = $consumer.ScriptFileName
            }

            $entry = @{
                category = "wmi-subscriptions"
                path = "WMI:root\subscription\$consumerType\$($consumer.Name)"
                name = $consumer.Name
                consumer_type = $consumerType
                command = $commandLine
                type = "EventConsumer"
                content_hash = Get-SHA256Hash -Content "$($consumer.Name)$commandLine"
                mitre_technique = "T1546.003"
                command_preview = Get-ContentPreview -Content $commandLine
            }
            $entries += $entry
        }
    } catch {
        Write-Warning2 "Could not enumerate WMI subscriptions: $_"
    }

    return $entries
}

function Scan-BootExecute {
    $entries = @()

    $sessionManagerPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"

    if (Test-Path $sessionManagerPath) {
        Write-Info "Scanning: $sessionManagerPath"
        try {
            $bootExec = Get-ItemProperty -Path $sessionManagerPath -Name "BootExecute" -ErrorAction SilentlyContinue
            if ($bootExec -and $bootExec.BootExecute) {
                $values = $bootExec.BootExecute -join ";"
                $entry = @{
                    category = "boot-execute"
                    path = "$sessionManagerPath\BootExecute"
                    name = "BootExecute"
                    values = $bootExec.BootExecute
                    content_hash = Get-SHA256Hash -Content $values
                    mitre_technique = "T1547.012"
                    command_preview = Get-ContentPreview -Content $values
                }
                $entries += $entry
            }
        } catch { }
    }

    return $entries
}

function Scan-LSAPackages {
    $entries = @()

    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $valuesToCheck = @("Security Packages", "Authentication Packages", "Notification Packages")

    if (Test-Path $lsaPath) {
        Write-Info "Scanning: $lsaPath"
        foreach ($valueName in $valuesToCheck) {
            try {
                $value = Get-ItemProperty -Path $lsaPath -Name $valueName -ErrorAction SilentlyContinue
                if ($value -and $value.$valueName) {
                    $packages = $value.$valueName -join ";"
                    $entry = @{
                        category = "lsa-packages"
                        path = "$lsaPath\$valueName"
                        name = $valueName
                        packages = $value.$valueName
                        content_hash = Get-SHA256Hash -Content $packages
                        mitre_technique = "T1547.002"
                        command_preview = Get-ContentPreview -Content $packages
                    }
                    $entries += $entry
                }
            } catch { }
        }
    }

    return $entries
}

function Scan-PrintMonitors {
    $entries = @()

    $monitorPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors"

    if (Test-Path $monitorPath) {
        Write-Info "Scanning: $monitorPath"
        $subkeys = Get-ChildItem -Path $monitorPath -ErrorAction SilentlyContinue

        foreach ($key in $subkeys) {
            try {
                $driver = Get-ItemProperty -Path $key.PSPath -Name "Driver" -ErrorAction SilentlyContinue
                if ($driver -and $driver.Driver) {
                    $entry = @{
                        category = "print-monitors"
                        path = $key.PSPath
                        name = $key.PSChildName
                        driver = $driver.Driver
                        content_hash = Get-SHA256Hash -Content "$($key.PSChildName)$($driver.Driver)"
                        mitre_technique = "T1547.010"
                        command_preview = Get-ContentPreview -Content $driver.Driver
                    }
                    $entries += $entry
                }
            } catch { }
        }
    }

    return $entries
}

function Scan-NetshHelpers {
    $entries = @()

    $netshPath = "HKLM:\SOFTWARE\Microsoft\NetSh"

    if (Test-Path $netshPath) {
        Write-Info "Scanning: $netshPath"
        try {
            $key = Get-Item -Path $netshPath -ErrorAction SilentlyContinue
            if ($key) {
                foreach ($valueName in $key.GetValueNames()) {
                    if ([string]::IsNullOrEmpty($valueName)) { continue }
                    $value = $key.GetValue($valueName)
                    $entry = @{
                        category = "netsh-helpers"
                        path = "$netshPath\$valueName"
                        name = $valueName
                        dll = $value
                        content_hash = Get-SHA256Hash -Content "$valueName=$value"
                        mitre_technique = "T1546.007"
                        command_preview = Get-ContentPreview -Content $value
                    }
                    $entries += $entry
                }
            }
        } catch { }
    }

    return $entries
}

function Scan-OfficeAddins {
    $entries = @()

    $officeApps = @("Word", "Excel", "PowerPoint", "Outlook")
    $officeVersions = @("16.0", "15.0", "14.0")

    Write-Info "Scanning: Office Add-ins"

    foreach ($app in $officeApps) {
        foreach ($ver in $officeVersions) {
            $addinPath = "HKCU:\Software\Microsoft\Office\$ver\$app\Addins"

            if (Test-Path $addinPath) {
                $subkeys = Get-ChildItem -Path $addinPath -ErrorAction SilentlyContinue

                foreach ($key in $subkeys) {
                    try {
                        $props = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
                        $entry = @{
                            category = "office-addins"
                            path = $key.PSPath
                            name = $key.PSChildName
                            application = $app
                            version = $ver
                            description = if ($props.Description) { $props.Description } else { "" }
                            load_behavior = if ($props.LoadBehavior) { $props.LoadBehavior } else { 0 }
                            content_hash = Get-SHA256Hash -Content "$($key.PSChildName)$app$ver"
                            mitre_technique = "T1137"
                            command_preview = $key.PSChildName
                        }
                        $entries += $entry
                    } catch { }
                }
            }
        }
    }

    return $entries
}

function Scan-BITSJobs {
    $entries = @()

    Write-Info "Scanning: BITS Jobs"

    try {
        # Try using Get-BitsTransfer first
        $jobs = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue

        foreach ($job in $jobs) {
            $entry = @{
                category = "bits-jobs"
                path = "BITS:$($job.JobId)"
                name = $job.DisplayName
                job_id = $job.JobId.ToString()
                job_type = $job.TransferType.ToString()
                job_state = $job.JobState.ToString()
                owner = $job.OwnerAccount
                files = ($job | Get-BitsTransfer | Select-Object -ExpandProperty FileList | ForEach-Object { $_.RemoteName }) -join ";"
                content_hash = Get-SHA256Hash -Content "$($job.JobId)$($job.DisplayName)"
                mitre_technique = "T1197"
                command_preview = Get-ContentPreview -Content $job.DisplayName
            }
            $entries += $entry
        }
    } catch {
        # Fall back to bitsadmin if Get-BitsTransfer fails
        try {
            $output = & bitsadmin /list /allusers /verbose 2>$null
            if ($output) {
                # Parse bitsadmin output (basic parsing)
                $jobName = ""
                foreach ($line in $output) {
                    if ($line -match "DISPLAY:\s*(.+)") {
                        $jobName = $matches[1]
                    }
                    if ($line -match "GUID:\s*(.+)" -and $jobName) {
                        $entry = @{
                            category = "bits-jobs"
                            path = "BITS:$($matches[1])"
                            name = $jobName
                            job_id = $matches[1]
                            content_hash = Get-SHA256Hash -Content "$($matches[1])$jobName"
                            mitre_technique = "T1197"
                            command_preview = $jobName
                        }
                        $entries += $entry
                        $jobName = ""
                    }
                }
            }
        } catch { }
    }

    return $entries
}

# Main scanning dispatcher
function Get-PersistenceEntries {
    param(
        [int]$ScanLevel,
        [string]$CategoryFilter
    )

    $allEntries = @()
    $categories = Get-CategoriesToScan -ScanLevel $ScanLevel -CategoryFilter $CategoryFilter

    foreach ($cat in $categories) {
        switch ($cat) {
            "run-keys"          { $allEntries += Scan-RunKeys }
            "scheduled-tasks"   { $allEntries += Scan-ScheduledTasks }
            "services"          { $allEntries += Scan-Services }
            "startup-folder"    { $allEntries += Scan-StartupFolder }
            "winlogon"          { $allEntries += Scan-Winlogon }
            "appinit-dlls"      { $allEntries += Scan-AppInitDLLs }
            "image-hijacks"     { $allEntries += Scan-ImageHijacks }
            "browser-helpers"   { $allEntries += Scan-BrowserHelpers }
            "com-hijacks"       { $allEntries += Scan-COMHijacks }
            "wmi-subscriptions" { $allEntries += Scan-WMISubscriptions }
            "boot-execute"      { $allEntries += Scan-BootExecute }
            "lsa-packages"      { $allEntries += Scan-LSAPackages }
            "print-monitors"    { $allEntries += Scan-PrintMonitors }
            "netsh-helpers"     { $allEntries += Scan-NetshHelpers }
            "office-addins"     { $allEntries += Scan-OfficeAddins }
            "bits-jobs"         { $allEntries += Scan-BITSJobs }
        }
    }

    return $allEntries
}

# Baseline command
function Create-Baseline {
    param(
        [string]$OutputFile,
        [int]$ScanLevel,
        [string]$CategoryFilter
    )

    Write-Header "Creating Persistence Baseline"
    Write-Info "Scan Level: $ScanLevel"

    $categories = Get-CategoriesToScan -ScanLevel $ScanLevel -CategoryFilter $CategoryFilter
    Write-Info "Categories: $($categories -join ', ')"

    $entries = Get-PersistenceEntries -ScanLevel $ScanLevel -CategoryFilter $CategoryFilter

    $baseline = @{
        timestamp = (Get-Date).ToString("o")
        hostname = $env:COMPUTERNAME
        platform = "Windows"
        scan_level = $ScanLevel
        categories_scanned = $categories
        entries = $entries
    }

    $json = $baseline | ConvertTo-Json -Depth 10
    $json | Out-File -FilePath $OutputFile -Encoding UTF8

    Write-Host ""
    Write-Success "Baseline created: $OutputFile"
    Write-Info "Total entries: $($entries.Count)"
}

# Scan command
function Scan-Persistence {
    param(
        [string]$BaselineFile,
        [string]$OutputFile,
        [int]$ScanLevel,
        [string]$CategoryFilter
    )

    if (-not (Test-Path $BaselineFile)) {
        Write-Error2 "Baseline file not found: $BaselineFile"
        exit 1
    }

    Write-Header "Scanning for Persistence Anomalies"
    Write-Info "Baseline: $BaselineFile"
    Write-Info "Scan Level: $ScanLevel"

    # Load baseline
    $baselineContent = Get-Content -Path $BaselineFile -Raw | ConvertFrom-Json
    $baselineEntries = @{}
    foreach ($entry in $baselineContent.entries) {
        $baselineEntries[$entry.path] = $entry
    }

    # Get current entries
    $currentEntries = Get-PersistenceEntries -ScanLevel $ScanLevel -CategoryFilter $CategoryFilter
    $currentPaths = @{}
    foreach ($entry in $currentEntries) {
        $currentPaths[$entry.path] = $entry
    }

    # Find anomalies
    $anomalies = @()
    $newCount = 0
    $modifiedCount = 0
    $missingCount = 0

    Write-Header "Checking for New/Modified Entries"

    foreach ($entry in $currentEntries) {
        $path = $entry.path

        if (-not $baselineEntries.ContainsKey($path)) {
            # New entry
            $newCount++
            $indicators = Get-RiskIndicators -Path $path -Content $entry.command_preview -Value $entry.value -ModTime $null
            $riskScore = Get-RiskScore -Indicators $indicators

            Write-New $path
            Write-Host "    Category:    $($entry.category)" -ForegroundColor Cyan
            Write-Host "    MITRE:       $($entry.mitre_technique)" -ForegroundColor Cyan
            Write-Host "    Risk:        $riskScore" -ForegroundColor $(switch($riskScore) { "CRITICAL" { "Red" } "HIGH" { "Red" } "MEDIUM" { "Yellow" } default { "Cyan" } })
            if ($entry.command_preview) {
                Write-Host "    Preview:     $($entry.command_preview)" -ForegroundColor Gray
            }
            foreach ($ind in $indicators) {
                Write-Suspicious $ind
            }
            Write-Host ""

            $anomaly = @{
                category = "new"
                entry_type = $entry.category
                path = $path
                mitre_technique = $entry.mitre_technique
                content_hash = $entry.content_hash
                command_preview = $entry.command_preview
                risk_score = $riskScore
                risk_indicators = $indicators
            }
            $anomalies += $anomaly
        }
        elseif ($entry.content_hash -ne $baselineEntries[$path].content_hash) {
            # Modified entry
            $modifiedCount++
            $indicators = Get-RiskIndicators -Path $path -Content $entry.command_preview -Value $entry.value -ModTime $null
            $indicators += "Content hash changed"
            $riskScore = Get-RiskScore -Indicators $indicators

            Write-Modified $path
            Write-Host "    Category:    $($entry.category)" -ForegroundColor Cyan
            Write-Host "    MITRE:       $($entry.mitre_technique)" -ForegroundColor Cyan
            Write-Host "    Risk:        $riskScore" -ForegroundColor $(switch($riskScore) { "CRITICAL" { "Red" } "HIGH" { "Red" } "MEDIUM" { "Yellow" } default { "Cyan" } })
            Write-Host "    Old Hash:    $($baselineEntries[$path].content_hash)" -ForegroundColor Gray
            Write-Host "    New Hash:    $($entry.content_hash)" -ForegroundColor Gray
            foreach ($ind in $indicators) {
                Write-Suspicious $ind
            }
            Write-Host ""

            $anomaly = @{
                category = "modified"
                entry_type = $entry.category
                path = $path
                mitre_technique = $entry.mitre_technique
                baseline_hash = $baselineEntries[$path].content_hash
                current_hash = $entry.content_hash
                command_preview = $entry.command_preview
                risk_score = $riskScore
                risk_indicators = $indicators
            }
            $anomalies += $anomaly
        }
    }

    Write-Header "Checking for Missing Entries"

    foreach ($path in $baselineEntries.Keys) {
        if (-not $currentPaths.ContainsKey($path)) {
            $missingCount++
            $baseEntry = $baselineEntries[$path]

            Write-Missing $path
            Write-Host "    Category:    $($baseEntry.category)" -ForegroundColor Cyan
            Write-Host "    MITRE:       $($baseEntry.mitre_technique)" -ForegroundColor Cyan
            Write-Host ""

            $anomaly = @{
                category = "missing"
                entry_type = $baseEntry.category
                path = $path
                mitre_technique = $baseEntry.mitre_technique
                baseline_hash = $baseEntry.content_hash
                risk_score = "LOW"
                risk_indicators = @("Entry removed since baseline")
            }
            $anomalies += $anomaly
        }
    }

    # Summary
    Write-Header "Scan Summary"

    if ($newCount -gt 0) {
        Write-Host "[!] New entries:      $newCount" -ForegroundColor Red
    } else {
        Write-Host "[+] New entries:      $newCount" -ForegroundColor Green
    }

    if ($missingCount -gt 0) {
        Write-Host "[!] Missing entries:  $missingCount" -ForegroundColor Yellow
    } else {
        Write-Host "[+] Missing entries:  $missingCount" -ForegroundColor Green
    }

    if ($modifiedCount -gt 0) {
        Write-Host "[!] Modified entries: $modifiedCount" -ForegroundColor Magenta
    } else {
        Write-Host "[+] Modified entries: $modifiedCount" -ForegroundColor Green
    }

    $totalAnomalies = $newCount + $missingCount + $modifiedCount
    Write-Host ""
    if ($totalAnomalies -gt 0) {
        Write-Warning2 "Total anomalies: $totalAnomalies"
    } else {
        Write-Success "No anomalies detected"
    }

    # Save results
    if ($OutputFile) {
        $results = @{
            scan_type = "persistence_anomaly"
            timestamp = (Get-Date).ToString("o")
            hostname = $env:COMPUTERNAME
            platform = "Windows"
            baseline_file = $BaselineFile
            scan_level = $ScanLevel
            summary = @{
                new_count = $newCount
                modified_count = $modifiedCount
                missing_count = $missingCount
                total_anomalies = $totalAnomalies
            }
            anomalies = $anomalies
        }

        $json = $results | ConvertTo-Json -Depth 10
        $json | Out-File -FilePath $OutputFile -Encoding UTF8

        Write-Host ""
        Write-Success "Scan results saved to: $OutputFile"
    }
}

# Show command
function Show-Results {
    param(
        [string]$FilePath,
        [bool]$ShowAll = $false,
        [int]$ShowLimit = 5
    )

    if (-not (Test-Path $FilePath)) {
        Write-Error2 "File not found: $FilePath"
        exit 1
    }

    $data = Get-Content -Path $FilePath -Raw | ConvertFrom-Json

    if ($data.scan_type -eq "persistence_anomaly") {
        # Scan results
        Write-Header "Persistence Anomaly Scan Results"
        Write-Host "Timestamp:     $($data.timestamp)"
        Write-Host "Hostname:      $($data.hostname)"
        Write-Host "Baseline:      $($data.baseline_file)"
        Write-Host "Scan Level:    $($data.scan_level)"
        Write-Host ""
        Write-Host "Summary:" -ForegroundColor Cyan
        Write-Host "  New:       $($data.summary.new_count)"
        Write-Host "  Modified:  $($data.summary.modified_count)"
        Write-Host "  Missing:   $($data.summary.missing_count)"
        Write-Host "  Total:     $($data.summary.total_anomalies)"
        Write-Host "Output Mode: " -NoNewline
        if ($ShowAll) {
            Write-Host "Showing all anomalies" -ForegroundColor White
        } else {
            Write-Host "Showing up to $ShowLimit anomalies (use -All for full output)" -ForegroundColor Yellow
        }
        Write-Host ""

        if ($data.anomalies.Count -gt 0) {
            Write-Header "Anomalies"

            $totalAnomalies = $data.anomalies.Count
            $displayAnomalies = if ($ShowAll) { $data.anomalies } else { $data.anomalies | Select-Object -First $ShowLimit }
            $skipped = $totalAnomalies - @($displayAnomalies).Count

            foreach ($anomaly in $displayAnomalies) {
                $color = switch($anomaly.category) {
                    "new" { "Red" }
                    "modified" { "Magenta" }
                    "missing" { "Yellow" }
                    default { "White" }
                }

                Write-Host "[$($anomaly.category.ToUpper())] $($anomaly.path)" -ForegroundColor $color
                Write-Host "    Type:    $($anomaly.entry_type)" -ForegroundColor Cyan
                Write-Host "    MITRE:   $($anomaly.mitre_technique)" -ForegroundColor Cyan
                Write-Host "    Risk:    $($anomaly.risk_score)" -ForegroundColor $(switch($anomaly.risk_score) { "CRITICAL" { "Red" } "HIGH" { "Red" } "MEDIUM" { "Yellow" } default { "Cyan" } })
                if ($anomaly.command_preview) {
                    Write-Host "    Preview: $($anomaly.command_preview)" -ForegroundColor Gray
                }
                if ($anomaly.risk_indicators) {
                    foreach ($ind in $anomaly.risk_indicators) {
                        Write-Suspicious $ind
                    }
                }
                Write-Host ""
            }

            # Show skipped count
            if ($skipped -gt 0) {
                Write-Host "  ... and $skipped more anomalies (use -All to see all)" -ForegroundColor Yellow
            }
        }
    }
    else {
        # Baseline - show detailed information
        Write-Header "Persistence Baseline"
        Write-Host "Timestamp:     $($data.timestamp)"
        Write-Host "Hostname:      $($data.hostname)"
        Write-Host "Scan Level:    $($data.scan_level)"
        Write-Host "Categories:    $($data.categories_scanned -join ', ')"
        Write-Host "Total Entries: $($data.entries.Count)"
        Write-Host "Output Mode:   " -NoNewline
        if ($ShowAll) {
            Write-Host "Showing all entries" -ForegroundColor White
        } else {
            Write-Host "Showing up to $ShowLimit entries per category (use -All for full output)" -ForegroundColor Yellow
        }
        Write-Host ""

        # MITRE mappings
        $mitreMap = @{
            "run-keys" = "T1547.001"; "scheduled-tasks" = "T1053.005"; "services" = "T1543.003"
            "startup-folder" = "T1547.001"; "winlogon" = "T1547.004"; "appinit-dlls" = "T1546.010"
            "image-hijacks" = "T1546.012"; "browser-helpers" = "T1176"; "com-hijacks" = "T1546.015"
            "wmi-subscriptions" = "T1546.003"; "boot-execute" = "T1547.012"; "lsa-packages" = "T1547.002"
            "print-monitors" = "T1547.010"; "netsh-helpers" = "T1546.007"; "office-addins" = "T1137"
            "bits-jobs" = "T1197"
        }

        # Group by category
        $grouped = $data.entries | Group-Object -Property category

        foreach ($group in $grouped) {
            $catName = $group.Name
            $mitre = if ($mitreMap.ContainsKey($catName)) { $mitreMap[$catName] } else { "Unknown" }
            $totalInCat = $group.Count
            Write-Header "$catName ($totalInCat entries) - $mitre"

            # Apply limit unless ShowAll
            $displayEntries = if ($ShowAll) { $group.Group } else { $group.Group | Select-Object -First $ShowLimit }
            $skipped = $totalInCat - @($displayEntries).Count

            $count = 0
            foreach ($entry in $displayEntries) {
                $count++

                $name = if ($entry.name) { $entry.name } else { Split-Path $entry.path -Leaf }
                Write-Host "[$count] $name" -ForegroundColor White

                Write-Host "    Path:     $($entry.path)" -ForegroundColor Cyan

                # Category-specific details
                switch ($catName) {
                    "run-keys" {
                        if ($entry.value) { Write-Host "    Value:    $($entry.value)" -ForegroundColor Yellow }
                    }
                    "scheduled-tasks" {
                        if ($entry.state) { Write-Host "    State:    $($entry.state)" -ForegroundColor Cyan }
                        if ($entry.author) { Write-Host "    Author:   $($entry.author)" -ForegroundColor Cyan }
                        if ($entry.actions) { Write-Host "    Actions:  $($entry.actions)" -ForegroundColor Yellow }
                        if ($entry.last_run) { Write-Host "    Last Run: $($entry.last_run)" -ForegroundColor Cyan }
                    }
                    "services" {
                        if ($entry.display_name) { Write-Host "    Display:  $($entry.display_name)" -ForegroundColor Cyan }
                        if ($entry.state) { Write-Host "    State:    $($entry.state)" -ForegroundColor Cyan }
                        if ($entry.start_mode) { Write-Host "    Start:    $($entry.start_mode)" -ForegroundColor Cyan }
                        if ($entry.path_name) { Write-Host "    Binary:   $($entry.path_name)" -ForegroundColor Yellow }
                        if ($entry.account) { Write-Host "    Account:  $($entry.account)" -ForegroundColor Cyan }
                    }
                    "startup-folder" {
                        if ($entry.size) { Write-Host "    Size:     $($entry.size) bytes" -ForegroundColor Cyan }
                        if ($entry.mtime) { Write-Host "    Modified: $($entry.mtime)" -ForegroundColor Cyan }
                    }
                    "winlogon" {
                        if ($entry.value) { Write-Host "    Value:    $($entry.value)" -ForegroundColor Yellow }
                    }
                    "appinit-dlls" {
                        if ($entry.value) { Write-Host "    DLLs:     $($entry.value)" -ForegroundColor Yellow }
                        if ($entry.load_enabled) { Write-Host "    Enabled:  $($entry.load_enabled)" -ForegroundColor Cyan }
                    }
                    "image-hijacks" {
                        if ($entry.debugger) { Write-Host "    Debugger: $($entry.debugger)" -ForegroundColor Red }
                    }
                    "browser-helpers" {
                        if ($entry.dll_path) { Write-Host "    DLL:      $($entry.dll_path)" -ForegroundColor Yellow }
                    }
                    "com-hijacks" {
                        if ($entry.dll_path) { Write-Host "    DLL:      $($entry.dll_path)" -ForegroundColor Yellow }
                    }
                    "wmi-subscriptions" {
                        if ($entry.type) { Write-Host "    Type:     $($entry.type)" -ForegroundColor Cyan }
                        if ($entry.query) { Write-Host "    Query:    $($entry.query)" -ForegroundColor Yellow }
                        if ($entry.command) { Write-Host "    Command:  $($entry.command)" -ForegroundColor Yellow }
                    }
                    "boot-execute" {
                        if ($entry.values) { Write-Host "    Values:   $($entry.values -join '; ')" -ForegroundColor Yellow }
                    }
                    "lsa-packages" {
                        if ($entry.packages) { Write-Host "    Packages: $($entry.packages -join ', ')" -ForegroundColor Yellow }
                    }
                    "print-monitors" {
                        if ($entry.driver) { Write-Host "    Driver:   $($entry.driver)" -ForegroundColor Yellow }
                    }
                    "netsh-helpers" {
                        if ($entry.dll) { Write-Host "    DLL:      $($entry.dll)" -ForegroundColor Yellow }
                    }
                    "office-addins" {
                        if ($entry.application) { Write-Host "    App:      $($entry.application)" -ForegroundColor Cyan }
                        if ($entry.version) { Write-Host "    Version:  $($entry.version)" -ForegroundColor Cyan }
                    }
                    "bits-jobs" {
                        if ($entry.job_state) { Write-Host "    State:    $($entry.job_state)" -ForegroundColor Cyan }
                        if ($entry.owner) { Write-Host "    Owner:    $($entry.owner)" -ForegroundColor Cyan }
                        if ($entry.files) { Write-Host "    Files:    $($entry.files)" -ForegroundColor Yellow }
                    }
                    default {
                        if ($entry.command_preview) {
                            Write-Host "    Preview:  $($entry.command_preview.Substring(0, [Math]::Min(80, $entry.command_preview.Length)))" -ForegroundColor Gray
                        }
                    }
                }

                if ($entry.content_hash) {
                    Write-Host "    Hash:     $($entry.content_hash.Substring(0, 16))..." -ForegroundColor DarkGray
                }
                Write-Host ""
            }

            # Show skipped count
            if ($skipped -gt 0) {
                Write-Host "  ... and $skipped more entries in this category (use -All to see all)" -ForegroundColor Yellow
                Write-Host ""
            }
        }
    }
}

# Help function
function Show-Help {
    Write-Host @"

Persistence Anomaly Detection - Windows

USAGE:
    .\persistence_anomaly.ps1 <command> [options]

COMMANDS:
    baseline    Create baseline of persistence mechanisms
    scan        Scan and compare against baseline
    show        Display baseline/scan results

OPTIONS:
    -OutputFile FILE      Output file for baseline/scan results
    -BaselineFile FILE    Baseline file for comparison (scan command)
    -File FILE            File to display (show command)
    -All                  Show all entries (no limit, for show command)
    -Limit NUM            Limit entries per group (default: 5, for show command)
    -Level 1|2|3          Scan level (default: 2)
                            1 = Essential (fast, low noise)
                            2 = Comprehensive (balanced)
                            3 = Exhaustive (full coverage)
    -Category LIST        Specific categories (comma-separated)

CATEGORIES:
    Level 1: run-keys, scheduled-tasks, services, startup-folder
    Level 2: winlogon, appinit-dlls, image-hijacks, browser-helpers, com-hijacks
    Level 3: wmi-subscriptions, boot-execute, lsa-packages, print-monitors,
             netsh-helpers, office-addins, bits-jobs

EXAMPLES:
    # Create level 2 baseline
    .\persistence_anomaly.ps1 baseline -Level 2 -OutputFile baseline.json

    # Scan against baseline
    .\persistence_anomaly.ps1 scan -BaselineFile baseline.json -OutputFile results.json

    # Scan specific categories
    .\persistence_anomaly.ps1 scan -BaselineFile baseline.json -Category run-keys,services

    # View results
    .\persistence_anomaly.ps1 show -File results.json

"@
}

# Main execution
switch ($Mode) {
    "baseline" {
        if (-not $OutputFile) {
            $OutputFile = "persistence_baseline_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        }
        Create-Baseline -OutputFile $OutputFile -ScanLevel $Level -CategoryFilter $Category
    }
    "scan" {
        if (-not $BaselineFile) {
            Write-Error2 "Baseline file required for scan mode. Use -BaselineFile"
            exit 1
        }
        Scan-Persistence -BaselineFile $BaselineFile -OutputFile $OutputFile -ScanLevel $Level -CategoryFilter $Category
    }
    "show" {
        if (-not $File) {
            Write-Error2 "File required for show mode. Use -File"
            exit 1
        }
        Show-Results -FilePath $File -ShowAll $All.IsPresent -ShowLimit $Limit
    }
}

<#
.SYNOPSIS
    File Anomaly Detection - Pure PowerShell Implementation
    No external dependencies - uses native cmdlets only

.DESCRIPTION
    Monitors suspicious directories for unauthorized files:
    - Temp directories (world-writable)
    - Startup folders (persistence)
    - Public folders (world-writable)
    - Task scheduler locations

.PARAMETER Mode
    baseline - Create a baseline of files in suspicious directories
    scan - Scan for anomalies against baseline

.PARAMETER OutputFile
    Output file for baseline (default: file_baseline.json)

.PARAMETER BaselineFile
    Baseline file for scan mode

.EXAMPLE
    .\file_anomaly.ps1 baseline -OutputFile file_baseline.json
    .\file_anomaly.ps1 scan -BaselineFile file_baseline.json
#>

param(
    [Parameter(Position=0, Mandatory=$true)]
    [ValidateSet("baseline", "scan", "show")]
    [string]$Mode,

    [Parameter()]
    [string]$OutputFile = "file_baseline.json",

    [Parameter()]
    [string]$BaselineFile,

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

# Suspicious directories to monitor
$SuspiciousPaths = @(
    "$env:TEMP",
    "$env:SystemRoot\Temp",
    "$env:PUBLIC",
    "$env:ALLUSERSPROFILE",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:SystemRoot\Tasks",
    "$env:SystemRoot\System32\Tasks",
    "C:\Users\Public\Downloads",
    "C:\Users\Public\Documents"
)

# Add user profile directories
$userProfiles = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notin @("Public", "Default", "Default User", "All Users") }

foreach ($profile in $userProfiles) {
    $SuspiciousPaths += "$($profile.FullName)\AppData\Local\Temp"
    $SuspiciousPaths += "$($profile.FullName)\Downloads"
    $SuspiciousPaths += "$($profile.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
}

# Suspicious file extensions
$SuspiciousExtensions = @(
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".psm1", ".psd1",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".msi", ".msp",
    ".com", ".pif", ".application", ".gadget", ".hta", ".cpl",
    ".msc", ".jar", ".reg", ".lnk"
)

# Compute SHA256 hash
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

# Check if extension is suspicious
function Test-SuspiciousExtension {
    param([string]$FileName)

    $ext = [System.IO.Path]::GetExtension($FileName).ToLower()
    return $ext -in $SuspiciousExtensions
}

# Get file information
function Get-FileDetails {
    param([System.IO.FileInfo]$File)

    $info = @{
        path = $File.FullName
        name = $File.Name
        size = $File.Length
        extension = $File.Extension.ToLower()
        created = $File.CreationTime.ToString("o")
        modified = $File.LastWriteTime.ToString("o")
        accessed = $File.LastAccessTime.ToString("o")
        attributes = $File.Attributes.ToString()
        hidden = $File.Attributes.HasFlag([System.IO.FileAttributes]::Hidden)
        hash = $null
    }

    # Compute hash for executables
    if (Test-SuspiciousExtension -FileName $File.Name) {
        $info.hash = Get-SafeFileHash -FilePath $File.FullName
    }

    return $info
}

# Scan directory for files
function Get-DirectoryFiles {
    param(
        [string]$Path,
        [int]$MaxDepth = 3
    )

    if (-not (Test-Path -Path $Path -PathType Container)) {
        return @()
    }

    $files = @()

    try {
        $items = Get-ChildItem -Path $Path -File -Recurse -Depth $MaxDepth -ErrorAction SilentlyContinue

        foreach ($item in $items) {
            $files += $item
        }
    }
    catch {
        # Access denied or other error
    }

    return $files
}

# Create baseline
function New-FileBaseline {
    param([string]$OutputPath)

    Write-Header "Creating File Baseline"

    $hostname = $env:COMPUTERNAME
    $timestamp = Get-Date -Format "o"

    Write-Info "Hostname: $hostname"
    Write-Info "Timestamp: $timestamp"

    $allFiles = @()
    $count = 0

    # Filter to only existing paths
    $validPaths = $SuspiciousPaths | Where-Object { Test-Path -Path $_ -PathType Container }

    Write-Info "Monitoring $($validPaths.Count) directories"

    foreach ($dir in $validPaths) {
        Write-Info "Scanning: $dir"

        $files = Get-DirectoryFiles -Path $dir -MaxDepth 3

        foreach ($file in $files) {
            $count++

            if ($count % 100 -eq 0) {
                Write-Host "`r[*] Processed $count files..." -NoNewline -ForegroundColor Blue
            }

            $details = Get-FileDetails -File $file
            $allFiles += $details
        }
    }

    Write-Host ""

    $baseline = @{
        timestamp = $timestamp
        hostname = $hostname
        platform = "Windows"
        monitored_paths = $validPaths
        files = $allFiles
    }

    # Convert to JSON and save
    $json = $baseline | ConvertTo-Json -Depth 10
    $json | Out-File -FilePath $OutputPath -Encoding UTF8

    Write-Success "Baseline created: $OutputPath"
    Write-Info "Total files: $($allFiles.Count)"
}

# Run anomaly scan
function Invoke-FileScan {
    param([string]$BaselinePath)

    Write-Header "File Anomaly Scan"

    if (-not (Test-Path -Path $BaselinePath)) {
        Write-Error2 "Baseline file not found: $BaselinePath"
        exit 1
    }

    Write-Info "Loading baseline: $BaselinePath"

    $baseline = Get-Content -Path $BaselinePath -Raw | ConvertFrom-Json

    # Build lookup tables
    $baselineFiles = @{}
    $baselineHashes = @{}

    foreach ($file in $baseline.files) {
        $baselineFiles[$file.path] = $file
        if ($file.hash) {
            $baselineHashes[$file.path] = $file.hash
        }
    }

    Write-Info "Baseline files: $($baseline.files.Count)"

    $currentFiles = @{}
    $newCount = 0
    $missingCount = 0
    $modifiedCount = 0

    Write-Header "Scanning for New/Modified Files"

    # Filter to only existing paths
    $validPaths = $SuspiciousPaths | Where-Object { Test-Path -Path $_ -PathType Container }

    foreach ($dir in $validPaths) {
        $files = Get-DirectoryFiles -Path $dir -MaxDepth 3

        foreach ($file in $files) {
            $path = $file.FullName
            $currentFiles[$path] = $true

            if (-not $baselineFiles.ContainsKey($path)) {
                # New file
                $newCount++

                Write-Host ""
                Write-New $path
                Write-Host "    Size:        $($file.Length) bytes" -ForegroundColor Cyan
                Write-Host "    Created:     $($file.CreationTime)" -ForegroundColor Cyan
                Write-Host "    Modified:    $($file.LastWriteTime)" -ForegroundColor Cyan
                Write-Host "    Attributes:  $($file.Attributes)" -ForegroundColor Cyan

                # Suspicious indicators
                if ($file.Attributes.HasFlag([System.IO.FileAttributes]::Hidden)) {
                    Write-Host "    [!] SUSPICIOUS: Hidden file" -ForegroundColor Red
                }

                if (Test-SuspiciousExtension -FileName $file.Name) {
                    Write-Host "    [!] SUSPICIOUS: Executable extension" -ForegroundColor Red
                }

                if ($path -match "\\Startup\\") {
                    Write-Host "    [!] SUSPICIOUS: Startup persistence location" -ForegroundColor Red
                }

                if ($path -match "\\Tasks\\") {
                    Write-Host "    [!] SUSPICIOUS: Scheduled task location" -ForegroundColor Red
                }

                # Check for double extensions
                if ($file.Name -match "\.(doc|pdf|txt|jpg|png)\.(exe|scr|bat|cmd|ps1|vbs)$") {
                    Write-Host "    [!] SUSPICIOUS: Double extension (masquerading)" -ForegroundColor Red
                }

                # Very long filename
                if ($file.Name.Length -gt 100) {
                    Write-Host "    [!] SUSPICIOUS: Unusually long filename" -ForegroundColor Red
                }
            }
            else {
                # Check for modification
                if ($baselineHashes.ContainsKey($path)) {
                    $currentHash = Get-SafeFileHash -FilePath $path
                    $baselineHash = $baselineHashes[$path]

                    if ($currentHash -and $baselineHash -and $currentHash -ne $baselineHash) {
                        $modifiedCount++

                        Write-Host ""
                        Write-Modified $path
                        Write-Host "    Baseline Hash: $baselineHash" -ForegroundColor Cyan
                        Write-Host "    Current Hash:  $currentHash" -ForegroundColor Red
                    }
                }
            }
        }
    }

    # Check for missing files
    Write-Header "Checking for Missing Files"

    foreach ($path in $baselineFiles.Keys) {
        if (-not $currentFiles.ContainsKey($path)) {
            $missingCount++
            Write-Missing $path
        }
    }

    # Summary
    Write-Header "Scan Summary"

    if ($newCount -gt 0) {
        Write-Host "[!] New files:      $newCount" -ForegroundColor Red
    } else {
        Write-Host "[+] New files:      $newCount" -ForegroundColor Green
    }

    if ($missingCount -gt 0) {
        Write-Host "[!] Missing files:  $missingCount" -ForegroundColor Yellow
    } else {
        Write-Host "[+] Missing files:  $missingCount" -ForegroundColor Green
    }

    if ($modifiedCount -gt 0) {
        Write-Host "[!] Modified files: $modifiedCount" -ForegroundColor Magenta
    } else {
        Write-Host "[+] Modified files: $modifiedCount" -ForegroundColor Green
    }

    $totalAnomalies = $newCount + $missingCount + $modifiedCount
    Write-Host ""

    if ($totalAnomalies -gt 0) {
        Write-Warning2 "Total anomalies: $totalAnomalies"
    } else {
        Write-Success "No anomalies detected"
    }
}

# Show baseline results with detailed information
function Show-BaselineResults {
    param(
        [string]$BaselinePath,
        [bool]$ShowAll = $false,
        [int]$ShowLimit = 5
    )

    Write-Header "File Baseline Summary"

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
    Write-Host "Total Files:    " -ForegroundColor Cyan -NoNewline
    Write-Host "$($baseline.files.Count)" -ForegroundColor Green
    Write-Host "Output Mode:    " -ForegroundColor Cyan -NoNewline
    if ($ShowAll) {
        Write-Host "Showing all entries" -ForegroundColor White
    } else {
        Write-Host "Showing up to $ShowLimit entries per group (use -All for full output)" -ForegroundColor Yellow
    }
    Write-Host ""

    # Monitored paths
    Write-Header "Monitored Directories"
    foreach ($path in $baseline.monitored_paths) {
        Write-Host "  $path" -ForegroundColor DarkGray
    }
    Write-Host ""

    # Group by extension
    $byExtension = $baseline.files | Group-Object extension

    Write-Header "Files by Extension"
    foreach ($group in ($byExtension | Sort-Object Count -Descending)) {
        $ext = if ([string]::IsNullOrEmpty($group.Name)) { "(no extension)" } else { $group.Name }
        $color = if ($ext -in $SuspiciousExtensions) { "Red" } else { "White" }
        Write-Host "  $ext" -ForegroundColor $color -NoNewline
        Write-Host " - $($group.Count) files" -ForegroundColor DarkGray
    }
    Write-Host ""

    # Suspicious extensions detail
    Write-Header "Suspicious Executable Files"
    $execCount = 0
    foreach ($file in $baseline.files) {
        if ($file.extension -in $SuspiciousExtensions) {
            $execCount++
            Write-Host ""
            Write-Host "  Name:       " -ForegroundColor Cyan -NoNewline
            Write-Host "$($file.name)" -ForegroundColor Yellow
            Write-Host "  Path:       " -ForegroundColor Cyan -NoNewline
            Write-Host "$($file.path)" -ForegroundColor White
            Write-Host "  Size:       " -ForegroundColor Cyan -NoNewline
            $sizeKB = [math]::Round($file.size / 1KB, 2)
            Write-Host "$sizeKB KB ($($file.size) bytes)" -ForegroundColor White
            Write-Host "  Created:    " -ForegroundColor Cyan -NoNewline
            Write-Host "$($file.created)" -ForegroundColor White
            Write-Host "  Modified:   " -ForegroundColor Cyan -NoNewline
            Write-Host "$($file.modified)" -ForegroundColor White
            Write-Host "  Attributes: " -ForegroundColor Cyan -NoNewline
            Write-Host "$($file.attributes)" -ForegroundColor White
            if ($file.hidden) {
                Write-Host "  [HIDDEN FILE]" -ForegroundColor Red
            }
            if ($file.hash) {
                Write-Host "  SHA256:     " -ForegroundColor Cyan -NoNewline
                Write-Host "$($file.hash)" -ForegroundColor DarkGray
            }
        }
    }
    if ($execCount -eq 0) {
        Write-Host "  (none found)" -ForegroundColor Green
    }
    Write-Host ""

    # Hidden files
    Write-Header "Hidden Files"
    $hiddenCount = 0
    foreach ($file in $baseline.files) {
        if ($file.hidden) {
            $hiddenCount++
            Write-Host "  $($file.path)" -ForegroundColor Yellow
        }
    }
    if ($hiddenCount -eq 0) {
        Write-Host "  (none found)" -ForegroundColor Green
    }
    Write-Host ""

    # Group by directory
    $byDirectory = @{}
    foreach ($file in $baseline.files) {
        $dir = try { [System.IO.Path]::GetDirectoryName($file.path) } catch { "Unknown" }
        if (-not $byDirectory.ContainsKey($dir)) {
            $byDirectory[$dir] = @()
        }
        $byDirectory[$dir] += $file
    }

    Write-Header "All Files by Directory"
    foreach ($dir in ($byDirectory.Keys | Sort-Object)) {
        $files = $byDirectory[$dir]
        $totalInDir = $files.Count
        Write-Host ""
        Write-Host "[$dir]" -ForegroundColor Yellow
        Write-Host "  ($totalInDir files)" -ForegroundColor DarkGray

        # Apply limit unless ShowAll
        $displayFiles = if ($ShowAll) { $files | Sort-Object name } else { ($files | Sort-Object name) | Select-Object -First $ShowLimit }
        $skipped = $totalInDir - @($displayFiles).Count

        foreach ($file in $displayFiles) {
            Write-Host ""
            Write-Host "    Name:       " -ForegroundColor Cyan -NoNewline
            Write-Host "$($file.name)" -ForegroundColor White
            Write-Host "    Path:       " -ForegroundColor Cyan -NoNewline
            Write-Host "$($file.path)" -ForegroundColor White
            Write-Host "    Size:       " -ForegroundColor Cyan -NoNewline
            $sizeKB = [math]::Round($file.size / 1KB, 2)
            Write-Host "$sizeKB KB ($($file.size) bytes)" -ForegroundColor White
            Write-Host "    Extension:  " -ForegroundColor Cyan -NoNewline
            $extColor = if ($file.extension -in $SuspiciousExtensions) { "Red" } else { "White" }
            Write-Host "$($file.extension)" -ForegroundColor $extColor
            Write-Host "    Created:    " -ForegroundColor Cyan -NoNewline
            Write-Host "$($file.created)" -ForegroundColor White
            Write-Host "    Modified:   " -ForegroundColor Cyan -NoNewline
            Write-Host "$($file.modified)" -ForegroundColor White
            Write-Host "    Attributes: " -ForegroundColor Cyan -NoNewline
            Write-Host "$($file.attributes)" -ForegroundColor White
            if ($file.hash) {
                Write-Host "    SHA256:     " -ForegroundColor Cyan -NoNewline
                Write-Host "$($file.hash)" -ForegroundColor DarkGray
            }
        }

        # Show skipped count
        if ($skipped -gt 0) {
            Write-Host ""
            Write-Host "    ... and $skipped more files in this directory (use -All to see all)" -ForegroundColor Yellow
        }
    }

    # Summary statistics
    Write-Header "Summary Statistics"
    Write-Host "Total Files:               " -ForegroundColor Cyan -NoNewline
    Write-Host "$($baseline.files.Count)" -ForegroundColor Green
    Write-Host "Monitored Directories:     " -ForegroundColor Cyan -NoNewline
    Write-Host "$($baseline.monitored_paths.Count)" -ForegroundColor White
    Write-Host "Unique Extensions:         " -ForegroundColor Cyan -NoNewline
    Write-Host "$($byExtension.Count)" -ForegroundColor White
    Write-Host "Executable Files:          " -ForegroundColor Cyan -NoNewline
    Write-Host "$execCount" -ForegroundColor $(if ($execCount -gt 0) { "Yellow" } else { "Green" })
    Write-Host "Hidden Files:              " -ForegroundColor Cyan -NoNewline
    Write-Host "$hiddenCount" -ForegroundColor $(if ($hiddenCount -gt 0) { "Yellow" } else { "Green" })

    # Files with hashes
    $withHash = ($baseline.files | Where-Object { $_.hash }).Count
    Write-Host "Files with Hash:           " -ForegroundColor Cyan -NoNewline
    Write-Host "$withHash" -ForegroundColor White

    # Total size
    $totalSize = ($baseline.files | Measure-Object -Property size -Sum).Sum
    $totalMB = [math]::Round($totalSize / 1MB, 2)
    Write-Host "Total Size:                " -ForegroundColor Cyan -NoNewline
    Write-Host "$totalMB MB" -ForegroundColor White
}

# Main
switch ($Mode) {
    "baseline" {
        New-FileBaseline -OutputPath $OutputFile
    }
    "scan" {
        if ([string]::IsNullOrEmpty($BaselineFile)) {
            Write-Error2 "Baseline file required for scan mode (-BaselineFile)"
            exit 1
        }
        Invoke-FileScan -BaselinePath $BaselineFile
    }
    "show" {
        if ([string]::IsNullOrEmpty($BaselineFile)) {
            Write-Error2 "Baseline file required for show mode (-BaselineFile)"
            exit 1
        }
        Show-BaselineResults -BaselinePath $BaselineFile -ShowAll $All.IsPresent -ShowLimit $Limit
    }
}

<#
.SYNOPSIS
    Test Runner for Native PowerShell IR Scripts
    Pure PowerShell testing - no external dependencies

.DESCRIPTION
    Comprehensive tests for process_anomaly.ps1, file_anomaly.ps1, and process_hunter.ps1
    Tests can run on both Windows and Linux (via PowerShell Core)
#>

param(
    [switch]$Verbose
)

$ErrorActionPreference = "Continue"

# Paths
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent (Split-Path -Parent $ScriptDir)
$WindowsScripts = Join-Path $ProjectDir "windows"
$FixturesDir = Join-Path (Split-Path -Parent $ScriptDir) "fixtures"

# Test counters
$script:TestsRun = 0
$script:TestsPassed = 0
$script:TestsFailed = 0
$script:CurrentSuite = ""

# Temp directory
$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "ir_script_tests_$(Get-Random)"
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

# Output functions
function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host ""
}

function Write-Suite {
    param([string]$Name)
    $script:CurrentSuite = $Name
    Write-Host ""
    Write-Host "* Test Suite: $Name" -ForegroundColor Blue
    Write-Host ("-" * 45) -ForegroundColor Blue
}

function Write-Test {
    param([string]$Name)
    Write-Host "  o $Name... " -NoNewline -ForegroundColor Yellow
}

function Pass {
    $script:TestsPassed++
    $script:TestsRun++
    Write-Host "PASS" -ForegroundColor Green
}

function Fail {
    param([string]$Message = "")
    $script:TestsFailed++
    $script:TestsRun++
    Write-Host "FAIL" -ForegroundColor Red
    if ($Message) {
        Write-Host "    -> $Message" -ForegroundColor Red
    }
}

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Message = ""
    )
    if ($Condition) {
        return $true
    }
    return $false
}

function Assert-Contains {
    param(
        [string]$Haystack,
        [string]$Needle
    )
    return $Haystack -match [regex]::Escape($Needle)
}

function Assert-FileExists {
    param([string]$Path)
    return Test-Path -Path $Path -PathType Leaf
}

function Assert-ValidJson {
    param([string]$Path)
    try {
        $content = Get-Content -Path $Path -Raw
        $null = $content | ConvertFrom-Json
        return $true
    }
    catch {
        return $false
    }
}

#
# ═══════════════════════════════════════════════════════════════
# PROCESS ANOMALY TESTS
# ═══════════════════════════════════════════════════════════════
#

function Test-ProcessAnomaly-ScriptExists {
    Write-Test "process_anomaly.ps1 exists"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    if (Assert-FileExists $scriptPath) {
        Pass
    } else {
        Fail "Script not found at $scriptPath"
    }
}

function Test-ProcessAnomaly-HasRequiredParams {
    Write-Test "Has Mode parameter"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match '\$Mode') {
        Pass
    } else {
        Fail "Mode parameter not found"
    }
}

function Test-ProcessAnomaly-SupportsBaseline {
    Write-Test "Supports baseline mode"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match 'ValidateSet.*baseline') {
        Pass
    } else {
        Fail "baseline mode not supported"
    }
}

function Test-ProcessAnomaly-SupportsScan {
    Write-Test "Supports scan mode"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match 'ValidateSet.*scan') {
        Pass
    } else {
        Fail "scan mode not supported"
    }
}

function Test-ProcessAnomaly-HasOutputFunctions {
    Write-Test "Has colored output functions"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match 'function Write-Header' -and $content -match 'ForegroundColor') {
        Pass
    } else {
        Fail "Missing output functions"
    }
}

function Test-ProcessAnomaly-HasHashFunction {
    Write-Test "Has hash computation function"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match 'Get-FileHash' -or $content -match 'Get-SafeFileHash') {
        Pass
    } else {
        Fail "Missing hash function"
    }
}

function Test-ProcessAnomaly-UsesGetProcess {
    Write-Test "Uses Get-Process cmdlet"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match 'Get-Process') {
        Pass
    } else {
        Fail "Not using Get-Process"
    }
}

function Test-ProcessAnomaly-UsesWmi {
    Write-Test "Uses WMI/CIM for process details"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match 'Get-CimInstance' -or $content -match 'Win32_Process') {
        Pass
    } else {
        Fail "Not using WMI/CIM"
    }
}

function Test-ProcessAnomaly-DetectsTempExecutables {
    Write-Test "Detects executables in temp directories"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match '\\Temp\\' -or $content -match 'SUSPICIOUS.*temp') {
        Pass
    } else {
        Fail "Not detecting temp executables"
    }
}

function Test-ProcessAnomaly-DetectsEncodedPowerShell {
    Write-Test "Detects encoded PowerShell commands"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match '-enc' -or $content -match 'encodedcommand') {
        Pass
    } else {
        Fail "Not detecting encoded commands"
    }
}

#
# ═══════════════════════════════════════════════════════════════
# RECON MODE TESTS
# ═══════════════════════════════════════════════════════════════
#

function Test-ProcessAnomaly-SupportsReconMode {
    Write-Test "Supports recon mode"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match 'ValidateSet.*recon') {
        Pass
    } else {
        Fail "recon mode not supported"
    }
}

function Test-ProcessAnomaly-HasReconCommands {
    Write-Test "Defines reconnaissance commands"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match '\$ReconCommands') {
        Pass
    } else {
        Fail "Missing ReconCommands definition"
    }
}

function Test-ProcessAnomaly-HasHoursParam {
    Write-Test "Has Hours parameter for recon mode"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match '\$Hours') {
        Pass
    } else {
        Fail "Missing Hours parameter"
    }
}

function Test-ProcessAnomaly-HasSuspiciousParents {
    Write-Test "Defines suspicious system parent processes"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match '\$SuspiciousSystemParents') {
        Pass
    } else {
        Fail "Missing SuspiciousSystemParents"
    }
}

function Test-ProcessAnomaly-ReconHasMitreMapping {
    Write-Test "Recon commands have MITRE ATT&CK mapping"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match 'T1082' -and $content -match 'T1016' -and $content -match 'T1033') {
        Pass
    } else {
        Fail "Missing MITRE techniques for recon"
    }
}

function Test-ProcessAnomaly-DetectsHostname {
    Write-Test "Detects hostname command"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match '"hostname"') {
        Pass
    } else {
        Fail "hostname not in recon list"
    }
}

function Test-ProcessAnomaly-DetectsIpconfig {
    Write-Test "Detects ipconfig command"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match '"ipconfig"') {
        Pass
    } else {
        Fail "ipconfig not in recon list"
    }
}

function Test-ProcessAnomaly-DetectsNetCommand {
    Write-Test "Detects net command"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match '"net"') {
        Pass
    } else {
        Fail "net not in recon list"
    }
}

function Test-ProcessAnomaly-DetectsQuser {
    Write-Test "Detects quser command"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match '"quser"') {
        Pass
    } else {
        Fail "quser not in recon list"
    }
}

function Test-ProcessAnomaly-DetectsQwinsta {
    Write-Test "Detects qwinsta command"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match '"qwinsta"') {
        Pass
    } else {
        Fail "qwinsta not in recon list"
    }
}

function Test-ProcessAnomaly-DetectsScCommand {
    Write-Test "Detects sc command with query flags"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match '"sc"' -and $content -match 'query' -and $content -match 'queryex' -and $content -match 'qc') {
        Pass
    } else {
        Fail "sc command or query flags not detected"
    }
}

function Test-ProcessAnomaly-DetectsSysteminfo {
    Write-Test "Detects systeminfo command"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match '"systeminfo"') {
        Pass
    } else {
        Fail "systeminfo not in recon list"
    }
}

function Test-ProcessAnomaly-DetectsTasklist {
    Write-Test "Detects tasklist command"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match '"tasklist"') {
        Pass
    } else {
        Fail "tasklist not in recon list"
    }
}

function Test-ProcessAnomaly-DetectsDsquery {
    Write-Test "Detects dsquery command"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match '"dsquery"') {
        Pass
    } else {
        Fail "dsquery not in recon list"
    }
}

function Test-ProcessAnomaly-DetectsWhoami {
    Write-Test "Detects whoami command"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match '"whoami"') {
        Pass
    } else {
        Fail "whoami not in recon list"
    }
}

function Test-ProcessAnomaly-DetectsCmd {
    Write-Test "Detects cmd.exe"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match '"cmd"') {
        Pass
    } else {
        Fail "cmd not in recon list"
    }
}

function Test-ProcessAnomaly-HasRiskLevels {
    Write-Test "Has risk level indicators (CRITICAL, HIGH, MEDIUM)"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match 'CRITICAL' -and $content -match 'HIGH' -and $content -match 'MEDIUM') {
        Pass
    } else {
        Fail "Missing risk level indicators"
    }
}

function Test-ProcessAnomaly-DetectsServicesParent {
    Write-Test "Detects services.exe as suspicious parent"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match '"services".*CRITICAL') {
        Pass
    } else {
        Fail "services.exe not flagged as CRITICAL parent"
    }
}

function Test-ProcessAnomaly-DetectsSvchostParent {
    Write-Test "Detects svchost.exe as suspicious parent"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match '"svchost".*HIGH') {
        Pass
    } else {
        Fail "svchost.exe not flagged as HIGH parent"
    }
}

function Test-ProcessAnomaly-DetectsLsassParent {
    Write-Test "Detects lsass.exe as suspicious parent"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match '"lsass".*CRITICAL') {
        Pass
    } else {
        Fail "lsass.exe not flagged as CRITICAL parent"
    }
}

function Test-ProcessAnomaly-HasColoredRiskOutput {
    Write-Test "Has colored output for risk levels"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match 'Write-Critical' -and $content -match 'Write-HighRisk' -and $content -match 'Write-MediumRisk') {
        Pass
    } else {
        Fail "Missing colored risk output functions"
    }
}

function Test-ProcessAnomaly-UsesEventLog {
    Write-Test "Uses Security Event Log (4688) for historical recon"
    $scriptPath = Join-Path $WindowsScripts "process_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match 'Get-WinEvent' -and $content -match '4688') {
        Pass
    } else {
        Fail "Not using Event Log for recon history"
    }
}

#
# ═══════════════════════════════════════════════════════════════
# FILE ANOMALY TESTS
# ═══════════════════════════════════════════════════════════════
#

function Test-FileAnomaly-ScriptExists {
    Write-Test "file_anomaly.ps1 exists"
    $scriptPath = Join-Path $WindowsScripts "file_anomaly.ps1"
    if (Assert-FileExists $scriptPath) {
        Pass
    } else {
        Fail "Script not found"
    }
}

function Test-FileAnomaly-MonitorsTempDir {
    Write-Test "Monitors Temp directories"
    $scriptPath = Join-Path $WindowsScripts "file_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match '\$env:TEMP' -or $content -match 'Temp') {
        Pass
    } else {
        Fail "Not monitoring Temp"
    }
}

function Test-FileAnomaly-MonitorsStartup {
    Write-Test "Monitors Startup folders"
    $scriptPath = Join-Path $WindowsScripts "file_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match 'Startup') {
        Pass
    } else {
        Fail "Not monitoring Startup"
    }
}

function Test-FileAnomaly-MonitorsPublic {
    Write-Test "Monitors Public folders"
    $scriptPath = Join-Path $WindowsScripts "file_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match 'PUBLIC' -or $content -match 'Public') {
        Pass
    } else {
        Fail "Not monitoring Public"
    }
}

function Test-FileAnomaly-HasSuspiciousExtensions {
    Write-Test "Defines suspicious extensions"
    $scriptPath = Join-Path $WindowsScripts "file_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match '\.exe' -and $content -match '\.ps1' -and $content -match '\.vbs') {
        Pass
    } else {
        Fail "Missing suspicious extensions"
    }
}

function Test-FileAnomaly-DetectsHiddenFiles {
    Write-Test "Detects hidden files"
    $scriptPath = Join-Path $WindowsScripts "file_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match 'Hidden' -or $content -match 'hidden') {
        Pass
    } else {
        Fail "Not detecting hidden files"
    }
}

function Test-FileAnomaly-DetectsDoubleExtensions {
    Write-Test "Detects double extensions (masquerading)"
    $scriptPath = Join-Path $WindowsScripts "file_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match 'double.*extension' -or $content -match '\.(doc|pdf).*\.(exe|scr)') {
        Pass
    } else {
        Fail "Not detecting double extensions"
    }
}

function Test-FileAnomaly-ProducesJson {
    Write-Test "Produces JSON output"
    $scriptPath = Join-Path $WindowsScripts "file_anomaly.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match 'ConvertTo-Json') {
        Pass
    } else {
        Fail "Not producing JSON"
    }
}

#
# ═══════════════════════════════════════════════════════════════
# PROCESS HUNTER TESTS
# ═══════════════════════════════════════════════════════════════
#

function Test-ProcessHunter-ScriptExists {
    Write-Test "process_hunter.ps1 exists"
    $scriptPath = Join-Path $WindowsScripts "process_hunter.ps1"
    if (Assert-FileExists $scriptPath) {
        Pass
    } else {
        Fail "Script not found"
    }
}

function Test-ProcessHunter-HasPatternParam {
    Write-Test "Has Pattern parameter"
    $scriptPath = Join-Path $WindowsScripts "process_hunter.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match '\$Pattern') {
        Pass
    } else {
        Fail "Missing Pattern parameter"
    }
}

function Test-ProcessHunter-HasKillParam {
    Write-Test "Has Kill parameter"
    $scriptPath = Join-Path $WindowsScripts "process_hunter.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match '\$Kill' -or $content -match 'switch.*Kill') {
        Pass
    } else {
        Fail "Missing Kill parameter"
    }
}

function Test-ProcessHunter-HasSuspiciousPatterns {
    Write-Test "Defines suspicious cmdline patterns"
    $scriptPath = Join-Path $WindowsScripts "process_hunter.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match 'SuspiciousCmdlinePatterns' -or $content -match 'suspicious.*pattern') {
        Pass
    } else {
        Fail "Missing suspicious patterns"
    }
}

function Test-ProcessHunter-DetectsEncodedCommands {
    Write-Test "Detects encoded PowerShell"
    $scriptPath = Join-Path $WindowsScripts "process_hunter.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match '-enc' -and $content -match 'encodedcommand') {
        Pass
    } else {
        Fail "Not detecting encoded commands"
    }
}

function Test-ProcessHunter-DetectsDownloadPatterns {
    Write-Test "Detects download patterns"
    $scriptPath = Join-Path $WindowsScripts "process_hunter.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match 'downloadstring' -or $content -match 'webclient') {
        Pass
    } else {
        Fail "Not detecting downloads"
    }
}

function Test-ProcessHunter-DetectsNetcat {
    Write-Test "Detects netcat/nc"
    $scriptPath = Join-Path $WindowsScripts "process_hunter.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match 'netcat' -or $content -match '\bnc\b') {
        Pass
    } else {
        Fail "Not detecting netcat"
    }
}

function Test-ProcessHunter-DetectsMimikatz {
    Write-Test "Detects mimikatz"
    $scriptPath = Join-Path $WindowsScripts "process_hunter.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match 'mimikatz') {
        Pass
    } else {
        Fail "Not detecting mimikatz"
    }
}

function Test-ProcessHunter-DetectsLOLBins {
    Write-Test "Detects LOLBins (certutil, mshta, etc)"
    $scriptPath = Join-Path $WindowsScripts "process_hunter.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match 'certutil' -and $content -match 'mshta') {
        Pass
    } else {
        Fail "Not detecting LOLBins"
    }
}

function Test-ProcessHunter-HasStopProcess {
    Write-Test "Uses Stop-Process for termination"
    $scriptPath = Join-Path $WindowsScripts "process_hunter.ps1"
    $content = Get-Content -Path $scriptPath -Raw
    if ($content -match 'Stop-Process') {
        Pass
    } else {
        Fail "Not using Stop-Process"
    }
}

#
# ═══════════════════════════════════════════════════════════════
# FIXTURE VALIDATION TESTS
# ═══════════════════════════════════════════════════════════════
#

function Test-Fixture-WindowsBaselineExists {
    Write-Test "Windows baseline fixture exists"
    $fixturePath = Join-Path $FixturesDir "windows_process_baseline.json"
    if (Assert-FileExists $fixturePath) {
        Pass
    } else {
        Fail "Fixture not found"
    }
}

function Test-Fixture-WindowsCompromisedExists {
    Write-Test "Windows compromised fixture exists"
    $fixturePath = Join-Path $FixturesDir "windows_process_compromised.json"
    if (Assert-FileExists $fixturePath) {
        Pass
    } else {
        Fail "Fixture not found"
    }
}

function Test-Fixture-WindowsBaselineValidJson {
    Write-Test "Windows baseline is valid JSON"
    $fixturePath = Join-Path $FixturesDir "windows_process_baseline.json"
    if (Assert-ValidJson $fixturePath) {
        Pass
    } else {
        Fail "Invalid JSON"
    }
}

function Test-Fixture-WindowsCompromisedValidJson {
    Write-Test "Windows compromised is valid JSON"
    $fixturePath = Join-Path $FixturesDir "windows_process_compromised.json"
    if (Assert-ValidJson $fixturePath) {
        Pass
    } else {
        Fail "Invalid JSON"
    }
}

function Test-Fixture-HasRealisticProcesses {
    Write-Test "Baseline has realistic process count"
    $fixturePath = Join-Path $FixturesDir "windows_process_baseline.json"
    $content = Get-Content -Path $fixturePath -Raw | ConvertFrom-Json
    if ($content.processes.Count -ge 10) {
        Pass
    } else {
        Fail "Only $($content.processes.Count) processes"
    }
}

function Test-Fixture-CompromisedHasAttacks {
    Write-Test "Compromised has attack markers"
    $fixturePath = Join-Path $FixturesDir "windows_process_compromised.json"
    $content = Get-Content -Path $fixturePath -Raw
    if ($content -match 'ATTACK:') {
        Pass
    } else {
        Fail "No attack markers"
    }
}

function Test-Fixture-HasMitreTechniques {
    Write-Test "References MITRE ATT&CK techniques"
    $fixturePath = Join-Path $FixturesDir "windows_process_compromised.json"
    $content = Get-Content -Path $fixturePath -Raw
    if ($content -match 'T1\d{3}') {
        Pass
    } else {
        Fail "No MITRE techniques"
    }
}

function Test-Fixture-HasEncodedPowerShell {
    Write-Test "Compromised has encoded PowerShell attack"
    $fixturePath = Join-Path $FixturesDir "windows_process_compromised.json"
    $content = Get-Content -Path $fixturePath -Raw
    if ($content -match '-enc' -and $content -match 'T1059.001') {
        Pass
    } else {
        Fail "No encoded PowerShell"
    }
}

function Test-Fixture-HasLOLBinAttacks {
    Write-Test "Compromised has LOLBin attacks"
    $fixturePath = Join-Path $FixturesDir "windows_process_compromised.json"
    $content = Get-Content -Path $fixturePath -Raw
    if ($content -match 'certutil' -or $content -match 'mshta' -or $content -match 'rundll32') {
        Pass
    } else {
        Fail "No LOLBin attacks"
    }
}

function Test-Fixture-HasCredentialDumping {
    Write-Test "Compromised has credential dumping"
    $fixturePath = Join-Path $FixturesDir "windows_process_compromised.json"
    $content = Get-Content -Path $fixturePath -Raw
    if ($content -match 'mimikatz' -or $content -match 'T1003') {
        Pass
    } else {
        Fail "No credential dumping"
    }
}

#
# ═══════════════════════════════════════════════════════════════
# RUN ALL TESTS
# ═══════════════════════════════════════════════════════════════
#

function Invoke-AllTests {
    Write-Header "Native PowerShell IR Scripts - Test Suite"

    Write-Suite "Process Anomaly Detection"
    Test-ProcessAnomaly-ScriptExists
    Test-ProcessAnomaly-HasRequiredParams
    Test-ProcessAnomaly-SupportsBaseline
    Test-ProcessAnomaly-SupportsScan
    Test-ProcessAnomaly-HasOutputFunctions
    Test-ProcessAnomaly-HasHashFunction
    Test-ProcessAnomaly-UsesGetProcess
    Test-ProcessAnomaly-UsesWmi
    Test-ProcessAnomaly-DetectsTempExecutables
    Test-ProcessAnomaly-DetectsEncodedPowerShell

    Write-Suite "Recon Mode Detection"
    Test-ProcessAnomaly-SupportsReconMode
    Test-ProcessAnomaly-HasReconCommands
    Test-ProcessAnomaly-HasHoursParam
    Test-ProcessAnomaly-HasSuspiciousParents
    Test-ProcessAnomaly-ReconHasMitreMapping
    Test-ProcessAnomaly-DetectsHostname
    Test-ProcessAnomaly-DetectsIpconfig
    Test-ProcessAnomaly-DetectsNetCommand
    Test-ProcessAnomaly-DetectsQuser
    Test-ProcessAnomaly-DetectsQwinsta
    Test-ProcessAnomaly-DetectsScCommand
    Test-ProcessAnomaly-DetectsSysteminfo
    Test-ProcessAnomaly-DetectsTasklist
    Test-ProcessAnomaly-DetectsDsquery
    Test-ProcessAnomaly-DetectsWhoami
    Test-ProcessAnomaly-DetectsCmd
    Test-ProcessAnomaly-HasRiskLevels
    Test-ProcessAnomaly-DetectsServicesParent
    Test-ProcessAnomaly-DetectsSvchostParent
    Test-ProcessAnomaly-DetectsLsassParent
    Test-ProcessAnomaly-HasColoredRiskOutput
    Test-ProcessAnomaly-UsesEventLog

    Write-Suite "File Anomaly Detection"
    Test-FileAnomaly-ScriptExists
    Test-FileAnomaly-MonitorsTempDir
    Test-FileAnomaly-MonitorsStartup
    Test-FileAnomaly-MonitorsPublic
    Test-FileAnomaly-HasSuspiciousExtensions
    Test-FileAnomaly-DetectsHiddenFiles
    Test-FileAnomaly-DetectsDoubleExtensions
    Test-FileAnomaly-ProducesJson

    Write-Suite "Process Hunter"
    Test-ProcessHunter-ScriptExists
    Test-ProcessHunter-HasPatternParam
    Test-ProcessHunter-HasKillParam
    Test-ProcessHunter-HasSuspiciousPatterns
    Test-ProcessHunter-DetectsEncodedCommands
    Test-ProcessHunter-DetectsDownloadPatterns
    Test-ProcessHunter-DetectsNetcat
    Test-ProcessHunter-DetectsMimikatz
    Test-ProcessHunter-DetectsLOLBins
    Test-ProcessHunter-HasStopProcess

    Write-Suite "Test Fixtures Validation"
    Test-Fixture-WindowsBaselineExists
    Test-Fixture-WindowsCompromisedExists
    Test-Fixture-WindowsBaselineValidJson
    Test-Fixture-WindowsCompromisedValidJson
    Test-Fixture-HasRealisticProcesses
    Test-Fixture-CompromisedHasAttacks
    Test-Fixture-HasMitreTechniques
    Test-Fixture-HasEncodedPowerShell
    Test-Fixture-HasLOLBinAttacks
    Test-Fixture-HasCredentialDumping

    # Summary
    Write-Header "Test Summary"
    Write-Host "Tests run:    $script:TestsRun" -ForegroundColor Blue
    Write-Host "Tests passed: $script:TestsPassed" -ForegroundColor Green
    Write-Host "Tests failed: $script:TestsFailed" -ForegroundColor Red
    Write-Host ""

    if ($script:TestsFailed -eq 0) {
        Write-Host ("=" * 45) -ForegroundColor Green
        Write-Host "  ALL TESTS PASSED!" -ForegroundColor Green
        Write-Host ("=" * 45) -ForegroundColor Green
        return 0
    } else {
        Write-Host ("=" * 45) -ForegroundColor Red
        Write-Host "  SOME TESTS FAILED" -ForegroundColor Red
        Write-Host ("=" * 45) -ForegroundColor Red
        return 1
    }
}

# Cleanup
try {
    $exitCode = Invoke-AllTests
}
finally {
    if (Test-Path $TempDir) {
        Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

exit $exitCode

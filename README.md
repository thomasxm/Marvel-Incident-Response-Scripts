# Native Incident Response & Threat Hunting Toolkit

[![Author](https://img.shields.io/badge/Author-Medjed-blue.svg)](https://github.com/medjed)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-green.svg)]()
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)]()
[![Bash](https://img.shields.io/badge/Bash-4.0%2B-green.svg)]()
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red.svg)]()

**Enterprise-grade incident response and threat hunting scripts with zero external dependencies.**

Developed by **Medjed** for Security Operations Center (SOC) teams, incident responders, and threat hunters who need reliable, portable tools that work in air-gapped environments without Python, Ruby, or other runtime dependencies.

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Linux Scripts](#linux-scripts)
  - [Process Anomaly Detection](#process-anomaly-detection-linux)
  - [File Anomaly Detection](#file-anomaly-detection-linux)
  - [Process Hunter](#process-hunter-linux)
- [Windows Scripts](#windows-scripts)
  - [Process Anomaly Detection](#process-anomaly-detection-windows)
  - [File Anomaly Detection](#file-anomaly-detection-windows)
  - [Process Hunter](#process-hunter-windows)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Use Cases](#use-cases)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)
- [Author](#author)

---

## Overview

The **Native IR Toolkit** provides pure Bash (Linux) and pure PowerShell (Windows) scripts for:

- **Baseline Creation**: Capture known-good system state for later comparison
- **Anomaly Detection**: Identify new, missing, or modified processes and files
- **Reconnaissance Detection**: Detect enumeration commands with suspicious parent processes
- **Threat Hunting**: Search for indicators of compromise using pattern matching

All scripts are designed for **enterprise deployment** with:
- Zero external dependencies (no Python, no compiled binaries)
- Colored terminal output for rapid triage
- JSON output for SIEM integration
- MITRE ATT&CK technique mapping
- Comprehensive logging and audit trails

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Zero Dependencies** | Pure Bash/PowerShell - works on fresh OS installs |
| **Baseline Comparison** | Create and compare system state over time |
| **Hash Verification** | SHA256 hashing for executable integrity checking |
| **Recon Detection** | Identify reconnaissance commands with risk scoring |
| **Parent-Child Analysis** | Detect suspicious process relationships |
| **MITRE ATT&CK Mapping** | All detections mapped to ATT&CK techniques |
| **Colored Output** | Risk-based color coding for rapid triage |
| **Cross-Platform** | Matching functionality on Linux and Windows |
| **Air-Gap Ready** | No network connectivity or package managers required |
| **SIEM Integration** | JSON output compatible with Elastic, Splunk, etc. |

---

## Architecture

```
native_scripts/
├── linux/                      # Bash scripts for Linux systems
│   ├── process_anomaly.sh      # Process baseline and anomaly detection
│   ├── file_anomaly.sh         # File system monitoring
│   └── process_hunter.sh       # IOC-based process hunting
├── windows/                    # PowerShell scripts for Windows systems
│   ├── process_anomaly.ps1     # Process baseline, anomaly, and recon detection
│   ├── file_anomaly.ps1        # File system monitoring
│   └── process_hunter.ps1      # IOC-based process hunting
└── tests/                      # Comprehensive test suite
    ├── bash/                   # Bash unit and integration tests
    ├── powershell/             # PowerShell tests
    └── fixtures/               # Synthetic test data with attack scenarios
```

---

## Requirements

### Linux
- Bash 4.0 or later
- Standard Unix utilities: `find`, `stat`, `sha256sum`, `ps`, `grep`, `awk`
- Root/sudo access recommended for full process visibility

### Windows
- PowerShell 5.1 (built into Windows 10/11, Server 2016+)
- PowerShell Core 7.x (optional, for cross-platform)
- Administrator privileges recommended for full WMI access
- Security Event Log access for historical recon detection (Event ID 4688)

---

## Installation

### Option 1: Git Clone
```bash
git clone https://github.com/medjed/native-ir-toolkit.git
cd native-ir-toolkit/native_scripts
```

### Option 2: Direct Download
```bash
# Linux
curl -LO https://github.com/medjed/native-ir-toolkit/archive/main.zip
unzip main.zip

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/medjed/native-ir-toolkit/archive/main.zip" -OutFile main.zip
Expand-Archive main.zip -DestinationPath .
```

### Option 3: Air-Gapped Deployment
Copy the `native_scripts/` directory to removable media for deployment to isolated systems.

---

## Quick Start

### Linux - Detect Process Anomalies
```bash
# Create baseline on clean system
sudo ./linux/process_anomaly.sh baseline -o /secure/baseline.json

# Later, scan for anomalies
sudo ./linux/process_anomaly.sh scan -b /secure/baseline.json
```

### Windows - Detect Reconnaissance Activity
```powershell
# Scan for recon commands in the past 4 hours
.\windows\process_anomaly.ps1 recon -Hours 4

# With specific time window
.\windows\process_anomaly.ps1 recon -Hours 24
```

---

## Linux Scripts

### Process Anomaly Detection (Linux)

**Script:** `linux/process_anomaly.sh`

Monitors running processes by creating baselines and detecting deviations.

#### Modes

| Mode | Description |
|------|-------------|
| `baseline` | Capture current process state to JSON |
| `scan` | Compare current state against baseline |

#### Usage

```bash
# Create baseline
./process_anomaly.sh baseline -o baseline.json

# Scan against baseline
./process_anomaly.sh scan -b baseline.json
```

#### Detection Capabilities

- **New Processes**: Processes not present in baseline
- **Missing Processes**: Expected processes no longer running
- **Modified Executables**: Hash changes indicating tampering
- **Suspicious Indicators**:
  - Executables in `/tmp`, `/dev/shm`, `/var/tmp`
  - Reverse shell patterns (`/dev/tcp`, `bash -i`)
  - Network tools (`nc`, `ncat`, `netcat`, `socat`)

#### Sample Output

```
[NEW] Process: xmrig (PID: 31337)
    User:    www-data
    Exe:     /tmp/.hidden/xmrig
    Cmdline: ./xmrig -o stratum+tcp://pool.example.com:3333
    [!] SUSPICIOUS: Executable in temp directory
```

---

### File Anomaly Detection (Linux)

**Script:** `linux/file_anomaly.sh`

Monitors high-risk directories for unauthorized file changes.

#### Monitored Directories

| Directory | Risk Category |
|-----------|--------------|
| `/tmp`, `/var/tmp`, `/dev/shm` | World-writable locations |
| `/etc/cron.*`, `/var/spool/cron` | Persistence mechanisms |
| `/root`, `/home/*` | User directories |
| `~/.ssh`, `~/.config` | Credential/config storage |

#### Usage

```bash
# Create file baseline
./file_anomaly.sh baseline -o file_baseline.json

# Scan for file anomalies
./file_anomaly.sh scan -b file_baseline.json
```

#### Detection Capabilities

- **New Files**: Files not in baseline
- **Missing Files**: Deleted files (evidence destruction)
- **Modified Files**: Content changes (hash mismatch)
- **Suspicious Indicators**:
  - Hidden files (dotfiles)
  - Executable extensions (`.sh`, `.py`, `.elf`)
  - Cron persistence locations
  - SSH key modifications

---

### Process Hunter (Linux)

**Script:** `linux/process_hunter.sh`

Active threat hunting by searching for IOC patterns in running processes.

#### Usage

```bash
# Search by process name pattern
./process_hunter.sh "crypto\|miner\|xmrig"

# Search by PID
./process_hunter.sh -p 1234

# Search with PPID filter
./process_hunter.sh --ppid 1

# Full scan for all suspicious patterns
./process_hunter.sh --full
```

#### Built-in Suspicious Patterns

- Cryptocurrency miners: `xmrig`, `minerd`, `cryptonight`
- Reverse shells: `/dev/tcp`, `bash -i`, `nc -e`
- Reconnaissance: `nmap`, `masscan`, `enum4linux`
- Credential theft: `mimikatz`, `lazagne`, `secretsdump`
- Web shells: `c99`, `r57`, `weevely`

---

## Windows Scripts

### Process Anomaly Detection (Windows)

**Script:** `windows/process_anomaly.ps1`

Comprehensive process monitoring with baseline comparison and reconnaissance detection.

#### Modes

| Mode | Description |
|------|-------------|
| `baseline` | Capture current process state to JSON |
| `scan` | Compare current state against baseline |
| `recon` | Detect reconnaissance commands (NEW) |

#### Baseline and Scan

```powershell
# Create baseline
.\process_anomaly.ps1 baseline -OutputFile C:\Secure\baseline.json

# Scan against baseline
.\process_anomaly.ps1 scan -BaselineFile C:\Secure\baseline.json
```

#### Reconnaissance Detection Mode

Detects enumeration commands commonly used by attackers during the discovery phase, with special attention to suspicious parent-child process relationships.

```powershell
# Scan past 4 hours (default)
.\process_anomaly.ps1 recon

# Scan past 24 hours
.\process_anomaly.ps1 recon -Hours 24
```

##### Detected Reconnaissance Commands

| Command | MITRE Technique | Description |
|---------|-----------------|-------------|
| `hostname` | T1082 | System hostname discovery |
| `systeminfo` | T1082 | Detailed system information |
| `ipconfig` | T1016 | Network configuration |
| `netstat` | T1016 | Network connections |
| `whoami` | T1033 | Current user identity |
| `quser` | T1033 | Logged-on users |
| `qwinsta` | T1033 | Remote Desktop sessions |
| `tasklist` | T1057 | Running processes |
| `sc query/queryex/qc` | T1007 | Service enumeration |
| `net` | T1087 | User/network enumeration |
| `dsquery` | T1087 | Active Directory queries |
| `nltest` | T1087 | Domain trust enumeration |
| `cmd` | T1059.003 | Windows Command Shell |
| `powershell` | T1059.001 | PowerShell execution |

##### Suspicious Parent Process Detection

When reconnaissance commands are spawned from system-level processes, they receive elevated risk scores:

| Risk Level | Visual | Parent Processes | Interpretation |
|------------|--------|------------------|----------------|
| **CRITICAL** | White on Red | `services.exe`, `lsass.exe`, `csrss.exe`, `smss.exe` | Almost certainly malicious |
| **HIGH** | Red | `svchost.exe`, `winlogon.exe`, `spoolsv.exe`, `wsmprovhost.exe` | Highly suspicious |
| **MEDIUM** | Yellow | `WmiPrvSE.exe`, `dllhost.exe`, `taskhost.exe` | Unusual, investigate |
| **INFO** | Cyan | `explorer.exe`, `cmd.exe`, etc. | Likely legitimate admin activity |

##### Sample Recon Output

```
════════════════════════════════════════════════════════════
  CRITICAL RISK - Suspicious Parent Process Spawning Recon
════════════════════════════════════════════════════════════

[CRITICAL] ipconfig spawned by services (PID: 4521)
    MITRE ATT&CK: T1016 - Network configuration discovery
    Time:       2024-01-15 14:30:22
    User:       NT AUTHORITY\SYSTEM
    Command:    ipconfig /all
    Parent:     services (PID: 684)
    Parent Path: C:\Windows\System32\services.exe
    Risk:       Service Control Manager - should not spawn recon

════════════════════════════════════════════════════════════
  Reconnaissance Scan Summary
════════════════════════════════════════════════════════════
Time Window:           Past 4 hours
Total Recon Commands:  15

[!!!] CRITICAL findings: 2
[!!]  HIGH findings:     3
[!]   MEDIUM findings:   1
[*]   INFO findings:     9

========================================
  ALERT: 6 suspicious parent-child relationships detected!
  Review CRITICAL and HIGH findings immediately.
========================================
```

---

### File Anomaly Detection (Windows)

**Script:** `windows/file_anomaly.ps1`

Monitors high-risk Windows directories for unauthorized changes.

#### Monitored Directories

| Directory | Risk Category |
|-----------|--------------|
| `%TEMP%`, `%TMP%` | Temporary file locations |
| `C:\Users\Public` | World-writable user folder |
| `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` | User persistence |
| `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup` | System persistence |
| `%USERPROFILE%` | User home directories |

#### Usage

```powershell
# Create baseline
.\file_anomaly.ps1 baseline -OutputFile file_baseline.json

# Scan for anomalies
.\file_anomaly.ps1 scan -BaselineFile file_baseline.json
```

#### Detection Capabilities

- New files in monitored directories
- Modified files (hash changes)
- Deleted files (evidence tampering)
- Suspicious indicators:
  - Double extensions (e.g., `document.pdf.exe`)
  - Hidden files
  - Executable extensions in temp directories

---

### Process Hunter (Windows)

**Script:** `windows/process_hunter.ps1`

Active threat hunting with IOC pattern matching.

#### Usage

```powershell
# Search by pattern
.\process_hunter.ps1 -Pattern "mimikatz|sekurlsa"

# Full suspicious process scan
.\process_hunter.ps1 -ScanSuspicious

# Terminate matching processes (DANGER)
.\process_hunter.ps1 -Pattern "cryptominer" -Kill
```

#### Built-in Detection Patterns

- **Encoded Commands**: `-enc`, `-encodedcommand`, `FromBase64String`
- **Download Cradles**: `DownloadString`, `WebClient`, `Invoke-WebRequest`
- **Credential Tools**: `mimikatz`, `sekurlsa`, `lsadump`
- **LOLBins**: `certutil -urlcache`, `mshta`, `regsvr32 /s /i`
- **Lateral Movement**: `psexec`, `wmiexec`, `smbexec`

---

## MITRE ATT&CK Coverage

This toolkit provides detection coverage for the following ATT&CK techniques:

### Discovery (TA0007)

| Technique | ID | Scripts |
|-----------|----|---------|
| System Information Discovery | T1082 | `process_anomaly.ps1 recon` |
| System Network Configuration Discovery | T1016 | `process_anomaly.ps1 recon` |
| System Owner/User Discovery | T1033 | `process_anomaly.ps1 recon` |
| Process Discovery | T1057 | `process_anomaly.ps1 recon` |
| System Service Discovery | T1007 | `process_anomaly.ps1 recon` |
| Account Discovery | T1087 | `process_anomaly.ps1 recon` |
| File and Directory Discovery | T1083 | `process_anomaly.ps1 recon` |

### Execution (TA0002)

| Technique | ID | Scripts |
|-----------|----|---------|
| Command and Scripting Interpreter: PowerShell | T1059.001 | All Windows scripts |
| Command and Scripting Interpreter: Windows Command Shell | T1059.003 | `process_anomaly.ps1 recon` |
| Command and Scripting Interpreter: Unix Shell | T1059.004 | All Linux scripts |

### Persistence (TA0003)

| Technique | ID | Scripts |
|-----------|----|---------|
| Scheduled Task/Job: Cron | T1053.003 | `file_anomaly.sh` |
| Boot or Logon Autostart Execution | T1547 | `file_anomaly.ps1` |
| Server Software Component: Web Shell | T1505.003 | `process_hunter.*` |

### Defense Evasion (TA0005)

| Technique | ID | Scripts |
|-----------|----|---------|
| Masquerading | T1036 | `file_anomaly.*` |
| Indicator Removal | T1070 | Baseline comparison |
| Obfuscated Files or Information | T1027 | `process_hunter.*` |

### Credential Access (TA0006)

| Technique | ID | Scripts |
|-----------|----|---------|
| OS Credential Dumping | T1003 | `process_hunter.*` |

---

## Use Cases

### 1. Post-Incident Baseline Comparison

```bash
# Before incident (or on known-clean system)
./process_anomaly.sh baseline -o /evidence/pre_incident.json

# After suspected compromise
./process_anomaly.sh scan -b /evidence/pre_incident.json > /evidence/anomalies.txt
```

### 2. Daily Security Monitoring

```powershell
# Scheduled task running daily
.\process_anomaly.ps1 recon -Hours 24 | Out-File "C:\Logs\recon_$(Get-Date -Format 'yyyyMMdd').log"
```

### 3. Live Incident Response

```bash
# Rapid triage during active incident
./process_hunter.sh --full | tee /evidence/suspicious_processes.txt

# Kill cryptominer
./process_hunter.sh -k "xmrig\|minerd"
```

### 4. Threat Hunting Campaign

```powershell
# Hunt for Cobalt Strike indicators
.\process_hunter.ps1 -Pattern "beacon|cobaltstrike|rundll32.*,Start"

# Hunt for encoded PowerShell
.\process_hunter.ps1 -Pattern "-enc|-encodedcommand"
```

### 5. Compliance Auditing

```bash
# Create golden image baseline
./file_anomaly.sh baseline -o /compliance/golden_image.json

# Weekly compliance check
./file_anomaly.sh scan -b /compliance/golden_image.json
```

---

## Testing

The toolkit includes a comprehensive test suite with unit tests, integration tests, and synthetic attack data.

### Run All Tests

```bash
cd tests
./run_all_tests.sh
```

### Run Specific Test Suites

```bash
# Bash unit tests (39 tests)
./bash/test_runner.sh

# Bash scenario tests (28 tests)
./bash/test_scenarios.sh

# PowerShell tests (60+ tests)
pwsh -File ./powershell/Test-AllScripts.ps1
```

### Test Fixtures

The `tests/fixtures/` directory contains synthetic datasets with realistic attack scenarios:

| Fixture | Description |
|---------|-------------|
| `linux_process_baseline.json` | Clean Linux process state |
| `linux_process_compromised.json` | 12 malicious processes (web shells, miners, etc.) |
| `linux_file_baseline.json` | Clean file system state |
| `linux_file_compromised.json` | 10 malicious files (backdoors, cron persistence) |
| `windows_process_baseline.json` | Clean Windows process state |
| `windows_process_compromised.json` | Windows attack scenarios |

---

## Contributing

Contributions are welcome! Please follow these guidelines:

### Code Standards

- **Bash**: Follow [Google Shell Style Guide](https://google.github.io/styleguide/shellguide.html)
- **PowerShell**: Follow [PowerShell Best Practices](https://poshcode.gitbook.io/powershell-practice-and-style/)
- **Zero Dependencies**: No external tools, packages, or binaries
- **MITRE Mapping**: All detections should reference ATT&CK techniques

### Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-detection`)
3. Add tests for new functionality
4. Ensure all tests pass (`./tests/run_all_tests.sh`)
5. Submit a pull request

### Reporting Issues

Please include:
- OS version and shell/PowerShell version
- Steps to reproduce
- Expected vs actual behavior
- Relevant log output

---

## License

MIT License

Copyright (c) 2024 Medjed

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## Author

**Medjed**

Developed for the security community to enable effective incident response and threat hunting without dependency hell.

- Enterprise-focused design
- Battle-tested in production SOC environments
- Continuous improvement based on real-world IR engagements

---

## Acknowledgments

- MITRE ATT&CK Framework for technique taxonomy
- The open-source security community for detection research
- SOC analysts and incident responders who provided feedback

---

*"The best incident response tool is the one that works when you need it."* — Medjed

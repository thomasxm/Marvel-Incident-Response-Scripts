# Marvel Incident Response & Threat Hunting Toolkit

[![Author](https://img.shields.io/badge/Author-Medjed-blue.svg)](https://github.com/thomasxm)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-green.svg)]()
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)]()
[![Bash](https://img.shields.io/badge/Bash-4.0%2B-green.svg)]()
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)]()
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red.svg)]()

**Enterprise-grade incident response and threat hunting toolkit for SOC teams.**

A comprehensive collection of cross-platform scripts for:
- **Native Scripts** - Pure Bash/PowerShell with zero dependencies (air-gap ready)
- **Python Scripts** - Enhanced detection with SIEM/Elastic integration
- **Network Isolation** - Interactive firewall management for containment

Developed by **Medjed** for Security Operations Center (SOC) teams, incident responders, and threat hunters.

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Native Scripts](#native-scripts)
  - [Process Anomaly Detection](#process-anomaly-detection)
  - [File Anomaly Detection](#file-anomaly-detection)
  - [Persistence Anomaly Detection](#persistence-anomaly-detection)
  - [Process Hunter](#process-hunter)
- [Network Isolation](#network-isolation)
  - [Linux (iptables)](#linux-iptables)
  - [Linux (UFW)](#linux-ufw)
  - [Windows Firewall](#windows-firewall)
- [Python IR Scripts](#python-ir-scripts)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Use Cases](#use-cases)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)
- [Author](#author)

---

## Overview

The **Marvel IR Toolkit** provides a comprehensive set of tools for incident response and threat hunting:

### Native Scripts (Zero Dependencies)
Pure Bash (Linux) and PowerShell (Windows) scripts that work on fresh OS installs:
- **Baseline Creation**: Capture known-good system state for later comparison
- **Anomaly Detection**: Identify new, missing, or modified processes, files, and persistence mechanisms
- **Reconnaissance Detection**: Detect enumeration commands with suspicious parent processes
- **Threat Hunting**: Search for indicators of compromise using pattern matching

### Network Isolation Tools
Interactive firewall management for rapid containment during incidents:
- **iptables/UFW (Linux)**: Block IPs, ports, or fully isolate compromised systems
- **Windows Firewall**: Equivalent functionality for Windows environments
- **Emergency Isolation**: One-click network containment

### Python Scripts (SIEM Integration)
Enhanced detection capabilities with Elastic/Splunk integration:
- Process hunting with psutil
- Extensible detection framework
- JSON output for SIEM ingestion

All scripts are designed for **enterprise deployment** with:
- Colored terminal output for rapid triage
- JSON output for SIEM integration
- MITRE ATT&CK technique mapping
- Comprehensive logging and audit trails

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Zero Dependencies** | Native scripts work on fresh OS installs (Bash/PowerShell only) |
| **Baseline Comparison** | Create and compare system state over time |
| **Hash Verification** | SHA256 hashing for executable integrity checking |
| **Persistence Detection** | Monitor cron, systemd, Run keys, scheduled tasks, and 20+ persistence mechanisms |
| **Network Isolation** | Interactive firewall tools for rapid containment (iptables, UFW, Windows Firewall) |
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
marvel-ir-toolkit/
├── native_scripts/                 # Zero-dependency scripts
│   ├── linux/                      # Bash scripts for Linux
│   │   ├── process_anomaly.sh      # Process baseline and anomaly detection
│   │   ├── file_anomaly.sh         # File system monitoring
│   │   ├── persistence_anomaly.sh  # Persistence mechanism detection
│   │   └── process_hunter.sh       # IOC-based process hunting
│   ├── windows/                    # PowerShell scripts for Windows
│   │   ├── process_anomaly.ps1     # Process baseline, anomaly, and recon detection
│   │   ├── file_anomaly.ps1        # File system monitoring
│   │   ├── persistence_anomaly.ps1 # Persistence mechanism detection
│   │   └── process_hunter.ps1      # IOC-based process hunting
│   └── tests/                      # Comprehensive test suite
│
├── network_isolation/              # Firewall management tools
│   ├── linux/
│   │   ├── network_isolate_iptables.sh  # iptables-based isolation
│   │   └── network_isolate_ufw.sh       # UFW-based isolation
│   └── windows/
│       └── network_isolate.ps1          # Windows Firewall management
│
├── ir_scripts/                     # Python-based IR scripts
│   ├── process_hunter.py           # Advanced process hunting
│   ├── process_anomaly.py          # Process anomaly detection
│   ├── file_anomaly.py             # File anomaly detection
│   └── utils/                      # Shared utilities
│
└── tests/                          # Python test suite
```

---

## Requirements

### Native Scripts (Zero Dependencies)

#### Linux
- Bash 4.0 or later
- Standard Unix utilities: `find`, `stat`, `sha256sum`, `ps`, `grep`, `awk`
- iptables or ufw (for network isolation)
- Root/sudo access recommended for full process visibility

#### Windows
- PowerShell 5.1 (built into Windows 10/11, Server 2016+)
- PowerShell Core 7.x (optional, for cross-platform)
- Administrator privileges recommended for full WMI access
- Security Event Log access for historical recon detection (Event ID 4688)

### Python Scripts (Optional)
- Python 3.8+
- psutil (`pip install psutil`)

---

## Installation

### Option 1: Git Clone
```bash
git clone https://github.com/thomasxm/Marvel-Incident-Response-Scripts.git
cd Marvel-Incident-Response-Scripts
```

### Option 2: Direct Download
```bash
# Linux
curl -LO https://github.com/thomasxm/Marvel-Incident-Response-Scripts/archive/main.zip
unzip main.zip

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/thomasxm/Marvel-Incident-Response-Scripts/archive/main.zip" -OutFile main.zip
Expand-Archive main.zip -DestinationPath .
```

### Option 3: Air-Gapped Deployment
Copy the `native_scripts/` and `network_isolation/` directories to removable media for deployment to isolated systems.

### Python Scripts (Optional)
```bash
pip install -r requirements.txt
```

---

## Quick Start

### Detect Process Anomalies
```bash
# Linux - Create baseline on clean system
sudo ./native_scripts/linux/process_anomaly.sh baseline -o /secure/baseline.json
sudo ./native_scripts/linux/process_anomaly.sh scan -b /secure/baseline.json

# Windows - Scan for recon commands
.\native_scripts\windows\process_anomaly.ps1 recon -Hours 4
```

### Detect Persistence Mechanisms
```bash
# Linux - Scan for cron, systemd, SSH keys, etc.
sudo ./native_scripts/linux/persistence_anomaly.sh baseline -o baseline.json
sudo ./native_scripts/linux/persistence_anomaly.sh scan -b baseline.json

# Windows - Scan Run keys, scheduled tasks, services, etc.
.\native_scripts\windows\persistence_anomaly.ps1 baseline -OutputFile baseline.json
.\native_scripts\windows\persistence_anomaly.ps1 scan -BaselineFile baseline.json
```

### Emergency Network Isolation
```bash
# Linux - Launch interactive isolation menu
sudo ./network_isolation/linux/network_isolate_iptables.sh

# Windows - Launch interactive isolation menu
.\network_isolation\windows\network_isolate.ps1
```

---

## Native Scripts

**Zero external dependencies** - no Python, no compiled binaries, no package managers required. Pure Bash (Linux) and PowerShell (Windows) scripts that work on fresh OS installs and in air-gapped environments.

### Process Anomaly Detection

| Platform | Script |
|----------|--------|
| Linux | `native_scripts/linux/process_anomaly.sh` |
| Windows | `native_scripts/windows/process_anomaly.ps1` |

Monitors running processes by creating baselines and detecting deviations.

#### Modes

| Mode | Description |
|------|-------------|
| `baseline` | Capture current process state to JSON |
| `scan` | Compare current state against baseline |

#### Usage

```bash
# Linux - Create baseline
./process_anomaly.sh baseline -o baseline.json

# Linux - Scan against baseline
./process_anomaly.sh scan -b baseline.json
```

```powershell
# Windows - Create baseline
.\process_anomaly.ps1 baseline -OutputFile baseline.json

# Windows - Scan against baseline
.\process_anomaly.ps1 scan -BaselineFile baseline.json

# Windows - Detect reconnaissance commands
.\process_anomaly.ps1 recon -Hours 4
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

### File Anomaly Detection

| Platform | Script |
|----------|--------|
| Linux | `native_scripts/linux/file_anomaly.sh` |
| Windows | `native_scripts/windows/file_anomaly.ps1` |

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
# Linux - Create file baseline
./file_anomaly.sh baseline -o file_baseline.json

# Linux - Scan for file anomalies
./file_anomaly.sh scan -b file_baseline.json
```

```powershell
# Windows - Create file baseline
.\file_anomaly.ps1 baseline -OutputFile file_baseline.json

# Windows - Scan for file anomalies
.\file_anomaly.ps1 scan -BaselineFile file_baseline.json
```

#### Detection Capabilities

- **New Files**: Files not in baseline
- **Missing Files**: Deleted files (evidence destruction)
- **Modified Files**: Content changes (hash mismatch)
- **Suspicious Indicators**:
  - Hidden files (dotfiles)
  - Executable extensions (`.sh`, `.py`, `.elf`, `.exe`, `.dll`)
  - Cron/Startup persistence locations
  - SSH key / credential file modifications

---

### Process Hunter

| Platform | Script |
|----------|--------|
| Linux | `native_scripts/linux/process_hunter.sh` |
| Windows | `native_scripts/windows/process_hunter.ps1` |

Active threat hunting by searching for IOC patterns in running processes.

#### Usage

```bash
# Linux - Search by process name pattern
./process_hunter.sh "crypto\|miner\|xmrig"

# Linux - Search by PID
./process_hunter.sh -p 1234

# Linux - Full scan for all suspicious patterns
./process_hunter.sh --full

# Linux - Kill matching processes
./process_hunter.sh -k "xmrig\|minerd"
```

```powershell
# Windows - Search by pattern
.\process_hunter.ps1 -Pattern "mimikatz|sekurlsa"

# Windows - Full suspicious process scan
.\process_hunter.ps1 -ScanSuspicious

# Windows - Terminate matching processes (DANGER)
.\process_hunter.ps1 -Pattern "cryptominer" -Kill
```

#### Built-in Suspicious Patterns

- Cryptocurrency miners: `xmrig`, `minerd`, `cryptonight`
- Reverse shells: `/dev/tcp`, `bash -i`, `nc -e`
- Reconnaissance: `nmap`, `masscan`, `enum4linux`
- Credential theft: `mimikatz`, `lazagne`, `secretsdump`
- Web shells: `c99`, `r57`, `weevely`

---

### Persistence Anomaly Detection

| Platform | Script |
|----------|--------|
| Linux | `native_scripts/linux/persistence_anomaly.sh` |
| Windows | `native_scripts/windows/persistence_anomaly.ps1` |

Comprehensive persistence mechanism monitoring with multi-level scanning.

#### Scan Levels

| Level | Description | Categories |
|-------|-------------|------------|
| 1 | Essential | Cron, systemd services, Run keys, scheduled tasks, startup folders |
| 2 | Comprehensive | + SSH keys, shell configs, Winlogon, AppInit DLLs, COM hijacks |
| 3 | Exhaustive | + Kernel modules, udev rules, WMI subscriptions, LSA packages |

#### Linux Persistence Categories

| Category | MITRE Technique | Description |
|----------|-----------------|-------------|
| `cron` | T1053.003 | Cron Jobs |
| `systemd-services` | T1543.002 | Systemd Services |
| `systemd-timers` | T1053.006 | Systemd Timers |
| `shell-rc` | T1546.004 | Shell Configuration (.bashrc, .profile) |
| `ssh-keys` | T1098.004 | SSH Authorized Keys |
| `init-scripts` | T1037.004 | Init Scripts |
| `ld-preload` | T1574.006 | LD_PRELOAD Hijacking |
| `kernel-modules` | T1547.006 | Kernel Modules |
| `udev-rules` | T1546.012 | Udev Rules |

#### Windows Persistence Categories

| Category | MITRE Technique | Description |
|----------|-----------------|-------------|
| `run-keys` | T1547.001 | Registry Run Keys |
| `scheduled-tasks` | T1053.005 | Scheduled Tasks |
| `services` | T1543.003 | Windows Services |
| `startup-folder` | T1547.001 | Startup Folder |
| `winlogon` | T1547.004 | Winlogon Helper DLL |
| `appinit-dlls` | T1546.010 | AppInit DLLs |
| `image-hijacks` | T1546.012 | Image File Execution Options |
| `wmi-subscriptions` | T1546.003 | WMI Event Subscription |
| `com-hijacks` | T1546.015 | COM Object Hijacking |

#### Usage

```bash
# Linux - Create baseline and scan
./persistence_anomaly.sh baseline -o baseline.json
./persistence_anomaly.sh scan -b baseline.json -o results.json

# Windows - Scan with level 2 (comprehensive)
.\persistence_anomaly.ps1 baseline -Level 2 -OutputFile baseline.json
.\persistence_anomaly.ps1 scan -BaselineFile baseline.json -Level 2
```

---

## Network Isolation

Interactive firewall management tools for rapid network containment during incident response.

### Linux (iptables)

**Script:** `network_isolation/linux/network_isolate_iptables.sh`

Interactive menu-driven iptables management for incident response.

#### Features

| Feature | Description |
|---------|-------------|
| View Rules | Show current iptables rules with line numbers |
| Block/Allow Ports | Block or allow specific ports (TCP/UDP) |
| Block/Allow IPs | Block or allow specific IP addresses or CIDR ranges |
| Emergency Isolation | Block all incoming or outgoing traffic |
| Interface Control | Take down or bring up network interfaces |
| Reset | Reset iptables to allow all traffic |

#### Usage

```bash
sudo ./network_isolation/linux/network_isolate_iptables.sh
```

### Linux (UFW)

**Script:** `network_isolation/linux/network_isolate_ufw.sh`

UFW-based alternative for systems using Uncomplicated Firewall.

#### Usage

```bash
sudo ./network_isolation/linux/network_isolate_ufw.sh
```

### Windows Firewall

**Script:** `network_isolation/windows/network_isolate.ps1`

Interactive Windows Firewall management with netsh.

#### Features

| Feature | Description |
|---------|-------------|
| Firewall Status | View all profile states and settings |
| Block/Allow Ports | Create inbound/outbound port rules |
| Block/Allow IPs | Block or allow specific IP addresses |
| Emergency Isolation | Block all inbound/outbound (emergency containment) |
| Adapter Control | Disable/enable network adapters |
| Reset | Reset firewall to Windows defaults |

#### Usage

```powershell
# Run as Administrator
.\network_isolation\windows\network_isolate.ps1
```

#### Sample Menu

```
  ================================================================
       Windows Network Isolation Script - Incident Response
  ================================================================

  FIREWALL STATUS
  [1] Show firewall status and profiles
  [2] Show open ports and connections

  BLOCK RULES
  [5] Block a specific port (inbound)
  [6] Block a specific port (outbound)
  [7] Block a specific IP address

  EMERGENCY ISOLATION
  [11] Block all inbound (emergency isolation)
  [12] Block all outbound (emergency isolation)
```

---

## Python IR Scripts

Python-based scripts with enhanced detection capabilities and SIEM integration.

**Requirements:** Python 3.8+, psutil

| Script | Description |
|--------|-------------|
| `ir_scripts/process_hunter.py` | Advanced process hunting with regex patterns |
| `ir_scripts/process_anomaly.py` | Process baseline and anomaly detection |
| `ir_scripts/file_anomaly.py` | File system monitoring |

#### Installation

```bash
pip install -r requirements.txt
```

#### Process Hunter (Python)

```bash
# Hunt for suspicious processes
python ir_scripts/process_hunter.py "nc|ncat|netcat"

# Search in command lines
python ir_scripts/process_hunter.py -c "base64|/dev/tcp"

# Output to JSON for SIEM ingestion
python ir_scripts/process_hunter.py -o results.json "pattern"

# Kill matching processes
python ir_scripts/process_hunter.py -k "xmrig|miner"
```

#### Process Anomaly (Python)

```bash
# Create baseline
python ir_scripts/process_anomaly.py baseline -o baseline.json

# Scan for anomalies
python ir_scripts/process_anomaly.py scan -b baseline.json

# Output to JSON
python ir_scripts/process_anomaly.py scan -b baseline.json -o results.json
```

#### File Anomaly (Python)

```bash
# Create baseline of monitored directories
python ir_scripts/file_anomaly.py baseline -o file_baseline.json

# Scan for file changes
python ir_scripts/file_anomaly.py scan -b file_baseline.json

# Output to JSON
python ir_scripts/file_anomaly.py scan -b file_baseline.json -o results.json
```

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
| Scheduled Task/Job: Cron | T1053.003 | `persistence_anomaly.sh` |
| Scheduled Task/Job: Windows Task Scheduler | T1053.005 | `persistence_anomaly.ps1` |
| Systemd Services | T1543.002 | `persistence_anomaly.sh` |
| Windows Services | T1543.003 | `persistence_anomaly.ps1` |
| Registry Run Keys | T1547.001 | `persistence_anomaly.ps1` |
| Winlogon Helper DLL | T1547.004 | `persistence_anomaly.ps1` |
| SSH Authorized Keys | T1098.004 | `persistence_anomaly.sh` |
| AppInit DLLs | T1546.010 | `persistence_anomaly.ps1` |
| WMI Event Subscription | T1546.003 | `persistence_anomaly.ps1` |
| Boot or Logon Autostart Execution | T1547 | `file_anomaly.*` |
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

### 6. Emergency Network Containment

```bash
# Linux - Immediately isolate compromised host
sudo ./network_isolation/linux/network_isolate_iptables.sh
# Select option 7 or 8 for emergency isolation

# Windows - Isolate while preserving forensic access
.\network_isolation\windows\network_isolate.ps1
# Block all outbound, allow specific forensic IP
```

### 7. Persistence Mechanism Audit

```bash
# Linux - Full persistence scan
./native_scripts/linux/persistence_anomaly.sh baseline -o baseline.json
./native_scripts/linux/persistence_anomaly.sh scan -b baseline.json --level 3

# Windows - Scan all persistence locations
.\native_scripts\windows\persistence_anomaly.ps1 scan -Level 3
```

---

## Testing

The toolkit includes a comprehensive test suite with unit tests, integration tests, and synthetic attack data.

### Run All Tests

```bash
# Native script tests
cd native_scripts/tests
./run_all_tests.sh

# Python tests
cd tests
pytest
```

### Run Specific Test Suites

```bash
# Bash unit tests
./native_scripts/tests/bash/test_runner.sh

# Bash scenario tests
./native_scripts/tests/bash/test_scenarios.sh

# PowerShell tests
pwsh -File ./native_scripts/tests/powershell/Test-AllScripts.ps1

# Python tests
pytest tests/
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
- **Python**: Follow PEP 8, use type hints
- **Native Scripts**: Zero external dependencies (Bash/PowerShell only)
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

Copyright (c) 2026 Medjed

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

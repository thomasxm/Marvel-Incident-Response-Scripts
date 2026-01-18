# Persistence Anomaly Detection - Design Document

**Author:** Medjed
**Date:** 2026-01-18
**Status:** Approved

## Overview

Native persistence detection scripts for Linux and Windows that create baselines of persistence mechanisms and detect new/modified entries with MITRE ATT&CK mapping and risk scoring.

## Scripts

- `persistence_anomaly.sh` - Linux (Pure Bash)
- `persistence_anomaly.ps1` - Windows (Pure PowerShell)

## Commands

| Command | Description |
|---------|-------------|
| `baseline` | Create baseline of persistence mechanisms |
| `scan` | Scan and compare against baseline |
| `show` | Display baseline/scan results in formatted table |

## Options

| Option | Description |
|--------|-------------|
| `-o, --output FILE` | Output file for baseline/scan results |
| `-b, --baseline FILE` | Baseline file for comparison (scan command) |
| `-f, --file FILE` | File to display (show command) |
| `-l, --level 1\|2\|3` | Scan level: 1=Essential, 2=Comprehensive, 3=Exhaustive (default: 2) |
| `-c, --category LIST` | Specific categories (comma-separated) |
| `-h, --help` | Show help with category list |

## Scan Levels

### Level 1 - Essential (Fast, Low Noise)
Most common persistence mechanisms used by attackers.

### Level 2 - Comprehensive (Balanced) - Default
Adds less common but important mechanisms.

### Level 3 - Exhaustive (Full Coverage)
Nearly all known MITRE ATT&CK persistence techniques.

## Linux Persistence Mechanisms

| Level | Category | Locations | MITRE ATT&CK |
|-------|----------|-----------|--------------|
| 1 | cron | `/etc/crontab`, `/etc/cron.d/*`, `/etc/cron.{daily,hourly,weekly,monthly}/*`, `/var/spool/cron/crontabs/*` | T1053.003 |
| 1 | systemd-services | `/etc/systemd/system/*`, `/lib/systemd/system/*`, `~/.config/systemd/user/*` | T1543.002 |
| 1 | shell-rc | `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zshrc`, `/etc/profile`, `/etc/profile.d/*` | T1546.004 |
| 1 | ssh-keys | `~/.ssh/authorized_keys`, `/etc/ssh/sshd_config` | T1098.004 |
| 2 | systemd-timers | `*.timer` files in systemd paths | T1053.006 |
| 2 | at-jobs | `/var/spool/at/*`, `/var/spool/atjobs/*` | T1053.002 |
| 2 | init-scripts | `/etc/init.d/*`, `/etc/rc.local` | T1037.004 |
| 2 | xdg-autostart | `~/.config/autostart/*`, `/etc/xdg/autostart/*` | T1547.013 |
| 3 | ld-preload | `/etc/ld.so.preload`, `LD_PRELOAD` in shell configs | T1574.006 |
| 3 | kernel-modules | `/etc/modules`, `/etc/modules-load.d/*` | T1547.006 |
| 3 | udev-rules | `/etc/udev/rules.d/*` | T1546.012 |
| 3 | motd-scripts | `/etc/update-motd.d/*` | T1546 |

## Windows Persistence Mechanisms

| Level | Category | Locations | MITRE ATT&CK |
|-------|----------|-----------|--------------|
| 1 | run-keys | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `HKCU\...\Run`, `RunOnce` variants | T1547.001 |
| 1 | scheduled-tasks | `schtasks /query` (all tasks), `C:\Windows\System32\Tasks\*` | T1053.005 |
| 1 | services | `HKLM\SYSTEM\CurrentControlSet\Services\*`, `sc query` | T1543.003 |
| 1 | startup-folder | `%APPDATA%\...\Startup\*`, `%ProgramData%\...\Startup\*` | T1547.001 |
| 2 | winlogon | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` (Shell, Userinit) | T1547.004 |
| 2 | appinit-dlls | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` | T1546.010 |
| 2 | image-hijacks | `HKLM\...\Image File Execution Options\*` | T1546.012 |
| 2 | browser-helpers | `HKLM\...\Browser Helper Objects\*` | T1176 |
| 2 | com-hijacks | `HKCR\CLSID\*\InprocServer32`, `TreatAs`, `ScriptletURL` keys | T1546.015 |
| 3 | wmi-subscriptions | `Get-WMIObject __FilterToConsumerBinding` | T1546.003 |
| 3 | boot-execute | `HKLM\SYSTEM\...\Session Manager\BootExecute` | T1547.012 |
| 3 | lsa-packages | `HKLM\SYSTEM\...\Control\Lsa` (Security/Auth Packages) | T1547.002 |
| 3 | print-monitors | `HKLM\SYSTEM\...\Print\Monitors\*` | T1547.010 |
| 3 | netsh-helpers | `HKLM\SOFTWARE\Microsoft\NetSh` | T1546.007 |
| 3 | office-addins | `HKCU\Software\Microsoft\Office\*\Addins\*` | T1137 |
| 3 | bits-jobs | `bitsadmin /list /allusers /verbose` | T1197 |

## Detection Approach

### Existence-Based
- Track which persistence entries exist (paths, names, registry keys)
- Detect NEW entries not in baseline
- Detect MISSING entries removed since baseline

### Hash-Based
- Store SHA256 hash of entry content (script files, registry values, task XML)
- Detect MODIFIED entries where content changed

## Risk Scoring

| Score | Criteria |
|-------|----------|
| CRITICAL | 3+ indicators OR network+shell combo OR temp path execution |
| HIGH | 2 indicators OR encoded/obfuscated content |
| MEDIUM | 1 indicator OR recently modified (< 24h) |
| LOW | New entry with no suspicious indicators |

### Risk Indicators

**Path-Based:**
- Executable in `/tmp`, `/dev/shm`, `/var/tmp` (Linux)
- Executable in `%TEMP%`, `%APPDATA%` unusual paths (Windows)
- Base64/encoded commands in scripts

**Behavioral:**
- Recently modified entries (within configurable hours)
- Network commands: `curl`, `wget`, `nc`, `powershell -enc`
- Hidden files/obfuscated names
- Running as SYSTEM/root unexpectedly

## JSON Output Format

### Baseline Structure
```json
{
  "timestamp": "ISO8601",
  "hostname": "string",
  "platform": "Linux|Windows",
  "scan_level": 1|2|3,
  "categories_scanned": ["array"],
  "entries": [
    {
      "category": "string",
      "path": "string",
      "content_hash": "sha256",
      "owner": "string",
      "permissions": "string",
      "mtime": "unix_timestamp",
      "mitre_technique": "Txxxx.xxx",
      "command_preview": "string (first 200 chars)"
    }
  ]
}
```

### Scan Results Structure
```json
{
  "scan_type": "persistence_anomaly",
  "timestamp": "ISO8601",
  "hostname": "string",
  "baseline_file": "string",
  "scan_level": 1|2|3,
  "summary": {
    "new_count": 0,
    "modified_count": 0,
    "missing_count": 0,
    "total_anomalies": 0
  },
  "anomalies": [
    {
      "category": "new|modified|missing",
      "entry_type": "category_name",
      "path": "string",
      "mitre_technique": "Txxxx.xxx",
      "content_hash": "sha256",
      "command_preview": "string",
      "risk_score": "LOW|MEDIUM|HIGH|CRITICAL",
      "risk_indicators": ["array"]
    }
  ]
}
```

## Example Usage

```bash
# Linux - Quick baseline
./persistence_anomaly.sh baseline -l 1 -o baseline.json

# Linux - Full scan
./persistence_anomaly.sh scan -b baseline.json -l 3 -o results.json

# Linux - Scan specific categories
./persistence_anomaly.sh scan -b baseline.json -c cron,ssh-keys -o cron_results.json

# Linux - View results
./persistence_anomaly.sh show -f results.json
```

```powershell
# Windows - Comprehensive baseline
.\persistence_anomaly.ps1 baseline -Level 2 -Output baseline.json

# Windows - Exhaustive scan
.\persistence_anomaly.ps1 scan -Baseline baseline.json -Level 3 -Output results.json

# Windows - View results
.\persistence_anomaly.ps1 show -File results.json
```

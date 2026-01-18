"""
Process utilities for incident response.

Provides functions for enumerating processes, extracting attributes,
identifying kernel processes, and computing executable hashes.
"""

import hashlib
import os
import platform
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

import psutil

# Linux kernel processes (protected system processes)
LINUX_KERNEL_PROCESSES: Set[str] = {
    'kthreadd',
    'kworker',
    'ksoftirqd',
    'kswapd',
    'migration',
    'rcu_sched',
    'rcu_bh',
    'rcu_preempt',
    'watchdog',
    'cpuhp',
    'kdevtmpfs',
    'netns',
    'kauditd',
    'khungtaskd',
    'oom_reaper',
    'writeback',
    'kcompactd',
    'ksmd',
    'khugepaged',
    'kintegrityd',
    'kblockd',
    'kthrotld',
    'kswapd0',
    'ecryptfs-kthrea',
    'charger_manager',
    'scsi_eh',
    'scsi_tmf',
    'irq',
    'kpsmoused',
    'ipv6_addrconf',
    'krfcommd',
    'zswap',
}

# Windows kernel/system processes (protected system processes)
WINDOWS_KERNEL_PROCESSES: Set[str] = {
    'System',
    'Registry',
    'smss.exe',
    'csrss.exe',
    'wininit.exe',
    'services.exe',
    'lsass.exe',
    'winlogon.exe',
    'svchost.exe',
    'dwm.exe',
    'taskhostw.exe',
    'RuntimeBroker.exe',
    'sihost.exe',
    'fontdrvhost.exe',
    'WmiPrvSE.exe',
    'spoolsv.exe',
    'SearchIndexer.exe',
    'audiodg.exe',
    'conhost.exe',
    'dllhost.exe',
    'lsm.exe',
    'MsMpEng.exe',
}


def is_kernel_process(name: str, pid: int) -> bool:
    """
    Check if a process is a protected kernel/system process.

    Args:
        name: Process name
        pid: Process ID

    Returns:
        True if this is a kernel/system process, False otherwise
    """
    system = platform.system()

    if system == 'Linux':
        # PID 0 is the kernel itself (swapper/sched)
        # PID 1 is init/systemd
        # PID 2 is kthreadd (kernel thread daemon)
        if pid in (0, 1, 2):
            return True

        # Check if name matches known kernel processes
        # Many kernel threads have names like 'kworker/0:1' so check prefix
        for kernel_proc in LINUX_KERNEL_PROCESSES:
            if name.startswith(kernel_proc):
                return True

        # Check if process has no executable (kernel threads don't have exe)
        try:
            proc = psutil.Process(pid)
            exe = proc.exe()
            if not exe:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    elif system == 'Windows':
        # PID 0 is System Idle Process
        # PID 4 is System
        if pid in (0, 4):
            return True

        # Check against known Windows system processes
        if name in WINDOWS_KERNEL_PROCESSES:
            return True

    return False


def compute_process_hash(exe_path: str, algorithm: str = 'sha256') -> Optional[str]:
    """
    Compute hash of a process executable.

    Args:
        exe_path: Path to the executable file
        algorithm: Hash algorithm to use (md5, sha1, sha256, sha512)

    Returns:
        Hex digest of the hash, or None if file cannot be read
    """
    if not exe_path or not os.path.isfile(exe_path):
        return None

    try:
        hasher = hashlib.new(algorithm)
        with open(exe_path, 'rb') as f:
            # Read in chunks to handle large files
            for chunk in iter(lambda: f.read(65536), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (OSError, IOError, PermissionError, ValueError):
        return None


def get_process_attributes(proc: psutil.Process) -> Dict[str, Any]:
    """
    Extract comprehensive attributes from a psutil.Process object.

    Args:
        proc: psutil.Process object

    Returns:
        Dictionary with process attributes
    """
    attrs = {
        'pid': None,
        'ppid': None,
        'name': None,
        'exe': None,
        'cmdline': None,
        'username': None,
        'status': None,
        'create_time': None,
        'cwd': None,
        'num_threads': None,
        'num_fds': None,
        'memory_percent': None,
        'cpu_percent': None,
        'connections': None,
        'open_files': None,
        'exe_hash': None,
        'exe_size': None,
    }

    # Get basic attributes with error handling
    try:
        attrs['pid'] = proc.pid
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

    try:
        attrs['ppid'] = proc.ppid()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

    try:
        attrs['name'] = proc.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

    try:
        attrs['exe'] = proc.exe()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

    try:
        cmdline = proc.cmdline()
        attrs['cmdline'] = ' '.join(cmdline) if cmdline else None
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

    try:
        attrs['username'] = proc.username()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

    try:
        attrs['status'] = proc.status()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

    try:
        create_time = proc.create_time()
        if create_time:
            attrs['create_time'] = datetime.fromtimestamp(create_time).isoformat()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

    try:
        attrs['cwd'] = proc.cwd()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

    try:
        attrs['num_threads'] = proc.num_threads()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

    # num_fds is Linux-only
    if platform.system() == 'Linux':
        try:
            attrs['num_fds'] = proc.num_fds()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    try:
        attrs['memory_percent'] = proc.memory_percent()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

    try:
        # cpu_percent needs interval=None for non-blocking call
        attrs['cpu_percent'] = proc.cpu_percent(interval=None)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

    try:
        connections = proc.connections()
        if connections:
            attrs['connections'] = [
                {
                    'fd': c.fd,
                    'family': str(c.family),
                    'type': str(c.type),
                    'laddr': f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                    'raddr': f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                    'status': c.status,
                }
                for c in connections
            ]
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

    try:
        open_files = proc.open_files()
        if open_files:
            attrs['open_files'] = [f.path for f in open_files]
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

    # Compute executable hash and size
    if attrs['exe']:
        attrs['exe_hash'] = compute_process_hash(attrs['exe'])
        try:
            attrs['exe_size'] = os.path.getsize(attrs['exe'])
        except (OSError, IOError):
            pass

    return attrs


def get_all_processes() -> List[Dict[str, Any]]:
    """
    Get all running processes with their attributes.

    Returns:
        List of dictionaries containing process attributes
    """
    processes = []

    for proc in psutil.process_iter():
        try:
            attrs = get_process_attributes(proc)
            if attrs.get('pid') is not None:
                processes.append(attrs)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Process may have terminated during iteration
            continue

    return processes


def compare_processes(
    baseline: List[Dict[str, Any]],
    current: List[Dict[str, Any]]
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Compare two process lists to find new, missing, and modified processes.

    Args:
        baseline: List of process dictionaries from baseline scan
        current: List of process dictionaries from current scan

    Returns:
        Dict with keys 'new', 'missing', 'modified' containing process lists.
        Modified processes include 'process' and 'changes' keys.
    """
    # Create lookup dictionaries by (name, exe) tuple for comparison
    # We use name+exe because PIDs change between scans
    def make_key(proc: Dict[str, Any]) -> Tuple[str, str]:
        return (proc.get('name') or '', proc.get('exe') or '')

    baseline_by_key = {}
    for proc in baseline:
        key = make_key(proc)
        if key not in baseline_by_key:
            baseline_by_key[key] = []
        baseline_by_key[key].append(proc)

    current_by_key = {}
    for proc in current:
        key = make_key(proc)
        if key not in current_by_key:
            current_by_key[key] = []
        current_by_key[key].append(proc)

    new_processes = []
    missing_processes = []
    modified_processes = []

    # Find new processes (in current but not in baseline)
    for key, procs in current_by_key.items():
        if key not in baseline_by_key:
            new_processes.extend(procs)
        else:
            # Check for modified (different exe_hash)
            baseline_procs = baseline_by_key[key]
            baseline_hashes = {p.get('exe_hash') for p in baseline_procs if p.get('exe_hash')}
            for curr_proc in procs:
                curr_hash = curr_proc.get('exe_hash')
                if curr_hash and curr_hash not in baseline_hashes:
                    # Find the baseline process to compare against
                    baseline_proc = baseline_procs[0] if baseline_procs else {}
                    changes = []
                    if baseline_proc.get('exe_hash') != curr_hash:
                        changes.append({
                            'field': 'exe_hash',
                            'old': baseline_proc.get('exe_hash'),
                            'new': curr_hash
                        })
                    if baseline_proc.get('exe_size') != curr_proc.get('exe_size'):
                        changes.append({
                            'field': 'exe_size',
                            'old': baseline_proc.get('exe_size'),
                            'new': curr_proc.get('exe_size')
                        })
                    modified_processes.append({
                        'process': curr_proc,
                        'changes': changes
                    })

    # Find missing processes (in baseline but not in current)
    for key, procs in baseline_by_key.items():
        if key not in current_by_key:
            missing_processes.extend(procs)

    return {
        'new': new_processes,
        'missing': missing_processes,
        'modified': modified_processes
    }

#!/usr/bin/env python3
"""
Process Anomaly Detection Script.

This script provides functionality for creating process baselines and detecting
anomalies by comparing current processes against a saved baseline.

Usage:
    python process_anomaly.py baseline              # Record current state
    python process_anomaly.py scan                  # Compare against baseline
    python process_anomaly.py scan -b baseline.json # Use custom baseline file
"""

import argparse
import json
import os
import platform
import socket
from datetime import datetime
from typing import Any, Dict, List, Optional

from ir_scripts.utils.colors import (
    Colors,
    print_anomaly,
    print_error,
    print_header,
    print_info,
    print_success,
    print_table_header,
    print_table_row,
    print_warning,
)
from ir_scripts.utils.process_utils import (
    compare_processes,
    get_all_processes,
    is_kernel_process,
)


# Default paths for baseline storage
DEFAULT_BASELINE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'baselines')
DEFAULT_BASELINE_FILE = 'process_baseline.json'


def get_baseline_path(custom_path: Optional[str] = None) -> str:
    """
    Get the path to the baseline file.

    Args:
        custom_path: Optional custom path to the baseline file

    Returns:
        Full path to the baseline file
    """
    if custom_path:
        return os.path.abspath(custom_path)

    # Ensure the default baseline directory exists
    os.makedirs(DEFAULT_BASELINE_DIR, exist_ok=True)
    return os.path.join(DEFAULT_BASELINE_DIR, DEFAULT_BASELINE_FILE)


def create_baseline(output_path: Optional[str] = None) -> str:
    """
    Create a baseline of all current processes and save to JSON.

    Args:
        output_path: Optional custom path to save the baseline

    Returns:
        Path to the created baseline file
    """
    baseline_path = get_baseline_path(output_path)

    print_info(f"Scanning all running processes...")

    # Get all running processes
    all_processes = get_all_processes()

    # Filter out kernel processes
    filtered_processes = []
    kernel_count = 0

    for proc in all_processes:
        name = proc.get('name') or ''
        pid = proc.get('pid') or 0

        if is_kernel_process(name, pid):
            kernel_count += 1
        else:
            filtered_processes.append(proc)

    print_info(f"Found {len(all_processes)} total processes")
    print_info(f"Filtered {kernel_count} kernel/system processes")
    print_info(f"Recording {len(filtered_processes)} user processes")

    # Create baseline structure
    baseline = {
        'timestamp': datetime.now().isoformat(),
        'hostname': socket.gethostname(),
        'platform': platform.system(),
        'processes': filtered_processes,
    }

    # Ensure output directory exists
    output_dir = os.path.dirname(baseline_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    # Write baseline to JSON file
    with open(baseline_path, 'w') as f:
        json.dump(baseline, f, indent=2, default=str)

    print_success(f"Baseline saved to: {baseline_path}")

    return baseline_path


def load_baseline(path: str) -> Dict[str, Any]:
    """
    Load a baseline from a JSON file.

    Args:
        path: Path to the baseline JSON file

    Returns:
        Dictionary containing baseline data

    Raises:
        FileNotFoundError: If the baseline file doesn't exist
        json.JSONDecodeError: If the file is not valid JSON
    """
    with open(path, 'r') as f:
        return json.load(f)


def run_anomaly_scan(baseline_path: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
    """
    Compare current processes against a baseline to detect anomalies.

    Args:
        baseline_path: Path to the baseline file

    Returns:
        Dictionary with 'new', 'missing', and 'modified' process lists
    """
    path = get_baseline_path(baseline_path)

    # Load baseline
    baseline_data = load_baseline(path)
    baseline_processes = baseline_data.get('processes', [])

    print_info(f"Loaded baseline from: {path}")
    print_info(f"Baseline created: {baseline_data.get('timestamp')}")
    print_info(f"Baseline hostname: {baseline_data.get('hostname')}")
    print_info(f"Baseline processes: {len(baseline_processes)}")

    # Get current processes (filtered)
    print_info("Scanning current processes...")
    all_current = get_all_processes()

    current_processes = []
    for proc in all_current:
        name = proc.get('name') or ''
        pid = proc.get('pid') or 0

        if not is_kernel_process(name, pid):
            current_processes.append(proc)

    print_info(f"Current processes: {len(current_processes)}")

    # Compare processes
    results = compare_processes(baseline_processes, current_processes)

    return results


def display_anomalies(results: Dict[str, List[Dict[str, Any]]], quiet: bool = False) -> None:
    """
    Display detected anomalies in a formatted, colored output.

    Args:
        results: Dictionary with 'new', 'missing', 'modified' keys
        quiet: If True, only show summary counts
    """
    new_procs = results.get('new', [])
    missing_procs = results.get('missing', [])
    modified_procs = results.get('modified', [])

    if quiet:
        print(f"New: {len(new_procs)}, Missing: {len(missing_procs)}, Modified: {len(modified_procs)}")
        return

    # Display NEW processes (RED - potential threats)
    if new_procs:
        print_header("NEW PROCESSES DETECTED")
        for proc in new_procs:
            print_anomaly(f"NEW PROCESS: {proc.get('name')}")
            print(f"{Colors.RED}  PID:         {proc.get('pid')}{Colors.RESET}")
            print(f"{Colors.RED}  Name:        {proc.get('name')}{Colors.RESET}")
            print(f"{Colors.RED}  PPID:        {proc.get('ppid')}{Colors.RESET}")
            print(f"{Colors.RED}  User:        {proc.get('username')}{Colors.RESET}")
            print(f"{Colors.RED}  Exe:         {proc.get('exe')}{Colors.RESET}")
            print(f"{Colors.RED}  Cmdline:     {proc.get('cmdline')}{Colors.RESET}")
            print(f"{Colors.RED}  Created:     {proc.get('create_time')}{Colors.RESET}")
            print(f"{Colors.RED}  CWD:         {proc.get('cwd')}{Colors.RESET}")
            print(f"{Colors.RED}  Hash:        {proc.get('exe_hash')}{Colors.RESET}")

            # Display network connections if any
            connections = proc.get('connections')
            if connections:
                print(f"{Colors.RED}  Network Connections:{Colors.RESET}")
                for conn in connections:
                    print(f"{Colors.RED}    - {conn.get('laddr')} -> {conn.get('raddr')} ({conn.get('status')}){Colors.RESET}")

            print()
    else:
        print_success("No new processes detected")

    # Display MISSING processes (YELLOW - services may have stopped)
    if missing_procs:
        print_header("MISSING PROCESSES")
        print_warning(f"Found {len(missing_procs)} processes from baseline that are no longer running:")
        print()
        print_table_header(['Name', 'PID', 'Exe'])
        for proc in missing_procs:
            name = str(proc.get('name', 'N/A'))[:15]
            pid = str(proc.get('pid', 'N/A'))[:15]
            exe = str(proc.get('exe', 'N/A'))[:15]
            print(f"{Colors.YELLOW}{name:^15} | {pid:^15} | {exe:^15}{Colors.RESET}")
        print()
    else:
        print_success("No missing processes detected")

    # Display MODIFIED processes (MAGENTA - binaries may have been changed)
    if modified_procs:
        print_header("MODIFIED PROCESSES")
        print_warning(f"Found {len(modified_procs)} processes with changed executables:")
        print()
        for item in modified_procs:
            proc = item.get('process', {})
            changes = item.get('changes', [])

            print(f"{Colors.MAGENTA}Process: {proc.get('name')} (PID: {proc.get('pid')}){Colors.RESET}")
            print(f"{Colors.MAGENTA}  Exe: {proc.get('exe')}{Colors.RESET}")
            for change in changes:
                print(f"{Colors.MAGENTA}  {change.get('field')}: {change.get('old')} -> {change.get('new')}{Colors.RESET}")
            print()
    else:
        print_success("No modified processes detected")

    # Summary footer
    print_header("SUMMARY")
    total_anomalies = len(new_procs) + len(missing_procs) + len(modified_procs)

    if total_anomalies == 0:
        print_success("No anomalies detected! System state matches baseline.")
    else:
        print_warning(f"Total anomalies detected: {total_anomalies}")
        if new_procs:
            print(f"  {Colors.RED}NEW:      {len(new_procs)}{Colors.RESET}")
        if missing_procs:
            print(f"  {Colors.YELLOW}MISSING:  {len(missing_procs)}{Colors.RESET}")
        if modified_procs:
            print(f"  {Colors.MAGENTA}MODIFIED: {len(modified_procs)}{Colors.RESET}")


def main() -> None:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description='Process Anomaly Detection Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s baseline                    Create a baseline of current processes
  %(prog)s baseline -o custom.json     Save baseline to custom file
  %(prog)s scan                        Scan for anomalies against default baseline
  %(prog)s scan -b custom.json         Scan using custom baseline file
  %(prog)s scan -q                     Quiet mode - only show summary
        """
    )

    parser.add_argument(
        'action',
        choices=['baseline', 'scan'],
        help='Action to perform: "baseline" to create baseline, "scan" to detect anomalies'
    )

    parser.add_argument(
        '-b', '--baseline',
        dest='baseline_file',
        help='Path to baseline file (for scan action)'
    )

    parser.add_argument(
        '-o', '--output',
        dest='output_file',
        help='Output path for baseline file (for baseline action)'
    )

    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Quiet mode - only show summary counts'
    )

    args = parser.parse_args()

    try:
        if args.action == 'baseline':
            print_header("CREATING PROCESS BASELINE")
            create_baseline(args.output_file)

        elif args.action == 'scan':
            print_header("PROCESS ANOMALY SCAN")
            baseline_path = args.baseline_file
            results = run_anomaly_scan(baseline_path)
            display_anomalies(results, args.quiet)

    except FileNotFoundError as e:
        print_error(f"Baseline file not found: {e}")
        print_info("Run 'process_anomaly.py baseline' first to create a baseline")
        exit(1)
    except json.JSONDecodeError as e:
        print_error(f"Invalid baseline file format: {e}")
        exit(1)
    except PermissionError as e:
        print_error(f"Permission denied: {e}")
        exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        exit(1)


if __name__ == '__main__':
    main()

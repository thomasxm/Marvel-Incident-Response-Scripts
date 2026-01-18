#!/usr/bin/env python3
"""
File Anomaly Detection Script.

This script provides functionality for creating file baselines and detecting
anomalies by comparing current filesystem state against a saved baseline.
It monitors suspicious directories commonly used by attackers for staging
malware, tools, or persistence mechanisms.

Usage:
    python file_anomaly.py baseline              # Record current state
    python file_anomaly.py scan                  # Compare against baseline
    python file_anomaly.py scan -b baseline.json # Use custom baseline file
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
    print_warning,
)
from ir_scripts.utils.file_utils import (
    LINUX_SUSPICIOUS_PATHS,
    WINDOWS_SUSPICIOUS_PATHS,
    scan_directory,
)


# Default paths for baseline storage
DEFAULT_BASELINE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'baselines')
DEFAULT_BASELINE_FILE = 'file_baseline.json'


def get_default_paths() -> List[str]:
    """
    Return platform-specific list of suspicious paths to scan.

    Returns:
        List of directory paths commonly used by attackers for the current platform.
    """
    if platform.system() == 'Windows':
        return WINDOWS_SUSPICIOUS_PATHS
    else:
        return LINUX_SUSPICIOUS_PATHS


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


def create_baseline(output_path: str, paths: Optional[List[str]] = None) -> str:
    """
    Create a baseline of all files in specified paths and save to JSON.

    Args:
        output_path: Path to save the baseline file.
        paths: Optional list of paths to scan. If None, uses platform defaults.

    Returns:
        Path to the created baseline file
    """
    if paths is None:
        paths = get_default_paths()

    # Filter to only existing directories
    existing_paths = [p for p in paths if os.path.isdir(p)]

    print_info(f"Scanning {len(existing_paths)} directories...")

    all_files = []
    for scan_path in existing_paths:
        print_info(f"  Scanning: {scan_path}")
        files = scan_directory(scan_path, recursive=True)
        all_files.extend(files)
        print_info(f"    Found {len(files)} files")

    print_info(f"Total files recorded: {len(all_files)}")

    # Create baseline structure
    baseline = {
        'timestamp': datetime.now().isoformat(),
        'hostname': socket.gethostname(),
        'platform': platform.system(),
        'paths_scanned': existing_paths,
        'total_files': len(all_files),
        'files': all_files,
    }

    # Ensure output directory exists
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    # Write baseline to JSON file
    with open(output_path, 'w') as f:
        json.dump(baseline, f, indent=2, default=str)

    print_success(f"Baseline saved to: {output_path}")

    return output_path


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


def compare_files(
    baseline_files: List[Dict[str, Any]],
    current_files: List[Dict[str, Any]]
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Compare baseline files with current files to detect anomalies.

    Args:
        baseline_files: List of file records from baseline
        current_files: List of file records from current scan

    Returns:
        Dictionary with 'new', 'modified', 'deleted' keys containing lists of files
    """
    # Create lookup dictionaries by path
    baseline_by_path = {f.get('path'): f for f in baseline_files if f.get('path')}
    current_by_path = {f.get('path'): f for f in current_files if f.get('path')}

    baseline_paths = set(baseline_by_path.keys())
    current_paths = set(current_by_path.keys())

    # Find new files
    new_paths = current_paths - baseline_paths
    new_files = [current_by_path[p] for p in new_paths]

    # Find deleted files
    deleted_paths = baseline_paths - current_paths
    deleted_files = [baseline_by_path[p] for p in deleted_paths]

    # Find modified files (same path but different hash or mtime)
    modified_files = []
    common_paths = baseline_paths & current_paths

    for path in common_paths:
        baseline_file = baseline_by_path[path]
        current_file = current_by_path[path]

        changes = []

        # Check hash change
        baseline_hash = baseline_file.get('hash')
        current_hash = current_file.get('hash')
        if baseline_hash and current_hash and baseline_hash != current_hash:
            changes.append({
                'field': 'hash',
                'old': baseline_hash,
                'new': current_hash,
            })

        # Check size change
        baseline_size = baseline_file.get('size')
        current_size = current_file.get('size')
        if baseline_size != current_size:
            changes.append({
                'field': 'size',
                'old': baseline_size,
                'new': current_size,
            })

        # Check mode change
        baseline_mode = baseline_file.get('mode')
        current_mode = current_file.get('mode')
        if baseline_mode != current_mode:
            changes.append({
                'field': 'mode',
                'old': baseline_file.get('mode_octal'),
                'new': current_file.get('mode_octal'),
            })

        if changes:
            modified_files.append({
                'file': current_file,
                'changes': changes,
            })

    return {
        'new': new_files,
        'modified': modified_files,
        'deleted': deleted_files,
    }


def run_anomaly_scan(
    baseline_path: str,
    paths: Optional[List[str]] = None
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Compare current filesystem state against a baseline to detect anomalies.

    Args:
        baseline_path: Path to the baseline file
        paths: Optional list of paths to scan. If None, uses paths from baseline.

    Returns:
        Dictionary with 'new', 'modified', 'deleted' file lists
    """
    # Load baseline
    baseline_data = load_baseline(baseline_path)
    baseline_files = baseline_data.get('files', [])

    print_info(f"Loaded baseline from: {baseline_path}")
    print_info(f"Baseline created: {baseline_data.get('timestamp')}")
    print_info(f"Baseline hostname: {baseline_data.get('hostname')}")
    print_info(f"Baseline files: {len(baseline_files)}")

    # Determine paths to scan
    if paths is None:
        paths = baseline_data.get('paths_scanned', get_default_paths())

    # Filter to only existing directories
    existing_paths = [p for p in paths if os.path.isdir(p)]

    # Scan current files
    print_info("Scanning current filesystem state...")
    current_files = []
    for scan_path in existing_paths:
        files = scan_directory(scan_path, recursive=True)
        current_files.extend(files)

    print_info(f"Current files: {len(current_files)}")

    # Compare files
    results = compare_files(baseline_files, current_files)

    return results


def display_anomalies(results: Dict[str, List[Dict[str, Any]]], quiet: bool = False) -> None:
    """
    Display detected file anomalies in a formatted, colored output.

    Args:
        results: Dictionary with 'new', 'modified', 'deleted' keys
        quiet: If True, only show summary counts
    """
    new_files = results.get('new', [])
    modified_files = results.get('modified', [])
    deleted_files = results.get('deleted', [])

    if quiet:
        print(f"New: {len(new_files)}, Modified: {len(modified_files)}, Deleted: {len(deleted_files)}")
        return

    # Display NEW files (RED - potential threats)
    if new_files:
        print_header("NEW FILES DETECTED")
        for file_info in new_files:
            # Check if this is a suspicious file
            is_suspicious = file_info.get('is_executable') or file_info.get('extension') in {'.sh', '.py', '.pl', '.rb', '.php', '.ps1', '.exe', '.dll', '.so', '.bin'}

            if is_suspicious:
                print_anomaly(f"NEW SUSPICIOUS FILE: {file_info.get('path')}")
            else:
                print(f"{Colors.RED}[!] NEW FILE: {file_info.get('path')}{Colors.RESET}")

            print(f"{Colors.RED}  Name:        {file_info.get('name')}{Colors.RESET}")
            print(f"{Colors.RED}  Size:        {file_info.get('size')} bytes{Colors.RESET}")
            print(f"{Colors.RED}  Mode:        {file_info.get('mode_octal')}{Colors.RESET}")
            print(f"{Colors.RED}  Executable:  {file_info.get('is_executable')}{Colors.RESET}")
            print(f"{Colors.RED}  Hidden:      {file_info.get('is_hidden')}{Colors.RESET}")
            print(f"{Colors.RED}  Hash:        {file_info.get('hash')}{Colors.RESET}")
            print()
    else:
        print_success("No new files detected")

    # Display MODIFIED files (MAGENTA - files may have been tampered with)
    if modified_files:
        print_header("MODIFIED FILES")
        print_warning(f"Found {len(modified_files)} files with changes:")
        print()
        for item in modified_files:
            file_info = item.get('file', {})
            changes = item.get('changes', [])

            print(f"{Colors.MAGENTA}File: {file_info.get('path')}{Colors.RESET}")
            for change in changes:
                print(f"{Colors.MAGENTA}  {change.get('field')}: {change.get('old')} -> {change.get('new')}{Colors.RESET}")
            print()
    else:
        print_success("No modified files detected")

    # Display DELETED files (YELLOW - files may have been removed)
    if deleted_files:
        print_header("DELETED FILES")
        print_warning(f"Found {len(deleted_files)} files from baseline that no longer exist:")
        print()
        for file_info in deleted_files:
            print(f"{Colors.YELLOW}  {file_info.get('path')}{Colors.RESET}")
        print()
    else:
        print_success("No deleted files detected")

    # Summary footer
    print_header("SUMMARY")
    total_anomalies = len(new_files) + len(modified_files) + len(deleted_files)

    if total_anomalies == 0:
        print_success("No anomalies detected! Filesystem state matches baseline.")
    else:
        print_warning(f"Total anomalies detected: {total_anomalies}")
        if new_files:
            print(f"  {Colors.RED}NEW:      {len(new_files)}{Colors.RESET}")
        if modified_files:
            print(f"  {Colors.MAGENTA}MODIFIED: {len(modified_files)}{Colors.RESET}")
        if deleted_files:
            print(f"  {Colors.YELLOW}DELETED:  {len(deleted_files)}{Colors.RESET}")


def main() -> None:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description='File Anomaly Detection Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s baseline                       Create a baseline of filesystem state
  %(prog)s baseline -o custom.json        Save baseline to custom file
  %(prog)s baseline -p /tmp /var/www      Scan specific paths
  %(prog)s scan                           Scan for anomalies against default baseline
  %(prog)s scan -b custom.json            Scan using custom baseline file
  %(prog)s scan -q                        Quiet mode - only show summary
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
        '-p', '--paths',
        dest='paths',
        nargs='+',
        help='Paths to scan (default: platform-specific suspicious directories)'
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
            print_header("CREATING FILE BASELINE")
            output_path = args.output_file or get_baseline_path()
            create_baseline(output_path, args.paths)

        elif args.action == 'scan':
            print_header("FILE ANOMALY SCAN")
            baseline_path = args.baseline_file or get_baseline_path()
            results = run_anomaly_scan(baseline_path, args.paths)
            display_anomalies(results, args.quiet)

    except FileNotFoundError as e:
        print_error(f"Baseline file not found: {e}")
        print_info("Run 'file_anomaly.py baseline' first to create a baseline")
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

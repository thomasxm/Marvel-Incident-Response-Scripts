#!/usr/bin/env python3
"""
Process Hunter - Threat Hunting Script for Process Analysis.

This script provides functionality for hunting suspicious processes using
regex pattern matching, suspicious indicator detection, and interactive
process termination capabilities.

Usage:
    python process_hunter.py 'pattern'                    # Search by name
    python process_hunter.py -c 'pattern'                 # Search in cmdline
    python process_hunter.py -k 'nc|ncat|netcat'          # Search and kill option
    python process_hunter.py -o results.json 'pattern'    # Output to file
"""

import argparse
import json
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

import psutil

from ir_scripts.utils.colors import (
    Colors,
    print_error,
    print_header,
    print_info,
    print_success,
    print_warning,
)
from ir_scripts.utils.process_utils import get_all_processes, get_process_attributes


# Suspicious path patterns (processes running from these locations)
# Note: Longer/more specific patterns first to avoid substring matches
# Using startswith() in check function for proper path matching
SUSPICIOUS_PATH_PREFIXES = [
    '/var/tmp/',
    '/var/tmp',
    '/dev/shm/',
    '/dev/shm',
    '/tmp/',
    '/tmp',
]

# Suspicious process names (commonly used for attacks)
SUSPICIOUS_NAMES = [
    'nc',
    'ncat',
    'netcat',
    'socat',
    'curl',
    'wget',
    'python',
    'perl',
    'ruby',
    'php',
]

# Suspicious command line patterns
SUSPICIOUS_CMDLINE_PATTERNS = [
    (r'/dev/tcp/', 'Reverse shell via /dev/tcp'),
    (r'bash\s*-i\b', 'Interactive bash shell (bash -i)'),
    (r'base64\s+(-d|--decode)', 'Base64 decode (potential obfuscation)'),
    (r'\beval\s*\(', 'Eval execution (potential code injection)'),
    (r'-e\s+/bin/(ba)?sh', 'Shell execution via -e flag'),
    (r'exec\s*\([^)]*\)', 'Exec execution (potential code injection)'),
    (r'mkfifo', 'Named pipe creation (potential reverse shell)'),
    (r'\|\s*(ba)?sh', 'Piping to shell (potential command injection)'),
]


def search_processes(pattern: str, search_cmdline: bool = True) -> List[Dict[str, Any]]:
    """
    Search for processes matching a regex pattern.

    Args:
        pattern: Regex pattern to match against process name (and cmdline if enabled)
        search_cmdline: If True, also search in command line

    Returns:
        List of matching process dictionaries
    """
    all_procs = get_all_processes()
    matches = []

    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        print_error(f"Invalid regex pattern: {e}")
        return []

    for proc in all_procs:
        name = proc.get('name') or ''
        cmdline = proc.get('cmdline') or ''

        # Check name
        if regex.search(name):
            matches.append(proc)
        elif search_cmdline and regex.search(cmdline):
            matches.append(proc)

    return matches


def check_suspicious(proc: Dict[str, Any]) -> List[str]:
    """
    Check a process for suspicious indicators.

    Args:
        proc: Process dictionary with name, exe, cmdline, etc.

    Returns:
        List of suspicious indicator strings
    """
    indicators = []

    name = proc.get('name') or ''
    exe = proc.get('exe') or ''
    cmdline = proc.get('cmdline') or ''

    # Check for suspicious paths (using startswith for proper path matching)
    for path in SUSPICIOUS_PATH_PREFIXES:
        if exe.startswith(path):
            indicators.append(f"Suspicious path: Running from {path}")
            break

    # Check for hidden directories (containing /.)
    if '/.' in exe:
        indicators.append("Hidden path: Running from hidden directory")

    # Check for suspicious process names
    name_lower = name.lower()
    for suspicious_name in SUSPICIOUS_NAMES:
        if name_lower == suspicious_name or name_lower == suspicious_name + '.exe':
            indicators.append(f"Suspicious name: {suspicious_name}")
            break

    # Check command line for suspicious patterns
    for pattern, description in SUSPICIOUS_CMDLINE_PATTERNS:
        if re.search(pattern, cmdline, re.IGNORECASE):
            indicators.append(f"Suspicious cmdline: {description}")

    return indicators


def format_process_details(proc: Dict[str, Any]) -> str:
    """
    Format process information for display.

    Args:
        proc: Process dictionary

    Returns:
        Formatted string with process details
    """
    lines = []
    lines.append(f"{'='*60}")
    lines.append(f"  PID:      {proc.get('pid', 'N/A')}")
    lines.append(f"  Name:     {proc.get('name', 'N/A')}")
    lines.append(f"  PPID:     {proc.get('ppid', 'N/A')}")
    lines.append(f"  User:     {proc.get('username', 'N/A')}")
    lines.append(f"  Exe:      {proc.get('exe', 'N/A')}")
    lines.append(f"  Cmdline:  {proc.get('cmdline', 'N/A')}")
    lines.append(f"  CWD:      {proc.get('cwd', 'N/A')}")
    lines.append(f"  Status:   {proc.get('status', 'N/A')}")
    lines.append(f"  Created:  {proc.get('create_time', 'N/A')}")

    # Show network connections if present
    connections = proc.get('connections')
    if connections:
        lines.append(f"  Connections:")
        for conn in connections:
            laddr = conn.get('laddr', 'N/A')
            raddr = conn.get('raddr', 'N/A')
            status = conn.get('status', 'N/A')
            lines.append(f"    - {laddr} -> {raddr} ({status})")

    # Show open files if present
    open_files = proc.get('open_files')
    if open_files:
        lines.append(f"  Open Files: {len(open_files)}")
        for f in open_files[:5]:  # Show first 5
            lines.append(f"    - {f}")
        if len(open_files) > 5:
            lines.append(f"    ... and {len(open_files) - 5} more")

    # Check for suspicious indicators
    indicators = check_suspicious(proc)
    if indicators:
        lines.append(f"  {Colors.RED}SUSPICIOUS INDICATORS:{Colors.RESET}")
        for indicator in indicators:
            lines.append(f"    {Colors.RED}- {indicator}{Colors.RESET}")

    lines.append(f"{'='*60}")

    return '\n'.join(lines)


def save_results(results: List[Dict[str, Any]], output_path: str) -> None:
    """
    Save search results to a JSON file.

    Args:
        results: List of process dictionaries
        output_path: Path to output file
    """
    try:
        # Ensure output directory exists
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        # Add timestamp and metadata
        output_data = results

        with open(output_path, 'w') as f:
            json.dump(output_data, f, indent=2, default=str)
    except PermissionError:
        print_error(f"Permission denied: Cannot write to {output_path}")
    except OSError as e:
        print_error(f"Error writing to file {output_path}: {e}")
    except Exception as e:
        print_error(f"Unexpected error while saving results: {e}")


def kill_process_interactive(proc: Dict[str, Any]) -> bool:
    """
    Interactively ask for confirmation and kill a process.

    Args:
        proc: Process dictionary with pid and name

    Returns:
        True if process was killed, False otherwise
    """
    pid = proc.get('pid')
    name = proc.get('name')

    print_warning(f"Kill process {name} (PID: {pid})?")
    response = input(f"{Colors.YELLOW}Confirm kill? [y/N]: {Colors.RESET}").strip().lower()

    if response == 'y':
        try:
            p = psutil.Process(pid)
            p.terminate()
            print_success(f"Process {name} (PID: {pid}) terminated")
            return True
        except psutil.NoSuchProcess:
            print_error(f"Process {pid} no longer exists")
            return False
        except psutil.AccessDenied:
            print_error(f"Access denied - cannot terminate process {pid}")
            return False
        except Exception as e:
            print_error(f"Error terminating process: {e}")
            return False
    else:
        print_info(f"Kill cancelled for {name} (PID: {pid})")
        return False


def create_parser() -> argparse.ArgumentParser:
    """
    Create the argument parser for the CLI.

    Returns:
        ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        description='Process Hunter - Threat Hunting Script',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 'bash'                    Search for processes named 'bash'
  %(prog)s -c 'nc.*4444'             Search cmdline for netcat on port 4444
  %(prog)s -c '/dev/tcp'             Find potential reverse shells
  %(prog)s -k 'nc|ncat|netcat'       Search and offer to kill netcat processes
  %(prog)s -o results.json 'python'  Save results to JSON file

Suspicious indicators checked:
  - Processes running from /tmp/, /dev/shm/, /var/tmp/
  - Processes in hidden directories (path contains /.)
  - Known risky tools: nc, ncat, netcat, socat, curl, wget, python, perl, ruby, php
  - Cmdline patterns: /dev/tcp, bash -i, base64 decode, eval, exec
        """
    )

    parser.add_argument(
        'pattern',
        help='Regex pattern to search for'
    )

    parser.add_argument(
        '-c', '--cmdline',
        action='store_true',
        default=False,
        help='Also search in process command line (default: name only)'
    )

    parser.add_argument(
        '-k', '--kill',
        action='store_true',
        default=False,
        help='Offer to kill matching processes interactively'
    )

    parser.add_argument(
        '-o', '--output',
        metavar='FILE',
        help='Save results to JSON file'
    )

    return parser


def main() -> None:
    """Main entry point for the CLI."""
    parser = create_parser()
    args = parser.parse_args()

    try:
        print_header("PROCESS HUNTER")
        print_info(f"Searching for pattern: {args.pattern}")

        if args.cmdline:
            print_info("Search scope: process name and command line")
        else:
            print_info("Search scope: process name only")

        # Search for processes
        results = search_processes(args.pattern, search_cmdline=args.cmdline)

        if not results:
            print_warning("No matching processes found")
            return

        print_success(f"Found {len(results)} matching process(es)")
        print()

        # Track suspicious processes
        suspicious_count = 0

        # Display results
        for proc in results:
            indicators = check_suspicious(proc)
            if indicators:
                suspicious_count += 1
                print(f"{Colors.RED}{format_process_details(proc)}{Colors.RESET}")
            else:
                print(format_process_details(proc))

            # Offer to kill if requested
            if args.kill:
                kill_process_interactive(proc)
                print()

        # Summary
        print_header("SUMMARY")
        print_info(f"Total matches: {len(results)}")
        if suspicious_count > 0:
            print_warning(f"Suspicious processes: {suspicious_count}")
        else:
            print_success("No suspicious indicators detected")

        # Save to file if requested
        if args.output:
            save_results(results, args.output)
            print_success(f"Results saved to: {args.output}")

    except KeyboardInterrupt:
        print()
        print_info("Search cancelled by user")
    except Exception as e:
        print_error(f"Error: {e}")
        exit(1)


if __name__ == '__main__':
    main()

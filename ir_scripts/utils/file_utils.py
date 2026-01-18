"""
File utilities for filesystem scanning and analysis.

This module provides file scanning functionality for the file anomaly detection
script. It scans directories commonly used by attackers for malicious payloads.
"""

import hashlib
import os
import stat
from typing import Dict, List, Optional, Any

# Maximum file size for hashing (50MB)
MAX_HASH_FILE_SIZE = 50 * 1024 * 1024

# Linux paths commonly used by attackers for staging malware/tools
LINUX_SUSPICIOUS_PATHS = [
    '/tmp',
    '/var/tmp',
    '/dev/shm',
    '/var/www',
    '/var/www/html',
    '/opt',
    '/home',
    '/root',
    '/var/spool/cron',
    '/var/spool/cron/crontabs',
    '/etc/cron.d',
    '/etc/cron.daily',
    '/etc/cron.hourly',
    '/etc/cron.weekly',
    '/etc/cron.monthly',
    '/var/log',
    '/usr/local/bin',
    '/usr/local/sbin',
    '/run/shm',
    '/var/run',
]

# Windows paths commonly used by attackers
WINDOWS_SUSPICIOUS_PATHS = [
    'C:\\Temp',
    'C:\\Windows\\Temp',
    'C:\\Windows\\Tasks',
    'C:\\Windows\\System32\\Tasks',
    'C:\\Users\\Public',
    'C:\\ProgramData',
    'C:\\Windows\\SysWOW64',
    'C:\\Windows\\System32\\spool\\drivers\\color',
    'C:\\Windows\\System32\\config\\systemprofile',
    'C:\\Windows\\System32\\wbem',
    'C:\\Windows\\Fonts',
    'C:\\inetpub\\wwwroot',
    'C:\\Windows\\System32\\WindowsPowerShell\\v1.0',
    'C:\\Windows\\Microsoft.NET',
    'C:\\Windows\\assembly',
    'C:\\Windows\\Debug',
]

# Suspicious file extensions commonly associated with malware/tools
SUSPICIOUS_EXTENSIONS = {
    # Executables
    '.exe',
    '.dll',
    '.sys',
    '.com',
    '.scr',
    '.pif',
    '.msi',
    '.msp',
    # Scripts
    '.ps1',
    '.psm1',
    '.psd1',
    '.bat',
    '.cmd',
    '.vbs',
    '.vbe',
    '.js',
    '.jse',
    '.wsh',
    '.wsf',
    '.sh',
    '.bash',
    '.zsh',
    '.py',
    '.pyw',
    '.pl',
    '.rb',
    '.php',
    # Linux executables
    '.elf',
    '.so',
    '.bin',
    '.out',
    # Archives (often used to stage payloads)
    '.zip',
    '.tar',
    '.gz',
    '.7z',
    '.rar',
    '.cab',
    # Documents with macros
    '.docm',
    '.xlsm',
    '.pptm',
    '.dotm',
    '.xlam',
    # Other suspicious
    '.hta',
    '.jar',
    '.class',
    '.war',
    '.lnk',
    '.url',
    '.iso',
    '.img',
    '.vhd',
    '.vhdx',
}


def compute_file_hash(path: str, algorithm: str = 'sha256') -> Optional[str]:
    """
    Compute hash of a file.

    Args:
        path: Path to the file to hash.
        algorithm: Hash algorithm to use (default: sha256).
                   Supported: md5, sha1, sha256, sha512.

    Returns:
        Hexadecimal hash string, or None if file cannot be read.
    """
    try:
        hash_func = hashlib.new(algorithm)
        with open(path, 'rb') as f:
            # Read in chunks to handle large files efficiently
            for chunk in iter(lambda: f.read(65536), b''):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except (IOError, OSError, ValueError):
        return None


def get_file_attributes(path: str) -> Dict[str, Any]:
    """
    Get detailed attributes for a file.

    Args:
        path: Absolute path to the file.

    Returns:
        Dictionary containing file attributes:
        - path: Absolute path
        - name: Filename
        - size: File size in bytes
        - mode: File mode (permissions) as integer
        - mode_octal: File mode as octal string (e.g., '0o755')
        - uid: Owner user ID
        - gid: Owner group ID
        - atime: Last access time (Unix timestamp)
        - mtime: Last modification time (Unix timestamp)
        - ctime: Creation/change time (Unix timestamp)
        - inode: Inode number
        - nlink: Number of hard links
        - is_executable: Whether file is executable
        - is_hidden: Whether file is hidden (starts with .)
        - extension: File extension (lowercase, with dot)
        - hash: SHA256 hash (None for files > 50MB or on error)
    """
    try:
        file_stat = os.stat(path)
    except (OSError, IOError):
        # Return minimal info if stat fails
        return {
            'path': path,
            'name': os.path.basename(path),
            'error': 'Cannot stat file',
        }

    name = os.path.basename(path)
    _, ext = os.path.splitext(name)

    # Check if file is executable
    is_executable = bool(file_stat.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))

    # Check if hidden (Unix-style: starts with dot)
    is_hidden = name.startswith('.')

    # Compute hash only for files under 50MB
    file_hash = None
    if file_stat.st_size <= MAX_HASH_FILE_SIZE:
        file_hash = compute_file_hash(path)

    return {
        'path': path,
        'name': name,
        'size': file_stat.st_size,
        'mode': file_stat.st_mode,
        'mode_octal': oct(file_stat.st_mode),
        'uid': file_stat.st_uid,
        'gid': file_stat.st_gid,
        'atime': file_stat.st_atime,
        'mtime': file_stat.st_mtime,
        'ctime': file_stat.st_ctime,
        'inode': file_stat.st_ino,
        'nlink': file_stat.st_nlink,
        'is_executable': is_executable,
        'is_hidden': is_hidden,
        'extension': ext.lower() if ext else '',
        'hash': file_hash,
    }


def scan_directory(
    path: str,
    recursive: bool = True,
    max_files: int = 10000
) -> List[Dict[str, Any]]:
    """
    Scan a directory and return file attributes for all files.

    Args:
        path: Directory path to scan.
        recursive: If True, scan subdirectories recursively.
        max_files: Maximum number of files to process (default: 10000).

    Returns:
        List of dictionaries containing file attributes for each file.
    """
    results = []
    file_count = 0

    if not os.path.isdir(path):
        return results

    try:
        if recursive:
            for root, dirs, files in os.walk(path):
                # Skip hidden directories
                dirs[:] = [d for d in dirs if not d.startswith('.')]

                for filename in files:
                    if file_count >= max_files:
                        return results

                    file_path = os.path.join(root, filename)
                    # Skip symlinks to avoid loops and potential security issues
                    if os.path.islink(file_path):
                        continue

                    attrs = get_file_attributes(file_path)
                    results.append(attrs)
                    file_count += 1
        else:
            for entry in os.listdir(path):
                if file_count >= max_files:
                    break

                file_path = os.path.join(path, entry)
                if os.path.isfile(file_path) and not os.path.islink(file_path):
                    attrs = get_file_attributes(file_path)
                    results.append(attrs)
                    file_count += 1
    except (OSError, PermissionError):
        # Return what we have so far if we hit permission issues
        pass

    return results

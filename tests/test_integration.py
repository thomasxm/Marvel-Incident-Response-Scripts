# tests/test_integration.py
"""Integration tests using synthetic fixtures for process anomaly detection."""

import json
import os
import unittest
from typing import Any, Dict, List

from ir_scripts.utils.process_utils import compare_processes


# Path to fixtures directory
FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures')


def load_fixture(filename: str) -> Dict[str, Any]:
    """Load a JSON fixture file."""
    filepath = os.path.join(FIXTURES_DIR, filename)
    with open(filepath, 'r') as f:
        return json.load(f)


class TestIntegrationProcessComparison(unittest.TestCase):
    """Integration tests for process comparison using synthetic fixtures."""

    @classmethod
    def setUpClass(cls):
        """Load fixtures once for all tests."""
        cls.baseline_data = load_fixture('synthetic_baseline.json')
        cls.current_data = load_fixture('synthetic_processes.json')
        cls.baseline_processes = cls.baseline_data['processes']
        cls.current_processes = cls.current_data['processes']
        cls.expected_new = cls.current_data['expected_new']
        cls.expected_missing = cls.current_data['expected_missing']
        cls.expected_modified = cls.current_data['expected_modified']

    def test_fixtures_load_correctly(self):
        """Test that fixtures can be loaded and have expected structure."""
        # Verify baseline structure
        self.assertIn('timestamp', self.baseline_data)
        self.assertIn('hostname', self.baseline_data)
        self.assertIn('platform', self.baseline_data)
        self.assertIn('processes', self.baseline_data)
        self.assertEqual(len(self.baseline_processes), 4)

        # Verify current data structure
        self.assertIn('description', self.current_data)
        self.assertIn('processes', self.current_data)
        self.assertIn('expected_new', self.current_data)
        self.assertIn('expected_missing', self.current_data)
        self.assertIn('expected_modified', self.current_data)
        self.assertEqual(len(self.current_processes), 5)

    def test_compare_processes_returns_expected_structure(self):
        """Test that compare_processes returns dict with new, missing, modified keys."""
        results = compare_processes(self.baseline_processes, self.current_processes)

        self.assertIsInstance(results, dict)
        self.assertIn('new', results)
        self.assertIn('missing', results)
        self.assertIn('modified', results)
        self.assertIsInstance(results['new'], list)
        self.assertIsInstance(results['missing'], list)
        self.assertIsInstance(results['modified'], list)

    def test_detects_new_processes(self):
        """Test that new processes (reverse_shell, cryptominer) are detected."""
        results = compare_processes(self.baseline_processes, self.current_processes)
        new_names = [proc.get('name') for proc in results['new']]

        self.assertEqual(len(results['new']), len(self.expected_new))
        for expected_name in self.expected_new:
            self.assertIn(expected_name, new_names,
                         f"Expected new process '{expected_name}' not detected")

    def test_detects_missing_processes(self):
        """Test that missing processes (postgres) are detected."""
        results = compare_processes(self.baseline_processes, self.current_processes)
        missing_names = [proc.get('name') for proc in results['missing']]

        self.assertEqual(len(results['missing']), len(self.expected_missing))
        for expected_name in self.expected_missing:
            self.assertIn(expected_name, missing_names,
                         f"Expected missing process '{expected_name}' not detected")

    def test_detects_modified_processes(self):
        """Test that modified processes (nginx with changed hash) are detected."""
        results = compare_processes(self.baseline_processes, self.current_processes)

        self.assertEqual(len(results['modified']), len(self.expected_modified))

        # Verify modified process structure
        for item in results['modified']:
            self.assertIn('process', item)
            self.assertIn('changes', item)
            proc = item['process']
            proc_name = proc.get('name')
            self.assertIn(proc_name, self.expected_modified,
                         f"Unexpected modified process '{proc_name}'")

    def test_modified_process_has_hash_change(self):
        """Test that modified nginx process shows the hash change."""
        results = compare_processes(self.baseline_processes, self.current_processes)

        # Find nginx in modified processes
        nginx_modified = None
        for item in results['modified']:
            if item['process'].get('name') == 'nginx':
                nginx_modified = item
                break

        self.assertIsNotNone(nginx_modified, "nginx not found in modified processes")

        # Verify hash change is recorded
        changes = nginx_modified['changes']
        hash_change = None
        for change in changes:
            if change.get('field') == 'exe_hash':
                hash_change = change
                break

        self.assertIsNotNone(hash_change, "exe_hash change not recorded")
        self.assertEqual(hash_change['old'], 'ghi789')
        self.assertEqual(hash_change['new'], 'modified_hash')


class TestSuspiciousIndicators(unittest.TestCase):
    """Tests for detecting suspicious indicators in malicious processes."""

    @classmethod
    def setUpClass(cls):
        """Load fixtures once for all tests."""
        cls.baseline_data = load_fixture('synthetic_baseline.json')
        cls.current_data = load_fixture('synthetic_processes.json')
        cls.baseline_processes = cls.baseline_data['processes']
        cls.current_processes = cls.current_data['processes']

    def test_reverse_shell_has_suspicious_cmdline(self):
        """Test that reverse_shell process has netcat command with attacker address."""
        results = compare_processes(self.baseline_processes, self.current_processes)

        # Find reverse_shell in new processes
        reverse_shell = None
        for proc in results['new']:
            if proc.get('name') == 'reverse_shell':
                reverse_shell = proc
                break

        self.assertIsNotNone(reverse_shell, "reverse_shell not found in new processes")

        # Check for suspicious indicators
        cmdline = reverse_shell.get('cmdline', '')
        self.assertIn('nc', cmdline, "netcat command not found in cmdline")
        self.assertIn('-e', cmdline, "-e flag (execute) not found in cmdline")
        self.assertIn('/bin/sh', cmdline, "shell spawn not found in cmdline")
        self.assertIn('attacker.com', cmdline, "attacker address not found in cmdline")

    def test_reverse_shell_in_tmp_directory(self):
        """Test that reverse_shell executable is in /tmp (suspicious location)."""
        results = compare_processes(self.baseline_processes, self.current_processes)

        reverse_shell = None
        for proc in results['new']:
            if proc.get('name') == 'reverse_shell':
                reverse_shell = proc
                break

        self.assertIsNotNone(reverse_shell, "reverse_shell not found")
        exe = reverse_shell.get('exe', '')
        self.assertTrue(exe.startswith('/tmp/'),
                       "reverse_shell exe not in /tmp directory")

    def test_cryptominer_in_hidden_dev_shm(self):
        """Test that cryptominer executable is in /dev/shm (suspicious location)."""
        results = compare_processes(self.baseline_processes, self.current_processes)

        cryptominer = None
        for proc in results['new']:
            if proc.get('name') == 'cryptominer':
                cryptominer = proc
                break

        self.assertIsNotNone(cryptominer, "cryptominer not found")
        exe = cryptominer.get('exe', '')
        self.assertTrue(exe.startswith('/dev/shm/'),
                       "cryptominer exe not in /dev/shm directory")
        self.assertIn('.hidden', exe,
                     "cryptominer not in hidden directory")

    def test_cryptominer_runs_as_nobody(self):
        """Test that cryptominer runs as 'nobody' user (suspicious)."""
        results = compare_processes(self.baseline_processes, self.current_processes)

        cryptominer = None
        for proc in results['new']:
            if proc.get('name') == 'cryptominer':
                cryptominer = proc
                break

        self.assertIsNotNone(cryptominer, "cryptominer not found")
        username = cryptominer.get('username', '')
        self.assertEqual(username, 'nobody',
                        "cryptominer not running as 'nobody' user")

    def test_reverse_shell_child_of_sshd(self):
        """Test that reverse_shell is a child of sshd (spawned from SSH session)."""
        results = compare_processes(self.baseline_processes, self.current_processes)

        reverse_shell = None
        for proc in results['new']:
            if proc.get('name') == 'reverse_shell':
                reverse_shell = proc
                break

        self.assertIsNotNone(reverse_shell, "reverse_shell not found")
        ppid = reverse_shell.get('ppid')
        self.assertEqual(ppid, 100, "reverse_shell PPID should be 100 (sshd)")

        # Verify the parent is sshd
        sshd = None
        for proc in self.current_processes:
            if proc.get('pid') == 100:
                sshd = proc
                break

        self.assertIsNotNone(sshd, "Parent sshd not found")
        self.assertEqual(sshd.get('name'), 'sshd',
                        "Parent process is not sshd")


class TestBaselineIntegrity(unittest.TestCase):
    """Tests for baseline data integrity checks."""

    @classmethod
    def setUpClass(cls):
        """Load fixtures once for all tests."""
        cls.baseline_data = load_fixture('synthetic_baseline.json')
        cls.current_data = load_fixture('synthetic_processes.json')

    def test_baseline_metadata_present(self):
        """Test that baseline has all required metadata fields."""
        self.assertEqual(self.baseline_data['timestamp'], '2026-01-15T10:00:00')
        self.assertEqual(self.baseline_data['hostname'], 'test-host')
        self.assertEqual(self.baseline_data['platform'], 'Linux')

    def test_all_baseline_processes_have_required_fields(self):
        """Test that all baseline processes have required fields."""
        required_fields = ['pid', 'name', 'exe', 'ppid', 'username', 'exe_hash']

        for proc in self.baseline_data['processes']:
            for field in required_fields:
                self.assertIn(field, proc,
                             f"Process {proc.get('name', 'unknown')} missing field '{field}'")

    def test_all_current_processes_have_required_fields(self):
        """Test that all current processes have required fields."""
        required_fields = ['pid', 'name', 'exe', 'ppid', 'username', 'exe_hash']

        for proc in self.current_data['processes']:
            for field in required_fields:
                self.assertIn(field, proc,
                             f"Process {proc.get('name', 'unknown')} missing field '{field}'")


if __name__ == '__main__':
    unittest.main()

# tests/test_process_anomaly.py
"""Tests for process anomaly detection script."""

import json
import os
import platform
import socket
import tempfile
import unittest
from datetime import datetime
from unittest.mock import patch, MagicMock

from ir_scripts.utils.process_utils import compare_processes


class TestProcessAnomaly(unittest.TestCase):
    """Tests for the process_anomaly module."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.baseline_file = os.path.join(self.temp_dir, 'test_baseline.json')

    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.baseline_file):
            os.remove(self.baseline_file)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_create_baseline_creates_file(self):
        """Test that create_baseline creates a JSON file."""
        from ir_scripts.process_anomaly import create_baseline

        create_baseline(self.baseline_file)
        self.assertTrue(os.path.exists(self.baseline_file))

        # Verify it's valid JSON
        with open(self.baseline_file, 'r') as f:
            data = json.load(f)
        self.assertIsInstance(data, dict)

    def test_baseline_has_required_structure(self):
        """Test that baseline file has required fields: timestamp, hostname, platform, processes."""
        from ir_scripts.process_anomaly import create_baseline

        create_baseline(self.baseline_file)

        with open(self.baseline_file, 'r') as f:
            data = json.load(f)

        # Check required keys
        self.assertIn('timestamp', data)
        self.assertIn('hostname', data)
        self.assertIn('platform', data)
        self.assertIn('processes', data)

        # Validate types
        self.assertIsInstance(data['timestamp'], str)
        self.assertIsInstance(data['hostname'], str)
        self.assertIsInstance(data['platform'], str)
        self.assertIsInstance(data['processes'], list)

        # Validate content
        self.assertEqual(data['hostname'], socket.gethostname())
        self.assertEqual(data['platform'], platform.system())

    def test_load_baseline_returns_dict(self):
        """Test that load_baseline returns a dictionary."""
        from ir_scripts.process_anomaly import create_baseline, load_baseline

        create_baseline(self.baseline_file)
        data = load_baseline(self.baseline_file)

        self.assertIsInstance(data, dict)
        self.assertIn('processes', data)

    def test_run_anomaly_scan_returns_results(self):
        """Test that run_anomaly_scan returns dict with 'new', 'missing', 'modified' keys."""
        from ir_scripts.process_anomaly import create_baseline, run_anomaly_scan

        create_baseline(self.baseline_file)
        results = run_anomaly_scan(self.baseline_file)

        self.assertIsInstance(results, dict)
        self.assertIn('new', results)
        self.assertIn('missing', results)
        self.assertIn('modified', results)

        # All values should be lists
        self.assertIsInstance(results['new'], list)
        self.assertIsInstance(results['missing'], list)
        self.assertIsInstance(results['modified'], list)


class TestSyntheticDataset(unittest.TestCase):
    """Tests using synthetic process data to verify detection logic."""

    def test_detect_new_process(self):
        """Test that new processes are detected when comparing process lists."""
        baseline = [
            {'name': 'bash', 'exe': '/bin/bash', 'pid': 100, 'exe_hash': 'abc123'},
            {'name': 'python', 'exe': '/usr/bin/python3', 'pid': 101, 'exe_hash': 'def456'},
        ]
        current = [
            {'name': 'bash', 'exe': '/bin/bash', 'pid': 200, 'exe_hash': 'abc123'},
            {'name': 'python', 'exe': '/usr/bin/python3', 'pid': 201, 'exe_hash': 'def456'},
            {'name': 'suspicious', 'exe': '/tmp/malware', 'pid': 666, 'exe_hash': 'evil999'},
        ]

        results = compare_processes(baseline, current)

        self.assertEqual(len(results['new']), 1)
        self.assertEqual(results['new'][0]['name'], 'suspicious')
        self.assertEqual(results['new'][0]['exe'], '/tmp/malware')

    def test_detect_missing_process(self):
        """Test that missing processes are detected when comparing process lists."""
        baseline = [
            {'name': 'bash', 'exe': '/bin/bash', 'pid': 100, 'exe_hash': 'abc123'},
            {'name': 'python', 'exe': '/usr/bin/python3', 'pid': 101, 'exe_hash': 'def456'},
            {'name': 'important_service', 'exe': '/usr/bin/important', 'pid': 102, 'exe_hash': 'ghi789'},
        ]
        current = [
            {'name': 'bash', 'exe': '/bin/bash', 'pid': 200, 'exe_hash': 'abc123'},
            {'name': 'python', 'exe': '/usr/bin/python3', 'pid': 201, 'exe_hash': 'def456'},
        ]

        results = compare_processes(baseline, current)

        self.assertEqual(len(results['missing']), 1)
        self.assertEqual(results['missing'][0]['name'], 'important_service')
        self.assertEqual(results['missing'][0]['exe'], '/usr/bin/important')


if __name__ == '__main__':
    unittest.main()

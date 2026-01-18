import unittest
import tempfile
import os
import json
from ir_scripts.file_anomaly import create_baseline, run_anomaly_scan

class TestFileAnomaly(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.baseline_path = os.path.join(self.temp_dir, 'file_baseline.json')
        self.test_file = os.path.join(self.temp_dir, 'test.txt')
        with open(self.test_file, 'w') as f:
            f.write('test')

    def test_create_baseline(self):
        create_baseline(self.baseline_path, [self.temp_dir])
        self.assertTrue(os.path.exists(self.baseline_path))

    def test_detect_new_file(self):
        create_baseline(self.baseline_path, [self.temp_dir])
        new_file = os.path.join(self.temp_dir, 'new_malware.sh')
        with open(new_file, 'w') as f:
            f.write('#!/bin/bash\nmalicious')
        results = run_anomaly_scan(self.baseline_path, [self.temp_dir])
        self.assertGreater(len(results.get('new', [])), 0)

if __name__ == '__main__':
    unittest.main()

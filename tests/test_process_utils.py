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
        import platform
        if platform.system() == 'Linux':
            self.assertTrue(is_kernel_process('kthreadd', 2))

    def test_compute_process_hash_returns_string(self):
        result = compute_process_hash('/bin/ls')
        self.assertIsInstance(result, (str, type(None)))

if __name__ == '__main__':
    unittest.main()

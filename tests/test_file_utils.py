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

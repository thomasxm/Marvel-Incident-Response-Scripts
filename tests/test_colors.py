# tests/test_colors.py
import unittest
from ir_scripts.utils.colors import Colors, print_header, print_success, print_warning, print_error, print_info

class TestColors(unittest.TestCase):
    def test_colors_class_has_attributes(self):
        self.assertTrue(hasattr(Colors, 'RED'))
        self.assertTrue(hasattr(Colors, 'GREEN'))
        self.assertTrue(hasattr(Colors, 'YELLOW'))
        self.assertTrue(hasattr(Colors, 'BLUE'))
        self.assertTrue(hasattr(Colors, 'RESET'))

    def test_print_functions_exist(self):
        # These should not raise
        print_header("Test")
        print_success("Test")
        print_warning("Test")
        print_error("Test")
        print_info("Test")

if __name__ == '__main__':
    unittest.main()

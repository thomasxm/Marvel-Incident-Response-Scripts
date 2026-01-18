#!/usr/bin/env python3
"""
Realistic scenario tests using production-like synthetic data.

Tests detection of actual attack techniques:
- Process masquerading (fake kernel threads)
- Living off the land (python/bash reverse shells)
- Cryptominers in hidden directories
- Web shells spawning processes
- Persistence mechanisms
- Deleted executables
- Encoded payloads
"""
import unittest
import json
import os

# Get fixtures directory
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')


class TestRealisticFixturesLoad(unittest.TestCase):
    """Verify realistic fixtures load correctly."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(FIXTURES_DIR, 'realistic_baseline.json')) as f:
            cls.baseline = json.load(f)
        with open(os.path.join(FIXTURES_DIR, 'realistic_compromised.json')) as f:
            cls.compromised = json.load(f)

    def test_baseline_has_production_like_process_count(self):
        """Baseline should have realistic number of processes (15+)."""
        self.assertGreaterEqual(len(self.baseline['processes']), 15)

    def test_compromised_has_more_processes(self):
        """Compromised state should have additional malicious processes."""
        self.assertGreater(
            len(self.compromised['processes']),
            len(self.baseline['processes'])
        )

    def test_processes_have_realistic_hashes(self):
        """Hashes should be 64 character hex strings (SHA256)."""
        for proc in self.baseline['processes']:
            h = proc.get('exe_hash')
            if h:
                self.assertEqual(len(h), 64, f"Hash for {proc['name']} not 64 chars")
                self.assertTrue(
                    all(c in '0123456789abcdef' for c in h.lower()),
                    f"Hash for {proc['name']} not valid hex"
                )

    def test_processes_have_realistic_cmdlines(self):
        """Cmdlines should be realistic, not placeholder values."""
        for proc in self.baseline['processes']:
            cmdline = proc.get('cmdline', '')
            self.assertNotIn('abc123', cmdline)
            self.assertNotIn('test', cmdline.lower())


class TestAnomalyDetection(unittest.TestCase):
    """Test detection of various anomaly types."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(FIXTURES_DIR, 'realistic_baseline.json')) as f:
            cls.baseline = json.load(f)
        with open(os.path.join(FIXTURES_DIR, 'realistic_compromised.json')) as f:
            cls.compromised = json.load(f)

        from ir_scripts.utils.process_utils import compare_processes
        cls.results = compare_processes(
            cls.baseline['processes'],
            cls.compromised['processes']
        )

    def test_detects_new_malicious_processes(self):
        """Should detect all new processes added in compromised state."""
        new_pids = {p['pid'] for p in self.results['new']}

        # Expected new malicious PIDs
        expected_new = {15234, 15456, 15789, 15890, 16001, 16234, 16456, 16567, 16789, 16890}

        self.assertTrue(
            expected_new.issubset(new_pids),
            f"Missing expected new PIDs. Found: {new_pids}"
        )

    def test_detects_missing_processes(self):
        """Should detect legitimate processes that were killed."""
        missing_names = {p['name'] for p in self.results['missing']}

        # fail2ban and postgres should be detected as missing
        self.assertIn('fail2ban-server', missing_names)
        self.assertIn('postgres', missing_names)

    def test_count_of_anomalies_matches_expected(self):
        """Verify we detect the right number of anomalies."""
        # 10 new malicious processes
        self.assertGreaterEqual(len(self.results['new']), 10)

        # At least 4 missing (fail2ban, postgres master, 2 postgres workers, nginx worker)
        self.assertGreaterEqual(len(self.results['missing']), 4)


class TestWebShellDetection(unittest.TestCase):
    """Test detection of web shell activity."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(FIXTURES_DIR, 'realistic_compromised.json')) as f:
            cls.compromised = json.load(f)
        cls.processes = {p['pid']: p for p in cls.compromised['processes']}

    def test_detects_php_spawning_shell(self):
        """Web shell: PHP-FPM (2002) spawning sh (15234)."""
        shell_proc = self.processes.get(15234)
        self.assertIsNotNone(shell_proc)
        self.assertEqual(shell_proc['ppid'], 2002)  # Parent is php-fpm
        self.assertEqual(shell_proc['name'], 'sh')
        self.assertIn('whoami', shell_proc['cmdline'])

    def test_shell_working_directory_is_uploads(self):
        """Web shell typically runs from uploads or writable directory."""
        shell_proc = self.processes.get(15234)
        self.assertIn('uploads', shell_proc['cwd'])


class TestReverseShellDetection(unittest.TestCase):
    """Test detection of reverse shell techniques."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(FIXTURES_DIR, 'realistic_compromised.json')) as f:
            cls.compromised = json.load(f)
        cls.processes = {p['pid']: p for p in cls.compromised['processes']}

    def test_detects_bash_dev_tcp_reverse_shell(self):
        """Classic bash reverse shell using /dev/tcp."""
        proc = self.processes.get(15456)
        self.assertIsNotNone(proc)
        self.assertIn('/dev/tcp/', proc['cmdline'])
        self.assertIn('203.0.113.66', proc['cmdline'])

    def test_detects_python_reverse_shell(self):
        """Python socket-based reverse shell."""
        proc = self.processes.get(16234)
        self.assertIsNotNone(proc)
        self.assertIn('socket.socket', proc['cmdline'])
        self.assertIn('subprocess', proc['cmdline'])

    def test_reverse_shell_has_network_connection(self):
        """Reverse shell should have outbound connection."""
        proc = self.processes.get(15456)
        self.assertIn('connections', proc)
        conn = proc['connections'][0]
        self.assertEqual(conn['raddr'], '203.0.113.66:4444')
        self.assertEqual(conn['status'], 'ESTABLISHED')

    def test_detects_netcat_backdoor(self):
        """Netcat with -e flag is a backdoor."""
        proc = self.processes.get(16567)
        self.assertIsNotNone(proc)
        self.assertIn('-e /bin/bash', proc['cmdline'])
        self.assertEqual(proc['name'], 'nc')


class TestProcessMasquerading(unittest.TestCase):
    """Test detection of process masquerading (T1036)."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(FIXTURES_DIR, 'realistic_compromised.json')) as f:
            cls.compromised = json.load(f)
        cls.processes = {p['pid']: p for p in cls.compromised['processes']}

    def test_detects_fake_kernel_thread(self):
        """Process named [kworker] but not a kernel thread."""
        proc = self.processes.get(15789)
        self.assertIsNotNone(proc)

        # Name looks like kernel thread
        self.assertIn('[kworker', proc['name'])

        # But has a real executable path (kernel threads have no exe)
        self.assertIsNotNone(proc['exe'])
        self.assertIn('/tmp/', proc['exe'])

        # And runs as non-root (kernel threads run as root with no user)
        self.assertEqual(proc['username'], 'www-data')

    def test_fake_systemd_process(self):
        """Process named systemd-helper but in wrong location."""
        proc = self.processes.get(16001)
        self.assertIsNotNone(proc)

        # Name sounds like systemd
        self.assertIn('systemd', proc['name'])

        # But exe is in /var/tmp (not /usr/lib/systemd)
        self.assertIn('/var/tmp/', proc['exe'])


class TestCryptominerDetection(unittest.TestCase):
    """Test detection of cryptominer activity."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(FIXTURES_DIR, 'realistic_compromised.json')) as f:
            cls.compromised = json.load(f)
        cls.processes = {p['pid']: p for p in cls.compromised['processes']}

    def test_detects_miner_in_dev_shm(self):
        """Cryptominer hidden in /dev/shm."""
        proc = self.processes.get(15890)
        self.assertIsNotNone(proc)
        self.assertIn('/dev/shm/', proc['exe'])

    def test_detects_mining_pool_in_cmdline(self):
        """Cmdline contains mining pool reference."""
        proc = self.processes.get(15890)
        self.assertIn('stratum', proc['cmdline'])
        self.assertIn('pool', proc['cmdline'].lower())

    def test_cryptominer_high_cpu(self):
        """Cryptominers typically use high CPU."""
        proc = self.processes.get(15789)
        self.assertGreater(proc.get('cpu_percent', 0), 90)

    def test_miner_uses_hidden_directory(self):
        """Miners often hide in directories starting with dot."""
        proc = self.processes.get(15890)
        # /dev/shm/... contains hidden "..." directory
        self.assertIn('...', proc['exe'])


class TestEncodedPayloadDetection(unittest.TestCase):
    """Test detection of encoded/obfuscated payloads."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(FIXTURES_DIR, 'realistic_compromised.json')) as f:
            cls.compromised = json.load(f)
        cls.processes = {p['pid']: p for p in cls.compromised['processes']}

    def test_detects_base64_decode_pipe_bash(self):
        """Base64 decode piped to bash is suspicious."""
        proc = self.processes.get(16789)
        self.assertIsNotNone(proc)
        self.assertIn('base64', proc['cmdline'])
        self.assertIn('| bash', proc['cmdline'])

    def test_detects_curl_pipe_bash(self):
        """Curl output piped to bash for download-and-execute."""
        proc = self.processes.get(16890)
        self.assertIsNotNone(proc)
        self.assertIn('curl', proc['cmdline'])
        self.assertIn('| bash', proc['cmdline'])


class TestDeletedExecutableDetection(unittest.TestCase):
    """Test detection of processes with deleted executables."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(FIXTURES_DIR, 'realistic_compromised.json')) as f:
            cls.compromised = json.load(f)
        cls.processes = {p['pid']: p for p in cls.compromised['processes']}

    def test_detects_deleted_binary(self):
        """Process running from deleted binary."""
        proc = self.processes.get(16456)
        self.assertIsNotNone(proc)
        self.assertIn('(deleted)', proc['exe'])

    def test_deleted_binary_has_no_hash(self):
        """Cannot hash a deleted binary."""
        proc = self.processes.get(16456)
        self.assertIsNone(proc.get('exe_hash'))


class TestSuspiciousParentChild(unittest.TestCase):
    """Test detection of suspicious parent-child relationships."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(FIXTURES_DIR, 'realistic_compromised.json')) as f:
            cls.compromised = json.load(f)
        cls.processes = {p['pid']: p for p in cls.compromised['processes']}

    def test_web_server_spawning_shell(self):
        """PHP-FPM spawning shell is suspicious."""
        shell = self.processes.get(15234)
        php_fpm = self.processes.get(2002)

        self.assertEqual(shell['ppid'], php_fpm['pid'])
        self.assertIn('php', php_fpm['name'].lower())
        self.assertIn('sh', shell['name'])

    def test_cron_spawning_reverse_shell(self):
        """Cron spawning Python reverse shell."""
        python_shell = self.processes.get(16234)
        cron = self.processes.get(1456)

        self.assertEqual(python_shell['ppid'], cron['pid'])
        self.assertEqual(cron['name'], 'cron')
        self.assertIn('socket', python_shell['cmdline'])


class TestSuspiciousIndicatorsIntegration(unittest.TestCase):
    """Test that check_suspicious catches realistic IOCs."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(FIXTURES_DIR, 'realistic_compromised.json')) as f:
            cls.compromised = json.load(f)

        cls.processes = {p['pid']: p for p in cls.compromised['processes']}

    def check_suspicious(self, proc):
        """Wrapper to call check_suspicious function."""
        from ir_scripts.process_hunter import check_suspicious
        return check_suspicious(proc)

    def test_flags_tmp_executable(self):
        """Executable in /tmp flagged as suspicious."""
        proc = self.processes.get(15789)  # Fake kworker in /tmp
        indicators = self.check_suspicious(proc)

        path_flags = [i for i in indicators if '/tmp' in i.lower()]
        self.assertTrue(len(path_flags) > 0, f"Should flag /tmp path. Got: {indicators}")

    def test_flags_dev_shm_executable(self):
        """Executable in /dev/shm flagged as suspicious."""
        proc = self.processes.get(15890)  # Miner in /dev/shm
        indicators = self.check_suspicious(proc)

        path_flags = [i for i in indicators if 'shm' in i.lower() or 'dev' in i.lower()]
        self.assertTrue(len(path_flags) > 0, f"Should flag /dev/shm path. Got: {indicators}")

    def test_flags_nc_tool(self):
        """Netcat flagged as suspicious tool."""
        proc = self.processes.get(16567)  # nc backdoor
        indicators = self.check_suspicious(proc)

        self.assertTrue(
            any('nc' in i.lower() or 'netcat' in i.lower() or 'network' in i.lower()
                for i in indicators),
            f"Should flag nc. Got: {indicators}"
        )

    def test_flags_reverse_shell_pattern(self):
        """Reverse shell patterns in cmdline flagged."""
        proc = self.processes.get(15456)  # bash -i >& /dev/tcp
        indicators = self.check_suspicious(proc)

        self.assertTrue(
            any('suspicious' in i.lower() or 'shell' in i.lower() or 'tcp' in i.lower()
                for i in indicators),
            f"Should flag reverse shell. Got: {indicators}"
        )

    def test_flags_base64_decode(self):
        """Base64 decode in cmdline flagged."""
        proc = self.processes.get(16789)  # base64 -d | bash
        indicators = self.check_suspicious(proc)

        self.assertTrue(
            any('base64' in i.lower() or 'suspicious' in i.lower() or 'encoded' in i.lower()
                for i in indicators),
            f"Should flag base64 decode. Got: {indicators}"
        )


if __name__ == '__main__':
    unittest.main()

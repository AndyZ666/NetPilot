"""Fixture-only independent Phase 5D integration checks. Never contacts devices."""
import importlib.util
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('netpilot_phase5d_test_app', ROOT / 'app.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Phase5DSafety(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='netpilot-phase5d-safety-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.inventory = self.root / 'devices.yml'
        self.generated = self.root / 'generated_configs'
        self.golden = self.root / 'golden_configs'
        self.generated.mkdir()
        self.golden.mkdir()
        self.data = {'network': {'defaults': {'template': 'templates/arista_ceos.j2'}}, 'devices': {
            'R1': {'hostname': 'R1', 'role': 'edge_router', 'vendor': 'Arista', 'platform': 'cEOSLab', 'management': {'ipv4': '192.0.2.1'}, 'template': 'templates/arista_ceos.j2'},
            'TEST-R10': {'hostname': 'TEST-R10', 'role': 'edge_router', 'vendor': 'Arista', 'platform': 'cEOSLab', 'management': {'ipv4': '192.0.2.10'}, 'template': 'templates/arista_ceos.j2'},
        }}
        self.inventory.write_text(yaml.safe_dump(self.data))
        for name, value in [('INVENTORY_PATH', self.inventory), ('GENERATED_CONFIGS_PATH', self.generated), ('GOLDEN_CONFIGS_PATH', self.golden)]:
            self.enterContext(patch.object(m, name, value, create=True))
        self.enterContext(patch.dict(os.environ, {}, clear=True))
        m.app.config.update(TESTING=True, SECRET_KEY='fixture-session-key')
        self.client = m.app.test_client()
        with self.client.session_transaction() as session:
            session['config_csrf'] = 'fixture-csrf'
        self.runner = self.enterContext(patch('subprocess.run'))
        self.runner.return_value = subprocess.CompletedProcess([], 1, stdout='', stderr='fixture-backend-diagnostic')

    def post(self, page, action, hostname='R1', **kwargs):
        return self.client.post(page, data={'csrf_token': 'fixture-csrf', 'action': action, 'hostname': hostname}, follow_redirects=True, **kwargs)

    def creds(self):
        self.enterContext(patch.dict(os.environ, {'NETPILOT_USERNAME': 'fixture-login', 'NETPILOT_PASSWORD': 'fixture-password'}))

    def snap(self, filename='R1_20260921_164113.cfg', text='hostname R1\ninterface Ethernet1\n description line one\n', host='R1'):
        folder = self.golden / host
        folder.mkdir(exist_ok=True)
        path = folder / filename
        path.write_text(text)
        return path

    def test_get_routes_never_run_backend(self):
        self.snap()
        for route in ['/configuration', '/configuration?hostname=R1', '/golden-configs', '/golden-configs?hostname=R1', '/golden-configs/R1/R1_20260921_164113.cfg']:
            with self.subTest(route=route):
                response = self.client.get(route)
                self.assertEqual(response.status_code, 200)
        self.runner.assert_not_called()

    def test_post_csrf_required(self):
        self.creds()
        for page, action in [('/configuration', 'generate'), ('/golden-configs', 'capture')]:
            response = self.client.post(page, data={'hostname': 'R1', 'action': action}, follow_redirects=True)
            self.assertLess(response.status_code, 500)
        self.runner.assert_not_called()

    def test_unknown_host_cannot_run_backend(self):
        self.creds()
        for page, action in [('/configuration', 'generate'), ('/golden-configs', 'capture')]:
            for hostname in ['UNKNOWN', '../R1', '--help', 'R1;bad', '']:
                with self.subTest(page=page, hostname=hostname):
                    response = self.post(page, action, hostname)
                    self.assertLess(response.status_code, 500)
        self.runner.assert_not_called()

    def test_missing_credentials(self):
        response = self.post('/golden-configs', 'capture')
        self.assertLess(response.status_code, 500)
        self.assertIn(b'Device credentials are not currently available', response.data)
        self.runner.assert_not_called()

    def test_backend_exception_text_never_leaks(self):
        self.creds()
        for page, action in [('/configuration', 'generate'), ('/golden-configs', 'capture')]:
            for exc in [OSError('fixture-secret-marker'), subprocess.TimeoutExpired('fixture-secret-marker', 1, output='fixture-secret-marker')]:
                self.runner.side_effect = exc
                response = self.post(page, action)
                self.assertLess(response.status_code, 500)
                self.assertNotIn(b'fixture-secret-marker', response.data)

    def test_failed_backend_output_never_leaks(self):
        self.creds()
        self.runner.return_value = subprocess.CompletedProcess([], 1, 'fixture-secret-marker', 'fixture-secret-marker')
        for page, action in [('/configuration', 'generate'), ('/golden-configs', 'capture')]:
            response = self.post(page, action)
            self.assertLess(response.status_code, 500)
            self.assertNotIn(b'fixture-secret-marker', response.data)

    def test_success_exit_without_output_is_handled(self):
        self.creds()
        self.runner.return_value = subprocess.CompletedProcess([], 0, '', '')
        for page, action in [('/configuration', 'generate'), ('/golden-configs', 'capture')]:
            response = self.post(page, action)
            self.assertLess(response.status_code, 500)

    def test_successful_single_generation_uses_existing_cli(self):
        def run(command, **kwargs):
            self.assertIsInstance(command, list)
            self.assertEqual(command[2], str(ROOT / 'render_configs.py'))
            self.assertEqual(command[3], 'R1')
            self.assertFalse(kwargs['shell'])
            self.assertTrue(kwargs['capture_output'])
            self.assertGreater(kwargs['timeout'], 0)
            self.assertNotIn('save_golden_configs.py', ' '.join(command))
            target = self.generated / 'R1.cfg'
            target.write_text('hostname R1\ninterface Ethernet1\n description fixture-desired-output\n')
            return subprocess.CompletedProcess(command, 0, f'[OK] R1 -> {target}\n', '')
        self.runner.side_effect = run
        response = self.post('/configuration', 'generate')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Configuration generated successfully.', response.data)
        self.assertIn(b'fixture-desired-output', response.data)
        self.assertIn('no-store', response.headers.get('Cache-Control', ''))
        self.runner.assert_called_once()

    def test_successful_single_capture_uses_existing_cli(self):
        self.creds()
        def run(command, **kwargs):
            self.assertEqual(command, [m.sys.executable, '-u', str(ROOT / 'save_golden_configs.py'), 'R1'])
            self.assertFalse(kwargs['shell'])
            self.assertNotIn('fixture-password', ' '.join(command))
            target = self.snap()
            return subprocess.CompletedProcess(command, 0, f'[OK] R1 -> {target}\n', '')
        self.runner.side_effect = run
        response = self.post('/golden-configs', 'capture')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Golden Config captured successfully.', response.data)
        self.assertIn(b'R1_20260921_164113.cfg', response.data)
        self.assertNotIn(b'fixture-password', response.data)
        self.runner.assert_called_once()

    def test_all_capture_reports_partial_success(self):
        self.creds()
        def run(command, **kwargs):
            self.assertEqual(command, [m.sys.executable, '-u', str(ROOT / 'save_golden_configs.py')])
            target = self.snap()
            return subprocess.CompletedProcess(command, 1, f'[OK] R1 -> {target}\n[FAIL] TEST-R10: fixture-secret-marker\n', '')
        self.runner.side_effect = run
        response = self.post('/golden-configs', 'capture_all', '')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Golden Config captured successfully.', response.data)
        self.assertIn(b'Golden Config capture failed', response.data)
        self.assertIn(b'TEST-R10', response.data)
        self.assertNotIn(b'fixture-secret-marker', response.data)
        self.runner.assert_called_once()

    def test_timeout_preserves_completed_device_success(self):
        self.creds()
        def run(command, **kwargs):
            target = self.snap()
            raise subprocess.TimeoutExpired(command, 1, output=f'[OK] R1 -> {target}\n'.encode())
        self.runner.side_effect = run
        response = self.post('/golden-configs', 'capture_all', '')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Golden Config captured successfully.', response.data)
        self.assertIn(b'timed out', response.data)

    def test_generate_all_stops_failure_without_claiming_remaining_success(self):
        def run(command, **kwargs):
            self.assertNotIn('R1', command)
            target = self.generated / 'R1.cfg'
            target.write_text('hostname R1\n')
            return subprocess.CompletedProcess(command, 1, f'[OK] R1 -> {target}\n', '')
        self.runner.side_effect = run
        response = self.post('/configuration', 'generate_all', '')
        self.assertIn(b'Configuration generated successfully.', response.data)
        self.assertIn(b'Configuration generation failed', response.data)
        self.assertIn(b'TEST-R10', response.data)

    def test_stale_outputs_never_count_as_new_success(self):
        self.creds()
        desired = self.generated / 'R1.cfg'
        desired.write_text('hostname R1\n')
        golden = self.snap()
        for page, action, target in [('/configuration', 'generate', desired), ('/golden-configs', 'capture', golden)]:
            self.runner.return_value = subprocess.CompletedProcess([], 0, f'[OK] R1 -> {target}\n', '')
            response = self.post(page, action)
            self.assertEqual(response.status_code, 200)
            self.assertNotIn(b'Configuration generated successfully.', response.data)
            self.assertNotIn(b'Golden Config captured successfully.', response.data)
            self.assertIn(b'failed', response.data)

    def test_host_output_symlinks_prevent_backend_writes(self):
        outside = self.root / 'outside.cfg'
        outside.write_text('fixture-outside-marker')
        (self.generated / 'R1.cfg').symlink_to(outside)
        response = self.post('/configuration', 'generate')
        self.assertLess(response.status_code, 500)
        self.runner.assert_not_called()
        self.assertEqual(outside.read_text(), 'fixture-outside-marker')

    def test_hardlinked_snapshot_is_not_served(self):
        original = self.snap()
        os.link(original, self.root / 'outside.cfg')
        response = self.client.get('/golden-configs/R1/' + original.name)
        self.assertEqual(response.status_code, 404)

    def test_history_is_newest_first_and_filters_unrecognized_files(self):
        self.snap('R1_20260920_010101.cfg')
        self.snap('R1_20260921_010101.cfg')
        self.snap('R1_20269999_010101.cfg')
        self.snap('other.cfg')
        response = self.client.get('/golden-configs?hostname=R1')
        self.assertEqual(response.status_code, 200)
        self.assertLess(response.data.index(b'R1_20260921_010101.cfg'), response.data.index(b'R1_20260920_010101.cfg'))
        self.assertNotIn(b'R1_20269999_010101.cfg', response.data)
        self.assertNotIn(b'other.cfg', response.data)

    def test_symlink_loop_is_rejected_without_crashing(self):
        target = self.generated / 'R1.cfg'
        target.symlink_to(target)
        for response in [self.client.get('/configuration?hostname=R1'), self.post('/configuration', 'generate')]:
            self.assertLess(response.status_code, 500)
        folder = self.golden / 'R1'
        folder.symlink_to(folder, target_is_directory=True)
        response = self.client.get('/golden-configs/R1/R1_20260921_164113.cfg')
        self.assertEqual(response.status_code, 404)
        self.runner.assert_not_called()

    def test_routing_communities_remain_visible(self):
        snapshot = self.snap(text="""hostname R1
router bgp 65001
 neighbor 192.0.2.2 send-community
 neighbor 192.0.2.3 send-community extended
route-map EXPORT permit 10
 set community 65001:100 additive
snmp-server community fixture-snmp-marker ro
""")
        response = self.client.get('/golden-configs/R1/' + snapshot.name)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'neighbor 192.0.2.2 send-community', response.data)
        self.assertIn(b'neighbor 192.0.2.3 send-community extended', response.data)
        self.assertIn(b'set community 65001:100 additive', response.data)
        self.assertNotIn(b'fixture-snmp-marker', response.data)

    def test_snapshot_escaping_redaction_and_no_cache(self):
        text = '''hostname R1
interface Ethernet1
 description <script>alert("fixture")</script>
username fixture-login privilege 15 secret fixture-secret-marker
snmp-server community fixture-snmp-marker ro
enable secret fixture-enable-marker
router bgp 65001
 neighbor 192.0.2.2 password fixture-bgp-marker
-----BEGIN RSA PRIVATE KEY-----
fixture-private-key-marker
-----END RSA PRIVATE KEY-----
interface Ethernet2
 description remains-visible
'''
        snapshot = self.snap(text=text)
        response = self.client.get('/golden-configs/R1/' + snapshot.name)
        self.assertEqual(response.status_code, 200)
        for marker in [b'fixture-login', b'fixture-secret-marker', b'fixture-snmp-marker', b'fixture-enable-marker', b'fixture-bgp-marker', b'fixture-private-key-marker']:
            self.assertNotIn(marker, response.data)
        self.assertNotIn(b'<script>alert', response.data)
        self.assertIn(b'&lt;script&gt;', response.data)
        self.assertIn(b'remains-visible', response.data)
        self.assertIn('no-store', response.headers.get('Cache-Control', ''))
        self.assertEqual(snapshot.read_text(), text)

    def test_invalid_and_missing_snapshots(self):
        for route in ['/golden-configs/UNKNOWN/R1_20260921_164113.cfg', '/golden-configs/R1/missing.cfg', '/golden-configs/R1/../../app.py', '/golden-configs/R1/%2e%2e%2fapp.py', '/golden-configs/R1/R1_20260921_164113.cfg']:
            response = self.client.get(route)
            self.assertIn(response.status_code, [400, 404])
        self.runner.assert_not_called()

    def test_symlink_snapshot_is_not_served(self):
        folder = self.golden / 'R1'
        folder.mkdir()
        outside = self.root / 'outside.cfg'
        outside.write_text('fixture-outside-marker')
        (folder / 'R1_20260921_164113.cfg').symlink_to(outside)
        response = self.client.get('/golden-configs/R1/R1_20260921_164113.cfg')
        self.assertIn(response.status_code, [400, 404])
        self.assertNotIn(b'fixture-outside-marker', response.data)

    def test_symlink_host_directory_is_not_served(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / 'R1_20260921_164113.cfg').write_text('fixture-outside-marker')
        (self.golden / 'R1').symlink_to(outside, target_is_directory=True)
        response = self.client.get('/golden-configs/R1/R1_20260921_164113.cfg')
        self.assertIn(response.status_code, [400, 404])
        self.assertNotIn(b'fixture-outside-marker', response.data)


if __name__ == '__main__':
    unittest.main(verbosity=2)

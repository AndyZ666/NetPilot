"""Offline credential integration checks; no Vault access or live connections."""

import base64
import importlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import challenge_maintenance as maintenance
import save_golden_configs as golden
from security import credential_provider


class CredentialIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.provider = self.enterContext(patch.object(
            credential_provider, "get_credentials",
            return_value=("fixture-user", "fixture-password")))
        self.output = self.enterContext(patch("sys.stdout", new_callable=io.StringIO))
        self.enterContext(patch.dict(os.environ, {}, clear=True))

    def test_golden_fetches_once_and_passes_pair_to_each_existing_collector(self):
        devices = {name: {"management": {"ipv4": address}} for name, address in
                   (("R1", "192.0.2.1"), ("R2", "192.0.2.2"))}
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(golden, "OUTPUT_DIR", Path(directory)), \
                patch.object(golden, "load_inventory", return_value={"devices": devices}), \
                patch.object(golden, "save_golden_config") as save, \
                patch("sys.argv", ["save_golden_configs.py"]):
            self.assertEqual(golden.main(), 0)
        self.provider.assert_called_once_with()
        self.assertEqual(save.call_count, 2)
        for call in save.call_args_list:
            self.assertEqual(call.args[2:4], ("fixture-user", "fixture-password"))
        self.assertNotIn("fixture-password", self.output.getvalue())

    def test_golden_vault_failure_prevents_collection_or_output_creation(self):
        self.provider.side_effect = RuntimeError("fixture-vault-secret")
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(golden, "OUTPUT_DIR", Path(directory) / "not-created"), \
                patch.object(golden, "ConnectHandler") as connect, \
                patch.object(golden, "load_inventory") as load, \
                patch.dict(os.environ, {"NETPILOT_USERNAME": "stale", "NETPILOT_PASSWORD": "stale"}):
            self.assertEqual(golden.main(), 1)
            self.assertFalse(golden.OUTPUT_DIR.exists())
        connect.assert_not_called()
        load.assert_not_called()
        self.assertIn("1Password", self.output.getvalue())
        self.assertNotIn("fixture-vault-secret", self.output.getvalue())

    def test_golden_network_failure_is_sanitized(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(golden, "OUTPUT_DIR", Path(directory)), \
                patch.object(golden, "load_inventory", return_value={"devices": {"R1": {}}}), \
                patch.object(golden, "save_golden_config", side_effect=RuntimeError("fixture-password")), \
                patch("sys.argv", ["save_golden_configs.py", "R1"]):
            self.assertEqual(golden.main(), 1)
        self.assertNotIn("fixture-password", self.output.getvalue())

    def test_golden_retains_netmiko_connection_interface(self):
        with patch.object(golden, "ConnectHandler") as connect:
            connection = connect.return_value
            connection.check_enable_mode.return_value = True
            connection.send_command.return_value = "hostname R1\nend\n"
            self.assertEqual(golden.get_running_config(
                "R1", {"management": {"ipv4": "192.0.2.1"}},
                "fixture-user", "fixture-password"), "hostname R1\nend\n")
            self.assertEqual(connect.call_args.kwargs["username"], "fixture-user")
            self.assertEqual(connect.call_args.kwargs["password"], "fixture-password")
            self.assertEqual(connect.call_args.kwargs["secret"], "fixture-password")
            connection.disconnect.assert_called_once_with()
        self.assertNotIn("fixture-password", self.output.getvalue())

    def test_maintenance_uses_provider_for_eapi_authentication(self):
        with patch.object(maintenance.urllib.request, "build_opener") as build:
            api = maintenance.EAPI({"devices": {}})
        self.provider.assert_called_once_with()
        build.return_value.open.assert_not_called()
        expected = "Basic " + base64.b64encode(b"fixture-user:fixture-password").decode()
        self.assertEqual(api.authorization, expected)
        self.assertEqual(self.output.getvalue(), "")

    def test_maintenance_provider_failure_does_not_create_network_client(self):
        self.provider.side_effect = RuntimeError("fixture-vault-secret")
        with patch.object(maintenance.urllib.request, "build_opener") as build:
            with self.assertRaises(maintenance.MaintenanceError) as raised:
                maintenance.EAPI({})
        build.assert_not_called()
        self.assertIn("1Password", str(raised.exception))
        self.assertNotIn("fixture-vault-secret", str(raised.exception))
        self.assertTrue(raised.exception.__suppress_context__)

    def test_maintenance_status_does_not_need_vault(self):
        with patch.object(maintenance.Maintenance, "status") as status:
            self.assertEqual(maintenance.main(["status"]), 0)
        status.assert_called_once_with()
        self.provider.assert_not_called()

    def test_live_smoke_modules_are_import_safe(self):
        with patch("netmiko.ConnectHandler") as connect:
            for name in ("security.test_r1_vault", "security.test_all_vault"):
                importlib.reload(importlib.import_module(name))
        self.provider.assert_not_called()
        connect.assert_not_called()
        self.assertEqual(self.output.getvalue(), "")


class VaultDiagnosticTests(unittest.TestCase):
    """Explicit diagnostic decisions with synthetic credentials and SSH sessions."""

    def setUp(self):
        self.output = self.enterContext(patch('sys.stdout', new_callable=io.StringIO))
        for target in ('socket.socket.connect', 'socket.create_connection', 'subprocess.Popen',
                       'security.credential_provider._read_token', 'security.credential_provider._run_op'):
            self.enterContext(patch(target, side_effect=AssertionError('External operation forbidden')))
        with patch('security.credential_provider.get_credentials', side_effect=AssertionError('Import must be inert')), \
                patch('netmiko.ConnectHandler', side_effect=AssertionError('Import must be inert')):
            self.all_devices = importlib.import_module('security.test_all_vault')
            self.r1 = importlib.import_module('security.test_r1_vault')
        self.provider = MagicMock(return_value=('fixture-user', 'fixture-password'))
        self.connect = MagicMock()
        for module in (self.all_devices, self.r1):
            self.enterContext(patch.object(module, 'get_credentials', self.provider))
            self.enterContext(patch.object(module, 'ConnectHandler', self.connect))
        self.enterContext(patch.object(self.all_devices, 'DEVICES', {'R1': '192.0.2.1', 'S1': '192.0.2.2', 'S2': '192.0.2.3'}))

    def test_fleet_authentication_counts_success_mismatch_and_connection_failure(self):
        first, second = MagicMock(), MagicMock()
        first.__enter__.return_value.send_command.return_value = 'Hostname: R1\nFQDN: R1.example.test'
        second.__enter__.return_value.send_command.return_value = 'Hostname: S9'
        self.connect.side_effect = [first, second, TimeoutError('fixture-password private-server-response')]
        self.assertIsNone(self.all_devices.main())
        self.provider.assert_called_once_with()
        self.assertEqual([call.kwargs['host'] for call in self.connect.call_args_list],
                         ['192.0.2.1', '192.0.2.2', '192.0.2.3'])
        for context in (first, second):
            context.__enter__.return_value.send_command.assert_called_once_with('show hostname')
            context.__exit__.assert_called_once()
        text = self.output.getvalue()
        self.assertIn('Successful: 1', text)
        self.assertIn('Failed: 2', text)
        self.assertIn('Total: 3', text)
        self.assertNotIn('fixture-password', text)
        self.assertNotIn('private-server-response', text)

    def test_fleet_hostname_identity_must_not_accept_a_prefix_match(self):
        with patch.object(self.all_devices, 'DEVICES', {'R1': '192.0.2.1'}):
            self.connect.return_value.__enter__.return_value.send_command.return_value = 'Hostname: R10\nFQDN: R10.example.test'
            self.all_devices.main()
        self.assertIn('[FAIL] R1: Hostname mismatch', self.output.getvalue())
        self.assertIn('Successful: 0', self.output.getvalue())
        self.assertIn('Failed: 1', self.output.getvalue())

    def test_fleet_provider_failure_does_not_attempt_ssh_or_leak_exception(self):
        self.provider.side_effect = RuntimeError('fixture-password private-server-response')
        self.assertIsNone(self.all_devices.main())
        self.connect.assert_not_called()
        self.assertIn('[FAIL] Unable to retrieve credentials', self.output.getvalue())
        self.assertNotIn('fixture-password', self.output.getvalue())
        self.assertNotIn('private-server-response', self.output.getvalue())

    def test_r1_diagnostic_uses_only_hostname_read_and_returns_success(self):
        connection = self.connect.return_value.__enter__.return_value
        connection.send_command.return_value = 'Hostname: R1'
        self.assertEqual(self.r1.main(), 0)
        self.connect.assert_called_once_with(device_type='arista_eos', host='172.20.20.13',
            username='fixture-user', password='fixture-password', conn_timeout=10, auth_timeout=10)
        connection.send_command.assert_called_once_with('show hostname')
        connection.send_config_set.assert_not_called()
        self.connect.return_value.__exit__.assert_called_once()

    def test_r1_command_failure_returns_failure_and_closes_connection_without_secret(self):
        connection = self.connect.return_value.__enter__.return_value
        connection.send_command.side_effect = TimeoutError('fixture-password private-server-response')
        self.assertEqual(self.r1.main(), 1)
        self.connect.return_value.__exit__.assert_called_once()
        self.assertIn('[FAIL] Credential retrieval or SSH test failed', self.output.getvalue())
        self.assertNotIn('fixture-password', self.output.getvalue())
        self.assertNotIn('private-server-response', self.output.getvalue())


if __name__ == "__main__":
    unittest.main()

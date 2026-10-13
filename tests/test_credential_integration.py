"""Offline credential integration checks; no Vault access or live connections."""

import base64
import importlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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


if __name__ == "__main__":
    unittest.main()

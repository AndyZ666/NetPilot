"""Management scripts use mocked provider credentials and device connections."""

from contextlib import ExitStack, redirect_stdout
import importlib
import io
from pathlib import Path
import runpy
import sys
from types import ModuleType
import unittest
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_NAMES = ("configure_gnmi", "configure_netconf", "netconf_edit", "netconf_s3_test")
FIXTURE_CREDENTIALS = ("fixture-provider-user", "fixture-provider-password")
DEVICE = {"name": "S3", "ip": "192.0.2.3", "secret": "fixture-enable-secret"}
PRIVATE_ERROR = " ".join(FIXTURE_CREDENTIALS) + " fixture-enable-secret private-server-response"


class ManagementCredentialTests(unittest.TestCase):
    def setUp(self):
        ncclient, manager = ModuleType("ncclient"), ModuleType("ncclient.manager")
        manager.connect = MagicMock()
        ncclient.manager = manager
        optional_module = patch.dict(sys.modules, {"ncclient": ncclient, "ncclient.manager": manager})
        optional_module.start()
        self.addCleanup(optional_module.stop)
        with patch("security.credential_provider.get_credentials", side_effect=AssertionError("Provider called during import")), \
                patch("ncclient.manager.connect", side_effect=AssertionError("Network called during import")), \
                patch("socket.create_connection", side_effect=AssertionError("Socket called during import")), \
                patch("getpass.getpass", side_effect=AssertionError("Prompt called during import")):
            self.modules = {name: importlib.import_module("Functions." + name) for name in SCRIPT_NAMES}
        # Imports above are guarded, but leave reusable modules with the real
        # provider reference; each operation test patches its own runtime call.
        provider = importlib.import_module("security.credential_provider").get_credentials
        for module in self.modules.values():
            module.get_credentials = provider

    def assert_sanitized(self, text):
        for value in (*FIXTURE_CREDENTIALS, DEVICE["secret"], "private-server-response"):
            self.assertNotIn(value, text)

    def test_imports_never_request_credentials_connect_or_prompt(self):
        with ExitStack() as stack:
            calls = [stack.enter_context(patch(target, side_effect=AssertionError("Import side effect"))) for target in (
                "security.credential_provider.get_credentials", "ncclient.manager.connect",
                "netmiko.ConnectHandler", "socket.create_connection", "getpass.getpass", "subprocess.run",
            )]
            for name in SCRIPT_NAMES:
                runpy.run_path(str(ROOT / "Functions" / (name + ".py")), run_name="_management_import_check")
            for mock in calls:
                mock.assert_not_called()

    def test_direct_script_execution_imports_provider_and_stops_cleanly_on_failure(self):
        for name in SCRIPT_NAMES:
            with self.subTest(script=name), ExitStack() as stack:
                stack.enter_context(patch.object(sys, "path", [entry for entry in sys.path if entry not in ("", str(ROOT))]))
                provider = stack.enter_context(patch("security.credential_provider.get_credentials", side_effect=RuntimeError(PRIVATE_ERROR)))
                netconf = stack.enter_context(patch("ncclient.manager.connect"))
                netmiko = stack.enter_context(patch("netmiko.ConnectHandler"))
                sockets = stack.enter_context(patch("socket.create_connection"))
                output = stack.enter_context(redirect_stdout(io.StringIO()))
                with self.assertRaises(SystemExit) as caught:
                    runpy.run_path(str(ROOT / "Functions" / (name + ".py")), run_name="__main__")
                self.assertEqual(caught.exception.code, 1)
                self.assertIn(str(ROOT), sys.path)
                self.assertIn("credential provider", output.getvalue())
                self.assert_sanitized(output.getvalue())
                provider.assert_called_once_with()
                netconf.assert_not_called()
                netmiko.assert_not_called()
                sockets.assert_not_called()

    def test_gnmi_configuration_reuses_provider_and_preserves_commands_enable_secret(self):
        module = self.modules["configure_gnmi"]
        connect = MagicMock()
        connection = connect.return_value
        connection.save_config.return_value = "Configuration saved"
        connection.check_config_mode.return_value = False
        with patch.object(module, "get_credentials", return_value=FIXTURE_CREDENTIALS) as provider, \
                patch.object(module, "audit_device", return_value=("ENABLED", "6030", True)):
            result = module.configure_device(DEVICE, connect)
        provider.assert_called_once_with()
        self.assertEqual(result, ("ENABLED", "6030", True, ""))
        self.assertEqual(connect.call_args.kwargs["username"], FIXTURE_CREDENTIALS[0])
        self.assertEqual(connect.call_args.kwargs["password"], FIXTURE_CREDENTIALS[1])
        self.assertEqual(connect.call_args.kwargs["secret"], DEVICE["secret"])
        self.assertEqual(connection.send_config_set.call_args.args[0], module.GNMI_COMMANDS)
        connection.enable.assert_called_once_with()
        connection.save_config.assert_called_once_with()
        connection.disconnect.assert_called_once_with()

    def test_netconf_configuration_reuses_provider_and_preserves_commands(self):
        module = self.modules["configure_netconf"]
        connect = MagicMock()
        connect.return_value.save_config.return_value = "Saved"
        with patch.object(module, "get_credentials", return_value=FIXTURE_CREDENTIALS) as provider:
            result = module.configure_device(DEVICE, connect)
        provider.assert_called_once_with()
        self.assertEqual(result, "")
        self.assertEqual(connect.call_args.kwargs["password"], FIXTURE_CREDENTIALS[1])
        self.assertEqual(connect.call_args.kwargs["secret"], DEVICE["secret"])
        self.assertEqual(connect.return_value.send_config_set.call_args.args[0], module.NETCONF_COMMANDS)
        connect.return_value.disconnect.assert_called_once_with()

    def test_netconf_audit_reuses_provider_and_gets_running_config(self):
        module = self.modules["configure_netconf"]
        connect = MagicMock()
        session = connect.return_value.__enter__.return_value
        session.connected, session.session_id = True, "fixture-session"
        session.get_config.return_value.errors = []
        session.get_config.return_value.data_ele = object()
        with patch.object(module, "get_credentials", return_value=FIXTURE_CREDENTIALS) as provider, \
                patch.object(module.socket, "create_connection"):
            result = module.audit_device(DEVICE, connect)
        self.assertEqual(result, (True, True, True, ""))
        provider.assert_called_once_with()
        self.assertEqual(connect.call_args.kwargs["username"], FIXTURE_CREDENTIALS[0])
        session.get_config.assert_called_once_with(source="running")

    def test_provider_failure_prevents_connections_and_is_sanitized(self):
        for name, function in [("configure_gnmi", "configure_device"), ("configure_netconf", "configure_device"), ("configure_netconf", "audit_device")]:
            with self.subTest(script=name, function=function):
                module, connect = self.modules[name], MagicMock()
                with patch.object(module, "get_credentials", side_effect=RuntimeError(PRIVATE_ERROR)), \
                        patch.object(module.socket, "create_connection") as sockets:
                    result = getattr(module, function)(DEVICE, connect)
                connect.assert_not_called()
                sockets.assert_not_called()
                self.assert_sanitized(str(result))
                self.assertIn("credential provider", str(result))

    def test_shared_credentials_do_not_trigger_another_lookup(self):
        for name in ("configure_gnmi", "configure_netconf"):
            with self.subTest(script=name):
                module, connect = self.modules[name], MagicMock(side_effect=RuntimeError(PRIVATE_ERROR))
                with patch.object(module, "get_credentials") as provider:
                    result = module.configure_device(DEVICE, connect, FIXTURE_CREDENTIALS)
                provider.assert_not_called()
                self.assert_sanitized(str(result))

    def test_missing_optional_enable_secret_stays_empty(self):
        for name in ("configure_gnmi", "configure_netconf"):
            with self.subTest(script=name):
                connect = MagicMock(side_effect=RuntimeError(PRIVATE_ERROR))
                self.modules[name].configure_device({"ip": DEVICE["ip"]}, connect, FIXTURE_CREDENTIALS)
                self.assertEqual(connect.call_args.kwargs["secret"], "")

    def test_gnmi_configuration_error_still_audits_without_leaking_exception(self):
        module, connect = self.modules["configure_gnmi"], MagicMock()
        connect.return_value.send_config_set.side_effect = RuntimeError(PRIVATE_ERROR)
        connect.return_value.check_config_mode.return_value = False
        with patch.object(module, "audit_device", return_value=("ENABLED", "6030", True)) as audit:
            result = module.configure_device(DEVICE, connect, FIXTURE_CREDENTIALS)
        audit.assert_called_once()
        self.assertFalse(result[2])
        self.assert_sanitized(result[3])

    def test_netconf_audit_errors_are_sanitized(self):
        module, connect = self.modules["configure_netconf"], MagicMock(side_effect=RuntimeError(PRIVATE_ERROR))
        with patch.object(module.socket, "create_connection"):
            result = module.audit_device(DEVICE, connect, FIXTURE_CREDENTIALS)
        self.assertEqual(result[:3], (True, False, False))
        self.assert_sanitized(result[3])

    def test_configuration_main_fetches_credentials_once(self):
        for name in ("configure_gnmi", "configure_netconf"):
            module = self.modules[name]
            with self.subTest(script=name), ExitStack() as stack:
                stack.enter_context(patch.object(module, "load_devices", return_value=[DEVICE]))
                provider = stack.enter_context(patch.object(module, "get_credentials", return_value=FIXTURE_CREDENTIALS))
                configure = stack.enter_context(patch.object(module, "configure_device", return_value=("ENABLED", "6030", True, "") if name == "configure_gnmi" else ""))
                if name == "configure_netconf":
                    audit = stack.enter_context(patch.object(module, "audit_device", return_value=(True, True, True, "")))
                stack.enter_context(redirect_stdout(io.StringIO()))
                self.assertEqual(module.main(), 0)
                provider.assert_called_once_with()
                self.assertEqual(configure.call_args.args[2], FIXTURE_CREDENTIALS)
                if name == "configure_netconf":
                    self.assertEqual(audit.call_args.args[2], FIXTURE_CREDENTIALS)

    def test_netconf_examples_use_provider_and_preserve_operations(self):
        for name in ("netconf_edit", "netconf_s3_test"):
            module = self.modules[name]
            with self.subTest(script=name), patch.object(module, "get_credentials", return_value=FIXTURE_CREDENTIALS) as provider, \
                    patch("ncclient.manager.connect") as connect, redirect_stdout(io.StringIO()):
                session = connect.return_value.__enter__.return_value
                session.edit_config.return_value.errors = []
                session.get_config.return_value.errors = []
                session.get_config.return_value.data_xml = "<data><interfaces/></data>"
                self.assertEqual(module.main(), 0)
                provider.assert_called_once_with()
                self.assertEqual(connect.call_args.kwargs["username"], FIXTURE_CREDENTIALS[0])
                self.assertEqual(connect.call_args.kwargs["password"], FIXTURE_CREDENTIALS[1])
                if name == "netconf_edit":
                    session.edit_config.assert_called_once_with(target="running", config=module.config, default_operation="merge")
                else:
                    session.get_config.assert_called_once_with(source="running", filter=module.INTERFACE_FILTER)

    def test_netconf_example_network_errors_are_sanitized(self):
        for name in ("netconf_edit", "netconf_s3_test"):
            module = self.modules[name]
            with self.subTest(script=name), patch.object(module, "get_credentials", return_value=FIXTURE_CREDENTIALS), \
                    patch("ncclient.manager.connect", side_effect=RuntimeError(PRIVATE_ERROR)), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(module.main(), 1)
                self.assert_sanitized(output.getvalue())
                self.assertIn("NETCONF operation failed", output.getvalue())

    def test_netconf_error_replies_are_not_printed(self):
        for name in ("netconf_edit", "netconf_s3_test"):
            module = self.modules[name]
            with self.subTest(script=name), patch.object(module, "get_credentials", return_value=FIXTURE_CREDENTIALS), \
                    patch("ncclient.manager.connect") as connect, redirect_stdout(io.StringIO()) as output:
                session = connect.return_value.__enter__.return_value
                session.edit_config.return_value.errors = [PRIVATE_ERROR]
                session.get_config.return_value.errors = [PRIVATE_ERROR]
                session.get_config.return_value.data_xml = PRIVATE_ERROR
                self.assertEqual(module.main(), 1)
                self.assert_sanitized(output.getvalue())


if __name__ == "__main__":
    unittest.main()

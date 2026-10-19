"""Management scripts use mocked provider credentials and device connections."""

from contextlib import ExitStack, redirect_stdout
import importlib
import io
import json
from pathlib import Path
import runpy
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch
import xml.etree.ElementTree as ET


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


class ManagementProtocolTests(unittest.TestCase):
    """Real loaders, configuration decisions and audits with mocked transports."""

    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.output = self.enterContext(redirect_stdout(io.StringIO()))
        for target in ('socket.socket.connect', 'socket.socket.connect_ex', 'subprocess.Popen',
                       'security.credential_provider.get_credentials',
                       'security.credential_provider._read_token', 'security.credential_provider._run_op'):
            self.enterContext(patch(target, side_effect=AssertionError('External operation forbidden')))
        self.tcp = self.enterContext(patch('socket.create_connection'))
        self.sleep = self.enterContext(patch('time.sleep'))
        self.ssh = self.enterContext(patch('netmiko.ConnectHandler'))
        ncclient, manager = ModuleType('ncclient'), ModuleType('ncclient.manager')
        manager.connect = MagicMock()
        ncclient.manager = manager
        self.enterContext(patch.dict(sys.modules, {'ncclient': ncclient, 'ncclient.manager': manager}))
        self.netconf = manager.connect
        self.modules = {name: importlib.import_module('Functions.' + name) for name in SCRIPT_NAMES}
        self.providers = {}
        for name, module in self.modules.items():
            self.providers[name] = self.enterContext(patch.object(module, 'get_credentials', return_value=FIXTURE_CREDENTIALS))
            self.enterContext(patch.object(module, '__file__', str(self.root / (name + '.py'))))
        self.gnmi, self.nc = self.modules['configure_gnmi'], self.modules['configure_netconf']
        self.devices = [{'name': name, 'ip': f'192.0.2.{number}', 'type': 'router' if name.startswith('R') else 'switch'}
                        for number, name in enumerate(('R1', 'R2', 'R3', 'R4', 'R5', 'S1', 'S2', 'S3', 'S4'), 1)]
        self.write_inventory(self.devices)
        self.connection = self.ssh.return_value
        self.connection.save_config.return_value = 'Configuration saved'
        self.connection.check_config_mode.return_value = False
        self.connection.send_command.return_value = 'Transport: default\nEnabled: yes\nServer: running on port 6030\n'
        self.session = self.netconf.return_value.__enter__.return_value
        self.session.connected, self.session.session_id = True, 'fixture-session'
        self.session.get_config.return_value = SimpleNamespace(
            errors=[], data_ele=ET.fromstring('<data xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"/>'),
            data_xml='<data xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"/>')
        self.session.edit_config.return_value = SimpleNamespace(errors=[], ok=True)

    def write_inventory(self, devices):
        (self.root / 'devices.json').write_text(json.dumps({'devices': devices}))

    def assert_private(self, value):
        for secret in (*FIXTURE_CREDENTIALS, DEVICE['secret'], 'private-server-response'):
            self.assertNotIn(secret, str(value))

    def test_loaders_select_exactly_nine_routers_and_switches_without_hosts(self):
        self.write_inventory([{'name': 'host1', 'type': 'host'}, *self.devices])
        for module in (self.gnmi, self.nc):
            with self.subTest(module=module.__name__):
                self.assertEqual(module.load_devices(), self.devices)
        self.ssh.assert_not_called()
        self.netconf.assert_not_called()

    def test_inventory_failures_stop_main_before_credentials_or_connections(self):
        for devices in ([], self.devices[:-1], [dict(self.devices[0], ip=''), *self.devices[1:]],
                        [dict(self.devices[0], name=''), *self.devices[1:]]):
            self.write_inventory(devices)
            for name in ('configure_gnmi', 'configure_netconf'):
                with self.subTest(module=name, devices=devices):
                    self.assertEqual(self.modules[name].main(), 1)
                    self.providers[name].assert_not_called()
        self.ssh.assert_not_called()
        self.netconf.assert_not_called()
        self.tcp.assert_not_called()

    def test_malformed_inventory_rows_return_failure_without_raw_exception(self):
        for row in (None, 'private-server-response', 42):
            self.write_inventory([row, *self.devices[1:]])
            for name in ('configure_gnmi', 'configure_netconf'):
                with self.subTest(module=name, row=row):
                    try:
                        result = self.modules[name].main()
                    except Exception as error:
                        self.fail(f'Invalid inventory escaped main as {type(error).__name__}')
                    self.assertEqual(result, 1)
                    self.providers[name].assert_not_called()
        self.ssh.assert_not_called()
        self.netconf.assert_not_called()
        self.assert_private(self.output.getvalue())

    def test_real_configuration_uses_independent_eos_commands_and_saves_before_audit(self):
        for module, commands in ((self.gnmi, ['management api gnmi', 'transport grpc default', 'no ssl profile']),
                                 (self.nc, ['management api netconf', 'transport ssh default'])):
            with self.subTest(module=module.__name__):
                self.connection.reset_mock()
                result = module.configure_device(DEVICE, self.ssh, FIXTURE_CREDENTIALS)
                self.connection.send_config_set.assert_called_once_with(commands, error_pattern=r'(?m)^\s*%', read_timeout=20)
                actions = [call[0] for call in self.connection.mock_calls]
                self.assertLess(actions.index('enable'), actions.index('send_config_set'))
                self.assertLess(actions.index('send_config_set'), actions.index('save_config'))
                if module is self.gnmi:
                    self.assertEqual(result, ('ENABLED', '6030', True, ''))
                    self.assertLess(actions.index('save_config'), actions.index('send_command'))
                    self.tcp.assert_called_with((DEVICE['ip'], 6030), timeout=3)
                else:
                    self.assertEqual(result, '')
                self.assertEqual(actions[-1], 'disconnect')

    def test_gnmi_audit_never_combines_fields_from_different_transports(self):
        outputs = ('Transport: alternate\nEnabled: yes\nServer: running on port 6030\n',
                   'Transport: default\nEnabled: no\nTransport: alternate\nEnabled: yes\nServer: running on port 6030\n',
                   'Transport: default\nEnabled: yes\nTransport: alternate\nServer: running on port 6030\n',
                   'Transport: default\nEnabled: yes\nServer: running on port 60300\n',
                   'unrecognized output')
        for output in outputs:
            with self.subTest(output=output):
                reader = MagicMock(return_value=output)
                self.assertFalse(self.gnmi.audit_device(DEVICE, reader)[2])
                self.assertEqual(reader.call_count, 5)
                self.assertEqual({call.args for call in reader.call_args_list}, {('show management api gnmi',)})
        self.tcp.assert_not_called()

    def test_gnmi_audit_retries_unreachable_tcp_and_stops_on_recovery(self):
        self.tcp.side_effect = [TimeoutError(PRIVATE_ERROR), MagicMock()]
        result = self.gnmi.audit_device(DEVICE, self.connection.send_command)
        self.assertEqual(result, ('ENABLED', '6030', True))
        self.assertEqual(self.tcp.call_count, 2)
        self.sleep.assert_called_once_with(2)

    def test_gnmi_audit_exhaustion_is_failure_without_extra_sleep(self):
        self.tcp.side_effect = TimeoutError(PRIVATE_ERROR)
        result = self.gnmi.audit_device(DEVICE, self.connection.send_command)
        self.assertEqual(result, ('TCP UNREACHABLE', '6030', False))
        self.assertEqual(self.tcp.call_count, 5)
        self.assertEqual(self.sleep.call_count, 4)
        self.assert_private(result)

    def test_gnmi_failed_save_cannot_be_overridden_by_successful_real_audit(self):
        self.connection.save_config.return_value = '% Error ' + PRIVATE_ERROR
        self.connection.check_config_mode.return_value = True
        result = self.gnmi.configure_device(DEVICE, self.ssh, FIXTURE_CREDENTIALS)
        self.assertEqual(result[:3], ('ENABLED', '6030', False))
        self.assertIn('saving', result[3])
        self.assert_private(result)
        self.connection.exit_config_mode.assert_called_once()
        actions = [call[0] for call in self.connection.mock_calls]
        self.assertLess(actions.index('exit_config_mode'), actions.index('send_command'))
        self.connection.disconnect.assert_called_once()

    def test_netconf_failed_apply_does_not_save_and_disconnects(self):
        self.connection.send_config_set.side_effect = RuntimeError(PRIVATE_ERROR)
        result = self.nc.configure_device(DEVICE, self.ssh, FIXTURE_CREDENTIALS)
        self.assertIn('failed', result)
        self.assert_private(result)
        self.connection.save_config.assert_not_called()
        self.connection.disconnect.assert_called_once()

    def test_netconf_save_error_text_is_not_success_and_disconnect_failure_is_suppressed(self):
        self.connection.disconnect.side_effect = RuntimeError(PRIVATE_ERROR)
        for response in ('% Invalid input', 'Copy failed', 'Error saving configuration', None):
            with self.subTest(response=response):
                self.connection.save_config.return_value = response
                result = self.nc.configure_device(DEVICE, self.ssh, FIXTURE_CREDENTIALS)
                self.assertIn('failed', result)
                self.assert_private(result)

    def test_netconf_audit_requires_connected_session_and_session_id_before_rpc(self):
        for connected, session_id in ((False, 'id'), (True, ''), (True, None)):
            with self.subTest(connected=connected, session_id=session_id):
                self.session.connected, self.session.session_id = connected, session_id
                result = self.nc.audit_device(DEVICE, self.netconf, FIXTURE_CREDENTIALS)
                self.assertEqual(result[:3], (True, False, False))
                self.session.get_config.assert_not_called()
                self.assert_private(result)

    def test_netconf_audit_rejects_error_missing_and_incomplete_rpc_results(self):
        for reply in (None, SimpleNamespace(), SimpleNamespace(errors=[PRIVATE_ERROR], data_ele=object()),
                      SimpleNamespace(errors=[], data_ele=None)):
            with self.subTest(reply=reply):
                self.session.get_config.return_value = reply
                result = self.nc.audit_device(DEVICE, self.netconf, FIXTURE_CREDENTIALS)
                self.assertEqual(result[:3], (True, True, False))
                self.assertIn('audit failed', result[3])
                self.assert_private(result)

    def test_netconf_tcp_exhaustion_never_attempts_session(self):
        self.tcp.side_effect = OSError(PRIVATE_ERROR)
        self.assertEqual(self.nc.audit_device(DEVICE, self.netconf, FIXTURE_CREDENTIALS),
                         (False, False, False, 'TCP port 830 is unreachable.'))
        self.assertEqual(self.tcp.call_count, 5)
        self.assertEqual(self.sleep.call_count, 4)
        self.netconf.assert_not_called()

    def test_netconf_tcp_recovery_uses_explicit_password_auth_and_running_datastore(self):
        self.tcp.side_effect = [TimeoutError(), MagicMock()]
        self.assertEqual(self.nc.audit_device(DEVICE, self.netconf, FIXTURE_CREDENTIALS), (True, True, True, ''))
        self.netconf.assert_called_once_with(host=DEVICE['ip'], port=830, username=FIXTURE_CREDENTIALS[0],
            password=FIXTURE_CREDENTIALS[1], hostkey_verify=False, allow_agent=False, look_for_keys=False, timeout=30)
        self.session.get_config.assert_called_once_with(source='running')
        self.netconf.return_value.__exit__.assert_called_once()

    def test_main_real_deployments_and_audits_determine_batch_exit_status(self):
        # This is an offline integration test: loaders, deployment and audits all run.
        for name in ('configure_gnmi', 'configure_netconf'):
            for failed in (False, True):
                with self.subTest(module=name, failed=failed):
                    self.ssh.reset_mock()
                    self.connection.send_command.reset_mock()
                    self.session.get_config.reset_mock()
                    self.providers[name].reset_mock()
                    self.connection.send_config_set.side_effect = [RuntimeError(PRIVATE_ERROR) if failed else '', *([''] * 8)]
                    self.assertEqual(self.modules[name].main(), 1 if failed else 0)
                    self.assertEqual([call.kwargs['host'] for call in self.ssh.call_args_list],
                                     [f'192.0.2.{n}' for n in range(1, 10)])
                    self.providers[name].assert_called_once()
                    audits = self.connection.send_command if name == 'configure_gnmi' else self.session.get_config
                    self.assertEqual(audits.call_count, 9)
        self.assert_private(self.output.getvalue())

    def test_missing_optional_dependencies_returns_failure_before_credentials(self):
        for name in SCRIPT_NAMES:
            dependency = 'netmiko' if name == 'configure_gnmi' else 'ncclient'
            with self.subTest(module=name), patch.dict(sys.modules, {dependency: None}):
                self.assertEqual(self.modules[name].main(), 1)
                self.providers[name].assert_not_called()
        self.ssh.assert_not_called()
        self.netconf.assert_not_called()

    def test_edit_example_sends_namespaced_openconfig_merge_for_only_ethernet2(self):
        self.assertEqual(self.modules['netconf_edit'].main(), 0)
        request = self.session.edit_config.call_args.kwargs
        self.assertEqual((request['target'], request['default_operation']), ('running', 'merge'))
        root = ET.fromstring(request['config'])
        self.assertEqual(root.tag, '{urn:ietf:params:xml:ns:netconf:base:1.0}config')
        ns = {'oc': 'http://openconfig.net/yang/interfaces'}
        interfaces = root.findall('oc:interfaces/oc:interface', ns)
        self.assertEqual(len(interfaces), 1)
        self.assertEqual(interfaces[0].findtext('oc:name', namespaces=ns), 'Ethernet2')
        self.assertEqual(interfaces[0].findtext('oc:config/oc:name', namespaces=ns), 'Ethernet2')
        self.assertEqual(interfaces[0].findtext('oc:config/oc:description', namespaces=ns), 'to-S4-Eth2')
        self.assertEqual(self.netconf.call_args.kwargs['host'], '172.20.20.4')
        self.session.get_config.assert_not_called()

    def test_get_example_uses_netconf_subtree_filter_for_openconfig_interfaces(self):
        self.assertEqual(self.modules['netconf_s3_test'].main(), 0)
        request = self.session.get_config.call_args.kwargs
        self.assertEqual(request['source'], 'running')
        root = ET.fromstring(request['filter'])
        self.assertEqual(root.tag, '{urn:ietf:params:xml:ns:netconf:base:1.0}filter')
        self.assertEqual(root.attrib, {'type': 'subtree'})
        self.assertEqual([child.tag for child in root], ['{http://openconfig.net/yang/interfaces}interfaces'])
        self.session.edit_config.assert_not_called()

    def test_examples_sanitize_rpc_timeout_and_malformed_xml_errors_and_close_session(self):
        # ncclient owns reply parsing; model boundary exceptions without inventing
        # combinations of .errors/.ok/.data_xml that a parsed reply cannot return.
        for name, operation in (('netconf_edit', self.session.edit_config),
                                ('netconf_s3_test', self.session.get_config)):
            for error in (TimeoutError(PRIVATE_ERROR), ET.ParseError(PRIVATE_ERROR)):
                with self.subTest(module=name, error=type(error).__name__):
                    self.output.seek(0)
                    self.output.truncate(0)
                    self.netconf.return_value.__exit__.reset_mock()
                    operation.side_effect = error
                    self.assertEqual(self.modules[name].main(), 1)
                    self.netconf.return_value.__exit__.assert_called_once()
                    self.assertNotIn('EDIT-CONFIG RESULT: PASS', self.output.getvalue())
                    self.assert_private(self.output.getvalue())

    def test_examples_reject_empty_credentials_before_connecting(self):
        for name in ('netconf_edit', 'netconf_s3_test'):
            for credentials in (('', 'fixture-password'), ('fixture-user', ''), None):
                with self.subTest(module=name, credentials=credentials):
                    self.providers[name].return_value = credentials
                    self.assertEqual(self.modules[name].main(), 1)
        self.netconf.assert_not_called()


if __name__ == "__main__":
    unittest.main()

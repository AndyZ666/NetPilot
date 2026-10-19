"""Offline SNMP contracts using synthetic EOS replies and temporary inventories.

Both production modules have standard-library imports and guarded entry points.
Every test blocks process creation and network connections; subprocess.run is
replaced before any production function is called. No real inventory, Docker,
SSH, Vault, credential provider, or device is accessed. Expectations below are
literal fixtures, independent of production constants and command builders.
"""

import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import call, patch

from Functions import configure_snmp_traps as traps
from Functions import deploy_snmp as deploy


NAMES = ("R1", "R2", "R3", "R4", "R5", "S1", "S2", "S3", "S4")
HOST_REPLY = (
    "Notification host: 172.20.20.1     udp-port: 162   type: trap   refresh: False\n"
    "user: NetPilot                     security model: v2c\n"
)
INTERFACE_REPLY = "SNMP source interfaces:\n    Management0 in VRF default\n"
TRAPS_REPLY = (
    "snmp                   link-down                     Yes (snmp enabled)\n"
    "snmp                   link-up                       Yes (snmp enabled)\n"
)
REPAIR_COMMANDS = [
    "snmp-server host 172.20.20.1 version 2c NetPilot",
    "snmp-server local-interface Management0",
    "snmp-server enable traps snmp",
]
TRAP_APPLY_SCRIPT = (
    "printf 'enable\\nconfigure\\nsnmp-server host 172.20.20.1 version 2c NetPilot\\n"
    "snmp-server local-interface Management0\\nsnmp-server enable traps snmp\\nend\\n' | Cli"
)
COMMUNITY_APPLY_SCRIPT = 'printf "enable\nconfigure\nsnmp-server community NetPilot ro\nend\n" | Cli'
COMMUNITY_VERIFY_SCRIPT = 'printf "enable\nshow running-config | section snmp\n" | Cli'
COMMUNITY_REPLY = "snmp-server community NetPilot ro\n"
PASSWORD = "synthetic-snmp-password-never-a-real-secret"


def completed(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(["offline-fixture"], returncode, stdout, stderr)


class OfflineSNMPFixture(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.inventory_path = self.root / "devices.json"
        self.records = [
            {"name": name, "ip": f"192.0.2.{index}",
             "type": "router" if name.startswith("R") else "switch", "role": "fixture"}
            for index, name in enumerate(NAMES, 1)
        ]
        self.write_inventory(self.records)
        self.device = traps.Device("R1", "192.0.2.1", "router", "fixture", "clab-pilot-network-R1")
        self.output = self.enterContext(patch("sys.stdout", new_callable=io.StringIO))
        self.errors = self.enterContext(patch("sys.stderr", new_callable=io.StringIO))
        self.run = self.enterContext(patch.object(
            subprocess, "run", side_effect=AssertionError("Unscripted subprocess call in offline test")))
        self.enterContext(patch.object(
            subprocess, "Popen", side_effect=AssertionError("Real subprocess creation is forbidden")))
        self.enterContext(patch.object(
            os, "system", side_effect=AssertionError("Real shell execution is forbidden")))
        self.enterContext(patch.object(
            socket.socket, "connect", side_effect=AssertionError("Live networking is forbidden")))
        self.enterContext(patch.object(
            socket.socket, "connect_ex", side_effect=AssertionError("Live networking is forbidden")))
        self.enterContext(patch.object(
            socket, "create_connection", side_effect=AssertionError("Live networking is forbidden")))

    def write_inventory(self, records):
        self.inventory_path.write_text(json.dumps({"devices": records}), encoding="utf-8")

    def correct_audit(self, **overrides):
        fields = dict(device=self.device, container_running=True, trap_host="172.20.20.1",
                      trap_port=162, security_model="2c", community="NetPilot",
                      source_interface="Management0", link_down_enabled=True,
                      link_up_enabled=True, status="PASS")
        fields.update(overrides)
        return traps.AuditResult(**fields)

    def audit_replies(self, host=HOST_REPLY, interface=INTERFACE_REPLY, notifications=TRAPS_REPLY):
        """Keep real container checks, command execution, parsing, and audit logic."""
        self.run.reset_mock()
        self.run.side_effect = [completed("clab-pilot-network-R1"),
                                completed("clab-pilot-network-R1"), completed(host),
                                completed(interface), completed(notifications)]
        return traps.audit_device(self.device)

    def script_fleet(self, *, missing=(), apply_failures=(), stale=(), save_failures=(), unavailable=()):
        """Stateful transport fixture; only the expected EOS/Docker commands exist."""
        configured = {name: name not in missing for name in NAMES}
        events = []

        def respond(argv, **kwargs):
            self.assertIn("timeout", kwargs)
            self.assertTrue(kwargs.get("capture_output"))
            self.assertNotIn("shell", kwargs)
            if argv == ["docker", "--version"]:
                return completed("Docker version offline-fixture")
            if argv[:2] == ["docker", "ps"]:
                self.assertIn(argv[2:-1], (["-a", "--filter"], ["--filter"]))
                container = argv[-1].removeprefix("name=")
                name = container.removeprefix("clab-pilot-network-")
                self.assertIn(name, NAMES)
                return completed("" if name in unavailable else container)
            self.assertEqual(argv[:2], ["docker", "exec"])
            name = argv[2].removeprefix("clab-pilot-network-")
            self.assertIn(name, NAMES)
            if argv[3:5] == ["bash", "-c"]:
                self.assertEqual(argv[5:], [TRAP_APPLY_SCRIPT])
                events.append((name, "apply"))
                if name in apply_failures:
                    return completed(returncode=1, stderr="fixture apply denied")
                if name not in stale:
                    configured[name] = True
                return completed()
            self.assertEqual(argv[3:7], ["Cli", "-p", "15", "-c"])
            self.assertEqual(len(argv), 8)
            command = argv[-1]
            events.append((name, command))
            if command == "write memory":
                return completed(returncode=int(name in save_failures), stderr="fixture save denied")
            replies = {
                "show snmp notification host": HOST_REPLY,
                "show snmp local-interface": INTERFACE_REPLY,
                "show snmp notification": TRAPS_REPLY,
            }
            self.assertIn(command, replies)
            return completed(replies[command] if configured[name] else "")

        self.run.reset_mock()
        self.run.side_effect = respond
        return events

    def run_trap_main(self, *flags):
        with patch("sys.argv", ["configure_snmp_traps.py", "--inventory", str(self.inventory_path), *flags]):
            return traps.main()

    def assert_no_save(self, events, name):
        self.assertNotIn((name, "write memory"), events)


class TrapConfigurationTests(OfflineSNMPFixture):
    def test_inventory_loader_selects_exact_fleet_and_excludes_hosts_and_servers(self):
        self.records.extend([
            {"name": "H1", "ip": "192.0.2.100", "type": "host"},
            {"name": "NMAS", "ip": "192.0.2.101", "type": "server"},
        ])
        del self.records[0]["role"]
        self.write_inventory(self.records)
        before = self.inventory_path.read_bytes()
        devices = traps.validate_inventory(traps.load_inventory(str(self.inventory_path)))
        self.assertEqual([device.name for device in devices], list(NAMES))
        self.assertEqual([device.container_name for device in devices],
                         ["clab-pilot-network-" + name for name in NAMES])
        self.assertEqual(devices[0].role, "unknown")
        self.assertEqual(self.inventory_path.read_bytes(), before)
        self.run.assert_not_called()

    def test_inventory_rejects_missing_fields_duplicates_unsafe_names_and_wrong_fleet(self):
        cases = {
            "missing field": self.records + [{"name": "H1", "type": "host"}],
            "duplicate name": self.records + [{"name": "R1", "ip": "192.0.2.100", "type": "host"}],
            "duplicate IP": self.records + [{"name": "H1", "ip": "192.0.2.1", "type": "host"}],
            "unsafe name": self.records + [{"name": "H1;id", "ip": "192.0.2.100", "type": "host"}],
            "missing router": self.records[1:],
            "extra switch": self.records + [{"name": "S5", "ip": "192.0.2.100", "type": "switch"}],
        }
        for label, records in cases.items():
            with self.subTest(case=label), self.assertRaises(SystemExit) as raised:
                traps.validate_inventory(records)
            self.assertEqual(raised.exception.code, 1)
        self.run.assert_not_called()

    def test_load_inventory_missing_invalid_json_and_wrong_devices_shape_exit_one(self):
        for source in (None, "{invalid", "{}", '{"devices": {}}', '{"devices": null}'):
            with self.subTest(source=source):
                if source is None:
                    self.inventory_path.unlink()
                else:
                    self.inventory_path.write_text(source, encoding="utf-8")
                with self.assertRaises(SystemExit) as raised:
                    traps.load_inventory(str(self.inventory_path))
                self.assertEqual(raised.exception.code, 1)
        self.run.assert_not_called()

    def test_missing_config_is_empty_for_compliant_state_and_does_not_mutate_audit(self):
        result = self.correct_audit()
        before = vars(result).copy()
        self.assertEqual(traps.build_missing_config(result), [])
        self.assertEqual(vars(result), before)
        self.assertEqual(traps.build_missing_config(result), [])
        self.run.assert_not_called()

    def test_missing_config_uses_only_required_commands_in_dependency_order(self):
        cases = [
            ({"trap_host": None}, [REPAIR_COMMANDS[0]]),
            ({"trap_host": "192.0.2.50"}, [REPAIR_COMMANDS[0]]),
            ({"trap_port": 1162}, [REPAIR_COMMANDS[0]]),
            ({"security_model": "3"}, [REPAIR_COMMANDS[0]]),
            ({"community": "fixture-wrong"}, [REPAIR_COMMANDS[0]]),
            ({"source_interface": None}, [REPAIR_COMMANDS[1]]),
            ({"source_interface": "Ethernet1"}, [REPAIR_COMMANDS[1]]),
            ({"link_down_enabled": False}, [REPAIR_COMMANDS[2]]),
            ({"link_up_enabled": None}, [REPAIR_COMMANDS[2]]),
        ]
        for overrides, expected in cases:
            with self.subTest(overrides=overrides):
                self.assertEqual(traps.build_missing_config(self.correct_audit(**overrides)), expected)
        self.assertEqual(traps.build_missing_config(traps.AuditResult(self.device)), REPAIR_COMMANDS)

    def test_source_interface_requires_exact_management0_not_a_name_prefix(self):
        # The documented source is Management0; Management00 is another interface.
        for interface in ("Management00", "Management0.100"):
            with self.subTest(interface=interface):
                result = self.audit_replies(interface=f"SNMP source interfaces:\n {interface} in VRF default\n")
                self.assertEqual((result.status, traps.build_missing_config(result)),
                                 ("FAIL", [REPAIR_COMMANDS[1]]))

    def test_host_and_interface_parsers_handle_spacing_and_security_model_normalization(self):
        for model, expected in (("v2c", "2c"), ("V3", "3"), ("1", "1")):
            with self.subTest(model=model):
                self.run.side_effect = [completed(
                    "Notification host: 172.20.20.1   udp-port: 162  type: trap\n"
                    f"  user: NetPilot        security model: {model}\n"), completed(INTERFACE_REPLY)]
                self.assertEqual(traps.get_notification_host(self.device), ("172.20.20.1", 162, expected, "NetPilot"))
                self.assertEqual(traps.get_local_interface(self.device), "Management0")
        self.run.side_effect = [completed(returncode=1), completed(returncode=1)]
        self.assertEqual(traps.get_notification_host(self.device), (None, None, None, None))
        self.assertIsNone(traps.get_local_interface(self.device))

    def test_notification_parser_respects_explicit_no_even_when_snmp_is_enabled(self):
        cases = [
            (TRAPS_REPLY, (True, True)),
            ("snmp link-down No (snmp disabled)\nsnmp link-up Yes (snmp enabled)", (False, True)),
            ("snmp link-down No (snmp enabled)\nsnmp link-up Yes (snmp enabled)", (False, True)),
            ("snmp link-down Yes (snmp enabled)\nsnmp link-up No (snmp enabled)", (True, False)),
            ("snmp cold-start Yes (snmp enabled)", (None, None)),
        ]
        for reply, expected in cases:
            with self.subTest(reply=reply):
                self.run.side_effect = [completed(reply)]
                self.assertEqual(traps.get_notification_status(self.device), expected)
        self.run.side_effect = [completed(returncode=1)]
        self.assertEqual(traps.get_notification_status(self.device), (None, None))

    def test_audit_distinguishes_correct_incorrect_missing_and_unknown_configuration(self):
        cases = [
            ({}, "PASS", "SNMP trap configuration is correct"),
            ({"host": ""}, "FAIL", "SNMP trap host not configured"),
            ({"host": HOST_REPLY.replace("172.20.20.1", "192.0.2.50")}, "FAIL", "Incorrect trap destination or port"),
            ({"host": HOST_REPLY.replace("162", "1162")}, "FAIL", "Incorrect trap destination or port"),
            ({"host": HOST_REPLY.replace("v2c", "v3")}, "FAIL", "Incorrect SNMP security parameters"),
            ({"host": HOST_REPLY.replace("NetPilot", "fixture-wrong")}, "FAIL", "Incorrect SNMP security parameters"),
            ({"interface": ""}, "FAIL", "Source interface not configured correctly"),
            ({"notifications": TRAPS_REPLY.replace("Yes (snmp enabled)", "No (snmp disabled)")}, "FAIL", "Link traps not enabled"),
            ({"notifications": ""}, "WARN", "Partial SNMP trap configuration"),
        ]
        for replies, status, message in cases:
            with self.subTest(replies=replies):
                result = self.audit_replies(**replies)
                self.assertEqual((result.status, result.message), (status, message))
                self.assertTrue(result.container_running)
                self.assertFalse(result.changed)
                self.assertFalse(result.saved)
                self.assertEqual(self.run.call_count, 5)

    def test_unavailable_container_stops_before_eos_queries(self):
        for responses in ([completed("", 0)], [completed("fixture error", 1)],
                          [completed("clab-pilot-network-R1"), completed("")],
                          [subprocess.TimeoutExpired(["docker", "ps"], 5)]):
            with self.subTest(responses=responses):
                self.run.reset_mock()
                self.run.side_effect = responses
                result = traps.audit_device(self.device)
                self.assertEqual((result.status, result.message), ("FAIL", "Container not running"))
                self.assertFalse(result.container_running)
                self.assertTrue(all(item.args[0][:2] == ["docker", "ps"] for item in self.run.call_args_list))

    def test_eos_command_exact_argv_and_error_outcomes(self):
        cases = [(completed("  hostname R1\n"), (True, "hostname R1")),
                 (completed(returncode=1, stderr=" denied \n"), (False, "denied")),
                 (completed(returncode=1), (False, "Command failed")),
                 (subprocess.TimeoutExpired(["docker"], 10), (False, "Command timeout")),
                 (FileNotFoundError("fixture docker missing"), (False, "fixture docker missing"))]
        for reply, expected in cases:
            with self.subTest(reply=reply):
                self.run.reset_mock()
                self.run.side_effect = [reply]
                self.assertEqual(traps.run_eos_command(self.device, "show hostname"), expected)
                self.run.assert_called_once_with(
                    ["docker", "exec", "clab-pilot-network-R1", "Cli", "-p", "15", "-c", "show hostname"],
                    capture_output=True, text=True, timeout=10)

    def test_apply_builds_exact_multiline_cli_and_empty_delta_creates_no_process(self):
        self.assertTrue(traps.apply_device_config(self.device, []))
        self.run.assert_not_called()
        self.run.side_effect = [completed()]
        self.assertTrue(traps.apply_device_config(self.device, REPAIR_COMMANDS))
        self.run.assert_called_once_with(
            ["docker", "exec", "clab-pilot-network-R1", "bash", "-c", TRAP_APPLY_SCRIPT],
            capture_output=True, text=True, timeout=10)

    def test_apply_nonzero_timeout_and_exception_are_failures(self):
        for response in (completed(returncode=1, stderr="fixture denied"),
                         subprocess.TimeoutExpired(["docker"], 10), OSError("fixture unavailable")):
            with self.subTest(response=response):
                self.run.reset_mock()
                self.run.side_effect = [response]
                self.assertFalse(traps.apply_device_config(self.device, REPAIR_COMMANDS, verbose=True))
                self.assertEqual(self.run.call_count, 1)

    def test_verbose_configuration_errors_do_not_expose_passwords(self):
        # CONFIGURE_SNMP_TRAPS_SUMMARY.md promises no passwords in logs/output.
        for response in (completed(returncode=1, stderr="authentication password=" + PASSWORD),
                         RuntimeError("authentication password=" + PASSWORD)):
            with self.subTest(response=type(response).__name__):
                self.output.seek(0)
                self.output.truncate()
                self.run.side_effect = [response]
                self.assertFalse(traps.apply_device_config(self.device, REPAIR_COMMANDS, verbose=True))
                self.assertNotIn(PASSWORD, self.output.getvalue() + self.errors.getvalue())

    def test_main_default_is_read_only_and_returns_failure_for_missing_configuration(self):
        events = self.script_fleet(missing=("R1",))
        self.assertEqual(self.run_trap_main(), 1)
        self.assertEqual(len(events), 27)
        self.assertTrue(all(command.startswith("show ") for _, command in events))
        self.assertIn("Devices Checked : 9", self.output.getvalue())
        self.assertIn("Failed          : 1", self.output.getvalue())

    def test_main_apply_is_idempotent_for_a_compliant_fleet(self):
        events = self.script_fleet()
        self.assertEqual(self.run_trap_main("--apply"), 0)
        self.assertEqual(len(events), 27)
        self.assertTrue(all(command.startswith("show ") for _, command in events))
        self.assertIn("Changed         : 0", self.output.getvalue())
        self.assertIn("Already Correct : 9", self.output.getvalue())

    def test_main_repairs_then_reaudits_before_saving_and_reports_changed_state(self):
        events = self.script_fleet(missing=("R1",))
        observed = []
        with patch.object(traps, "print_results_table", side_effect=lambda results: observed.extend(results)):
            self.assertEqual(self.run_trap_main("--apply"), 0)
        self.assertEqual([command for name, command in events if name == "R1"], [
            "show snmp notification host", "show snmp local-interface", "show snmp notification", "apply",
            "show snmp notification host", "show snmp local-interface", "show snmp notification", "write memory"])
        result = next(result for result in observed if result.device.name == "R1")
        self.assertEqual((result.status, result.changed, result.saved, result.missing_config), ("PASS", True, True, []))
        self.assertIn("Changed         : 1", self.output.getvalue())

    def test_main_failed_apply_continues_other_devices_without_saving_failed_device(self):
        events = self.script_fleet(missing=("R1", "R2"), apply_failures=("R1",))
        self.assertEqual(self.run_trap_main("--apply"), 1)
        self.assert_no_save(events, "R1")
        self.assertIn(("R2", "write memory"), events)
        self.assertIn(("S4", "show snmp notification"), events)
        self.assertIn("APPLY FAILED", self.output.getvalue())
        self.assertIn("Changed         : 1", self.output.getvalue())

    def test_main_stale_post_apply_state_is_failure_and_is_never_saved(self):
        events = self.script_fleet(missing=("R1",), stale=("R1",))
        self.assertEqual(self.run_trap_main("--apply"), 1)
        self.assertEqual(events.count(("R1", "show snmp notification host")), 2)
        self.assert_no_save(events, "R1")
        self.assertIn("POST-AUDIT FAILED", self.output.getvalue())
        self.assertIn("Changed         : 0", self.output.getvalue())

    def test_main_save_failure_is_not_reported_as_success_or_saved(self):
        events = self.script_fleet(missing=("R1",), save_failures=("R1",))
        observed = []
        with patch.object(traps, "print_results_table", side_effect=lambda results: observed.extend(results)):
            self.assertEqual(self.run_trap_main("--apply"), 1)
        self.assertIn(("R1", "write memory"), events)
        result = next(result for result in observed if result.device.name == "R1")
        self.assertEqual((result.status, result.saved), ("FAIL", False))
        self.assertEqual(result.message, "Configuration applied but save failed")
        self.assertIn("SAVE FAILED", self.output.getvalue())


class CommunityDeploymentTests(OfflineSNMPFixture):
    def new_deployer(self):
        return deploy.SNMPDeployer(str(self.inventory_path))

    def test_target_selection_excludes_hosts_and_servers_and_preserves_inventory(self):
        records = [self.records[0], {"name": "H1", "type": "host"},
                   self.records[5], {"name": "NMAS", "type": "server"}]
        self.write_inventory(records)
        before = self.inventory_path.read_bytes()
        deployer = self.new_deployer()
        self.assertEqual(deployer.get_target_devices(), [records[0], records[2]])
        self.assertEqual(deployer.get_results(), {})
        self.assertEqual(self.inventory_path.read_bytes(), before)
        self.run.assert_not_called()

    def test_missing_and_invalid_inventory_exit_before_subprocess(self):
        for source in (None, "{invalid"):
            with self.subTest(source=source):
                if source is None:
                    self.inventory_path.unlink()
                else:
                    self.inventory_path.write_text(source, encoding="utf-8")
                with self.assertRaises(SystemExit) as raised:
                    self.new_deployer()
                self.assertEqual(raised.exception.code, 1)
        self.run.assert_not_called()

    def test_success_builds_exact_apply_and_verification_commands_and_records_output(self):
        deployer = self.new_deployer()
        self.run.side_effect = [completed(), completed("\n" + COMMUNITY_REPLY)]
        self.assertTrue(deployer.deploy_snmp_to_device(self.records[0]))
        self.assertEqual(self.run.call_args_list, [
            call(["docker", "exec", "clab-pilot-network-R1", "bash", "-c", COMMUNITY_APPLY_SCRIPT],
                 capture_output=True, text=True, timeout=10),
            call(["docker", "exec", "clab-pilot-network-R1", "bash", "-c", COMMUNITY_VERIFY_SCRIPT],
                 capture_output=True, text=True, timeout=10),
        ])
        self.assertEqual(deployer.get_results(), {
            "R1": {"status": "OK", "output": "snmp-server community NetPilot ro", "error": None}})

    def test_verification_missing_or_wrong_community_does_not_claim_success(self):
        for output in ("", "snmp-server community fixture-other ro\n", "snmp-server community NetPilot rw\n"):
            with self.subTest(output=output):
                deployer = self.new_deployer()
                self.run.side_effect = [completed(), completed(output)]
                self.assertFalse(deployer.deploy_snmp_to_device(self.records[0]))
                self.assertEqual(deployer.get_results()["R1"], {
                    "status": "FAILED", "output": output.strip(),
                    "error": "SNMP configuration not found in running config"})

    def test_failed_apply_cannot_succeed_from_preexisting_verification_output(self):
        # Existing configuration does not make a failed deployment successful.
        deployer = self.new_deployer()
        self.run.side_effect = [completed(returncode=1, stderr="fixture apply denied"), completed(COMMUNITY_REPLY)]
        self.assertFalse(deployer.deploy_snmp_to_device(self.records[0]))
        self.assertNotEqual(deployer.get_results()["R1"]["status"], "OK")

    def test_failed_verification_cannot_succeed_from_partial_stdout(self):
        deployer = self.new_deployer()
        self.run.side_effect = [completed(), completed(COMMUNITY_REPLY, returncode=1, stderr="fixture read failed")]
        self.assertFalse(deployer.deploy_snmp_to_device(self.records[0]))
        self.assertNotEqual(deployer.get_results()["R1"]["status"], "OK")

    def test_timeouts_at_either_stage_and_transport_errors_have_failure_outcomes(self):
        cases = [
            ([subprocess.TimeoutExpired(["docker"], 10)], "TIMEOUT", "Command execution timeout"),
            ([completed(), subprocess.TimeoutExpired(["docker"], 10)], "TIMEOUT", "Command execution timeout"),
            ([FileNotFoundError("fixture docker unavailable")], "ERROR", "fixture docker unavailable"),
        ]
        for responses, status, error in cases:
            with self.subTest(status=status, stage=len(responses)):
                deployer = self.new_deployer()
                self.run.reset_mock()
                self.run.side_effect = responses
                self.assertFalse(deployer.deploy_snmp_to_device(self.records[0]))
                self.assertEqual(deployer.get_results()["R1"], {"status": status, "output": "", "error": error})
                self.assertEqual(self.run.call_count, len(responses))

    def test_deploy_all_continues_after_partial_failure_and_reports_actual_totals(self):
        self.write_inventory([self.records[0], self.records[5], {"name": "H1", "type": "host"}])
        deployer = self.new_deployer()
        self.run.side_effect = [completed(), completed(""), completed(), completed(COMMUNITY_REPLY)]
        deployer.deploy_all()
        self.assertEqual({name: result["status"] for name, result in deployer.get_results().items()},
                         {"R1": "FAILED", "S1": "OK"})
        self.assertEqual([item.args[0][2] for item in self.run.call_args_list],
                         ["clab-pilot-network-R1", "clab-pilot-network-R1", "clab-pilot-network-S1", "clab-pilot-network-S1"])
        self.assertIn("Total Devices: 2\nSuccessful: 1\nFailed: 1", self.output.getvalue())

    def test_main_returns_zero_only_when_all_target_deployments_succeed(self):
        self.write_inventory([self.records[0], self.records[5]])
        for verify_reply, expected in ((COMMUNITY_REPLY, 0), ("", 1)):
            with self.subTest(expected=expected):
                self.run.reset_mock()
                self.run.side_effect = [completed(), completed(verify_reply), completed(), completed(COMMUNITY_REPLY)]
                # Redirect the real CLI's adjacent inventory lookup into the temp directory.
                with patch.object(deploy, "__file__", str(self.root / "deploy_snmp.py")):
                    self.assertEqual(deploy.main(), expected)
                self.assertEqual(self.run.call_count, 4)


if __name__ == "__main__":
    unittest.main()

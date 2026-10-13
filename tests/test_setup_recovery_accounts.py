"""Offline recovery-account tests; synthetic credentials and mocked transports only."""

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

from security import setup_recovery_accounts as recovery


PASSWORD = "fixture-recovery-password-only"
ADMIN_PASSWORD = "fixture-admin-password-only"
HASH = "$6$fixtureSalt$" + "A" * 86
OTHER_HASH = "$6$anotherSalt$" + "B" * 86
TARGETS = ("R2", "R3", "R4", "R5", "S1", "S2", "S3", "S4")
INVENTORY = {
    "R1": "192.0.2.1", "R2": "192.0.2.2", "R3": "192.0.2.3",
    "R4": "192.0.2.4", "R5": "192.0.2.5", "S1": "192.0.2.6",
    "S2": "192.0.2.7", "S3": "192.0.2.8", "S4": "192.0.2.9",
}


def account(password_hash=HASH):
    return "username netpilot-recovery privilege 15 role network-admin secret sha512 " + password_hash


def config(name="R2", recovery_line=None, extra=""):
    lines = ["! Command: show running-config", "! device: " + name + " (cEOSLab, EOS-4.36.2F)",
             "!", "hostname " + name, "!", "username admin privilege 15 role network-admin secret sha512 " + OTHER_HASH,
             "aaa authentication login default local", "!", "interface Management0", "   no shutdown",
             "   ip address 192.0.2.2/24", "!"]
    if recovery_line is not None:
        lines[5:5] = [recovery_line]
    if extra:
        lines.append(extra)
    lines.append("end")
    return "\n".join(lines) + "\n"


class InventoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "devices.yml"
        self.data = {"devices": {name: {"hostname": name, "vendor": "Arista", "platform": "cEOSLab",
                                      "management": {"ipv4": address}}
                                 for name, address in INVENTORY.items()}}
        self.write()

    def write(self):
        self.path.write_text(yaml.safe_dump(self.data), encoding="utf-8")

    def test_exact_eight_devices_and_order_without_r1(self):
        result = recovery.discover_targets(self.path)
        self.assertEqual(tuple(result), TARGETS)
        self.assertEqual(result, {name: INVENTORY[name] for name in TARGETS})
        self.assertNotIn("R1", result)

    def test_addresses_come_from_inventory(self):
        self.data["devices"]["R2"]["management"]["ipv4"] = "198.51.100.20"
        self.write()
        self.assertEqual(recovery.discover_targets(self.path)["R2"], "198.51.100.20")

    def test_historical_test_devices_are_ignored(self):
        self.data["devices"]["Test-R11"] = {"password": "synthetic-not-real"}
        self.write()
        self.assertEqual(tuple(recovery.discover_targets(self.path)), TARGETS)

    def test_duplicate_address_is_rejected(self):
        self.data["devices"]["R2"]["management"]["ipv4"] = INVENTORY["R1"]
        self.write()
        with self.assertRaises(recovery.RecoveryError):
            recovery.discover_targets(self.path)

    def test_missing_target_is_rejected(self):
        del self.data["devices"]["S4"]
        self.write()
        with self.assertRaises(recovery.RecoveryError):
            recovery.discover_targets(self.path)


class HashTests(unittest.TestCase):
    def test_password_goes_only_through_stdin(self):
        completed = subprocess.CompletedProcess([], 0, stdout=HASH + "\n", stderr="")
        with patch.object(recovery.subprocess, "run", return_value=completed) as command:
            result = recovery.sha512_crypt(PASSWORD)
        self.assertEqual(result, HASH)
        arguments, options = command.call_args
        self.assertEqual(Path(arguments[0][0]).name, "openssl")
        self.assertEqual(arguments[0][1:3], ["passwd", "-6"])
        self.assertIn("-stdin", arguments[0])
        self.assertNotIn(PASSWORD, repr(arguments))
        self.assertIn(PASSWORD, options["input"])
        self.assertFalse(options.get("shell", False))

    def test_legacy_hashing_allows_short_original_only_when_explicit(self):
        legacy = "short-old"
        completed = subprocess.CompletedProcess([], 0, stdout=HASH + "\n", stderr="")
        with patch.object(recovery.subprocess, "run", return_value=completed) as command:
            with self.assertRaises(recovery.RecoveryError):
                recovery.sha512_crypt(legacy)
            command.assert_not_called()
            self.assertEqual(recovery.sha512_crypt(legacy, allow_legacy=True), HASH)
        arguments, options = command.call_args
        self.assertNotIn(legacy, repr(arguments))
        self.assertEqual(options["input"], legacy + "\n")
        self.assertFalse(options["shell"])

    def test_legacy_hashing_still_rejects_unsafe_input_before_subprocess(self):
        with patch.object(recovery.subprocess, "run") as command:
            for value in (None, "", "short\nsecond", "short\r", "short\x00", "X" * 129):
                with self.subTest(value_type=type(value).__name__):
                    with self.assertRaises(recovery.RecoveryError):
                        recovery.sha512_crypt(value, allow_legacy=True)
            command.assert_not_called()

    def test_hashing_failure_suppresses_private_diagnostic(self):
        error = subprocess.CalledProcessError(1, ["openssl"], output=PASSWORD, stderr=HASH)
        with patch.object(recovery.subprocess, "run", side_effect=error):
            with self.assertRaises(recovery.RecoveryError) as caught:
                recovery.sha512_crypt(PASSWORD)
        self.assertNotIn(PASSWORD, str(caught.exception))
        self.assertNotIn(HASH, str(caught.exception))

    def test_malformed_hash_is_rejected(self):
        for output in ("", "not-a-hash", "$5$salt$value", HASH + "\n" + HASH):
            with self.subTest(output_type=output[:2]):
                completed = subprocess.CompletedProcess([], 0, stdout=output, stderr="")
                with patch.object(recovery.subprocess, "run", return_value=completed):
                    with self.assertRaises(recovery.RecoveryError):
                        recovery.sha512_crypt(PASSWORD)

    def test_multiline_password_is_rejected_before_subprocess(self):
        with patch.object(recovery.subprocess, "run") as command:
            with self.assertRaises(recovery.RecoveryError):
                recovery.sha512_crypt(PASSWORD + "\nsecond-line")
        command.assert_not_called()


class ConfigTests(unittest.TestCase):
    def test_running_and_startup_command_headers_do_not_count_as_drift(self):
        running = recovery.normalize_config(config(), "R2")
        startup = recovery.normalize_config(config().replace("show running-config", "show startup-config"), "R2")
        self.assertEqual(running, startup)

    def test_unrelated_account_aaa_and_interface_are_preserved(self):
        before = recovery.normalize_config(config(), "R2")
        after = recovery.normalize_config(config(recovery_line=account()), "R2")
        self.assertEqual(recovery.without_recovery(after), before)
        self.assertTrue(any("username admin " in line for line in after))
        self.assertIn("aaa authentication login default local", after)
        self.assertIn("interface Management0", after)

    def test_recovery_account_records_are_detected_without_format_assumptions(self):
        self.assertEqual(recovery.recovery_account(recovery.normalize_config(config(), "R2")), ())
        parsed = recovery.normalize_config(config(recovery_line=account()), "R2")
        self.assertEqual(recovery.recovery_account(parsed), (account(),))

    def test_existing_account_format_is_preserved_for_login_verification(self):
        for line in (
                "username netpilot-recovery role network-admin privilege 15 secret sha512 " + HASH,
                "username netpilot-recovery privilege 15 role network-admin secret 5 synthetic-legacy-hash",
                "username netpilot-recovery privilege 15",
                "username netpilot-recovery role network-admin"):
            with self.subTest(attribute=line.split()[2]):
                parsed = recovery.normalize_config(config(recovery_line=line), "R2")
                self.assertEqual(recovery.recovery_account(parsed), (line,))

    def test_multiple_account_records_are_preserved_without_rejecting_existing_account(self):
        role = "username netpilot-recovery role network-admin"
        parsed = recovery.normalize_config(config(recovery_line=account(), extra=role), "R2")
        self.assertEqual(recovery.recovery_account(parsed), (account(), role))

    def test_account_detection_uses_exact_top_level_username(self):
        for line in ("username netpilot-recovery-other privilege 15", "   username netpilot-recovery privilege 15"):
            with self.subTest(line=line):
                parsed = recovery.normalize_config(config(extra=line), "R2")
                self.assertEqual(recovery.recovery_account(parsed), ())
                self.assertIn(line, recovery.without_recovery(parsed))

    def test_wrong_hostname_is_rejected(self):
        with self.assertRaises(recovery.RecoveryError):
            recovery.normalize_config(config("R1"), "R2")

    def test_banner_text_is_not_silently_removed_from_diff(self):
        with self.assertRaises(recovery.RecoveryError):
            recovery.normalize_config(config(extra="banner login\n! an arbitrary banner\nEOF"), "R2")


class FakeConnection:
    def __init__(self, network, name, username):
        self.network, self.name, self.username = network, name, username
        self.disconnected = False
        self.enabled = network.initial_enabled
        self.counts = {}

    def check_enable_mode(self):
        self.network.events.append(("check_enable", self.name, self.username))
        if self.network.enable_mode_error is not None:
            raise self.network.enable_mode_error
        return self.enabled

    def enable(self):
        self.network.events.append(("enable", self.name, self.username))
        if self.network.enable_error is not None:
            raise self.network.enable_error
        if not self.network.ignore_enable:
            self.enabled = True
        return ""

    def send_command(self, command, **options):
        if not self.enabled:
            raise AssertionError("Privileged read attempted before entering enable mode")
        self.network.events.append(("read", self.name, self.username, command))
        self.counts[command] = self.counts.get(command, 0) + 1
        if self.network.hook:
            response = self.network.hook(self, command, self.counts[command])
            if response is not None:
                return response
        if command == "show hostname | json":
            return json.dumps({"hostname": self.name})
        if command == "show version | json":
            return json.dumps({"modelName": "cEOSLab", "version": "4.36.2F"})
        if command == "show privilege":
            return "Current privilege level is 15"
        if command in ("show users accounts", "show users detail"):
            raise AssertionError("Recovery setup must not depend on custom AAA table parsing")
        if command == "show running-config":
            return self.network.states[self.name]["running"]
        if command == "show startup-config":
            return self.network.states[self.name]["startup"].replace("show running-config", "show startup-config")
        raise AssertionError("Unrecognized mock read command")

    def send_config_set(self, commands, **options):
        self.network.events.append(("write", self.name, self.username))
        self.network.writes.append((self.name, list(commands)))
        if not self.network.ignore_write:
            self.network.states[self.name]["running"] = config(self.name, commands[0])
        if self.network.write_error is not None:
            raise self.network.write_error
        return ""

    def save_config(self):
        self.network.events.append(("save", self.name, self.username))
        self.network.saves.append(self.name)
        if not self.network.ignore_save:
            self.network.states[self.name]["startup"] = self.network.states[self.name]["running"]
        if self.network.save_error is not None:
            raise self.network.save_error
        return "Copy completed successfully."

    def disconnect(self):
        self.disconnected = True
        self.network.events.append(("disconnect", self.name, self.username))


class FakeNetwork:
    def __init__(self, existing=False):
        self.states = {name: {"running": config(name, account() if existing else None),
                              "startup": config(name, account() if existing else None)} for name in TARGETS}
        self.events, self.writes, self.saves, self.connections, self.arguments = [], [], [], [], []
        self.hook = None
        self.ignore_write = self.ignore_save = False
        self.write_error = self.save_error = None
        self.fail_name = self.rejected_username = None
        self.initial_enabled = False
        self.enable_mode_error = self.enable_error = None
        self.ignore_enable = False

    def connect(self, **kwargs):
        name = next(name for name, address in INVENTORY.items() if address == kwargs["host"])
        self.arguments.append(dict(kwargs))
        if name == self.fail_name or kwargs["username"] == self.rejected_username:
            raise RuntimeError("mock diagnostic " + PASSWORD + " " + HASH)
        self.events.append(("connect", name, kwargs["username"]))
        connection = FakeConnection(self, name, kwargs["username"])
        self.connections.append(connection)
        return connection


class FlowTests(unittest.TestCase):
    def setUp(self):
        self.inventory = {name: INVENTORY[name] for name in TARGETS}
        self.network = FakeNetwork()
        for attribute, options in (
                ("discover_targets", {"return_value": self.inventory}),
                ("ConnectHandler", {"side_effect": self.network.connect}),
                ("sha512_crypt", {"return_value": HASH})):
            patcher = patch.object(recovery, attribute, **options)
            setattr(self, attribute, patcher.start())
            self.addCleanup(patcher.stop)
        patcher = patch.object(recovery.credential_provider, "get_credentials", return_value=("admin", ADMIN_PASSWORD))
        self.credentials = patcher.start()
        self.addCleanup(patcher.stop)
        self.output = io.StringIO()

    def configure(self, **kwargs):
        with redirect_stdout(self.output):
            result = recovery.configure_all(self.inventory, PASSWORD, authorized=True,
                                            confirmation=recovery.CONFIRMATION, **kwargs)
        for secret in (PASSWORD, ADMIN_PASSWORD, HASH, OTHER_HASH):
            self.assertNotIn(secret, self.output.getvalue())
            self.assertNotIn(secret, repr(result))
        return result

    def verify(self):
        with redirect_stdout(self.output):
            return recovery.verify_all(self.inventory, PASSWORD)

    def test_configuration_requires_authorization_before_credentials_or_connection(self):
        for kwargs in ({}, {"authorized": True}, {"authorized": True, "confirmation": "yes"},
                       {"authorized": False, "confirmation": recovery.CONFIRMATION}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(recovery.RecoveryError):
                    recovery.configure_all(self.inventory, PASSWORD, **kwargs)
        self.credentials.assert_not_called()
        self.ConnectHandler.assert_not_called()
        self.sha512_crypt.assert_not_called()

    def test_all_eight_are_sequentially_verified_before_save_and_r1_excluded(self):
        result = self.configure()
        self.assertEqual([row["device"] for row in result], list(TARGETS))
        self.assertEqual([row["status"] for row in result], ["PASS"] * 8)
        self.assertEqual(self.network.saves, list(TARGETS))
        self.assertEqual([name for name, _ in self.network.writes], list(TARGETS))
        self.assertEqual(len(self.network.connections), 16)
        for name, commands in self.network.writes:
            self.assertEqual(commands, [account()])
            login = self.network.events.index(("connect", name, "netpilot-recovery"))
            privilege = self.network.events.index(("read", name, "netpilot-recovery", "show privilege"))
            saved = self.network.events.index(("save", name, "admin"))
            self.assertLess(login, privilege)
            self.assertLess(privilege, saved)
        for previous, following in zip(TARGETS, TARGETS[1:]):
            self.assertLess(self.network.events.index(("save", previous, "admin")),
                            self.network.events.index(("connect", following, "admin")))
        self.assertTrue(all(connection.disconnected for connection in self.network.connections))
        self.assertNotIn(INVENTORY["R1"], [entry["host"] for entry in self.network.arguments])
        for entry in self.network.arguments:
            self.assertEqual(entry["device_type"], "arista_eos")
            self.assertEqual(entry["password"], ADMIN_PASSWORD if entry["username"] == "admin" else PASSWORD)
            self.assertFalse(entry["ssh_strict"])
            self.assertFalse(entry["system_host_keys"])
            self.assertFalse(entry["use_keys"])
            self.assertFalse(entry["allow_agent"])
            self.assertIsNone(entry["session_log"])
            self.assertFalse(entry["session_log_record_writes"])

    def test_admin_and_fresh_recovery_user_exec_sessions_enable_before_reads(self):
        result = self.configure()
        self.assertTrue(all(row["status"] == "PASS" for row in result))
        for name in TARGETS:
            for username in ("admin", "netpilot-recovery"):
                events = [event for event in self.network.events if event[1:3] == (name, username)]
                enabled = next(index for index, event in enumerate(events) if event[0] == "enable")
                first_read = next(index for index, event in enumerate(events) if event[0] == "read")
                self.assertLess(enabled, first_read)
                self.assertEqual(sum(event[0] == "enable" for event in events), 1)
                self.assertIn(("read", name, username, "show privilege"), events)
                self.assertGreaterEqual(sum(event[0] == "check_enable" for event in events), 2)
        self.assertTrue(all("secret" not in entry for entry in self.network.arguments))

    def test_privileged_exec_sessions_skip_enable_but_verify_actual_privilege(self):
        self.network.initial_enabled = True
        result = self.configure()
        self.assertTrue(all(row["status"] == "PASS" for row in result))
        self.assertFalse(any(event[0] == "enable" for event in self.network.events))
        for name in TARGETS:
            for username in ("admin", "netpilot-recovery"):
                self.assertIn(("read", name, username, "show privilege"), self.network.events)

    def test_failed_enable_is_sanitized_stops_and_disconnects_before_writes(self):
        for error in (RuntimeError(PASSWORD + HASH), TimeoutError(ADMIN_PASSWORD + OTHER_HASH)):
            with self.subTest(error=type(error).__name__):
                self.network.enable_error = error
                result = self.configure()
                self.assertEqual(result[0]["error"], "enable_failed")
                self.assertFalse(result[0]["changed"])
                self.assertEqual([row["status"] for row in result], ["FAIL"] + ["SKIP"] * 7)
                self.assertTrue(all(connection.disconnected for connection in self.network.connections))
                self.assertEqual(self.network.writes, [])
                self.assertEqual(self.network.saves, [])
                self.assertFalse(any(event[0] == "read" for event in self.network.events))

    def test_enable_mode_check_failure_is_sanitized_and_disconnects(self):
        self.network.enable_mode_error = TimeoutError(PASSWORD + HASH)
        result = self.configure()
        self.assertEqual(result[0]["error"], "enable_failed")
        self.assertTrue(all(connection.disconnected for connection in self.network.connections))
        self.assertEqual(self.network.writes, [])
        self.assertEqual(self.network.saves, [])

    def test_enable_returning_without_privileged_mode_is_rejected(self):
        self.network.ignore_enable = True
        result = self.configure()
        self.assertEqual(result[0]["error"], "enable_mode")
        self.assertTrue(all(connection.disconnected for connection in self.network.connections))
        self.assertEqual(self.network.writes, [])
        self.assertEqual(self.network.saves, [])
        self.assertFalse(any(event[0] == "read" for event in self.network.events))

    def test_enabled_prompt_does_not_bypass_actual_session_privilege(self):
        self.network.initial_enabled = True
        self.network.hook = lambda connection, command, count: "Current privilege level is 1" if command == "show privilege" else None
        result = self.configure()
        self.assertEqual(result[0]["error"], "privilege")
        self.assertEqual(self.network.writes, [])
        self.assertEqual(self.network.saves, [])
        self.assertTrue(all(connection.disconnected for connection in self.network.connections))

    def test_missing_malformed_or_denied_privilege_output_is_diagnostic(self):
        for output in ("", "Current privilege level is unknown", "% Authorization denied", "Current privilege level is 15\n" + HASH):
            with self.subTest(response=output[:10]):
                self.network.hook = lambda connection, command, count: output if command == "show privilege" else None
                result = self.configure()
                self.assertEqual(result[0]["error"], "privilege_read")
                self.assertEqual(self.network.writes, [])
                self.assertEqual(self.network.saves, [])

    def test_privilege_query_exception_is_sanitized_and_classified(self):
        def hook(connection, command, count):
            if command == "show privilege":
                raise TimeoutError(PASSWORD + HASH)
        self.network.hook = hook
        result = self.configure()
        self.assertEqual(result[0]["error"], "privilege_read")
        self.assertEqual(self.network.writes, [])
        self.assertEqual(self.network.saves, [])

    def test_configuration_does_not_query_custom_aaa_tables(self):
        result = self.configure()
        self.assertTrue(all(row["status"] == "PASS" for row in result))
        commands = [event[3] for event in self.network.events if event[0] == "read"]
        self.assertNotIn("show users accounts", commands)
        self.assertNotIn("show users detail", commands)

    def test_independent_verification_does_not_query_custom_aaa_tables(self):
        self.network.states = FakeNetwork(existing=True).states
        result = self.verify()
        self.assertTrue(all(row["status"] == "PASS" for row in result))
        commands = [event[3] for event in self.network.events if event[0] == "read"]
        self.assertNotIn("show users accounts", commands)
        self.assertNotIn("show users detail", commands)

    def test_existing_account_login_failure_is_not_overwritten_or_saved(self):
        self.network.states = FakeNetwork(existing=True).states
        self.network.rejected_username = "netpilot-recovery"
        result = self.configure()
        self.assertEqual([row["status"] for row in result], ["FAIL"] + ["SKIP"] * 7)
        self.assertFalse(result[0]["changed"])
        self.assertEqual([entry["username"] for entry in self.network.arguments], ["admin", "netpilot-recovery"])
        self.assertEqual(self.network.writes, [])
        self.assertEqual(self.network.saves, [])
        self.sha512_crypt.assert_not_called()

    def test_fresh_recovery_privilege_failure_prevents_save(self):
        def hook(connection, command, count):
            if connection.username == "netpilot-recovery" and command == "show privilege":
                return "Current privilege level is 1"
        self.network.hook = hook
        result = self.configure()
        self.assertEqual(result[0]["error"], "privilege")
        self.assertEqual(len(self.network.writes), 1)
        self.assertEqual(self.network.saves, [])
        self.assertEqual([row["status"] for row in result], ["FAIL"] + ["SKIP"] * 7)

    def test_independent_verification_enters_enable_mode_and_preserves_read_only_flow(self):
        self.network.states = FakeNetwork(existing=True).states
        result = self.verify()
        self.assertTrue(all(row["status"] == "PASS" for row in result))
        self.assertEqual(sum(event[0] == "enable" for event in self.network.events), 8)
        self.assertTrue(all(connection.disconnected for connection in self.network.connections))
        self.credentials.assert_not_called()
        self.assertEqual(self.network.writes, [])
        self.assertEqual(self.network.saves, [])

    def test_existing_account_is_verified_without_rewriting_saving_or_hashing(self):
        self.network.states = FakeNetwork(existing=True).states
        self.sha512_crypt.side_effect = AssertionError("Existing accounts must not require OpenSSL")
        result = self.configure()
        self.assertTrue(all(row["status"] == "PASS" and row["changed"] is False and row["saved"] for row in result))
        self.assertEqual(self.network.writes, [])
        self.assertEqual(self.network.saves, [])
        self.sha512_crypt.assert_not_called()

    def test_account_only_unsaved_creation_is_verified_then_saved(self):
        self.network.states["R2"]["running"] = config("R2", account())
        result = self.configure()
        self.assertEqual(result[0]["status"], "PASS")
        self.assertFalse(result[0]["changed"])
        self.assertNotIn("R2", [name for name, _ in self.network.writes])
        self.assertIn("R2", self.network.saves)

    def test_unrelated_unsaved_changes_block_before_any_device_write(self):
        self.network.states["R2"]["running"] = config("R2", extra="ip route 198.51.100.0/24 192.0.2.3")
        result = self.configure()
        self.assertEqual(result[0]["error"], "unsaved_changes")
        self.assertEqual([row["status"] for row in result], ["FAIL"] + ["SKIP"] * 7)
        self.assertEqual(self.network.writes, [])
        self.assertEqual(self.network.saves, [])

    def test_existing_account_variants_are_verified_and_preserved(self):
        variants = (
            "username netpilot-recovery role network-admin privilege 15 secret sha512 " + HASH,
            "username netpilot-recovery privilege 15 role network-admin secret 5 synthetic-legacy-hash",
            "username netpilot-recovery privilege 15\nusername netpilot-recovery role network-admin",
        )
        for line in variants:
            with self.subTest(format=line.split()[2]):
                self.network.states = {name: {"running": config(name, line), "startup": config(name, line)}
                                       for name in TARGETS}
                before = {name: dict(state) for name, state in self.network.states.items()}
                result = self.configure()
                self.assertTrue(all(row["status"] == "PASS" for row in result))
                self.assertEqual(self.network.states, before)
                self.assertEqual(self.network.writes, [])
                self.assertEqual(self.network.saves, [])
                self.sha512_crypt.assert_not_called()

    def test_existing_account_login_is_attempted_before_unsaved_changes_gate(self):
        self.network.states["R2"] = {"running": config("R2", account(), "ip routing"),
                                     "startup": config("R2", account())}
        result = self.configure()
        self.assertEqual(result[0]["error"], "unsaved_changes")
        self.assertIn(("read", "R2", "netpilot-recovery", "show privilege"), self.network.events)
        self.assertEqual(self.network.writes, [])
        self.assertEqual(self.network.saves, [])
        self.sha512_crypt.assert_not_called()

    def test_existing_startup_account_difference_is_not_saved_after_fresh_login(self):
        self.network.states["R2"] = {"running": config("R2", account()),
                                     "startup": config("R2", account(OTHER_HASH))}
        result = self.configure()
        self.assertEqual(result[0]["error"], "account_conflict")
        self.assertIn(("read", "R2", "netpilot-recovery", "show privilege"), self.network.events)
        self.assertEqual(self.network.writes, [])
        self.assertEqual(self.network.saves, [])
        self.sha512_crypt.assert_not_called()

    def test_startup_only_account_is_not_automatically_recreated(self):
        self.network.states["R2"]["startup"] = config("R2", account())
        result = self.configure()
        self.assertEqual(result[0]["error"], "account_conflict")
        self.assertEqual(self.network.writes, [])
        self.assertEqual(self.network.saves, [])
        self.sha512_crypt.assert_not_called()

    def test_failure_stops_after_successful_previous_device(self):
        self.network.fail_name = "R3"
        result = self.configure()
        self.assertEqual([row["status"] for row in result], ["PASS", "FAIL"] + ["SKIP"] * 6)
        self.assertEqual(self.network.saves, ["R2"])
        self.assertEqual({row["host"] for row in self.network.arguments}, {INVENTORY["R2"], INVENTORY["R3"]})

    def test_apply_timeout_or_interrupt_is_ambiguous_and_never_saved(self):
        for error in (TimeoutError(PASSWORD + HASH), KeyboardInterrupt()):
            with self.subTest(error_type=type(error).__name__):
                self.network.write_error = error
                result = self.configure()
                self.assertIsNone(result[0]["changed"])
                self.assertIsNone(result[0]["saved"])
                self.assertEqual(result[0]["status"], "FAIL")
                self.assertEqual(self.network.saves, [])
                self.network.states = FakeNetwork().states

    def test_fresh_authentication_failure_prevents_save_and_stops(self):
        def hook(connection, command, count):
            if connection.username == "netpilot-recovery":
                raise RuntimeError(PASSWORD + HASH)
        self.network.hook = hook
        result = self.configure()
        self.assertEqual(result[0]["status"], "FAIL")
        self.assertEqual(self.network.saves, [])
        self.assertEqual(len(self.network.writes), 1)
        self.assertTrue(all(row["status"] == "SKIP" for row in result[1:]))

    def test_existing_account_without_privileged_access_is_not_overwritten(self):
        self.network.states = FakeNetwork(existing=True).states
        self.network.hook = lambda connection, command, count: (
            "Current privilege level is 1" if command == "show privilege"
            and connection.username == "netpilot-recovery" else None)
        result = self.configure()
        self.assertEqual(result[0]["error"], "privilege")
        self.assertFalse(result[0]["changed"])
        self.assertEqual(self.network.writes, [])
        self.assertEqual(self.network.saves, [])
        self.sha512_crypt.assert_not_called()

    def test_running_drift_during_new_login_blocks_save(self):
        def hook(connection, command, count):
            if connection.username == "netpilot-recovery" and command == "show running-config":
                self.network.states["R2"]["running"] = config("R2", account(), "ip routing")
        self.network.hook = hook
        result = self.configure()
        self.assertEqual(result[0]["error"], "concurrent_change")
        self.assertEqual(self.network.saves, [])

    def test_startup_drift_during_fresh_verification_is_unknown_and_never_saved(self):
        def hook(connection, command, count):
            if connection.username == "netpilot-recovery" and command == "show startup-config":
                self.network.states["R2"]["startup"] = config("R2", extra="ip routing")
        self.network.hook = hook
        result = self.configure()
        self.assertEqual(result[0]["status"], "FAIL")
        self.assertEqual(result[0]["error"], "concurrent_change")
        self.assertIsNone(result[0]["saved"])
        self.assertEqual(self.network.saves, [])

    def test_startup_or_running_drift_immediately_before_save_blocks_save(self):
        for key in ("running", "startup"):
            with self.subTest(config_type=key):
                def hook(connection, command, count):
                    if connection.username == "admin" and command == "show running-config" and count == 3:
                        self.network.states["R2"][key] = config("R2", account() if key == "running" else None, "ip routing")
                self.network.hook = hook
                result = self.configure()
                self.assertEqual(result[0]["error"], "concurrent_change")
                self.assertEqual(self.network.saves, [])
                self.network.states = FakeNetwork().states

    def test_save_readback_mismatch_is_not_reported_as_success(self):
        self.network.ignore_save = True
        result = self.configure()
        self.assertEqual(result[0]["status"], "FAIL")
        self.assertEqual(result[0]["error"], "save")
        self.assertIsNone(result[0]["saved"])
        self.assertEqual(self.network.saves, ["R2"])
        self.assertEqual([row["status"] for row in result[1:]], ["SKIP"] * 7)

    def test_verify_is_recovery_only_and_does_not_read_vault_or_write(self):
        self.network.states = FakeNetwork(existing=True).states
        result = self.verify()
        self.assertTrue(all(row["status"] == "PASS" for row in result))
        self.credentials.assert_not_called()
        self.sha512_crypt.assert_not_called()
        self.assertEqual(len(self.network.connections), 8)
        self.assertTrue(all(row["username"] == "netpilot-recovery" for row in self.network.arguments))
        for entry in self.network.arguments:
            self.assertEqual(entry["device_type"], "arista_eos")
            self.assertEqual(entry["password"], PASSWORD)
            self.assertFalse(entry["ssh_strict"])
            self.assertFalse(entry["system_host_keys"])
            self.assertFalse(entry["use_keys"])
            self.assertFalse(entry["allow_agent"])
        self.assertEqual(self.network.writes, [])
        self.assertEqual(self.network.saves, [])

    def test_verify_requires_recovery_account_in_startup(self):
        self.network.states = FakeNetwork(existing=True).states
        self.network.states["R2"]["startup"] = config("R2")
        result = self.verify()
        self.assertEqual(result[0]["error"], "save")
        self.assertTrue(all(row["status"] == "SKIP" for row in result[1:]))
        self.assertEqual(self.network.writes, [])
        self.assertEqual(self.network.saves, [])

    def test_admin_credentials_must_be_named_admin_and_separate_from_recovery(self):
        for value in (("other-user", ADMIN_PASSWORD), ("admin", PASSWORD)):
            with self.subTest(username=value[0]):
                self.credentials.return_value = value
                with self.assertRaises(recovery.RecoveryError):
                    self.configure()
        self.ConnectHandler.assert_not_called()
        self.sha512_crypt.assert_not_called()

    def test_r1_connection_is_refused_before_netmiko(self):
        with self.assertRaises(recovery.RecoveryError):
            recovery._connect("R1", INVENTORY["R1"], "admin", ADMIN_PASSWORD)
        self.ConnectHandler.assert_not_called()

    def test_wrong_hostname_prevents_all_writes(self):
        self.network.hook = lambda connection, command, count: json.dumps({"hostname": "R1"}) if command == "show hostname | json" else None
        result = self.configure()
        self.assertEqual(result[0]["error"], "identity")
        self.assertEqual(self.network.writes, [])
        self.assertEqual(self.network.saves, [])

    def test_transport_logging_setting_is_restored_after_failure(self):
        previous = recovery.logging.root.manager.disable
        recovery.logging.disable(23)
        self.addCleanup(recovery.logging.disable, previous)
        self.network.fail_name = "R2"
        self.configure()
        self.assertEqual(recovery.logging.root.manager.disable, 23)

    def test_dry_run_never_reads_credentials_prompts_hashes_or_connects(self):
        with patch.object(recovery, "prompt_password") as prompt:
            for args in (["--dry-run"], ["configure", "--dry-run"], ["verify", "--dry-run"]):
                with redirect_stdout(self.output):
                    self.assertEqual(recovery.main(args), 0)
            prompt.assert_not_called()
        self.credentials.assert_not_called()
        self.sha512_crypt.assert_not_called()
        self.ConnectHandler.assert_not_called()

    def test_configure_cli_without_execute_never_prompts_or_reads_credentials(self):
        with patch.object(recovery, "prompt_password") as prompt, redirect_stdout(self.output):
            self.assertEqual(recovery.main(["configure"]), 1)
            prompt.assert_not_called()
        self.credentials.assert_not_called()
        self.ConnectHandler.assert_not_called()

    def test_incorrect_cli_confirmation_prevents_secret_prompt(self):
        with patch.object(recovery.sys.stdin, "isatty", return_value=True), \
                patch("builtins.input", return_value="yes"), \
                patch.object(recovery, "prompt_password") as prompt, redirect_stdout(self.output):
            self.assertEqual(recovery.main(["configure", "--execute"]), 1)
            prompt.assert_not_called()
        self.credentials.assert_not_called()
        self.ConnectHandler.assert_not_called()


class PromptTests(unittest.TestCase):
    def test_noninteractive_password_prompt_is_refused_before_getpass(self):
        with patch.object(recovery.sys.stdin, "isatty", return_value=False), \
                patch.object(recovery.getpass, "getpass") as prompt:
            with self.assertRaises(recovery.RecoveryError):
                recovery.prompt_password()
            prompt.assert_not_called()

    def test_configuration_password_requires_matching_hidden_confirmation(self):
        with patch.object(recovery.sys.stdin, "isatty", return_value=True), \
                patch.object(recovery.getpass, "getpass", side_effect=[PASSWORD, PASSWORD]) as prompt:
            self.assertEqual(recovery.prompt_password(confirm=True), PASSWORD)
            self.assertEqual(prompt.call_count, 2)
        with patch.object(recovery.sys.stdin, "isatty", return_value=True), \
                patch.object(recovery.getpass, "getpass", side_effect=[PASSWORD, ADMIN_PASSWORD]):
            with self.assertRaises(recovery.RecoveryError):
                recovery.prompt_password(confirm=True)

    def test_echoing_getpass_fallback_is_blocked(self):
        def unavailable_hidden_input(prompt):
            recovery.warnings.warn("mock terminal cannot hide input", recovery.getpass.GetPassWarning)
            raise AssertionError("Must stop before an echoing fallback reads the password")
        with patch.object(recovery.sys.stdin, "isatty", return_value=True), \
                patch.object(recovery.getpass, "getpass", side_effect=unavailable_hidden_input):
            with self.assertRaises(recovery.getpass.GetPassWarning):
                recovery.prompt_password()

    def test_password_policy_rejects_short_control_and_overlong_values(self):
        for value in (None, "short", PASSWORD + "\x00", PASSWORD + "\r", "X" * 129):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(recovery.RecoveryError):
                    recovery.validate_password(value)


class LockTests(unittest.TestCase):
    def test_second_configuration_controller_cannot_acquire_existing_lock(self):
        with recovery.configuration_lock():
            with self.assertRaises(recovery.RecoveryError) as caught:
                with recovery.configuration_lock():
                    self.fail("Concurrent configuration lock must not succeed")
        self.assertEqual(caught.exception.category, "locked")


if __name__ == "__main__":
    unittest.main()

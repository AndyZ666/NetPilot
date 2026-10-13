"""Offline R1 password-change checks; all credentials and SSH sessions are fake."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import unittest
from unittest.mock import patch

from security import test_r1_password_change as script


ADMIN_PASSWORD = "synthetic-admin-password-only"
FIRST_PASSWORD = "synthetic-first-password-only"
SECOND_PASSWORD = "synthetic-second-password-only"
FIRST_HASH = "$6$firstFixture$" + "A" * 86
SECOND_HASH = "$6$secondFixture$" + "B" * 86
OTHER_HASH = "$6$otherFixture$" + "C" * 86


def account(password_hash=FIRST_HASH):
    return ("username netpilot-rotation-test privilege 15 role network-admin "
            "secret sha512 " + password_hash)


def config(extra=""):
    lines = [
        "! Command: show running-config", "!", "hostname R1", "!",
        "username admin privilege 15 role network-admin secret sha512 " + OTHER_HASH,
        "username netpilot-recovery privilege 15 role network-admin secret sha512 " + OTHER_HASH,
        "aaa authentication login default local", "!", "interface Management0",
        "   no shutdown", "   ip address 172.20.20.13/24", "!",
    ]
    if extra:
        lines.append(extra)
    return "\n".join(lines + ["end"]) + "\n"


class FakeConnection:
    def __init__(self, network, username):
        self.network, self.username = network, username
        self.enabled = False
        self.disconnected = False

    def check_enable_mode(self):
        return self.enabled

    def enable(self):
        self.network.events.append(("enable", self.username))
        self.enabled = True
        return ""

    def send_command(self, command, **kwargs):
        if not self.enabled:
            raise AssertionError("Privileged reads require enable mode")
        self.network.events.append(("read", self.username, command))
        if command == "show hostname | json":
            return json.dumps({"hostname": "R1"})
        if command == "show version | json":
            return json.dumps({"modelName": "cEOSLab", "version": "4.36.2F"})
        if command == "show privilege":
            return "Current privilege level is " + str(self.network.privilege)
        if command == "show running-config":
            return self.network.running
        if command == "show startup-config":
            return self.network.startup.replace("show running-config", "show startup-config")
        raise AssertionError("Unexpected mock read command")

    def send_config_set(self, commands, **kwargs):
        if not self.enabled:
            raise AssertionError("Configuration requires enable mode")
        commands = list(commands)
        if len(commands) != 1:
            raise AssertionError("Only one test-account command may be submitted")
        command = commands[0]
        if command not in (account(FIRST_HASH), account(SECOND_HASH),
                           "no username netpilot-rotation-test"):
            raise AssertionError("Non-test-account configuration was attempted")
        self.network.writes.append(command)
        self.network.events.append(("write", command))
        if command == "no username netpilot-rotation-test" and self.network.fail_delete:
            raise RuntimeError("synthetic secret diagnostic " + FIRST_PASSWORD + " " + FIRST_HASH)
        lines = [line for line in self.network.running.splitlines()
                 if not line.startswith("username netpilot-rotation-test ")]
        if not command.startswith("no username "):
            lines.insert(lines.index("end"), command)
        self.network.running = "\n".join(lines) + "\n"
        if len(self.network.writes) == self.network.fail_after_write:
            raise TimeoutError("synthetic secret diagnostic " + SECOND_PASSWORD + " " + SECOND_HASH)
        return ""

    def save_config(self, **kwargs):
        self.network.saves += 1
        raise AssertionError("Temporary test accounts must never be saved")

    def disconnect(self):
        self.disconnected = True
        self.network.events.append(("disconnect", self.username))


class FakeNetwork:
    def __init__(self):
        self.running = config()
        self.startup = config()
        self.arguments, self.connections, self.events, self.writes = [], [], [], []
        self.saves = 0
        self.privilege = 15
        self.fail_after_write = None
        self.fail_login_password = None
        self.fail_delete = False
        self.hijack_before_cleanup = False
        self.admin_connections = 0

    def connect(self, **kwargs):
        self.arguments.append(kwargs)
        if kwargs["host"] != "172.20.20.13":
            raise AssertionError("The test may connect only to R1")
        username, password = kwargs["username"], kwargs["password"]
        if username == "admin":
            if password != ADMIN_PASSWORD:
                raise AssertionError("Admin credentials must come from the provider")
            self.admin_connections += 1
            if self.admin_connections > 1 and self.hijack_before_cleanup:
                self.running = config(account(OTHER_HASH))
        elif username == "netpilot-rotation-test":
            expected = {FIRST_PASSWORD: FIRST_HASH, SECOND_PASSWORD: SECOND_HASH}.get(password)
            if (expected is None or account(expected) not in self.running.splitlines()
                    or password == self.fail_login_password):
                raise RuntimeError("synthetic authentication diagnostic " + password + " " + FIRST_HASH)
        else:
            raise AssertionError("Unexpected account login")
        self.events.append(("connect", username, password))
        connection = FakeConnection(self, username)
        self.connections.append(connection)
        return connection


class PasswordChangeTests(unittest.TestCase):
    def setUp(self):
        self.network = FakeNetwork()
        self.output = io.StringIO()
        self.credentials = self.enterContext(patch.object(
            script.credential_provider, "get_credentials", return_value=("admin", ADMIN_PASSWORD)))
        self.connect = self.enterContext(patch.object(
            script, "ConnectHandler", side_effect=self.network.connect))
        self.hashing = self.enterContext(patch.object(
            script.recovery, "sha512_crypt", side_effect=[FIRST_HASH, SECOND_HASH]))
        self.random_password = self.enterContext(patch.object(
            script.secrets, "token_urlsafe", side_effect=[FIRST_PASSWORD, SECOND_PASSWORD]))
        self.prompt = self.enterContext(patch("builtins.input", side_effect=AssertionError("No confirmation prompt")))

    def run_script(self, *arguments):
        with redirect_stdout(self.output), redirect_stderr(self.output):
            result = script.main(list(arguments))
        for secret in (ADMIN_PASSWORD, FIRST_PASSWORD, SECOND_PASSWORD,
                       FIRST_HASH, SECOND_HASH, OTHER_HASH):
            self.assertNotIn(secret, self.output.getvalue())
        self.assertEqual(self.network.saves, 0)
        self.prompt.assert_not_called()
        return result

    def test_dry_run_never_reads_vault_connects_or_generates_credentials(self):
        self.assertEqual(self.run_script("--dry-run"), 0)
        self.credentials.assert_not_called()
        self.connect.assert_not_called()
        self.hashing.assert_not_called()
        self.random_password.assert_not_called()

    def test_success_creates_changes_rolls_back_and_removes_only_test_account(self):
        original_running, original_startup = self.network.running, self.network.startup
        self.assertEqual(self.run_script("--execute"), 0)
        self.assertEqual(self.network.writes, [account(FIRST_HASH), account(SECOND_HASH),
                                              account(FIRST_HASH), "no username netpilot-rotation-test"])
        test_logins = [event[2] for event in self.network.events
                       if event[:2] == ("connect", "netpilot-rotation-test")]
        self.assertEqual(test_logins, [FIRST_PASSWORD, SECOND_PASSWORD, FIRST_PASSWORD])
        self.assertEqual(self.network.running, original_running)
        self.assertEqual(self.network.startup, original_startup)
        self.assertGreaterEqual(self.network.admin_connections, 2)
        self.assertTrue(all(connection.disconnected for connection in self.network.connections))
        self.assertEqual(self.hashing.call_args_list[0].args, (FIRST_PASSWORD,))
        self.assertEqual(self.hashing.call_args_list[1].args, (SECOND_PASSWORD,))
        self.assertIn("PASS", self.output.getvalue())
        self.assertNotIn("FAIL", self.output.getvalue())

    def test_ssh_policy_is_relaxed_only_for_host_keys_and_privilege_uses_enable(self):
        self.assertEqual(self.run_script("--execute"), 0)
        for arguments in self.network.arguments:
            self.assertEqual(arguments["device_type"], "arista_eos")
            self.assertEqual(arguments["host"], "172.20.20.13")
            self.assertFalse(arguments.get("ssh_strict", False))
            self.assertFalse(arguments.get("system_host_keys", False))
            self.assertFalse(arguments.get("use_keys", False))
            self.assertFalse(arguments.get("allow_agent", False))
            self.assertIsNone(arguments.get("session_log"))
        for connection in self.network.connections:
            self.assertTrue(connection.enabled)
        self.assertTrue(any(event[0] == "read" and event[2] == "show privilege"
                            for event in self.network.events))

    def test_existing_account_in_running_or_startup_is_never_modified(self):
        for location in ("running", "startup"):
            with self.subTest(location=location):
                self.network = FakeNetwork()
                self.connect.side_effect = self.network.connect
                setattr(self.network, location, config(account(OTHER_HASH)))
                original = (self.network.running, self.network.startup)
                self.assertEqual(self.run_script("--execute"), 1)
                self.assertEqual(self.network.writes, [])
                self.assertEqual((self.network.running, self.network.startup), original)
        self.hashing.assert_not_called()
        self.random_password.assert_not_called()

    def test_existing_unrelated_unsaved_changes_are_preserved_without_save(self):
        self.network.running = config("ip route 192.0.2.0/24 Null0")
        original = (self.network.running, self.network.startup)
        self.assertNotEqual(*original)
        self.assertEqual(self.run_script("--execute"), 0)
        self.assertEqual((self.network.running, self.network.startup), original)

    def test_insufficient_actual_privilege_fails_before_configuration(self):
        self.network.privilege = 1
        self.assertEqual(self.run_script("--execute"), 1)
        self.assertEqual(self.network.writes, [])
        self.assertIn("FAIL", self.output.getvalue())

    def test_create_timeout_after_apply_attempts_cleanup_and_hides_diagnostics(self):
        original = (self.network.running, self.network.startup)
        self.network.fail_after_write = 1
        self.assertEqual(self.run_script("--execute"), 1)
        self.assertEqual(self.network.writes, [account(FIRST_HASH), "no username netpilot-rotation-test"])
        self.assertEqual((self.network.running, self.network.startup), original)
        self.assertIn("FAIL", self.output.getvalue())

    def test_update_timeout_after_apply_cleans_up_updated_test_account(self):
        original = (self.network.running, self.network.startup)
        self.network.fail_after_write = 2
        self.assertEqual(self.run_script("--execute"), 1)
        self.assertEqual(self.network.writes, [account(FIRST_HASH), account(SECOND_HASH),
                                              "no username netpilot-rotation-test"])
        self.assertEqual((self.network.running, self.network.startup), original)

    def test_new_password_login_failure_cleans_up_the_temporary_account(self):
        original = (self.network.running, self.network.startup)
        self.network.fail_login_password = SECOND_PASSWORD
        self.assertEqual(self.run_script("--execute"), 1)
        self.assertEqual(self.network.writes[-1], "no username netpilot-rotation-test")
        self.assertEqual((self.network.running, self.network.startup), original)
        self.assertIn("FAIL", self.output.getvalue())

    def test_cleanup_failure_reports_that_test_account_may_remain(self):
        self.network.fail_delete = True
        self.assertEqual(self.run_script("--execute"), 1)
        self.assertIn(account(FIRST_HASH), self.network.running)
        output = self.output.getvalue().lower()
        self.assertIn("fail", output)
        self.assertIn("cleanup", output)
        self.assertIn("remain", output)

    def test_cleanup_does_not_delete_a_record_changed_by_another_writer(self):
        self.network.hijack_before_cleanup = True
        self.assertEqual(self.run_script("--execute"), 1)
        self.assertNotIn("no username netpilot-rotation-test", self.network.writes)
        self.assertIn(account(OTHER_HASH), self.network.running)
        self.assertIn("FAIL", self.output.getvalue())


if __name__ == "__main__":
    unittest.main()

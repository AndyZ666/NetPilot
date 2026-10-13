"""Offline account preservation, verification, and startup-save sequencing."""

import json
import traceback
import unittest
from unittest.mock import patch

from security import rotation_adapters as adapters
from security import setup_recovery_accounts as recovery

OLD = "short-old"  # Valid legacy admin password below the new-password minimum.
NEW = "synthetic-new-admin-password-only"
OLD_HASH = "$6$oldFixture$" + "A" * 86
NEW_HASH = "$6$newFixture$" + "B" * 86
RECOVERY_HASH = "$6$recoveryFixture$" + "C" * 86


def account(digest):
    return "username admin privilege 15 role network-admin secret sha512 " + digest


def configuration(digest=OLD_HASH):
    return "\n".join((
        "hostname R1", account(digest),
        "username admin ssh-key ssh-rsa fixture-only-public-key",
        "username netpilot-recovery privilege 15 role network-admin secret sha512 " + RECOVERY_HASH,
        "aaa authentication login default local", "interface Management0",
        "   ip address 172.20.20.13/24", "end", ""))


class Session:
    def __init__(self, network, password):
        self.network, self.password = network, password
        self.enabled = self.closed = False

    def check_enable_mode(self):
        return self.enabled

    def enable(self):
        self.enabled = True
        self.network.events.append(("enable", self.password))

    def send_command(self, command, **kwargs):
        if not self.enabled:
            raise AssertionError("Enable must precede privileged reads")
        if self.network.on_read:
            self.network.on_read(command)
        self.network.events.append(("read", command))
        return {
            "show privilege": "Current privilege level is 15",
            "show version | json": json.dumps({"modelName": "cEOSLab", "version": "4.36.2F"}),
            "show hostname | json": json.dumps({"hostname": "R1"}),
            "show running-config": self.network.running,
            "show startup-config": self.network.startup,
        }[command]

    def send_config_set(self, commands, **kwargs):
        if len(commands) != 1 or commands[0] not in (account(NEW_HASH), account(OLD_HASH)):
            raise AssertionError("Only the admin hash may change")
        self.network.events.append(("write",))
        self.network.writes += 1
        self.network.running = "\n".join(
            commands[0] if line.startswith("username admin privilege ") else line
            for line in self.network.running.splitlines()) + "\n"
        if self.network.fail_write:
            raise TimeoutError(NEW + " " + NEW_HASH)
        return ""

    def save_config(self):
        self.network.events.append(("save",))
        self.network.saves += 1
        self.network.startup = self.network.running
        if self.network.fail_save:
            raise TimeoutError(NEW + " " + NEW_HASH)
        return "Copy completed successfully."

    def disconnect(self):
        self.closed = True


class Network:
    def __init__(self):
        self.running = self.startup = configuration()
        self.events, self.arguments, self.sessions = [], [], []
        self.writes = self.saves = 0
        self.fail_write = self.fail_save = self.fail_login = False
        self.on_read = None

    def connect(self, **kwargs):
        self.arguments.append(kwargs)
        password = kwargs["password"]
        self.events.append(("connect", password))
        digest = {OLD: OLD_HASH, NEW: NEW_HASH}.get(password)
        if (digest is None or account(digest) not in self.running.splitlines()
                or (password == NEW and self.fail_login)):
            raise adapters.NetmikoAuthenticationException(password)
        connection = Session(self, password)
        self.sessions.append(connection)
        return connection


class FleetDeviceTests(unittest.TestCase):
    def setUp(self):
        self.network = Network()
        self.adapter = adapters.NetmikoDeviceAdapter()
        self.old = adapters.Credential("c" * 26, "admin", OLD)
        self.new = adapters.Credential("p" * 26, "admin", NEW)
        self.enterContext(patch.object(adapters, "ConnectHandler", side_effect=self.network.connect))
        self.hashing = self.enterContext(patch.object(recovery, "sha512_crypt", return_value=NEW_HASH))

    def change(self):
        self.adapter.change_password("R1", "172.20.20.13", self.old, self.new)

    def assert_failure(self, category, operation=None):
        with self.assertRaises(adapters.AdapterError) as caught:
            (operation or self.change)()
        self.assertEqual(caught.exception.category, category)
        text = "".join(traceback.format_exception(caught.exception))
        for secret in (OLD, NEW, OLD_HASH, NEW_HASH, RECOVERY_HASH):
            self.assertNotIn(secret, text)
        self.assertTrue(all(session.closed for session in self.network.sessions))

    def test_only_admin_hash_changes_and_fresh_login_precedes_save(self):
        self.change()
        self.assertEqual(self.network.running, configuration(NEW_HASH))
        self.assertEqual(self.network.startup, configuration(NEW_HASH))
        self.assertEqual((self.network.writes, self.network.saves), (1, 1))
        events = self.network.events
        self.assertLess(events.index(("write",)), events.index(("connect", NEW)))
        self.assertLess(events.index(("connect", NEW)), events.index(("save",)))
        self.assertTrue(all(session.closed for session in self.network.sessions))
        for options in self.network.arguments:
            self.assertEqual(options["host"], "172.20.20.13")
            self.assertEqual(options["username"], "admin")
            self.assertFalse(options["ssh_strict"])
            self.assertFalse(options["system_host_keys"])
            self.assertFalse(options["use_keys"])
            self.assertFalse(options["allow_agent"])
            self.assertIsNone(options["session_log"])
        self.assertEqual(self.adapter._authenticated[("R1", "172.20.20.13")], self.new)
        self.hashing.assert_called_once_with(NEW, allow_legacy=False)

    def test_short_or_unsafe_new_password_is_rejected_before_connection(self):
        for value in ("short-new", NEW + "\n", "X" * 129):
            with self.subTest(value_length=len(value)):
                replacement = adapters.Credential("p" * 26, "admin", value)
                self.assert_failure("credentials", lambda: self.adapter.change_password(
                    "R1", "172.20.20.13", self.old, replacement))
        self.assertEqual(self.network.arguments, [])
        self.assertEqual((self.network.writes, self.network.saves), (0, 0))
        self.hashing.assert_not_called()

    def test_hashing_failure_explains_local_cause_without_connection_or_secret(self):
        self.hashing.side_effect = recovery.RecoveryError("hashing")
        with self.assertRaises(adapters.AdapterError) as caught:
            self.change()
        self.assertEqual(caught.exception.category, "device_write")
        self.assertEqual(caught.exception.detail, "password_hashing")
        self.assertIn("OpenSSL", adapters.adapter_error_detail(caught.exception))
        self.assertEqual(self.network.arguments, [])
        self.assertEqual((self.network.writes, self.network.saves), (0, 0))
        for secret in (OLD, NEW, OLD_HASH, NEW_HASH):
            self.assertNotIn(secret, str(caught.exception))

    def test_error_details_never_echo_arbitrary_text(self):
        error = adapters.AdapterError("credentials", NEW)
        self.assertIsNone(error.detail)
        self.assertIsNone(adapters.adapter_error_detail(error))
        self.assertNotIn(NEW, str(error))
        external = RuntimeError(NEW)
        external.detail = NEW
        self.assertIsNone(adapters.adapter_error_detail(external))

    def test_unsupported_original_password_refuses_before_mutation(self):
        original = adapters.Credential("c" * 26, "admin", "unsupported\noriginal")
        self.assert_failure("credentials", lambda: self.adapter.change_password(
            "R1", "172.20.20.13", original, self.new))
        self.assertEqual(self.network.arguments, [])
        self.assertEqual((self.network.writes, self.network.saves), (0, 0))
        self.hashing.assert_not_called()

    def test_unrelated_unsaved_changes_prevent_any_write(self):
        self.network.running = self.network.running.replace("interface Management0", "ip routing\ninterface Management0")
        self.assert_failure("conflict")
        self.assertEqual((self.network.writes, self.network.saves), (0, 0))

    def test_wrong_admin_role_refuses_authentication(self):
        self.network.running = self.network.running.replace("username admin privilege 15 role network-admin", "username admin privilege 15 role network-operator")
        # Let the mock transport prove SSH without insisting on the old exact account line.
        with patch.object(adapters, "ConnectHandler", return_value=Session(self.network, OLD)):
            self.assert_failure("privilege", lambda: self.adapter.authenticate("R1", "172.20.20.13", self.old))
        self.assertEqual((self.network.writes, self.network.saves), (0, 0))

    def test_new_login_failure_retains_running_change_but_never_saves(self):
        self.network.fail_login = True
        self.assert_failure("authentication")
        self.assertEqual(self.network.running, configuration(NEW_HASH))
        self.assertEqual(self.network.startup, configuration())
        self.assertEqual(self.network.saves, 0)

    def test_ambiguous_write_does_not_guess_or_save(self):
        self.network.fail_write = True
        self.assert_failure("device_write")
        self.assertEqual(self.network.running, configuration(NEW_HASH))
        self.assertEqual(self.network.saves, 0)

    def test_ambiguous_save_is_not_reported_as_success(self):
        self.network.fail_save = True
        self.assert_failure("device_write")
        self.assertEqual(self.network.saves, 1)

    def test_configuration_drift_after_new_login_prevents_save(self):
        reads = 0
        def drift(command):
            nonlocal reads
            if command == "show running-config" and self.network.writes:
                reads += 1
                if reads == 3:  # Immediate pre-save read, after fresh verification.
                    self.network.running = self.network.running.replace("interface Management0", "ip routing\ninterface Management0")
        self.network.on_read = drift
        self.assert_failure("conflict")
        self.assertEqual(self.network.saves, 0)

    def test_resume_saves_only_known_admin_hash_difference(self):
        self.network.running = configuration(NEW_HASH)
        self.adapter.ensure_verified("R1", "172.20.20.13", self.new)
        self.assertEqual(self.network.startup, configuration(NEW_HASH))
        self.assertEqual((self.network.writes, self.network.saves), (0, 1))
        self.hashing.assert_not_called()

    def test_explicit_rollback_reconciles_unsaved_pending_then_restores_original(self):
        self.network.running = configuration(NEW_HASH)
        self.adapter.ensure_verified("R1", "172.20.20.13", self.new)
        self.hashing.return_value = OLD_HASH
        self.adapter.change_password("R1", "172.20.20.13", self.new, self.old, restore=True)
        self.assertEqual(self.network.running, configuration())
        self.assertEqual(self.network.startup, configuration())
        self.assertEqual((self.network.writes, self.network.saves), (1, 2))
        self.assertEqual(self.adapter._authenticated[("R1", "172.20.20.13")], self.old)
        self.hashing.assert_called_once_with(OLD, allow_legacy=True)

    def test_resume_refuses_unrelated_configuration_or_account_attribute_drift(self):
        for extra in ("\nip routing", "\nusername admin shell /bin/bash"):
            self.network.running = configuration(NEW_HASH).replace("\nend", extra + "\nend")
            self.assert_failure("conflict", lambda: self.adapter.ensure_verified("R1", "172.20.20.13", self.new))
        self.assertEqual((self.network.writes, self.network.saves), (0, 0))

    def test_already_saved_resume_only_verifies(self):
        self.network.running = self.network.startup = configuration(NEW_HASH)
        self.adapter.ensure_verified("R1", "172.20.20.13", self.new)
        self.assertEqual((self.network.writes, self.network.saves), (0, 0))

    def test_recovery_check_is_read_only_configured_presence_after_admin_auth(self):
        self.assertFalse(self.adapter.verify_recovery("R1", "172.20.20.13", "admin"))
        self.adapter.authenticate("R1", "172.20.20.13", self.old)
        self.assertTrue(self.adapter.verify_recovery("R1", "172.20.20.13", "admin"))
        self.network.running = self.network.running.replace("username netpilot-recovery", "username other-recovery")
        self.assertFalse(self.adapter.verify_recovery("R1", "172.20.20.13", "admin"))
        self.assertTrue(all(options["username"] == "admin" for options in self.network.arguments))
        self.assertEqual((self.network.writes, self.network.saves), (0, 0))


if __name__ == "__main__":
    unittest.main()

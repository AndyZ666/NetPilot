"""Offline R1 admin rotation/rollback tests; all Vault and SSH boundaries are fake."""

from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from security import credential_provider
from security import test_r1_admin_rotation as script
from security.rotation_adapters import AdapterError, Credential, OnePasswordStore
from security.rotation_state import FLEET, JournalStore, StateError, validate_state


OLD_PASSWORD = "synthetic-admin-original-password"
NEW_PASSWORD = "synthetic-admin-new-password-only"
OLD_HASH = "$6$originalFixture$" + "A" * 86
NEW_HASH = "$6$newFixture$" + "B" * 86
RECOVERY_HASH = "$6$recoveryFixture$" + "C" * 86
CURRENT_REF, PENDING_REF, PREVIOUS_REF = "c" * 26, "p" * 26, "a" * 26
INVENTORY = dict(zip(FLEET, ("172.20.20." + value for value in (
    "13", "14", "9", "11", "2", "7", "8", "4", "10"))))


def admin_line(digest=OLD_HASH):
    return "username admin privilege 15 role network-admin secret sha512 " + digest


def configuration(extra=""):
    return "\n".join([
        "! Command: show running-config", "!", "hostname R1", "!", admin_line(),
        "username netpilot-recovery privilege 15 role network-admin secret sha512 " + RECOVERY_HASH,
        "aaa authentication login default local", "!", "interface Management0",
        "   no shutdown", "   ip address 172.20.20.13/24", "!",
    ] + ([extra] if extra else []) + ["end", ""])


class FakeVault:
    live_writes_supported = True
    _require_owned = staticmethod(OnePasswordStore._require_owned)

    def __init__(self, events):
        self.events = events
        self.current = Credential(CURRENT_REF, "admin", OLD_PASSWORD)
        self.pending = self.previous = None
        self.items = {CURRENT_REF: self.current}
        self.writes = []
        self.fail_stage = False
        self.bad_readback = False

    def read_current(self):
        self.events.append(("vault_read", "current"))
        return self.current

    def find_pending(self):
        return self.pending

    def archive_current(self, rotation_id, current):
        self.writes.append("archive")
        self.previous = Credential(PREVIOUS_REF, current.username, current.password,
                                   rotation_id, current.reference)
        self.items[PREVIOUS_REF] = self.previous
        return self.previous

    def stage_pending(self, rotation_id, username, password, current_reference=None):
        self.writes.append("stage")
        if self.fail_stage:
            raise AdapterError("vault_write")
        self.pending = Credential(PENDING_REF, username, password, rotation_id, current_reference)
        self.items[PENDING_REF] = self.pending
        self.events.append(("pending_staged",))
        return self.pending

    def read(self, reference):
        self.events.append(("vault_read", reference))
        credential = self.items[reference]
        if reference == PENDING_REF and self.bad_readback:
            return replace(credential, password="synthetic-wrong-readback")
        return credential


class FakeConnection:
    def __init__(self, network):
        self.network = network
        self.enabled = self.disconnected = False

    def check_enable_mode(self):
        return self.enabled

    def enable(self):
        self.enabled = True
        self.network.events.append(("enable",))

    def send_command(self, command, **kwargs):
        if not self.enabled:
            raise AssertionError("Privileged reads require enable mode")
        self.network.events.append(("read", command))
        if command == "show hostname | json":
            return json.dumps({"hostname": "R1"})
        if command == "show privilege":
            return "Current privilege level is " + str(self.network.privilege)
        if command == "show running-config":
            return self.network.running
        if command == "show startup-config":
            return self.network.startup.replace("show running-config", "show startup-config")
        raise AssertionError("Unexpected device command")

    def send_config_set(self, commands, **kwargs):
        commands = list(commands)
        if not self.enabled or len(commands) != 1:
            raise AssertionError("Expected one privileged admin password command")
        command = commands[0]
        if command not in (admin_line(OLD_HASH), admin_line(NEW_HASH)):
            raise AssertionError("Only the R1 admin password may be changed")
        record = self.network.journal.load()
        if (record["credential_refs"]["pending"] != PENDING_REF
                or not record["devices"]["R1"]["attempted"]):
            raise AssertionError("Pending and write intent must be durable before mutation")
        self.network.writes.append(command)
        self.network.events.append(("write", command))
        if command == admin_line(OLD_HASH) and self.network.fail_restore:
            raise TimeoutError("synthetic diagnostic " + NEW_PASSWORD + " " + NEW_HASH)
        self.network.running = "\n".join(
            command if line.startswith("username admin ") else line
            for line in self.network.running.splitlines()) + "\n"
        if len(self.network.writes) == 1:
            if self.network.interrupt_update:
                raise KeyboardInterrupt
            if self.network.timeout_update:
                raise TimeoutError("synthetic diagnostic " + NEW_PASSWORD + " " + NEW_HASH)
        return ""

    def save_config(self, **kwargs):
        self.network.saves += 1
        raise AssertionError("Test must never save startup configuration")

    def disconnect(self):
        self.disconnected = True


class FakeNetwork:
    def __init__(self, events, journal):
        self.events, self.journal = events, journal
        self.running, self.startup = configuration(), configuration()
        self.arguments, self.connections, self.writes = [], [], []
        self.saves = 0
        self.privilege = 15
        self.fail_new_login = self.fail_restore = False
        self.timeout_update = self.interrupt_update = False

    def connect(self, **kwargs):
        self.arguments.append(kwargs)
        if kwargs["host"] != "172.20.20.13" or kwargs["username"] != "admin":
            raise AssertionError("Only R1 admin SSH is allowed")
        password = kwargs["password"]
        expected = {OLD_PASSWORD: OLD_HASH, NEW_PASSWORD: NEW_HASH}.get(password)
        if (expected is None or admin_line(expected) not in self.running.splitlines()
                or (self.fail_new_login and password == NEW_PASSWORD)):
            raise RuntimeError("synthetic login diagnostic " + password)
        self.events.append(("connect", password))
        connection = FakeConnection(self)
        self.connections.append(connection)
        return connection


class R1AdminRotationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(self.temporary)
        self.journal = JournalStore(self.root / "state")
        self.events = []
        self.vault = FakeVault(self.events)
        self.network = FakeNetwork(self.events, self.journal)
        self.output = io.StringIO()
        self.enterContext(patch.object(script.rotation, "STATE_DIR", self.journal.root))
        self.inventory = self.enterContext(patch.object(
            script.rotation, "discover_inventory", return_value=INVENTORY.copy()))
        self.vault_constructor = self.enterContext(patch.object(
            script, "OnePasswordStore", return_value=self.vault))
        self.connect = self.enterContext(patch.object(
            script.probe, "ConnectHandler", side_effect=self.network.connect))
        self.hashing = self.enterContext(patch.object(
            script.recovery, "sha512_crypt", return_value=NEW_HASH))
        self.random_password = self.enterContext(patch.object(
            script.rotation, "generate_password", return_value=NEW_PASSWORD))
        self.prompt = self.enterContext(patch("builtins.input", side_effect=AssertionError("No prompt allowed")))
        self.enterContext(patch.object(credential_provider, "_read_token", side_effect=AssertionError("No real token reads")))
        self.enterContext(patch.object(credential_provider, "_run_op", side_effect=AssertionError("No real Vault operations")))
        self.enterContext(patch("security.rotation_adapters.ConnectHandler", side_effect=AssertionError("No fleet connections")))
        self.enterContext(patch("socket.create_connection", side_effect=AssertionError("No network")))
        self.enterContext(patch("subprocess.run", side_effect=AssertionError("No processes or services")))

    def run_script(self, *arguments):
        with redirect_stdout(self.output), redirect_stderr(self.output):
            result = script.main(list(arguments))
        for value in (OLD_PASSWORD, NEW_PASSWORD, OLD_HASH, NEW_HASH, RECOVERY_HASH):
            self.assertNotIn(value, self.output.getvalue())
            for file in self.root.rglob("*"):
                if file.is_file():
                    self.assertNotIn(value, file.read_text())
        self.assertEqual(self.network.saves, 0)
        self.prompt.assert_not_called()
        if self.journal.path.exists():
            validate_state(self.journal.load())
        return result

    def test_dry_run_has_no_vault_device_or_state_side_effects(self):
        self.assertEqual(self.run_script("--dry-run"), 0)
        self.vault_constructor.assert_not_called()
        self.connect.assert_not_called()
        self.hashing.assert_not_called()
        self.random_password.assert_not_called()
        self.assertFalse(self.journal.root.exists())

    def test_success_stages_before_mutation_and_restores_exact_configuration(self):
        original = self.network.running, self.network.startup
        self.assertEqual(self.run_script("--execute"), 0)
        self.assertEqual(self.network.writes, [admin_line(NEW_HASH), admin_line(OLD_HASH)])
        self.assertEqual((self.network.running, self.network.startup), original)
        events = self.events
        staged = events.index(("pending_staged",))
        readback = events.index(("vault_read", PENDING_REF))
        changed = events.index(("write", admin_line(NEW_HASH)))
        restored = events.index(("write", admin_line(OLD_HASH)))
        self.assertLess(staged, readback)
        self.assertLess(readback, changed)
        self.assertLess(changed, events.index(("connect", NEW_PASSWORD)))
        self.assertTrue(any(index > restored and event == ("connect", OLD_PASSWORD)
                            for index, event in enumerate(events)))
        self.assertEqual(self.vault.current.password, OLD_PASSWORD)
        self.assertEqual(self.vault.writes, ["archive", "stage"])
        self.assertIsNotNone(self.vault.pending)
        state = self.journal.load()
        self.assertEqual(state["phase"], "ROLLED_BACK")
        self.assertEqual(state["scope"], ["R1"])
        self.assertEqual(state["devices"]["R1"]["state"], "verified_old")
        for name in FLEET[1:]:
            self.assertFalse(state["devices"][name]["attempted"])
        self.assertTrue(all(connection.disconnected for connection in self.network.connections))

    def test_only_r1_password_auth_and_lab_hostkeys_with_actual_privilege(self):
        self.assertEqual(self.run_script("--execute"), 0)
        for arguments in self.network.arguments:
            self.assertEqual(arguments["host"], "172.20.20.13")
            self.assertEqual(arguments["username"], "admin")
            self.assertFalse(arguments.get("ssh_strict", False))
            self.assertFalse(arguments.get("system_host_keys", False))
            self.assertFalse(arguments.get("use_keys", False))
            self.assertFalse(arguments.get("allow_agent", False))
            self.assertIsNone(arguments.get("session_log"))
        self.assertTrue(all(connection.enabled for connection in self.network.connections))
        self.assertIn(("read", "show privilege"), self.events)

    def test_existing_pending_is_preserved_without_device_changes(self):
        self.vault.pending = Credential(PENDING_REF, "admin", NEW_PASSWORD)
        self.assertEqual(self.run_script("--execute"), 1)
        self.assertEqual(self.vault.writes, [])
        self.assertEqual(self.network.writes, [])
        self.assertEqual(self.vault.pending.password, NEW_PASSWORD)

    def test_staging_failure_prevents_any_device_password_change(self):
        self.vault.fail_stage = True
        self.assertEqual(self.run_script("--execute"), 1)
        self.assertEqual(self.network.writes, [])
        self.assertEqual(self.network.running, configuration())
        self.assertEqual(self.vault.current.password, OLD_PASSWORD)

    def test_mismatched_independent_pending_readback_prevents_device_changes(self):
        self.vault.bad_readback = True
        self.assertEqual(self.run_script("--execute"), 1)
        self.assertEqual(self.network.writes, [])
        self.assertIsNotNone(self.vault.pending)

    def test_insufficient_privilege_does_not_change_admin(self):
        self.network.privilege = 1
        self.assertEqual(self.run_script("--execute"), 1)
        self.assertEqual(self.network.writes, [])
        self.assertEqual(self.network.running, configuration())

    def test_new_password_login_failure_verifies_original_on_rollback(self):
        self.network.fail_new_login = True
        self.assertEqual(self.run_script("--execute"), 1)
        self.assertEqual(self.network.running, configuration())
        self.assertEqual(self.journal.load()["phase"], "ROLLED_BACK")
        self.assertIsNotNone(self.vault.pending)
        self.assertIn("FAIL", self.output.getvalue())

    def test_timeout_after_device_apply_rolls_back_using_retained_credentials(self):
        self.network.timeout_update = True
        self.assertEqual(self.run_script("--execute"), 1)
        self.assertEqual(self.network.running, configuration())
        self.assertEqual(self.journal.load()["phase"], "ROLLED_BACK")
        self.assertEqual(self.vault.pending.password, NEW_PASSWORD)

    def test_interrupt_after_apply_attempts_verified_rollback(self):
        self.network.interrupt_update = True
        self.assertEqual(self.run_script("--execute"), 130)
        self.assertEqual(self.network.running, configuration())
        self.assertEqual(self.journal.load()["phase"], "ROLLED_BACK")
        self.assertEqual(self.vault.pending.password, NEW_PASSWORD)

    def test_incomplete_restoration_requires_recovery_and_preserves_pending(self):
        self.network.fail_restore = True
        self.assertEqual(self.run_script("--execute"), 1)
        self.assertIn(admin_line(NEW_HASH), self.network.running)
        state = self.journal.load()
        self.assertEqual(state["phase"], "RECOVERY_REQUIRED")
        self.assertEqual(state["devices"]["R1"]["state"], "unknown")
        self.assertEqual(state["credential_refs"]["pending"], PENDING_REF)
        self.assertEqual(self.vault.pending.password, NEW_PASSWORD)
        self.assertEqual(self.vault.current.password, OLD_PASSWORD)
        self.assertIn("FAIL", self.output.getvalue())

    def test_unresolved_journal_is_preserved_and_blocks_another_attempt(self):
        self.network.fail_restore = True
        self.assertEqual(self.run_script("--execute"), 1)
        original = self.journal.path.read_bytes()
        writes = list(self.network.writes)
        vault_writes = list(self.vault.writes)
        self.vault.pending = None  # Journal alone must still prevent a new test.
        self.assertEqual(self.run_script("--execute"), 1)
        self.assertEqual(self.journal.path.read_bytes(), original)
        self.assertEqual(self.network.writes, writes)
        self.assertEqual(self.vault.writes, vault_writes)

    def test_journal_outage_blocks_unrecorded_changes_but_does_not_block_rollback(self):
        save = JournalStore.save
        for timing in ("before_write", "after_write"):
            with self.subTest(timing=timing):
                self.journal = JournalStore(self.root / timing)
                self.events = []
                self.vault = FakeVault(self.events)
                self.network = FakeNetwork(self.events, self.journal)
                self.vault_constructor.return_value = self.vault
                self.connect.side_effect = self.network.connect
                failed = False

                def unavailable(journal, record):
                    nonlocal failed
                    trigger = (record["devices"]["R1"]["attempted"]
                               if timing == "before_write" else bool(self.network.writes))
                    failed = failed or trigger
                    if failed:
                        raise StateError("Synthetic durable journal outage")
                    return save(journal, record)

                with patch.object(script.rotation, "STATE_DIR", self.journal.root), patch.object(
                        JournalStore, "save", autospec=True, side_effect=unavailable):
                    self.assertEqual(self.run_script("--execute"), 1)
                self.assertTrue(failed)
                self.assertEqual(self.network.running, configuration())
                self.assertEqual(self.network.startup, configuration())
                self.assertEqual(self.vault.pending.password, NEW_PASSWORD)
                durable = self.journal.load()
                self.assertEqual(durable["credential_refs"]["pending"], PENDING_REF)
                self.assertNotEqual(durable["phase"], "ROLLED_BACK")
                if timing == "before_write":
                    self.assertEqual(self.network.writes, [])
                    self.assertFalse(durable["devices"]["R1"]["attempted"])
                else:
                    self.assertEqual(self.network.writes,
                                     [admin_line(NEW_HASH), admin_line(OLD_HASH)])
                    self.assertTrue(durable["devices"]["R1"]["attempted"])
                    restored = self.events.index(("write", admin_line(OLD_HASH)))
                    self.assertTrue(any(index > restored and event == ("connect", OLD_PASSWORD)
                                        for index, event in enumerate(self.events)))

    def test_unrelated_unsaved_changes_remain_and_are_never_saved(self):
        self.network.running = configuration("ip route 192.0.2.0/24 Null0")
        original = self.network.running, self.network.startup
        self.assertNotEqual(*original)
        self.assertEqual(self.run_script("--execute"), 0)
        self.assertEqual((self.network.running, self.network.startup), original)


if __name__ == "__main__":
    unittest.main()

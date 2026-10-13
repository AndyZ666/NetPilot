"""Offline rotation scenarios with synthetic credentials and in-memory adapters.

The real journal operates only in a temporary directory. Vault, network and
service boundaries are forbidden even if an implementation accidentally calls
the production adapters instead of the supplied fixtures.
"""

from copy import deepcopy
from dataclasses import replace
import io
import json
from pathlib import Path
import stat
import string
import tempfile
import unittest
from unittest.mock import patch

import yaml

from security import credential_provider
from security import credential_rotation as rotation
from security.rotation_adapters import AdapterError, Credential
from security.rotation_state import FLEET, JournalStore, StateError, validate_state
from security.telegraf_launcher import interpolation_value


OLD_PASSWORD = "OLD-fixture-PASSWORD-4711!@"
CURRENT_REFERENCE = "c" * 26
PENDING_REFERENCE = "p" * 26
PREVIOUS_REFERENCE = "a" * 26


class FakeCredentials:
    live_writes_supported = True

    def __init__(self):
        self.current = Credential(CURRENT_REFERENCE, "fixtureadmin", OLD_PASSWORD)
        self.pending = None
        self.previous = None
        self.items = {self.current.reference: self.current}
        self.reads = []
        self.writes = []
        self.fail = None
        self.promotion_takes_effect_then_fails = False
        self.staging_takes_effect_then_fails = False
        self.archive_takes_effect_then_fails = False
        self.promotion_returns_wrong_pair = False

    def _failure(self, operation):
        if self.fail == operation:
            category = "vault_read" if operation.startswith("read") or operation == "find_pending" else "vault_write"
            raise AdapterError(category)

    def read_current(self):
        self.reads.append("current")
        self._failure("read_current")
        return self.current

    def find_pending(self):
        self.reads.append("pending")
        self._failure("find_pending")
        return self.pending

    def read_previous(self, rotation_id):
        self.reads.append("previous")
        return self.previous if self.previous and self.previous.rotation_id == rotation_id else None

    def read(self, reference):
        self.reads.append(reference)
        self._failure("read")
        if reference not in self.items:
            raise AdapterError("vault_read")
        return self.items[reference]

    def archive_current(self, rotation_id, current):
        self.writes.append("archive")
        self._failure("archive")
        self.previous = Credential(PREVIOUS_REFERENCE, current.username, current.password,
                                   rotation_id, current.reference)
        self.items[self.previous.reference] = self.previous
        if self.archive_takes_effect_then_fails:
            raise AdapterError("vault_write")
        return self.previous

    def stage_pending(self, rotation_id, username, password, current_reference=None):
        self.writes.append("stage")
        self._failure("stage")
        self.pending = Credential(PENDING_REFERENCE, username, password, rotation_id, current_reference)
        self.items[self.pending.reference] = self.pending
        if self.staging_takes_effect_then_fails:
            raise AdapterError("vault_write")
        return self.pending

    def promote(self, current, pending):
        self.writes.append("promote")
        self._failure("promote")
        if self.promotion_returns_wrong_pair:
            return self.current
        self.current = replace(pending, reference=current.reference)
        self.items[self.current.reference] = self.current
        if self.promotion_takes_effect_then_fails:
            raise AdapterError("vault_write")
        return self.current

    def restore_current(self, current, previous):
        self.writes.append("restore")
        self._failure("restore")
        self.current = replace(previous, reference=current.reference)
        self.items[self.current.reference] = self.current
        return self.current


class FakeDevices:
    live_writes_supported = True

    def __init__(self):
        self.passwords = dict.fromkeys(FLEET, OLD_PASSWORD)
        self.startup_passwords = dict.fromkeys(FLEET, OLD_PASSWORD)
        self.save_checks = []
        self.save_fail = set()
        self.authentications = []
        self.recovery_checks = []
        self.writes = []
        self.unreachable = set()
        self.no_recovery = set()
        self.fail_before = set()
        self.disconnect_after = set()
        self.interrupt_after = set()
        self.ignore_write = set()
        self.rollback_fail = set()
        self.accept_both = set()

    def authenticate(self, name, management_ip, credential):
        self.authentications.append((name, management_ip, credential.reference))
        if name in self.unreachable:
            raise AdapterError("unreachable")
        if credential.username != "fixtureadmin":
            raise AdapterError("authentication")
        if name not in self.accept_both and credential.password != self.passwords[name]:
            raise AdapterError("authentication")

    def verify_recovery(self, name, management_ip, target_username):
        self.recovery_checks.append((name, management_ip, target_username))
        return name not in self.no_recovery

    def change_password(self, name, management_ip, auth, new, *, restore=False):
        if restore != (new.password == OLD_PASSWORD):
            raise AssertionError("Legacy policy is allowed only for rollback")
        self.authenticate(name, management_ip, auth)
        self.writes.append((name, new.reference))
        if name in self.fail_before or (new.password == OLD_PASSWORD and name in self.rollback_fail):
            raise AdapterError("unreachable")
        if name not in self.ignore_write:
            self.passwords[name] = new.password
        if name in self.disconnect_after:
            raise AdapterError("unreachable")
        if name in self.interrupt_after:
            raise KeyboardInterrupt


    def ensure_verified(self, name, management_ip, credential):
        self.authenticate(name, management_ip, credential)
        self.save_checks.append((name, credential.reference))
        if name in self.save_fail:
            raise AdapterError("device_write")
        self.startup_passwords[name] = credential.password


class FakeMonitoring:
    available = True
    verification_available = True

    def __init__(self):
        self.calls = []
        self.verification_calls = []
        self.result = True
        self.verification_result = True

    def verify_current(self, rotation_id, targets):
        self.verification_calls.append((rotation_id, tuple(targets)))
        return self.verification_result

    def refresh_and_verify(self, rotation_id, targets):
        self.calls.append((rotation_id, tuple(targets)))
        return self.result


class RotationEngineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.inventory = self.root / "devices.yml"
        self.inventory_data = {"devices": {
            name: {"hostname": name, "vendor": "Arista", "platform": "cEOSLab",
                   "management": {"ipv4": f"192.0.2.{index}"}}
            for index, name in enumerate(FLEET, 1)
        }}
        self.write_inventory()
        self.store = JournalStore(self.root / "journal")
        self.credentials = FakeCredentials()
        self.devices = FakeDevices()
        self.monitoring = FakeMonitoring()
        self.engine = self.new_engine()
        self.notification = self.enterContext(patch("security.rotation_email.send_notification",
                                                  return_value={"status": "not_configured", "error": "not_configured"}))
        self.enterContext(patch.object(credential_provider, "_read_token", side_effect=AssertionError("No real token reads")))
        self.enterContext(patch.object(credential_provider, "_run_op", side_effect=AssertionError("No real Vault operations")))
        self.enterContext(patch("security.rotation_adapters.ConnectHandler", side_effect=AssertionError("No real devices")))
        self.enterContext(patch("socket.create_connection", side_effect=AssertionError("No network")))
        self.enterContext(patch("subprocess.run", side_effect=AssertionError("No real processes/services")))

    def new_engine(self, monitoring=True):
        return rotation.RotationEngine(self.credentials, self.devices, self.store,
                                       inventory_path=self.inventory,
                                       monitoring=self.monitoring if monitoring else None)

    def write_inventory(self):
        self.inventory.write_text(yaml.safe_dump(self.inventory_data, sort_keys=False))

    def prepare(self, fleet=False):
        scope = FLEET if fleet else ("R1",)
        return self.engine.prepare(scope, authorized=True,
                                   confirmation="PREPARE FLEET" if fleet else "PREPARE R1")

    def rotate(self, fleet=False):
        return self.engine.rotate(device=None if fleet else "R1", fleet=fleet, authorized=True,
                                  confirmation="ROTATE FLEET" if fleet else "ROTATE R1")

    def recover(self, action):
        identifier = self.store.load()["rotation_id"]
        return self.engine.recover(action=action, authorized=True,
                                   confirmation=f"{action.upper()} {identifier}")

    def commit(self):
        identifier = self.store.load()["rotation_id"]
        return self.engine.commit(authorized=True, confirmation=f"COMMIT {identifier}")

    def assert_no_persisted_secrets(self):
        secrets = [OLD_PASSWORD]
        if self.credentials.pending:
            secrets.append(self.credentials.pending.password)
        if self.store.path.exists():
            content = self.store.path.read_text()
            for value in secrets:
                self.assertNotIn(value, content)
            validate_state(json.loads(content))

    def test_inventory_discovers_expected_nine_in_order_and_ignores_historical_devices(self):
        for name in ("Test-S4", "Test-R11", "Test-R12"):
            self.inventory_data["devices"][name] = deepcopy(self.inventory_data["devices"]["R1"])
        self.write_inventory()
        discovered = rotation.discover_inventory(self.inventory)
        self.assertEqual(tuple(discovered), FLEET)
        self.assertEqual(discovered["R1"], "192.0.2.1")

    def test_inventory_missing_duplicate_and_invalid_addresses_are_rejected(self):
        original = deepcopy(self.inventory_data)
        invalid = []
        missing = deepcopy(original)
        missing["devices"].pop("S4")
        invalid.append(missing)
        duplicate = deepcopy(original)
        duplicate["devices"]["R2"]["management"]["ipv4"] = "192.0.2.1"
        invalid.append(duplicate)
        for address in ("not-an-ip", "192.0.2.1/24", "127.0.0.1"):
            candidate = deepcopy(original)
            candidate["devices"]["R1"]["management"]["ipv4"] = address
            invalid.append(candidate)
        for candidate in invalid:
            with self.subTest(candidate=candidate):
                self.inventory_data = candidate
                self.write_inventory()
                with self.assertRaises(rotation.RotationError):
                    rotation.discover_inventory(self.inventory)

    def test_plan_and_status_are_offline_and_do_not_create_journal(self):
        inventory_before = self.inventory.read_bytes()
        for scope in (("R1",), FLEET):
            plan = self.engine.plan(scope)
            self.assertIsInstance(plan, dict)
            self.assertNotIn(OLD_PASSWORD, json.dumps(plan))
        self.assertIsInstance(self.engine.status(), dict)
        self.assertEqual(self.credentials.reads, [])
        self.assertEqual(self.credentials.writes, [])
        self.assertEqual(self.devices.authentications, [])
        self.assertEqual(self.devices.writes, [])
        self.assertEqual(self.monitoring.calls, [])
        self.assertFalse(self.store.root.exists())
        self.assertEqual(self.inventory.read_bytes(), inventory_before)

    def test_scope_rejects_unapproved_single_device_and_partial_fleet(self):
        for scope in ((), ("R2",), ("R1", "R2"), ("Test-R11",), ("R1", "R1")):
            with self.subTest(scope=scope), self.assertRaises(rotation.RotationError):
                self.engine.plan(scope)
        self.assertEqual(self.credentials.reads, [])

    def test_mutations_require_authorization_and_reject_conflicting_legacy_confirmation(self):
        operations = (
            lambda **kw: self.engine.prepare(("R1",), **kw),
            lambda **kw: self.engine.rotate(device="R1", **kw),
            lambda **kw: self.engine.recover(action="resume", **kw),
            lambda **kw: self.engine.recover(action="rollback", **kw),
            lambda **kw: self.engine.commit(**kw),
        )
        for operation in operations:
            for kwargs in ({}, {"authorized": False, "confirmation": "PREPARE R1"},
                           {"authorized": True, "confirmation": "wrong confirmation"}):
                with self.subTest(kwargs=kwargs), self.assertRaises((rotation.RotationError, StateError)):
                    operation(**kwargs)
        self.assertEqual(self.credentials.writes, [])
        self.assertEqual(self.devices.writes, [])
        self.assertEqual(self.monitoring.calls, [])

    def test_disabled_live_adapter_blocks_prepare_before_vault_writes(self):
        self.devices.live_writes_supported = False
        with self.assertRaises(rotation.RotationError):
            self.prepare()
        self.assertEqual(self.credentials.writes, [])
        self.assertEqual(self.devices.writes, [])

    def test_precheck_missing_current_credentials_and_unreachable_device(self):
        self.credentials.fail = "read_current"
        result = self.engine.precheck(("R1",))
        self.assertIsInstance(result, dict)
        self.assertFalse(result["passed"])
        self.assertEqual(self.credentials.writes, [])
        self.credentials.fail = None
        self.devices.unreachable.add("R1")
        result = self.engine.precheck(("R1",))
        self.assertIsInstance(result, dict)
        self.assertFalse(result["passed"])
        self.assertEqual(self.devices.writes, [])
        self.assertFalse(self.store.root.exists())

    def test_missing_recovery_account_blocks_preparation(self):
        self.devices.no_recovery.add("R1")
        with self.assertRaises(rotation.RotationError):
            self.prepare()
        self.assertEqual(self.credentials.writes, [])
        self.assertEqual(self.devices.writes, [])
        state = self.store.load()
        self.assertTrue(state is None or state["phase"] != "PREPARED")

    def test_prepare_stages_pending_and_preserves_current_without_device_changes(self):
        before = self.inventory.read_bytes()
        result = self.prepare()
        state = self.store.load()
        self.assertEqual(state["phase"], "PREPARED")
        self.assertEqual(state["scope"], ["R1"])
        self.assertEqual(self.credentials.current.password, OLD_PASSWORD)
        self.assertNotEqual(self.credentials.pending.password, OLD_PASSWORD)
        self.assertEqual(self.credentials.pending.rotation_id, state["rotation_id"])
        self.assertEqual(self.credentials.previous.password, OLD_PASSWORD)
        self.assertEqual(self.credentials.writes, ["archive", "stage"])
        self.assertEqual({name for name, _, _ in self.devices.authentications}, set(FLEET))
        self.assertEqual(self.devices.writes, [])
        self.assertEqual(self.monitoring.calls, [])
        self.assertEqual(self.inventory.read_bytes(), before)
        self.assertEqual(stat.S_IMODE(self.store.path.stat().st_mode), 0o600)
        self.assert_no_persisted_secrets()
        self.assertNotIn(self.credentials.pending.password, json.dumps(result))

    def test_existing_foreign_pending_or_unresolved_rotation_blocks_new_prepare(self):
        self.credentials.pending = Credential(PENDING_REFERENCE, "fixtureadmin", "UNRELATED-fixture-PASSWORD-4722", "f" * 32, CURRENT_REFERENCE)
        with self.assertRaises(rotation.RotationError):
            self.prepare()
        self.assertEqual(self.credentials.writes, [])
        self.credentials.pending = None
        # Use a fresh journal: a refused preparation must not authorize replacement.
        self.store = JournalStore(self.root / "second-journal")
        self.engine = self.new_engine()
        self.prepare()
        writes = list(self.credentials.writes)
        with self.assertRaises(rotation.RotationError):
            self.prepare()
        self.assertEqual(self.credentials.writes, writes)

    def test_pending_stage_failure_is_recoverable_and_current_is_preserved(self):
        self.credentials.fail = "stage"
        self.prepare()
        self.assertEqual(self.credentials.current.password, OLD_PASSWORD)
        self.assertEqual(self.devices.writes, [])
        self.assertIn(self.store.load()["phase"], {"RECOVERY_REQUIRED", "ERROR"})
        self.assert_no_persisted_secrets()

    def test_single_device_rotation_verifies_fresh_login_and_never_promotes(self):
        self.prepare()
        self.rotate()
        state = self.store.load()
        self.assertEqual(state["phase"], "VERIFYING")
        self.assertEqual(state["devices"]["R1"]["state"], "verified_new")
        self.assertEqual([name for name, _ in self.devices.writes], ["R1"])
        self.assertEqual(self.devices.passwords["R1"], self.credentials.pending.password)
        for name in FLEET[1:]:
            self.assertEqual(self.devices.passwords[name], OLD_PASSWORD)
        self.assertEqual(self.credentials.current.password, OLD_PASSWORD)
        self.assertEqual(self.monitoring.calls, [])
        with self.assertRaises(rotation.RotationError):
            self.commit()
        self.assertNotIn("promote", self.credentials.writes)
        self.assert_no_persisted_secrets()

    def test_successful_fleet_rotates_sequentially_then_requires_separate_commit(self):
        self.prepare(fleet=True)
        self.rotate(fleet=True)
        state = self.store.load()
        self.assertEqual(state["phase"], "READY_TO_COMMIT")
        self.assertEqual([name for name, _ in self.devices.writes], list(FLEET))
        self.assertTrue(all(device["state"] == "verified_new" for device in state["devices"].values()))
        self.assertTrue(all(password == self.credentials.pending.password for password in self.devices.passwords.values()))
        self.assertEqual(self.credentials.current.password, OLD_PASSWORD)
        self.assertEqual(self.monitoring.calls, [])
        self.assert_no_persisted_secrets()

    def test_password_setting_failure_stops_fleet_without_changing_current(self):
        self.prepare(fleet=True)
        self.devices.fail_before.add("R4")
        self.rotate(fleet=True)
        state = self.store.load()
        self.assertIn(state["phase"], {"PARTIAL_FAILURE", "RECOVERY_REQUIRED"})
        self.assertEqual([name for name, _ in self.devices.writes], list(FLEET[:4]))
        self.assertEqual(self.credentials.current.password, OLD_PASSWORD)
        self.assertEqual(self.devices.passwords["R5"], OLD_PASSWORD)
        self.assertEqual(self.monitoring.calls, [])
        self.assert_no_persisted_secrets()

    def test_command_success_without_new_login_is_not_rotation_success(self):
        self.prepare(fleet=True)
        self.devices.ignore_write.add("R1")
        self.rotate(fleet=True)
        state = self.store.load()
        self.assertNotEqual(state["devices"]["R1"]["state"], "verified_new")
        self.assertIn(state["phase"], {"PARTIAL_FAILURE", "RECOVERY_REQUIRED"})
        self.assertEqual([name for name, _ in self.devices.writes], ["R1"])
        self.assertEqual(self.monitoring.calls, [])

    def test_disconnect_after_submission_keeps_unknown_until_readonly_reconciliation(self):
        self.prepare(fleet=True)
        self.devices.disconnect_after.add("R2")
        self.rotate(fleet=True)
        state = self.store.load()
        self.assertIn(state["phase"], {"PARTIAL_FAILURE", "RECOVERY_REQUIRED"})
        self.assertEqual([name for name, _ in self.devices.writes], ["R1", "R2"])
        self.assertNotEqual(state["devices"]["R2"]["state"], "verified_new")
        original = self.store.path.read_bytes()
        result = self.engine.verify()
        self.assertIsInstance(result, dict)
        self.assertEqual(self.store.path.read_bytes(), original)
        self.assertEqual(self.credentials.current.password, OLD_PASSWORD)
        self.assert_no_persisted_secrets()

    def test_process_interruption_preserves_durable_unknown_intent(self):
        self.prepare(fleet=True)
        self.devices.interrupt_after.add("R1")
        try:
            self.rotate(fleet=True)
        except KeyboardInterrupt:
            pass
        state = self.store.load()
        self.assertIn(state["phase"], {"ROTATING", "PARTIAL_FAILURE", "RECOVERY_REQUIRED"})
        self.assertTrue(state["devices"]["R1"]["attempted"])
        self.assertEqual(state["devices"]["R1"]["state"], "unknown")
        self.assertEqual([name for name, _ in self.devices.writes], ["R1"])
        self.assert_no_persisted_secrets()

    def test_resume_after_restart_reconciles_actual_device_and_skips_completed_write(self):
        self.prepare(fleet=True)
        self.devices.disconnect_after.add("R2")
        self.rotate(fleet=True)
        self.devices.disconnect_after.clear()
        self.engine = self.new_engine()
        self.recover("resume")
        state = self.store.load()
        self.assertEqual(state["phase"], "READY_TO_COMMIT")
        self.assertEqual([name for name, _ in self.devices.writes], list(FLEET))
        self.assertEqual(self.credentials.current.password, OLD_PASSWORD)
        self.assertEqual(self.monitoring.calls, [])

    def test_recovery_inspect_and_verify_are_readonly(self):
        self.prepare()
        self.rotate()
        before = self.store.path.read_bytes()
        vault_writes = list(self.credentials.writes)
        device_writes = list(self.devices.writes)
        self.assertIsInstance(self.engine.recover(action="inspect"), dict)
        self.assertIsInstance(self.engine.verify(), dict)
        self.assertEqual(self.store.path.read_bytes(), before)
        self.assertEqual(self.credentials.writes, vault_writes)
        self.assertEqual(self.devices.writes, device_writes)
        self.assertEqual(self.monitoring.calls, [])

    def test_ambiguous_reconciliation_stops_resume_before_any_new_writes(self):
        self.prepare(fleet=True)
        self.devices.disconnect_after.add("R1")
        self.rotate(fleet=True)
        self.devices.disconnect_after.clear()
        self.devices.accept_both.add("R1")
        before = list(self.devices.writes)
        self.recover("resume")
        self.assertEqual(self.devices.writes, before)
        self.assertEqual(self.store.load()["phase"], "RECOVERY_REQUIRED")

    def test_rollback_single_device_restores_current_pair_and_verifies_fleet(self):
        self.prepare()
        self.rotate()
        self.recover("rollback")
        state = self.store.load()
        self.assertEqual(state["phase"], "ROLLED_BACK")
        self.assertTrue(all(password == OLD_PASSWORD for password in self.devices.passwords.values()))
        self.assertTrue(all(device["state"] == "verified_old" for device in state["devices"].values()))
        self.assertEqual(self.credentials.current.password, OLD_PASSWORD)
        self.assertEqual([name for name, _ in self.devices.writes], ["R1", "R1"])
        self.assertEqual(self.monitoring.verification_calls, [(state["rotation_id"], FLEET)] * 2)
        self.assertEqual(state["monitoring_state"], "verified")
        self.assertEqual(self.monitoring.calls, [])
        self.assert_no_persisted_secrets()

    def test_rollback_failure_does_not_report_success_or_discard_pending(self):
        self.prepare()
        self.rotate()
        self.devices.rollback_fail.add("R1")
        self.recover("rollback")
        self.assertEqual(self.store.load()["phase"], "RECOVERY_REQUIRED")
        self.assertIsNotNone(self.credentials.pending)
        self.assertIsNotNone(self.credentials.previous)
        self.assertEqual(self.credentials.current.password, OLD_PASSWORD)

    def test_full_commit_promotes_only_after_fresh_verification_and_monitoring(self):
        self.prepare(fleet=True)
        self.rotate(fleet=True)
        self.devices.authentications.clear()
        self.commit()
        state = self.store.load()
        self.assertEqual(state["phase"], "COMMITTED")
        self.assertEqual(state["vault_state"], "promoted")
        self.assertEqual(state["monitoring_state"], "verified")
        self.assertEqual(self.credentials.current.password, self.credentials.pending.password)
        self.assertEqual({name for name, _, _ in self.devices.authentications}, set(FLEET))
        self.assertEqual(self.monitoring.calls, [(state["rotation_id"], FLEET)])
        self.assertIsNotNone(self.credentials.previous)
        self.assert_no_persisted_secrets()

    def test_commit_without_monitoring_hook_refuses_promotion(self):
        self.prepare(fleet=True)
        self.rotate(fleet=True)
        self.engine = self.new_engine(monitoring=False)
        with self.assertRaises(rotation.RotationError):
            self.commit()
        self.assertNotIn("promote", self.credentials.writes)
        self.assertEqual(self.credentials.current.password, OLD_PASSWORD)

    def test_commit_rechecks_devices_and_stops_if_one_no_longer_accepts_pending(self):
        self.prepare(fleet=True)
        self.rotate(fleet=True)
        self.devices.passwords["S4"] = OLD_PASSWORD
        self.commit()
        self.assertNotIn("promote", self.credentials.writes)
        self.assertEqual(self.credentials.current.password, OLD_PASSWORD)
        self.assertEqual(self.monitoring.calls, [])
        self.assertNotEqual(self.store.load()["phase"], "COMMITTED")
        self.assertEqual(self.store.load()["devices"]["S4"]["state"], "unknown")

    def test_vault_promotion_failure_preserves_recovery_material_and_blocks_monitoring(self):
        self.prepare(fleet=True)
        self.rotate(fleet=True)
        self.credentials.fail = "promote"
        self.commit()
        self.assertEqual(self.store.load()["phase"], "RECOVERY_REQUIRED")
        self.assertEqual(self.credentials.current.password, OLD_PASSWORD)
        self.assertIsNotNone(self.credentials.pending)
        self.assertIsNotNone(self.credentials.previous)
        self.assertEqual(self.monitoring.calls, [])
        self.assert_no_persisted_secrets()

    def test_promotion_wrong_readback_is_not_committed(self):
        self.prepare(fleet=True)
        self.rotate(fleet=True)
        self.credentials.promotion_returns_wrong_pair = True
        self.commit()
        self.assertEqual(self.store.load()["phase"], "RECOVERY_REQUIRED")
        self.assertEqual(self.monitoring.calls, [])

    def test_monitoring_failure_reports_actual_promoted_vault_and_preserves_recovery(self):
        self.prepare(fleet=True)
        self.rotate(fleet=True)
        self.monitoring.result = False
        self.commit()
        state = self.store.load()
        self.assertEqual(state["phase"], "RECOVERY_REQUIRED")
        self.assertEqual(state["vault_state"], "promoted")
        self.assertEqual(state["monitoring_state"], "failed")
        self.assertEqual(self.credentials.current.password, self.credentials.pending.password)
        self.assertIsNotNone(self.credentials.previous)
        self.assert_no_persisted_secrets()

    def test_inventory_drift_and_concurrent_operation_prevent_device_writes(self):
        self.prepare()
        self.inventory_data["devices"]["R1"]["management"]["ipv4"] = "192.0.2.99"
        self.write_inventory()
        with self.assertRaises(rotation.RotationError):
            self.rotate()
        self.assertEqual(self.devices.writes, [])
        self.inventory_data["devices"]["R1"]["management"]["ipv4"] = "192.0.2.1"
        self.write_inventory()
        with self.store.lock():
            with self.assertRaises((rotation.RotationError, StateError)):
                other = rotation.RotationEngine(self.credentials, self.devices, JournalStore(self.store.root),
                                                inventory_path=self.inventory, monitoring=self.monitoring)
                other.rotate(device="R1", authorized=True, confirmation="ROTATE R1")
        self.assertEqual(self.devices.writes, [])


    def test_precheck_authentication_failure_is_categorized_without_journal_or_writes(self):
        self.devices.passwords["R1"] = "not-the-current-fixture-password"
        report = self.engine.precheck(("R1",))
        self.assertFalse(report["passed"])
        self.assertEqual(report["error"], "authentication")
        self.assertFalse(self.store.root.exists())
        self.assertEqual(self.credentials.writes, [])
        self.assertEqual(self.devices.writes, [])

    def test_stage_reply_lost_after_vault_write_can_resume_from_owned_pending(self):
        self.credentials.staging_takes_effect_then_fails = True
        self.prepare(fleet=True)
        state = self.store.load()
        self.assertEqual(state["phase"], "RECOVERY_REQUIRED")
        self.assertIsNone(state["credential_refs"]["pending"])
        self.assertIsNotNone(self.credentials.pending)
        self.credentials.staging_takes_effect_then_fails = False
        self.engine = self.new_engine()
        self.recover("resume")
        self.assertEqual(self.store.load()["phase"], "READY_TO_COMMIT")
        self.assertEqual(self.credentials.writes.count("stage"), 1)
        self.assertEqual([name for name, _ in self.devices.writes], list(FLEET))
        self.assert_no_persisted_secrets()

    def test_promotion_reply_lost_reconciles_current_and_does_not_promote_twice(self):
        self.prepare(fleet=True)
        self.rotate(fleet=True)
        self.credentials.promotion_takes_effect_then_fails = True
        self.commit()
        self.assertEqual(self.store.load()["phase"], "RECOVERY_REQUIRED")
        self.assertEqual(self.store.load()["vault_state"], "unknown")
        self.assertEqual(self.credentials.current.password, self.credentials.pending.password)
        self.assertEqual(self.monitoring.calls, [])
        self.credentials.promotion_takes_effect_then_fails = False
        self.engine = self.new_engine()
        self.commit()
        self.assertEqual(self.store.load()["phase"], "COMMITTED")
        self.assertEqual(self.credentials.writes.count("promote"), 1)
        self.assertEqual(len(self.monitoring.calls), 1)
        self.assert_no_persisted_secrets()

    def test_monitoring_failure_can_be_retried_without_rewriting_devices_or_vault(self):
        self.prepare(fleet=True)
        self.rotate(fleet=True)
        self.monitoring.result = False
        self.commit()
        device_writes = list(self.devices.writes)
        vault_writes = list(self.credentials.writes)
        self.monitoring.result = True
        self.commit()
        self.assertEqual(self.store.load()["phase"], "COMMITTED")
        self.assertEqual(self.devices.writes, device_writes)
        self.assertEqual(self.credentials.writes, vault_writes)
        self.assertEqual(len(self.monitoring.calls), 2)

    def test_rollback_after_promotion_restores_vault_and_refreshes_existing_consumer(self):
        self.prepare(fleet=True)
        self.rotate(fleet=True)
        self.monitoring.result = False
        self.commit()
        self.monitoring.result = True
        self.recover("rollback")
        state = self.store.load()
        self.assertEqual(state["phase"], "ROLLED_BACK")
        self.assertEqual(state["vault_state"], "unchanged")
        self.assertEqual(state["monitoring_state"], "verified")
        self.assertEqual(self.credentials.current.password, OLD_PASSWORD)
        self.assertTrue(all(value == OLD_PASSWORD for value in self.devices.passwords.values()))
        self.assertEqual(self.credentials.writes.count("restore"), 1)
        self.assertEqual(len(self.monitoring.calls), 2)
        self.assert_no_persisted_secrets()

    def test_failed_durable_device_intent_prevents_password_submission(self):
        self.prepare()
        save = self.store.save

        def save_with_failure(record):
            event = record["events"][-1]
            if event["operation"] == "rotate" and event["result"] == "INFO":
                raise StateError("Fixture journal unavailable")
            return save(record)

        with patch.object(self.store, "save", side_effect=save_with_failure):
            self.rotate()
        self.assertEqual(self.devices.writes, [])
        self.assertNotEqual(self.store.load()["devices"]["R1"]["state"], "verified_new")
        self.assertEqual(self.credentials.current.password, OLD_PASSWORD)

    def test_cli_default_plan_is_offline_and_does_not_mutate(self):
        with patch.object(rotation, "RotationEngine", return_value=self.engine), \
                patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(rotation.main(["plan", "--dry-run"]), 0)
            result = json.loads(output.getvalue())
        self.assertEqual(result["mode"], "offline_dry_run")
        self.assertEqual(result["targets"], ["R1"])
        self.assertEqual(self.credentials.reads, [])
        self.assertEqual(self.devices.authentications, [])
        self.assertFalse(self.store.root.exists())

    def test_cli_execute_authorizes_without_a_terminal_or_confirmation_prompt(self):
        with patch.object(rotation, "RotationEngine", return_value=self.engine) as factory, \
                patch("sys.stdin.isatty", return_value=False), \
                patch("sys.stdout", new_callable=io.StringIO), \
                patch("builtins.input", side_effect=AssertionError("Noninteractive confirmation forbidden")):
            factory._category = type(self.engine)._category
            self.assertEqual(rotation.main(["prepare", "--device", "R1", "--execute"]), 0)
        self.assertEqual(self.credentials.writes, ["archive", "stage"])
        self.assertEqual(self.devices.writes, [])
        self.assertEqual(self.store.load()["phase"], "PREPARED")


    def test_failed_rollback_monitoring_is_retried_after_current_was_already_restored(self):
        self.prepare(fleet=True)
        self.rotate(fleet=True)
        self.monitoring.result = False
        self.commit()
        self.recover("rollback")
        self.assertEqual(self.credentials.current.password, OLD_PASSWORD)
        self.assertTrue(all(value == OLD_PASSWORD for value in self.devices.passwords.values()))
        self.assertEqual(self.store.load()["phase"], "RECOVERY_REQUIRED")
        device_writes = list(self.devices.writes)
        vault_writes = list(self.credentials.writes)
        calls = len(self.monitoring.calls)
        self.recover("rollback")
        self.assertEqual(self.store.load()["phase"], "RECOVERY_REQUIRED")
        self.assertEqual(len(self.monitoring.calls), calls + 1)
        self.monitoring.result = True
        self.recover("rollback")
        self.assertEqual(self.store.load()["phase"], "ROLLED_BACK")
        self.assertEqual(self.store.load()["monitoring_state"], "verified")
        self.assertEqual(len(self.monitoring.calls), calls + 2)
        self.assertEqual(self.devices.writes, device_writes)
        self.assertEqual(self.credentials.writes, vault_writes)

    def test_resume_after_crash_during_final_verification_does_not_repeat_device_writes(self):
        self.prepare(fleet=True)
        self.rotate(fleet=True)
        with self.store.lock():
            state = self.store.load()
            state["phase"] = "VERIFYING"
            self.store.save(state)
        writes = list(self.devices.writes)
        self.engine = self.new_engine()
        self.recover("resume")
        self.assertEqual(self.store.load()["phase"], "READY_TO_COMMIT")
        self.assertEqual(self.devices.writes, writes)
        self.assertEqual(self.credentials.current.password, OLD_PASSWORD)
        self.assertEqual(self.monitoring.calls, [])

    def test_failed_prepare_before_pending_can_be_explicitly_abandoned_without_writes(self):
        self.credentials.fail = "stage"
        self.prepare()
        self.assertIsNone(self.credentials.pending)
        self.assertFalse(any(item["attempted"] for item in self.store.load()["devices"].values()))
        writes = list(self.credentials.writes)
        self.devices.authentications.clear()
        self.recover("rollback")
        self.assertEqual(self.store.load()["phase"], "ROLLED_BACK")
        self.assertEqual(self.credentials.writes, writes)
        self.assertEqual(self.devices.writes, [])
        self.assertEqual({name for name, _, _ in self.devices.authentications}, set(FLEET))
        self.assertEqual(self.monitoring.calls, [])
        self.assert_no_persisted_secrets()

    def test_failed_archive_before_pending_can_be_explicitly_abandoned_without_writes(self):
        self.credentials.fail = "archive"
        self.prepare()
        self.assertIsNone(self.credentials.previous)
        self.assertIsNone(self.credentials.pending)
        writes = list(self.credentials.writes)
        self.recover("rollback")
        self.assertEqual(self.store.load()["phase"], "ROLLED_BACK")
        self.assertEqual(self.credentials.writes, writes)
        self.assertEqual(self.devices.writes, [])
        self.assertEqual(self.credentials.current.password, OLD_PASSWORD)

    def test_lost_archive_reply_is_recovered_by_owned_rotation_reference(self):
        self.credentials.archive_takes_effect_then_fails = True
        self.prepare()
        self.assertIsNotNone(self.credentials.previous)
        self.assertIsNone(self.store.load()["credential_refs"]["previous"])
        writes = list(self.credentials.writes)
        self.recover("rollback")
        self.assertEqual(self.store.load()["phase"], "ROLLED_BACK")
        self.assertEqual(self.credentials.writes, writes)
        self.assertEqual(self.devices.writes, [])
        self.assertEqual(self.credentials.current.password, OLD_PASSWORD)


    def test_r1_rollback_waits_for_readonly_monitoring_proof_and_retries_without_writes(self):
        self.prepare()
        self.rotate()
        self.monitoring.verification_result = False
        result = self.recover("rollback")
        self.assertEqual(result["monitoring_request"]["action"], "verify_current")
        self.assertEqual(self.store.load()["phase"], "RECOVERY_REQUIRED")
        self.assertEqual(self.credentials.current.password, OLD_PASSWORD)
        self.assertTrue(all(value == OLD_PASSWORD for value in self.devices.passwords.values()))
        self.assertEqual(self.monitoring.calls, [])
        self.assertEqual(len(self.monitoring.verification_calls), 2)
        writes = list(self.devices.writes)
        self.recover("rollback")
        self.assertEqual(self.store.load()["phase"], "RECOVERY_REQUIRED")
        self.assertEqual(len(self.monitoring.verification_calls), 3)
        self.monitoring.verification_result = True
        self.recover("rollback")
        self.assertEqual(self.store.load()["phase"], "ROLLED_BACK")
        self.assertEqual(self.store.load()["monitoring_state"], "verified")
        self.assertEqual(len(self.monitoring.verification_calls), 4)
        self.assertEqual(self.devices.writes, writes)
        self.assertEqual(self.monitoring.calls, [])
        self.assert_no_persisted_secrets()

    def test_unavailable_r1_telemetry_hook_does_not_prevent_password_restoration(self):
        self.prepare()
        self.rotate()
        self.monitoring.verification_available = False
        self.recover("rollback")
        self.assertEqual(self.devices.passwords["R1"], OLD_PASSWORD)
        self.assertEqual(self.store.load()["phase"], "RECOVERY_REQUIRED")
        self.assertEqual(len(self.monitoring.verification_calls), 1)
        writes = list(self.devices.writes)
        self.monitoring.verification_available = True
        self.recover("rollback")
        self.assertEqual(self.store.load()["phase"], "ROLLED_BACK")
        self.assertEqual(self.devices.writes, writes)
        self.assertEqual(len(self.monitoring.verification_calls), 2)
        self.assertEqual(self.monitoring.calls, [])


    def test_verify_after_commit_reports_unknown_authentication_without_rewriting_journal(self):
        self.prepare(fleet=True)
        self.rotate(fleet=True)
        self.commit()
        before = self.store.path.read_bytes()
        vault_writes = list(self.credentials.writes)
        device_writes = list(self.devices.writes)
        self.devices.unreachable.add("S4")
        result = self.engine.verify()
        self.assertFalse(result["passed"])
        self.assertFalse(result["observations_complete"])
        self.assertEqual(result["device_states"]["S4"]["state"], "unknown")
        self.assertEqual(result["outcome"], "Verification Observations")
        self.assertTrue(result["observation_only"])
        self.assertEqual(self.store.path.read_bytes(), before)
        self.assertEqual(self.credentials.writes, vault_writes)
        self.assertEqual(self.devices.writes, device_writes)

    def test_verify_known_old_after_commit_is_complete_but_does_not_pass(self):
        self.prepare(fleet=True)
        self.rotate(fleet=True)
        self.commit()
        before = self.store.path.read_bytes()
        self.devices.passwords["S4"] = OLD_PASSWORD
        result = self.engine.verify()
        self.assertFalse(result["passed"])
        self.assertTrue(result["observations_complete"])
        self.assertEqual(result["device_states"]["S4"]["state"], "verified_old")
        self.assertEqual(self.store.path.read_bytes(), before)

    def test_current_reference_replaced_during_promotion_fails_readback(self):
        self.prepare(fleet=True)
        self.rotate(fleet=True)
        promote = self.credentials.promote

        def promote_with_replacement(current, pending):
            promoted = promote(current, pending)
            self.credentials.current = replace(promoted, reference="z" * 26)
            self.credentials.items[self.credentials.current.reference] = self.credentials.current
            return self.credentials.current

        with patch.object(self.credentials, "promote", side_effect=promote_with_replacement):
            result = self.commit()
        self.assertEqual(result["phase"], "RECOVERY_REQUIRED")
        self.assertNotEqual(result["outcome"], "Success")
        self.assertEqual(self.store.load()["phase"], "RECOVERY_REQUIRED")
        self.assertEqual(self.monitoring.calls, [])
        self.assertIsNotNone(self.credentials.previous)
        self.assertIsNotNone(self.credentials.pending)
        self.assert_no_persisted_secrets()

    def test_failed_terminal_commit_journal_save_cannot_report_success(self):
        self.prepare(fleet=True)
        self.rotate(fleet=True)
        save = self.store.save

        def fail_terminal_save(record):
            if record["phase"] == "COMMITTED":
                raise StateError("Fixture terminal journal failure")
            return save(record)

        with patch.object(self.store, "save", side_effect=fail_terminal_save):
            result = self.commit()
        self.assertEqual(result["phase"], "RECOVERY_REQUIRED")
        self.assertNotEqual(result["outcome"], "Success")
        state = self.store.load()
        self.assertEqual(state["phase"], "RECOVERY_REQUIRED")
        self.assertIsNone(state["ended_at"])
        self.assertEqual(state["events"][-1]["error"], "journal")
        self.assertEqual(self.credentials.current.password, self.credentials.pending.password)
        self.assert_no_persisted_secrets()

    def test_failed_terminal_rollback_journal_save_cannot_report_completion(self):
        self.prepare()
        self.rotate()
        save = self.store.save

        def fail_terminal_save(record):
            if record["phase"] == "ROLLED_BACK":
                raise StateError("Fixture terminal journal failure")
            return save(record)

        with patch.object(self.store, "save", side_effect=fail_terminal_save):
            result = self.recover("rollback")
        self.assertEqual(result["phase"], "RECOVERY_REQUIRED")
        self.assertNotEqual(result["outcome"], "Rollback Completed")
        state = self.store.load()
        self.assertEqual(state["phase"], "RECOVERY_REQUIRED")
        self.assertIsNone(state["ended_at"])
        self.assertEqual(state["events"][-1]["error"], "journal")
        self.assertEqual(self.devices.passwords["R1"], OLD_PASSWORD)
        self.assert_no_persisted_secrets()


    def test_prepare_without_monitoring_proof_hook_refuses_before_journal_or_vault_access(self):
        self.engine = self.new_engine(monitoring=False)
        with self.assertRaises(rotation.RotationError):
            self.prepare()
        self.assertFalse(self.store.root.exists())
        self.assertEqual(self.credentials.reads, [])
        self.assertEqual(self.credentials.writes, [])
        self.assertEqual(self.devices.writes, [])

    def test_fleet_prepare_requires_refresh_hook_in_addition_to_readonly_verification(self):
        self.monitoring.available = False
        with self.assertRaises(rotation.RotationError):
            self.prepare(fleet=True)
        self.assertFalse(self.store.root.exists())
        self.assertEqual(self.credentials.writes, [])
        self.assertEqual(self.devices.writes, [])
        self.prepare()  # R1 only needs the independent read-only rollback proof hook.
        self.assertEqual(self.store.load()["phase"], "PREPARED")
        self.assertEqual(self.store.load()["scope"], ["R1"])

    def test_rotate_refuses_if_required_monitoring_hook_disappears_after_preparation(self):
        self.prepare()
        writes = list(self.credentials.writes)
        self.monitoring.verification_available = False
        result = self.rotate()
        self.assertEqual(result["phase"], "RECOVERY_REQUIRED")
        self.assertEqual(self.store.load()["events"][-1]["error"], "monitoring")
        self.assertFalse(any(item["attempted"] for item in self.store.load()["devices"].values()))
        self.assertEqual(self.devices.writes, [])
        self.assertEqual(self.credentials.writes, writes)


    def test_fleet_command_stages_before_devices_then_saves_all_before_promotion_and_restart(self):
        events = []

        def trace(owner, method, label, device=False):
            original = getattr(owner, method)

            def observed(*args, **kwargs):
                events.append((label, args[0]) if device else label)
                return original(*args, **kwargs)

            self.enterContext(patch.object(owner, method, side_effect=observed))

        trace(self.monitoring, "verify_current", "baseline")
        trace(self.credentials, "stage_pending", "stage")
        trace(self.devices, "change_password", "change", device=True)
        trace(self.devices, "ensure_verified", "verify_save", device=True)
        trace(self.credentials, "promote", "promote")
        trace(self.monitoring, "refresh_and_verify", "restart_verify")
        result = self.engine.run_fleet(authorized=True)
        expected = ["baseline", "stage"]
        for name in FLEET:
            expected.extend([("change", name), ("verify_save", name)])
        expected.extend(("verify_save", name) for name in FLEET)
        expected.extend(["promote", "restart_verify"])
        self.assertEqual(events, expected)
        self.assertEqual(result["phase"], "COMMITTED")
        self.assertTrue(all(password == self.credentials.pending.password
                            for password in self.devices.startup_passwords.values()))
        self.assert_no_persisted_secrets()

    def test_fleet_command_stops_at_first_failure_and_retains_current_pending_without_restart(self):
        self.devices.fail_before.add("R3")
        result = self.engine.run_fleet(authorized=True)
        self.assertEqual(result["phase"], "PARTIAL_FAILURE")
        self.assertEqual([name for name, _ in self.devices.writes], list(FLEET[:3]))
        self.assertEqual([name for name, _ in self.devices.save_checks], list(FLEET[:2]))
        self.assertEqual(self.credentials.current.password, OLD_PASSWORD)
        self.assertIsNotNone(self.credentials.pending)
        self.assertIsNotNone(self.credentials.previous)
        self.assertNotIn("promote", self.credentials.writes)
        self.assertEqual(self.monitoring.calls, [])
        self.assert_no_persisted_secrets()

    def test_failed_monitoring_baseline_blocks_staging_and_device_changes(self):
        self.monitoring.verification_result = False
        with self.assertRaises(rotation.RotationError):
            self.engine.run_fleet(authorized=True)
        self.assertFalse(self.store.path.exists())
        self.assertEqual(self.credentials.writes, [])
        self.assertEqual(self.devices.writes, [])
        self.assertEqual(self.monitoring.calls, [])

    def test_resume_requires_verified_startup_save_before_advancing_past_changed_device(self):
        self.prepare(fleet=True)
        self.devices.disconnect_after.add("R2")
        self.rotate(fleet=True)
        self.assertEqual(self.devices.passwords["R2"], self.credentials.pending.password)
        self.assertEqual(self.devices.startup_passwords["R2"], OLD_PASSWORD)
        self.devices.disconnect_after.clear()
        self.devices.save_fail.add("R2")
        self.recover("resume")
        self.assertEqual([name for name, _ in self.devices.writes], ["R1", "R2"])
        self.assertEqual(self.store.load()["devices"]["R2"]["state"], "unknown")
        self.assertEqual(self.credentials.current.password, OLD_PASSWORD)
        self.assertEqual(self.monitoring.calls, [])
        self.devices.save_fail.clear()
        self.recover("resume")
        self.assertEqual(self.store.load()["phase"], "READY_TO_COMMIT")
        self.assertEqual([name for name, _ in self.devices.writes], list(FLEET))
        self.assertTrue(all(password == self.credentials.pending.password
                            for password in self.devices.startup_passwords.values()))

    def test_commit_startup_verification_failure_prevents_promotion_and_restart(self):
        self.prepare(fleet=True)
        self.rotate(fleet=True)
        self.devices.save_fail.add("S3")
        result = self.commit()
        self.assertEqual(result["phase"], "RECOVERY_REQUIRED")
        self.assertEqual(self.store.load()["devices"]["S3"]["state"], "unknown")
        self.assertNotIn("promote", self.credentials.writes)
        self.assertEqual(self.monitoring.calls, [])
        self.assertEqual(self.credentials.current.password, OLD_PASSWORD)

    def test_cli_fleet_execute_needs_no_prompts_and_returns_success(self):
        with patch.object(rotation, "RotationEngine", return_value=self.engine) as factory, \
                patch("sys.stdin.isatty", return_value=False), \
                patch("sys.stdout", new_callable=io.StringIO) as output, \
                patch("builtins.input", side_effect=AssertionError("No extra confirmation")):
            factory._category = type(self.engine)._category
            self.assertEqual(rotation.main(["fleet", "--execute"]), 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(report["phase"], "COMMITTED")
        self.notification.assert_called_once()
        from security.rotation_email import notification_content
        subject, body = notification_content(self.notification.call_args.args[0])
        self.assertEqual(subject, "NetPilot Password Rotation Successful")
        for value in ("9/9", "1Password synchronization: promoted", "Monitoring verification: verified"):
            self.assertIn(value, body)
        self.assertNotIn(OLD_PASSWORD, output.getvalue())
        self.assertNotIn(self.credentials.pending.password, output.getvalue())

    def test_cli_fleet_dry_run_is_offline_and_execute_cannot_be_combined(self):
        with patch.object(rotation, "RotationEngine", return_value=self.engine) as factory, \
                patch("sys.stdout", new_callable=io.StringIO) as output, \
                patch("builtins.input", side_effect=AssertionError("No extra confirmation")):
            factory._category = type(self.engine)._category
            self.assertEqual(rotation.main(["fleet", "--dry-run"]), 0)
            report = json.loads(output.getvalue())
            self.assertEqual(report["targets"], list(FLEET))
            output.truncate(0)
            output.seek(0)
            self.assertEqual(rotation.main(["fleet", "--dry-run", "--execute"]), 1)
            self.assertEqual(json.loads(output.getvalue())["error"], "blocked")
        self.assertEqual(self.credentials.reads, [])
        self.assertEqual(self.credentials.writes, [])
        self.assertEqual(self.devices.authentications, [])
        self.assertEqual(self.devices.writes, [])
        self.assertEqual(self.monitoring.calls, [])
        self.assertEqual(self.monitoring.verification_calls, [])
        self.assertFalse(self.store.root.exists())
        self.notification.assert_not_called()

    def test_failed_cleanup_requires_execute_and_cli_has_no_extra_prompt(self):
        with self.assertRaises(rotation.RotationError):
            self.engine.cleanup_failed()
        self.assertFalse(self.store.root.exists())
        with patch.object(rotation, "RotationEngine", return_value=self.engine) as factory, \
                patch.object(self.engine, "cleanup_failed", return_value={"passed": True, "phase": "CLEANED"}) as cleanup, \
                patch("sys.stdin.isatty", return_value=False), \
                patch("sys.stdout", new_callable=io.StringIO) as output, \
                patch("builtins.input", side_effect=AssertionError("No extra confirmation")):
            factory._category = type(self.engine)._category
            self.assertEqual(rotation.main(["cleanup-failed"]), 1)
            cleanup.assert_not_called()
            output.seek(0)
            output.truncate(0)
            self.assertEqual(rotation.main(["cleanup-failed", "--execute"]), 0)
            cleanup.assert_called_once_with(authorized=True)
            self.assertEqual(json.loads(output.getvalue())["result"], "PASS")
        self.assertEqual(self.credentials.reads, [])
        self.assertEqual(self.devices.writes, [])

    def test_fixed_password_diagnostic_is_reported_without_persisting_payloads(self):
        self.prepare(fleet=True)
        error = AdapterError("credentials", detail="replacement_password_policy")
        with patch.object(self.devices, "change_password", side_effect=error):
            result = self.rotate(fleet=True)
        self.assertEqual(result["phase"], "PARTIAL_FAILURE")
        self.assertEqual(result["error_message"], rotation.adapter_error_detail(error))
        self.assertNotIn(OLD_PASSWORD, json.dumps(result))
        self.assertNotIn(self.credentials.pending.password, json.dumps(result))
        self.assertNotIn("error_message", self.store.load())
        self.assert_no_persisted_secrets()

    def test_full_fleet_holds_one_lock_across_all_phases(self):
        other = JournalStore(self.store.root)
        original = self.devices.change_password
        attempted = []
        def probe(*args, **kwargs):
            with self.assertRaises(StateError):
                with other.lock():
                    self.fail("Concurrent manual/scheduled mutation acquired the lock")
            attempted.append(args[0])
            return original(*args, **kwargs)
        with patch.object(self.devices, "change_password", side_effect=probe):
            self.assertEqual(self.engine.run_fleet(authorized=True)["phase"], "COMMITTED")
        self.assertEqual(attempted, list(FLEET))

    def test_next_cycle_retires_owned_pending_only_after_fresh_fleet_and_monitoring_checks(self):
        self.engine.run_fleet(authorized=True)
        previous = self.store.load()
        self.devices.authentications.clear()
        before_baselines = len(self.monitoring.verification_calls)
        def retire(engine, record, current):
            self.assertEqual(record, previous)
            self.assertEqual(set(name for name, _, _ in self.devices.authentications), set(FLEET))
            self.assertEqual(len(self.monitoring.verification_calls), before_baselines + 1)
            self.store._assert_locked()
            self.store.archive_completed(record)
            self.credentials.pending = None
        with patch("security.rotation_cleanup.retire_completed_pending", side_effect=retire) as retirement:
            result = self.engine.run_fleet(authorized=True)
        retirement.assert_called_once()
        self.assertEqual(result["phase"], "COMMITTED")
        self.assertNotEqual(result["rotation_id"], previous["rotation_id"])
        self.assertEqual(self.store.history(), [previous])
        self.assertEqual(len(self.devices.writes), 18)

    def test_failed_fresh_baseline_never_retires_completed_pending(self):
        self.engine.run_fleet(authorized=True)
        previous = self.store.path.read_bytes()
        self.monitoring.verification_result = False
        with patch("security.rotation_cleanup.retire_completed_pending") as retirement:
            with self.assertRaises(rotation.RotationError):
                self.engine.run_fleet(authorized=True)
        retirement.assert_not_called()
        self.assertEqual(self.store.path.read_bytes(), previous)
        self.assertEqual(len(self.devices.writes), 9)

    def test_cli_mail_failure_is_separate_from_committed_rotation(self):
        self.notification.return_value = {"status": "failed", "error": "smtp_delivery_failed"}
        with patch.object(rotation, "RotationEngine", return_value=self.engine) as factory, \
                patch("sys.stdout", new_callable=io.StringIO) as output:
            factory._category = type(self.engine)._category
            self.assertEqual(rotation.main(["fleet", "--execute"]), 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["phase"], "COMMITTED")
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(report["notification"]["status"], "failed")
        self.assertEqual(self.store.load()["phase"], "COMMITTED")
        self.notification.assert_called_once()

    def test_cli_sends_failure_notification_on_stopped_fleet(self):
        self.devices.fail_before.add("R2")
        with patch.object(rotation, "RotationEngine", return_value=self.engine) as factory, \
                patch("sys.stdout", new_callable=io.StringIO):
            factory._category = type(self.engine)._category
            self.assertEqual(rotation.main(["fleet", "--execute"]), 1)
        self.notification.assert_called_once()
        report = self.notification.call_args.args[0]
        self.assertEqual(report["phase"], "PARTIAL_FAILURE")
        self.assertEqual(report["device_states"]["R2"]["state"], "unknown")
        from security.rotation_email import notification_content
        subject, body = notification_content(report)
        self.assertEqual(subject, "NetPilot Password Rotation Failed")
        for value in ("Failed device: R2", "Failed stage: rotate", "Manual recovery required: YES"):
            self.assertIn(value, body)
        self.assertNotIn(OLD_PASSWORD, body)
        self.assertNotIn(self.credentials.pending.password, body)

    def test_interrupt_during_mail_leaves_committed_rotation_successful(self):
        self.notification.side_effect = KeyboardInterrupt
        with patch.object(rotation, "RotationEngine", return_value=self.engine) as factory, \
                patch("sys.stdout", new_callable=io.StringIO) as output:
            factory._category = type(self.engine)._category
            self.assertEqual(rotation.main(["fleet", "--execute"]), 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["phase"], "COMMITTED")
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(report["notification"]["status"], "failed")
        self.notification.assert_called_once()

    def test_preparation_exception_and_interrupt_send_exactly_one_failure_notice(self):
        for error in (rotation.RotationError("monitoring"), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                self.notification.reset_mock()
                with patch.object(rotation, "RotationEngine", return_value=self.engine) as factory, \
                        patch.object(self.engine, "run_fleet", side_effect=error), \
                        patch("sys.stdout", new_callable=io.StringIO) as output:
                    factory._category = type(self.engine)._category
                    self.assertIn(rotation.main(["fleet", "--execute"]), (1, 130))
                self.notification.assert_called_once()
                report = json.loads(output.getvalue())
                self.assertEqual(report["result"], "FAIL")
                self.assertIn(report["error"], ("monitoring", "interrupted"))

    def test_fleet_requires_execute_authorization_before_external_operations(self):
        with self.assertRaises(rotation.RotationError):
            self.engine.run_fleet()
        self.assertEqual(self.credentials.reads, [])
        self.assertEqual(self.credentials.writes, [])
        self.assertEqual(self.devices.authentications, [])
        self.assertEqual(self.devices.writes, [])
        self.assertEqual(self.monitoring.calls, [])


    def test_readonly_commands_do_not_email_even_with_execute_or_failed_state(self):
        self.devices.fail_before.add("R2")
        self.engine.run_fleet(authorized=True)
        self.notification.assert_not_called()  # Only the manual/scheduled caller delivers.
        before = self.store.path.read_bytes()
        for action in ("status", "verify", "recover"):
            with self.subTest(action=action), \
                    patch.object(rotation, "RotationEngine", return_value=self.engine), \
                    patch("sys.stdout", new_callable=io.StringIO):
                rotation.main([action, "--execute"])
        self.notification.assert_not_called()
        self.assertEqual(self.store.path.read_bytes(), before)

    def test_terminal_output_failure_does_not_send_duplicate_notification(self):
        with patch.object(rotation, "RotationEngine", return_value=self.engine) as factory, \
                patch("builtins.print", side_effect=[OSError("closed terminal"), None]):
            factory._category = type(self.engine)._category
            self.assertEqual(rotation.main(["fleet", "--execute"]), 1)
        self.notification.assert_called_once()
        self.assertEqual(self.notification.call_args.args[0]["phase"], "COMMITTED")
        self.assertEqual(self.store.load()["phase"], "COMMITTED")


class PasswordPolicyTests(unittest.TestCase):
    def test_random_passwords_have_length_diversity_and_telegraf_compatible_alphabet(self):
        passwords = {rotation.generate_password(OLD_PASSWORD) for _ in range(20)}
        self.assertEqual(len(passwords), 20)
        allowed = set(string.ascii_letters + string.digits + "-_!@")
        for password in passwords:
            self.assertGreaterEqual(len(password), 24)
            self.assertLessEqual(set(password), allowed)
            self.assertNotEqual(password, OLD_PASSWORD)
            self.assertEqual(interpolation_value(password), password)

    def test_generated_password_equal_to_previous_is_discarded(self):
        with patch.object(rotation.secrets, "choice", side_effect=list("a" * 32 + "b" * 32)):
            self.assertEqual(rotation.generate_password("a" * 32), "b" * 32)

    def test_password_length_rejects_less_than_24_and_accepts_explicit_length(self):
        for length in (0, 1, 23):
            with self.subTest(length=length), self.assertRaises((rotation.RotationError, ValueError)):
                rotation.generate_password(OLD_PASSWORD, length=length)
        self.assertEqual(len(rotation.generate_password(OLD_PASSWORD, length=24)), 24)


if __name__ == "__main__":
    unittest.main()

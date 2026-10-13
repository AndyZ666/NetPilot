"""Offline cleanup ownership and interrupted-archive tests; no real Vault/SSH."""

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from security import credential_provider
from security import rotation_cleanup as cleanup
from security.rotation_adapters import AdapterError, OnePasswordStore
from security.credential_rotation import RotationEngine
from security.rotation_state import FLEET, JournalStore, StateError


CURRENT, PENDING, PREVIOUS = "c" * 26, "p" * 26, "v" * 26
ROTATION = "a" * 32
OLD, NEW = "synthetic-original-password", "synthetic-pending-password"
STAMP = "2026-10-12T12:00:00Z"
INVENTORY = dict(zip(FLEET, ("172.20.20." + suffix for suffix in (
    "13", "14", "9", "11", "2", "7", "8", "4", "10"))))


def completed_record():
    record = {
        "version": 1, "rotation_id": ROTATION, "started_at": STAMP, "updated_at": STAMP,
        "ended_at": STAMP, "phase": "ROLLED_BACK", "scope": ["R1"], "username": "admin",
        "devices": {name: {"management_ip": address, "state": "pending", "attempted": False,
                            "verified_at": None, "last_error": None}
                    for name, address in INVENTORY.items()},
        "credential_refs": {"current": CURRENT, "pending": PENDING, "previous": PREVIOUS},
        "vault_state": "pending_staged", "monitoring_state": "not_requested", "events": [],
    }
    record["devices"]["R1"].update(state="verified_old", attempted=True, verified_at=STAMP)
    for operation, phase in (("verify", "VERIFYING"), ("rollback", "ROLLING_BACK")):
        record["events"].append({"at": STAMP, "phase": phase, "operation": operation,
                                 "device": "R1", "result": "PASS", "error": None})
    return record


def item(reference, title, password, binding=False):
    fields = [{"id": "username", "value": "admin"}, {"id": "password", "value": password}]
    if binding:
        fields += [{"id": "netpilot_rotation_id", "value": ROTATION},
                   {"id": "netpilot_current_reference", "value": CURRENT}]
    return {"id": reference, "title": title, "category": "LOGIN", "fields": fields}


class FakeVault:
    def __init__(self, events):
        self.events, self.calls, self.archived = events, [], set()
        self.items = {
            CURRENT: item(CURRENT, "NetPilot-Current", OLD),
            PENDING: item(PENDING, "NetPilot-Pending", NEW, True),
            PREVIOUS: item(PREVIOUS, "NetPilot-Previous-" + ROTATION, OLD, True),
            "u" * 26: item("u" * 26, "Unrelated-Account", "synthetic-unrelated"),
        }
        self.fail_archive = self.archive_then_fail = None
        self.ignore_archive = False

    def run(self, arguments, **kwargs):
        self.calls.append(list(arguments))
        operation = arguments[1]
        if operation == "list":
            return json.dumps([{"id": key, "title": value["title"]}
                               for key, value in self.items.items() if key not in self.archived])
        if operation == "get":
            reference = arguments[2]
            if reference == "NetPilot-Current":
                reference = CURRENT
            if reference in self.archived and "--include-archive" not in arguments:
                raise RuntimeError("Archived item requires explicit read")
            value = self.items[reference]
            if "--fields" in arguments:
                return json.dumps([{**field, "label": field["id"]} for field in value["fields"]
                                   if field["id"] in ("username", "password")])
            return json.dumps(value)
        if operation == "delete":
            reference = arguments[2]
            if arguments != ["item", "delete", reference, "--vault", "NetPilot-Secrets", "--archive"]:
                raise AssertionError("Only scoped archive-by-ID is permitted")
            if reference not in (PENDING, PREVIOUS):
                raise AssertionError("Unrelated item mutation")
            if self.fail_archive == reference:
                raise RuntimeError(OLD)
            if not self.ignore_archive:
                self.archived.add(reference)
            self.events.append(("archive", reference))
            if self.archive_then_fail == reference:
                self.archive_then_fail = None
                raise RuntimeError(NEW)
            return ""
        raise AssertionError("Unexpected CLI operation")


class FakeJournal:
    def __init__(self, events):
        self.record, self.archives, self.events = completed_record(), [], events
        self.locked = True

    def _assert_locked(self):
        if not self.locked:
            raise StateError("No lock")

    def load(self):
        return deepcopy(self.record)

    def archive_completed(self, record):
        if record != self.record:
            raise StateError("Changed journal")
        if record not in self.archives:
            self.archives.append(deepcopy(record))
        self.events.append(("journal_archive",))

    archive_failed = archive_completed

    def finish_failed(self, record):
        self.finish_completed(record)

    def finish_completed(self, record):
        self.archive_completed(record)
        self.record = None
        self.events.append(("journal_finish",))


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.vault, self.journal = FakeVault(self.events), FakeJournal(self.events)
        self.store = OnePasswordStore()
        self.devices = Mock()
        self.devices.authenticate.side_effect = lambda *args: self.events.append(("authenticate",))
        self.enterContext(patch.object(credential_provider, "_run_op", side_effect=self.vault.run))
        self.enterContext(patch.object(credential_provider, "_read_token", side_effect=AssertionError("No token reads")))
        self.enterContext(patch("socket.create_connection", side_effect=AssertionError("No network")))

    def run_cleanup(self):
        return cleanup.cleanup_r1_test(self.store, self.devices, self.journal, INVENTORY)

    def assert_refused(self):
        with self.assertRaises(cleanup.CleanupError) as caught:
            self.run_cleanup()
        for secret in (OLD, NEW):
            self.assertNotIn(secret, str(caught.exception))
        self.assertIsNotNone(self.journal.record)
        return caught.exception

    def test_completed_test_archives_only_bound_items_after_fresh_authentication(self):
        before = deepcopy(self.vault.items)
        result = self.run_cleanup()
        self.assertTrue(result["passed"])
        self.assertEqual(result["phase"], "CLEANED")
        self.assertEqual(self.vault.archived, {PENDING, PREVIOUS})
        self.assertEqual(self.vault.items, before)
        self.assertIsNone(self.journal.record)
        self.assertEqual(len(self.journal.archives), 1)
        self.assertEqual(self.events[0], ("authenticate",))
        self.assertLess(self.events.index(("journal_archive",)), self.events.index(("archive", PENDING)))
        name, address, credential = self.devices.authenticate.call_args.args
        self.assertEqual((name, address, credential.password), ("R1", INVENTORY["R1"], OLD))
        self.assertFalse(any(secret in repr(self.vault.calls) for secret in (OLD, NEW)))

    def test_ambiguous_or_failed_test_is_refused_without_vault_mutation(self):
        mutations = (
            lambda r: r.update(phase="RECOVERY_REQUIRED"),
            lambda r: r.update(scope=list(FLEET)),
            lambda r: r.update(monitoring_state="verified"),
            lambda r: r["devices"]["R2"].update(attempted=True),
            lambda r: r["devices"]["R1"].update(state="unknown"),
            lambda r: r["events"].reverse(),
            lambda r: r["events"][0].update(result="FAIL"),
            lambda r: r["credential_refs"].update(pending=None),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.journal.record = completed_record()
                mutation(self.journal.record)
                self.assert_refused()
                self.assertEqual(self.vault.archived, set())
        self.devices.authenticate.assert_not_called()

    def test_different_current_or_misbound_items_are_refused(self):
        for reference, key, value in ((CURRENT, "password", NEW),
                                      (PENDING, "netpilot_rotation_id", "b" * 32),
                                      (PREVIOUS, "netpilot_current_reference", "x" * 26)):
            with self.subTest(reference=reference, key=key):
                original = deepcopy(self.vault.items)
                next(field for field in self.vault.items[reference]["fields"] if field["id"] == key)["value"] = value
                self.assert_refused()
                self.assertEqual(self.vault.archived, set())
                self.vault.items = original
        self.devices.authenticate.assert_not_called()

    def test_original_password_failure_preserves_everything(self):
        self.devices.authenticate.side_effect = RuntimeError(OLD)
        self.assertEqual(self.assert_refused().stage, "fresh R1 original admin authentication")
        self.assertFalse(self.vault.archived)
        self.assertFalse(self.journal.archives)

    def test_current_drift_after_authentication_blocks_archives(self):
        def change(*args):
            self.vault.items[CURRENT]["fields"][1]["value"] = NEW
        self.devices.authenticate.side_effect = change
        self.assert_refused()
        self.assertFalse(self.vault.archived)

    def test_partial_archive_timeout_can_retry_by_id_without_losing_journal(self):
        self.vault.archive_then_fail = PENDING
        self.assert_refused()
        self.assertEqual(self.vault.archived, {PENDING})
        self.assertEqual(len(self.journal.archives), 1)
        self.assertTrue(self.run_cleanup()["passed"])
        self.assertEqual(self.vault.archived, {PENDING, PREVIOUS})
        self.assertEqual(self.events.count(("archive", PENDING)), 1)
        self.assertEqual(self.devices.authenticate.call_count, 2)

    def test_conflicting_active_pending_blocks_partial_cleanup_retry(self):
        self.vault.archived.add(PENDING)
        self.vault.items["x" * 26] = item("x" * 26, "NetPilot-Pending", NEW, True)
        self.assert_refused()
        self.assertEqual(self.vault.archived, {PENDING})
        self.devices.authenticate.assert_not_called()

    def test_unconfirmed_archive_does_not_clear_journal_or_archive_previous(self):
        self.vault.ignore_archive = True
        self.assertEqual(self.assert_refused().stage, "bound pending archive")
        self.assertFalse(self.vault.archived)
        self.assertNotIn(("archive", PREVIOUS), self.events)

    def test_missing_item_is_not_treated_as_already_archived(self):
        del self.vault.items[PENDING]
        self.assert_refused()
        self.assertFalse(self.vault.archived)
        self.devices.authenticate.assert_not_called()

    def test_cleanup_requires_existing_operation_lock(self):
        self.journal.locked = False
        self.assert_refused()
        self.assertEqual(self.vault.calls, [])


def failed_record():
    record = completed_record()
    record.update(phase="PARTIAL_FAILURE", scope=list(FLEET), ended_at=None)
    for entry in record["devices"].values():
        entry.update(state="verified_old", verified_at=STAMP)
    record["devices"]["R1"].update(state="unknown", verified_at=None, last_error="credentials")
    record["events"] = [{"at": STAMP, "phase": "PARTIAL_FAILURE", "operation": "rotate",
                         "device": "R1", "result": "FAIL", "error": "credentials"}]
    return record


class FailedCleanupTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.vault, self.journal = FakeVault(self.events), FakeJournal(self.events)
        self.journal.record = failed_record()
        self.original = deepcopy(self.journal.record)
        self.devices = Mock()
        self.devices.authenticate.side_effect = self.authenticate
        self.engine = RotationEngine(OnePasswordStore(), self.devices, self.journal)
        self.engine._inventory = Mock(return_value=INVENTORY)
        self.device_passwords = dict.fromkeys(FLEET, OLD)
        self.unknown = set()
        self.enterContext(patch.object(credential_provider, "_run_op", side_effect=self.vault.run))
        self.enterContext(patch.object(credential_provider, "_read_token", side_effect=AssertionError("No token reads")))
        self.enterContext(patch("socket.create_connection", side_effect=AssertionError("No network")))

    def authenticate(self, name, address, credential):
        self.events.append(("authenticate", name))
        if name in self.unknown:
            raise AdapterError("unreachable")
        if credential.password != self.device_passwords[name]:
            raise AdapterError("authentication")

    def run_cleanup(self):
        return cleanup.cleanup_failed_rotation(self.engine)

    def assert_refused(self):
        with self.assertRaises(cleanup.CleanupError) as caught:
            self.run_cleanup()
        self.assertIsNotNone(self.journal.record)
        self.assertNotIn(OLD, str(caught.exception))
        self.assertNotIn(NEW, str(caught.exception))
        return caught.exception

    def assert_no_device_writes(self):
        self.devices.change_password.assert_not_called()
        self.devices.ensure_verified.assert_not_called()
        self.devices.verify_recovery.assert_not_called()

    def test_closes_failed_attempt_after_existing_verify_authenticates_all_nine_old_only(self):
        before = deepcopy(self.vault.items)
        with patch.object(self.engine, "verify", wraps=self.engine.verify) as verify:
            result = self.run_cleanup()
            verify.assert_called_once_with(include_archived=True)
        self.assertEqual(result["phase"], "CLEANED")
        self.assertEqual(result["devices_verified_old"], list(FLEET))
        self.assertEqual(self.devices.authenticate.call_count, 18)
        self.assertEqual(self.vault.archived, {PENDING, PREVIOUS})
        self.assertEqual(self.vault.items, before)
        self.assertIsNone(self.journal.record)
        self.assertEqual(self.journal.archives, [self.original])
        first_archive = self.events.index(("journal_archive",))
        self.assertEqual(self.events[:first_archive],
                         [("authenticate", name) for name in FLEET for _ in range(2)])
        self.assert_no_device_writes()

    def test_new_or_unknown_device_blocks_all_cleanup_even_with_old_recorded_state(self):
        for unknown in (False, True):
            with self.subTest(unknown=unknown):
                self.device_passwords["S4"] = NEW if not unknown else OLD
                self.unknown = {"S4"} if unknown else set()
                self.assertEqual(self.assert_refused().stage,
                                 "fresh nine-device original admin verification")
                self.assertFalse(self.vault.archived)
                self.assertFalse(self.journal.archives)
                self.assertEqual(self.journal.record, self.original)
                self.assert_no_device_writes()

    def test_promoted_current_or_foreign_items_refuse_cleanup_before_device_checks(self):
        for reference, key, value in ((CURRENT, "password", NEW),
                                      (PENDING, "netpilot_rotation_id", "b" * 32),
                                      (PREVIOUS, "netpilot_current_reference", "x" * 26)):
            with self.subTest(reference=reference):
                before = deepcopy(self.vault.items)
                next(f for f in self.vault.items[reference]["fields"] if f["id"] == key)["value"] = value
                self.assert_refused()
                self.assertFalse(self.vault.archived)
                self.vault.items = before
        self.devices.authenticate.assert_not_called()

    def test_nonfailed_or_ambiguous_journal_refuses_cleanup_without_connections(self):
        mutations = (lambda r: r.update(phase="ROTATING"),
                     lambda r: r.update(scope=["R1"]),
                     lambda r: r.update(vault_state="promoted"),
                     lambda r: r.update(monitoring_state="verified"),
                     lambda r: r.update(events=[]),
                     lambda r: r["credential_refs"].update(previous=None))
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.journal.record = deepcopy(self.original)
                mutate(self.journal.record)
                self.assert_refused()
                self.assertFalse(self.vault.archived)
        self.devices.authenticate.assert_not_called()

    def test_partial_archive_retry_reverifies_all_nine_using_archived_bound_ids(self):
        self.vault.archive_then_fail = PENDING
        self.assertEqual(self.assert_refused().stage, "bound pending archive")
        self.assertEqual(self.vault.archived, {PENDING})
        self.assertEqual(self.journal.archives, [self.original])
        self.assertTrue(self.run_cleanup()["passed"])
        self.assertEqual(self.vault.archived, {PENDING, PREVIOUS})
        self.assertEqual(self.events.count(("archive", PENDING)), 1)
        self.assertEqual(self.devices.authenticate.call_count, 36)
        self.assert_no_device_writes()

    def test_real_journal_archives_failed_audit_and_clears_only_after_retry_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = JournalStore(Path(directory) / "rotation")
            self.engine.journal = journal
            with journal.lock():
                journal.save(self.original)
                self.vault.archive_then_fail = PENDING
                with self.assertRaises(cleanup.CleanupError):
                    self.run_cleanup()
                self.assertEqual(journal.load(), self.original)
                archived_path = journal.root / "history" / (ROTATION + ".json")
                original_archive = archived_path.read_bytes()
                self.assertEqual(json.loads(original_archive), self.original)
                self.assertTrue(self.run_cleanup()["passed"])
                self.assertIsNone(journal.load())
                self.assertEqual(archived_path.read_bytes(), original_archive)
            self.assertEqual(self.devices.authenticate.call_count, 36)
            self.assertEqual(self.vault.archived, {PENDING, PREVIOUS})
            self.assert_no_device_writes()

    def test_partial_archive_retry_with_unknown_device_retains_remaining_recovery_records(self):
        self.vault.archive_then_fail = PENDING
        self.assert_refused()
        self.unknown.add("R2")
        self.assert_refused()
        self.assertEqual(self.vault.archived, {PENDING})
        self.assertEqual(self.journal.record, self.original)
        self.assert_no_device_writes()

    def test_conflicting_active_pending_blocks_interrupted_cleanup_retry(self):
        self.vault.archived.add(PENDING)
        self.vault.items["x" * 26] = item("x" * 26, "NetPilot-Pending", NEW, True)
        self.assert_refused()
        self.assertEqual(self.vault.archived, {PENDING})
        self.devices.authenticate.assert_not_called()

    def test_current_changed_during_fresh_authentication_blocks_archives(self):
        def authenticate_and_drift(name, address, credential):
            self.authenticate(name, address, credential)
            if name == "S4":
                self.vault.items[CURRENT]["fields"][1]["value"] = NEW
        self.devices.authenticate.side_effect = authenticate_and_drift
        self.assert_refused()
        self.assertFalse(self.vault.archived)
        self.assert_no_device_writes()

    def test_cleanup_requires_existing_lock(self):
        self.journal.locked = False
        self.assert_refused()
        self.assertFalse(self.vault.calls)
        self.devices.authenticate.assert_not_called()


def terminal_fleet_record(phase="COMMITTED"):
    record = completed_record()
    record.update(phase=phase, scope=list(FLEET), monitoring_state="verified",
                  vault_state="promoted" if phase == "COMMITTED" else "unchanged")
    for entry in record["devices"].values():
        entry.update(state="verified_new" if phase == "COMMITTED" else "verified_old",
                     attempted=True, verified_at=STAMP, last_error=None)
    return record


class RetireCompletedPendingTests(unittest.TestCase):
    """Starting another cycle retains Previous and immutable completed history."""

    def setUp(self):
        self.events = []
        self.vault, self.journal = FakeVault(self.events), FakeJournal(self.events)
        self.journal.record = terminal_fleet_record()
        self.vault.items[CURRENT]["fields"][1]["value"] = NEW
        self.devices = Mock()
        self.engine = RotationEngine(OnePasswordStore(), self.devices, self.journal)
        self.enterContext(patch.object(credential_provider, "_run_op", side_effect=self.vault.run))
        self.enterContext(patch.object(credential_provider, "_read_token", side_effect=AssertionError("No token reads")))
        self.enterContext(patch("socket.create_connection", side_effect=AssertionError("No network")))

    def retire(self, current=None, record=None):
        return cleanup.retire_completed_pending(
            self.engine, self.engine.journal.load() if record is None else record,
            self.engine.credentials.read_current() if current is None else current)

    def assert_no_device_actions(self):
        self.devices.authenticate.assert_not_called()
        self.devices.change_password.assert_not_called()
        self.devices.ensure_verified.assert_not_called()

    def test_committed_archives_only_bound_pending_and_preserves_current_previous_and_journal(self):
        before, record = deepcopy(self.vault.items), deepcopy(self.journal.record)
        self.assertTrue(cleanup.completed_fleet(record))
        self.retire()
        self.assertEqual(self.vault.archived, {PENDING})
        self.assertEqual(self.vault.items, before)
        self.assertEqual(self.journal.record, record)
        self.assertEqual(self.journal.archives, [record])
        self.assertLess(self.events.index(("journal_archive",)), self.events.index(("archive", PENDING)))
        self.assertEqual([call[1] for call in self.vault.calls if call[1] not in ("list", "get")], ["delete"])
        self.assert_no_device_actions()

    def test_full_fleet_rollback_retires_pending_only_when_current_matches_previous(self):
        self.journal.record = terminal_fleet_record("ROLLED_BACK")
        self.vault.items[CURRENT]["fields"][1]["value"] = OLD
        before = deepcopy(self.vault.items)
        self.assertTrue(cleanup.completed_fleet(self.journal.record))
        self.retire()
        self.assertEqual(self.vault.archived, {PENDING})
        self.assertEqual(self.vault.items, before)
        self.assertEqual(self.journal.archives, [self.journal.record])
        self.assert_no_device_actions()

    def test_foreign_pending_or_previous_binding_refuses_any_archive(self):
        for reference, key, value in ((PENDING, "netpilot_rotation_id", "b" * 32),
                                      (PREVIOUS, "netpilot_current_reference", "x" * 26)):
            with self.subTest(reference=reference):
                before = deepcopy(self.vault.items)
                next(field for field in self.vault.items[reference]["fields"] if field["id"] == key)["value"] = value
                with self.assertRaises(cleanup.CleanupError):
                    self.retire()
                self.assertFalse(self.vault.archived)
                self.assertFalse(self.journal.archives)
                self.vault.items = before
        self.assert_no_device_actions()

    def test_current_drift_or_wrong_terminal_password_refuses_any_archive(self):
        current = self.engine.credentials.read_current()
        self.vault.items[CURRENT]["fields"][1]["value"] = OLD
        with self.assertRaises(cleanup.CleanupError):
            self.retire(current=current)
        with self.assertRaises(cleanup.CleanupError):
            self.retire()
        self.assertFalse(self.vault.archived)
        self.assertFalse(self.journal.archives)

    def test_ambiguous_terminal_evidence_refuses_any_archive(self):
        mutations = (lambda r: r.update(phase="RECOVERY_REQUIRED"),
                     lambda r: r.update(scope=["R1"]),
                     lambda r: r.update(ended_at=None),
                     lambda r: r.update(vault_state="unknown"),
                     lambda r: r.update(monitoring_state="failed"),
                     lambda r: r["devices"]["S4"].update(state="unknown"),
                     lambda r: r["devices"]["S4"].update(verified_at=None),
                     lambda r: r["devices"]["S4"].update(last_error="verification"))
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.journal.record = terminal_fleet_record()
                mutate(self.journal.record)
                self.assertFalse(cleanup.completed_fleet(self.journal.record))
                with self.assertRaises(cleanup.CleanupError):
                    self.retire()
                self.assertFalse(self.vault.archived)
                self.assertFalse(self.journal.archives)
        self.assert_no_device_actions()

    def test_missing_references_or_changed_journal_refuses_any_archive(self):
        record = deepcopy(self.journal.record)
        self.journal.record["credential_refs"]["pending"] = None
        with self.assertRaises(cleanup.CleanupError):
            self.retire()
        with self.assertRaises(cleanup.CleanupError):
            self.retire(record=record)
        self.assertFalse(self.vault.archived)
        self.assertFalse(self.journal.archives)

    def test_interrupted_archive_retries_owned_archived_pending_without_touching_previous(self):
        self.vault.archive_then_fail = PENDING
        record = deepcopy(self.journal.record)
        with self.assertRaises(cleanup.CleanupError):
            self.retire()
        self.assertEqual(self.vault.archived, {PENDING})
        self.assertEqual(self.journal.record, record)
        self.assertEqual(self.journal.archives, [record])
        self.retire()
        self.assertEqual(self.events.count(("archive", PENDING)), 1)
        self.assertEqual(self.vault.archived, {PENDING})
        self.assertEqual(self.journal.archives, [record])

    def test_foreign_active_pending_blocks_archived_pending_retry(self):
        self.vault.archived.add(PENDING)
        self.vault.items["x" * 26] = item("x" * 26, "NetPilot-Pending", NEW, True)
        with self.assertRaises(cleanup.CleanupError):
            self.retire()
        self.assertFalse(self.journal.archives)
        self.assertEqual(self.vault.archived, {PENDING})

    def test_real_journal_and_immutable_history_unchanged_on_repeat(self):
        record = deepcopy(self.journal.record)
        with tempfile.TemporaryDirectory() as directory:
            journal = JournalStore(Path(directory) / "rotation")
            self.engine.journal = journal
            with journal.lock():
                journal.save(record)
                self.retire()
                archive = journal.root / "history" / (ROTATION + ".json")
                before = archive.read_bytes()
                self.assertEqual(json.loads(before), record)
                self.assertEqual(journal.load(), record)
                self.retire()
                self.assertEqual(archive.read_bytes(), before)
                self.assertEqual(journal.load(), record)
        self.assertEqual(self.events.count(("archive", PENDING)), 1)
        self.assertEqual(self.vault.archived, {PENDING})

    def test_operation_lock_is_required(self):
        self.journal.locked = False
        current = self.engine.credentials.read_current()
        self.vault.calls.clear()
        with self.assertRaises(cleanup.CleanupError):
            self.retire(current=current)
        self.assertFalse(self.vault.calls)
        self.assertFalse(self.vault.archived)


if __name__ == "__main__":
    unittest.main()

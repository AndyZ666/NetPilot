"""Offline scheduling checks; synthetic journals and a fake fleet engine only."""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from security import rotation_scheduler as scheduler
from security.credential_rotation import RotationEngine
from security.rotation_state import FLEET, JournalStore, StateError


BASE = datetime(2026, 1, 31, 12, tzinfo=timezone.utc)
DUE = BASE + timedelta(days=30)


def record(phase="COMMITTED", rotation_id="1" * 32, ended_at=BASE):
    timestamp = ended_at.isoformat()
    state = "verified_old" if phase == "ROLLED_BACK" else "verified_new"
    result = {
        "version": 1, "rotation_id": rotation_id, "phase": phase,
        "started_at": timestamp, "updated_at": timestamp, "ended_at": timestamp,
        "scope": list(FLEET), "username": "admin",
        "devices": {name: {"management_ip": f"192.0.2.{index}", "state": state,
                            "attempted": True, "verified_at": timestamp, "last_error": None}
                    for index, name in enumerate(FLEET, 1)},
        "credential_refs": {"current": "current", "pending": "pending", "previous": "previous"},
        "vault_state": "unchanged" if phase == "ROLLED_BACK" else "promoted",
        "monitoring_state": "verified", "events": [],
    }
    if phase == "PARTIAL_FAILURE":
        result["ended_at"] = None
        result["vault_state"] = "pending_staged"
        result["monitoring_state"] = "not_requested"
        result["devices"]["R1"].update(state="unknown", verified_at=None, last_error="unreachable")
    return result


class FakeEngine:
    def __init__(self, journal):
        self.journal = journal
        self.calls = []
        self.effect = self.succeed
        self.marker_before_attempt = None

    def run_fleet(self, authorized=False):
        self.calls.append(authorized)
        self.marker_before_attempt = scheduler._marker(self.journal)
        self.journal._assert_locked()
        # The real engine reacquires operation(), not an independent lock.
        with self.journal.operation():
            return self.effect()

    def succeed(self):
        previous = self.journal.load()
        if previous:
            self.journal.archive_completed(previous)
        current = record(rotation_id="2" * 32, ended_at=DUE)
        self.journal.save(current)
        return RotationEngine._summary(current)

    def fail(self):
        previous = self.journal.load()
        self.journal.archive_completed(previous)
        current = record("PARTIAL_FAILURE", rotation_id="2" * 32, ended_at=DUE)
        self.journal.save(current)
        return RotationEngine._summary(current)


class SchedulerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.journal = JournalStore(Path(self.temporary.name) / "rotation")
        self.engine = FakeEngine(self.journal)
        self.notify = Mock(return_value={"status": "sent", "error": None})

    def save(self, value):
        with self.journal.operation():
            self.journal.save(value)

    def block(self):
        with self.journal.operation():
            scheduler._block(self.journal, DUE.isoformat(), "1" * 32)

    def attempt(self):
        return scheduler.run(self.engine, authorized=True, now=DUE, notify=self.notify)

    def test_status_and_missing_baseline_tick_create_no_storage(self):
        result = scheduler.status(self.journal, DUE)
        self.assertFalse(result["armed"])
        self.assertFalse(result["due"])
        self.assertEqual(result["blocked_reason"], "no_successful_baseline")
        self.assertFalse(self.journal.root.exists())
        self.assertEqual(self.attempt()["action"], "skipped")
        self.assertFalse(self.journal.root.exists())
        self.assertFalse(self.engine.calls)
        self.notify.assert_not_called()

    def test_due_means_thirty_full_days_not_a_calendar_month(self):
        self.save(record())
        self.assertFalse(scheduler.status(self.journal, DUE - timedelta(microseconds=1))["due"])
        status = scheduler.status(self.journal, DUE)
        self.assertTrue(status["due"])
        self.assertEqual(status["next_due_at"], "2026-03-02T12:00:00+00:00")
        self.assertTrue(status["armed"])

    def test_future_success_blocks_clock_regression(self):
        self.save(record())
        result = scheduler.status(self.journal, BASE - timedelta(seconds=1))
        self.assertEqual(result["blocked_reason"], "clock_before_last_success")
        self.assertFalse(result["armed"])

    def test_not_due_never_acquires_lock_or_reads_credentials(self):
        self.save(record())
        before = self.journal.path.read_bytes()
        with patch.object(self.journal, "operation", side_effect=AssertionError("unexpected mutation")):
            result = scheduler.run(self.engine, authorized=True, now=BASE, notify=self.notify)
        self.assertEqual(result["action"], "skipped")
        self.assertEqual(self.journal.path.read_bytes(), before)
        self.assertFalse(self.engine.calls)
        self.notify.assert_not_called()

    def test_status_uses_latest_success_from_audit_after_cleanup(self):
        self.save(record())
        with self.journal.operation():
            self.journal.finish_completed(self.journal.load())
        self.assertIsNone(self.journal.load())
        status = scheduler.status(self.journal, DUE)
        self.assertTrue(status["armed"])
        self.assertEqual(status["last_success_rotation_id"], "1" * 32)
        self.assertEqual(status["next_due_at"], DUE.isoformat())

    def test_incomplete_commit_is_not_a_success_baseline(self):
        for field, value in (("scope", ["R1"]), ("monitoring_state", "failed"),
                             ("vault_state", "unknown"), ("ended_at", None)):
            with self.subTest(field=field):
                candidate = record()
                candidate[field] = value
                self.save(candidate)
                self.assertEqual(scheduler.status(self.journal, DUE)["blocked_reason"],
                                 "no_successful_baseline")

    def test_success_has_durable_private_marker_then_clears_it(self):
        self.save(record())
        result = self.attempt()
        self.assertEqual(self.engine.calls, [True])
        self.assertEqual(self.engine.marker_before_attempt["previous_rotation_id"], "1" * 32)
        self.assertEqual(result["phase"], "COMMITTED")
        self.assertEqual(result["result"], "PASS")
        self.assertFalse(result["manual_recovery_required"])
        self.assertTrue(result["scheduler_armed"])
        self.assertIsNone(scheduler._marker(self.journal))
        self.assertEqual(len(self.journal.history()), 1)
        self.notify.assert_called_once()

    def test_partial_failure_stays_latched_and_sends_only_one_notification(self):
        self.save(record())
        self.engine.effect = self.engine.fail
        result = self.attempt()
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(result["phase"], "PARTIAL_FAILURE")
        self.assertFalse(result["scheduler_armed"])
        mode = (self.journal.root / scheduler.MARKER).stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)
        self.assertEqual(self.attempt()["action"], "skipped")
        self.assertEqual(len(self.engine.calls), 1)
        self.notify.assert_called_once()

    def test_prejournal_failure_never_reports_the_previous_commit_as_success(self):
        self.save(record())
        self.engine.effect = Mock(side_effect=RuntimeError("SECRET must not escape"))
        result = self.attempt()
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(result["phase"], "ERROR")
        self.assertEqual(result["stage"], "precheck")
        self.assertIsNone(result["rotation_id"])
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertEqual(self.journal.load()["phase"], "COMMITTED")
        self.assertEqual(self.attempt()["blocked_reason"], "operator_rearm_required")
        self.notify.assert_called_once()

    def test_prejournal_failure_does_not_reuse_prior_rollback_failure(self):
        self.save(record())
        with self.journal.operation():
            self.journal.archive_completed(self.journal.load())
            rolled_back = record("ROLLED_BACK", rotation_id="2" * 32, ended_at=DUE)
            rolled_back["events"] = [{"at": DUE.isoformat(), "phase": "PARTIAL_FAILURE",
                                       "operation": "rotate", "device": "R3",
                                       "result": "FAIL", "error": "authentication"}]
            self.journal.save(rolled_back)
        self.engine.effect = Mock(side_effect=RuntimeError("new precheck failure"))
        result = self.attempt()
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(result["phase"], "ERROR")
        self.assertEqual(result["stage"], "precheck")
        self.assertEqual(result["error"], "ambiguous")
        self.assertIsNone(result["rotation_id"])
        self.assertNotIn("audit_events", result)
        self.assertEqual(self.journal.load(), rolled_back)
        self.notify.assert_called_once()

    def test_unreadable_journal_after_failure_still_sends_sanitized_notice(self):
        self.save(record())

        def corrupt_then_fail():
            self.journal.path.write_text("unreadable journal")
            raise RuntimeError("SECRET")

        self.engine.effect = corrupt_then_fail
        result = self.attempt()
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(result["phase"], "ERROR")
        self.assertIsNone(result["rotation_id"])
        self.assertFalse(result["scheduler_armed"])
        self.assertNotIn("SECRET", json.dumps(result))
        self.notify.assert_called_once()

    def test_interrupt_leaves_marker_and_sanitized_failure_notification(self):
        self.save(record())
        self.engine.effect = Mock(side_effect=KeyboardInterrupt)
        result = self.attempt()
        self.assertEqual(result["error"], "interrupted")
        self.assertFalse(result["scheduler_armed"])
        self.assertIsNotNone(scheduler._marker(self.journal))
        self.notify.assert_called_once()

    def test_abrupt_exit_keeps_crash_latch_for_next_process(self):
        self.save(record())
        self.engine.effect = Mock(side_effect=SystemExit(99))
        with self.assertRaises(SystemExit):
            self.attempt()
        fresh_store = JournalStore(self.journal.root)
        self.assertEqual(scheduler.status(fresh_store, DUE)["blocked_reason"], "operator_rearm_required")
        self.assertEqual(self.attempt()["action"], "skipped")
        self.assertEqual(len(self.engine.calls), 1)

    def test_mail_delivery_failure_does_not_change_success_or_schedule_retry(self):
        self.save(record())
        self.notify.side_effect = RuntimeError("private SMTP response")
        result = self.attempt()
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["phase"], "COMMITTED")
        self.assertEqual(result["notification"]["status"], "failed")
        self.assertNotIn("private SMTP response", json.dumps(result))
        self.assertTrue(result["scheduler_armed"])
        self.assertEqual(self.attempt()["action"], "skipped")
        self.assertEqual(len(self.engine.calls), 1)

    def test_marker_clear_failure_reports_committed_success_separately(self):
        self.save(record())
        with patch.object(scheduler, "_unblock", side_effect=OSError("private path")):
            result = self.attempt()
        self.assertEqual(result["phase"], "COMMITTED")
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["scheduler_error"], "marker_clear_failed")
        self.assertFalse(result["scheduler_armed"])
        self.assertFalse(result["manual_recovery_required"])
        self.assertEqual(self.notify.call_args.args[0]["result"], "PASS")
        self.assertEqual(scheduler.status(self.journal, DUE)["blocked_reason"], "operator_rearm_required")

    def test_rearm_needs_execute_and_refuses_unresolved_state(self):
        self.save(record())
        self.engine.effect = self.engine.fail
        self.attempt()
        with self.assertRaises(StateError):
            scheduler.rearm(self.journal, now=DUE)
        result = scheduler.rearm(self.journal, authorized=True, now=DUE)
        self.assertEqual(result["result"], "FAIL")
        self.assertFalse(result["rearmed"])
        self.assertIsNotNone(scheduler._marker(self.journal))

    def test_verified_operator_cleanup_then_explicit_rearm(self):
        self.save(record())
        self.engine.effect = self.engine.fail
        self.attempt()
        # Simulates the existing cleanup command after its fresh verification.
        with self.journal.operation():
            self.journal.finish_failed(self.journal.load())
        self.assertFalse(scheduler.status(self.journal, DUE)["armed"])
        result = scheduler.rearm(self.journal, authorized=True, now=DUE)
        self.assertTrue(result["rearmed"])
        self.assertTrue(result["armed"])
        self.assertTrue(result["due"])
        self.assertEqual(len(self.journal.history()), 2)

    def test_verified_full_fleet_rollback_allows_rearm_with_historical_baseline(self):
        self.save(record())
        with self.journal.operation():
            self.journal.archive_completed(self.journal.load())
            self.journal.save(record("ROLLED_BACK", rotation_id="2" * 32, ended_at=DUE))
        self.block()
        result = scheduler.rearm(self.journal, authorized=True, now=DUE)
        self.assertTrue(result["rearmed"])
        self.assertEqual(result["last_success_at"], BASE.isoformat())
        self.assertTrue(result["due"])

    def test_unverified_rollback_and_single_router_test_do_not_allow_rearm(self):
        self.save(record())
        with self.journal.operation():
            self.journal.archive_completed(self.journal.load())
        for change in ({"monitoring_state": "not_requested"}, {"scope": ["R1"]}):
            candidate = record("ROLLED_BACK", rotation_id="2" * 32, ended_at=DUE)
            candidate.update(change)
            self.save(candidate)
            result = scheduler.rearm(self.journal, authorized=True, now=DUE)
            self.assertEqual(result["result"], "FAIL")
            self.assertEqual(result["blocked_reason"], "unresolved_transaction")

    def test_preflight_failure_requires_explicit_rearm_even_if_current_commit_healthy(self):
        self.save(record())
        self.engine.effect = Mock(side_effect=RuntimeError)
        self.attempt()
        self.assertEqual(self.attempt()["action"], "skipped")
        result = scheduler.rearm(self.journal, authorized=True, now=DUE)
        self.assertTrue(result["armed"])
        self.assertIsNone(scheduler._marker(self.journal))

    def test_operation_lock_excludes_manual_writer(self):
        self.save(record())
        other = JournalStore(self.journal.root)
        with other.operation():
            with self.assertRaises(StateError):
                self.attempt()
        self.assertFalse(self.engine.calls)
        self.assertIsNone(scheduler._marker(self.journal))
        self.notify.assert_not_called()

    def test_due_guard_is_rechecked_after_lock_acquisition(self):
        self.save(record())
        actual = scheduler.status
        count = 0

        def changed_status(journal, now):
            nonlocal count
            count += 1
            result = actual(journal, now)
            if count == 2:
                result["due"] = False
            return result

        with patch.object(scheduler, "status", side_effect=changed_status):
            self.assertEqual(self.attempt()["action"], "skipped")
        self.assertEqual(count, 2)
        self.assertFalse(self.engine.calls)
        self.assertIsNone(scheduler._marker(self.journal))

    def test_run_requires_explicit_execute_before_any_work(self):
        with self.assertRaises(StateError):
            scheduler.run(self.engine, now=DUE, notify=self.notify)
        self.assertFalse(self.journal.root.exists())
        self.assertFalse(self.engine.calls)
        self.notify.assert_not_called()

    def test_unsafe_or_malformed_marker_never_allows_retry(self):
        self.save(record())
        marker = self.journal.root / scheduler.MARKER
        marker.write_text('{"unexpected": "SECRET"}')
        marker.chmod(0o600)
        with self.assertRaises(StateError):
            self.attempt()
        self.assertFalse(self.engine.calls)
        self.notify.assert_not_called()

    def test_default_delivery_uses_shared_helper_once_after_success(self):
        self.save(record())
        with patch("security.rotation_email.send_notification", self.notify), \
                patch.object(scheduler, "_notification", wraps=scheduler._notification) as delivery:
            result = scheduler.run(self.engine, authorized=True, now=DUE)
            self.assertEqual(scheduler.run(self.engine, authorized=True, now=DUE)["action"], "skipped")
        delivery.assert_called_once()
        self.notify.assert_called_once()
        from security.rotation_email import notification_content
        subject, body = notification_content(self.notify.call_args.args[0])
        self.assertEqual(subject, "NetPilot Password Rotation Successful")
        for value in ("9/9", "1Password synchronization: promoted", "Monitoring verification: verified"):
            self.assertIn(value, body)
        self.assertEqual(result["result"], "PASS")

    def test_default_delivery_uses_shared_helper_once_after_failure(self):
        self.save(record())
        self.engine.effect = self.engine.fail
        with patch("security.rotation_email.send_notification", self.notify), \
                patch.object(scheduler, "_notification", wraps=scheduler._notification) as delivery:
            result = scheduler.run(self.engine, authorized=True, now=DUE)
            self.assertEqual(scheduler.run(self.engine, authorized=True, now=DUE)["action"], "skipped")
        delivery.assert_called_once()
        self.notify.assert_called_once()
        self.assertEqual(result["result"], "FAIL")
        self.assertTrue(result["manual_recovery_required"])

    def test_default_delivery_interrupt_keeps_committed_result(self):
        self.save(record())
        with patch("security.rotation_email.send_notification", side_effect=KeyboardInterrupt) as delivery:
            result = scheduler.run(self.engine, authorized=True, now=DUE)
        delivery.assert_called_once()
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["phase"], "COMMITTED")
        self.assertEqual(result["notification"], {"status": "failed", "error": "notification_failed"})
        self.assertTrue(result["scheduler_armed"])

    def test_status_cli_does_not_construct_live_adapters(self):
        with patch.object(scheduler, "STATE_DIR", self.journal.root), \
                patch("security.rotation_adapters.OnePasswordStore", side_effect=AssertionError("no Vault")), \
                patch("sys.stdout", new_callable=io.StringIO) as output:
            code = scheduler.main(["status"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["blocked_reason"], "no_successful_baseline")
        self.assertFalse(self.journal.root.exists())

    def test_latest_success_uses_timestamp_not_archive_filename_or_active_position(self):
        self.save(record(rotation_id="f" * 32, ended_at=BASE - timedelta(days=5)))
        with self.journal.operation():
            self.journal.finish_completed(self.journal.load())
        self.save(record(rotation_id="2" * 32, ended_at=BASE + timedelta(days=1)))
        with self.journal.operation():
            self.journal.finish_completed(self.journal.load())
        self.save(record(rotation_id="3" * 32, ended_at=BASE))

        report = scheduler.status(self.journal, DUE)
        self.assertEqual(report["last_success_rotation_id"], "2" * 32)
        self.assertEqual(report["next_due_at"], "2026-03-03T12:00:00+00:00")
        self.assertFalse(report["due"])
        self.assertTrue(report["armed"])
        self.assertEqual(self.attempt()["action"], "skipped")
        self.assertEqual(self.engine.calls, [])
        self.notify.assert_not_called()

    def test_non_utc_or_naive_scheduler_clock_is_rejected_before_state_access(self):
        for now in (datetime(2026, 3, 2, 12),
                    datetime(2026, 3, 2, 12, tzinfo=timezone(timedelta(hours=1)))):
            with self.subTest(now=now), patch.object(self.journal, "load") as load:
                with self.assertRaisesRegex(StateError, "UTC clock"):
                    scheduler.run(self.engine, authorized=True, now=now, notify=self.notify)
                load.assert_not_called()
        self.assertFalse(self.journal.root.exists())
        self.assertEqual(self.engine.calls, [])
        self.notify.assert_not_called()

    def test_corrupt_active_or_historical_state_prevents_attempt_and_notification(self):
        for location in ("active", "history"):
            with self.subTest(location=location), tempfile.TemporaryDirectory() as directory:
                journal = JournalStore(Path(directory) / "rotation")
                with journal.operation():
                    journal.save(record())
                    if location == "history":
                        journal.finish_completed(journal.load())
                path = journal.path if location == "active" else journal.root / "history" / ("1" * 32 + ".json")
                path.write_text("fixture-private-invalid-state")
                engine = FakeEngine(journal)
                with self.assertRaises(StateError) as error:
                    scheduler.run(engine, authorized=True, now=DUE, notify=self.notify)
                self.assertNotIn("fixture-private", str(error.exception))
                self.assertEqual(engine.calls, [])
                self.assertFalse((journal.root / scheduler.MARKER).exists())
        self.notify.assert_not_called()

    def test_marker_fsync_failure_prevents_rotation_and_leaves_retry_blocked(self):
        self.save(record())
        original = self.journal.path.read_bytes()
        for failure_at in (1, 2):  # Marker contents, then its directory entry.
            with self.subTest(failure_at=failure_at):
                with self.journal.operation():
                    outcomes = [None] * (failure_at - 1) + [OSError("fixture-private-storage-error")]
                    with patch.object(scheduler.os, "fsync", side_effect=outcomes) as fsync:
                        with self.assertRaises(OSError):
                            self.attempt()
                    self.assertEqual(fsync.call_count, failure_at)
                self.assertEqual(self.engine.calls, [])
                self.notify.assert_not_called()
                self.assertEqual(self.journal.path.read_bytes(), original)
                self.assertEqual(self.attempt()["blocked_reason"], "operator_rearm_required")
                (self.journal.root / scheduler.MARKER).unlink()

    def test_concurrent_new_commit_is_rechecked_using_actual_state_after_lock(self):
        self.save(record())
        operation = self.journal.operation

        @contextmanager
        def commit_before_acquisition():
            # A manual writer finishes between the first due check and our lock.
            with operation():
                self.journal.save(record(rotation_id="3" * 32, ended_at=DUE))
                yield self.journal

        with patch.object(self.journal, "operation", side_effect=commit_before_acquisition):
            report = self.attempt()
        self.assertEqual(self.engine.calls, [])
        self.notify.assert_not_called()
        self.assertEqual(report["action"], "skipped")
        self.assertEqual(report["last_success_rotation_id"], "3" * 32)
        self.assertFalse(report["due"])
        self.assertIsNone(scheduler._marker(self.journal))

    def test_claimed_commit_without_new_durable_journal_is_failure(self):
        self.save(record())
        self.engine.effect = Mock(return_value=RotationEngine._summary(record(rotation_id="2" * 32)))
        report = self.attempt()
        self.assertEqual(report["result"], "FAIL")
        self.assertEqual(report["phase"], "ERROR")
        self.assertIsNone(report["rotation_id"])
        self.assertTrue(report["manual_recovery_required"])
        self.assertFalse(report["scheduler_armed"])
        self.assertEqual(self.journal.load()["rotation_id"], "1" * 32)
        self.assertEqual(self.attempt()["action"], "skipped")
        self.assertEqual(self.engine.calls, [True])
        self.notify.assert_called_once()

    def test_interrupt_after_durable_commit_preserves_success_and_prevents_duplicate_notice(self):
        self.save(record())

        def commit_then_interrupt():
            self.engine.succeed()
            raise KeyboardInterrupt("fixture-private-interruption")

        self.engine.effect = commit_then_interrupt
        report = self.attempt()
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(report["rotation_id"], "2" * 32)
        self.assertFalse(report["manual_recovery_required"])
        self.assertTrue(report["scheduler_armed"])
        self.assertNotIn("fixture-private", json.dumps(report))
        self.assertEqual(self.attempt()["action"], "skipped")
        self.assertEqual(self.engine.calls, [True])
        self.notify.assert_called_once()

    def cli_run(self):
        # The scheduler is real; the fleet engine is the external operation here.
        with patch.object(scheduler, "STATE_DIR", self.journal.root), \
                patch.object(scheduler, "datetime", wraps=datetime) as clock, \
                patch.object(scheduler.RotationEngine, "__new__", return_value=self.engine), \
                patch("security.rotation_adapters.OnePasswordStore"), \
                patch("security.rotation_adapters.NetmikoDeviceAdapter"), \
                patch("security.rotation_monitoring.ManagedTelegrafMonitoring"), \
                patch("security.rotation_email.send_notification", self.notify), \
                patch.object(scheduler.signal, "signal", return_value="previous-handler") as signal, \
                patch("sys.stdout", new_callable=io.StringIO) as output:
            clock.now.return_value = DUE
            code = scheduler.main(["run", "--execute"])
        self.assertEqual(signal.call_args_list, [
            unittest.mock.call(scheduler.signal.SIGTERM, scheduler._interrupted),
            unittest.mock.call(scheduler.signal.SIGTERM, "previous-handler"),
        ])
        return code, json.loads(output.getvalue())

    def test_run_cli_returns_success_when_notification_fails_after_commit(self):
        self.save(record())
        self.notify.side_effect = RuntimeError("fixture-private-smtp-error")
        code, report = self.cli_run()
        self.assertEqual(code, 0)
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(report["phase"], "COMMITTED")
        self.assertEqual(report["notification"], {"status": "failed", "error": "notification_failed"})
        self.assertNotIn("fixture-private", json.dumps(report))
        self.assertEqual(self.engine.calls, [True])
        self.notify.assert_called_once()

    def test_run_cli_returns_failure_after_interruption_and_restores_signal_handler(self):
        self.save(record())
        self.engine.effect = Mock(side_effect=KeyboardInterrupt("fixture-private-interruption"))
        code, report = self.cli_run()
        self.assertEqual(code, 1)
        self.assertEqual(report["result"], "FAIL")
        self.assertEqual(report["error"], "interrupted")
        self.assertTrue(report["manual_recovery_required"])
        self.assertFalse(report["scheduler_armed"])
        self.assertNotIn("fixture-private", json.dumps(report))
        self.notify.assert_called_once()

    def test_status_cli_returns_sanitized_failure_for_corrupt_journal_without_live_adapters(self):
        self.save(record())
        self.journal.path.write_text("fixture-private-corrupt-json")
        with patch.object(scheduler, "STATE_DIR", self.journal.root), \
                patch("security.rotation_adapters.OnePasswordStore") as vault, \
                patch("security.rotation_adapters.NetmikoDeviceAdapter") as device, \
                patch("security.rotation_monitoring.ManagedTelegrafMonitoring") as monitoring, \
                patch("sys.stdout", new_callable=io.StringIO) as output:
            code = scheduler.main(["status"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue()), {
            "result": "FAIL", "error": "journal", "stage": "scheduler", "manual_recovery_required": True,
        })
        vault.assert_not_called()
        device.assert_not_called()
        monitoring.assert_not_called()
        self.assertFalse((self.journal.root / scheduler.MARKER).exists())


if __name__ == "__main__":
    unittest.main()

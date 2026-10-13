"""Daily, non-interactive guard for rotation after 30 full days.

The journal's existing operation lock covers the due check and the entire fleet
run. A durable local marker is installed before an attempt: interruption or
failure requires explicit operator rearming, rather than an automatic retry.
"""

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
import signal

from security.credential_rotation import RotationEngine, STATE_DIR, _notification
from security.rotation_cleanup import completed_fleet
from security.rotation_state import JournalStore, StateError, _private


INTERVAL = timedelta(days=30)
MARKER = "scheduler-blocked.json"


def _time(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.utcoffset() != timedelta(0):
        raise StateError("Rotation scheduling requires UTC timestamps.")
    return parsed


def committed(record):
    """Only the complete nine-device success is a scheduling baseline."""
    return bool(record and record.get("phase") == "COMMITTED" and completed_fleet(record))


def _marker(journal):
    directory = descriptor = None
    try:
        directory = journal._open_directory(create=False)
        descriptor = os.open(MARKER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory)
        _private(os.fstat(descriptor), 0o600)
        content = os.read(descriptor, 2049)
        if len(content) > 2048:
            raise ValueError
        value = json.loads(content)
        if (type(value) is not dict
                or set(value) != {"version", "attempted_at", "previous_rotation_id"}
                or type(value["version"]) is not int or value["version"] != 1
                or type(value["previous_rotation_id"]) is not str
                or len(value["previous_rotation_id"]) != 32
                or any(character not in "0123456789abcdef" for character in value["previous_rotation_id"])):
            raise ValueError
        _time(value["attempted_at"])
        return value
    except FileNotFoundError:
        return None
    except Exception:
        raise StateError("The scheduler marker is unsafe or unreadable; inspect it before rearming.") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory is not None:
            os.close(directory)


def _block(journal, timestamp, previous_id):
    journal._assert_locked()
    content = json.dumps({"version": 1, "attempted_at": timestamp,
                          "previous_rotation_id": previous_id}).encode() + b"\n"
    descriptor = os.open(MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=journal._directory_fd)
    with os.fdopen(descriptor, "wb") as destination:
        os.fchmod(destination.fileno(), 0o600)
        destination.write(content)
        destination.flush()
        os.fsync(destination.fileno())
    os.fsync(journal._directory_fd)


def _unblock(journal):
    journal._assert_locked()
    if _marker(journal) is not None:
        os.unlink(MARKER, dir_fd=journal._directory_fd)
        os.fsync(journal._directory_fd)


def status(journal, now=None):
    """Offline status: no credentials, network calls or file creation."""
    now = now or datetime.now(timezone.utc)
    if now.utcoffset() != timedelta(0):
        raise StateError("Rotation scheduling requires a UTC clock.")
    active = journal.load()
    history = journal.history()
    successes = [record for record in history + ([active] if active else []) if committed(record)]
    latest = max(successes, key=lambda record: _time(record["ended_at"])) if successes else None
    blocked = _marker(journal)
    safe = active is None or completed_fleet(active)
    due_at = _time(latest["ended_at"]) + INTERVAL if latest else None
    reason = ("no_successful_baseline" if latest is None else
              "clock_before_last_success" if _time(latest["ended_at"]) > now else
              "unresolved_transaction" if not safe else
              "operator_rearm_required" if blocked else None)
    return {"result": "PASS", "mode": "offline_status", "interval_days": 30,
            "checked_at": now.isoformat(), "last_success_at": latest["ended_at"] if latest else None,
            "last_success_rotation_id": latest["rotation_id"] if latest else None,
            "next_due_at": due_at.isoformat() if due_at else None,
            "due": bool(due_at and now >= due_at), "armed": reason is None,
            "blocked_reason": reason, "active_phase": active["phase"] if active else "IDLE",
            "scheduled_attempt_at": blocked["attempted_at"] if blocked else None}


def rearm(journal, authorized=False, now=None):
    if authorized is not True:
        raise StateError("Rearming requires --execute.")
    with journal.operation():
        report = status(journal, now)
        if report["blocked_reason"] not in (None, "operator_rearm_required"):
            return dict(report, result="FAIL", rearmed=False)
        _unblock(journal)
        return dict(status(journal, now), rearmed=True)


def _failure_report(journal, starting_id, error):
    category = RotationEngine._category(error)
    try:
        active = journal.load()
    except Exception:
        active = None
    if active and active["rotation_id"] != starting_id:
        report = RotationEngine._summary(active)
    else:
        report = {"rotation_id": None, "phase": "ERROR", "stage": "precheck"}
    # A prior successful transaction must never masquerade as this attempt.
    report.update(result="FAIL", error=category, manual_recovery_required=True)
    return report


def run(engine, authorized=False, now=None, notify=None):
    """Run the existing fleet workflow only when the 30-day guard is satisfied."""
    if authorized is not True:
        raise StateError("Scheduled execution requires --execute.")
    # Not-due and blocked timer ticks must not create even a lock directory.
    due = status(engine.journal, now)
    if not due["armed"] or not due["due"]:
        return dict(due, action="skipped")
    with engine.journal.operation():
        due = status(engine.journal, now)  # Recheck after excluding manual writers.
        if not due["armed"] or not due["due"]:
            return dict(due, action="skipped")
        previous_id = due["last_success_rotation_id"]
        starting = engine.journal.load()
        starting_id = starting["rotation_id"] if starting else None
        _block(engine.journal, due["checked_at"], previous_id)
        success = False
        try:
            report = engine.run_fleet(authorized=True)
            active = engine.journal.load()
            success = committed(active) and active["rotation_id"] != previous_id
            if success:
                # The durable journal is authoritative, even if a final display
                # or return-value operation did not finish.
                report = RotationEngine._summary(active)
            elif report.get("phase") == "COMMITTED":
                raise StateError("Scheduled rotation completion was not recorded.")
            report = dict(report, result="PASS" if success else "FAIL",
                          manual_recovery_required=not success)
        except (Exception, KeyboardInterrupt) as error:
            report = _failure_report(engine.journal, starting_id, error)
            try:
                active = engine.journal.load()
            except Exception:
                active = None
            success = committed(active) and active["rotation_id"] != previous_id
            if success:
                report = dict(RotationEngine._summary(active), result="PASS",
                              manual_recovery_required=False)
        if success:
            try:
                _unblock(engine.journal)
            except (Exception, KeyboardInterrupt):
                # Failure to clear local scheduling state cannot undo COMMITTED.
                report["scheduler_error"] = "marker_clear_failed"
        # Mail never changes the outcome or rearms a failed rotation. In
        # particular, delivery failure after COMMITTED cannot cause a retry.
        report["notification"] = _notification(report, notify=notify)
        try:
            report["scheduler_armed"] = _marker(engine.journal) is None and "scheduler_error" not in report
        except Exception:
            report["scheduler_armed"] = False
            report["scheduler_error"] = "marker_unavailable"
        return report


def _interrupted(signum, frame):
    raise KeyboardInterrupt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("status", "run", "rearm"))
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    previous_handler = None
    try:
        journal = JournalStore(STATE_DIR)
        if args.action == "status":
            report = status(journal)
        elif args.action == "rearm":
            report = rearm(journal, authorized=args.execute)
        else:
            from security.rotation_adapters import NetmikoDeviceAdapter, OnePasswordStore
            from security.rotation_monitoring import ManagedTelegrafMonitoring
            from security.setup_recovery_accounts import quiet_transport
            engine = RotationEngine(OnePasswordStore(), NetmikoDeviceAdapter(), journal,
                                    monitoring=ManagedTelegrafMonitoring())
            previous_handler = signal.signal(signal.SIGTERM, _interrupted)
            with quiet_transport():
                report = run(engine, authorized=args.execute)
        print(json.dumps(report, indent=2))
        return int(report.get("result") == "FAIL")
    except (Exception, KeyboardInterrupt) as error:
        print(json.dumps({"result": "FAIL", "error": RotationEngine._category(error),
                          "stage": "scheduler", "manual_recovery_required": True}))
        return 1
    finally:
        if previous_handler is not None:
            signal.signal(signal.SIGTERM, previous_handler)


if __name__ == "__main__":
    raise SystemExit(main())

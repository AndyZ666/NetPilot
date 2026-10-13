"""R1 admin rotation/rollback rehearsal; --execute is the only authorization gate.

Uses the existing Pending/Previous adapter and shared rotation journal. Never
promotes Current, saves startup configuration, or enables fleet device writes.
"""

import argparse
from pathlib import Path
import re
import secrets
import sys
import uuid

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from security import credential_rotation as rotation
from security import setup_recovery_accounts as recovery
from security import test_r1_password_change as probe
from security.rotation_adapters import OnePasswordStore
from security.rotation_state import JournalStore, transition


def _admin_command(config):
    """Keep all account attributes and ancillary records; replace only its hash."""
    matches = [line for line in config if re.fullmatch(
        r"username admin\s+.*\bsecret sha512 " + recovery._HASH, line)]
    if len(matches) != 1:
        raise rotation.RotationError("credentials")
    command = matches[0]
    attributes = command.rsplit(" secret sha512 ", 1)[0]
    if (not re.search(r"\bprivilege 15(?:\s|$)", attributes)
            or not re.search(r"\brole network-admin(?:\s|$)", attributes)):
        raise rotation.RotationError("privilege")
    return command


def _verify(password, expected):
    connection = None
    try:
        connection = probe._connect("admin", password)
        if recovery.read_configs(connection, "R1") != expected:
            raise rotation.RotationError("verification")
    finally:
        recovery._disconnect(connection)


def _current_unchanged(store, current):
    live = store.read_current()
    if live.reference != current.reference or not rotation.same_pair(live, current):
        raise rotation.RotationError("vault_conflict")


def _record_failure(engine, record, error, device=None):
    if record is not None:
        try:
            engine._fail(record, error, device=device)
        except (Exception, KeyboardInterrupt):
            print("FAIL | journal update | retained intent must be reconciled before retrying")


def _restore(connection, current, pending, original, old_command, new_command):
    # Prefer the held admin session. Reconnect with known Vault credentials if it
    # died or a previous restore timed out; never guess a recovery password.
    for password in (None, current.password, pending.password):
        if password is None and connection is None:
            continue
        candidate = connection if password is None else None
        try:
            if candidate is None:
                candidate = probe._connect("admin", password)
            running, _ = recovery.read_configs(candidate, "R1")
            live_command = _admin_command(running)
            if live_command == new_command:
                probe._send(candidate, old_command)
            elif live_command != old_command:
                raise rotation.RotationError("conflict")
            _verify(current.password, original)
            return
        except Exception:
            continue
        finally:
            if candidate is not connection:
                recovery._disconnect(candidate)
    raise rotation.RotationError("verification")


def _rollback(engine, record, connection, current, pending, original, old_command, new_command):
    journal_ok = True
    try:
        entry = record["devices"]["R1"]
        entry.update(state="unknown", verified_at=None)
        engine._phase(record, "ROLLING_BACK")
        engine._event(record, "rollback", "R1")
    except (Exception, KeyboardInterrupt):
        # A journal outage must not prevent restoring R1 with credentials in RAM.
        journal_ok = False
        print("FAIL | rollback journal intent | attempting device restoration")
    try:
        _restore(connection, current, pending, original, old_command, new_command)
        print("PASS | original admin password, permissions and configurations restored via fresh SSH")
        entry = record["devices"]["R1"]
        entry.update(state="verified_old", verified_at=rotation.stamp(), last_error=None)
        _current_unchanged(engine.credentials, current)
        record["vault_state"] = "pending_staged"
        engine._event(record, "rollback", "R1", "PASS")
        engine._phase(record, "ROLLED_BACK")
        print("PASS | NetPilot-Current credentials unchanged; Pending and Previous retained")
        return journal_ok
    except (Exception, KeyboardInterrupt) as error:
        # Keep verified_old only when the fresh original-password/config check passed.
        device = None if record["devices"]["R1"]["state"] == "verified_old" else "R1"
        _record_failure(engine, record, error, device)
        print("FAIL | rollback completion | recovery required; consult retained journal and Vault credentials")
        return False


def _execute(engine):
    connection = record = None
    attempted = False
    result = 0
    stage = "existing rotation state"
    try:
        prior = engine.journal.load()
        if prior and prior["phase"] not in rotation.TERMINAL:
            raise rotation.RotationError("conflict")
        inventory = rotation.discover_inventory()
        if inventory["R1"] != probe.HOST or probe.HOST != "172.20.20.13":
            raise rotation.RotationError("inventory")
        store = engine.credentials
        stage = "Current credentials and Pending absence"
        if store.live_writes_supported is not True or store.find_pending() is not None:
            raise rotation.RotationError("vault_conflict")
        current = store.read_current()  # Also checks the existing Credential Provider read.
        if current.username != "admin":
            raise rotation.RotationError("credentials")
        stage = "R1 original admin access and configuration"
        connection = probe._connect("admin", current.password)
        original = recovery.read_configs(connection, "R1")
        old_command = _admin_command(original[0])
        print("PASS | R1 original admin SSH, privilege 15 and network-admin configuration")
        if prior:
            engine.journal.archive_completed(prior)
        now = rotation.stamp()
        record = {
            "version": 1, "rotation_id": uuid.uuid4().hex, "started_at": now,
            "updated_at": now, "ended_at": None, "phase": transition("IDLE", "PRECHECK"),
            "scope": ["R1"], "username": "admin",
            "devices": {name: {"management_ip": address, "state": "pending",
                               "attempted": False, "verified_at": None, "last_error": None}
                        for name, address in inventory.items()},
            "credential_refs": {"current": current.reference, "pending": None, "previous": None},
            "vault_state": "unchanged", "monitoring_state": "not_requested", "events": [],
        }
        record["devices"]["R1"].update(state="verified_old", verified_at=now)
        engine._event(record, "precheck", "R1", "PASS")
        stage = "original credential archive"
        engine._event(record, "archive_current")
        previous = store.archive_current(record["rotation_id"], current)
        record["credential_refs"]["previous"] = previous.reference
        stage = "Pending credential staging and readback"
        password = rotation.generate_password(current.password)
        record["vault_state"] = "staging"
        engine._event(record, "stage_pending")
        pending = store.stage_pending(record["rotation_id"], "admin", password,
                                      current_reference=current.reference)
        record["credential_refs"]["pending"] = pending.reference
        # Reuse independent adapter reads plus existing rotation ownership checks.
        old, pending, live = engine._credentials(record)
        if (not rotation.same_pair(old, current) or not rotation.same_pair(live, current)
                or not secrets.compare_digest(pending.password.encode(), password.encode())):
            raise rotation.RotationError("vault_conflict")
        record["vault_state"] = "pending_staged"
        engine._phase(record, "PREPARED")
        print("PASS | Pending staged and read back; recovery references persisted")
        stage = "R1 pre-change check and hashing"
        new_command = old_command.rsplit(" secret sha512 ", 1)[0] + " secret sha512 " + recovery.sha512_crypt(pending.password)
        _current_unchanged(store, current)
        if recovery.read_configs(connection, "R1") != original:
            raise rotation.RotationError("conflict")
        stage = "R1 admin password change"
        engine._phase(record, "ROTATING")
        record["devices"]["R1"].update(state="unknown", attempted=True, verified_at=None)
        engine._event(record, "rotate", "R1")  # Durable intent BEFORE sending a command.
        attempted = True
        probe._send(connection, new_command)
        stage = "new admin password fresh SSH verification"
        engine._phase(record, "VERIFYING")
        expected = (tuple(new_command if line == old_command else line for line in original[0]), original[1])
        _verify(pending.password, expected)
        record["devices"]["R1"].update(state="verified_new", verified_at=rotation.stamp())
        engine._event(record, "verify", "R1", "PASS")
        print("PASS | new admin password verified via fresh SSH; unrelated configuration preserved")
    except (Exception, KeyboardInterrupt) as error:
        result = 130 if isinstance(error, KeyboardInterrupt) else 1
        print(f"FAIL | {stage}")
        if record is not None and record["vault_state"] == "staging":
            record["vault_state"] = "unknown"
        _record_failure(engine, record, error, "R1" if attempted else None)
    finally:
        try:
            if attempted and not _rollback(engine, record, connection, current, pending,
                                           original, old_command, new_command):
                result = result or 1
        finally:
            recovery._disconnect(connection)
    if record is not None:
        if result == 0:
            print("PASS | R1 admin test | state=ROLLED_BACK")
        else:
            print("FAIL | R1 admin test | review the rotation journal and retained Vault items before retrying")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="Offline preview; no credentials, connections or journal writes.")
    mode.add_argument("--execute", action="store_true", help="Run the R1-only test without additional prompts.")
    args = parser.parse_args(argv)
    if args.dry_run:
        print("PASS | offline plan | R1 172.20.20.13 only; no Vault/device access or journal writes")
        print("PASS | plan | archive original -> stage Pending -> change admin -> fresh SSH -> restore -> fresh SSH")
        print("PASS | plan | Current, startup configuration, other devices and monitoring services unchanged")
        return 0
    try:
        journal = JournalStore(rotation.STATE_DIR)
        engine = rotation.RotationEngine(OnePasswordStore(), None, journal)
        with recovery.quiet_transport(), journal.lock():
            return _execute(engine)
    except (Exception, KeyboardInterrupt) as error:
        print("FAIL | rotation journal/access | inspect retained recovery information before retrying")
        return 130 if isinstance(error, KeyboardInterrupt) else 1


if __name__ == "__main__":
    raise SystemExit(main())

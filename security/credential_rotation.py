"""Recoverable shared-admin rotation for the isolated NetPilot Containerlab.

Run ``python3 -m security.credential_rotation plan --dry-run`` for an offline plan.
No imports perform Vault, device, service or journal operations.
"""

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re
import secrets
import string
import sys
import uuid

import config_changes
from security.rotation_adapters import AdapterError, NetmikoDeviceAdapter, OnePasswordStore, adapter_error_detail
from security.rotation_state import FLEET, JournalStore, StateError, transition
from security.telegraf_launcher import interpolation_value


ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "inventory" / "devices.yml"
STATE_DIR = Path.home() / ".local/state/netpilot/rotation"
ALPHABET = string.ascii_letters + string.digits + "-_!@"
TERMINAL = {"COMMITTED", "ROLLED_BACK"}


class RotationError(RuntimeError):
    """An allowlisted category, never an adapter's private exception text."""

    def __init__(self, category="blocked"):
        self.category = category
        super().__init__("Rotation stopped safely: " + category + ".")


def stamp():
    return datetime.now(timezone.utc).isoformat()


def generate_password(previous, length=32):
    if isinstance(length, bool) or not isinstance(length, int) or not 24 <= length <= 128:
        raise RotationError("credentials")
    for _ in range(16):
        candidate = "".join(secrets.choice(ALPHABET) for _ in range(length))
        if candidate != previous:
            interpolation_value(candidate)
            return candidate
    raise RotationError("credentials")


def discover_inventory(path=INVENTORY):
    try:
        inventory = config_changes.load_inventory(path)
        records = inventory["devices"]
        if not isinstance(records, dict):
            raise ValueError
        if any(name not in FLEET and not name.lower().startswith("test-") for name in records):
            raise ValueError
        result = {}
        for name in FLEET:
            device = records[name]
            if (device.get("hostname", name) != name or device.get("vendor") != "Arista"
                    or device.get("platform") not in ("cEOS", "cEOSLab")):
                raise ValueError
            address = ipaddress.IPv4Address(device["management"]["ipv4"])
            if address.is_unspecified or address.is_multicast or address.is_loopback:
                raise ValueError
            result[name] = str(address)
        if len(set(result.values())) != len(FLEET):
            raise ValueError
        return result
    except Exception:
        raise RotationError("inventory") from None


def checked_scope(scope):
    scope = list(scope)
    if scope not in (["R1"], list(FLEET)):
        raise RotationError("inventory")
    return scope


def same_pair(left, right):
    return left.username == right.username and secrets.compare_digest(left.password.encode(), right.password.encode())


class MonitoringBoundary:
    """Unconfigured callers cannot claim monitoring verification."""

    available = False
    verification_available = False

    def verify_current(self, rotation_id, targets):
        """Read-only proof of collector health and fresh gNMI from every target."""
        raise RotationError("monitoring")

    def refresh_and_verify(self, rotation_id, targets):
        raise RotationError("monitoring")


class RotationEngine:
    def __init__(self, credentials, devices, journal, inventory_path=INVENTORY, monitoring=None):
        self.credentials = credentials
        self.devices = devices
        self.journal = journal
        self.inventory_path = Path(inventory_path)
        self.monitoring = monitoring if monitoring is not None else MonitoringBoundary()

    def _authorize(self, authorized, confirmation, expected):
        if authorized is not True or confirmation not in ("", expected):
            raise RotationError("blocked")
        if not (self.credentials.live_writes_supported and self.devices.live_writes_supported):
            raise RotationError("blocked")

    def _inventory(self, record=None):
        inventory = discover_inventory(self.inventory_path)
        if record is not None and inventory != {
                name: item["management_ip"] for name, item in record["devices"].items()}:
            raise RotationError("inventory")
        return inventory

    def _load(self):
        record = self.journal.load()
        if record is None:
            raise RotationError("journal")
        self._inventory(record)
        return record

    def _event(self, record, operation, device=None, result="INFO", error=None):
        record["updated_at"] = stamp()
        record["events"].append({"at": record["updated_at"], "operation": operation,
                                  "device": device, "phase": record["phase"], "result": result, "error": error})
        self.journal.save(record)

    def _phase(self, record, phase):
        # Do not advance the caller's state until its transition is durable.
        candidate = deepcopy(record)
        if candidate["phase"] != phase:
            candidate["phase"] = transition(candidate["phase"], phase)
        if phase in TERMINAL:
            candidate["ended_at"] = stamp()
        self._event(candidate, "transition")
        for key in ("phase", "ended_at", "updated_at", "events"):
            record[key] = candidate[key]

    @staticmethod
    def _category(error, default="ambiguous"):
        value = getattr(error, "category", None)
        allowed = {"inventory", "credentials", "authentication", "unreachable", "identity",
                   "privilege", "recovery_access", "device_write", "verification", "vault_read",
                   "vault_write", "vault_conflict", "journal", "interrupted", "ambiguous",
                   "monitoring", "blocked", "conflict"}
        return value if value in allowed else ("interrupted" if isinstance(error, KeyboardInterrupt)
                                                else "journal" if isinstance(error, StateError) else default)

    def _fail(self, record, error, phase="RECOVERY_REQUIRED", device=None, operation="interrupt"):
        category = self._category(error)
        if device is not None:
            record["devices"][device].update(state="unknown", verified_at=None, last_error=category)
        if record["phase"] != phase:
            record["phase"] = transition(record["phase"], phase)
        self._event(record, operation, device, "FAIL", category)
        report = self._summary(record)
        detail = adapter_error_detail(error)
        if detail:
            report["error_message"] = detail
        return report

    @staticmethod
    def _summary(record):
        if record is None:
            return {"phase": "IDLE", "outcome": "Not Started", "device_states": {}, "monitoring_request": None}
        phase = record["phase"]
        outcome = {"COMMITTED": "Success", "ROLLED_BACK": "Rollback Completed",
                   "PARTIAL_FAILURE": "Partial Failure", "RECOVERY_REQUIRED": "Recovery Required",
                   "ERROR": "Recovery Required"}.get(phase, "In Progress")
        return {"rotation_id": record["rotation_id"], "phase": phase, "outcome": outcome,
                "started_at": record["started_at"], "updated_at": record["updated_at"],
                "ended_at": record["ended_at"], "scope": list(record["scope"]),
                "device_states": {name: {key: value for key, value in item.items()}
                                  for name, item in record["devices"].items()},
                "vault_state": record["vault_state"], "monitoring_state": record["monitoring_state"],
                "monitoring_request": ({"rotation_id": record["rotation_id"],
                                        "service": "netpilot-telegraf.service",
                                        "action": ("verify_current" if record["monitoring_state"] == "verification_required"
                                                   else "refresh_and_verify"),
                                        "targets": list(FLEET)}
                                       if record["monitoring_state"] in ("refresh_required", "failed", "verification_required")
                                       and ((record["vault_state"] == "promoted"
                                             and all(item["state"] == "verified_new" for item in record["devices"].values()))
                                            or (record["vault_state"] == "unchanged"
                                                and all(item["state"] == "verified_old" for item in record["devices"].values())))
                                       else None),
                "audit_events": deepcopy(record["events"])}

    def status(self):
        return self._summary(self.journal.load())

    def plan(self, scope=("R1",)):
        scope = checked_scope(scope)
        inventory = self._inventory()
        record = self.journal.load()
        blockers = ["Vault ownership, running/startup equality and live access are checked at execution.",
                    "Independent recovery SSH login was operator-verified; runtime checks its configured role/privilege.",
                    "Run during exclusive maintenance access; no concurrent device or Vault edits."]
        if record:
            blockers.append("Existing journal: " + record["phase"] +
                            "; completed R1 test cleanup is separate from fleet execution.")
        return {"mode": "offline_dry_run", "targets": scope, "inventory": inventory,
                "password_policy": {"length": 32, "alphabet_size": len(ALPHABET), "minimum_length": 24},
                "actions": ["Verify Current logins, configured recovery accounts and fresh all-device telemetry.",
                            "Archive Current in owned Previous; securely stage and read back one shared Pending password.",
                            "Rotate sequentially; fresh SSH and guarded startup save after each change.",
                            "Stop on failure, retaining Current, Pending, Previous and recovery journal.",
                            "After all nine verify: promote Current, restart managed user Telegraf, verify fresh telemetry."],
                "blockers": blockers,
                "live_execution_enabled": bool(self.credentials.live_writes_supported
                                               and self.devices.live_writes_supported
                                               and self.monitoring.available)}

    def precheck(self, scope=("R1",)):
        scope = checked_scope(scope)
        inventory = self._inventory()
        report = {"mode": "live_read_only", "targets": scope, "devices": {}, "pending_item": "unknown",
                  "recovery_account_configured": False, "passed": False, "error": None}
        try:
            existing = self.journal.load()
            if existing and existing["phase"] not in TERMINAL:
                raise RotationError("conflict")
            current = self.credentials.read_current()
            pending = self.credentials.find_pending()
            report["pending_item"] = "present" if pending is not None else "absent"
            recovery = True
            for name in scope:
                self.devices.authenticate(name, inventory[name], current)
                recovered = self.devices.verify_recovery(name, inventory[name], current.username) is True
                report["devices"][name] = {"current_authentication": "PASS", "recovery_account_configured": recovered}
                recovery = recovery and recovered
            report["recovery_account_configured"] = recovery
            report["passed"] = recovery and pending is None
            if not recovery:
                report["error"] = "recovery_access"
            elif pending is not None:
                report["error"] = "vault_conflict"
        except Exception as error:
            report["error"] = self._category(error, "credentials")
        return report

    def prepare(self, scope=("R1",), authorized=False, confirmation=""):
        scope = checked_scope(scope)
        self._authorize(authorized, confirmation, "PREPARE " + ("FLEET" if len(scope) == 9 else "R1"))
        if (self.monitoring.verification_available is not True
                or (scope == list(FLEET) and self.monitoring.available is not True)):
            raise RotationError("monitoring")
        with self.journal.operation():
            previous_record = self.journal.load()
            if previous_record and previous_record["phase"] not in TERMINAL:
                raise RotationError("conflict")
            inventory = self._inventory()
            current = self.credentials.read_current()
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", current.username):
                raise RotationError("credentials")
            from security.rotation_cleanup import completed_fleet, retire_completed_pending
            completed = completed_fleet(previous_record)
            if self.credentials.find_pending() is not None and not completed:
                # Only exact owned, verified terminal records may free Pending.
                raise RotationError("vault_conflict")
            for name in FLEET:
                self.devices.authenticate(name, inventory[name], current)
                if name in scope and self.devices.verify_recovery(name, inventory[name], current.username) is not True:
                    raise RotationError("recovery_access")
            rotation_id = uuid.uuid4().hex
            if self.monitoring.verify_current(rotation_id, inventory) is not True:
                raise RotationError("monitoring")
            if completed:
                retire_completed_pending(self, previous_record, current)
            elif previous_record:
                self.journal.archive_completed(previous_record)
            now = stamp()
            record = {"version": 1, "rotation_id": rotation_id, "started_at": now,
                      "updated_at": now, "ended_at": None, "phase": transition("IDLE", "PRECHECK"), "scope": scope,
                      "username": current.username,
                      "devices": {name: {"management_ip": inventory[name], "state": "verified_old",
                                         "attempted": False, "verified_at": now, "last_error": None} for name in FLEET},
                      "credential_refs": {"current": current.reference, "pending": None, "previous": None},
                      "vault_state": "unchanged", "monitoring_state": "not_requested", "events": []}
            self._event(record, "precheck", result="PASS")
            try:
                self._event(record, "archive_current")
                previous = self.credentials.archive_current(record["rotation_id"], current)
                if not same_pair(previous, current) or previous.rotation_id != record["rotation_id"]:
                    raise RotationError("vault_conflict")
                record["credential_refs"]["previous"] = previous.reference
                record["vault_state"] = "staging"
                self._event(record, "stage_pending")
                password = generate_password(current.password)
                pending = self.credentials.stage_pending(record["rotation_id"], current.username, password,
                                                         current_reference=current.reference)
                if (pending.username != current.username or pending.password != password
                        or pending.rotation_id != record["rotation_id"]
                        or pending.current_reference != current.reference):
                    raise RotationError("vault_conflict")
                record["credential_refs"]["pending"] = pending.reference
                record["vault_state"] = "pending_staged"
                self._phase(record, "PREPARED")
                return self._summary(record)
            except (Exception, KeyboardInterrupt) as error:
                record["vault_state"] = "unknown"
                return self._fail(record, error, operation="prepare")

    def _credentials(self, record, *, include_archived=False):
        refs = record["credential_refs"]
        # Cleanup retries may need secrets archived by an interrupted prior run.
        # Normal rotation/recovery continues to read active items only.
        options = {"include_archived": True} if include_archived else {}
        old = (self.credentials.read(refs["previous"], **options) if refs["previous"]
               else self.credentials.read_previous(record["rotation_id"]))
        pending = self.credentials.read(refs["pending"], **options) if refs["pending"] else self.credentials.find_pending()
        if (old is None or pending is None or old.rotation_id != record["rotation_id"]
                or pending.rotation_id != record["rotation_id"]
                or old.current_reference != refs["current"] or pending.current_reference != refs["current"]
                or old.username != record["username"] or pending.username != record["username"]
                or same_pair(old, pending)):
            raise RotationError("vault_conflict")
        current = self.credentials.read_current()
        if current.reference != refs["current"] or not (same_pair(current, old) or same_pair(current, pending)):
            raise RotationError("vault_conflict")
        refs.update(previous=old.reference, pending=pending.reference)
        return old, pending, current

    def _classify(self, name, address, old, pending):
        results = []
        for credential in (old, pending):
            try:
                self.devices.authenticate(name, address, credential)
                results.append(True)
            except AdapterError as error:
                if self._category(error) != "authentication":
                    return "unknown"
                results.append(False)
            except Exception:
                return "unknown"
        return "verified_old" if results == [True, False] else "verified_new" if results == [False, True] else "unknown"

    def _reconcile(self, record, old, pending, persist=False):
        for name, entry in record["devices"].items():
            state = self._classify(name, entry["management_ip"], old, pending)
            entry.update(state=state, verified_at=stamp() if state != "unknown" else None,
                         last_error="ambiguous" if state == "unknown" else None)
            if persist:
                self._event(record, "reconcile", name, "FAIL" if state == "unknown" else "PASS",
                            "ambiguous" if state == "unknown" else None)
        return all(entry["state"] != "unknown" for entry in record["devices"].values())

    def verify(self, *, include_archived=False):
        record = self._load()
        old, pending, current = self._credentials(record, include_archived=include_archived)
        complete = self._reconcile(record, old, pending)
        expected_old = record["phase"] in ("PRECHECK", "PREPARED", "ROLLED_BACK")
        matches = all(entry["state"] == ("verified_old" if expected_old or name not in record["scope"]
                                        else "verified_new") for name, entry in record["devices"].items())
        report = self._summary(record)
        report.update(mode="live_read_only", observed_vault="pending" if same_pair(current, pending) else "old",
                      observation_only=True, observed_at=stamp(), observations_complete=complete,
                      passed=complete and matches)
        # Never report a stale terminal journal as a fresh fleet health result.
        report["outcome"] = "Verification Observations"
        return report

    def _rotate(self, record):
        if (self.monitoring.verification_available is not True
                or (record["scope"] == list(FLEET) and self.monitoring.available is not True)):
            raise RotationError("monitoring")
        old, pending, current = self._credentials(record)
        if not same_pair(current, old):
            raise RotationError("vault_conflict")
        if not self._reconcile(record, old, pending, persist=True):
            return self._fail(record, RotationError("ambiguous"))
        if any(entry["state"] != "verified_old" for name, entry in record["devices"].items()
               if name not in record["scope"]):
            return self._fail(record, RotationError("conflict"))
        record["credential_refs"]["pending"] = pending.reference
        record["vault_state"] = "pending_staged"
        self._phase(record, "ROTATING")
        for name in record["scope"]:
            entry = record["devices"][name]
            already_new = entry["state"] == "verified_new"
            try:
                if already_new and not entry["attempted"]:
                    raise RotationError("conflict")
                self._inventory(record)
                if self.devices.verify_recovery(name, entry["management_ip"], record["username"]) is not True:
                    raise RotationError("recovery_access")
                # Durable uncertainty BEFORE submission survives timeout or power loss.
                entry.update(state="unknown", attempted=True, verified_at=None, last_error=None)
                self._event(record, "rotate", name)
                if not already_new:
                    self.devices.change_password(name, entry["management_ip"], old, pending)
                # On resume, SSH success alone does not prove startup persistence.
                self.devices.ensure_verified(name, entry["management_ip"], pending)
                entry.update(state="verified_new", verified_at=stamp(), last_error=None)
                self._event(record, "verify", name, "PASS")
            except (Exception, KeyboardInterrupt) as error:
                return self._fail(record, error, "PARTIAL_FAILURE", name, "rotate")
        self._phase(record, "VERIFYING")
        try:
            # Every final result is based on a fresh authentication session.
            for name in FLEET:
                credential = pending if name in record["scope"] else old
                self.devices.authenticate(name, record["devices"][name]["management_ip"], credential)
                record["devices"][name].update(state="verified_new" if name in record["scope"] else "verified_old",
                                               verified_at=stamp(), last_error=None)
                self._event(record, "verify", name, "PASS")
            if record["scope"] == list(FLEET):
                self._phase(record, "READY_TO_COMMIT")
            return self._summary(record)
        except (Exception, KeyboardInterrupt) as error:
            return self._fail(record, error, "PARTIAL_FAILURE", name, "verify")

    def rotate(self, device=None, fleet=False, authorized=False, confirmation=""):
        expected = "ROTATE FLEET" if fleet else "ROTATE R1"
        self._authorize(authorized, confirmation, expected)
        if (fleet and device is not None) or (not fleet and device != "R1"):
            raise RotationError("inventory")
        with self.journal.operation():
            record = self._load()
            if record["phase"] != "PREPARED" or record["scope"] != (list(FLEET) if fleet else ["R1"]):
                raise RotationError("conflict")
            try:
                return self._rotate(record)
            except (Exception, KeyboardInterrupt) as error:
                return self._fail(record, error, operation="rotate")

    def recover(self, action="inspect", authorized=False, confirmation=""):
        if action == "inspect":
            return self.verify()
        if action not in ("resume", "rollback"):
            raise RotationError("blocked")
        # Validate authorization BEFORE creating a journal directory or acquiring secrets.
        record = self._load()
        self._authorize(authorized, confirmation, action.upper() + " " + record["rotation_id"])
        with self.journal.operation():
            locked = self._load()
            if locked["rotation_id"] != record["rotation_id"] or locked["phase"] in TERMINAL:
                raise RotationError("conflict")
            record = locked
            if action == "resume" and record["phase"] not in (
                    "PRECHECK", "ERROR", "PARTIAL_FAILURE", "RECOVERY_REQUIRED", "ROTATING", "PREPARED", "VERIFYING"):
                raise RotationError("conflict")
            try:
                # A crash may leave any in-flight phase. Persist recovery intent first.
                if record["phase"] != "RECOVERY_REQUIRED":
                    self._phase(record, "RECOVERY_REQUIRED")
                if action == "resume":
                    return self._rotate(record)
                return self._rollback(record)
            except (Exception, KeyboardInterrupt) as error:
                return self._fail(record, error, operation=action)

    def _abandon_unstaged(self, record):
        """Explicit rollback of preparation that never acquired a Pending item.

        No device could have been submitted without a durable attempted marker.
        Re-check every device and Current; preserve any recovery item in the Vault.
        """
        refs = record["credential_refs"]
        if refs["pending"] or any(item["attempted"] for item in record["devices"].values()):
            raise RotationError("vault_conflict")
        current = self.credentials.read_current()
        previous = (self.credentials.read(refs["previous"]) if refs["previous"]
                    else self.credentials.read_previous(record["rotation_id"]))
        if (current.reference != refs["current"] or current.username != record["username"]
                or (previous is not None and (not same_pair(previous, current)
                    or previous.rotation_id != record["rotation_id"]
                    or previous.current_reference != current.reference))):
            raise RotationError("vault_conflict")
        self._phase(record, "ROLLING_BACK")
        for name, entry in record["devices"].items():
            try:
                self.devices.authenticate(name, entry["management_ip"], current)
                entry.update(state="verified_old", verified_at=stamp(), last_error=None)
                self._event(record, "rollback", name, "PASS")
            except (Exception, KeyboardInterrupt) as error:
                return self._fail(record, error, device=name, operation="rollback")
        readback = self.credentials.read_current()
        if (self.credentials.find_pending() is not None or readback.reference != current.reference
                or not same_pair(readback, current)):
            raise RotationError("vault_conflict")
        record["vault_state"] = "unchanged"
        if previous is not None:
            refs["previous"] = previous.reference
        self._phase(record, "ROLLED_BACK")
        return self._summary(record)

    def _rollback(self, record):
        if record["credential_refs"]["pending"] is None and self.credentials.find_pending() is None:
            return self._abandon_unstaged(record)
        old, pending, current = self._credentials(record)
        promoted = same_pair(current, pending)
        needs_refresh = promoted or record["monitoring_state"] in ("refresh_required", "failed")
        if needs_refresh and not self.monitoring.available:
            raise RotationError("monitoring")
        if not self._reconcile(record, old, pending, persist=True):
            return self._fail(record, RotationError("ambiguous"))
        if any(entry["state"] != "verified_old" for name, entry in record["devices"].items()
               if name not in record["scope"]):
            return self._fail(record, RotationError("conflict"))
        self._phase(record, "ROLLING_BACK")
        for name in reversed(record["scope"]):
            entry = record["devices"][name]
            already_old = entry["state"] == "verified_old"
            if already_old and not entry["attempted"]:
                continue
            try:
                if not entry["attempted"]:
                    raise RotationError("conflict")
                self._inventory(record)
                if self.devices.verify_recovery(name, entry["management_ip"], record["username"]) is not True:
                    raise RotationError("recovery_access")
                entry.update(state="unknown", attempted=True, verified_at=None)
                self._event(record, "rollback", name)
                if not already_old:
                    # A failed submission may have changed only running config.
                    # Persist only the verified owned hash before restoring Old.
                    self.devices.ensure_verified(name, entry["management_ip"], pending)
                    self.devices.change_password(name, entry["management_ip"], pending, old, restore=True)
                self.devices.ensure_verified(name, entry["management_ip"], old)
                entry.update(state="verified_old", verified_at=stamp(), last_error=None)
                self._event(record, "rollback", name, "PASS")
            except (Exception, KeyboardInterrupt) as error:
                return self._fail(record, error, device=name, operation="rollback")
        active_device = None
        operation = "rollback"
        try:
            for name, entry in record["devices"].items():
                active_device = name
                self.devices.authenticate(name, entry["management_ip"], old)
                entry.update(state="verified_old", verified_at=stamp(), last_error=None)
                self._event(record, "verify", name, "PASS")
            active_device = None
            current = self.credentials.read_current()
            if current.reference != record["credential_refs"]["current"]:
                raise RotationError("vault_conflict")
            if same_pair(current, pending):
                record["vault_state"] = "promotion_intent"
                record["monitoring_state"] = "refresh_required"
                self._event(record, "promote")
                self.credentials.restore_current(current, old)
                needs_refresh = True
            elif not same_pair(current, old):
                raise RotationError("vault_conflict")
            readback = self.credentials.read_current()
            if readback.reference != record["credential_refs"]["current"] or not same_pair(readback, old):
                raise RotationError("vault_conflict")
            record["vault_state"] = "unchanged"
            if needs_refresh:
                operation = "monitoring"
                record["monitoring_state"] = "refresh_required"
                self._event(record, "monitoring")
                if self.monitoring.refresh_and_verify(record["rotation_id"], dict(self._inventory(record))) is not True:
                    raise RotationError("monitoring")
                record["monitoring_state"] = "verified"
            elif any(entry["attempted"] for entry in record["devices"].values()):
                # Current never changed; verify the existing collector redialed with Old.
                # Do not restart it merely to finish an R1-only rehearsal.
                operation = "monitoring"
                record["monitoring_state"] = "verification_required"
                self._event(record, "monitoring")
                if (not self.monitoring.verification_available
                        or self.monitoring.verify_current(record["rotation_id"], self._inventory(record)) is not True):
                    raise RotationError("monitoring")
                record["monitoring_state"] = "verified"
            self._phase(record, "ROLLED_BACK")
            return self._summary(record)
        except (Exception, KeyboardInterrupt) as error:
            if record["vault_state"] == "promotion_intent":
                record["vault_state"] = "unknown"
            if operation == "monitoring":
                record["monitoring_state"] = "failed" if needs_refresh else "verification_required"
            return self._fail(record, error, device=active_device, operation=operation)

    def commit(self, authorized=False, confirmation=""):
        record = self._load()
        self._authorize(authorized, confirmation, "COMMIT " + record["rotation_id"])
        if not self.monitoring.available:
            raise RotationError("monitoring")
        with self.journal.operation():
            locked = self._load()
            if (locked["rotation_id"] != record["rotation_id"] or locked["scope"] != list(FLEET)
                    or locked["phase"] not in ("READY_TO_COMMIT", "COMMITTING", "RECOVERY_REQUIRED")):
                raise RotationError("conflict")
            record = locked
            active_device = None
            operation = "verify"
            try:
                old, pending, current = self._credentials(record)
                for name, entry in record["devices"].items():
                    active_device = name
                    if not entry["attempted"]:
                        raise RotationError("conflict")
                    entry.update(state="unknown", verified_at=None)
                    self._event(record, "verify", name)
                    self.devices.ensure_verified(name, entry["management_ip"], pending)
                    entry.update(state="verified_new", verified_at=stamp(), last_error=None)
                    self._event(record, "verify", name, "PASS")
                active_device = None
                operation = "promote"
                self._phase(record, "COMMITTING")
                if same_pair(current, old):
                    record["vault_state"] = "promotion_intent"
                    self._event(record, "promote")
                    self.credentials.promote(current, pending)
                readback = self.credentials.read_current()
                if readback.reference != record["credential_refs"]["current"] or not same_pair(readback, pending):
                    raise RotationError("vault_conflict")
                record["vault_state"] = "promoted"
                operation = "monitoring"
                record["monitoring_state"] = "refresh_required"
                self._event(record, "monitoring")
                if self.monitoring.refresh_and_verify(record["rotation_id"], self._inventory(record)) is not True:
                    record["monitoring_state"] = "failed"
                    raise RotationError("monitoring")
                record["monitoring_state"] = "verified"
                self._phase(record, "COMMITTED")
                return self._summary(record)
            except (Exception, KeyboardInterrupt) as error:
                if record["vault_state"] == "promotion_intent":
                    record["vault_state"] = "unknown"
                if operation == "monitoring":
                    record["monitoring_state"] = "failed"
                return self._fail(record, error, device=active_device, operation=operation)

    def run_fleet(self, authorized=False):
        """One explicit command, reusing the established three guarded phases."""
        self._authorize(authorized, "", "")
        # Keep one lock across prepare/rotate/commit, including scheduled callers.
        with self.journal.operation():
            result = self.prepare(FLEET, authorized=authorized)
            if result["phase"] != "PREPARED":
                return result
            result = self.rotate(fleet=True, authorized=authorized)
            if result["phase"] != "READY_TO_COMMIT":
                return result
            return self.commit(authorized=authorized)

    def cleanup_r1(self, authorized=False):
        self._authorize(authorized, "", "")
        from security.rotation_cleanup import cleanup_r1_test
        with self.journal.operation():
            return cleanup_r1_test(self.credentials, self.devices, self.journal, self._inventory())

    def cleanup_failed(self, authorized=False):
        self._authorize(authorized, "", "")
        from security.rotation_cleanup import cleanup_failed_rotation
        with self.journal.operation():
            return cleanup_failed_rotation(self)


def _notification(report, notify=None):
    """Shared manual/scheduled delivery; mail cannot change transaction results."""
    try:
        if notify is None:
            from security.rotation_email import send_notification
            notify = send_notification
        return notify(report)
    except (Exception, KeyboardInterrupt):
        return {"status": "failed", "error": "notification_failed"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "status", "precheck", "prepare", "rotate", "verify",
                                          "recover", "commit", "cleanup-r1", "cleanup-failed", "fleet"))
    parser.add_argument("--dry-run", action="store_true", help="Offline planning; no external access or changes.")
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--device", choices=("R1",))
    scope.add_argument("--fleet", action="store_true")
    parser.add_argument("--action", dest="recovery_action", choices=("inspect", "resume", "rollback"), default="inspect")
    parser.add_argument("--execute", action="store_true", help="Authorize this live operation; no further prompt.")
    args = parser.parse_args(argv)
    notify = (args.execute and not args.dry_run
              and (args.action in ("fleet", "rotate", "commit")
                   or args.action == "recover" and args.recovery_action != "inspect"))
    try:
        from security.rotation_monitoring import ManagedTelegrafMonitoring
        from security.setup_recovery_accounts import quiet_transport
        engine = RotationEngine(OnePasswordStore(), NetmikoDeviceAdapter(), JournalStore(STATE_DIR),
                                monitoring=ManagedTelegrafMonitoring())
        selected = list(FLEET) if args.fleet or args.action == "fleet" else [args.device or "R1"]
        if (args.dry_run and (args.action not in ("plan", "fleet") or args.execute)
                or (args.action in ("fleet", "cleanup-r1", "cleanup-failed") and args.device)):
            raise RotationError("blocked")
        with quiet_transport():
            if args.action == "plan" or (args.action == "fleet" and args.dry_run):
                result = engine.plan(selected)
            elif args.action == "status":
                result = engine.status()
                result["evidence"] = "Recorded state only; use verify for fresh SSH observations."
            elif args.action == "precheck":
                result = engine.precheck(selected)
            elif args.action == "verify":
                result = engine.verify()
            elif args.action == "recover" and args.recovery_action == "inspect":
                result = engine.recover()
            else:
                if not args.execute:
                    raise RotationError("blocked")
                if args.action == "prepare":
                    result = engine.prepare(selected, authorized=True)
                elif args.action == "rotate":
                    result = engine.rotate(None if args.fleet else "R1", args.fleet, authorized=True)
                elif args.action == "recover":
                    result = engine.recover(args.recovery_action, authorized=True)
                elif args.action == "cleanup-r1":
                    result = engine.cleanup_r1(authorized=True)
                elif args.action == "cleanup-failed":
                    result = engine.cleanup_failed(authorized=True)
                elif args.action == "fleet":
                    result = engine.run_fleet(authorized=True)
                else:
                    result = engine.commit(authorized=True)
        failed = result.get("phase") in ("PARTIAL_FAILURE", "RECOVERY_REQUIRED", "ERROR") or result.get("passed") is False
        result["result"] = "FAIL" if failed else "PASS"
        if notify and (failed or result.get("phase") == "COMMITTED"):
            # A later output error must not send a second, conflicting notice.
            notify = False
            result["notification"] = _notification(result)
        print(json.dumps(result, indent=2))
        return int(failed)
    except (KeyboardInterrupt, EOFError):
        report = {"result": "FAIL", "error": "interrupted", "outcome": "Recovery Required"}
        if notify:
            report["notification"] = _notification(report)
        print(json.dumps(report))
        return 130
    except Exception as error:
        report = {"result": "FAIL", "error": RotationEngine._category(error), "outcome": "Stopped; inspect status before recovery."}
        if getattr(error, "stage", None):
            report["stage"] = error.stage
        detail = adapter_error_detail(error)
        if detail:
            report["error_message"] = detail
        if notify:
            report.setdefault("stage", {"fleet": "prepare", "commit": "promote",
                                        "recover": args.recovery_action}.get(args.action, args.action))
            report["notification"] = _notification(report)
        print(json.dumps(report))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

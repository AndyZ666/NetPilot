"""Archive only verified, transaction-owned rotation recovery records.

The caller supplies --execute authorization and holds JournalStore.lock(). No
password changes or service operations occur here. Archived Vault items remain
recoverable; interrupted cleanup can be retried with the original journal.
"""

from security import credential_provider
from security.rotation_adapters import PENDING, PREVIOUS_PREFIX, _same_pair
from security.rotation_state import FLEET, validate_state


class CleanupError(RuntimeError):
    """Only fixed step names cross the CLI boundary; never Vault/SSH output."""

    category = "conflict"

    def __init__(self, stage):
        self.stage = stage
        super().__init__("Rotation cleanup failed at " + stage + "; recovery records retained.")


def _completed_r1_test(record, inventory):
    validate_state(record)
    if (record["phase"] != "ROLLED_BACK" or record["scope"] != ["R1"]
            or record["username"] != "admin" or not record["ended_at"]
            or record["vault_state"] != "pending_staged"
            or record["monitoring_state"] != "not_requested"
            or inventory.get("R1") != "172.20.20.13"
            or set(inventory) != set(FLEET)):
        raise CleanupError("completed R1 test evidence")
    for name, entry in record["devices"].items():
        if entry["management_ip"] != inventory[name] or entry["last_error"] is not None:
            raise CleanupError("completed R1 test evidence")
        if name == "R1":
            valid = (entry["attempted"] and entry["state"] == "verified_old"
                     and entry["verified_at"] is not None)
        else:
            valid = (not entry["attempted"] and entry["state"] == "pending"
                     and entry["verified_at"] is None)
        if not valid:
            raise CleanupError("completed R1 test evidence")
    events = record["events"]
    if any(event["result"] == "FAIL" or event["error"] is not None
           or event["device"] not in (None, "R1") for event in events):
        raise CleanupError("completed R1 test evidence")
    verified = [index for index, event in enumerate(events)
                if event["operation"] == "verify" and event["device"] == "R1"
                and event["result"] == "PASS"]
    restored = [index for index, event in enumerate(events)
                if event["operation"] == "rollback" and event["device"] == "R1"
                and event["result"] == "PASS"]
    references = list(record["credential_refs"].values())
    if (not verified or not restored or max(verified) >= max(restored)
            or None in references or len(set(references)) != 3):
        raise CleanupError("completed R1 test evidence")


def _bound_item(store, record, key, title):
    reference = record["credential_refs"][key]
    # Documented get-by-ID/include-archive keeps retry possible after interruption.
    # https://developer.1password.com/docs/cli/reference/management-commands/item/
    item = store._json(["item", "get", reference, "--vault", credential_provider.VAULT,
                        "--include-archive", "--format", "json", "--reveal"])
    credential = store._credential(item, title)
    if (credential.reference != reference or credential.username != "admin"
            or credential.rotation_id != record["rotation_id"]
            or credential.current_reference != record["credential_refs"]["current"]):
        raise CleanupError("Vault item ownership")
    active = store._named(title)
    if active not in (None, reference):
        raise CleanupError("Vault item ownership")
    # Same-title ID found by include-archive, absent from normal listing => archived.
    return credential, active is not None


def _current_unchanged(store, original):
    current = store.read_current()
    if current != original:
        raise CleanupError("Current unchanged check")


def cleanup_r1_test(store, devices, journal, inventory):
    """Verify, then archive the exact bound items; clear only an archived journal.

    Returns a secret-free result. Failures leave the active journal available,
    including when the first Vault archive succeeded and a later step failed.
    """
    stage = "completed R1 test evidence"
    try:
        journal._assert_locked()
        record = journal.load()
        _completed_r1_test(record, inventory)
        stage = "Vault item ownership"
        current = store.read_current()
        if current.reference != record["credential_refs"]["current"] or current.username != "admin":
            raise CleanupError(stage)
        previous_title = PREVIOUS_PREFIX + record["rotation_id"]
        pending, _ = _bound_item(store, record, "pending", PENDING)
        previous, _ = _bound_item(store, record, "previous", previous_title)
        if not _same_pair(current, previous) or _same_pair(current, pending):
            raise CleanupError(stage)
        stage = "fresh R1 original admin authentication"
        devices.authenticate("R1", inventory["R1"], current)
        _current_unchanged(store, current)
        if journal.load() != record:
            raise CleanupError("completed R1 test evidence")
        # Preserve immutable evidence BEFORE removing active Vault/journal entries.
        stage = "completed journal archive"
        journal.archive_completed(record)
        for key, title, expected in (("pending", PENDING, pending),
                                     ("previous", previous_title, previous)):
            stage = "bound " + key + " archive"
            actual, active = _bound_item(store, record, key, title)
            if actual != expected or journal.load() != record:
                raise CleanupError(stage)
            _current_unchanged(store, current)
            if active:
                # --archive is mandatory: never permanently delete any credential.
                credential_provider._run_op([
                    "item", "delete", actual.reference, "--vault", credential_provider.VAULT,
                    "--archive",
                ])
            archived, still_active = _bound_item(store, record, key, title)
            if still_active or archived != expected:
                raise CleanupError(stage)
        stage = "completed journal finalization"
        _current_unchanged(store, current)
        journal.finish_completed(record)
        return {"passed": True, "phase": "CLEANED", "rotation_id": record["rotation_id"]}
    except CleanupError:
        raise
    except KeyboardInterrupt:
        raise CleanupError(stage) from None
    except Exception:
        raise CleanupError(stage) from None


def _failed_fleet(record, inventory):
    validate_state(record)
    refs = list(record["credential_refs"].values())
    if (record["phase"] not in ("PARTIAL_FAILURE", "RECOVERY_REQUIRED")
            or record["scope"] != list(FLEET) or record["username"] != "admin"
            or record["vault_state"] != "pending_staged"
            or record["monitoring_state"] != "not_requested"
            or set(inventory) != set(FLEET) or None in refs or len(set(refs)) != 3
            or any(entry["management_ip"] != inventory[name]
                   for name, entry in record["devices"].items())
            or not any(event["result"] == "FAIL" for event in record["events"])):
        raise CleanupError("failed fleet transaction evidence")


def cleanup_failed_rotation(engine):
    """Close a failed fleet attempt only after fresh old-only authentication.

    The caller holds the journal lock and supplies --execute authorization.
    This never calls a password-change/save method or rewrites Current. Archived
    credentials remain readable by their bound IDs so interrupted cleanup can
    repeat the same live verification before proceeding.
    """
    stage = "failed fleet transaction evidence"
    store, journal = engine.credentials, engine.journal
    try:
        journal._assert_locked()
        record = journal.load()
        _failed_fleet(record, engine._inventory(record))
        stage = "Vault item ownership"
        current = store.read_current()
        if current.reference != record["credential_refs"]["current"] or current.username != "admin":
            raise CleanupError(stage)
        previous_title = PREVIOUS_PREFIX + record["rotation_id"]
        pending, _ = _bound_item(store, record, "pending", PENDING)
        previous, _ = _bound_item(store, record, "previous", previous_title)
        if not _same_pair(current, previous) or _same_pair(current, pending):
            raise CleanupError(stage)

        stage = "fresh nine-device original admin verification"
        report = engine.verify(include_archived=True)
        observations = report.get("device_states", {})
        # verify.passed expects new credentials in PARTIAL_FAILURE; inspect its
        # actual fresh observations instead of interpreting that flag as old-only.
        if (report.get("rotation_id") != record["rotation_id"]
                or report.get("phase") != record["phase"]
                or report.get("scope") != list(FLEET)
                or report.get("mode") != "live_read_only"
                or report.get("observations_complete") is not True
                or report.get("observed_vault") != "old"
                or set(observations) != set(FLEET)
                or any(entry.get("state") != "verified_old" or not entry.get("verified_at")
                       for entry in observations.values())):
            raise CleanupError(stage)
        _current_unchanged(store, current)
        if journal.load() != record:
            raise CleanupError("failed fleet transaction evidence")

        stage = "failed journal archive"
        journal.archive_failed(record)
        for key, title, expected in (("pending", PENDING, pending),
                                     ("previous", previous_title, previous)):
            stage = "bound " + key + " archive"
            actual, active = _bound_item(store, record, key, title)
            if actual != expected or journal.load() != record:
                raise CleanupError(stage)
            _current_unchanged(store, current)
            if active:
                credential_provider._run_op([
                    "item", "delete", actual.reference, "--vault", credential_provider.VAULT,
                    "--archive",
                ])
            archived, still_active = _bound_item(store, record, key, title)
            if still_active or archived != expected:
                raise CleanupError(stage)
        stage = "failed journal finalization"
        _current_unchanged(store, current)
        journal.finish_failed(record)
        return {"passed": True, "phase": "CLEANED", "rotation_id": record["rotation_id"],
                "archived_phase": record["phase"], "observed_vault": "old",
                "devices_verified_old": list(FLEET)}
    except CleanupError:
        raise
    except KeyboardInterrupt:
        raise CleanupError(stage) from None
    except Exception:
        raise CleanupError(stage) from None


def completed_fleet(record):
    """Only verified full-fleet terminal records qualify for the next cycle."""
    if not record or record["scope"] != list(FLEET) or not record["ended_at"]:
        return False
    if record["phase"] == "COMMITTED":
        credential_state, vault_state = "verified_new", "promoted"
    elif record["phase"] == "ROLLED_BACK":
        credential_state, vault_state = "verified_old", "unchanged"
    else:
        return False
    return (record["vault_state"] == vault_state and record["monitoring_state"] == "verified"
            and all(entry["state"] == credential_state and entry["verified_at"]
                    and entry["last_error"] is None for entry in record["devices"].values()))


def retire_completed_pending(engine, record, current):
    """Free only an owned terminal Pending after the caller's fresh fleet precheck.

    Previous credentials remain in the Vault. The immutable journal is archived
    before archiving Pending; a lost reply can be retried by its original ID.
    """
    store, journal = engine.credentials, engine.journal
    stage = "completed fleet ownership"
    try:
        journal._assert_locked()
        validate_state(record)
        if not completed_fleet(record) or journal.load() != record:
            raise CleanupError(stage)
        refs = record["credential_refs"]
        if current.reference != refs["current"] or None in refs.values() or len(set(refs.values())) != 3:
            raise CleanupError(stage)
        pending, active = _bound_item(store, record, "pending", PENDING)
        previous, _ = _bound_item(store, record, "previous", PREVIOUS_PREFIX + record["rotation_id"])
        expected = pending if record["phase"] == "COMMITTED" else previous
        if not _same_pair(current, expected) or _same_pair(previous, pending):
            raise CleanupError(stage)
        _current_unchanged(store, current)
        journal.archive_completed(record)
        stage = "completed Pending archive"
        if active:
            credential_provider._run_op(["item", "delete", pending.reference,
                                        "--vault", credential_provider.VAULT, "--archive"])
        archived, still_active = _bound_item(store, record, "pending", PENDING)
        if still_active or archived != pending or journal.load() != record:
            raise CleanupError(stage)
        _current_unchanged(store, current)
    except CleanupError:
        raise
    except (Exception, KeyboardInterrupt):
        raise CleanupError(stage) from None

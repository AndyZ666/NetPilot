"""Private, durable rotation metadata; this module never handles credentials.

Only the explicit schema below is persisted. Callers must use ``transition``
for phase changes and hold ``JournalStore.lock()`` throughout an operation.
"""

from contextlib import contextmanager
from datetime import datetime, timedelta
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import threading
import uuid


FLEET = ("R1", "R2", "R3", "R4", "R5", "S1", "S2", "S3", "S4")
TRANSITIONS = {
    "IDLE": {"PRECHECK"},
    "PRECHECK": {"PREPARED", "ERROR", "RECOVERY_REQUIRED"},
    "PREPARED": {"ROTATING", "VERIFYING", "ROLLING_BACK", "RECOVERY_REQUIRED"},
    "ROTATING": {"VERIFYING", "PARTIAL_FAILURE", "RECOVERY_REQUIRED"},
    "VERIFYING": {"READY_TO_COMMIT", "PARTIAL_FAILURE", "RECOVERY_REQUIRED", "ROLLING_BACK"},
    "READY_TO_COMMIT": {"COMMITTING", "ROLLING_BACK", "VERIFYING", "RECOVERY_REQUIRED"},
    "COMMITTING": {"COMMITTED", "RECOVERY_REQUIRED"},
    "COMMITTED": set(),
    "PARTIAL_FAILURE": {"ROTATING", "ROLLING_BACK", "RECOVERY_REQUIRED", "VERIFYING"},
    "RECOVERY_REQUIRED": {"ROTATING", "ROLLING_BACK", "VERIFYING", "COMMITTING"},
    "ROLLING_BACK": {"ROLLED_BACK", "RECOVERY_REQUIRED"},
    "ROLLED_BACK": set(),
    "ERROR": {"PRECHECK", "RECOVERY_REQUIRED"},
}
PHASES = frozenset(TRANSITIONS)
ERROR_CATEGORIES = frozenset({
    "inventory", "credentials", "authentication", "unreachable", "identity",
    "privilege", "recovery_access", "device_write", "verification", "vault_read",
    "vault_write", "vault_conflict", "journal", "interrupted", "ambiguous",
    "monitoring", "blocked", "conflict",
})
OPERATIONS = frozenset({
    "precheck", "prepare", "stage_pending", "rotate", "verify", "reconcile",
    "rollback", "resume", "archive_current", "promote", "monitoring",
    "transition", "interrupt",
})
MAX_EVENTS = 10000
MAX_BYTES = 4 * 1024 * 1024
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|\+00:00)\Z")
_USERNAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}\Z")
_REFERENCE = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")


class StateError(RuntimeError):
    """Fixed, sanitized journal error suitable for the command-line boundary."""


def transition(current, new):
    if (type(current) is not str or type(new) is not str
            or new not in TRANSITIONS.get(current, set())):
        raise StateError("The requested rotation phase transition is not allowed.")
    return new


def _require(condition):
    if not condition:
        raise StateError("Rotation journal schema is invalid.")


def _keys(value, expected):
    _require(type(value) is dict and set(value) == set(expected))


def _timestamp(value, nullable=False):
    if value is None and nullable:
        return
    _require(type(value) is str and bool(_TIMESTAMP.fullmatch(value)))
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    _require(parsed.utcoffset() == timedelta(0))


def _choice(value, choices, nullable=False):
    _require((value is None and nullable) or (type(value) is str and value in choices))


def validate_state(state):
    """Validate every persisted field; no free-text errors or payloads are allowed.

    References are opaque Vault item identifiers, never credential values. The
    controller owns their provenance; schema validation cannot recognize a
    credential deliberately placed in an otherwise valid metadata field.
    """
    try:
        _keys(state, ("version", "rotation_id", "started_at", "updated_at", "ended_at",
                      "phase", "scope", "username", "devices", "credential_refs",
                      "vault_state", "monitoring_state", "events"))
        _require(type(state["version"]) is int and state["version"] == 1)
        _require(type(state["rotation_id"]) is str and bool(re.fullmatch(r"[0-9a-f]{32}", state["rotation_id"])))
        for key in ("started_at", "updated_at"):
            _timestamp(state[key])
        _timestamp(state["ended_at"], nullable=True)
        _choice(state["phase"], PHASES)
        _require(type(state["scope"]) is list and state["scope"] in (["R1"], list(FLEET)))
        _require(type(state["username"]) is str and bool(_USERNAME.fullmatch(state["username"])))
        _keys(state["devices"], FLEET)
        addresses = set()
        for device in state["devices"].values():
            _keys(device, ("management_ip", "state", "attempted", "verified_at", "last_error"))
            address = device["management_ip"]
            _require(type(address) is str and str(ipaddress.IPv4Address(address)) == address)
            _require(address not in addresses)
            addresses.add(address)
            _choice(device["state"], {"pending", "verified_old", "verified_new", "unknown"})
            _require(type(device["attempted"]) is bool)
            _timestamp(device["verified_at"], nullable=True)
            _choice(device["last_error"], ERROR_CATEGORIES, nullable=True)
        _keys(state["credential_refs"], ("current", "pending", "previous"))
        for name, reference in state["credential_refs"].items():
            _require((name != "current" and reference is None)
                     or (type(reference) is str and bool(_REFERENCE.fullmatch(reference))))
        _choice(state["vault_state"], {"unchanged", "staging", "pending_staged", "promotion_intent", "promoted", "unknown"})
        _choice(state["monitoring_state"], {"not_requested", "verification_required", "refresh_required", "verified", "failed"})
        _require(type(state["events"]) is list and len(state["events"]) <= MAX_EVENTS)
        for event in state["events"]:
            _keys(event, ("at", "phase", "operation", "device", "result", "error"))
            _timestamp(event["at"])
            _choice(event["phase"], PHASES)
            _choice(event["operation"], OPERATIONS)
            _choice(event["device"], FLEET, nullable=True)
            _choice(event["result"], {"PASS", "FAIL", "INFO"})
            _choice(event["error"], ERROR_CATEGORIES, nullable=True)
    except StateError:
        raise
    except Exception:
        raise StateError("Rotation journal schema is invalid.") from None
    return state


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise StateError("Rotation journal contains duplicate fields.")
        result[key] = value
    return result


def _decode(content):
    if len(content) > MAX_BYTES:
        raise StateError("Rotation journal exceeds the supported size.")
    try:
        return validate_state(json.loads(content.decode("utf-8"), object_pairs_hook=_unique_object))
    except StateError:
        raise
    except Exception:
        raise StateError("Rotation journal cannot be read safely.") from None


def _private(info, mode, directory=False):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (not kind(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != mode
            or (not directory and info.st_nlink != 1)):
        raise StateError("Rotation storage ownership, type, or permissions are unsafe.")


def _read_file(directory, name):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        _private(os.fstat(descriptor), 0o600)
        chunks, size = [], 0
        while size <= MAX_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        content = b"".join(chunks)
        _decode(content)
        return content
    finally:
        os.close(descriptor)


class JournalStore:
    """One journal and advisory lock in a private directory outside the repository."""

    def __init__(self, root):
        self.root = Path(os.path.abspath(os.fspath(root)))
        self.path = self.root / "journal.json"
        self._directory_fd = None
        self._owner = None

    def _open_directory(self, create=False):
        """Walk using directory descriptors; reject symlinks in every component."""
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for component in self.root.parts[1:]:
                if create:
                    try:
                        os.mkdir(component, mode=0o700, dir_fd=descriptor)
                        os.fsync(descriptor)
                    except FileExistsError:
                        pass
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            _private(os.fstat(descriptor), 0o700, directory=True)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    @contextmanager
    def lock(self):
        if self._directory_fd is not None:
            raise StateError("This rotation store already holds an operation lock.")
        directory = descriptor = None
        try:
            directory = self._open_directory(create=True)
            descriptor = os.open("rotation.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 0o600, dir_fd=directory)
            _private(os.fstat(descriptor), 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise StateError("Another rotation operation is already running.") from None
            os.fsync(directory)
            self._directory_fd = directory
            self._owner = (os.getpid(), threading.get_ident())
            yield self
        except StateError:
            raise
        except OSError:
            raise StateError("The rotation operation lock is unavailable or unsafe.") from None
        finally:
            self._directory_fd = None
            self._owner = None
            if descriptor is not None:
                os.close(descriptor)
            if directory is not None:
                os.close(directory)
            # Never unlink the lock: contenders must use the same inode.

    def load(self):
        """Read atomically published state without creating files or directories."""
        directory = descriptor = None
        try:
            directory = self._open_directory()
            descriptor = os.open("journal.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 dir_fd=directory)
            _private(os.fstat(descriptor), 0o600)
            chunks, size = [], 0
            while size <= MAX_BYTES:
                chunk = os.read(descriptor, min(65536, MAX_BYTES + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            return _decode(b"".join(chunks))
        except FileNotFoundError:
            return None
        except StateError:
            raise
        except Exception:
            raise StateError("Rotation journal cannot be read safely.") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if directory is not None:
                os.close(directory)

    @contextmanager
    def operation(self):
        """Reuse this thread's lock across the existing multi-phase controller."""
        if self._directory_fd is not None:
            self._assert_locked()
            yield self
        else:
            with self.lock():
                yield self

    def history(self):
        """Read validated immutable audit records without creating storage."""
        directory = history = None
        try:
            directory = self._open_directory()
            history = os.open("history", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=directory)
            _private(os.fstat(history), 0o700, directory=True)
            records = []
            for name in sorted(os.listdir(history)):
                if not re.fullmatch(r"[0-9a-f]{32}\.json", name):
                    continue
                record = _decode(_read_file(history, name))
                if record["rotation_id"] + ".json" != name:
                    raise StateError("Rotation audit identity is inconsistent.")
                records.append(record)
            return records
        except FileNotFoundError:
            return []
        except StateError:
            raise
        except Exception:
            raise StateError("Rotation audit history cannot be read safely.") from None
        finally:
            if history is not None:
                os.close(history)
            if directory is not None:
                os.close(directory)

    def _assert_locked(self):
        if self._directory_fd is None or self._owner != (os.getpid(), threading.get_ident()):
            raise StateError("Saving rotation state requires the operation lock.")
        current = self._open_directory()
        try:
            expected, actual = os.fstat(self._directory_fd), os.fstat(current)
            if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
                raise StateError("Rotation storage changed during the operation.")
        finally:
            os.close(current)

    def save(self, state):
        """Publish validated metadata; fail closed if durability is uncertain.

        Failures before replacement leave the previous journal intact. A failed
        directory fsync after replacement is reported, never masked as success.
        """
        temporary = descriptor = None
        replaced = False
        try:
            self._assert_locked()
            validate_state(state)
            content = (json.dumps(state, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
            _decode(content)
            # Do not replace an unsafe or malformed previous journal.
            self.load()
            temporary = ".journal-" + uuid.uuid4().hex + ".tmp"
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=self._directory_fd)
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as destination:
                descriptor = None
                destination.write(content)
                destination.flush()
                os.fsync(destination.fileno())
            if _read_file(self._directory_fd, temporary) != content:
                raise StateError("Temporary rotation journal verification failed.")
            self._assert_locked()
            os.replace(temporary, "journal.json", src_dir_fd=self._directory_fd,
                       dst_dir_fd=self._directory_fd)
            replaced = True
            temporary = None
            os.fsync(self._directory_fd)
        except StateError:
            raise
        except Exception:
            message = ("Rotation journal durability is uncertain; reconcile before further changes."
                       if replaced else "Rotation journal could not be saved safely.")
            raise StateError(message) from None
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary is not None:
                try:
                    os.unlink(temporary, dir_fd=self._directory_fd)
                except OSError:
                    pass


    def archive_completed(self, state):
        """Keep a terminal journal immutable before a new rotation is prepared."""
        self._archive_record(state, {"COMMITTED", "ROLLED_BACK"})

    def archive_failed(self, state):
        """Preserve the failed audit unchanged; cleanup supplies fresh verification."""
        self._archive_record(state, {"PARTIAL_FAILURE", "RECOVERY_REQUIRED"})

    def _archive_record(self, state, allowed_phases):
        history = descriptor = temporary = None
        try:
            self._assert_locked()
            validate_state(state)
            content = (json.dumps(state, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
            _decode(content)
            if state["phase"] not in allowed_phases or self.load() != state:
                raise StateError("Only the matching rotation in an allowed phase can be archived.")
            try:
                os.mkdir("history", mode=0o700, dir_fd=self._directory_fd)
                os.fsync(self._directory_fd)
            except FileExistsError:
                pass
            history = os.open("history", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=self._directory_fd)
            _private(os.fstat(history), 0o700, directory=True)
            name = state["rotation_id"] + ".json"
            self._recover_archive_temporary(history, name)
            try:
                previous = _read_file(history, name)
            except FileNotFoundError:
                previous = None
            if previous is not None:
                if previous != content:
                    raise StateError("The completed rotation archive conflicts with this journal.")
                os.fsync(history)  # A retry must confirm prior publication durability.
                return
            temporary = ".archive-" + uuid.uuid4().hex + ".tmp"
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=history)
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as destination:
                descriptor = None
                destination.write(content)
                destination.flush()
                os.fsync(destination.fileno())
            if _read_file(history, temporary) != content:
                raise StateError("Temporary rotation archive verification failed.")
            self._assert_locked()
            # Atomic immutable publication: link never overwrites an existing name.
            os.link(temporary, name, src_dir_fd=history, dst_dir_fd=history,
                    follow_symlinks=False)
            os.unlink(temporary, dir_fd=history)
            temporary = None
            os.fsync(history)
        except StateError:
            raise
        except Exception:
            raise StateError("Completed rotation archive could not be saved durably.") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary is not None and history is not None:
                try:
                    os.unlink(temporary, dir_fd=history)
                except OSError:
                    pass
            if history is not None:
                os.close(history)


    def finish_completed(self, state):
        """Archive this terminal record before clearing its active journal slot."""
        self._assert_locked()
        self.archive_completed(state)
        self._clear_archived(state)

    def finish_failed(self, state):
        """Clear only after the cleanup caller verified Old and archived its items."""
        self._assert_locked()
        self.archive_failed(state)
        self._clear_archived(state)

    def _clear_archived(self, state):
        self._assert_locked()
        if self.load() != state:
            raise StateError("The completed rotation changed during cleanup.")
        try:
            os.unlink("journal.json", dir_fd=self._directory_fd)
            os.fsync(self._directory_fd)
        except OSError:
            raise StateError("Journal cleanup is uncertain; its history is preserved.") from None

    @staticmethod
    def _recover_archive_temporary(history, name):
        """Finish a publication interrupted between link and temporary unlink."""
        try:
            original = os.stat(name, dir_fd=history, follow_symlinks=False)
        except FileNotFoundError:
            return
        if original.st_nlink != 2 or not stat.S_ISREG(original.st_mode):
            return  # Normal strict file validation rejects other unsafe cases.
        if original.st_uid != os.geteuid() or stat.S_IMODE(original.st_mode) != 0o600:
            raise StateError("The completed rotation archive is unsafe.")
        candidates = []
        for entry in os.listdir(history):
            if re.fullmatch(r"\.archive-[0-9a-f]{32}\.tmp", entry):
                info = os.stat(entry, dir_fd=history, follow_symlinks=False)
                if (info.st_dev, info.st_ino) == (original.st_dev, original.st_ino):
                    candidates.append(entry)
        if len(candidates) == 1:
            os.unlink(candidates[0], dir_fd=history)
            os.fsync(history)

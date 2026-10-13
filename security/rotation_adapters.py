"""Secret-safe Vault operations and verified EOS admin password rotation.

1Password documents JSON stdin for item create/edit:
https://developer.1password.com/docs/cli/reference/management-commands/item/
Device writes reuse the verified isolated-lab Netmiko/SHA-512 method and
refuse to save unrelated pending configuration changes.
"""

from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, field
import ipaddress
import json
import re
import secrets

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from security import credential_provider


PENDING = "NetPilot-Pending"
PREVIOUS_PREFIX = "NetPilot-Previous-"
_ITEM_ID = re.compile(r"[a-z0-9]{26}\Z")
_ROTATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,95}\Z")
_MESSAGES = {
    "vault_read": "The credential store read failed.",
    "vault_write": "The credential store write could not be confirmed.",
    "vault_conflict": "Credential state conflicts with this rotation.",
    "credentials": "Rotation adapter input or response is invalid.",
    "authentication": "The device rejected authentication.",
    "unreachable": "Device access could not be confirmed.",
    "identity": "The expected Arista EOS device identity was not confirmed.",
    "privilege": "Required device privileges were not confirmed.",
    "blocked": "Live password changes require independently verified safety prerequisites.",
    "conflict": "Configuration changed unexpectedly or has unrelated pending changes.",
    "device_write": "The device password change or startup save could not be confirmed.",
    "verification": "Fresh authentication or exact configuration verification failed.",
}


_DETAIL_MESSAGES = {
    "original_password_unsupported": "The original password cannot be safely hashed for rollback; no device change was attempted.",
    "replacement_password_policy": "The replacement password does not meet the required input policy; no device change was attempted.",
    "password_hashing": "Local SHA-512 password hashing failed; check OpenSSL availability. No device change was attempted.",
}


class AdapterError(RuntimeError):
    def __init__(self, category, detail=None):
        self.category = category if category in _MESSAGES else "credentials"
        self.detail = detail if isinstance(detail, str) and detail in _DETAIL_MESSAGES else None
        super().__init__(_DETAIL_MESSAGES.get(self.detail, _MESSAGES[self.category]))


def adapter_error_detail(error):
    """Return only fixed, allowlisted diagnostics, never arbitrary exception text."""
    detail = getattr(error, "detail", None)
    return _DETAIL_MESSAGES.get(detail) if isinstance(detail, str) else None


@dataclass(frozen=True, repr=False)
class Credential:
    reference: str
    username: str
    password: str = field(repr=False)
    rotation_id: str | None = None
    current_reference: str | None = None

    def __repr__(self):
        return "<Credential redacted>"


def _same_pair(first, second):
    return (secrets.compare_digest(first.username.encode(), second.username.encode())
            and secrets.compare_digest(first.password.encode(), second.password.encode()))


def _rotation(value):
    if not isinstance(value, str) or not _ROTATION_ID.fullmatch(value):
        raise AdapterError("credentials")
    return value


def _reference(value):
    if not isinstance(value, str) or not _ITEM_ID.fullmatch(value):
        raise AdapterError("credentials")
    return value


class OnePasswordStore:
    """Use the existing provider's token/CLI boundary, never a second login path.

    Compare-before-write detects observed drift; the CLI does not offer an
    atomic cross-item transaction. The controller must retain its journal and
    reconcile ambiguous failures. Previous/Pending items are never deleted.
    """

    live_writes_supported = True

    @staticmethod
    def _json(arguments, payload=None):
        try:
            if payload is None:
                output = credential_provider._run_op(arguments)
            else:
                output = credential_provider._run_op(arguments, input_text=json.dumps(payload))
            return json.loads(output)
        except Exception:
            raise AdapterError("vault_read" if payload is None else "vault_write") from None

    def _named(self, title):
        rows = self._json(["item", "list", "--vault", credential_provider.VAULT, "--format", "json"])
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise AdapterError("credentials")
        found = [row for row in rows if row.get("title") == title]
        if len(found) > 1:
            raise AdapterError("vault_conflict")
        return _reference(found[0].get("id")) if found else None

    def _item(self, reference, *, include_archived=False):
        reference = _reference(reference)
        arguments = ["item", "get", reference, "--vault", credential_provider.VAULT,
                     "--format", "json", "--reveal"]
        if include_archived:
            arguments.append("--include-archive")
        item = self._json(arguments)
        if not isinstance(item, dict) or item.get("id") != reference:
            raise AdapterError("credentials")
        return item

    @staticmethod
    def _credential(item, expected_title=None):
        title = item.get("title")
        if (not isinstance(title, str) or (expected_title is not None and title != expected_title)
                or not isinstance(item.get("category"), str) or not item["category"]):
            raise AdapterError("credentials")
        if title not in (credential_provider.ITEM, PENDING):
            if not title.startswith(PREVIOUS_PREFIX):
                raise AdapterError("credentials")
            _rotation(title[len(PREVIOUS_PREFIX):])
        fields = item.get("fields")
        if not isinstance(fields, list) or any(not isinstance(field, dict) for field in fields):
            raise AdapterError("credentials")
        values = {}
        for key in ("username", "password", "netpilot_rotation_id", "netpilot_current_reference"):
            matches = [field for field in fields if field.get("id") == key or field.get("label") == key]
            if len(matches) > 1:
                raise AdapterError("vault_conflict")
            value = matches[0].get("value") if matches else None
            if key in ("username", "password") and (not isinstance(value, str) or not value.strip()):
                raise AdapterError("credentials")
            if value is not None and not isinstance(value, str):
                raise AdapterError("credentials")
            values[key] = value
        rotation = values["netpilot_rotation_id"]
        binding = values["netpilot_current_reference"]
        if rotation is not None:
            _rotation(rotation)
        if binding is not None:
            _reference(binding)
        return Credential(_reference(item.get("id")), values["username"], values["password"], rotation, binding)

    def read(self, reference, *, include_archived=False):
        if include_archived:
            return self._credential(self._item(reference, include_archived=True))
        return self._credential(self._item(reference))

    def read_current(self):
        reference = self._named(credential_provider.ITEM)
        if reference is None:
            raise AdapterError("vault_read")
        current = self._credential(self._item(reference), credential_provider.ITEM)
        try:
            username, password = credential_provider.get_credentials()
            consumer = Credential(reference, username, password)
            if not _same_pair(current, consumer):
                raise AdapterError("vault_conflict")
        except AdapterError:
            raise
        except Exception:
            raise AdapterError("vault_read") from None
        return current

    def find_pending(self):
        reference = self._named(PENDING)
        return self._credential(self._item(reference), PENDING) if reference else None

    def read_previous(self, rotation_id):
        title = PREVIOUS_PREFIX + _rotation(rotation_id)
        reference = self._named(title)
        return self._credential(self._item(reference), title) if reference else None

    @staticmethod
    def _set_field(item, label, value, field_type="STRING"):
        matches = [field for field in item["fields"] if field.get("id") == label or field.get("label") == label]
        if len(matches) > 1:
            raise AdapterError("vault_conflict")
        if matches:
            matches[0]["value"] = value
        else:
            item["fields"].append({"id": label, "label": label, "type": field_type, "value": value})

    @staticmethod
    def _require_owned(actual, expected):
        if (actual is None or (expected.reference and actual.reference != expected.reference)
                or not _same_pair(actual, expected)
                or actual.rotation_id != expected.rotation_id
                or actual.current_reference != expected.current_reference):
            raise AdapterError("vault_conflict")
        return actual

    def _create(self, title, expected):
        template = self._json(["item", "template", "get", "Login", "--format", "json"])
        if (not isinstance(template, dict) or not isinstance(template.get("fields"), list)
                or any(not isinstance(field, dict) for field in template["fields"])):
            raise AdapterError("credentials")
        template = deepcopy(template)
        template["title"] = title
        self._set_field(template, "username", expected.username)
        self._set_field(template, "password", expected.password, "CONCEALED")
        self._set_field(template, "netpilot_rotation_id", expected.rotation_id)
        self._set_field(template, "netpilot_current_reference", expected.current_reference)
        # '-' selects documented JSON stdin; no secret is an argv assignment.
        created = self._json(["item", "create", "-", "--vault", credential_provider.VAULT,
                              "--format", "json"], template)
        if not isinstance(created, dict):
            raise AdapterError("credentials")
        reference = _reference(created.get("id"))
        if self._named(title) != reference:
            raise AdapterError("vault_conflict")
        return self._require_owned(self._credential(self._item(reference), title), expected)

    def stage_pending(self, rotation_id, username, password, current_reference=None):
        _rotation(rotation_id)
        if not all(isinstance(value, str) and value.strip() for value in (username, password)):
            raise AdapterError("credentials")
        current = self.read_current()
        if current_reference is not None and current_reference != current.reference:
            raise AdapterError("vault_conflict")
        if username != current.username or secrets.compare_digest(password.encode(), current.password.encode()):
            raise AdapterError("vault_conflict")
        expected = Credential("", username, password, rotation_id, current.reference)
        pending = self.find_pending()
        if pending is not None:
            return self._require_owned(pending, expected)
        return self._create(PENDING, expected)

    def archive_current(self, rotation_id, current):
        rotation_id = _rotation(rotation_id)
        expected = Credential("", current.username, current.password, rotation_id, current.reference)
        previous = self.read_previous(rotation_id)
        if previous is not None:
            return self._require_owned(previous, expected)
        live = self.read_current()
        if live.reference != current.reference or not _same_pair(live, current):
            raise AdapterError("vault_conflict")
        return self._create(PREVIOUS_PREFIX + rotation_id, expected)

    def _replace_current(self, current, replacement):
        if self._named(credential_provider.ITEM) != current.reference:
            raise AdapterError("vault_conflict")
        item = self._item(current.reference)
        live = self._credential(item, credential_provider.ITEM)
        if not _same_pair(live, current):
            raise AdapterError("vault_conflict")
        # JSON template edits cannot preserve passkeys; reject instead of dropping them.
        if item.get("files") or item.get("passkeys") or any(
                "passkey" in str(field.get("type", "")).lower() for field in item["fields"]):
            raise AdapterError("blocked")
        edited = deepcopy(item)
        self._set_field(edited, "username", replacement.username)
        self._set_field(edited, "password", replacement.password, "CONCEALED")
        self._set_field(edited, "netpilot_rotation_id", replacement.rotation_id)
        self._set_field(edited, "netpilot_current_reference", current.reference)
        self._json(["item", "edit", current.reference, "--vault", credential_provider.VAULT,
                    "--format", "json"], edited)
        updated = self.read_current()
        if updated.reference != current.reference or not _same_pair(updated, replacement):
            raise AdapterError("vault_conflict")
        return updated

    def promote(self, current, pending):
        _rotation(pending.rotation_id)
        if pending.current_reference != current.reference:
            raise AdapterError("vault_conflict")
        self._require_owned(self.find_pending(), pending)
        previous = self.read_previous(pending.rotation_id)
        if (previous is None or previous.rotation_id != pending.rotation_id
                or previous.current_reference != current.reference or not _same_pair(previous, current)):
            raise AdapterError("vault_conflict")
        live = self.read_current()
        if live.reference == current.reference and _same_pair(live, pending):
            return live
        return self._replace_current(current, pending)

    def restore_current(self, current, previous):
        _rotation(previous.rotation_id)
        self._require_owned(self.read_previous(previous.rotation_id), previous)
        if previous.current_reference != current.reference:
            raise AdapterError("vault_conflict")
        live = self.read_current()
        if live.reference == current.reference and _same_pair(live, previous):
            return live
        return self._replace_current(current, previous)


class NetmikoDeviceAdapter:
    """Verified admin-only writes for the isolated NetPilot Containerlab.

    The controller supplies NSOT addresses and durable write intent. Recovery
    login was independently verified by the operator; verify_recovery checks
    its configured privileges, never claims a fresh recovery-password login.
    """

    live_writes_supported = True

    def __init__(self):
        self._authenticated = {}  # Credentials stay in RAM only.

    @staticmethod
    def blockers():
        return []

    @staticmethod
    def _admin_command(config):
        # Local imports avoid the existing rotation/recovery import cycle.
        from security.test_r1_admin_rotation import _admin_command
        try:
            return _admin_command(config)
        except Exception as error:
            category = "privilege" if getattr(error, "category", None) == "privilege" else "credentials"
            raise AdapterError(category) from None

    @contextmanager
    def _session(self, name, management_ip, credential):
        from security import setup_recovery_accounts as recovery
        from security.rotation_state import FLEET
        connection = None
        with recovery.quiet_transport():
            try:
                if name not in FLEET or credential.username != "admin" or not credential.password:
                    raise AdapterError("credentials")
                host = str(ipaddress.IPv4Address(management_ip))
                # Match the already-tested policy for this isolated lab only.
                connection = ConnectHandler(
                    device_type="arista_eos", host=host, username=credential.username,
                    password=credential.password, ssh_strict=False, system_host_keys=False,
                    use_keys=False, allow_agent=False, session_log=None,
                    session_log_record_writes=False, conn_timeout=10, auth_timeout=15,
                    banner_timeout=15, fast_cli=False,
                )
                try:
                    recovery._ensure_privileged(connection)
                except recovery.RecoveryError:
                    raise AdapterError("privilege") from None
                try:
                    version = json.loads(connection.send_command("show version | json", read_timeout=20))
                    hostname = json.loads(connection.send_command("show hostname | json", read_timeout=20))
                    if (not isinstance(version, dict) or not isinstance(hostname, dict)
                            or hostname.get("hostname") != name
                            or not isinstance(version.get("version"), str) or not version["version"]
                            or str(version.get("modelName", "")).lower() != "ceoslab"):
                        raise ValueError
                except (ValueError, TypeError):
                    raise AdapterError("identity") from None
                running = recovery.normalize_config(
                    connection.send_command("show running-config", read_timeout=30), name)
                self._admin_command(running)
                yield connection
                self._authenticated[(name, host)] = credential
            except AdapterError:
                raise
            except NetmikoAuthenticationException:
                raise AdapterError("authentication") from None
            except (NetmikoTimeoutException, OSError):
                raise AdapterError("unreachable") from None
            except Exception:
                raise AdapterError("unreachable" if connection is None else "verification") from None
            finally:
                recovery._disconnect(connection)

    def authenticate(self, name, management_ip, credential):
        with self._session(name, management_ip, credential):
            pass

    def verify_recovery(self, name, management_ip, target_username):
        from security import setup_recovery_accounts as recovery
        credential = self._authenticated.get((name, str(management_ip)))
        if target_username != "admin" or credential is None:
            return False
        with self._session(name, management_ip, credential) as connection:
            running, _ = recovery.read_configs(connection, name)
            records = recovery.recovery_account(running)
            return any(re.search(r"\bprivilege 15(?:\s|$)", line)
                       and re.search(r"\brole network-admin(?:\s|$)", line) for line in records)

    @staticmethod
    def _save_verified(connection, name, expected, startup):
        from security import setup_recovery_accounts as recovery
        if recovery.read_configs(connection, name) != (expected, startup):
            raise AdapterError("conflict")
        if expected != startup:
            try:
                recovery.checked_response(connection.save_config())
            except Exception:
                raise AdapterError("device_write") from None
        if recovery.read_configs(connection, name) != (expected, expected):
            raise AdapterError("verification")

    def ensure_verified(self, name, management_ip, credential):
        """Reconcile journal-owned writes; save only an isolated admin hash diff."""
        from security import setup_recovery_accounts as recovery
        with self._session(name, management_ip, credential) as connection:
            running, startup = recovery.read_configs(connection, name)
            current = self._admin_command(running)
            prior = self._admin_command(startup)
            if (current.rsplit(" secret sha512 ", 1)[0] != prior.rsplit(" secret sha512 ", 1)[0]
                    or tuple(prior if line == current else line for line in running) != startup):
                raise AdapterError("conflict")
            self._save_verified(connection, name, running, startup)

    def change_password(self, name, management_ip, auth_credential, new_credential, *, restore=False):
        from security import setup_recovery_accounts as recovery
        from security.test_r1_password_change import _send
        if auth_credential.username != "admin" or new_credential.username != "admin":
            raise AdapterError("credentials")
        # Existing admin credentials need to be safely restorable, not satisfy
        # the policy for newly generated passwords. Rollback alone may reuse them.
        try:
            recovery.validate_password(auth_credential.password, allow_legacy=True)
        except recovery.RecoveryError:
            raise AdapterError("credentials", "original_password_unsupported") from None
        try:
            recovery.validate_password(new_credential.password, allow_legacy=restore)
            new_hash = recovery.sha512_crypt(new_credential.password, allow_legacy=restore)
        except recovery.RecoveryError as error:
            if error.category == "password_input":
                raise AdapterError("credentials", "replacement_password_policy") from None
            raise AdapterError("device_write", "password_hashing") from None
        with self._session(name, management_ip, auth_credential) as connection:
            running, startup = recovery.read_configs(connection, name)
            if running != startup:
                raise AdapterError("conflict")
            old_command = self._admin_command(running)
            new_command = (old_command.rsplit(" secret sha512 ", 1)[0]
                           + " secret sha512 " + new_hash)
            if recovery.read_configs(connection, name) != (running, startup):
                raise AdapterError("conflict")
            try:
                _send(connection, new_command)
            except Exception:
                raise AdapterError("device_write") from None
            expected = tuple(new_command if line == old_command else line for line in running)
            with self._session(name, management_ip, new_credential) as fresh:
                if recovery.read_configs(fresh, name) != (expected, startup):
                    raise AdapterError("verification")
                self._save_verified(fresh, name, expected, startup)
        # The outer session authenticated using the old password before mutation.
        self._authenticated[(name, str(management_ip))] = new_credential

"""Explicitly approved synthetic Vault write/readback test; default is offline.

Uses the rotation adapter's authenticated JSON-stdin boundary. No device access,
production credential reads, secret files, or automatic cleanup.
"""

import argparse
from copy import deepcopy
from pathlib import Path
import secrets
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from security import credential_provider
from security.rotation_adapters import AdapterError, OnePasswordStore

TITLE = "NetPilot-Vault-Write-Test"
USERNAME = "netpilot-synthetic-test"
CONFIRMATION = "WRITE " + TITLE
OVERWRITE_CONFIRMATION = "OVERWRITE " + TITLE


def _fields(item):
    fields = item.get("fields")
    if not isinstance(fields, list) or any(not isinstance(field, dict) for field in fields):
        raise AdapterError("credentials")
    selected = []
    for label in ("username", "password"):
        matches = [field for field in fields if field.get("id") == label or field.get("label") == label]
        if len(matches) != 1 or not isinstance(matches[0].get("value", ""), str):
            raise AdapterError("credentials")
        selected.append(matches[0])
    if selected[0] is selected[1] or selected[1].get("type") != "CONCEALED":
        raise AdapterError("credentials")
    return selected


def _read_test_item(store, reference):
    # Bind every read/edit to the discovered ID and fixed title, never Current/Pending.
    if store._named(TITLE) != reference:
        raise AdapterError("vault_conflict")
    item = store._item(reference)
    if item.get("title") != TITLE or item.get("category") != "LOGIN":
        raise AdapterError("vault_conflict")
    _fields(item)
    return item


def _payload(store, item, password):
    _fields(item)
    # JSON template edits cannot safely preserve passkeys or attachments.
    if item.get("files") or item.get("passkeys") or any(
            "passkey" in str(field.get("type", "")).lower() for field in item["fields"]):
        raise AdapterError("blocked")
    payload = deepcopy(item)
    payload["title"] = TITLE
    store._set_field(payload, "username", USERNAME)
    store._set_field(payload, "password", password, "CONCEALED")
    return payload


def _edit(store, original, password):
    reference = original["id"]
    payload = _payload(store, original, password)
    if _read_test_item(store, reference) != original:
        raise AdapterError("vault_conflict")
    # Documented piped JSON input; no plaintext argv assignments or file fallback.
    store._json(["item", "edit", reference, "--vault", credential_provider.VAULT,
                 "--format", "json"], payload)


def _verify(store, reference, password):
    # A separate CLI get, not the create/edit response, supplies verification evidence.
    item = _read_test_item(store, reference)
    username_field, password_field = _fields(item)
    if (username_field.get("value") != USERNAME
            or not secrets.compare_digest(password_field.get("value", "").encode(), password.encode())):
        raise AdapterError("vault_conflict")
    return item


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="Require interactive approval for real Vault writes.")
    parser.add_argument("--dry-run", action="store_true", help="Offline only; no Vault/token operations.")
    parser.add_argument("--overwrite-existing", action="store_true",
                        help="Permit a second prompt to overwrite this test item only.")
    args = parser.parse_args(argv)
    stage = "authorization"
    try:
        if (args.execute and args.dry_run) or (args.overwrite_existing and not args.execute):
            raise AdapterError("blocked")
        if not args.execute:
            print("PASS | offline plan | no Vault operations performed")
            return 0
        if not sys.stdin.isatty():
            raise AdapterError("blocked")
        if input(f"Type {CONFIRMATION} to write synthetic credentials in NetPilot-Secrets: ") != CONFIRMATION:
            raise AdapterError("blocked")
        store = OnePasswordStore()
        if credential_provider.VAULT != "NetPilot-Secrets" or store.live_writes_supported is not True:
            raise AdapterError("blocked")
        stage = "test item lookup"
        reference = store._named(TITLE)
        original = None
        if reference is not None:
            stage = "existing item approval (--overwrite-existing required)"
            if not args.overwrite_existing:
                raise AdapterError("blocked")
            original = _read_test_item(store, reference)
            if input(f"Type {OVERWRITE_CONFIRMATION} to replace this test item's credentials (ID {reference}): ") != OVERWRITE_CONFIRMATION:
                raise AdapterError("blocked")
        stage = "synthetic credential generation"
        first = secrets.token_urlsafe(32)
        second = secrets.token_urlsafe(32)
        if secrets.compare_digest(first, second):
            raise AdapterError("credentials")
        stage = "initial test credential write"
        if original is None:
            template = store._json(["item", "template", "get", "Login", "--format", "json"])
            if not isinstance(template, dict) or template.get("category") != "LOGIN":
                raise AdapterError("credentials")
            payload = _payload(store, template, first)
            if store._named(TITLE) is not None:
                raise AdapterError("vault_conflict")
            # 1Password documents '-' for item-create JSON stdin.
            created = store._json(["item", "create", "-", "--vault", credential_provider.VAULT,
                                   "--format", "json"], payload)
            if not isinstance(created, dict):
                raise AdapterError("credentials")
            reference = created.get("id")
        else:
            _edit(store, original, first)
        stage = "initial independent readback"
        verified = _verify(store, reference, first)
        print("PASS | initial write and independent readback")
        stage = "test credential update"
        _edit(store, verified, second)
        stage = "updated independent readback"
        _verify(store, reference, second)
        print("PASS | update and independent readback")
        print("PASS | test item retained; no automatic cleanup")
        return 0
    except (KeyboardInterrupt, EOFError):
        print(f"FAIL | {stage} | interrupted; inspect the test item before retrying")
        return 130
    except Exception as error:
        category = error.category if isinstance(error, AdapterError) else "operation_failed"
        print(f"FAIL | {stage} | {category}; no further operations")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

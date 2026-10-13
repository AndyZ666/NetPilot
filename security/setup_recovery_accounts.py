"""Set up the eight remaining EOS recovery accounts; default is offline planning.

No imports contact Vault/devices. R1 is excluded from every connection path.
Run with ``python3 -m security.setup_recovery_accounts --dry-run``.
"""

import argparse
from contextlib import contextmanager
import fcntl
import getpass
import json
import logging
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import warnings

# Permit both `python -m security.setup_recovery_accounts` and direct script use.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netmiko import ConnectHandler
from security import credential_provider
from security.credential_rotation import INVENTORY, discover_inventory

TARGETS = ("R2", "R3", "R4", "R5", "S1", "S2", "S3", "S4")
USERNAME = "netpilot-recovery"
CONFIRMATION = "CONFIGURE EIGHT RECOVERY ACCOUNTS"
_HASH = r"\$6\$(?:rounds=[0-9]+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}"
_ERRORS = re.compile(r"(?im)^\s*(?:%.*(?:invalid|error|failed|denied|incomplete|ambiguous)|error:|permission denied|authorization failed)")
_CATEGORIES = frozenset({"inventory", "authorization", "credentials", "password_input", "hashing",
                        "connection", "identity", "privilege",
                        "enable_failed", "enable_mode", "privilege_read",
                        "configuration", "account_conflict", "unsaved_changes", "concurrent_change",
                        "apply", "verification", "save", "interrupted", "locked"})

_ERROR_DETAILS = {
    "enable_failed": "Could not enter Privileged EXEC; check EOS enable authentication and authorization.",
    "enable_mode": "The enable request returned, but the session is still not in Privileged EXEC.",
    "privilege_read": "Could not read a valid session privilege level after entering Privileged EXEC.",
    "privilege": "The session reports a privilege level other than the required 15 after enable-mode checks.",
}


class RecoveryError(RuntimeError):
    def __init__(self, category):
        self.category = category if category in _CATEGORIES else "verification"
        super().__init__("Recovery setup stopped: " + self.category + ".")


def discover_targets(inventory_path=INVENTORY):
    """Reuse strict NetPilot discovery, retaining neither a second NSOT nor R1."""
    try:
        inventory = discover_inventory(inventory_path)
        return {name: inventory[name] for name in TARGETS}
    except Exception:
        raise RecoveryError("inventory") from None


def validate_password(password, *, allow_legacy=False):
    """Keep new passwords strong; allow safe existing values for rollback only."""
    minimum = 1 if allow_legacy else 16
    if (not isinstance(password, str) or not minimum <= len(password.encode("utf-8")) <= 128
            or not password.isprintable()):
        raise RecoveryError("password_input")


def sha512_crypt(password, *, allow_legacy=False):
    """OpenSSL generates the random salt; plaintext is supplied only over stdin."""
    validate_password(password, allow_legacy=allow_legacy)
    executable = shutil.which("openssl")
    if executable is None:
        raise RecoveryError("hashing")
    try:
        response = subprocess.run([executable, "passwd", "-6", "-stdin"],
                                  input=password + "\n", text=True, encoding="utf-8",
                                  capture_output=True, check=True, timeout=15, shell=False)
        digest = response.stdout.rstrip("\r\n")
        if not re.fullmatch(_HASH, digest):
            raise ValueError
        return digest
    except Exception:
        raise RecoveryError("hashing") from None


@contextmanager
def quiet_transport():
    """Netmiko DEBUG logs can include full configurations and command echoes."""
    previous = logging.root.manager.disable
    logging.disable(sys.maxsize)
    try:
        yield
    finally:
        logging.disable(previous)


@contextmanager
def configuration_lock():
    """One setup process per script checkout; no local state/secret file needed."""
    try:
        handle = open(__file__, "rb")
    except OSError:
        raise RecoveryError("locked") from None
    try:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise RecoveryError("locked") from None
        yield
    finally:
        handle.close()


def checked_response(response):
    if not isinstance(response, str) or _ERRORS.search(response):
        raise RecoveryError("configuration")
    return response


def normalize_config(text, hostname):
    """Strip only known volatile EOS header lines; preserve the actual body."""
    checked_response(text)
    output = []
    header = True
    for line in text.replace("\r\n", "\n").splitlines():
        if header and re.fullmatch(
                r"! (?:Command: show (?:running|startup)-config|Startup-config last modified at .+|Last configuration change at .+)", line):
            continue
        if line and not line.startswith("!"):
            header = False
        if re.match(r"\s*(?:banner|comment)(?:\s|$)", line):
            # Never mistake literal text in a multi-line body for an account.
            raise RecoveryError("configuration")
        output.append(line)
    while output and not output[0]:
        output.pop(0)
    while output and not output[-1]:
        output.pop()
    if output.count("hostname " + hostname) != 1 or not output or output[-1] != "end":
        raise RecoveryError("configuration")
    return tuple(output)


def recovery_account(config):
    """Detect and preserve existing account records without imposing a hash format."""
    return tuple(line for line in config if re.match(r"username netpilot-recovery(?:\s|$)", line))


def without_recovery(config):
    return tuple(line for line in config if not re.match(r"username netpilot-recovery(?:\s|$)", line))


def read_configs(connection, name):
    return tuple(normalize_config(connection.send_command(command, read_timeout=30), name)
                 for command in ("show running-config", "show startup-config"))


def _disconnect(connection):
    if connection is not None:
        try:
            connection.disconnect()
        except Exception:
            pass


def _ensure_privileged(connection):
    """EOS SSH can start in User EXEC even for an account configured at level 15."""
    try:
        if not connection.check_enable_mode():
            connection.enable()
        enabled = connection.check_enable_mode()
    except Exception:
        raise RecoveryError("enable_failed") from None
    if not enabled:
        raise RecoveryError("enable_mode")
    # A '#' prompt selects the mode; it is not proof of account authorization.
    try:
        privilege = checked_response(connection.send_command("show privilege", read_timeout=20))
    except Exception:
        raise RecoveryError("privilege_read") from None
    match = re.fullmatch(r"\s*Current privilege level is ([0-9]+)\s*", privilege)
    if match is None:
        raise RecoveryError("privilege_read")
    if match.group(1) != "15":
        raise RecoveryError("privilege")


def _connect(name, address, username, password):
    if name not in TARGETS:
        raise RecoveryError("inventory")
    connection = None
    try:
        # Isolated lab only: match test_all_vault.py host-key defaults.
        # Fresh hostname/platform checks still validate the expected lab target.
        connection = ConnectHandler(
            device_type="arista_eos", host=address, username=username, password=password,
            ssh_strict=False, system_host_keys=False, use_keys=False, allow_agent=False,
            session_log=None, session_log_record_writes=False, conn_timeout=10,
            auth_timeout=15, banner_timeout=15, fast_cli=False,
        )
        _ensure_privileged(connection)
        identity = json.loads(connection.send_command("show hostname | json", read_timeout=20))
        version = json.loads(connection.send_command("show version | json", read_timeout=20))
        if (not isinstance(identity, dict) or identity.get("hostname") != name
                or not isinstance(version, dict) or str(version.get("modelName", "")).lower() != "ceoslab"
                or not isinstance(version.get("version"), str) or not version["version"]):
            raise RecoveryError("identity")
        return connection
    except BaseException:
        _disconnect(connection)
        raise


def _fresh_verification(name, address, password):
    connection = None
    try:
        connection = _connect(name, address, USERNAME, password)
        running, startup = read_configs(connection, name)
        if not recovery_account(running):
            raise RecoveryError("verification")
        return running, startup
    finally:
        _disconnect(connection)


def _configure_device(name, address, password, admin):
    result = {"device": name, "status": "FAIL", "stage": "connection", "changed": False,
              "saved": None, "error": None}
    connection = None
    try:
        connection = _connect(name, address, *admin)
        result["stage"] = "precheck"
        running, startup = read_configs(connection, name)
        original_account = recovery_account(running)
        startup_account = recovery_account(startup)
        result["saved"] = bool(original_account) and original_account == startup_account
        if original_account:
            # Test existing credentials first; never reset or replace the account.
            result["stage"] = "verification"
            verified, verified_startup = _fresh_verification(name, address, password)
        result["stage"] = "precheck"
        if without_recovery(running) != without_recovery(startup):
            raise RecoveryError("unsaved_changes")
        # Do not persist an out-of-band replacement/deletion of a saved account.
        if startup_account and original_account != startup_account:
            raise RecoveryError("account_conflict")
        intended_account = original_account
        if not original_account:
            result["stage"] = "apply"
            digest = sha512_crypt(password)
            intended_account = (
                f"username {USERNAME} privilege 15 role network-admin secret sha512 {digest}",)
            # Recheck immediately before submission, including every unrelated line.
            if read_configs(connection, name) != (running, startup):
                raise RecoveryError("concurrent_change")
            result["changed"] = None  # An ambiguous timeout must never be called success.
            response = connection.send_config_set(list(intended_account), read_timeout=30,
                                                   cmd_verify=True, error_pattern=_ERRORS.pattern)
            checked_response(response)
            result["stage"] = "verification"
            verified, verified_startup = _fresh_verification(name, address, password)
        if (recovery_account(verified) != intended_account
                or without_recovery(verified) != without_recovery(running) or verified_startup != startup):
            result["saved"] = None
            raise RecoveryError("concurrent_change")
        result["changed"] = not original_account
        result["stage"] = "presave"
        current, current_startup = read_configs(connection, name)
        if current != verified or current_startup != startup:
            result["saved"] = None
            raise RecoveryError("concurrent_change")
        if current != current_startup:
            result["stage"] = "save"
            result["saved"] = None
            checked_response(connection.save_config())
            result["stage"] = "persistence"
            final_running, final_startup = read_configs(connection, name)
            if final_running != verified or final_startup != verified:
                raise RecoveryError("save")
        result.update(status="PASS", stage="verified_and_saved", saved=True)
    except (Exception, KeyboardInterrupt) as error:
        category = error.category if isinstance(error, RecoveryError) else (
            "interrupted" if isinstance(error, KeyboardInterrupt) else
            {"connection": "connection", "apply": "apply", "save": "save", "persistence": "save"}.get(result["stage"], "verification"))
        result["error"] = category
        if result["changed"] is None:
            result["saved"] = None
    finally:
        _disconnect(connection)
    return result


def _check_targets(inventory):
    expected = discover_targets()
    if inventory != expected or tuple(inventory) != TARGETS:
        raise RecoveryError("inventory")


def configure_all(inventory, password, authorized=False, confirmation=""):
    if authorized is not True or confirmation != CONFIRMATION:
        raise RecoveryError("authorization")
    validate_password(password)
    _check_targets(inventory)
    results = []
    with configuration_lock(), quiet_transport():
        try:
            admin = credential_provider.get_credentials()
            if (not isinstance(admin, tuple) or len(admin) != 2 or admin[0] != "admin"
                    or not isinstance(admin[1], str) or not admin[1]
                    or secrets.compare_digest(password.encode(), admin[1].encode())):
                raise RecoveryError("credentials")
        except Exception:
            raise RecoveryError("credentials") from None
        stopped = False
        for name, address in inventory.items():
            if stopped:
                results.append({"device": name, "status": "SKIP", "stage": "not_attempted",
                                "changed": False, "saved": None, "error": None})
                continue
            # Reject an inventory edit during execution before the next device.
            try:
                _check_targets(inventory)
                result = _configure_device(name, address, password, admin)
            except (Exception, KeyboardInterrupt) as error:
                result = {"device": name, "status": "FAIL", "stage": "precheck", "changed": False,
                          "saved": None, "error": "interrupted" if isinstance(error, KeyboardInterrupt) else "inventory"}
            results.append(result)
            print_result(result)
            stopped = result["status"] != "PASS"
    return results


def verify_all(inventory, password):
    validate_password(password)
    _check_targets(inventory)
    results = []
    stopped = False
    with quiet_transport():
        for name, address in inventory.items():
            result = {"device": name, "status": "SKIP", "stage": "not_attempted", "changed": False,
                      "saved": None, "error": None}
            if not stopped:
                result.update(status="FAIL", stage="verification")
                try:
                    _check_targets(inventory)
                    running, startup = _fresh_verification(name, address, password)
                    if recovery_account(running) != recovery_account(startup):
                        raise RecoveryError("save")
                    result.update(status="PASS", stage="verified_and_saved", saved=True)
                except (Exception, KeyboardInterrupt) as error:
                    result["error"] = error.category if isinstance(error, RecoveryError) else (
                        "interrupted" if isinstance(error, KeyboardInterrupt) else "verification")
                stopped = result["status"] != "PASS"
                print_result(result)
            results.append(result)
    return results


def print_result(result):
    saved = {True: "YES", False: "NO", None: "UNKNOWN"}[result["saved"]]
    changed = {True: "YES", False: "NO", None: "UNKNOWN"}[result["changed"]]
    print(f"{result['device']}: {result['status']} | {result['stage']} | changed={changed} | saved={saved}"
          + (f" | error={result['error']}" if result["error"] else "")
          + (" | " + _ERROR_DETAILS[result["error"]] if result["error"] in _ERROR_DETAILS else ""))


def prompt_password(confirm=False):
    if not sys.stdin.isatty():
        raise RecoveryError("password_input")
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        password = getpass.getpass("Recovery password from your Personal Vault (hidden): ")
        validate_password(password)
        if confirm:
            repeated = getpass.getpass("Confirm recovery password (hidden): ")
            if not secrets.compare_digest(password.encode(), repeated.encode()):
                raise RecoveryError("password_input")
    return password


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", default="plan", choices=("plan", "configure", "verify"))
    parser.add_argument("--dry-run", action="store_true", help="Offline discovery/plan; no credentials or connections.")
    parser.add_argument("--execute", action="store_true", help="Configure only, with exact interactive confirmation.")
    args = parser.parse_args(argv)
    try:
        if args.execute and (args.action != "configure" or args.dry_run):
            raise RecoveryError("authorization")
        inventory = discover_targets()
        if args.dry_run or args.action == "plan":
            print("OFFLINE PLAN: R1 excluded. No credentials read, devices contacted, or files changed.")
            for name, address in inventory.items():
                print(f"{name} ({address}): verify existing account or create {USERNAME}; fresh SSH verification; guarded save.")
            print("Save gate: no unrelated running/startup differences, then recheck immediately before save.")
            print("Requires an isolated lab, an exclusive configuration window, admin Vault access and OpenSSL.")
            return 0
        if args.action == "configure":
            if not args.execute or not sys.stdin.isatty():
                raise RecoveryError("authorization")
            print("Confirm an exclusive maintenance window: no other configuration writers may run until completion.")
            print("Only R2 R3 R4 R5 S1 S2 S3 S4 are targeted. Existing accounts are verified, never overwritten.")
            confirmation = input("Type exactly " + CONFIRMATION + " to approve the changes and guarded startup saves: ")
            if confirmation != CONFIRMATION:
                raise RecoveryError("authorization")
            results = configure_all(inventory, prompt_password(confirm=True), True, confirmation)
        else:
            results = verify_all(inventory, prompt_password())
        print("SUMMARY (R1 not contacted)")
        for result in results:
            print_result(result)
        passed = sum(row["status"] == "PASS" for row in results)
        print(f"PASS={passed} FAIL={sum(row['status'] == 'FAIL' for row in results)} SKIP={sum(row['status'] == 'SKIP' for row in results)}")
        if passed != len(TARGETS):
            print("Stopped. No automatic rollback or deletion. Review the failed device before retrying; UNKNOWN is not a successful save.")
        return 0 if passed == len(TARGETS) else 1
    except (KeyboardInterrupt, EOFError):
        print("FAIL: interrupted; any submitted device change requires inspection.")
        return 130
    except Exception as error:
        category = error.category if isinstance(error, RecoveryError) else "verification"
        print("FAIL: " + category + ". No further devices processed."
              + (" " + _ERROR_DETAILS[category] if category in _ERROR_DETAILS else ""))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

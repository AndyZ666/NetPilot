"""R1-only temporary password change/rollback test; --execute authorizes live changes.

No Vault writes, startup saves, secret files, or changes to existing accounts.
"""

import argparse
import json
from pathlib import Path
import re
import secrets
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netmiko import ConnectHandler
from security import credential_provider
from security import setup_recovery_accounts as recovery

HOST = "172.20.20.13"
USERNAME = "netpilot-rotation-test"


def _connect(username, password):
    connection = None
    try:
        # Relaxed host-key validation is for this isolated Containerlab only.
        connection = ConnectHandler(
            device_type="arista_eos", host=HOST, username=username, password=password,
            ssh_strict=False, system_host_keys=False, use_keys=False, allow_agent=False,
            session_log=None, session_log_record_writes=False, conn_timeout=10,
            auth_timeout=15, banner_timeout=15, fast_cli=False,
        )
        recovery._ensure_privileged(connection)
        identity = json.loads(connection.send_command("show hostname | json", read_timeout=20))
        if identity.get("hostname") != "R1":
            raise ValueError("Unexpected device")
        return connection
    except BaseException:
        recovery._disconnect(connection)
        raise


def _account(config):
    return tuple(line for line in config if re.match(r"username " + USERNAME + r"(?:\s|$)", line))


def _send(connection, command):
    recovery.checked_response(connection.send_config_set(
        [command], read_timeout=30, cmd_verify=True, error_pattern=recovery._ERRORS.pattern))


def _verify_password(password):
    connection = None
    try:
        connection = _connect(USERNAME, password)
    finally:
        recovery._disconnect(connection)


def _cleanup(admin, original, owned_accounts):
    connection = None
    try:
        # Fresh admin SSH also handles an earlier timeout leaving the old session unusable.
        connection = _connect(*admin)
        running, startup = recovery.read_configs(connection, "R1")
        account = _account(running)
        if account:
            # Never delete an account whose contents no longer belong to this run.
            if account not in tuple((command,) for command in owned_accounts):
                raise ValueError("Test account changed unexpectedly")
            _send(connection, "no username " + USERNAME)
        running, startup = recovery.read_configs(connection, "R1")
        if _account(running) or _account(startup):
            raise ValueError("Removal not verified")
        print("PASS | temporary account removal verified")
        if (running, startup) != original:
            print("FAIL | original configuration comparison | unrelated changes detected")
            return False
        print("PASS | original running and startup configurations preserved")
        return True
    except (Exception, KeyboardInterrupt):
        print("FAIL | cleanup incomplete | netpilot-rotation-test may remain on R1; inspect before retrying")
        return False
    finally:
        recovery._disconnect(connection)


def _run():
    connection = None
    attempted = False
    result = 0
    stage = "admin credentials"
    try:
        admin = credential_provider.get_credentials()
        if admin[0] != "admin":
            raise ValueError("Expected admin credentials")
        stage = "admin SSH and privileged access"
        connection = _connect(*admin)
        stage = "test account absence in running and startup configurations"
        original = recovery.read_configs(connection, "R1")
        if any(_account(config) for config in original):
            print("FAIL | test account already exists | left unchanged")
            return 1
        print("PASS | R1 privileged access; temporary account absent")
        stage = "synthetic password generation and hashing"
        first, second = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        if secrets.compare_digest(first, second):
            raise ValueError("Passwords must differ")
        first_hash, second_hash = recovery.sha512_crypt(first), recovery.sha512_crypt(second)
        owned_accounts = tuple(
            f"username {USERNAME} privilege 15 role network-admin secret sha512 {digest}"
            for digest in (first_hash, second_hash))
        stage = "pre-change configuration check"
        if recovery.read_configs(connection, "R1") != original:
            raise ValueError("Configuration changed before test")
        stage = "temporary account creation"
        attempted = True  # Includes a command timeout after EOS may have applied it.
        _send(connection, owned_accounts[0])
        stage = "initial password fresh SSH verification"
        _verify_password(first)
        print("PASS | initial password fresh SSH and privileged access")
        stage = "test account password update"
        _send(connection, owned_accounts[1])
        stage = "updated password fresh SSH verification"
        _verify_password(second)
        print("PASS | updated password fresh SSH and privileged access")
        stage = "original test password restoration"
        _send(connection, owned_accounts[0])
        stage = "rollback password fresh SSH verification"
        _verify_password(first)
        print("PASS | rollback password fresh SSH and privileged access")
    except (Exception, KeyboardInterrupt) as error:
        print(f"FAIL | {stage}")
        result = 130 if isinstance(error, KeyboardInterrupt) else 1
    finally:
        recovery._disconnect(connection)
        if attempted and not _cleanup(admin, original, owned_accounts):
            result = result or 1
    print(("PASS" if result == 0 else "FAIL") + " | R1 password change/rollback test")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="Offline preview; no credentials or connections.")
    mode.add_argument("--execute", action="store_true", help="Run the live R1 test without further prompts.")
    args = parser.parse_args(argv)
    if args.dry_run:
        print("PASS | offline preview | R1 (172.20.20.13) only; no Vault or device access")
        print("PASS | plan | create test account -> verify -> change -> verify -> restore -> verify -> remove")
        print("PASS | plan | no startup saves; existing admin and recovery accounts preserved")
        return 0
    with recovery.quiet_transport():
        return _run()


if __name__ == "__main__":
    raise SystemExit(main())

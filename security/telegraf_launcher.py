#!/usr/bin/env python3
"""Start the existing collector with fresh credentials; --check is read-only.

No import-time secret access. The live collector is never stopped by this module.
"""

import argparse
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import shutil
import stat
import sys
import tomllib

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from security import credential_provider


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "telegraf" / "telegraf-gnmi-influx.conf"
TELEGRAF = Path("/usr/bin/telegraf")
PROC = Path("/proc")
MAX_SECRET_BYTES = 65536


class LauncherError(RuntimeError):
    """Only fixed, secret-free diagnostics may cross the CLI boundary."""


def report(message):
    print(message, flush=True)


def private_file(path):
    """Check metadata only; never read the existing 1Password token in preflight."""
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise LauncherError("Credential file must be private, regular, owned by this user, and not a symlink.")
    except OSError:
        raise LauncherError("Required credential file is unavailable.") from None


def read_influx_file(path):
    """Read the systemd-supplied credential without following a symlink."""
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise LauncherError("Influx credential file has unsafe ownership, type, or permissions.")
        raw = os.read(descriptor, MAX_SECRET_BYTES + 1)
        if len(raw) > MAX_SECRET_BYTES:
            raise LauncherError("Influx credential file is invalid.")
        return raw.decode("utf-8").rstrip("\r\n")
    except (OSError, UnicodeError):
        raise LauncherError("Influx credential file could not be read safely.") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def interpolation_value(value):
    # Telegraf substitutes these values into quoted TOML strings before parsing.
    # Do not transform a password and accidentally authenticate with a different one.
    if (not isinstance(value, str) or not value.strip()
            or any(character in '\\"' or not character.isprintable() for character in value)):
        raise LauncherError("A required credential is empty or incompatible with the existing quoted TOML placeholders.")
    return value


def influx_token(environment):
    directory = environment.get("CREDENTIALS_DIRECTORY")
    if directory:
        path = Path(directory)
        if not path.is_absolute():
            raise LauncherError("The managed credential directory must be absolute.")
        # An explicitly configured managed source must never fall back to stale env.
        return interpolation_value(read_influx_file(path / "influx-token"))
    token = environment.get("INFLUX_TOKEN")
    if not token:
        raise LauncherError("INFLUX_TOKEN is required, or provide the managed influx-token credential.")
    return interpolation_value(token)


def validate_installation():
    if not TELEGRAF.is_absolute() or not TELEGRAF.is_file() or not os.access(TELEGRAF, os.X_OK):
        raise LauncherError("The Telegraf executable is unavailable or not executable.")
    if not CONFIG.is_absolute() or not CONFIG.is_file() or CONFIG.is_symlink():
        raise LauncherError("The existing Telegraf configuration is unavailable or is a symlink.")
    if not shutil.which("op"):
        raise LauncherError("The 1Password CLI is not available on PATH.")
    private_file(credential_provider.TOKEN_FILE)
    try:
        with CONFIG.open("rb") as source:
            data = tomllib.load(source)
        inputs = data["inputs"]["gnmi"]
        outputs = data["outputs"]["influxdb_v2"]
        if not inputs or not outputs or any(
            entry.get("username") != "${NETPILOT_USERNAME}"
            or entry.get("password") != "${NETPILOT_PASSWORD}" for entry in inputs
        ) or any(entry.get("token") not in ("${INFLUX_TOKEN}", "$INFLUX_TOKEN") for entry in outputs):
            raise ValueError
    except (OSError, ValueError, KeyError, TypeError):
        raise LauncherError("The existing Telegraf configuration cannot be validated for environment credentials.") from None


def existing_collectors():
    """Inspect process names only: never read or expose process environments/args."""
    found = []
    try:
        entries = list(PROC.iterdir())
        for entry in entries:
            if not entry.name.isdigit():
                continue
            try:
                name = (entry / "comm").read_text().strip()
                if name == "telegraf":
                    found.append(int(entry.name))
            except FileNotFoundError:
                continue  # Normal process exit during inspection.
    except OSError:
        raise LauncherError("Cannot inspect existing collectors safely; startup refused.") from None
    return sorted(found)


def runtime_directory(environment):
    base = Path(environment.get("XDG_RUNTIME_DIR") or f"/run/user/{os.geteuid()}")
    try:
        info = base.lstat()
        if (not base.is_absolute() or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise LauncherError("A private runtime directory owned by this user is required.")
    except OSError:
        raise LauncherError("The user runtime directory is unavailable; use the intended user session.") from None
    return base / "netpilot-telegraf"


@contextmanager
def collector_lock(directory):
    descriptor = None
    try:
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise LauncherError("The collector lock directory is unsafe.")
        descriptor = os.open(directory / "collector.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise LauncherError("The collector lock file is unsafe.")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise LauncherError("Another managed collector or launcher is active; startup refused.") from None
        yield descriptor
    except OSError:
        raise LauncherError("The collector startup lock could not be acquired safely.") from None
    finally:
        if descriptor is not None:
            # Never unlink: competing launchers must lock the same inode.
            os.close(descriptor)


def child_environment(environment, token):
    try:
        username, password = credential_provider.get_credentials()
    except Exception:
        raise LauncherError("Device credentials unavailable from 1Password; collector not started.") from None
    child = {key: value for key, value in environment.items()
             if not key.startswith("OP_") and key not in ("CREDENTIALS_DIRECTORY", "ENCRYPTED_CREDENTIALS_DIRECTORY")}
    child.update(NETPILOT_USERNAME=interpolation_value(username),
                 NETPILOT_PASSWORD=interpolation_value(password), INFLUX_TOKEN=token)
    return child


def exec_collector(environment, lock_descriptor):
    """Replace this PID: Telegraf receives signals and returns its own exit status.

    Raw collector logs are suppressed because expanded-config diagnostics can
    contain secrets. Restore our descriptors only if exec fails (or is mocked).
    """
    saved = []
    try:
        for descriptor in (1, 2):
            saved.append((descriptor, os.dup(descriptor)))
        with open(os.devnull, "wb") as sink:
            for descriptor in (1, 2):
                os.dup2(sink.fileno(), descriptor)
        os.set_inheritable(lock_descriptor, True)
        os.execve(str(TELEGRAF), [str(TELEGRAF), "--config", str(CONFIG)], environment)
    except (OSError, ValueError):
        raise LauncherError("Telegraf could not be executed; no retry was attempted.") from None
    finally:
        for descriptor, original in saved:
            os.dup2(original, descriptor)
            os.close(original)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Start NetPilot Telegraf with fresh 1Password device credentials.")
    parser.add_argument("--check", action="store_true",
                        help="Read-only prerequisite check; no Vault authentication or collector start.")
    args = parser.parse_args(argv)
    try:
        environment = dict(os.environ)
        validate_installation()
        directory = runtime_directory(environment)
        if args.check:
            influx_token(environment)
            running = existing_collectors()
            report("[PASS] Executable, configuration, private token metadata, runtime directory, and Influx token source checked.")
            if running:
                report("[WARN] An existing collector is present; launch mode would refuse to start.")
            report("[CHECK] No collector started; Vault authentication and telemetry health were not tested.")
            return 0
        with collector_lock(directory) as descriptor:
            if existing_collectors():
                raise LauncherError("An existing Telegraf collector is present; it was left running and startup was refused.")
            token = influx_token(environment)
            child = child_environment(environment, token)
            # Vault retrieval can take time. Recheck before replacing this PID.
            if existing_collectors():
                raise LauncherError("A Telegraf collector appeared during preflight; startup refused.")
            report("[START] Launching the existing Telegraf configuration; collector output is suppressed. Verify fresh telemetry separately.")
            exec_collector(child, descriptor)
        return 0  # Only reachable when exec is mocked by an offline test.
    except LauncherError as error:
        report("[FAIL] " + str(error))
        return 1
    except KeyboardInterrupt:
        report("[STOP] Launcher interrupted; no automatic retry.")
        return 130
    except Exception:
        report("[FAIL] Launcher could not complete safely; private diagnostics suppressed.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

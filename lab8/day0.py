"""Render permanent Day-0 accounts privately, then publish for a short ZTP window.

Only ``render`` reads the existing Vault. No command connects to devices, changes
Vault records, starts containers, or activates the infrastructure topology.
"""

import argparse
import getpass
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time
import warnings

from jinja2 import Environment, FileSystemLoader, StrictUndefined

import render_configs
from security import credential_provider
from security.setup_recovery_accounts import quiet_transport, sha512_crypt


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INVENTORY = render_configs.DEFAULT_INVENTORY
RUNTIME = ROOT / "runtime" / "lab8-ztp"
DEVICES = ("R6", "R7")


class Day0Error(RuntimeError):
    """Sanitized preparation failure; never include credentials or config text."""


def _directories(runtime):
    runtime = Path(runtime)
    for directory in (runtime, runtime / "private", runtime / "http"):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = directory.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700):
            raise Day0Error("Day-0 runtime directories must be owner-only directories, not symlinks.")
    return runtime / "private", runtime / "http"


def _write_private(path, text, created):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    created.append(path)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(text)


def _read_private(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
        metadata = os.fstat(handle.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600):
            raise Day0Error("Day-0 configurations must be owner-only regular files.")
        return handle.read()


def _require_absent(paths):
    if any(os.path.lexists(path) for path in paths):
        raise Day0Error("Day-0 output already exists; clear it before preparing another window.")


def _rollback(created):
    # Reverse order removes the publication marker before either HTTP file.
    for path in reversed(created):
        path.unlink(missing_ok=True)


def _device_name(hostname):
    if not isinstance(hostname, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,62}", hostname):
        raise Day0Error("Day-0 requires a safe device hostname.")
    return hostname


def render_one(device_record, recovery_password, *, runtime=RUNTIME):
    """Prepare one GUI-selected device; recovery stays in memory, never getpass."""
    created = []
    try:
        name = _device_name(device_record["hostname"])
        render_configs._validate_day0_device(device_record, name)
        if device_record["template"] != "templates/arista_day0.j2":
            raise Day0Error("Day-0 requires the dedicated pending-device template.")
        private, public = _directories(runtime)
        path = private / (name + ".cfg")
        outputs = (path, public / (name + ".cfg"), public / ("." + name + ".expires"))
        _require_absent(outputs + ((public / ".expires",) if name in DEVICES else ()))
        if not isinstance(recovery_password, str) or not recovery_password.strip():
            raise Day0Error("The existing recovery password is unavailable.")
        env = Environment(loader=FileSystemLoader(str(render_configs.DEFAULT_TEMPLATE_DIR)),
                          undefined=StrictUndefined, lstrip_blocks=True,
                          keep_trailing_newline=True)
        with quiet_transport():
            username, password = credential_provider.get_credentials()
            if username != "admin" or not isinstance(password, str) or not password.strip():
                raise Day0Error("The existing administrative credential must identify admin.")
            if secrets.compare_digest(password.encode("utf-8"), recovery_password.encode("utf-8")):
                raise Day0Error("Recovery and administrative passwords must be distinct.")
            hashes = {
                "admin": sha512_crypt(password, allow_legacy=True),
                "netpilot-recovery": sha512_crypt(recovery_password, allow_legacy=True),
            }
            configuration = render_configs.render_device(
                env, {"devices": {name: device_record}}, name, day0_hashes=hashes)
            _write_private(path, configuration, created)
        return path
    except (Exception, KeyboardInterrupt):
        try:
            _rollback(created)
        finally:
            raise Day0Error("Day-0 rendering failed; check pending inventory, runtime permissions, and account credentials.") from None


def publish_one(hostname, *, runtime=RUNTIME, seconds=300):
    """Publish only this device under its own bounded HTTP lease."""
    created = []
    try:
        name = _device_name(hostname)
        if type(seconds) is not int or not 1 <= seconds <= 600:
            raise Day0Error("Publication must last 1 through 600 seconds.")
        private, public = _directories(runtime)
        path = public / (name + ".cfg")
        marker = public / ("." + name + ".expires")
        _require_absent((path, marker) + ((public / ".expires",) if name in DEVICES else ()))
        configuration = _read_private(private / (name + ".cfg"))
        _write_private(path, configuration, created)
        expires = time.time() + seconds
        _write_private(marker, str(expires) + "\n", created)
        return expires
    except (Exception, KeyboardInterrupt):
        try:
            _rollback(created)
        finally:
            raise Day0Error("Day-0 publication failed; check this device's private configuration and publication window.") from None


def clear_one(hostname, *, runtime=RUNTIME):
    """Revoke and remove this device's files, preserving every other device."""
    try:
        name = _device_name(hostname)
        private, public = _directories(runtime)
        (public / ("." + name + ".expires")).unlink(missing_ok=True)
        for directory in (public, private):
            (directory / (name + ".cfg")).unlink(missing_ok=True)
    except (Exception, KeyboardInterrupt):
        raise Day0Error("Day-0 cleanup failed; verify this device's publication has expired and inspect runtime permissions.") from None


def render(*, inventory=DEFAULT_INVENTORY, runtime=RUNTIME):
    """Read admin from Vault and prompt for recovery; render without publishing."""
    created = []
    try:
        nsot = render_configs.load_yaml(Path(inventory))
        for name in DEVICES:
            device = nsot["devices"][name]
            render_configs._validate_day0_device(device, name)
            if device["template"] != "templates/arista_day0.j2":
                raise Day0Error("Day-0 requires the dedicated pending-device template.")
        private, public = _directories(runtime)
        paths = tuple(private / (name + ".cfg") for name in DEVICES)
        _require_absent((*paths, public / "R6.cfg", public / "R7.cfg", public / ".expires",
                         public / ".R6.expires", public / ".R7.expires"))
        env = Environment(loader=FileSystemLoader(str(render_configs.DEFAULT_TEMPLATE_DIR)),
                          undefined=StrictUndefined, lstrip_blocks=True,
                          keep_trailing_newline=True)
        with quiet_transport():
            username, password = credential_provider.get_credentials()
            if username != "admin" or not isinstance(password, str) or not password.strip():
                raise Day0Error("The existing administrative credential must identify admin.")
            with warnings.catch_warnings():
                # getpass must never fall back to input that echoes the password.
                warnings.simplefilter("error", getpass.GetPassWarning)
                recovery = getpass.getpass("Existing netpilot-recovery password (hidden): ")
            if not isinstance(recovery, str) or not recovery.strip():
                raise Day0Error("The existing recovery password is unavailable.")
            # Preserve the existing recovery setup's independent-password contract.
            if secrets.compare_digest(password.encode("utf-8"), recovery.encode("utf-8")):
                raise Day0Error("Recovery and administrative passwords must be distinct.")
            hashes = {
                "admin": sha512_crypt(password, allow_legacy=True),
                "netpilot-recovery": sha512_crypt(recovery, allow_legacy=True),
            }
            configurations = [render_configs.render_device(env, nsot, name, day0_hashes=hashes)
                              for name in DEVICES]
            for path, configuration in zip(paths, configurations):
                _write_private(path, configuration, created)
        return paths
    except (Exception, KeyboardInterrupt):
        try:
            _rollback(created)
        finally:
            raise Day0Error("Day-0 rendering failed; check pending inventory, private runtime permissions, admin Vault access, and hidden recovery password input.") from None


def publish(*, runtime=RUNTIME, seconds=300):
    """Publish a complete pair; the updated HTTP server enforces the deadline."""
    created = []
    try:
        if type(seconds) is not int or not 1 <= seconds <= 600:
            raise Day0Error("Publication must last 1 through 600 seconds.")
        private, public = _directories(runtime)
        paths = tuple(public / (name + ".cfg") for name in DEVICES)
        marker = public / ".expires"
        _require_absent((*paths, marker, public / ".R6.expires", public / ".R7.expires"))
        configurations = [_read_private(private / (name + ".cfg")) for name in DEVICES]
        for path, configuration in zip(paths, configurations):
            _write_private(path, configuration, created)
        expires = time.time() + seconds
        _write_private(marker, str(expires) + "\n", created)
        return expires
    except (Exception, KeyboardInterrupt):
        try:
            _rollback(created)
        finally:
            raise Day0Error("Day-0 publication failed; require both private configurations, an empty publication directory, and a 1–600 second window.") from None


def clear(*, runtime=RUNTIME):
    """Revoke HTTP access first, then delete only the known sensitive outputs."""
    try:
        private, public = _directories(runtime)
        (public / ".expires").unlink(missing_ok=True)
        for name in DEVICES:
            (public / ("." + name + ".expires")).unlink(missing_ok=True)
        for directory in (public, private):
            for name in DEVICES:
                (directory / (name + ".cfg")).unlink(missing_ok=True)
    except (Exception, KeyboardInterrupt):
        raise Day0Error("Day-0 cleanup failed; verify the publication window has expired and inspect runtime permissions.") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("render", help="Read admin from Vault and prompt for the existing recovery password")
    publishing = actions.add_parser("publish", help="Publish through the updated HTTP server only")
    publishing.add_argument("--seconds", type=int, default=300)
    actions.add_parser("clear", help="Revoke publication and remove private/published hash files")
    args = parser.parse_args(argv)
    try:
        if args.action == "render":
            render()
            print("R6/R7 configurations prepared privately in runtime/lab8-ztp/private; not published.")
        elif args.action == "publish":
            publish(seconds=args.seconds)
            print(f"R6/R7 published for at most {args.seconds} seconds; clear immediately after provisioning.")
        else:
            clear()
            print("Day-0 publication revoked and runtime configurations removed.")
    except Day0Error as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

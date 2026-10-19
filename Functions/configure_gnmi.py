#!/usr/bin/env python3
"""Add the requested gNMI transport, save, and audit inventory devices.

Requires Netmiko: python3 -m pip install netmiko
Run: python3 Functions/configure_gnmi.py
"""

import json
from pathlib import Path
import re
import socket
import sys
import time

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from security.credential_provider import get_credentials

GNMI_COMMANDS = [
    "management api gnmi",
    "transport grpc default",
    "no ssl profile",
]


def load_devices():
    with Path(__file__).with_name("devices.json").open() as inventory:
        devices = json.load(inventory)["devices"]
    if not isinstance(devices, list) or any(not isinstance(device, dict) for device in devices):
        raise ValueError("Inventory devices must be a list of objects.")
    devices = [d for d in devices if d.get("type") in ("router", "switch")]
    if len(devices) != 9:
        raise ValueError(f"Expected 9 routers/switches; found {len(devices)}.")
    for device in devices:
        for field in ("name", "ip"):
            if not isinstance(device.get(field), str) or not device[field]:
                raise ValueError(f"Inventory device has a missing or invalid {field}.")
    return devices


def audit_device(device, run_cli):
    """Check the default transport and actual management TCP reachability."""
    status, port = "UNKNOWN", "-"
    for attempt in range(5):
        output = run_cli("show management api gnmi")
        # Keep fields from different transports separate.
        blocks = re.split(r"(?im)^\s*Transport:\s*", output)
        default = next((block for block in blocks[1:]
                        if block.splitlines()[0].strip() == "default"), "")
        enabled = bool(re.search(r"(?im)^\s*Enabled:\s*yes\s*$", default))
        server = re.search(r"(?im)^\s*Server:\s*running on port\s+(\d+)\b", default)
        status = "ENABLED" if enabled else "DISABLED/UNKNOWN"
        port = server.group(1) if server else "-"
        if enabled and port == "6030":
            try:
                with socket.create_connection((device["ip"], 6030), timeout=3):
                    return status, port, True
            except OSError:
                status = "TCP UNREACHABLE"
        if attempt < 4:
            time.sleep(2)
    return status, port, False


def configure_device(device, connect, credentials=None):
    connection = None
    errors = []
    status, port, passed = "ERROR", "-", False
    try:
        username, password = get_credentials() if credentials is None else credentials
        if not username or not password:
            raise ValueError
    except Exception:
        return status, port, passed, "Device credentials are not available from the credential provider."
    try:
        connection = connect(
            device_type="arista_eos", host=device["ip"],
            username=username, password=password,
            secret=device.get("secret", ""), conn_timeout=10,
            auth_timeout=10, banner_timeout=15,
        )
        connection.enable()
        try:
            connection.send_config_set(
                GNMI_COMMANDS, error_pattern=r"(?m)^\s*%", read_timeout=20,
            )
            saved = connection.save_config()
            if re.search(r"(?im)^\s*%|\b(?:failed|error)\b", saved):
                raise RuntimeError("Saving configuration failed.")
        except Exception:
            errors.append("gNMI configuration or saving the configuration failed.")
        # Still audit a connected device if configuration or saving failed.
        if connection.check_config_mode():
            connection.exit_config_mode()
        status, port, passed = audit_device(device, connection.send_command)
    except Exception:
        errors.append("Device connection or gNMI audit failed.")
    finally:
        if connection is not None:
            try:
                connection.disconnect()
            except Exception:
                pass
    if not passed and not errors:
        errors.append("gNMI must be enabled and reachable on management TCP port 6030.")
    # Only fixed messages leave this function; network errors may contain secrets.
    detail = "; ".join(errors)
    return status, port, passed and not errors, detail


def main():
    try:
        from netmiko import ConnectHandler
    except ImportError:
        print("Netmiko is required. Install with: python3 -m pip install netmiko")
        return 1
    try:
        devices = load_devices()
    except (OSError, ValueError, KeyError, TypeError):
        print("Inventory could not be loaded or validated.")
        return 1
    try:
        credentials = get_credentials()
    except Exception:
        print("Device credentials are not available from the credential provider.")
        return 1

    print("\ngNMI Configuration and Audit")
    print("-" * 70)
    print(f"{'Device':<9} {'Mgmt IP':<16} {'gNMI Status':<20} {'Port':<7} Result")
    print("-" * 70)
    passed_count = 0
    errors = []
    for device in devices:
        status, port, passed, detail = configure_device(device, ConnectHandler, credentials)
        passed_count += passed
        print(f"{device['name']:<9} {device['ip']:<16} {status:<20} "
              f"{port:<7} {'PASS' if passed else 'FAIL'}", flush=True)
        if detail:
            errors.append(f"{device['name']}: {detail}")
    print("-" * 70)
    for error in errors:
        print(error)
    print(f"\n{passed_count}/{len(devices)} devices passed")
    return 0 if passed_count == len(devices) else 1


if __name__ == "__main__":
    raise SystemExit(main())

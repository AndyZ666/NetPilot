#!/usr/bin/env python3
"""Configure and audit NETCONF on the nine inventory routers and switches.

Dependencies: python3 -m pip install netmiko ncclient
Run: python3 Functions/configure_netconf.py
"""

import json
from pathlib import Path
import re
import socket
import time
import os

USERNAME = os.getenv("NETPILOT_USERNAME")
PASSWORD = os.getenv("NETPILOT_PASSWORD")

if not USERNAME or not PASSWORD:
    raise RuntimeError(
        "NETPILOT_USERNAME and NETPILOT_PASSWORD must be set"
    )


NETCONF_COMMANDS = [
    "management api netconf",
    "transport ssh default",
]


def load_devices():
    with Path(__file__).with_name("devices.json").open() as inventory:
        devices = json.load(inventory)["devices"]
    devices = [d for d in devices if d.get("type") in ("router", "switch")]
    if len(devices) != 9:
        raise ValueError(f"Expected 9 routers/switches; found {len(devices)}.")
    for device in devices:
        for field in ("name", "ip"):
            if not device.get(field):
                raise ValueError(f"Inventory device is missing {field}.")
    return devices


def configure_device(device, connect):
    connection = None
    try:
        connection = connect(
            device_type="arista_eos", host=device["ip"],
            username=USERNAME, password=PASSWORD,
            secret=device.get("secret", ""), conn_timeout=10,
            auth_timeout=10, banner_timeout=15,
        )
        connection.enable()
        connection.send_config_set(
            NETCONF_COMMANDS, error_pattern=r"(?m)^\s*%", read_timeout=20,
        )
        saved = connection.save_config()
        if re.search(r"(?im)^\s*%|\b(?:failed|error)\b", saved):
            raise RuntimeError("Saving configuration failed.")
        return ""
    except Exception as error:
        return f"Deployment/save failed: {error}"
    finally:
        if connection is not None:
            try:
                connection.disconnect()
            except Exception:
                pass


def audit_device(device, connect):
    port_ok = session_ok = get_ok = False
    # Allow the NETCONF service a short time to start after configuration.
    for attempt in range(5):
        try:
            with socket.create_connection((device["ip"], 830), timeout=3):
                port_ok = True
            break
        except OSError:
            if attempt < 4:
                time.sleep(2)
    if not port_ok:
        return False, False, False, "TCP port 830 is unreachable."

    try:
        # Match the connection settings in netconf_s3_test.py.
        with connect(
            host=device["ip"], port=830,
            username=USERNAME, password=PASSWORD,
            hostkey_verify=False, allow_agent=False, look_for_keys=False,
            timeout=30,
        ) as session:
            if not session.connected or not session.session_id:
                raise RuntimeError("NETCONF session was not established.")
            session_ok = True
            reply = session.get_config(source="running")
            if reply.errors or reply.data_ele is None:
                raise RuntimeError("GET-CONFIG did not return a successful data reply.")
            get_ok = True
        return port_ok, session_ok, get_ok, ""
    except Exception as error:
        return port_ok, session_ok, get_ok, f"NETCONF audit failed: {error}"


def main():
    try:
        from netmiko import ConnectHandler
        from ncclient import manager
    except ImportError:
        print("Install dependencies: python3 -m pip install netmiko ncclient")
        return 1
    try:
        devices = load_devices()
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Inventory error: {error}")
        return 1

    print("\nConfiguring NETCONF and saving on all 9 devices...")
    deployment_errors = []
    for device in devices:
        error = configure_device(device, ConnectHandler)
        deployment_errors.append(error)
        print(f"  {device['name']:<8} {'FAILED' if error else 'SAVED'}", flush=True)

    print("\nNETCONF Audit")
    print("-" * 79)
    print(f"{'Device':<9} {'Mgmt IP':<16} {'Port 830':<12} "
          f"{'NETCONF Session':<18} {'GET-CONFIG':<12} Result")
    print("-" * 79)
    passed_count = 0
    details = []
    # Audit every device, including devices whose deployment failed.
    for device, deployment_error in zip(devices, deployment_errors):
        port_ok, session_ok, get_ok, audit_error = audit_device(device, manager.connect)
        passed = all((port_ok, session_ok, get_ok)) and not deployment_error and not audit_error
        passed_count += bool(passed)
        print(f"{device['name']:<9} {device['ip']:<16} "
              f"{'YES' if port_ok else 'NO':<12} "
              f"{'YES' if session_ok else 'NO':<18} "
              f"{'PASS' if get_ok else 'FAIL':<12} "
              f"{'PASS' if passed else 'FAIL'}", flush=True)
        detail = "; ".join(error for error in (deployment_error, audit_error) if error)
        if detail:
            for credential in (PASSWORD, device.get("secret", "")):
                if credential:
                    detail = detail.replace(credential, "[redacted]")
            details.append(f"{device['name']}: {detail}")
    print("-" * 79)
    for detail in details:
        print(detail)
    print(f"\n{passed_count}/{len(devices)} devices passed")
    return 0 if passed_count == len(devices) else 1


if __name__ == "__main__":
    raise SystemExit(main())

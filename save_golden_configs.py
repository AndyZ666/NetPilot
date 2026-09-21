
#!/usr/bin/env python3

from pathlib import Path
from datetime import datetime
import os
import sys
import yaml

from netmiko import ConnectHandler


# ============================================================
# Paths
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
INVENTORY_FILE = BASE_DIR / "inventory" / "devices.yml"
OUTPUT_DIR = BASE_DIR / "golden_configs"


# ============================================================
# Load NSOT
# ============================================================

def load_inventory():
    if not INVENTORY_FILE.exists():
        raise FileNotFoundError(
            f"NSOT inventory not found: {INVENTORY_FILE}"
        )

    with INVENTORY_FILE.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not data:
        raise RuntimeError("NSOT inventory is empty.")

    if "devices" not in data:
        raise RuntimeError(
            "NSOT inventory does not contain a 'devices:' section."
        )

    return data


# ============================================================
# Validate returned running config
# ============================================================

def validate_running_config(hostname, config):
    if not config or not config.strip():
        raise RuntimeError(
            f"{hostname}: running-config response was empty."
        )

    error_strings = [
        "% invalid input",
        "privileged mode required",
        "% incomplete command",
        "% ambiguous command",
        "authorization failed",
        "permission denied",
    ]

    config_lower = config.lower()

    for error in error_strings:
        if error in config_lower:
            raise RuntimeError(
                f"{hostname}: device returned CLI error: {error}"
            )

    # Basic sanity check:
    # A valid EOS running config should normally contain hostname.
    if "hostname " not in config_lower:
        raise RuntimeError(
            f"{hostname}: output does not look like a valid running-config."
        )


# ============================================================
# Retrieve configuration from one device
# ============================================================

def get_running_config(hostname, device, username, password):
    mgmt_ip = device["management"]["ipv4"]

    connection_info = {
        "device_type": "arista_eos",
        "host": mgmt_ip,
        "username": username,
        "password": password,

        # Used when Netmiko needs to execute "enable"
        "secret": password,

        # More forgiving connection timers
        "conn_timeout": 15,
        "auth_timeout": 20,
        "banner_timeout": 20,

        # More reliable for lab environments
        "fast_cli": False,
    }

    print(f"[CONNECT] {hostname} ({mgmt_ip})")

    connection = None

    try:
        connection = ConnectHandler(**connection_info)

        current_prompt = connection.find_prompt()
        print(f"[PROMPT]  {hostname}: {current_prompt}")

        # ----------------------------------------------------
        # Make sure we are in privileged EXEC mode
        # R1>  = normal EXEC
        # R1#  = privileged EXEC
        # ----------------------------------------------------

        if not connection.check_enable_mode():

            print(f"[ENABLE]  {hostname}: entering privileged mode")

            connection.enable()

        if not connection.check_enable_mode():
            raise RuntimeError(
                f"{hostname}: unable to enter privileged EXEC mode."
            )

        current_prompt = connection.find_prompt()
        print(f"[PRIV]    {hostname}: {current_prompt}")

        # ----------------------------------------------------
        # Retrieve actual running configuration
        # ----------------------------------------------------

        config = connection.send_command(
            "show running-config",
            read_timeout=60,
            strip_prompt=True,
            strip_command=True,
        )

        validate_running_config(hostname, config)

        return config

    finally:
        if connection is not None:
            connection.disconnect()


# ============================================================
# Save Golden Config
# ============================================================

def save_golden_config(
    hostname,
    device,
    username,
    password,
    timestamp
):
    mgmt_ip = device["management"]["ipv4"]

    config = get_running_config(
        hostname,
        device,
        username,
        password,
    )

    # One folder per device
    device_dir = OUTPUT_DIR / hostname
    device_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    filename = (
        device_dir /
        f"{hostname}_{timestamp}.cfg"
    )

    header = (
        "! ============================================================\n"
        "! NetPilot Golden Configuration\n"
        "! ============================================================\n"
        f"! Device: {hostname}\n"
        f"! Management IP: {mgmt_ip}\n"
        f"! Captured: {timestamp}\n"
        "! Source: live running-config\n"
        "! ============================================================\n"
        "!\n"
    )

    # Write to a temporary file first.
    # Only rename to the real .cfg after the write succeeds.
    temp_file = filename.with_suffix(".tmp")

    temp_file.write_text(
        header + config.strip() + "\n",
        encoding="utf-8"
    )

    temp_file.replace(filename)

    print(f"[OK]      {hostname} -> {filename}")

    return filename


# ============================================================
# Main
# ============================================================

def main():

    # --------------------------------------------------------
    # Credentials
    # --------------------------------------------------------

    username = os.getenv("NETPILOT_USERNAME")
    password = os.getenv("NETPILOT_PASSWORD")

    if not username:
        print(
            "[ERROR] NETPILOT_USERNAME environment variable is not set."
        )
        return 1

    if not password:
        print(
            "[ERROR] NETPILOT_PASSWORD environment variable is not set."
        )
        return 1

    # --------------------------------------------------------
    # Load NSOT
    # --------------------------------------------------------

    try:
        inventory = load_inventory()

    except Exception as exc:
        print(f"[ERROR] Unable to load NSOT: {exc}")
        return 1

    devices = inventory["devices"]

    # Same timestamp for every device in one snapshot run
    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------------------------
    # Device selection
    #
    # python3 save_golden_configs.py
    #       -> all devices
    #
    # python3 save_golden_configs.py R1
    #       -> R1 only
    #
    # python3 save_golden_configs.py R1 R2 R3
    #       -> selected devices
    # --------------------------------------------------------

    requested_devices = sys.argv[1:]

    if requested_devices:
        targets = requested_devices
    else:
        targets = list(devices.keys())

    print()
    print("============================================================")
    print("NetPilot Golden Configuration Backup")
    print("============================================================")
    print(f"Inventory:               {INVENTORY_FILE}")
    print(f"Golden config directory: {OUTPUT_DIR}")
    print(f"Snapshot timestamp:      {timestamp}")
    print(f"Devices requested:       {len(targets)}")
    print("============================================================")
    print()

    success = 0
    failed = 0

    # --------------------------------------------------------
    # Collect configs
    # --------------------------------------------------------

    for hostname in targets:

        if hostname not in devices:
            print(
                f"[FAIL]    {hostname}: "
                "device not found in NSOT."
            )
            failed += 1
            continue

        try:
            save_golden_config(
                hostname,
                devices[hostname],
                username,
                password,
                timestamp,
            )

            success += 1

        except Exception as exc:

            print(
                f"[FAIL]    {hostname}: {exc}"
            )

            failed += 1

        print()

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print("============================================================")
    print("Golden Config Summary")
    print("============================================================")
    print(f"Saved:  {success}")
    print(f"Failed: {failed}")
    print("============================================================")

    if failed == 0:
        print(
            "\nAll requested Golden Configs were saved successfully."
        )
        return 0

    print(
        "\nOne or more devices failed. "
        "No invalid configuration should have been saved "
        "for failed devices."
    )

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
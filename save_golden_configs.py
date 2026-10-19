
#!/usr/bin/env python3

from pathlib import Path
from datetime import datetime
import re
import sys
import yaml

from netmiko import ConnectHandler
from security import credential_provider


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

def validate_running_config(hostname, config, *, expected_hostname=None):
    # Existing callers also use hostname as a display label ("selected device").
    # Only collectors that know the expected identity request a hostname match.
    if not isinstance(config, str) or not config.strip():
        raise RuntimeError(
            f"{hostname}: running-config response was empty or not text."
        )

    captured_hostnames = []
    in_banner = False
    for raw_line in config.splitlines():
        line = raw_line.strip()
        # EOS login/MOTD banners are literal text terminated by EOF, not CLI.
        if in_banner:
            if line == "EOF":
                in_banner = False
            continue
        if re.fullmatch(r"banner[ \t]+(?:login|motd)", line, re.I):
            in_banner = True
            continue

        # Diagnose response lines, not error words inside descriptions/comments.
        error = re.match(
            r"(?:%\s*)?(?:error:\s*)?(invalid input|privileged mode required|"
            r"incomplete command|ambiguous command|authorization failed|permission denied)\b",
            line, re.I,
        )
        if error:
            raise RuntimeError(
                f"{hostname}: device returned CLI error: {error.group(1).lower()}"
            )
        identity = re.fullmatch(r"hostname[ \t]+(\S+)", line, re.I)
        if identity:
            captured_hostnames.append(identity.group(1))

    if in_banner or len(captured_hostnames) != 1:
        raise RuntimeError(
            f"{hostname}: output does not look like a valid running-config."
        )
    if expected_hostname is not None and captured_hostnames[0] != expected_hostname:
        raise RuntimeError(
            f"{hostname}: running-config hostname does not match the requested device."
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

        print(f"[CONNECT] {hostname}: session established")

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

        print(f"[PRIV]    {hostname}: privileged access verified")

        # ----------------------------------------------------
        # Retrieve actual running configuration
        # ----------------------------------------------------

        config = connection.send_command(
            "show running-config",
            read_timeout=60,
            strip_prompt=True,
            strip_command=True,
        )

        validate_running_config(hostname, config, expected_hostname=hostname)

        return config

    finally:
        if connection is not None:
            try:
                connection.disconnect()
            except Exception:
                pass


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

    try:
        username, password = credential_provider.get_credentials()
    except Exception:
        print("[ERROR] Device credentials unavailable from 1Password. Check CLI, token file, and Vault access.")
        return 1

    # --------------------------------------------------------
    # Load NSOT
    # --------------------------------------------------------

    try:
        inventory = load_inventory()

    except Exception:
        print("[ERROR] Unable to load NSOT. Check inventory path and YAML structure.")
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

        except Exception:

            print(
                f"[FAIL]    {hostname}: capture failed. Check device reachability, authentication, privileged access, and output permissions."
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

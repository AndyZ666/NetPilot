#!/usr/bin/env python3
"""Test cEOS linkDown and restoration linkUp traps using Docker and the journal.

Run on the NMAS: sudo python3 Functions/test_snmp_trap.py
Uses the existing NetPilot SNMPv2c configuration; no SNMP setup is changed.
"""

import json
from pathlib import Path
import re
import subprocess
import time


LINE = "-" * 40
JOURNAL = ["journalctl", "--no-pager", "-u", "snmptrapd.service"]


def run_command(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=15)
    if result.returncode or re.search(r"^%", result.stdout, re.MULTILINE):
        raise RuntimeError(result.stderr.strip() or result.stdout.strip()
                           or "Command failed")
    if "permission" in result.stderr.lower() or "not seeing" in result.stderr.lower():
        raise RuntimeError("Journal access denied. Run this script with sudo.")
    return result.stdout


def load_devices():
    with Path(__file__).with_name("devices.json").open() as inventory:
        devices = json.load(inventory)["devices"]
    devices = [d for d in devices if d.get("type") in ("router", "switch")]
    if not devices:
        raise RuntimeError("No routers or switches found in devices.json.")
    return devices


def choose_device(devices):
    print("\nSelect a device:")
    for number, device in enumerate(devices, 1):
        print(f"{number}. {device['name']:<8} {device['ip']}")
    while True:
        choice = input("Device number: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(devices):
            return devices[int(choice) - 1]
        print("Please enter a number from the menu.")


def eos(device, command):
    container = f"clab-pilot-network-{device['name']}"
    return run_command(["docker", "exec", container, "Cli", "-p", "15",
                        "-c", command])


def get_interfaces(device):
    data = json.loads(eos(device, "show interfaces | json"))["interfaces"]
    interfaces = []
    for name, details in data.items():
        if re.fullmatch(r"Ethernet\d+(?:/\d+)*", name):
            interfaces.append({
                "name": name,
                "state": str(details.get("lineProtocolStatus", "unknown")).upper(),
                "ifindex": details.get("ifIndex"),
            })
    interfaces.sort(key=lambda item: [int(n) for n in re.findall(r"\d+", item["name"])])
    if not interfaces:
        raise RuntimeError("No Ethernet interfaces found on the selected device.")
    return interfaces


def choose_interface(interfaces):
    print("\nSelect an Ethernet interface:")
    for number, interface in enumerate(interfaces, 1):
        print(f"{number}. {interface['name']:<16} {interface['state']}")
    while True:
        choice = input("Interface number: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(interfaces):
            return interfaces[int(choice) - 1]
        print("Please enter a number from the menu.")


def set_interface_state(device, interface, shutdown):
    action = "shutdown" if shutdown else "no shutdown"
    eos(device, f"configure terminal\ninterface {interface['name']}\n{action}\nend")


def journal_cursor():
    tail = run_command(["journalctl", "--no-pager", "-n", "1", "--show-cursor"])
    match = re.search(r"^-- cursor: (.+)$", tail, re.MULTILINE)
    if not match:
        raise RuntimeError("Cannot record journal cursor.")
    return match.group(1)


def check_link_trap(device, interface, cursor, trap_type):
    # Default snmptrapd output may put the sender and varbinds on separate
    # journal lines. Group by sender header, never across different traps.
    source_pattern = r"UDP: \[([^\]]+)\]:\d+"
    oid_number = {"linkDown": 3, "linkUp": 4}[trap_type]
    oid_pattern = (
        r"(?:SNMPv2-MIB::snmpTrapOID\.0|\.?1\.3\.6\.1\.6\.3\.1\.1\.4\.1\.0)"
        r"\s*(?:=\s*)?(?:OID:\s*)?"
        rf"(?:IF-MIB::{trap_type}|SNMPv2-MIB::{trap_type}|"
        rf"SNMPv2-MIB::snmpTraps\.{oid_number}|"
        rf"\.?1\.3\.6\.1\.6\.3\.1\.1\.5\.{oid_number})(?![\w.])"
    )
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        time.sleep(2)
        output = run_command(JOURNAL + ["--after-cursor", cursor, "-o", "cat"])
        # Net-SNMP may resolve only the root of a numeric OID as "iso".
        # Normalize it for both snmpTrapOID and interface-index matching.
        headers = list(re.finditer(source_pattern, output))
        for position, header in enumerate(headers):
            end = headers[position + 1].start() if position + 1 < len(headers) else len(output)
            evidence = output[header.start():end].strip()
            trap = re.sub(r"(?<![\w.])\.?iso\.(?=\d)", "1.", evidence)
            if header.group(1) != device["ip"] or not re.search(oid_pattern, trap):
                continue
            names = re.findall(r"\bEthernet\d+(?:/\d+)*\b", trap)
            indexes = re.findall(
                r"(?:IF-MIB::ifIndex|\.?1\.3\.6\.1\.2\.1\.2\.2\.1\.1)\.\d+"
                r"\s*(?:=\s*)?(?:INTEGER:\s*)?(\d+)\b", trap)
            if names and interface["name"] not in names:
                continue
            if indexes and interface["ifindex"] is not None:
                if str(interface["ifindex"]) not in indexes:
                    continue
            verified = bool(names or (indexes and interface["ifindex"] is not None))
            print(f"\n{trap_type} Trap Evidence\n{LINE}")
            print(f"Source IP       : {header.group(1)}")
            print(f"Trap OID        : 1.3.6.1.6.3.1.1.5.{oid_number}")
            print(f"Interface Match : {'YES' if verified else 'UNAVAILABLE'}")
            print("Journal entry:")
            for line in evidence.replace("\t", "\n").splitlines():
                if line.strip():
                    print(f"  {line.strip()}")
            print(LINE)
            return True
    print(f"\n{trap_type} Trap Evidence\n{LINE}")
    print("No matching new trap received within 15 seconds.")
    return False


def main():
    device = choose_device(load_devices())
    interface = choose_interface(get_interfaces(device))
    print(f"\nSNMP Trap Test\n{LINE}")
    print(f"Device        : {device['name']}")
    print(f"Management IP : {device['ip']}")
    print(f"Interface     : {interface['name']}")
    print(f"Current State : {interface['state']}")
    if interface["state"] != "UP":
        raise RuntimeError("Select an UP interface to generate a linkDown transition.")

    # EOS does not include ifIndex in every version's show interfaces JSON.
    if interface["ifindex"] is None:
        try:
            mapping = eos(device, "show snmp mib ifmib ifindex")
            match = re.search(rf"^\s*{re.escape(interface['name'])}\s+(\d+)\s*$",
                              mapping, re.MULTILINE)
            if match:
                interface["ifindex"] = int(match.group(1))
        except RuntimeError:
            pass  # Source and trap OID can still be checked.

    # Verify service journal access, then capture the global journal tail so
    # this also works when snmptrapd has not logged any traps yet.
    run_command(JOURNAL + ["-n", "1", "-o", "cat"])
    cursor = journal_cursor()
    received = up_received = restored = False
    test_error = False
    try:
        print("\nShutting down interface and waiting for linkDown trap...")
        set_interface_state(device, interface, shutdown=True)
        received = check_link_trap(device, interface, cursor, "linkDown")
    except (Exception, KeyboardInterrupt) as error:
        test_error = True
        print(f"\nTest error: {error or 'Interrupted'}")
    finally:
        print(f"\nLink Down Trap Test\n{LINE}")
        print(f"Device        : {device['name']}")
        print(f"Interface     : {interface['name']}")
        print("Trap Type     : linkDown")
        print(f"Trap Received : {'YES' if received else 'NO'}")
        print(f"Result        : {'PASS' if received and not test_error else 'FAIL'}")
        print("\nRestoring interface...")
        up_cursor = None
        try:
            up_cursor = journal_cursor()
        except (Exception, KeyboardInterrupt) as error:
            print(f"linkUp journal checkpoint failed: {error or 'Interrupted'}")
        # A failed journal checkpoint must never prevent no shutdown.
        try:
            set_interface_state(device, interface, shutdown=False)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if any(item["name"] == interface["name"] and item["state"] == "UP"
                       for item in get_interfaces(device)):
                    restored = True
                    break
                time.sleep(2)
        except (Exception, KeyboardInterrupt) as error:
            print(f"Restoration error: {error or 'Interrupted'}")
        print(f"Interface State : {'UP' if restored else 'UP NOT CONFIRMED'}")
        if up_cursor is not None:
            try:
                up_received = check_link_trap(device, interface, up_cursor, "linkUp")
            except (Exception, KeyboardInterrupt) as error:
                print(f"linkUp evidence error: {error or 'Interrupted'}")

    passed = received and up_received and restored and not test_error
    print(f"\n{LINE}\nSNMP TRAP TEST RESULT\n{LINE}")
    print(f"Device             : {device['name']}")
    print(f"Interface          : {interface['name']}")
    print(f"linkDown Received  : {'YES' if received else 'NO'}")
    print(f"linkUp Received    : {'YES' if up_received else 'NO'}")
    print(f"Interface Restored : {'YES' if restored else 'NO'}")
    print(f"\nFINAL RESULT       : {'PASS' if passed else 'FAIL'}\n{LINE}")
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Exception, KeyboardInterrupt) as error:
        print(f"\nError: {error or 'Interrupted'}")
        raise SystemExit(1)

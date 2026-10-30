"""Small read-only EOS observation cache for the existing Devices GUI.

Only protocol summaries are cached. Running configuration and credentials never
leave the refresh call, and intended inventory is never written here.
"""

from copy import deepcopy
from datetime import datetime, timezone
import ipaddress
import re
import threading
import time

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

from save_golden_configs import validate_running_config
from security import credential_provider
from security.setup_recovery_accounts import quiet_transport


_CACHE = {}
_LOCK = threading.Lock()
_CACHE_SECONDS = 30
_DEVICE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
_PROTOCOLS = (("ospfv2", "OSPFv2"), ("ospfv3", "OSPFv3"),
              ("ripv2", "RIP"), ("bgp", "BGP"))
_ROUTERS = (
    ("ospfv2", re.compile(r"router ospf [0-9]+(?:\s|$)")),
    ("ospfv3", re.compile(r"(?:ipv6 router ospf [0-9]+|router ospfv3)(?:\s|$)")),
    ("ripv2", re.compile(r"router rip(?:\s|$)")),
    ("bgp", re.compile(r"router bgp [0-9]+(?:\.[0-9]+)?(?:\s|$)")),
)


def configured_protocols(config, hostname):
    """Detect configuration, not adjacency health, from a complete EOS config.

Recognize both EOS OSPFv3 syntaxes and interface-level protocol settings. A
configured process may be administratively shut down or have no neighbors.
    Descriptions, literal comments, banners, negations and redistribution are not processes.
"""
    validate_running_config("Selected device", config, expected_hostname=hostname)
    if config.rstrip().splitlines()[-1].strip() != "end":
        raise ValueError("Incomplete running configuration.")
    protocols = {name: {"name": name, "label": label, "configured": False, "interfaces": []}
                 for name, label in _PROTOCOLS}
    interface = None
    in_banner = False
    for raw in config.splitlines():
        line = raw.strip()
        if in_banner:
            if line == "EOF":
                in_banner = False
            continue
        if line == "comment" or re.fullmatch(r"banner[ \t]+(?:login|motd)", line, re.I):
            in_banner = True
            continue
        if not line or line.startswith("!"):
            continue
        if raw == raw.lstrip():
            match = re.fullmatch(r"interface ([A-Za-z][A-Za-z0-9/_.:-]{0,63})", line)
            interface = match.group(1) if match else None
            for name, pattern in _ROUTERS:
                if pattern.match(line):
                    protocols[name]["configured"] = True
        elif interface is not None:
            name = None
            if line.startswith("ip ospf "):
                name = "ospfv2"
            elif line.startswith(("ipv6 ospf ", "ospfv3 ")):
                name = "ospfv3"
            elif line.startswith("ip rip "):
                name = "ripv2"
            if name is not None:
                protocols[name]["configured"] = True
                if interface not in protocols[name]["interfaces"]:
                    protocols[name]["interfaces"].append(interface)
    if in_banner:
        raise ValueError("Unterminated configuration literal.")
    return list(protocols.values())


def _target(device):
    if not isinstance(device, dict):
        raise ValueError
    hostname = device.get("hostname")
    if not isinstance(hostname, str) or not _DEVICE_NAME.fullmatch(hostname):
        raise ValueError
    if str(device.get("vendor", "")).casefold() != "arista":
        raise ValueError
    if str(device.get("platform", "ceoslab")).casefold() not in {"ceoslab", "ceos", "eos", "arista_eos"}:
        raise ValueError
    management = device.get("management", {})
    address = device.get("management_ip")
    if address is None and isinstance(management, dict):
        address = management.get("ipv4")
    if not isinstance(address, str):
        raise ValueError
    address = ipaddress.IPv4Interface(address).ip
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        raise ValueError
    return hostname, str(address)


def _unavailable(message, last_success=None, reachable=None):
    return {"status": "unavailable", "reachable": reachable, "protocols": None,
            "checked_at": datetime.now(timezone.utc).isoformat(), "last_success": last_success,
            "message": "Live status unavailable. " + message, "operational": "Not checked"}


def observed_state(device_record, force=False):
    """Observe an inventory-selected device with a 30-second process-local cache.

The GUI supplies the record, not a user-selected command or SSH destination.
Failures retain only the last successful refresh timestamp, never stale protocol
flags presented as current state. No raw exception or configuration is returned.
"""
    try:
        hostname, address = _target(device_record)
    except (ValueError, TypeError):
        return _unavailable("Select an Arista device with a valid management IPv4 address.")
    key = (hostname, address)
    now = time.monotonic()
    previous = _CACHE.get(key)
    if previous is not None and not force and now - previous[0] < _CACHE_SECONDS:
        return deepcopy(previous[1])
    last_success = previous[1]["last_success"] if previous is not None else None
    if not _LOCK.acquire(blocking=False):
        return _unavailable("Another live refresh is in progress; try again shortly.", last_success)
    try:
        # Match the existing project's transport logging and isolated-lab SSH
        # policy. Nothing is saved, and all commands below are fixed read-only CLI.
        with quiet_transport():
            connection = None
            stage = "credentials"
            reachable = None
            try:
                username, password = credential_provider.get_credentials()
                stage = "connection"
                connection = ConnectHandler(
                    device_type="arista_eos", host=address, username=username,
                    password=password, secret=password, conn_timeout=8, auth_timeout=8,
                    banner_timeout=8, fast_cli=False, use_keys=False, allow_agent=False,
                    ssh_strict=False, system_host_keys=False, session_log=None,
                )
                reachable = True
                stage = "configuration"
                if not connection.check_enable_mode():
                    connection.enable()
                if not connection.check_enable_mode():
                    raise ValueError
                config = connection.send_command("show running-config", read_timeout=12)
                protocols = configured_protocols(config, hostname)
                stamp = datetime.now(timezone.utc).isoformat()
                result = {"status": "available", "reachable": True, "protocols": protocols,
                          "checked_at": stamp, "last_success": stamp,
                          "message": "Read from EOS running configuration. Neighbor/session health was not queried.",
                          "operational": "Not checked"}
            except NetmikoAuthenticationException:
                result = _unavailable("SSH authentication failed.", last_success, True)
            except NetmikoTimeoutException:
                result = _unavailable("SSH timed out or the device is unreachable.", last_success, False)
            except Exception:
                message = {"credentials": "Administrative credentials could not be read.",
                           "connection": "The device could not be reached over SSH.",
                           "configuration": "Running configuration could not be read or device identity did not match."}[stage]
                result = _unavailable(message, last_success, reachable)
            finally:
                if connection is not None:
                    try:
                        connection.disconnect()
                    except Exception:
                        pass
        _CACHE[key] = (time.monotonic(), deepcopy(result))
        return result
    finally:
        _LOCK.release()

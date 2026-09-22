"""NetPilot inventory, desired configurations, and live Golden snapshots."""

from copy import deepcopy
from datetime import datetime
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import threading

from flask import Flask, flash, redirect, render_template, request, session, url_for
import yaml


BASE_DIR = Path(__file__).resolve().parent
INVENTORY_PATH = BASE_DIR / "inventory" / "devices.yml"
CONFIGURATION_TEMPLATES_PATH = BASE_DIR / "templates"
GOLDEN_CONFIGS_PATH = BASE_DIR / "golden_configs"
GENERATED_CONFIGS_PATH = BASE_DIR / "generated_configs"
GRAFANA_DEFAULT_URL = "http://127.0.0.1:3000"
TOPOLOGY_FILE_PATH = BASE_DIR / "nettopo.clab.yml"
TOPOLOGY_SCRIPT_PATH = BASE_DIR / "Functions" / "realtime_topology.py"
TOPOLOGY_SNAPSHOT_PATH = BASE_DIR / "web" / "static" / "generated" / "topology.png"
CISCO_SAMPLE_HOSTNAME = "CISCO-R1"
CISCO_SAMPLE_INVENTORY_PATH = BASE_DIR / "examples" / "cisco_test_device.yml"
_CONFIGURATION_LOCK = threading.Lock()
_SAFE_HOSTNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}\Z")
_SENSITIVE_CONFIG = re.compile(
    r"(?<![\w-])(?:username|password|passwd|secret|token|access-token|key-string|"
    r"authentication-key|private-key|passphrase|credentials?|api-key|auth-key)"
    r"(?![\w-])|\bsnmp-server\s+(?:community|user)\b|\bkey\s+", re.IGNORECASE,
)
_MAX_CONFIG_BYTES = 4 * 1024 * 1024

app = Flask(
    __name__,
    template_folder="web/templates",
    static_folder="web/static",
)
# Local sessions protect forms; device credentials are never stored in sessions.
app.config.update(
    SECRET_KEY=secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=32 * 1024,
)

# These are the combinations and role values already supported by this NSOT.
SUPPORTED_DEVICE_TYPES = ({
    "vendor": "Arista",
    "vendor_label": "Arista",
    "platform": "cEOSLab",
    "platform_label": "cEOS",
    "template": "templates/arista_ceos.j2",
    "label": "Arista cEOS",
},)
SUPPORTED_ROLES = (
    ("edge_router", "Router — Edge"),
    ("border_router", "Router — Border"),
    ("redistribution_router", "Router — Redistribution"),
    ("access_switch", "Switch — Access"),
    ("core_switch", "Switch — Core"),
)
ROUTING_PROTOCOLS = ("ospfv2", "ospfv3", "ripv2", "bgp")
DEVICE_FORM_FIELDS = (
    "hostname", "role", "vendor", "platform", "management_ip", "template",
    "ospfv2_process_id", "ospfv2_router_id", "ospfv3_process_id",
    "ospfv3_router_id", "bgp_local_asn", "bgp_router_id",
)
_INVENTORY_WRITE_LOCK = threading.Lock()


class DeviceValidationError(ValueError):
    """Keep field feedback available when revalidation under the lock fails."""

    def __init__(self, errors):
        super().__init__("Device registration validation failed.")
        self.errors = errors


class InventoryWriteError(RuntimeError):
    """A safe, human-readable reason why the inventory cannot be changed."""


class _UniqueKeyLoader(yaml.SafeLoader):
    """Refuse ambiguous YAML rather than silently discarding duplicate keys."""

    def construct_mapping(self, node, deep=False):
        self.flatten_mapping(node)
        mapping = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                if key in mapping:
                    raise InventoryWriteError(
                        "The inventory contains duplicate YAML keys. Resolve them before adding a device."
                    )
                mapping[key] = self.construct_object(value_node, deep=deep)
            except TypeError as error:
                raise InventoryWriteError("The inventory contains an unsupported YAML key.") from error
        return mapping


def get_supported_roles():
    return list(SUPPORTED_ROLES)


def get_supported_templates():
    """Return the central allowlist, checking each approved file on disk."""
    choices = []
    for supported in SUPPORTED_DEVICE_TYPES:
        choice = dict(supported)
        try:
            path = (BASE_DIR / choice["template"]).resolve(strict=True)
            path.relative_to(CONFIGURATION_TEMPLATES_PATH.resolve(strict=True))
            with path.open("rb") as template_file:
                template_file.read(0)
            choice["available"] = path.is_file()
        except (OSError, ValueError, RuntimeError):
            choice["available"] = False
        choices.append(choice)
    return choices


def validate_new_device(form, inventory):
    """Validate submitted values against the original, unnormalized NSOT."""
    errors = {}
    if not isinstance(inventory, dict) or not isinstance(inventory.get("devices"), dict):
        return {"_form": "The inventory is unavailable or has an unsupported structure. No changes were made."}
    records = inventory["devices"]

    hostname = form.get("hostname", "")
    if not hostname:
        errors["hostname"] = "Enter a hostname for this device."
    elif not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", hostname):
        errors["hostname"] = "Use 1–63 letters, numbers, or hyphens, starting and ending with a letter or number."
    elif hostname.casefold() == "add":
        errors["hostname"] = "Choose another hostname; 'add' is reserved for the registration page."
    else:
        for name, device in records.items():
            existing_names = [str(name), str(_mapping(device).get("hostname", ""))]
            if hostname.casefold() in {name.casefold() for name in existing_names}:
                errors["hostname"] = f"{name} already exists in the NetPilot Source of Truth."
                break

    management_ip = form.get("management_ip", "")
    try:
        address = ipaddress.IPv4Address(management_ip)
    except ipaddress.AddressValueError:
        errors["management_ip"] = (
            "Enter a management IP address." if not management_ip
            else "Enter a valid IPv4 management address."
        )
    else:
        for name, device in records.items():
            management = _mapping(_mapping(device).get("management"))
            for field in ("ipv4", "ipv4_prefix"):
                try:
                    existing = ipaddress.IPv4Interface(str(management.get(field))).ip
                except ValueError:
                    continue
                if address == existing:
                    errors["management_ip"] = f"{address} is already assigned to {name}."
                    break
            if "management_ip" in errors:
                break

    if form.get("role") not in dict(SUPPORTED_ROLES):
        errors["role"] = "Select a supported device role."
    choices = get_supported_templates()
    vendor_choices = [choice for choice in choices if choice["vendor"] == form.get("vendor")]
    platform_choices = [choice for choice in vendor_choices if choice["platform"] == form.get("platform")]
    if not vendor_choices:
        errors["vendor"] = "Select a supported vendor. Currently, Arista is available."
    if not platform_choices:
        errors["platform"] = "Select a supported platform for this vendor."
    selected = next((choice for choice in platform_choices if choice["template"] == form.get("template")), None)
    if selected is None:
        errors["template"] = "Select the approved configuration template for this platform."
    elif not selected["available"]:
        errors["template"] = "The approved configuration template is unavailable. Please restore it before adding a device."

    protocols = form.get("protocols", [])
    if not isinstance(protocols, list) or any(protocol not in ROUTING_PROTOCOLS for protocol in protocols):
        errors["protocols"] = "Select only supported routing protocols."
        return errors
    for protocol in ("ospfv2", "ospfv3", "bgp"):
        if protocol not in protocols:
            continue
        number_field = f"{protocol}_local_asn" if protocol == "bgp" else f"{protocol}_process_id"
        maximum = 4294967294 if protocol == "bgp" else 65535
        value = form.get(number_field, "")
        if not re.fullmatch(r"[0-9]{1,10}", value) or not 1 <= int(value) <= maximum:
            errors[number_field] = (
                "Enter a Local ASN from 1 to 4294967294." if protocol == "bgp"
                else "Enter a process ID from 1 to 65535."
            )
        router_id_field = f"{protocol}_router_id"
        try:
            router_id = ipaddress.IPv4Address(form.get(router_id_field, ""))
            if router_id.is_unspecified or router_id.is_multicast or int(router_id) == 4294967295:
                raise ipaddress.AddressValueError
        except ipaddress.AddressValueError:
            errors[router_id_field] = "Enter a nonzero IPv4 router ID, for example 10.10.10.10."
    return errors


def build_new_device(form):
    """Build only supplied intent and empty structures required by the template."""
    routing = {protocol: {"enabled": False} for protocol in ROUTING_PROTOCOLS}
    for protocol in form.get("protocols", []):
        if protocol in ("ospfv2", "ospfv3"):
            routing[protocol] = {
                "enabled": True,
                "process_id": int(form[f"{protocol}_process_id"]),
                "router_id": str(ipaddress.IPv4Address(form[f"{protocol}_router_id"])),
                "passive_interfaces": [],
                "networks" if protocol == "ospfv2" else "interfaces": [],
            }
        elif protocol == "ripv2":
            routing[protocol] = {"enabled": True, "version": 2, "networks": []}
        elif protocol == "bgp":
            routing[protocol] = {
                "enabled": True,
                "local_asn": int(form["bgp_local_asn"]),
                "router_id": str(ipaddress.IPv4Address(form["bgp_router_id"])),
                "neighbors": [],
                "networks": {"ipv4": [], "ipv6": []},
            }
    return {
        "hostname": form["hostname"],
        "role": form["role"],
        "vendor": form["vendor"],
        "platform": form["platform"],
        "management": {"ipv4": str(ipaddress.IPv4Address(form["management_ip"]))},
        "template": form["template"],
        "interfaces": {},
        "routing": routing,
        "redistribution": [],
        "policy": {"prefix_lists": {"ipv4": {}, "ipv6": {}}, "route_maps": {}},
        "vlans": {},
    }


def _read_writable_inventory(path):
    """Read the real schema and source positions; never use the display model."""
    if path.is_symlink():
        raise InventoryWriteError("The inventory must be a regular file before devices can be added.")
    original = path.read_bytes()
    loader = _UniqueKeyLoader(original.decode("utf-8"))
    try:
        root_node = loader.get_single_node()
        inventory = loader.construct_document(root_node) if root_node is not None else None
    finally:
        loader.dispose()
    if not isinstance(inventory, dict) or not isinstance(inventory.get("devices"), dict):
        raise InventoryWriteError("The inventory is unavailable or has an unsupported structure. No changes were made.")
    if not all(isinstance(name, str) and isinstance(device, dict) for name, device in inventory["devices"].items()):
        raise InventoryWriteError("The inventory contains an unsupported device record. No changes were made.")
    device_node = next(value for key, value in root_node.value if key.value == "devices")
    if device_node.flow_style or not device_node.value or device_node.start_mark.column == 0:
        raise InventoryWriteError("Device registration requires the existing indented YAML device mapping. No changes were made.")
    return original, inventory, device_node


def _serialize_added_device(original, inventory, device_node, record):
    """Insert one YAML block, leaving every original character in place."""
    source = original.decode("utf-8")
    offset = device_node.end_mark.index
    # A block can end at a document marker or at EOF, with or without a newline.
    if offset < len(source) and device_node.end_mark.column != 0:
        raise InventoryWriteError("The inventory layout cannot be safely extended. No changes were made.")
    newline = "\r\n" if "\r\n" in source else "\n"
    block = yaml.safe_dump({record["hostname"]: record}, sort_keys=False, allow_unicode=True)
    indent = " " * device_node.start_mark.column
    block = "".join(indent + line + newline for line in block.splitlines())
    separator = "" if offset == 0 or source[:offset].endswith("\n") else newline
    updated = (source[:offset] + separator + block + source[offset:]).encode("utf-8")
    expected = deepcopy(inventory)
    expected["devices"][record["hostname"]] = record
    if yaml.load(updated, Loader=_UniqueKeyLoader) != expected:
        raise InventoryWriteError("The updated inventory did not pass validation. No changes were made.")
    return updated, expected


def _serialize_removed_device(original, inventory, device_node, hostname):
    """Delete exactly one device's YAML block, leaving every other character in place."""
    source = original.decode("utf-8")
    entry = next(((key, value) for key, value in device_node.value if key.value == hostname), None)
    if entry is None:
        raise InventoryWriteError(f"'{hostname}' was not found in the inventory. No changes were made.")
    key_node, value_node = entry
    # Snap to the true start of each line rather than trusting mark.index directly: PyYAML
    # sometimes includes the following sibling's own indentation in a value's end mark
    # (harmless for a middle entry, since the deleted indent is simply inherited by the next
    # sibling) but not when the following content is a dedented key, which would otherwise
    # leave that dedented line with orphaned leading whitespace.
    start = source.rfind("\n", 0, key_node.start_mark.index) + 1
    end = source.rfind("\n", 0, value_node.end_mark.index) + 1
    if not (0 <= start < end <= len(source)):
        raise InventoryWriteError("The inventory layout cannot be safely changed for this device. No changes were made.")
    updated = (source[:start] + source[end:]).encode("utf-8")
    expected = deepcopy(inventory)
    del expected["devices"][hostname]
    if yaml.load(updated, Loader=_UniqueKeyLoader) != expected:
        raise InventoryWriteError("The updated inventory did not pass validation. No changes were made.")
    return updated, expected


def create_nsot_backup(original_bytes, inventory_path):
    """Exclusively create an exact, durable pre-change copy; never overwrite."""
    directory = Path(inventory_path).parent / "backups"
    if directory.is_symlink():
        raise InventoryWriteError("The backup directory is unavailable. The inventory was not changed.")
    directory.mkdir(exist_ok=True)
    backup_path = directory / f"devices_{datetime.now():%Y%m%d_%H%M%S}.yml"
    try:
        descriptor = os.open(backup_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise InventoryWriteError("A backup was already created this second. Please try adding the device again.") from error
    try:
        with os.fdopen(descriptor, "wb") as backup_file:
            backup_file.write(original_bytes)
            backup_file.flush()
            os.fsync(backup_file.fileno())
        if backup_path.read_bytes() != original_bytes:
            raise InventoryWriteError("The backup could not be verified. The inventory was not changed.")
        directory_descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except Exception:
        try:
            backup_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return backup_path


def save_inventory_safely(form, path=None):
    """Serialize web writers, back up, verify a temp file, then atomically replace."""
    inventory_path = Path(path if path is not None else INVENTORY_PATH)
    with _INVENTORY_WRITE_LOCK:
        # The directory inode stays stable when the inventory file is replaced.
        # flock also coordinates separate local Flask worker processes.
        try:
            directory_descriptor = os.open(inventory_path.parent, os.O_RDONLY)
        except OSError as error:
            raise InventoryWriteError("The inventory directory is unavailable. No changes were made.") from error
        temporary_path = None
        try:
            fcntl.flock(directory_descriptor, fcntl.LOCK_EX)
            original, inventory, device_node = _read_writable_inventory(inventory_path)
            errors = validate_new_device(form, inventory)
            if errors:
                raise DeviceValidationError(errors)
            record = build_new_device(form)
            updated, expected = _serialize_added_device(original, inventory, device_node, record)
            backup_path = create_nsot_backup(original, inventory_path)
            descriptor, name = tempfile.mkstemp(prefix=".devices-", suffix=".yml.tmp", dir=inventory_path.parent)
            temporary_path = Path(name)
            with os.fdopen(descriptor, "wb") as temporary_file:
                os.fchmod(temporary_file.fileno(), inventory_path.stat().st_mode & 0o777)
                temporary_file.write(updated)
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
            with temporary_path.open(encoding="utf-8") as temporary_file:
                if yaml.load(temporary_file, Loader=_UniqueKeyLoader) != expected:
                    raise InventoryWriteError("The updated inventory did not pass validation. No changes were made.")
            # Detect edits from an editor or another program that does not use our lock.
            if inventory_path.is_symlink() or inventory_path.read_bytes() != original:
                raise InventoryWriteError("The inventory changed while this form was saving. Please submit it again.")
            os.replace(temporary_path, inventory_path)
            temporary_path = None
            # Once committed, a directory flush failure must not report a failed add.
            try:
                os.fsync(directory_descriptor)
            except OSError:
                app.logger.warning("Inventory saved, but its directory could not be flushed to disk.")
            return record, backup_path
        except (DeviceValidationError, InventoryWriteError):
            raise
        except Exception as error:
            # Avoid logging YAML fragments or submitted values, which may be sensitive.
            app.logger.error("Device registration could not be saved (%s).", type(error).__name__)
            raise InventoryWriteError(
                "The device could not be saved safely. The inventory was not changed. Please try again."
            ) from error
        finally:
            if temporary_path is not None:
                try:
                    temporary_path.unlink(missing_ok=True)
                except OSError:
                    app.logger.warning("An unused inventory temporary file could not be removed.")
            try:
                os.close(directory_descriptor)
            except OSError:
                app.logger.warning("The inventory directory handle could not be closed.")


def remove_device_safely(hostname, path=None):
    """Serialize web writers, back up, verify a temp file, then atomically replace."""
    inventory_path = Path(path if path is not None else INVENTORY_PATH)
    with _INVENTORY_WRITE_LOCK:
        try:
            directory_descriptor = os.open(inventory_path.parent, os.O_RDONLY)
        except OSError as error:
            raise InventoryWriteError("The inventory directory is unavailable. No changes were made.") from error
        temporary_path = None
        try:
            fcntl.flock(directory_descriptor, fcntl.LOCK_EX)
            original, inventory, device_node = _read_writable_inventory(inventory_path)
            if hostname not in inventory["devices"]:
                raise InventoryWriteError(f"'{hostname}' was not found in the inventory. No changes were made.")
            if len(inventory["devices"]) <= 1:
                raise InventoryWriteError("The last remaining device cannot be removed from the inventory.")
            updated, expected = _serialize_removed_device(original, inventory, device_node, hostname)
            backup_path = create_nsot_backup(original, inventory_path)
            descriptor, name = tempfile.mkstemp(prefix=".devices-", suffix=".yml.tmp", dir=inventory_path.parent)
            temporary_path = Path(name)
            with os.fdopen(descriptor, "wb") as temporary_file:
                os.fchmod(temporary_file.fileno(), inventory_path.stat().st_mode & 0o777)
                temporary_file.write(updated)
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
            with temporary_path.open(encoding="utf-8") as temporary_file:
                if yaml.load(temporary_file, Loader=_UniqueKeyLoader) != expected:
                    raise InventoryWriteError("The updated inventory did not pass validation. No changes were made.")
            # Detect edits from an editor or another program that does not use our lock.
            if inventory_path.is_symlink() or inventory_path.read_bytes() != original:
                raise InventoryWriteError("The inventory changed while this request was processing. Please try again.")
            os.replace(temporary_path, inventory_path)
            temporary_path = None
            # Once committed, a directory flush failure must not report a failed removal.
            try:
                os.fsync(directory_descriptor)
            except OSError:
                app.logger.warning("Inventory saved, but its directory could not be flushed to disk.")
            return backup_path
        except InventoryWriteError:
            raise
        except Exception as error:
            # Avoid logging YAML fragments or submitted values, which may be sensitive.
            app.logger.error("Device removal could not be saved (%s).", type(error).__name__)
            raise InventoryWriteError(
                "The device could not be removed safely. The inventory was not changed. Please try again."
            ) from error
        finally:
            if temporary_path is not None:
                try:
                    temporary_path.unlink(missing_ok=True)
                except OSError:
                    app.logger.warning("An unused inventory temporary file could not be removed.")
            try:
                os.close(directory_descriptor)
            except OSError:
                app.logger.warning("The inventory directory handle could not be closed.")


def load_inventory(path=None):
    """Read a mapping or list inventory; return None when it is unavailable."""
    try:
        with Path(path if path is not None else INVENTORY_PATH).open(encoding="utf-8") as inventory_file:
            inventory = yaml.safe_load(inventory_file)
    except (OSError, UnicodeError, yaml.YAMLError):
        return None

    if isinstance(inventory, dict):
        inventory = inventory.get("inventory", inventory)
    if not isinstance(inventory, (dict, list)):
        return None
    if isinstance(inventory, dict) and "devices" in inventory:
        if not isinstance(inventory["devices"], (dict, list)):
            return None
    return inventory


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _text(value):
    """Only pass scalar display values to templates, never arbitrary YAML objects."""
    if isinstance(value, str):
        return value.strip() or None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return None


def _first_text(*values):
    return next((text for value in values if (text := _text(value)) is not None), None)


def _strings(value):
    values = value if isinstance(value, list) else [value]
    return [text for item in values if (text := _text(item)) is not None]


def _named_records(value):
    """Support keyed mappings and lists of named records without guessing names."""
    if isinstance(value, dict):
        return list(value.items())
    if isinstance(value, list):
        return [(None, item) for item in value]
    return []


def _addresses(value):
    values = value if isinstance(value, list) else [value]
    addresses = []
    for item in values:
        if isinstance(item, dict):
            address = _first_text(item.get("address"), item.get("ip"), item.get("prefix"))
            length = _text(item.get("prefix_length"))
            if address and length and "/" not in address:
                address = f"{address}/{length}"
        else:
            address = _text(item)
        if address:
            addresses.append(address)
    return addresses


def _enabled(value):
    if isinstance(value, dict):
        value = value.get("enabled")
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().casefold()
        if normalized in {"true", "yes", "on", "enabled"}:
            return True
        if normalized in {"false", "no", "off", "disabled"}:
            return False
    return None


def _normalize_interfaces(value, vlans):
    interfaces = []
    for key, raw in _named_records(value):
        record = _mapping(raw)
        name = _first_text(record.get("name"), record.get("interface"), key)
        if not name:
            continue
        peer = _mapping(record.get("peer") or record.get("neighbor"))
        switchport = _mapping(record.get("switchport"))
        vlan_labels = []
        access_vlan = _first_text(switchport.get("access_vlan"), record.get("access_vlan"))
        if access_vlan:
            vlan_labels.append(f"Access VLAN {access_vlan}")
        trunk_vlans = _strings(switchport.get("trunk_allowed_vlans"))
        if trunk_vlans:
            vlan_labels.append(f"Trunk VLANs {', '.join(trunk_vlans)}")
        vlan_labels.extend(_strings(record.get("vlan")))
        vlan_labels.extend(_strings(record.get("vlans")))
        for vlan in vlans:
            if vlan["svi"] == name:
                vlan_labels.append(f"VLAN {vlan['id']}")
        addressing = _mapping(record.get("addresses"))
        interfaces.append({
            "name": name,
            "description": _text(record.get("description")),
            "ipv4": _addresses(record.get("ipv4", record.get("ipv4_address", record.get("ipv4_addresses", addressing.get("ipv4"))))),
            "ipv6": _addresses(record.get("ipv6", record.get("ipv6_address", record.get("ipv6_addresses", addressing.get("ipv6"))))),
            "peer_device": _first_text(peer.get("device"), peer.get("hostname"), record.get("peer_device")),
            "peer_interface": _first_text(peer.get("interface"), record.get("peer_interface")),
            "vlans": list(dict.fromkeys(vlan_labels)),
        })
    return interfaces


def _normalize_vlans(value):
    vlans = []
    for key, raw in _named_records(value):
        record = _mapping(raw)
        vlan_id = _first_text(record.get("id"), record.get("vlan_id"), key)
        if vlan_id:
            vlans.append({
                "id": vlan_id,
                "name": _text(record.get("name")),
                "svi": _text(record.get("svi")),
                "interfaces": _strings(record.get("member_interfaces")),
                "ipv4": _addresses(record.get("svi_ipv4")),
                "ipv6": _addresses(record.get("svi_ipv6")),
            })
    return vlans


def _normalize_bgp(value):
    record = _mapping(value)
    if not record or _enabled(value) is False:
        return None
    neighbors = []
    for key, raw in _named_records(record.get("neighbors")):
        neighbor = _mapping(raw)
        address = _first_text(neighbor.get("address"), neighbor.get("ip"), key, raw)
        if address:
            neighbors.append({
                "address": address,
                "remote_asn": _first_text(neighbor.get("remote_asn"), neighbor.get("remote_as")),
                "address_family": _first_text(neighbor.get("transport_address_family"), neighbor.get("address_family")),
            })
    return {
        "asn": _first_text(record.get("local_asn"), record.get("asn"), record.get("local_as")),
        "router_id": _text(record.get("router_id")),
        "neighbors": neighbors,
    }


def _policy_entries(value, fields):
    """Pick recognized policy fields; credentials and raw configuration stay private."""
    if isinstance(value, dict) and "entries" in value:
        value = value["entries"]
    if isinstance(value, dict) and any(field in value for field in fields):
        value = [value]
    entries = []
    for key, raw in _named_records(value):
        if not isinstance(raw, dict):
            continue
        entry = {
            field: _strings(raw.get(field)) if field in {"match", "set"} else _text(raw.get(field))
            for field in fields
        }
        entry["sequence"] = _first_text(raw.get("sequence"), raw.get("seq"), key)
        entries.append(entry)
    return entries


def _normalize_prefix_lists(value):
    prefix_lists = []
    groups = [(None, value)]
    if isinstance(value, dict) and any(family in value for family in ("ipv4", "ipv6")):
        groups = [(family, value.get(family)) for family in ("ipv4", "ipv6")]
    for family, group in groups:
        for key, raw in _named_records(group):
            record = _mapping(raw)
            name = _first_text(record.get("name"), key)
            if not name:
                continue
            prefix_lists.append({
                "name": name,
                "family": _first_text(record.get("family"), family),
                "entries": _policy_entries(raw, ("sequence", "action", "prefix", "ge", "le")),
            })
    return prefix_lists


def _normalize_route_maps(value):
    route_maps = []
    for key, raw in _named_records(value):
        name = _first_text(_mapping(raw).get("name"), key)
        if name:
            route_maps.append({
                "name": name,
                "entries": _policy_entries(raw, ("sequence", "action", "match", "set")),
            })
    return route_maps


def normalize_inventory(inventory):
    """Build an ephemeral display model from the NSOT, with no writes or caching."""
    if isinstance(inventory, dict):
        inventory = inventory.get("inventory", inventory)
    root = _mapping(inventory)
    defaults = _mapping(_mapping(root.get("network")).get("defaults", root.get("defaults")))
    records = root.get("devices", inventory)
    metadata_keys = {
        "metadata", "network", "defaults", "endpoints", "groups",
        "routing_domains", "validation_notes", "all", "children",
    }
    devices = []
    for key, raw in _named_records(records):
        if records is inventory and key in metadata_keys:
            continue
        if not isinstance(raw, dict):
            continue
        hostname = _first_text(raw.get("hostname"), raw.get("name"), key)
        if not hostname:
            continue
        role = _first_text(raw.get("role"), raw.get("type"), raw.get("device_type"))
        kind = "other"
        for field in ("role", "type", "device_type"):
            words = (_text(raw.get(field)) or "").casefold().replace("-", "_").replace(" ", "_").split("_")
            if "router" in words:
                kind = "router"
                break
            if "switch" in words:
                kind = "switch"
                break
        management = _mapping(raw.get("management"))
        routing = _mapping(raw.get("routing", raw.get("routing_protocols")))
        protocols = []
        for name, label, alias in (("ospfv2", "OSPFv2", "ospf"), ("ospfv3", "OSPFv3", "ospf3"), ("ripv2", "RIP", "rip"), ("bgp", "BGP", "bgp")):
            protocols.append({"name": name, "label": label, "enabled": _enabled(routing.get(name, routing.get(alias)))})
        policy = _mapping(raw.get("policy"))
        redistribution = []
        for _, item in _named_records(raw.get("redistribution", policy.get("redistribution"))):
            if isinstance(item, dict):
                redistribution.append({
                    "source": _first_text(item.get("source_protocol"), item.get("source")),
                    "destination": _first_text(item.get("destination_protocol"), item.get("destination")),
                    "route_map": _text(item.get("route_map")),
                    "qualifiers": _text(item.get("qualifiers")),
                })
        vlans = _normalize_vlans(raw.get("vlans"))
        devices.append({
            "hostname": hostname,
            "kind": kind,
            "role": role.replace("_", " ").replace("-", " ").capitalize() if role else None,
            "vendor": _first_text(raw.get("vendor"), raw.get("manufacturer"), defaults.get("vendor")),
            "platform": _first_text(raw.get("platform"), defaults.get("platform")),
            "template": _first_text(raw.get("template"), defaults.get("template")),
            "management_ip": _first_text(management.get("ipv4"), management.get("ipv4_prefix"), management.get("ip"), management.get("address"), raw.get("management_ip"), raw.get("mgmt_ip"), raw.get("ip")),
            "management_ipv6": _text(management.get("ipv6")),
            "management_interface": _text(management.get("interface")),
            "protocols": protocols,
            "interfaces": _normalize_interfaces(raw.get("interfaces"), vlans),
            "bgp": _normalize_bgp(routing.get("bgp")),
            "redistribution": redistribution,
            "prefix_lists": _normalize_prefix_lists(policy.get("prefix_lists", raw.get("prefix_lists"))),
            "route_maps": _normalize_route_maps(policy.get("route_maps", raw.get("route_maps"))),
            "vlans": vlans,
        })
    return devices


def count_configuration_templates(directory=CONFIGURATION_TEMPLATES_PATH):
    """Count network Jinja2 templates separately from the Flask HTML files."""
    try:
        return sum(
            1
            for path in Path(directory).rglob("*")
            if path.is_file() and path.suffix.lower() in {".j2", ".jinja", ".jinja2"}
        )
    except OSError:
        return 0


def compute_dashboard_statistics(inventory):
    """Summarize managed device records without exposing inventory contents."""
    devices = normalize_inventory(inventory)
    return {
        "total_devices": len(devices),
        "routers": sum(device["kind"] == "router" for device in devices),
        "switches": sum(device["kind"] == "switch" for device in devices),
        "vendors": len({device["vendor"].casefold() for device in devices if device["vendor"]}),
        "templates": count_configuration_templates(),
    }


def _render_page(page_title, active_page, placeholder_description=None):
    inventory = load_inventory()
    stats = compute_dashboard_statistics(inventory)
    inventory_available = inventory is not None
    return render_template(
        "dashboard.html",
        page_title=page_title,
        active_page=active_page,
        placeholder=placeholder_description is not None,
        placeholder_description=placeholder_description,
        stats=stats,
        inventory_available=inventory_available,
        templates_available=stats["templates"] > 0,
        golden_configs_available=GOLDEN_CONFIGS_PATH.is_dir(),
        inventory_message=(
            "Device totals are read from the central inventory."
            if inventory_available
            else "The central inventory is unavailable or invalid. Device totals are unknown."
        ),
    )


@app.get("/")
def dashboard():
    return _render_page("Dashboard", "dashboard")


@app.get("/devices")
def devices():
    inventory = load_inventory()
    return render_template(
        "devices.html",
        page_title="Devices",
        active_page="devices",
        devices=normalize_inventory(inventory),
        stats=compute_dashboard_statistics(inventory),
        inventory_available=inventory is not None,
    )


@app.get("/devices/<hostname>")
def device_detail(hostname):
    inventory = load_inventory()
    device = next((item for item in normalize_inventory(inventory) if item["hostname"] == hostname), None)
    token = session.get("remove_device_csrf")
    if not isinstance(token, str):
        token = session["remove_device_csrf"] = secrets.token_hex(32)
    return render_template(
        "device_detail.html",
        page_title=device["hostname"] if device else "Device not found",
        active_page="devices",
        device=device,
        requested_hostname=hostname,
        inventory_available=inventory is not None,
        csrf_token=token,
    ), 200 if device else 404


@app.post("/devices/<hostname>/remove")
def remove_device(hostname):
    """Remove one device's NSOT record only; live devices are never contacted."""
    token = session.get("remove_device_csrf")
    submitted_token = request.form.get("csrf_token", "")
    if not isinstance(token, str) or not secrets.compare_digest(submitted_token.encode("utf-8"), token.encode("utf-8")):
        flash("This form has expired or could not be verified. Please try again.", "error")
        return redirect(url_for("device_detail", hostname=hostname), code=303)
    try:
        remove_device_safely(hostname)
    except InventoryWriteError as error:
        flash(str(error), "error")
        return redirect(url_for("device_detail", hostname=hostname), code=303)
    session.pop("remove_device_csrf", None)
    flash(f"{hostname} was removed from the NetPilot inventory.", "success")
    return redirect(url_for("devices"), code=303)


@app.route("/devices/add", methods=["GET", "POST"])
def add_device():
    """Register one device; all validation and persistence run on the server."""
    supported_templates = get_supported_templates()
    form = {field: "" for field in DEVICE_FORM_FIELDS}
    form.update({field: supported_templates[0][field] for field in ("vendor", "platform", "template")})
    form["protocols"] = []
    errors = {}
    status = 200
    try:
        _, inventory, _ = _read_writable_inventory(INVENTORY_PATH)
        inventory_available = True
    except (OSError, UnicodeError, yaml.YAMLError, InventoryWriteError):
        inventory = None
        inventory_available = False

    token = session.get("add_device_csrf")
    if not isinstance(token, str):
        token = session["add_device_csrf"] = secrets.token_hex(32)

    if request.method == "POST":
        form.update({field: request.form.get(field, "").strip() for field in DEVICE_FORM_FIELDS})
        form["protocols"] = request.form.getlist("protocols")
        submitted_token = request.form.get("csrf_token", "")
        if not secrets.compare_digest(submitted_token.encode("utf-8"), token.encode("utf-8")):
            errors["csrf_token"] = "This form has expired or could not be verified. Review your entries and submit it again."
            token = session["add_device_csrf"] = secrets.token_hex(32)
            status = 400
        else:
            errors = validate_new_device(form, inventory)
            if errors:
                status = 400
            else:
                try:
                    record, _ = save_inventory_safely(form)
                except DeviceValidationError as error:
                    errors = error.errors
                    status = 400
                except InventoryWriteError as error:
                    errors["_form"] = str(error)
                    status = 503
                else:
                    session.pop("add_device_csrf", None)
                    flash(f"{record['hostname']} has been added to the NetPilot Network Source of Truth.", "success")
                    return redirect(url_for("device_detail", hostname=record["hostname"]), code=303)
    return render_template(
        "add_device.html",
        page_title="Add Device",
        active_page="add_device",
        form=form,
        errors=errors,
        role_choices=get_supported_roles(),
        supported_templates=supported_templates,
        csrf_token=token,
        inventory_available=inventory_available,
    ), status


def _operation_devices(inventory):
    """Use the exact NSOT keys expected by both existing command-line scripts."""
    records = _mapping(inventory).get("devices")
    if not isinstance(records, dict) or any(
        not isinstance(name, str) or not _SAFE_HOSTNAME.fullmatch(name)
        or not isinstance(record, dict) for name, record in records.items()
    ):
        return None
    display_inventory = dict(inventory)
    display_inventory["devices"] = {
        name: {**record, "hostname": name} for name, record in records.items()
    }
    return normalize_inventory(display_inventory)


def _managed_path(root, *parts):
    """Reject links and non-directory parents before reading or invoking a writer."""
    root = Path(root).absolute()
    try:
        resolved_root = root.resolve()
        resolved_path = root.joinpath(*parts).resolve()
    except RuntimeError as error:
        raise ValueError("Configuration links are not supported.") from error
    if resolved_root != root or (root.exists() and not root.is_dir()):
        raise ValueError("Unsafe configuration directory.")
    path = root.joinpath(*parts)
    if not resolved_path.is_relative_to(root):
        raise ValueError("Unsafe configuration path.")
    current = root
    for part in parts:
        if not part or Path(part).name != part or part in {".", ".."}:
            raise ValueError("Unsafe configuration filename.")
        current = current / part
        if current.is_symlink():
            raise ValueError("Configuration links are not supported.")
        if current != path and current.exists() and not current.is_dir():
            raise ValueError("Unsafe configuration directory.")
    if path.exists() and path.is_file() and path.stat().st_nlink != 1:
        raise ValueError("Configuration links are not supported.")
    return path


def _snapshot_timestamp(hostname, filename):
    match = re.fullmatch(re.escape(hostname) + r"_(\d{8}_\d{6})\.cfg", filename)
    if not match:
        raise ValueError("Invalid snapshot filename.")
    return datetime.strptime(match.group(1), "%Y%m%d_%H%M%S")


def _list_snapshots(hostname):
    folder = _managed_path(GOLDEN_CONFIGS_PATH, hostname)
    if not folder.exists():
        return []
    snapshots = []
    for entry in folder.iterdir():
        try:
            timestamp = _snapshot_timestamp(hostname, entry.name)
            path = _managed_path(GOLDEN_CONFIGS_PATH, hostname, entry.name)
            if path.is_file():
                snapshots.append({"filename": entry.name, "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S")})
        except ValueError:
            continue
    return sorted(snapshots, key=lambda item: item["filename"], reverse=True)


def _redact_configuration(content):
    """Hide credential commands and private-key blocks in browser copies only."""
    lines = []
    private_key = False
    sensitive_indent = None
    redacted = False
    for line in content.splitlines(keepends=True):
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if re.search(r"-----BEGIN .*PRIVATE KEY-----", line):
            private_key = True
            redacted = True
            lines.append("! [sensitive configuration hidden]\n")
        elif private_key:
            if re.search(r"-----END .*PRIVATE KEY-----", line):
                private_key = False
        elif sensitive_indent is not None and stripped and indent > sensitive_indent:
            continue
        elif _SENSITIVE_CONFIG.search(line):
            redacted = True
            sensitive_indent = indent
            lines.append(" " * indent + "! [sensitive configuration hidden]\n")
        else:
            sensitive_indent = None
            lines.append(line)
    return "".join(lines), redacted


def _read_configuration(path):
    # O_NOFOLLOW also protects the final open if a file was replaced after validation.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "r", encoding="utf-8") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > _MAX_CONFIG_BYTES:
            raise ValueError("Configuration file cannot be displayed.")
        content = source.read(_MAX_CONFIG_BYTES + 1)
    if not content or len(content) > _MAX_CONFIG_BYTES:
        raise ValueError("Configuration file is empty or too large.")
    return _redact_configuration(content)


def _output_state(hostname, golden):
    """Validate writer destinations and record fingerprints to exclude stale output."""
    if golden:
        folder = _managed_path(GOLDEN_CONFIGS_PATH, hostname)
        # The existing capture script writes .tmp before renaming to .cfg.
        paths = list(folder.iterdir()) if folder.exists() else []
        for entry in paths:
            _managed_path(GOLDEN_CONFIGS_PATH, hostname, entry.name)
    else:
        paths = [_managed_path(GENERATED_CONFIGS_PATH, hostname + ".cfg")]
    state = {}
    for path in paths:
        if path.exists():
            info = path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("Unsafe configuration output.")
            state[path.name] = (info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    return state


def _generate_cisco_sample():
    """Render the same way _run_configuration_action does, pointed at the sample-only inventory."""
    command = [
        sys.executable, "-u", str(BASE_DIR / "render_configs.py"), CISCO_SAMPLE_HOSTNAME,
        "--inventory", str(CISCO_SAMPLE_INVENTORY_PATH),
        "--template-dir", str(CONFIGURATION_TEMPLATES_PATH),
        "--output-dir", str(GENERATED_CONFIGS_PATH),
    ]
    try:
        completed = subprocess.run(
            command, cwd=BASE_DIR, shell=False, capture_output=True,
            text=True, encoding="utf-8", errors="replace", timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    expected = GENERATED_CONFIGS_PATH / f"{CISCO_SAMPLE_HOSTNAME}.cfg"
    return completed.returncode == 0 and expected.is_file()


def _run_configuration_action(targets, golden, all_devices):
    """Execute existing backends without a shell; never expose their raw diagnostics."""
    before = {name: _output_state(name, golden) for name in targets}
    script = "save_golden_configs.py" if golden else "render_configs.py"
    command = [sys.executable, "-u", str(BASE_DIR / script)]
    if not all_devices:
        command.append(targets[0])
    if not golden:
        command.extend([
            "--inventory", str(INVENTORY_PATH),
            "--template-dir", str(CONFIGURATION_TEMPLATES_PATH),
            "--output-dir", str(GENERATED_CONFIGS_PATH),
        ])
    timed_out = False
    try:
        completed = subprocess.run(
            command, cwd=BASE_DIR, shell=False, capture_output=True,
            text=True, encoding="utf-8", errors="replace",
            timeout=180 * len(targets) if golden else 120,
        )
        output = completed.stdout
    except subprocess.TimeoutExpired as error:
        timed_out = True
        output = error.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
    # Only accept backend success markers for validated, newly written files.
    saved = {}
    for match in re.finditer(r"^\[OK\]\s+(\S+)\s+->\s+([^\r\n]+)$", output, re.MULTILINE):
        name, reported_path = match.groups()
        if name not in before:
            continue
        filename = Path(reported_path).name
        try:
            if golden:
                _snapshot_timestamp(name, filename)
                path = _managed_path(GOLDEN_CONFIGS_PATH, name, filename)
            else:
                if filename != name + ".cfg":
                    continue
                path = _managed_path(GENERATED_CONFIGS_PATH, filename)
            if Path(reported_path) != path:
                continue
            after = _output_state(name, golden)
            if filename in after and after[filename] != before[name].get(filename):
                _read_configuration(path)
                saved[name] = filename
        except (OSError, ValueError, UnicodeError):
            continue
    results = []
    for name in targets:
        if name in saved:
            message = "Golden Config captured successfully." if golden else "Configuration generated successfully."
        elif timed_out:
            message = "The operation timed out before this device could be completed. Please try again."
        elif golden:
            message = "Golden Config capture failed or no new snapshot was saved. Check device reachability, SSH access, and the application credentials."
        else:
            message = "Configuration generation failed or no new output was found. Check the device inventory and assigned template. An earlier device failure can stop Generate All."
        results.append({"hostname": name, "success": name in saved, "message": message, "filename": saved.get(name)})
    return results


def _configuration_management(golden=False, hostname=None, filename=None):
    endpoint = "golden_configs" if golden else "configuration"
    inventory = load_inventory()
    device_list = _operation_devices(inventory)
    available = device_list is not None
    device_list = device_list or []
    token = session.get("config_csrf")
    if not isinstance(token, str):
        token = session["config_csrf"] = secrets.token_hex(32)
    selection = request.form if request.method == "POST" else request.args
    selected = hostname if hostname is not None else selection.get("hostname", "")
    device = next((item for item in device_list if item["hostname"] == selected), None)
    error = None
    status = 200
    if not available:
        error = "The device inventory is unavailable or is not compatible with the configuration scripts."
    if selected and not device:
        error = "Select a device currently registered in the Source of Truth."
        status = 404
    results = session.pop(endpoint + "_results", [])
    if request.method == "POST":
        submitted = request.form.get("csrf_token", "")
        action = request.form.get("action", "")
        allowed = ("capture", "capture_all") if golden else ("generate", "generate_all")
        all_devices = action == allowed[1]
        if not secrets.compare_digest(submitted.encode("utf-8"), token.encode("utf-8")):
            error = "This form has expired or could not be verified. Please reload the page and try again."
            status = 400
        elif not available or not device_list:
            error = "No usable devices are available in the Source of Truth."
            status = 400
        elif action not in allowed or (not all_devices and not device) or (selected and not device):
            error = "Select a registered device and a valid configuration action."
            status = 400
        elif golden and not (os.environ.get("NETPILOT_USERNAME") and os.environ.get("NETPILOT_PASSWORD")):
            error = "Device credentials are not currently available to the NetPilot application."
        elif not _CONFIGURATION_LOCK.acquire(blocking=False):
            error = "Another configuration operation is running. Please try again after it finishes."
            status = 409
        else:
            try:
                targets = [item["hostname"] for item in device_list] if all_devices else [selected]
                results = _run_configuration_action(targets, golden, all_devices)
            except (OSError, ValueError, UnicodeError):
                error = "The operation could not run. Check that the backend script and configuration directories are available and are regular files and folders."
            finally:
                _CONFIGURATION_LOCK.release()
            if error is None:
                session[endpoint + "_results"] = results
                return redirect(url_for(endpoint, hostname=selected or targets[0]), code=303)
    context = {
        "page_title": "Golden Configs" if golden else "Configuration",
        "active_page": endpoint, "devices": device_list,
        "selected_device": device, "selected_hostname": selected,
        "inventory_available": available, "csrf_token": token,
        "generated_content": None, "generated_filename": None, "generated_redacted": False,
        "snapshots": [], "snapshot_name": filename, "snapshot_content": None,
        "snapshot_redacted": False, "action_results": results,
    }
    if device:
        try:
            if golden:
                context["snapshots"] = _list_snapshots(selected)
                if filename is not None:
                    _snapshot_timestamp(selected, filename)
                    path = _managed_path(GOLDEN_CONFIGS_PATH, selected, filename)
                    context["snapshot_content"], context["snapshot_redacted"] = _read_configuration(path)
            else:
                path = _managed_path(GENERATED_CONFIGS_PATH, selected + ".cfg")
                if path.exists():
                    context["generated_content"], context["generated_redacted"] = _read_configuration(path)
                    context["generated_filename"] = path.name
                elif error is None:
                    error = "No generated configuration is available for this device yet. Use Generate Configuration to create it."
        except (OSError, ValueError, UnicodeError):
            if error is None:
                error = "The saved configuration could not be opened. It may be missing, unreadable, or an unsupported file."
            if filename is not None:
                status = 404
    if not golden:
        context["cisco_sample_available"] = False
        context["cisco_sample_content"] = None
        context["cisco_sample_redacted"] = False
        cisco_path = GENERATED_CONFIGS_PATH / f"{CISCO_SAMPLE_HOSTNAME}.cfg"
        if cisco_path.is_file():
            try:
                context["cisco_sample_content"], context["cisco_sample_redacted"] = _read_configuration(cisco_path)
                context["cisco_sample_available"] = True
            except (OSError, ValueError, UnicodeError):
                pass
    context["error"] = error
    return render_template(endpoint + ".html", **context), status


@app.route("/configuration", methods=["GET", "POST"])
def configuration():
    return _configuration_management()


@app.post("/configuration/cisco-sample")
def generate_cisco_sample():
    """Re-render the Cisco IOS-XE template demonstration; no live device is contacted."""
    token = session.get("config_csrf")
    submitted = request.form.get("csrf_token", "")
    if not isinstance(token, str) or not secrets.compare_digest(submitted.encode("utf-8"), token.encode("utf-8")):
        flash("This form has expired or could not be verified. Please try again.", "error")
    elif not _CONFIGURATION_LOCK.acquire(blocking=False):
        flash("Another configuration operation is running. Please try again after it finishes.", "error")
    else:
        try:
            if _generate_cisco_sample():
                flash(
                    "The Cisco IOS-XE sample configuration was regenerated from templates/cisco_iosxe.j2. "
                    "This is a template demonstration only; no live Cisco device exists.",
                    "success",
                )
            else:
                flash("The Cisco sample configuration could not be generated.", "error")
        finally:
            _CONFIGURATION_LOCK.release()
    return redirect(url_for("configuration"), code=303)


@app.route("/golden-configs", methods=["GET", "POST"])
def golden_configs():
    return _configuration_management(golden=True)


@app.get("/golden-configs/<hostname>/<filename>")
def golden_snapshot(hostname, filename):
    return _configuration_management(golden=True, hostname=hostname, filename=filename)


@app.after_request
def protect_configuration_responses(response):
    if request.endpoint in {"configuration", "golden_configs", "golden_snapshot"}:
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.get("/monitoring")
def monitoring():
    """Point the existing Flask GUI at the existing Grafana monitoring stack."""
    grafana_url = os.environ.get("GRAFANA_URL", "").strip() or GRAFANA_DEFAULT_URL
    return render_template(
        "monitoring.html",
        page_title="Monitoring",
        active_page="monitoring",
        grafana_url=grafana_url,
    )


def _generate_topology_snapshot():
    """Run the existing topology script once via subprocess; never raises."""
    generic_error = "The topology diagram could not be generated right now. It may be waiting on live telemetry (InfluxDB) or a reachable topology file."
    try:
        TOPOLOGY_SNAPSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None, generic_error
    command = [
        sys.executable, "-u", str(TOPOLOGY_SCRIPT_PATH),
        str(TOPOLOGY_FILE_PATH), "--once", "--output", str(TOPOLOGY_SNAPSHOT_PATH),
    ]
    try:
        completed = subprocess.run(
            command, cwd=BASE_DIR, shell=False, capture_output=True,
            text=True, encoding="utf-8", errors="replace", timeout=45,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, "Generating the topology diagram timed out or could not start. InfluxDB or the topology script may be unavailable."
    if completed.returncode != 0 or not TOPOLOGY_SNAPSHOT_PATH.is_file():
        return None, generic_error
    stats = None
    for line in reversed(completed.stdout.splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                stats = json.loads(line)
            except ValueError:
                stats = None
            break
    if not isinstance(stats, dict):
        return None, generic_error
    return stats, None


@app.get("/topology")
def topology():
    """Reuse the existing NetworkX/InfluxDB topology script to render a snapshot."""
    if not TOPOLOGY_FILE_PATH.is_file() or not TOPOLOGY_SCRIPT_PATH.is_file():
        stats, error = None, "The Containerlab topology file or topology script is not available, so a diagram cannot be generated."
    else:
        stats, error = _generate_topology_snapshot()
    snapshot_available = TOPOLOGY_SNAPSHOT_PATH.is_file()
    return render_template(
        "topology.html",
        page_title="Topology",
        active_page="topology",
        error=error,
        stats=stats,
        snapshot_available=snapshot_available,
        snapshot_version=int(datetime.now().timestamp()) if snapshot_available else None,
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

"""Three previewable EOS changes, with backup, verification, and narrow NSOT edits.

This module never accepts user-supplied CLI. Importing it performs no I/O or SSH.
"""

from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
import threading
import time

from netmiko import ConnectHandler
import yaml

from save_golden_configs import validate_running_config


BASE_DIR = Path(__file__).resolve().parent
INVENTORY_PATH = BASE_DIR / "inventory" / "devices.yml"
GOLDEN_CONFIGS_PATH = BASE_DIR / "golden_configs"
HISTORY_PATH = BASE_DIR / "config_changes" / "change_history.json"
SUPPORTED_CHANGES = {
    "interface_description": {"label": "Interface Description"},
    "interface_admin_state": {"label": "Interface Admin State"},
    "create_loopback": {"label": "Create Loopback Interface"},
}
MAX_DESCRIPTION_LENGTH = 240
MAX_LOOPBACK_ID = 1000
PREVIEW_MAX_AGE = 600
_DEVICE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
_INTERFACE_NAME = re.compile(
    r"(?:Ethernet[0-9]+(?:/[0-9]+)*(?:\.[0-9]+)?|Management[0-9]+|"
    r"Loopback[0-9]+|Vlan[0-9]+|Port-Channel[0-9]+(?:\.[0-9]+)?)\Z"
)
_CLI_ERROR = re.compile(
    r"^\s*(?:%|error:|(?:invalid input|incomplete command|ambiguous command|"
    r"authorization failed|permission denied|privileged mode required|failed to)\b)",
    re.I | re.M,
)
_WRITE_LOCK = threading.Lock()
_HISTORY_LOCK = threading.Lock()


class ChangeError(ValueError):
    """A message safe to show in the GUI; never wrap raw device responses here."""


class _InventoryLoader(yaml.SafeLoader):
    pass


def _unique_mapping(loader, node, deep=False):
    keys = set()
    for key_node, value_node in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            continue
        key = loader.construct_object(key_node, deep=deep)
        if key in keys:
            raise ChangeError("The inventory contains duplicate keys; repair it before making changes.")
        keys.add(key)
    # YAML merge aliases may legitimately be overridden by explicit fields.
    loader.flatten_mapping(node)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_InventoryLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def _read_inventory(path=None):
    path = Path(path if path is not None else INVENTORY_PATH)
    try:
        if path.is_symlink() or not path.is_file():
            raise ChangeError("The inventory file is unavailable or unsafe.")
        original = path.read_bytes()
        inventory = yaml.load(original, Loader=_InventoryLoader)
        if not isinstance(inventory, dict) or not isinstance(inventory.get("devices"), dict):
            raise ChangeError("The inventory must contain a devices mapping.")
        return original, inventory
    except ChangeError:
        raise
    except Exception:
        raise ChangeError("The inventory could not be read safely.") from None


def load_inventory(path=None):
    return _read_inventory(path)[1]


def get_device(inventory, hostname):
    if not isinstance(hostname, str) or not _DEVICE_NAME.fullmatch(hostname):
        raise ChangeError("Select a valid inventory device.")
    device = inventory.get("devices", {}).get(hostname)
    if not isinstance(device, dict):
        raise ChangeError("The selected device is no longer in the inventory.")
    defaults = inventory.get("network", {}).get("defaults", {})
    vendor = str(device.get("vendor", defaults.get("vendor", ""))).lower()
    platform = str(device.get("platform", defaults.get("platform", ""))).lower()
    if vendor != "arista" or platform not in {"ceoslab", "ceos", "eos", "arista_eos"}:
        raise ChangeError("Basic configuration changes currently support Arista EOS devices only.")
    try:
        address = device["management"]["ipv4"]
        ipaddress.IPv4Address(address)
    except (KeyError, TypeError, ValueError, ipaddress.AddressValueError):
        raise ChangeError("The selected device has no valid management IPv4 address.") from None
    return device


def get_interfaces(inventory, hostname):
    interfaces = get_device(inventory, hostname).get("interfaces")
    if not isinstance(interfaces, dict):
        raise ChangeError("The selected device has no usable interface inventory.")
    return interfaces


def _text(form, key, default=""):
    value = form.get(key, default)
    if not isinstance(value, str):
        raise ChangeError("Submitted fields must be text values.")
    return value


def _description(value, required=False):
    # EOS treats separators/control characters as CLI syntax, never descriptions here.
    if (value and not value.isprintable()) or any(
        char in value for char in ";|?!"
    ):
        raise ChangeError("Descriptions must be one line without control characters or CLI separators (; | ? !).")
    value = value.strip()
    if required and not value:
        raise ChangeError("Enter a nonempty interface description.")
    if len(value) > MAX_DESCRIPTION_LENGTH:
        raise ChangeError(f"Descriptions must be {MAX_DESCRIPTION_LENGTH} characters or fewer.")
    return value


def collect_assigned_ipv4_addresses(inventory):
    """Map exact management/interface host addresses to their NSOT owners."""
    assigned = {}

    def record(value, owner):
        if not isinstance(value, str):
            return
        try:
            address = str(ipaddress.IPv4Interface(value.strip()).ip)
        except ValueError:
            return
        owners = assigned.setdefault(address, [])
        if owner not in owners:
            owners.append(owner)

    for hostname, device in inventory.get("devices", {}).items():
        if not isinstance(device, dict):
            continue
        management = device.get("management", {})
        if isinstance(management, dict):
            owner = f"{hostname}:{management.get('interface') or 'Management'}"
            for field in ("ipv4", "ipv4_prefix"):
                record(management.get(field), owner)
        interfaces = device.get("interfaces", {})
        if not isinstance(interfaces, dict):
            continue
        for interface, facts in interfaces.items():
            if not isinstance(facts, dict):
                continue
            addresses = facts.get("ipv4", [])
            if isinstance(addresses, str):
                addresses = [addresses]
            if isinstance(addresses, list):
                for address in addresses:
                    record(address, f"{hostname}:{interface}")
    return assigned


def _loopback_number(name):
    match = re.fullmatch(r"loopback([0-9]+)", str(name), re.I)
    return int(match[1]) if match else None


def _validate_change(form, inventory=None):
    """Return a canonical preview; validation performs no device connection."""
    original, current = _read_inventory()
    if inventory is None:
        inventory = current
    device_name = _text(form, "device")
    device = get_device(inventory, device_name)
    interfaces = get_interfaces(inventory, device_name)
    change_type = _text(form, "change_type")
    if change_type not in SUPPORTED_CHANGES:
        raise ChangeError("Select one of the three supported change types.")
    canonical = {"device": device_name, "change_type": change_type}
    if change_type != "create_loopback":
        interface = _text(form, "interface")
        if not _INTERFACE_NAME.fullmatch(interface) or not isinstance(interfaces.get(interface), dict):
            raise ChangeError("Select an existing, supported interface from the inventory.")
        canonical["interface"] = interface
        if change_type == "interface_description":
            new_value = _description(_text(form, "new_description"), required=True)
            old_value = interfaces[interface].get("description")
            canonical["new_description"] = new_value
        else:
            new_value = _text(form, "new_admin_state")
            if new_value not in {"up", "down"}:
                raise ChangeError("Admin state must be exactly up or down.")
            if new_value == "down" and (
                interface.startswith("Management") or interface == device.get("management", {}).get("interface")
            ):
                raise ChangeError("The management interface cannot be shut down through this feature.")
            old_value = interfaces[interface].get("admin_state")
            canonical["new_admin_state"] = new_value
    else:
        raw_id = _text(form, "loopback_id")
        if not re.fullmatch(r"[0-9]{1,10}", raw_id):
            raise ChangeError("Loopback ID must be a nonnegative integer.")
        loopback_id = int(raw_id)
        if loopback_id > MAX_LOOPBACK_ID:
            raise ChangeError(f"Loopback ID must be between 0 and {MAX_LOOPBACK_ID}.")
        if any(_loopback_number(name) == loopback_id for name in interfaces):
            raise ChangeError(f"Loopback{loopback_id} already exists on {device_name}; it will not be overwritten.")
        interface = f"Loopback{loopback_id}"
        try:
            address = ipaddress.IPv4Address(_text(form, "ipv4"))
        except ValueError:
            raise ChangeError("Enter a valid IPv4 address without a prefix.") from None
        raw_prefix = _text(form, "prefix_length", "32") or "32"
        if not re.fullmatch(r"[0-9]{1,2}", raw_prefix) or not 0 <= int(raw_prefix) <= 32:
            raise ChangeError("Prefix length must be an integer between 0 and 32.")
        owners = collect_assigned_ipv4_addresses(inventory).get(str(address))
        if owners:
            locations = ", ".join(owner.replace(":", " ", 1) for owner in owners)
            raise ChangeError(f"{address} is already assigned to {locations}.")
        description = _description(_text(form, "description"))
        canonical.update(loopback_id=str(loopback_id), ipv4=str(address),
                         prefix_length=str(int(raw_prefix)), description=description)
        old_value = None
        new_value = {"description": description or None, "admin_state": "up",
                     "forwarding_model": "routed", "ipv4": [f"{address}/{int(raw_prefix)}"],
                     "ipv6": [], "peer": None}
    preview = {
        "device": device_name, "change_type": change_type, "interface": interface,
        "old_value": old_value, "new_value": new_value, "request": canonical,
        "inventory_digest": hashlib.sha256(original).hexdigest(),
        "created_at": time.time(), "change_id": secrets.token_hex(16),
    }
    preview["generated_commands"] = build_change_commands(preview)
    return preview


def validate_change(form, inventory=None):
    try:
        return _validate_change(form, inventory)
    except ChangeError:
        raise
    except Exception:
        raise ChangeError("The submitted change or inventory data could not be validated safely.") from None


def build_change_commands(preview):
    """Generate a fixed command family from an already validated preview."""
    interface = preview["interface"]
    if not _INTERFACE_NAME.fullmatch(interface):
        raise ChangeError("The interface name is not supported.")
    commands = [f"interface {interface}"]
    kind = preview["change_type"]
    value = preview["new_value"]
    if kind == "interface_description":
        commands.append(f"description {_description(value, required=True)}")
    elif kind == "interface_admin_state" and value in {"up", "down"}:
        commands.append("no shutdown" if value == "up" else "shutdown")
    elif kind == "create_loopback":
        if not interface.startswith("Loopback") or not isinstance(value, dict):
            raise ChangeError("The loopback preview is invalid.")
        if value.get("description"):
            commands.append(f"description {_description(value['description'])}")
        try:
            address = ipaddress.IPv4Interface(value["ipv4"][0])
        except (ValueError, KeyError, TypeError, IndexError):
            raise ChangeError("The loopback address is invalid.") from None
        commands.extend([f"ip address {address}", "no shutdown"])
    else:
        raise ChangeError("The change preview is invalid.")
    return commands


@contextmanager
def _directory_lock(directory, thread_lock, create=False):
    directory = Path(directory)
    with thread_lock:
        if directory.is_symlink():
            raise ChangeError("A required storage directory is unsafe.")
        if create:
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield descriptor
        finally:
            os.close(descriptor)


def _history_read():
    path = Path(HISTORY_PATH)
    if path.is_symlink():
        raise ChangeError("Change history is unsafe; no new change can be applied.")
    if not path.exists():
        return []
    try:
        history = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(history, list) or any(
            not isinstance(item, dict) or not isinstance(item.get("change_id"), str) for item in history
        ):
            raise ValueError
        return history
    except Exception:
        raise ChangeError("Change history could not be read safely; no new change can be applied.") from None


def _atomic_write(path, data, mode=0o600, tolerate_directory_sync=False, validate=None):
    path = Path(path)
    temporary = None
    try:
        if path.is_symlink():
            raise ChangeError("A storage file is unsafe.")
        descriptor, name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), mode)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if validate is not None:
            validate(temporary)
        os.replace(temporary, path)
        temporary = None
        try:
            descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError:
            if tolerate_directory_sync:
                return False
            raise
        return True
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def log_change(result, claim=False):
    """Durably claim an ID before live writes, then replace its final result."""
    try:
        with _directory_lock(Path(HISTORY_PATH).parent, _HISTORY_LOCK, create=True):
            history = _history_read()
            matches = [i for i, item in enumerate(history) if item["change_id"] == result["change_id"]]
            if claim and matches:
                raise ChangeError("This preview has already been submitted. Create a new preview before applying again.")
            if matches:
                history[matches[0]] = deepcopy(result)
            else:
                history.append(deepcopy(result))
            _atomic_write(HISTORY_PATH, (json.dumps(history, indent=2, ensure_ascii=False) + "\n").encode())
    except ChangeError:
        raise
    except Exception:
        raise ChangeError("Change history could not be saved safely.") from None


def recent_changes(limit=10):
    try:
        # Reading an atomically replaced file needs no write or directory creation.
        if Path(HISTORY_PATH).parent.is_symlink():
            raise ChangeError("Change history is unsafe.")
        return list(reversed(_history_read()[-max(1, min(int(limit), 100)):]))
    except ChangeError:
        raise
    except Exception:
        raise ChangeError("Change history is currently unavailable.") from None


def _mapping_value(node, key):
    if not isinstance(node, yaml.MappingNode):
        raise ChangeError("This inventory layout cannot be edited safely.")
    for key_node, value_node in node.value:
        if key_node.value == key:
            return key_node, value_node
    return None, None


def _insert_mapping(source, node, snippet):
    if node.flow_style and not node.value:
        # Expand only the empty value token; retain its existing inline comment.
        end = source.find("\n", node.end_mark.index)
        if end == -1:
            end = len(source)
        comment = source[node.end_mark.index:end]
        return source[:node.start_mark.index] + comment + "\n" + snippet + source[min(end + 1, len(source)):]
    if node.flow_style or not node.value:
        raise ChangeError("This interface mapping layout cannot be edited safely.")
    position = node.end_mark.index
    line_start = source.rfind("\n", 0, position) + 1
    if not source[line_start:position].strip():
        position = line_start
    prefix = "" if position == 0 or source[position - 1] == "\n" else "\n"
    return source[:position] + prefix + snippet + source[position:]


def _intended_inventory(inventory, preview):
    """Detach the edited path so a shared YAML alias cannot change other paths."""
    expected = deepcopy(inventory)
    expected["devices"] = dict(expected["devices"])
    device = dict(expected["devices"][preview["device"]])
    expected["devices"][preview["device"]] = device
    interfaces = device["interfaces"] = dict(device["interfaces"])
    name = preview["interface"]
    if preview["change_type"] == "create_loopback":
        interfaces[name] = deepcopy(preview["new_value"])
    else:
        interfaces[name] = dict(interfaces[name])
        field = "description" if preview["change_type"] == "interface_description" else "admin_state"
        interfaces[name][field] = preview["new_value"]
    return expected


def _validate_inventory_update(content, expected):
    """Verify every value, including unrelated devices, VLANs and unknown fields."""
    loaded = yaml.safe_load(content)
    if (not isinstance(loaded, dict) or set(loaded) != set(expected)
            or not isinstance(loaded.get("devices"), dict)
            or set(loaded["devices"]) != set(expected["devices"])
            or loaded != expected or yaml.load(content, Loader=_InventoryLoader) != expected):
        raise ChangeError("The proposed inventory update did not preserve the expected data.")


def _patch_inventory_text(source, preview):
    root = yaml.compose(source, Loader=_InventoryLoader)
    _, devices_node = _mapping_value(root, "devices")
    _, device_node = _mapping_value(devices_node, preview["device"])
    interfaces_key, interfaces_node = _mapping_value(device_node, "interfaces")
    if interfaces_key is None or interfaces_node is None:
        raise ChangeError("An inherited interface mapping needs an expanded YAML update.")
    name = preview["interface"]
    if preview["change_type"] == "create_loopback":
        indent = interfaces_key.start_mark.column + 2
        snippet = yaml.safe_dump({name: preview["new_value"]}, sort_keys=False, allow_unicode=True)
        snippet = "".join(" " * indent + line + "\n" for line in snippet.splitlines())
        return _insert_mapping(source, interfaces_node, snippet)
    field = "description" if preview["change_type"] == "interface_description" else "admin_state"
    interface_key, interface_node = _mapping_value(interfaces_node, name)
    if interface_key is None or interface_node is None:
        raise ChangeError("An inherited interface entry needs an expanded YAML update.")
    _, value_node = _mapping_value(interface_node, field)
    scalar = json.dumps(preview["new_value"], ensure_ascii=False)
    if value_node is not None:
        if not isinstance(value_node, yaml.ScalarNode) or value_node.style in {"|", ">"}:
            raise ChangeError("This interface field layout cannot be edited safely.")
        separator = " " if value_node.start_mark.index and source[value_node.start_mark.index - 1] == ":" else ""
        return source[:value_node.start_mark.index] + separator + scalar + source[value_node.end_mark.index:]
    snippet = " " * (interface_key.start_mark.column + 2) + f"{field}: {scalar}\n"
    return _insert_mapping(source, interface_node, snippet)


class _ExpandedSafeDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def _prepare_inventory_update(original, inventory, preview):
    """Preserve source text where possible; safely expand shared targets if needed."""
    try:
        source = original.decode("utf-8")
        expected = _intended_inventory(inventory, preview)
        has_aliases = any(isinstance(token, (yaml.AliasToken, yaml.AnchorToken)) for token in yaml.scan(source))
        try:
            updated = _patch_inventory_text(source, preview)
            _validate_inventory_update(updated, expected)
        except (ChangeError, yaml.YAMLError):
            if not has_aliases:
                raise
            # Editing an aliased node in-place could also edit its other owners.
            # Expand values only when the narrow edit cannot preserve semantics.
            updated = yaml.dump(expected, Dumper=_ExpandedSafeDumper, sort_keys=False, allow_unicode=True)
            _validate_inventory_update(updated, expected)
        return updated.encode("utf-8")
    except ChangeError:
        raise
    except Exception:
        raise ChangeError("This inventory layout cannot be edited safely.") from None


def _exclusive_backup(directory, filename, data):
    directory = Path(directory)
    if directory.is_symlink() or directory.parent.is_symlink():
        raise ChangeError("The backup directory is unsafe.")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / filename
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if path.read_bytes() != data:
            raise ChangeError("The backup could not be verified.")
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return path


def _save_prechange_backup(preview, config):
    validate_running_config(preview["device"], config)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{preview['device']}_{stamp}_{preview['change_id'][:8]}_prechange.cfg"
    header = f"! NetPilot pre-change running-config snapshot\n! Change ID: {preview['change_id']}\n"
    return _exclusive_backup(Path(GOLDEN_CONFIGS_PATH) / preview["device"], filename,
                             (header + config.rstrip() + "\n").encode("utf-8"))


def _read_live_config(connection, all_defaults=False):
    config = connection.send_command(
        "show running-config all" if all_defaults else "show running-config",
        read_timeout=60, strip_prompt=True, strip_command=True,
    )
    if not isinstance(config, str) or not config.strip() or _CLI_ERROR.search(config):
        raise ChangeError("The device did not return a usable running configuration.")
    if all_defaults:
        # Ordinary backups reuse the Golden validator. For explicit-default reads,
        # do not confuse description text containing error words with CLI errors.
        if not re.search(r"^hostname\s+\S+\s*$", config, re.M) or not re.search(r"^end\s*$", config, re.M):
            raise ChangeError("The device did not return a complete running configuration with defaults.")
    else:
        try:
            validate_running_config("selected device", config)
        except Exception:
            raise ChangeError("The device did not return a usable running configuration.") from None
    return config


def _interface_blocks(config):
    blocks = {}
    current = None
    for line in config.splitlines():
        if line.startswith("interface "):
            current = line[len("interface "):].strip()
            if current in blocks:
                raise ChangeError("The interface configuration response was ambiguous.")
            blocks[current] = []
        elif line and not line[0].isspace():
            current = None
        elif current is not None and line.strip():
            blocks[current].append(line.strip())
    return blocks


def _admin_state(lines):
    states = [line for line in lines if line in {"shutdown", "no shutdown"}]
    if len(states) != 1:
        raise ChangeError("The device's administrative interface state could not be confirmed.")
    return "down" if states[0] == "shutdown" else "up"


def _live_old_value(preview, config):
    blocks = _interface_blocks(config)
    if not blocks:
        raise ChangeError("The live interface inventory could not be confirmed.")
    interface = preview["interface"]
    if preview["change_type"] == "create_loopback":
        number = _loopback_number(interface)
        if any(_loopback_number(name) == number for name in blocks):
            raise ChangeError("That loopback already exists on the live device; it will not be overwritten.")
        return None
    if interface not in blocks:
        raise ChangeError("The selected interface could not be confirmed on the live device.")
    lines = blocks[interface]
    if preview["change_type"] == "interface_admin_state":
        return _admin_state(lines)
    descriptions = [line[len("description "):] for line in lines if line.startswith("description ")]
    if len(descriptions) > 1:
        raise ChangeError("The device's interface description could not be confirmed.")
    return descriptions[0] if descriptions else None


def verify_change(connection, preview):
    """Read explicit defaults so operational link state cannot masquerade as admin state."""
    blocks = _interface_blocks(_read_live_config(connection, all_defaults=True))
    lines = blocks.get(preview["interface"])
    if lines is None:
        return False
    kind, value = preview["change_type"], preview["new_value"]
    if kind == "interface_description":
        return [line for line in lines if line.startswith("description ")] == [f"description {value}"]
    if kind == "interface_admin_state":
        return _admin_state(lines) == value
    if kind == "create_loopback":
        addresses = []
        for line in lines:
            if line.startswith("ip address "):
                tokens = line.split()
                try:
                    address = tokens[2] if "/" in tokens[2] else f"{tokens[2]}/{tokens[3]}"
                    addresses.append(str(ipaddress.IPv4Interface(address)))
                except (IndexError, ValueError):
                    return False
        description_ok = not value.get("description") or f"description {value['description']}" in lines
        return addresses == value["ipv4"] and _admin_state(lines) == "up" and description_ok
    return False


def _update_inventory(original, updated, preview):
    path = Path(INVENTORY_PATH)
    if path.is_symlink() or path.read_bytes() != original:
        raise ChangeError("The inventory changed during the device operation; it was not overwritten.")
    expected = _intended_inventory(yaml.load(original, Loader=_InventoryLoader), preview)
    _validate_inventory_update(updated, expected)
    filename = f"devices_{datetime.now():%Y%m%d_%H%M%S}_{preview['change_id'][:8]}_prechange.yml"
    _exclusive_backup(path.parent / "backups", filename, original)
    # Recheck immediately before replacement, including edits that ignore our directory lock.
    if path.is_symlink() or path.read_bytes() != original:
        raise ChangeError("The inventory changed during backup; it was not overwritten.")
    def validate_temporary(temporary):
        _validate_inventory_update(temporary.read_bytes(), expected)
        if path.is_symlink() or path.read_bytes() != original:
            raise ChangeError("The inventory changed during validation; it was not overwritten.")

    return _atomic_write(path, updated, mode=path.stat().st_mode & 0o777,
                         tolerate_directory_sync=True, validate=validate_temporary)


def apply_change(preview):
    """Apply once only after a fresh validation, durable claim, and verified backup."""
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "change_id": preview.get("change_id"), "device": preview.get("device"),
        "change_type": preview.get("change_type"), "interface": preview.get("interface"),
        "old_value": preview.get("old_value"), "new_value": preview.get("new_value"),
        "generated_commands": [], "backup_file": None, "backup_status": "not_attempted",
        "apply_status": "not_attempted", "verification_status": "not_attempted",
        "nsot_status": "not_attempted", "error": None,
    }
    connection = None
    claimed = False
    stage = "validation"
    try:
        with _directory_lock(Path(INVENTORY_PATH).parent, _WRITE_LOCK):
            if not isinstance(preview.get("change_id"), str) or not re.fullmatch(r"[a-f0-9]{32}", preview["change_id"]):
                raise ChangeError("The preview is invalid; create a new preview.")
            age = time.time() - float(preview.get("created_at", 0))
            if not 0 <= age <= PREVIEW_MAX_AGE:
                raise ChangeError("The preview has expired; create a new preview.")
            original, inventory = _read_inventory()
            if hashlib.sha256(original).hexdigest() != preview.get("inventory_digest"):
                raise ChangeError("The inventory changed after preview; create a new preview.")
            canonical = validate_change(preview.get("request", {}), inventory)
            for field in ("device", "change_type", "interface", "old_value", "new_value", "generated_commands"):
                if canonical[field] != preview.get(field):
                    raise ChangeError("The preview no longer matches validation; create a new preview.")
            canonical["change_id"] = preview["change_id"]
            commands = build_change_commands(canonical)
            result["generated_commands"] = commands
            updated = _prepare_inventory_update(original, inventory, canonical)
            username, password = os.environ.get("NETPILOT_USERNAME"), os.environ.get("NETPILOT_PASSWORD")
            if not username or not password:
                raise ChangeError("Device credentials are not currently available to the NetPilot application.")
            stage = "history"
            # A crashed process leaves this unknown record, preventing a repeated live apply.
            pending = deepcopy(result)
            pending["apply_status"] = "unknown"
            pending["error"] = "Operation started; final outcome has not been recorded. Check the device before retrying."
            log_change(pending, claim=True)
            claimed = True
            stage = "connection"
            device = get_device(inventory, canonical["device"])
            connection = ConnectHandler(
                device_type="arista_eos", host=device["management"]["ipv4"],
                username=username, password=password, secret=password,
                conn_timeout=15, auth_timeout=20, banner_timeout=20, fast_cli=False,
            )
            if not connection.check_enable_mode():
                connection.enable()
            if not connection.check_enable_mode():
                raise ChangeError("The device did not permit privileged access.")
            stage = "backup"
            running_config = _read_live_config(connection)
            backup = _save_prechange_backup(canonical, running_config)
            result["backup_status"], result["backup_file"] = "saved", str(backup.relative_to(BASE_DIR)) if backup.is_relative_to(BASE_DIR) else str(backup)
            stage = "live_validation"
            result["old_value"] = _live_old_value(canonical, _read_live_config(connection, all_defaults=True))
            # An editor may ignore flock; stop before writing live configuration in that case.
            if Path(INVENTORY_PATH).is_symlink() or Path(INVENTORY_PATH).read_bytes() != original:
                raise ChangeError("The inventory changed during preflight; no device change was sent.")
            stage = "apply"
            result["apply_status"] = "unknown"
            output = connection.send_config_set(commands, read_timeout=60)
            if not isinstance(output, str) or not output.strip() or _CLI_ERROR.search(output):
                raise ChangeError("The device did not confirm all commands. Its configuration may have partially changed; NSOT was not updated.")
            result["apply_status"] = "applied"
            stage = "verification"
            if not verify_change(connection, canonical):
                raise ChangeError("Configuration applied but verification failed; NSOT was not updated.")
            result["verification_status"] = "passed"
            stage = "nsot"
            durable = _update_inventory(original, updated, canonical)
            result["nsot_status"] = "updated"
            if not durable:
                result["error"] = "The verified change and NSOT update succeeded, but inventory directory durability could not be confirmed."
    except Exception as error:
        if stage == "backup":
            result["backup_status"] = "failed"
        if stage == "verification":
            result["verification_status"] = "failed"
        if stage == "nsot":
            result["nsot_status"] = "failed"
        messages = {
            "validation": "The change could not be validated safely; no device change was sent.",
            "history": "Change history could not be saved; no device change was sent.",
            "connection": "The device could not be reached or authenticated; no device change was sent.",
            "backup": "The pre-change backup failed; no device change was sent.",
            "live_validation": "The live interface state could not be confirmed; no device change was sent.",
            "apply": "The device operation was interrupted. Configuration may have partially changed; NSOT was not updated.",
            "verification": "Configuration applied but verification failed; NSOT was not updated.",
            "nsot": "The live change was verified, but NSOT could not be updated. Reconcile the inventory before further changes.",
        }
        result["error"] = str(error) if isinstance(error, ChangeError) else messages[stage]
    finally:
        if connection is not None:
            try:
                connection.disconnect()
            except Exception:
                pass
        if claimed:
            try:
                log_change(result)
            except ChangeError:
                message = "Final change history could not be saved; its pending record prevents replay. Check the device before retrying."
                result["error"] = f"{result['error']} {message}" if result["error"] else message
    return result

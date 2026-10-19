"""Offline inventory contracts: synthetic NSOT files, no automation or credentials."""

from copy import deepcopy
from datetime import datetime
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import yaml


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("netpilot_inventory_test_app", ROOT / "app.py")
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)

INVENTORY = """# Synthetic inventory; formatting must survive registration.
network:
  defaults: &defaults
    vendor: Arista
    platform: cEOSLab
devices:
  R1:
    hostname: R1
    role: edge_router
    management: {ipv4: 192.0.2.1}
    interfaces:
      Ethernet1:
        description: 'Preserve this uplink'
        ipv4: [198.51.100.1/30]
        ipv6: ['2001:db8:1::1/64']
    routing:
      ospfv2: {enabled: true, process_id: 10, router_id: 203.0.113.1}
      bgp: {enabled: true, local_asn: 64512, neighbors: []}
  R2:
    hostname: R2
    management: {ipv4: 192.0.2.2}
    interfaces: {}
metadata:
  copied_defaults: *defaults
  owner: fixture-only
"""


class InventoryFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="netpilot-inventory-tests-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / "inventory" / "devices.yml"
        self.path.parent.mkdir()
        self.path.write_text(INVENTORY, encoding="utf-8")
        self.original = self.path.read_bytes()
        self.data = yaml.safe_load(INVENTORY)
        self.templates = self.root / "templates"
        self.templates.mkdir()
        self.template = self.templates / "arista_ceos.j2"
        self.template.write_text("hostname {{ device.hostname }}\n", encoding="utf-8")
        for name, value in {
            "BASE_DIR": self.root, "INVENTORY_PATH": self.path,
            "CONFIGURATION_TEMPLATES_PATH": self.templates,
            "GENERATED_CONFIGS_PATH": self.root / "generated",
            "GOLDEN_CONFIGS_PATH": self.root / "golden",
        }.items():
            self.enterContext(patch.object(m, name, value))
        self.enterContext(patch.dict(os.environ, {}, clear=True))
        for target in (
            "subprocess.run", "socket.create_connection", "socket.socket.connect",
            "security.credential_provider.get_credentials", "config_changes.ConnectHandler",
            "health_checks.ConnectHandler", "health_checks.InfluxDBClient",
            "config_changes.apply_change", "health_checks.run",
        ):
            self.enterContext(patch(target, side_effect=AssertionError("External operation forbidden in inventory tests")))
        m.app.config.update(TESTING=True, SECRET_KEY="inventory-fixture-session")
        self.client = m.app.test_client()

    def form(self, **changes):
        result = {"hostname": "LAB-R3", "role": "edge_router", "vendor": "Arista",
                  "platform": "cEOSLab", "management_ip": "192.0.2.3",
                  "template": "templates/arista_ceos.j2", "protocols": []}
        result.update(changes)
        return result

    def expected_record(self):
        # A literal specification of the registration schema, not renderer output.
        return {
            "hostname": "LAB-R3", "role": "edge_router", "vendor": "Arista",
            "platform": "cEOSLab", "management": {"ipv4": "192.0.2.3"},
            "template": "templates/arista_ceos.j2", "interfaces": {},
            "routing": {"ospfv2": {"enabled": False}, "ospfv3": {"enabled": False},
                        "ripv2": {"enabled": False}, "bgp": {"enabled": False}},
            "redistribution": [], "policy": {"prefix_lists": {"ipv4": {}, "ipv6": {}},
                                              "route_maps": {}}, "vlans": {},
        }

    def backups(self):
        return sorted((self.path.parent / "backups").glob("*.yml"))

    def assert_unchanged(self, expected=None):
        self.assertEqual(self.path.read_bytes(), self.original if expected is None else expected)
        self.assertEqual(list(self.path.parent.glob(".devices-*.yml.tmp")), [])


class DeviceRegistrationValidation(InventoryFixture):
    def test_valid_form_builds_exact_minimal_record_without_mutating_inputs(self):
        form = self.form()
        before = deepcopy(form), deepcopy(self.data)
        self.assertEqual(m.validate_new_device(form, self.data), {})
        self.assertEqual(m.build_new_device(form), self.expected_record())
        self.assertEqual((form, self.data), before)

    def test_each_required_registration_field_has_field_feedback(self):
        for field in ("hostname", "role", "vendor", "platform", "management_ip", "template"):
            with self.subTest(field=field):
                form = self.form()
                del form[field]
                self.assertIn(field, m.validate_new_device(form, self.data))

    def test_hostname_contract_boundaries_reserved_name_and_invalid_characters(self):
        for hostname in ("A", "7", "a-b", "a" * 63):
            with self.subTest(valid=hostname):
                self.assertNotIn("hostname", m.validate_new_device(self.form(hostname=hostname), self.data))
        for hostname in ("", "a" * 64, "-router", "router-", "router_one", "router.example",
                         "router one", "../R3", "R3\n", "réseau", "add", "ADD"):
            with self.subTest(invalid=hostname):
                self.assertIn("hostname", m.validate_new_device(self.form(hostname=hostname), self.data))

    def test_duplicate_key_and_explicit_hostname_are_case_insensitive(self):
        inventory = {"devices": {"ASSET-42": {"hostname": "Actual-Router"}}}
        for hostname in ("asset-42", "ACTUAL-ROUTER"):
            with self.subTest(hostname=hostname):
                self.assertIn("hostname", m.validate_new_device(self.form(hostname=hostname), inventory))

    def test_all_documented_roles_supported_but_arbitrary_roles_rejected(self):
        for role in ("edge_router", "border_router", "redistribution_router", "access_switch", "core_switch"):
            with self.subTest(role=role):
                self.assertNotIn("role", m.validate_new_device(self.form(role=role), self.data))
        self.assertIn("role", m.validate_new_device(self.form(role="server"), self.data))

    def test_vendor_platform_template_allowlist_is_not_a_filesystem_picker(self):
        for field, value in (("vendor", "Cisco"), ("platform", "IOS-XE"),
                             ("template", "templates/cisco_iosxe.j2"),
                             ("template", "../arbitrary.j2")):
            with self.subTest(field=field, value=value):
                self.assertIn(field, m.validate_new_device(self.form(**{field: value}), self.data))

    def test_template_choices_require_regular_file_within_approved_directory(self):
        self.assertTrue(m.get_supported_templates()[0]["available"])
        self.template.unlink()
        self.assertFalse(m.get_supported_templates()[0]["available"])
        self.assertIn("template", m.validate_new_device(self.form(), self.data))
        self.template.mkdir()
        self.assertFalse(m.get_supported_templates()[0]["available"])
        self.template.rmdir()
        outside = self.root / "outside.j2"
        outside.write_text("not approved", encoding="utf-8")
        self.template.symlink_to(outside)
        self.assertFalse(m.get_supported_templates()[0]["available"])

    def test_protocol_selection_is_an_allowlisted_list(self):
        for protocols in ("ospfv2", None, {"bgp": True}, ["isis"], ["ospfv2", "unknown"]):
            with self.subTest(protocols=protocols):
                self.assertIn("protocols", m.validate_new_device(self.form(protocols=protocols), self.data))

    def test_selected_protocols_build_exact_typed_intent_without_invented_neighbors(self):
        form = self.form(protocols=["ospfv2", "ospfv3", "ripv2", "bgp"],
                         ospfv2_process_id="10", ospfv2_router_id="203.0.113.10",
                         ospfv3_process_id="20", ospfv3_router_id="203.0.113.20",
                         bgp_local_asn="64512", bgp_router_id="203.0.113.30")
        expected = self.expected_record()
        expected["routing"] = {
            "ospfv2": {"enabled": True, "process_id": 10, "router_id": "203.0.113.10",
                       "passive_interfaces": [], "networks": []},
            "ospfv3": {"enabled": True, "process_id": 20, "router_id": "203.0.113.20",
                       "passive_interfaces": [], "interfaces": []},
            "ripv2": {"enabled": True, "version": 2, "networks": []},
            "bgp": {"enabled": True, "local_asn": 64512, "router_id": "203.0.113.30",
                    "neighbors": [], "networks": {"ipv4": [], "ipv6": []}},
        }
        self.assertEqual(m.validate_new_device(form, self.data), {})
        self.assertEqual(m.build_new_device(form), expected)

    def test_unselected_protocol_fields_do_not_enable_or_inject_configuration(self):
        form = self.form(ospfv2_process_id="not a number", bgp_local_asn="999999999999",
                         ospfv2_router_id="invalid", bgp_router_id="invalid",
                         interfaces={"Ethernet1": {"shutdown": True}}, password="synthetic-marker")
        self.assertEqual(m.validate_new_device(form, self.data), {})
        self.assertEqual(m.build_new_device(form), self.expected_record())


class InventoryLoadingAndDisplay(InventoryFixture):
    def test_display_loader_accepts_documented_mapping_wrapper_and_list_formats(self):
        records = {"devices": {"FIXTURE": {"hostname": "FIXTURE"}}}
        for source, expected in ((records, records), ({"inventory": records}, records),
                                 ([{"hostname": "FIXTURE"}], [{"hostname": "FIXTURE"}]),
                                 ({"devices": [{"hostname": "FIXTURE"}]},
                                  {"devices": [{"hostname": "FIXTURE"}]})):
            with self.subTest(source=source):
                self.path.write_text(yaml.safe_dump(source), encoding="utf-8")
                self.assertEqual(m.load_inventory(self.path), expected)

    def test_display_loader_returns_none_for_unavailable_or_invalid_documents(self):
        self.assertIsNone(m.load_inventory(self.root / "missing.yml"))
        self.assertIsNone(m.load_inventory(self.path.parent))
        for content in (b"", b"null\n", b"true\n", b"42\n", b"devices: broken\n",
                        b"devices: [\n", b"\xff\xfe"):
            with self.subTest(content=content):
                self.path.write_bytes(content)
                self.assertIsNone(m.load_inventory(self.path))
        with patch.object(Path, "open", side_effect=PermissionError("fixture-permission")):
            self.assertIsNone(m.load_inventory(self.path))

    def test_writable_loader_rejects_unsupported_record_types_and_ambiguous_yaml(self):
        cases = ("devices: []\n", "devices: {}\n", "devices:\n  R1: null\n",
                 "devices:\n  42: {}\n", "devices:\n  R1: {}\n  R1: {}\n",
                 "devices:\n  R1:\n    hostname: R1\n    hostname: R2\n",
                 "devices:\n  ? [R1, R2]\n  : {}\n")
        for content in cases:
            with self.subTest(content=content):
                self.path.write_text(content, encoding="utf-8")
                with self.assertRaises(m.InventoryWriteError):
                    m._read_writable_inventory(self.path)
        self.assertEqual(self.backups(), [])

    def test_writable_loader_returns_exact_bytes_and_rejects_symlink(self):
        original, inventory, node = m._read_writable_inventory(self.path)
        self.assertEqual(original, self.original)
        self.assertEqual(inventory, self.data)
        self.assertEqual(node.start_mark.column, 2)
        link = self.path.parent / "link.yml"
        link.symlink_to(self.path)
        with self.assertRaisesRegex(m.InventoryWriteError, "regular file"):
            m._read_writable_inventory(link)

    def test_normalization_maps_network_fields_and_filters_private_unknown_fields(self):
        inventory = {"network": {"defaults": {"vendor": "Arista", "platform": "cEOSLab",
                                               "template": "templates/arista_ceos.j2"}}, "devices": {
            "ASSET-7": {"hostname": " EDGE-7 ", "role": "border_router",
                        "management": {"ipv4": "192.0.2.7", "ipv6": "2001:db8::7", "interface": "Management0"},
                        "interfaces": {"Vlan20": {"description": " Host VLAN ",
                            "addresses": {"ipv4": [{"address": "198.51.100.1", "prefix_length": 24}],
                                          "ipv6": ["2001:db8:20::1/64"]},
                            "peer": {"device": "S2", "interface": "Ethernet3"}}},
                        "routing": {"ospfv2": {"enabled": True}, "ospfv3": "disabled", "ripv2": False,
                                    "bgp": {"enabled": True, "local_asn": 64512, "router_id": "203.0.113.7",
                                            "neighbors": [{"address": "192.0.2.8", "remote_asn": 64513,
                                                           "transport_address_family": "ipv4"}]}},
                        "redistribution": [{"source_protocol": "rip", "destination_protocol": "ospf",
                                            "route_map": "RIP-TO-OSPF"}],
                        "policy": {"prefix_lists": {"ipv4": {"HOSTS": [{"sequence": 10, "action": "permit",
                                              "prefix": "198.51.100.0/24", "le": 32, "token": "hidden-marker"}]}},
                                   "route_maps": {"RIP-TO-OSPF": [{"sequence": 10, "action": "permit",
                                             "match": ["ip address prefix-list HOSTS"], "set": ["metric 20"]}]}},
                        "vlans": {20: {"name": "Hosts", "svi": "Vlan20", "member_interfaces": ["Ethernet2"],
                                       "svi_ipv4": ["198.51.100.1/24"], "svi_ipv6": ["2001:db8:20::1/64"]}},
                        "password": "hidden-marker", "raw_config": "hidden-marker"}}}
        expected = [{"hostname": "EDGE-7", "kind": "router", "role": "Border router", "vendor": "Arista",
                     "platform": "cEOSLab", "template": "templates/arista_ceos.j2", "management_ip": "192.0.2.7",
                     "management_ipv6": "2001:db8::7", "management_interface": "Management0",
                     "protocols": [{"name": "ospfv2", "label": "OSPFv2", "enabled": True},
                                   {"name": "ospfv3", "label": "OSPFv3", "enabled": False},
                                   {"name": "ripv2", "label": "RIP", "enabled": False},
                                   {"name": "bgp", "label": "BGP", "enabled": True}],
                     "interfaces": [{"name": "Vlan20", "description": "Host VLAN", "ipv4": ["198.51.100.1/24"],
                                     "ipv6": ["2001:db8:20::1/64"], "peer_device": "S2",
                                     "peer_interface": "Ethernet3", "vlans": ["VLAN 20"]}],
                     "bgp": {"asn": "64512", "router_id": "203.0.113.7", "neighbors": [
                         {"address": "192.0.2.8", "remote_asn": "64513", "address_family": "ipv4"}]},
                     "redistribution": [{"source": "rip", "destination": "ospf", "route_map": "RIP-TO-OSPF", "qualifiers": None}],
                     "prefix_lists": [{"name": "HOSTS", "family": "ipv4", "entries": [
                         {"sequence": "10", "action": "permit", "prefix": "198.51.100.0/24", "ge": None, "le": "32"}]}],
                     "route_maps": [{"name": "RIP-TO-OSPF", "entries": [{"sequence": "10", "action": "permit",
                                     "match": ["ip address prefix-list HOSTS"], "set": ["metric 20"]}]}],
                     "vlans": [{"id": "20", "name": "Hosts", "svi": "Vlan20", "interfaces": ["Ethernet2"],
                                "ipv4": ["198.51.100.1/24"], "ipv6": ["2001:db8:20::1/64"]}]}]
        original = deepcopy(inventory)
        self.assertEqual(m.normalize_inventory(inventory), expected)
        self.assertEqual(inventory, original)

    def test_normalization_skips_unnamed_records_and_does_not_invent_unknown_values(self):
        inventory = {"devices": [None, "bad record", {}, {"hostname": "S9", "role": "access_switch",
                       "vendor": {"unexpected": "object"}, "management": ["192.0.2.9"],
                       "routing": {"ospfv2": {"enabled": "unknown"}, "bgp": {"enabled": False}},
                       "interfaces": [{"name": "Ethernet1", "switchport": {"access_vlan": 20,
                           "trunk_allowed_vlans": [20, 30]}, "ipv4": True}, {"description": "no name"}]}]}
        result = m.normalize_inventory(inventory)
        self.assertEqual(len(result), 1)
        device = result[0]
        self.assertEqual((device["hostname"], device["kind"], device["role"]), ("S9", "switch", "Access switch"))
        self.assertIsNone(device["vendor"])
        self.assertIsNone(device["management_ip"])
        self.assertIsNone(device["bgp"])
        self.assertIsNone(device["protocols"][0]["enabled"])
        self.assertEqual(device["interfaces"], [{"name": "Ethernet1", "description": None,
                         "ipv4": [], "ipv6": [], "peer_device": None, "peer_interface": None,
                         "vlans": ["Access VLAN 20", "Trunk VLANs 20, 30"]}])


class InventoryPersistence(InventoryFixture):
    def test_add_persists_exact_record_preserves_original_bytes_and_private_backup(self):
        self.path.chmod(0o640)
        record, backup = m.save_inventory_safely(self.form())
        expected = deepcopy(self.data)
        expected["devices"]["LAB-R3"] = self.expected_record()
        self.assertEqual(record, self.expected_record())
        self.assertEqual(yaml.safe_load(self.path.read_bytes()), expected)
        before, after = self.original.split(b"metadata:\n", 1)
        updated = self.path.read_bytes()
        self.assertTrue(updated.startswith(before))
        self.assertTrue(updated.endswith(b"metadata:\n" + after))
        self.assertEqual(backup.parent, self.path.parent / "backups")
        self.assertEqual(backup.read_bytes(), self.original)
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o640)
        self.assertEqual(list(self.path.parent.glob(".devices-*.yml.tmp")), [])

    def test_add_preserves_crlf_and_valid_yaml_without_final_newline(self):
        for ending in ("crlf", "no-final-newline"):
            with self.subTest(ending=ending):
                content = INVENTORY.replace("\n", "\r\n").encode() if ending == "crlf" else INVENTORY.rstrip("\n").encode()
                self.path.write_bytes(content)
                # Avoid same-second backup collisions between independent cases.
                for backup in self.backups():
                    backup.unlink()
                m.save_inventory_safely(self.form())
                self.assertEqual(yaml.safe_load(self.path.read_bytes())["devices"]["LAB-R3"], self.expected_record())
                self.assertEqual(self.backups()[0].read_bytes(), content)
                if ending == "crlf":
                    self.assertNotIn(b"\n", self.path.read_bytes().replace(b"\r\n", b""))

    def test_remove_preserves_surviving_interfaces_routing_anchors_and_metadata(self):
        backup = m.remove_device_safely("R2")
        removed = b"  R2:\n    hostname: R2\n    management: {ipv4: 192.0.2.2}\n    interfaces: {}\n"
        expected = deepcopy(self.data)
        del expected["devices"]["R2"]
        self.assertEqual(self.path.read_bytes(), self.original.replace(removed, b""))
        self.assertEqual(yaml.safe_load(self.path.read_bytes()), expected)
        self.assertEqual(backup.read_bytes(), self.original)

    def test_remove_existing_last_entry_without_final_newline(self):
        # A missing final newline is valid YAML, not an unsupported schema.
        original = b"devices:\n  R1:\n    hostname: R1\n  R2:\n    hostname: R2"
        self.path.write_bytes(original)
        try:
            backup = m.remove_device_safely("R2")
        except m.InventoryWriteError as error:
            self.fail(f"Removing an existing device from valid YAML without a final newline was rejected: {error}")
        self.assertEqual(yaml.safe_load(self.path.read_bytes()), {"devices": {"R1": {"hostname": "R1"}}})
        self.assertEqual(backup.read_bytes(), original)

    def test_duplicate_or_invalid_registration_never_creates_backup(self):
        for fields, error_field in (({"hostname": "r1"}, "hostname"),
                                    ({"management_ip": "192.0.2.2"}, "management_ip"),
                                    ({"hostname": "../bad"}, "hostname")):
            with self.subTest(fields=fields):
                with self.assertRaises(m.DeviceValidationError) as caught:
                    m.save_inventory_safely(self.form(**fields))
                self.assertIn(error_field, caught.exception.errors)
                self.assert_unchanged()
                self.assertEqual(self.backups(), [])

    def test_nonexistent_and_last_device_removal_are_refused_without_backup(self):
        with self.assertRaisesRegex(m.InventoryWriteError, "not found"):
            m.remove_device_safely("MISSING")
        self.assert_unchanged()
        last = b"devices:\n  R1:\n    hostname: R1\n"
        self.path.write_bytes(last)
        with self.assertRaisesRegex(m.InventoryWriteError, "last remaining"):
            m.remove_device_safely("R1")
        self.assert_unchanged(last)
        self.assertEqual(self.backups(), [])

    def test_validation_is_repeated_against_current_inventory_under_write_lock(self):
        self.assertEqual(m.validate_new_device(self.form(), self.data), {})
        edited = deepcopy(self.data)
        edited["devices"]["OTHER"] = {"management": {"ipv4": "192.0.2.3"}}
        content = yaml.safe_dump(edited, sort_keys=False).encode()
        self.path.write_bytes(content)
        with self.assertRaises(m.DeviceValidationError) as caught:
            m.save_inventory_safely(self.form())
        self.assertIn("management_ip", caught.exception.errors)
        self.assert_unchanged(content)
        self.assertEqual(self.backups(), [])

    def test_backup_exists_and_candidate_is_complete_before_atomic_publication(self):
        replace = os.replace
        def inspect_and_replace(source, destination):
            self.assertEqual(Path(destination), self.path)
            self.assertEqual(self.path.read_bytes(), self.original)
            self.assertEqual(len(self.backups()), 1)
            self.assertEqual(self.backups()[0].read_bytes(), self.original)
            candidate = yaml.safe_load(Path(source).read_bytes())
            self.assertEqual(candidate["devices"]["LAB-R3"], self.expected_record())
            return replace(source, destination)
        with patch.object(m.os, "replace", side_effect=inspect_and_replace) as publish:
            m.save_inventory_safely(self.form())
        publish.assert_called_once()

    def test_backup_failure_prevents_both_add_and_remove(self):
        for action in (lambda: m.save_inventory_safely(self.form()), lambda: m.remove_device_safely("R2")):
            with self.subTest(action=action), patch.object(m, "create_nsot_backup", side_effect=PermissionError("private-marker")):
                with self.assertRaises(m.InventoryWriteError) as caught:
                    action()
                self.assertNotIn("private-marker", str(caught.exception))
                self.assert_unchanged()

    def test_write_permission_failure_leaves_original_and_removes_temporary_file(self):
        for action in (lambda: m.save_inventory_safely(self.form()), lambda: m.remove_device_safely("R2")):
            with self.subTest(action=action):
                for backup in self.backups():
                    backup.unlink()
                with patch.object(m.os, "fchmod", side_effect=PermissionError("private-marker")):
                    with self.assertRaises(m.InventoryWriteError) as caught:
                        action()
                self.assertNotIn("private-marker", str(caught.exception))
                self.assert_unchanged()
                self.assertEqual(self.backups()[0].read_bytes(), self.original)

    def test_atomic_replace_failure_leaves_original_and_cleans_candidate(self):
        for action in (lambda: m.save_inventory_safely(self.form()), lambda: m.remove_device_safely("R2")):
            with self.subTest(action=action):
                for backup in self.backups():
                    backup.unlink()
                with patch.object(m.os, "replace", side_effect=PermissionError("private-marker")):
                    with self.assertRaises(m.InventoryWriteError):
                        action()
                self.assert_unchanged()

    def test_corrupt_temporary_yaml_cannot_replace_inventory(self):
        mkstemp = tempfile.mkstemp
        read_open = Path.open
        candidate = []
        def create(*args, **kwargs):
            descriptor, name = mkstemp(*args, **kwargs)
            candidate.append(Path(name))
            return descriptor, name
        def corrupt_before_validation(path, *args, **kwargs):
            if candidate and path == candidate[0] and kwargs.get("encoding") == "utf-8":
                with read_open(path, "wb") as stream:
                    stream.write(b"devices: [\n")
            return read_open(path, *args, **kwargs)
        with patch.object(m.tempfile, "mkstemp", side_effect=create), patch.object(Path, "open", corrupt_before_validation):
            with self.assertRaises(m.InventoryWriteError):
                m.save_inventory_safely(self.form())
        self.assert_unchanged()

    def test_uncoordinated_editor_changes_after_backup_are_not_overwritten(self):
        create_backup = m.create_nsot_backup
        for remove in (False, True):
            with self.subTest(remove=remove):
                self.path.write_bytes(self.original)
                for backup in self.backups():
                    backup.unlink()
                edited = self.original + b"# concurrent editor update\n"
                def backup_and_edit(original, path):
                    backup = create_backup(original, path)
                    path.write_bytes(edited)
                    return backup
                with patch.object(m, "create_nsot_backup", side_effect=backup_and_edit):
                    with self.assertRaisesRegex(m.InventoryWriteError, "inventory changed"):
                        m.remove_device_safely("R2") if remove else m.save_inventory_safely(self.form())
                self.assert_unchanged(edited)
                self.assertEqual(self.backups()[0].read_bytes(), self.original)

    def test_invalid_paths_and_malformed_input_fail_without_backups(self):
        cases = (self.root / "missing-directory" / "devices.yml", self.path.parent,
                 self.path.parent / "missing.yml")
        for path in cases:
            with self.subTest(path=path), self.assertRaises(m.InventoryWriteError):
                m.save_inventory_safely(self.form(), path)
        self.assert_unchanged()
        self.assertEqual(self.backups(), [])
        for content in (b"", b"devices: [\n", b"devices:\n  R1: true\n", b"\xff\xfe"):
            with self.subTest(content=content):
                self.path.write_bytes(content)
                with self.assertRaises(m.InventoryWriteError):
                    m.save_inventory_safely(self.form())
                self.assert_unchanged(content)
                self.assertEqual(self.backups(), [])

    def test_symlink_inventory_and_backup_directory_are_never_followed_for_writes(self):
        target = self.root / "untouched.yml"
        target.write_bytes(self.original)
        self.path.unlink()
        self.path.symlink_to(target)
        with self.assertRaises(m.InventoryWriteError):
            m.save_inventory_safely(self.form())
        self.assertEqual(target.read_bytes(), self.original)
        self.path.unlink()
        self.path.write_bytes(self.original)
        outside = self.root / "outside-backups"
        outside.mkdir()
        (self.path.parent / "backups").symlink_to(outside)
        with self.assertRaises(m.InventoryWriteError):
            m.save_inventory_safely(self.form())
        self.assertEqual(list(outside.iterdir()), [])
        self.assert_unchanged()

    def test_backup_collision_cannot_overwrite_existing_copy(self):
        fixed = datetime(2026, 10, 19, 12, 34, 56)
        with patch.object(m, "datetime") as clock:
            clock.now.return_value = fixed
            backup = m.create_nsot_backup(self.original, self.path)
            self.assertEqual(backup.name, "devices_20261019_123456.yml")
            with self.assertRaisesRegex(m.InventoryWriteError, "already created"):
                m.create_nsot_backup(b"different content", self.path)
        self.assertEqual(backup.read_bytes(), self.original)
        self.assert_unchanged()

    def test_backup_fsync_failure_removes_incomplete_copy(self):
        with patch.object(m.os, "fsync", side_effect=OSError("synthetic disk failure")):
            with self.assertRaises(OSError):
                m.create_nsot_backup(self.original, self.path)
        self.assertEqual(self.backups(), [])
        self.assert_unchanged()

    def test_postcommit_directory_flush_failure_reports_actual_persisted_success(self):
        replace = os.replace
        fsync = os.fsync
        committed = False
        def publish(source, destination):
            nonlocal committed
            replace(source, destination)
            committed = True
        def flush(descriptor):
            if committed:
                raise OSError("synthetic directory flush failure")
            return fsync(descriptor)
        with patch.object(m.os, "replace", side_effect=publish), patch.object(m.os, "fsync", side_effect=flush):
            record, backup = m.save_inventory_safely(self.form())
        self.assertEqual(record, self.expected_record())
        self.assertEqual(yaml.safe_load(self.path.read_bytes())["devices"]["LAB-R3"], self.expected_record())
        self.assertEqual(backup.read_bytes(), self.original)


class InventoryRoutes(InventoryFixture):
    def test_add_route_uses_normalized_form_and_persists_only_after_csrf(self):
        response = self.client.post("/devices/add", data=self.form())
        self.assertEqual(response.status_code, 400)
        self.assert_unchanged()
        self.assertEqual(self.backups(), [])
        with self.client.session_transaction() as session:
            token = session["add_device_csrf"]
        form = self.form(hostname=" LAB-R3 ", management_ip=" 192.0.2.3 ", csrf_token=token)
        response = self.client.post("/devices/add", data=form)
        self.assertEqual(response.status_code, 303)
        self.assertTrue(response.headers["Location"].endswith("/devices/LAB-R3"))
        self.assertEqual(yaml.safe_load(self.path.read_bytes())["devices"]["LAB-R3"], self.expected_record())
        self.assertEqual(self.backups()[0].read_bytes(), self.original)

    def test_remove_route_requires_token_then_removes_only_requested_device(self):
        response = self.client.post("/devices/R2/remove", data={"csrf_token": "wrong"})
        self.assertEqual(response.status_code, 303)
        self.assert_unchanged()
        self.assertEqual(self.backups(), [])
        with self.client.session_transaction() as session:
            session["remove_device_csrf"] = "fixture-token"
        response = self.client.post("/devices/R2/remove", data={"csrf_token": "fixture-token"})
        self.assertEqual(response.status_code, 303)
        expected = deepcopy(self.data)
        del expected["devices"]["R2"]
        self.assertEqual(yaml.safe_load(self.path.read_bytes()), expected)
        self.assertEqual(self.backups()[0].read_bytes(), self.original)
        with self.client.session_transaction() as session:
            self.assertNotIn("remove_device_csrf", session)

    def test_add_route_reports_storage_failure_without_false_success_or_exception_data(self):
        with self.client.session_transaction() as session:
            session["add_device_csrf"] = "fixture-token"
        with patch.object(m.os, "replace", side_effect=PermissionError("synthetic-private-marker")):
            response = self.client.post("/devices/add", data=self.form(csrf_token="fixture-token"))
        self.assertEqual(response.status_code, 503)
        self.assertIn(b"could not be saved safely", response.data)
        self.assertNotIn(b"has been added", response.data)
        self.assertNotIn(b"synthetic-private-marker", response.data)
        self.assert_unchanged()


if __name__ == "__main__":
    unittest.main()

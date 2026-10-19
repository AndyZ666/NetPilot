"""Offline renderer contracts using synthetic NSOT data and real Jinja templates.

Expected commands are literal network configurations, never renderer-derived.
The renderer is a serializer, not an IP/schema validator: unsupported address
and field validation is reported separately rather than pinned as desired behavior.
"""

from copy import deepcopy
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from jinja2 import Environment, FileSystemLoader, StrictUndefined, TemplateNotFound
from jinja2 import TemplateSyntaxError, UndefinedError
import yaml

import render_configs as renderer


TEMPLATES = Path(__file__).resolve().parents[1] / "templates"


def arista_device():
    return {
        "hostname": "EDGE-A", "template": "templates/arista_ceos.j2",
        "interfaces": {}, "vlans": {}, "redistribution": [],
        "policy": {"prefix_lists": {"ipv4": {}, "ipv6": {}}, "route_maps": {}},
        "routing": {name: {"enabled": False} for name in ("ospfv2", "ospfv3", "ripv2", "bgp")},
    }


def cisco_device():
    return {
        "hostname": "DEMO-C", "template": "templates/cisco_iosxe.j2",
        "interfaces": {},
        "routing": {"ospf": {"enabled": False}, "bgp": {"enabled": False}},
    }


def interface(**values):
    record = {"description": None, "forwarding_model": "routed", "ipv4": [],
              "ipv6": [], "admin_state": "up"}
    record.update(values)
    return record


def command_lines(text):
    # Ignore template comments and blank lines, but retain indentation/context.
    return [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("!")]


class RenderingTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="netpilot-render-tests-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.inventory_path = self.root / "devices.yml"
        self.output_dir = self.root / "generated"
        self.env = Environment(loader=FileSystemLoader(str(TEMPLATES)),
                               undefined=StrictUndefined, lstrip_blocks=True,
                               keep_trailing_newline=True)
        self.inventory = {"devices": {"EDGE-A": arista_device()},
                          "network": {"defaults": {"template": "templates/arista_ceos.j2"}}}
        for name, value in (("DEFAULT_INVENTORY", self.inventory_path),
                            ("DEFAULT_OUTPUT_DIR", self.output_dir),
                            ("DEFAULT_TEMPLATE_DIR", TEMPLATES)):
            self.enterContext(patch.object(renderer, name, value))
        self.stdout = self.enterContext(patch("sys.stdout", new_callable=io.StringIO))
        self.stderr = self.enterContext(patch("sys.stderr", new_callable=io.StringIO))
        for target in ("socket.socket.connect", "socket.create_connection", "subprocess.run",
                       "security.credential_provider.get_credentials", "netmiko.ConnectHandler"):
            guard = self.enterContext(patch(target, side_effect=AssertionError("External operation forbidden")))
            self.addCleanup(guard.assert_not_called)

    def render(self, hostname="EDGE-A"):
        return renderer.render_device(self.env, self.inventory, hostname)

    def write_inventory(self):
        self.inventory_path.write_text(yaml.safe_dump(self.inventory, sort_keys=False), encoding="utf-8")

    def cli(self, *arguments):
        with patch("sys.argv", ["render_configs.py", *arguments]):
            return renderer.main()

    def test_load_yaml_preserves_nested_values_types_and_aliases(self):
        self.inventory_path.write_text(
            "defaults: &ports {ipv4: ['198.51.100.1/31'], enabled: true, area: 0}\n"
            "devices: {EDGE-A: {interfaces: *ports}}\n", encoding="utf-8")
        actual = renderer.load_yaml(self.inventory_path)
        self.assertEqual(actual["devices"]["EDGE-A"]["interfaces"],
                         {"ipv4": ["198.51.100.1/31"], "enabled": True, "area": 0})
        self.assertIs(actual["defaults"], actual["devices"]["EDGE-A"]["interfaces"])

    def test_load_yaml_missing_file_and_directory_raise_file_errors(self):
        for path, error in ((self.inventory_path, FileNotFoundError), (self.root, IsADirectoryError)):
            with self.subTest(path=path), self.assertRaises(error):
                renderer.load_yaml(path)

    def test_load_yaml_invalid_syntax_raises_parser_error(self):
        self.inventory_path.write_text("devices: [unterminated\n", encoding="utf-8")
        with self.assertRaises(yaml.YAMLError):
            renderer.load_yaml(self.inventory_path)

    def test_arista_identity_selection_and_input_are_preserved(self):
        other = arista_device()
        other["hostname"] = "EDGE-B"
        self.inventory["devices"]["EDGE-B"] = other
        before = deepcopy(self.inventory)
        output = self.render("EDGE-B")
        self.assertIn("! Device: EDGE-B\n", output)
        self.assertEqual(command_lines(output), ["hostname EDGE-B", "end"])
        self.assertNotIn("EDGE-A", output)
        self.assertEqual(self.inventory, before)
        self.assertTrue(output.endswith("end\n"))
        self.assertFalse(output.endswith("\n\n"))

    def test_arista_interface_addresses_prefixes_and_shutdown_states(self):
        self.inventory["devices"]["EDGE-A"]["interfaces"] = {
            "Management0": interface(description="Lab management", ipv4=["192.0.2.10/24"]),
            "Ethernet1": interface(description="Core uplink", ipv4=["198.51.100.1/31"],
                                   ipv6=["2001:db8:12::1/64"]),
            "Ethernet2": interface(description="Spare uplink", admin_state="down"),
        }
        self.assertEqual(command_lines(self.render()), [
            "hostname EDGE-A", "interface Management0", "   description Lab management",
            "   ip address 192.0.2.10/24", "   no shutdown",
            "interface Ethernet1", "   description Core uplink", "   no switchport",
            "   ip address 198.51.100.1/31", "   ipv6 address 2001:db8:12::1/64", "   no shutdown",
            "interface Ethernet2", "   description Spare uplink", "   no switchport", "   shutdown", "end",
        ])

    def test_arista_loopback_host_prefixes_do_not_emit_switchport_commands(self):
        # EOS documents loopback mode separately from switched/routed ports:
        # https://www.arista.com/en/um-eos/eos-data-transfer (interface loopback).
        # A software loopback has no Layer-2 switchport mode to disable.
        self.inventory["devices"]["EDGE-A"]["interfaces"] = {
            "Loopback7": interface(ipv4=["203.0.113.9/32"], ipv6=["2001:db8::9/128"]),
        }
        self.assertEqual(command_lines(self.render()), [
            "hostname EDGE-A", "interface Loopback7", "   ip address 203.0.113.9/32",
            "   ipv6 address 2001:db8::9/128", "   no shutdown", "end",
        ])

    def test_arista_vlan_access_trunk_and_svi_mapping(self):
        device = self.inventory["devices"]["EDGE-A"]
        device["vlans"] = {17: {"name": "LAB-USERS"}, 29: {"name": None}}
        device["interfaces"] = {
            "Ethernet3": interface(forwarding_model="bridged", switchport={"mode": "access", "access_vlan": 17}),
            "Ethernet4": interface(forwarding_model="bridged", switchport={"mode": "trunk", "trunk_allowed_vlans": [17, 29]}),
            "Vlan17": interface(ipv4=["192.0.2.1/24"], ipv6=["2001:db8:17::1/64"]),
        }
        self.assertEqual(command_lines(self.render()), [
            "hostname EDGE-A", "vlan 17", "   name LAB-USERS", "vlan 29",
            "interface Ethernet3", "   switchport mode access", "   switchport access vlan 17", "   no shutdown",
            "interface Ethernet4", "   switchport mode trunk", "   switchport trunk allowed vlan 17,29", "   no shutdown",
            "interface Vlan17", "   ip address 192.0.2.1/24", "   ipv6 address 2001:db8:17::1/64", "   no shutdown", "end",
        ])

    def test_arista_ospfv2_process_network_area_and_redistribution(self):
        device = self.inventory["devices"]["EDGE-A"]
        device["routing"]["ospfv2"] = {
            "enabled": True, "process_id": 27, "router_id": "203.0.113.9",
            "networks": [{"prefix": "198.51.100.0/31", "area": "0.0.0.7"}],
            "passive_interfaces": ["Loopback7"],
        }
        device["redistribution"] = [
            {"destination_protocol": "ospfv2", "configuration_statement": "redistribute rip route-map ACCESS-IN"},
            {"destination_protocol": "rip", "configuration_statement": "redistribute ospf metric 4"},
        ]
        self.assertEqual(command_lines(self.render()), [
            "hostname EDGE-A", "router ospf 27", "   router-id 203.0.113.9",
            "   network 198.51.100.0/31 area 0.0.0.7", "   passive-interface Loopback7",
            "   redistribute rip route-map ACCESS-IN", "end",
        ])

    def test_arista_ospfv3_binds_only_selected_interfaces(self):
        device = self.inventory["devices"]["EDGE-A"]
        device["interfaces"] = {"Ethernet1": interface(), "Ethernet2": interface()}
        device["routing"]["ospfv3"] = {
            "enabled": True, "process_id": 31, "router_id": "203.0.113.19",
            "interfaces": [{"name": "Ethernet2", "area": "0.0.0.9"}],
            "passive_interfaces": ["Loopback7"],
        }
        device["redistribution"] = [{"destination_protocol": "ospfv3",
                                      "configuration_statement": "redistribute connected route-map V6-LOCAL"}]
        self.assertEqual(command_lines(self.render()), [
            "hostname EDGE-A", "interface Ethernet1", "   no switchport", "   no shutdown",
            "interface Ethernet2", "   no switchport", "   ipv6 ospf 31 area 0.0.0.9", "   no shutdown",
            "ipv6 router ospf 31", "   router-id 203.0.113.19", "   passive-interface Loopback7",
            "   redistribute connected route-map V6-LOCAL", "end",
        ])

    def test_arista_rip_networks_and_destination_scoped_redistribution(self):
        device = self.inventory["devices"]["EDGE-A"]
        device["routing"]["ripv2"] = {"enabled": True, "networks": ["10.0.0.0/8", "192.0.2.0/24"]}
        device["redistribution"] = [{"destination_protocol": "rip",
                                      "configuration_statement": "redistribute ospf match internal route-map CORE-OUT"}]
        self.assertEqual(command_lines(self.render()), [
            "hostname EDGE-A", "router rip", "   network 10.0.0.0/8", "   network 192.0.2.0/24",
            "   redistribute ospf match internal route-map CORE-OUT", "end",
        ])

    def test_arista_bgp_asns_dual_stack_neighbors_and_advertised_networks(self):
        self.inventory["devices"]["EDGE-A"]["routing"]["bgp"] = {
            "enabled": True, "local_asn": 65051, "router_id": "203.0.113.9",
            "neighbors": [
                {"address": "198.51.100.0", "remote_asn": 65052, "transport_address_family": "ipv4"},
                {"address": "2001:db8:12::2", "remote_asn": 65053, "transport_address_family": "ipv6"},
            ],
            "networks": {"ipv4": [{"prefix": "203.0.113.0/24", "route_map": "EXPORT-V4"},
                                  {"prefix": "192.0.2.0/24", "route_map": None}],
                         "ipv6": [{"prefix": "2001:db8:feed::/48", "route_map": "EXPORT-V6"}]},
        }
        self.assertEqual(command_lines(self.render()), [
            "hostname EDGE-A", "router bgp 65051", "   router-id 203.0.113.9",
            "   neighbor 198.51.100.0 remote-as 65052", "   neighbor 2001:db8:12::2 remote-as 65053",
            "   address-family ipv4", "   neighbor 198.51.100.0 activate",
            "   network 203.0.113.0/24 route-map EXPORT-V4", "   network 192.0.2.0/24",
            "   address-family ipv6", "   neighbor 2001:db8:12::2 activate",
            "   network 2001:db8:feed::/48 route-map EXPORT-V6", "end",
        ])

    def test_arista_prefix_lists_and_route_maps_keep_sequences_and_actions(self):
        self.inventory["devices"]["EDGE-A"]["policy"] = {
            "prefix_lists": {
                "ipv4": {"V4-HOSTS": [
                    {"sequence": 15, "action": "permit", "prefix": "198.51.100.0/24", "ge": 25, "le": 28},
                    {"sequence": 90, "action": "deny", "prefix": "0.0.0.0/0", "ge": None, "le": 32}]},
                "ipv6": {"V6-HOSTS": [{"sequence": 25, "action": "permit", "prefix": "2001:db8::/32", "ge": 48, "le": 64}]},
            },
            "route_maps": {"EXPORT-V4": [
                {"action": "permit", "sequence": 10, "match": ["ip address prefix-list V4-HOSTS"],
                 "set": ["metric 42", "tag 123"], "other_statements": ["description Export lab prefixes"]},
                {"action": "deny", "sequence": 20, "match": [], "set": [], "other_statements": []}]},
        }
        self.assertEqual(command_lines(self.render()), [
            "hostname EDGE-A", "ip prefix-list V4-HOSTS seq 15 permit 198.51.100.0/24 ge 25 le 28",
            "ip prefix-list V4-HOSTS seq 90 deny 0.0.0.0/0 le 32",
            "ipv6 prefix-list V6-HOSTS seq 25 permit 2001:db8::/32 ge 48 le 64",
            "route-map EXPORT-V4 permit 10", "   match ip address prefix-list V4-HOSTS",
            "   set metric 42", "   set tag 123", "   description Export lab prefixes",
            "route-map EXPORT-V4 deny 20", "end",
        ])

    def test_arista_disabled_protocols_and_empty_collections_emit_no_commands(self):
        device = self.inventory["devices"]["EDGE-A"]
        for protocol in device["routing"].values():
            protocol.update(process_id=99, local_asn=65099, router_id="192.0.2.99")
        self.assertEqual(command_lines(self.render()), ["hostname EDGE-A", "end"])

    def test_cisco_interfaces_use_ip_netmask_pairs_and_admin_states(self):
        device = cisco_device()
        device["interfaces"] = {
            "GigabitEthernet1": {"description": "Demo transit", "ipv4": [{"ip": "198.51.100.2", "mask": "255.255.255.254"}], "admin_state": "up"},
            "Loopback4": {"description": None, "ipv4": [{"ip": "203.0.113.4", "mask": "255.255.255.255"}], "admin_state": "down"},
        }
        self.inventory["devices"] = {"DEMO-C": device}
        output = self.render("DEMO-C")
        self.assertIn("Cisco IOS-XE template demonstration", output)
        self.assertEqual(command_lines(output), [
            "hostname DEMO-C", "interface GigabitEthernet1", " description Demo transit",
            " ip address 198.51.100.2 255.255.255.254", " no shutdown",
            "interface Loopback4", " ip address 203.0.113.4 255.255.255.255", " shutdown", "end",
        ])

    def test_cisco_ospf_and_ipv4_bgp_parameter_mapping(self):
        device = cisco_device()
        device["interfaces"] = {"GigabitEthernet1": {"description": None, "ipv4": [], "admin_state": "up", "ospf_area": 7}}
        device["routing"] = {
            "ospf": {"enabled": True, "process_id": 41, "router_id": "203.0.113.4"},
            "bgp": {"enabled": True, "local_asn": 65101, "router_id": "203.0.113.14",
                    "neighbors": [{"address": "198.51.100.3", "remote_asn": 65102}]},
        }
        self.inventory["devices"] = {"DEMO-C": device}
        self.assertEqual(command_lines(self.render("DEMO-C")), [
            "hostname DEMO-C", "interface GigabitEthernet1", " ip ospf 41 area 7", " no shutdown",
            "router ospf 41", " router-id 203.0.113.4", "router bgp 65101",
            " bgp router-id 203.0.113.14", " neighbor 198.51.100.3 remote-as 65102",
            " address-family ipv4", "  neighbor 198.51.100.3 activate", " exit-address-family", "end",
        ])

    def test_device_template_override_and_default_fallback(self):
        self.inventory["network"]["defaults"]["template"] = "templates/cisco_iosxe.j2"
        self.assertNotIn("Cisco IOS-XE", self.render())
        device = cisco_device()
        del device["template"]
        self.inventory["devices"]["DEMO-C"] = device
        output = self.render("DEMO-C")
        self.assertIn("Cisco IOS-XE template demonstration", output)
        self.assertEqual(command_lines(output), ["hostname DEMO-C", "end"])

    def test_unknown_device_cannot_render_another_device(self):
        with self.assertRaisesRegex(KeyError, "UNKNOWN.*not found"):
            self.render("UNKNOWN")

    def test_missing_required_template_fields_fail_strictly(self):
        for factory, fields in ((arista_device, ("hostname", "interfaces", "routing", "policy", "vlans")),
                                (cisco_device, ("hostname", "interfaces", "routing"))):
            for field in fields:
                with self.subTest(template=factory.__name__, missing=field):
                    device = factory()
                    del device[field]
                    self.inventory["devices"] = {"EDGE-A": device}
                    with self.assertRaises(UndefinedError):
                        self.render()

    def test_non_mapping_interface_collection_cannot_render(self):
        for factory in (arista_device, cisco_device):
            for invalid in (None, [], "Ethernet1"):
                with self.subTest(template=factory.__name__, interfaces=invalid):
                    device = factory()
                    device["interfaces"] = invalid
                    self.inventory["devices"] = {"EDGE-A": device}
                    with self.assertRaises(UndefinedError):
                        self.render()

    def test_cisco_address_record_requires_separate_mask(self):
        device = cisco_device()
        device["interfaces"] = {"GigabitEthernet1": {"description": None, "admin_state": "up", "ipv4": [{"ip": "192.0.2.4"}]}}
        self.inventory["devices"] = {"DEMO-C": device}
        with self.assertRaises(UndefinedError):
            self.render("DEMO-C")

    def test_missing_template_raises_without_fallback(self):
        self.inventory["devices"]["EDGE-A"]["template"] = "templates/absent.j2"
        with self.assertRaises(TemplateNotFound):
            self.render()

    def test_invalid_template_syntax_is_not_rendered(self):
        (self.root / "broken.j2").write_text("{% if %}\nhostname EDGE-A\n", encoding="utf-8")
        env = Environment(loader=FileSystemLoader(str(self.root)), undefined=StrictUndefined)
        self.inventory["devices"]["EDGE-A"]["template"] = "broken.j2"
        with self.assertRaises(TemplateSyntaxError):
            renderer.render_device(env, self.inventory, "EDGE-A")

    def test_main_renders_both_real_templates_to_correct_files(self):
        self.inventory["devices"]["DEMO-C"] = cisco_device()
        self.write_inventory()
        self.assertEqual(self.cli(), 0)
        self.assertEqual({path.name for path in self.output_dir.iterdir()}, {"EDGE-A.cfg", "DEMO-C.cfg"})
        for name in ("EDGE-A", "DEMO-C"):
            output = (self.output_dir / f"{name}.cfg").read_text(encoding="utf-8")
            self.assertEqual(command_lines(output), [f"hostname {name}", "end"])
            self.assertIn(f"! Device: {name}\n", output)
            self.assertTrue(output.endswith("end\n"))
        self.assertIn("Cisco IOS-XE", (self.output_dir / "DEMO-C.cfg").read_text())
        self.assertNotIn("Cisco IOS-XE", (self.output_dir / "EDGE-A.cfg").read_text())
        self.assertIn("Rendered 2 configuration(s).", self.stdout.getvalue())

    def test_main_single_device_uses_explicit_inventory_template_and_output_paths(self):
        self.inventory["devices"]["DEMO-C"] = cisco_device()
        self.write_inventory()
        templates = self.root / "templates"
        templates.mkdir()
        (templates / "cisco_iosxe.j2").write_bytes((TEMPLATES / "cisco_iosxe.j2").read_bytes())
        output = self.root / "nested" / "selected"
        self.assertEqual(self.cli("DEMO-C", "--inventory", str(self.inventory_path),
                                  "--template-dir", str(templates), "--output-dir", str(output)), 0)
        self.assertEqual([path.name for path in output.iterdir()], ["DEMO-C.cfg"])
        self.assertEqual(command_lines((output / "DEMO-C.cfg").read_text()), ["hostname DEMO-C", "end"])
        self.assertFalse(self.output_dir.exists())

    def test_main_render_failure_stops_without_success_or_partial_file(self):
        self.inventory["devices"]["EDGE-A"]["template"] = "absent.j2"
        self.inventory["devices"]["DEMO-C"] = cisco_device()
        self.write_inventory()
        self.assertEqual(self.cli(), 1)
        self.assertEqual(list(self.output_dir.iterdir()), [])
        self.assertIn("[FAIL] EDGE-A", self.stderr.getvalue())
        self.assertNotIn("[OK]", self.stdout.getvalue())
        self.assertNotIn("Rendered", self.stdout.getvalue())

    def test_main_empty_or_missing_devices_refuses_generation(self):
        for inventory in ({"devices": {}}, {"network": {}}):
            with self.subTest(inventory=inventory):
                self.inventory = inventory
                self.write_inventory()
                with self.assertRaisesRegex(RuntimeError, "No devices found"):
                    self.cli()
                self.assertFalse(self.output_dir.exists())

    def test_main_invalid_yaml_does_not_create_output(self):
        self.inventory_path.write_text("devices: [unterminated\n", encoding="utf-8")
        with self.assertRaises(yaml.YAMLError):
            self.cli()
        self.assertFalse(self.output_dir.exists())
        self.assertNotIn("[OK]", self.stdout.getvalue())

    def test_main_output_directory_cannot_be_a_file(self):
        self.write_inventory()
        self.output_dir.write_text("keep original file", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            self.cli()
        self.assertEqual(self.output_dir.read_text(), "keep original file")
        self.assertNotIn("[OK]", self.stdout.getvalue())

    def test_main_write_failures_are_not_reported_as_success(self):
        self.write_inventory()
        original_write = Path.write_text
        for failure in (PermissionError("fixture write denied"), OSError("fixture disk full")):
            with self.subTest(error=type(failure).__name__):
                def fail_output(path, *args, **kwargs):
                    if path == self.output_dir / "EDGE-A.cfg":
                        raise failure
                    return original_write(path, *args, **kwargs)
                with patch.object(Path, "write_text", autospec=True, side_effect=fail_output):
                    with self.assertRaises(type(failure)):
                        self.cli()
                self.assertFalse((self.output_dir / "EDGE-A.cfg").exists())
                self.assertNotIn("[OK]", self.stdout.getvalue())
                self.assertNotIn("Rendered", self.stdout.getvalue())


if __name__ == "__main__":
    unittest.main()

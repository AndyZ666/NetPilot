"""Offline Day-0 rendering with the real renderer and production Jinja template.

Fixtures contain synthetic password hashes, never real credentials.
Consistency checks use the NSOT and real template; no sensitive runtime artifacts
are read. External actions are denied.
"""

from copy import deepcopy
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from jinja2 import Environment, FileSystemLoader, StrictUndefined
import yaml

import render_configs as renderer


TEMPLATES = Path(__file__).resolve().parents[1] / "templates"
HASHES = {"admin": "$6$fixtureAdmin$" + "A" * 86,
          "netpilot-recovery": "$6$fixtureRecovery$" + "B" * 86}


def day0_device(hostname="R6", verified=True):
    return {
        "hostname": hostname,
        "template": "templates/arista_day0.j2",
        "vendor": "Arista",
        "platform": "cEOS",
        "management": {
            "interface": "Management0",
            "ipv4": "172.31.252.2" if verified else None,
            "ipv4_prefix": "172.31.252.2/24" if verified else None,
        },
        "onboarding": {
            "status": "pending",
            "management_verified": verified,
            "bootstrap_mac": "02:00:00:00:00:06",
        },
    }


def legacy_device(hostname):
    return {
        "hostname": hostname,
        "interfaces": {}, "vlans": {}, "redistribution": [],
        "policy": {"prefix_lists": {"ipv4": {}, "ipv6": {}}, "route_maps": {}},
        "routing": {name: {"enabled": False} for name in ("ospfv2", "ospfv3", "ripv2", "bgp")},
    }


def commands(text):
    return [line.strip() for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("!")]


class Day0RenderingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="netpilot-day0-render-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.inventory_path = self.root / "inventory.yml"
        self.output_dir = self.root / "rendered"
        self.inventory = {
            "network": {"defaults": {"template": "templates/arista_ceos.j2"}},
            "devices": {"R6": day0_device(), "R7": day0_device("R7", verified=False)},
        }
        self.env = Environment(loader=FileSystemLoader(str(TEMPLATES)),
                               undefined=StrictUndefined, lstrip_blocks=True,
                               keep_trailing_newline=True)
        self.stdout = self.enterContext(patch("sys.stdout", new_callable=io.StringIO))
        self.stderr = self.enterContext(patch("sys.stderr", new_callable=io.StringIO))
        for name, value in (("DEFAULT_INVENTORY", self.inventory_path),
                            ("DEFAULT_TEMPLATE_DIR", TEMPLATES),
                            ("DEFAULT_OUTPUT_DIR", self.output_dir)):
            self.enterContext(patch.object(renderer, name, value))
        for target in ("security.credential_provider.get_credentials", "netmiko.ConnectHandler",
                       "socket.socket.connect", "socket.create_connection", "subprocess.run"):
            forbidden = self.enterContext(patch(target, side_effect=AssertionError("External action forbidden")))
            self.addCleanup(forbidden.assert_not_called)

    def render(self):
        return renderer.render_device(self.env, self.inventory, "R6", day0_hashes=HASHES)

    def cli(self, *arguments):
        self.inventory_path.write_text(yaml.safe_dump(self.inventory), encoding="utf-8")
        with patch("sys.argv", ["render_configs.py", *arguments]):
            return renderer.main()

    def test_real_day0_template_renders_only_required_management_services(self):
        original = deepcopy(self.inventory)
        output = self.render()
        lines = commands(output)
        self.assertIn("hostname R6", lines)
        self.assertIn("interface Management0\n   ip address 172.31.252.2/24\n   no shutdown", output)
        self.assertEqual([line for line in lines if line.startswith("interface ")], ["interface Management0"])
        for expected in (
            "aaa authentication login default local",
            "aaa authorization commands all default local",
            "username admin privilege 15 role network-admin secret sha512 " + HASHES["admin"],
            "username netpilot-recovery privilege 15 role network-admin secret sha512 " + HASHES["netpilot-recovery"],
            "authentication empty-passwords deny",
            "snmp-server local-interface Management0",
            "management api gnmi", "transport grpc default", "no ssl profile",
            "management api http-commands", "protocol https", "no protocol http",
        ):
            with self.subTest(command=expected):
                self.assertIn(expected, lines)
        self.assertIn("management ssh", lines)
        self.assertRegex(output, r"management api gnmi\n\s+transport grpc default\n\s+no ssl profile")
        api_stanza = output.split("management api http-commands\n", 1)[1]
        api_lines = []
        for line in api_stanza.splitlines():
            if not line.strip() or line.lstrip().startswith("!"):
                continue
            if not line[0].isspace():
                break
            api_lines.append(line.strip())
        self.assertTrue({"protocol https", "no protocol http", "no shutdown"}.issubset(api_lines))
        self.assertEqual(lines[-1], "end")
        self.assertEqual(self.inventory, original)
        self.assertTrue(output.endswith("end\n"))

    def test_only_permanent_accounts_exist_without_temporary_role_or_keys(self):
        output = self.render()
        accounts = [line for line in commands(output) if line.startswith("username ")]
        self.assertEqual(accounts, [
            "username admin privilege 15 role network-admin secret sha512 " + HASHES["admin"],
            "username netpilot-recovery privilege 15 role network-admin secret sha512 " + HASHES["netpilot-recovery"],
        ])
        for forbidden in ("netpilot-onboard", "role netpilot-onboarding", "sshkey", "nopassword\n"):
            self.assertNotIn(forbidden, output)

    def test_secret_fields_and_day1_routing_data_cannot_leak_into_day0(self):
        device = self.inventory["devices"]["R6"]
        device.update(
            credentials={"password": "SYNTHETIC-PASSWORD-DO-NOT-RENDER"},
            snmp={"community": "SYNTHETIC-COMMUNITY-DO-NOT-RENDER"},
            interfaces={"Loopback0": {"ipv4": ["6.6.6.6/32"]}, "Ethernet1": {"ipv4": ["10.250.0.6/24"]}},
            vlans={42: {"name": "DAY1-VLAN"}},
            routing={"bgp": {"enabled": True, "local_asn": 65006}, "ospfv2": {"enabled": True}},
            policy={"route_maps": {"DAY1-POLICY": []}},
            ntp={"servers": ["192.0.2.123"]},
        )
        device["onboarding"]["private_key"] = "SYNTHETIC-PRIVATE-KEY-DO-NOT-RENDER"
        self.inventory["network"]["credentials"] = {"token": "SYNTHETIC-TOKEN-DO-NOT-RENDER"}
        output = self.render()
        for forbidden in ("SYNTHETIC-", "6.6.6.6", "10.250.0.6", "DAY1-", "192.0.2.123",
                          "BEGIN OPENSSH PRIVATE KEY"):
            self.assertNotIn(forbidden, output)
        for line in commands(output):
            self.assertFalse(line.startswith(("router ", "ipv6 router ", "vlan ", "route-map ",
                                              "ip prefix-list ", "ntp ", "snmp-server community ")))

    def test_missing_invalid_or_mismatched_management_evidence_is_rejected(self):
        valid = deepcopy(self.inventory["devices"]["R6"]["management"])
        changes = (
            {"interface": "Management00"}, {"interface": "Management0.100"},
            {"ipv4": None}, {"ipv4": True}, {"ipv4": 1},
            {"ipv4": "172.31.252.2\nusername injected"},
            {"ipv4_prefix": None}, {"ipv4_prefix": "172.31.252.2/99"},
            {"ipv4_prefix": "172.31.252.3/24"}, {"ipv4_prefix": "2001:db8::2/64"},
        )
        for change in changes:
            with self.subTest(change=change):
                self.inventory["devices"]["R6"]["management"] = {**valid, **change}
                with self.assertRaises(ValueError):
                    self.render()

    def test_pending_status_and_verified_management_are_required(self):
        valid = deepcopy(self.inventory["devices"]["R6"]["onboarding"])
        for change in ({"status": "active"}, {"status": None},
                       {"management_verified": False}, {"management_verified": "true"}):
            with self.subTest(change=change):
                self.inventory["devices"]["R6"]["onboarding"] = {**valid, **change}
                with self.assertRaises(ValueError):
                    self.render()

    def test_both_sha512_hashes_required_without_echoing_invalid_values(self):
        invalid = "sensitive-fixture\nusername injected nopassword"
        for hashes in (None, {}, {"admin": HASHES["admin"]},
                       {**HASHES, "unexpected": HASHES["admin"]},
                       {**HASHES, "admin": invalid}, {**HASHES, "admin": True},
                       {**HASHES, "netpilot-recovery": "$5$not-sha512"}):
            with self.subTest(hashes=hashes):
                with self.assertRaises(ValueError) as caught:
                    renderer.render_device(self.env, self.inventory, "R6", day0_hashes=hashes)
                self.assertNotIn(invalid, str(caught.exception))
                self.assertNotIn(HASHES["admin"], str(caught.exception))

    def test_hostname_mismatch_or_newline_is_rejected_without_echoing_input(self):
        for hostname in ("R7", "R6\nusername SECRET-MARKER nopassword", None):
            with self.subTest(hostname=hostname):
                self.inventory["devices"]["R6"]["hostname"] = hostname
                with self.assertRaises(ValueError) as caught:
                    self.render()
                self.assertNotIn("SECRET-MARKER", str(caught.exception))

    def test_generic_cli_cannot_write_sensitive_day0_to_arbitrary_output(self):
        self.assertEqual(self.cli("R6"), 1)
        self.assertEqual(list(self.output_dir.glob("*.cfg")), [])
        self.assertIn("python -m lab8.day0 render", self.stderr.getvalue())
        self.assertEqual(yaml.safe_load(self.inventory_path.read_text()), self.inventory)

    def test_explicit_unverified_r7_cli_fails_without_writing_configuration(self):
        self.assertEqual(self.cli("R7"), 1)
        self.assertFalse((self.output_dir / "R7.cfg").exists())
        self.assertEqual(list(self.output_dir.glob("*.cfg")), [])
        self.assertIn("[FAIL] R7", self.stderr.getvalue())

    def test_r7_with_approved_pilot_management_address_renders_in_memory(self):
        r7 = self.inventory["devices"]["R7"]
        r7["management"].update(ipv4="172.20.20.31", ipv4_prefix="172.20.20.31/24")
        r7["onboarding"]["management_verified"] = True
        original = deepcopy(self.inventory)
        output = renderer.render_device(self.env, self.inventory, "R7", day0_hashes=HASHES)
        self.assertIn("hostname R7", commands(output))
        self.assertIn("interface Management0\n   ip address 172.20.20.31/24\n   no shutdown", output)
        self.assertEqual([line for line in commands(output) if line.startswith("interface ")],
                         ["interface Management0"])
        self.assertEqual(self.inventory, original)
        self.assertEqual(self.stderr.getvalue(), "")

    def test_default_cli_preserves_legacy_rendering_and_skips_all_pending_targets(self):
        for number in range(1, 10):
            hostname = f"LEGACY{number}"
            self.inventory["devices"][hostname] = legacy_device(hostname)
        self.assertEqual(self.cli(), 0)
        self.assertEqual(sorted(path.name for path in self.output_dir.glob("*.cfg")),
                         [f"LEGACY{number}.cfg" for number in range(1, 10)])
        for number in range(1, 10):
            hostname = f"LEGACY{number}"
            self.assertEqual(commands((self.output_dir / f"{hostname}.cfg").read_text()),
                             [f"hostname {hostname}", "end"])
        self.assertFalse((self.output_dir / "R7.cfg").exists())
        self.assertFalse((self.output_dir / "R6.cfg").exists())

    def test_pending_targets_match_topology_dhcp_and_permanent_account_template(self):
        project = TEMPLATES.parent
        inventory = yaml.safe_load((project / "inventory" / "devices.yml").read_text())
        topology = yaml.safe_load((project / "nettopo.clab.yml").read_text())
        self.assertEqual(topology["name"], "pilot-network")
        self.assertEqual(topology["mgmt"]["network"], "clab")
        self.assertEqual(topology["mgmt"]["ipv4-subnet"], "172.20.20.0/24")
        dhcp_lines = [line.strip() for line in (project / "lab8" / "day0-dnsmasq.conf").read_text().splitlines()
                      if line.strip() and not line.lstrip().startswith("#")]
        self.assertEqual([line for line in dhcp_lines if line.startswith("dhcp-option-force=")],
                         ["dhcp-option-force=tag:r6,67,http://10.250.0.1/day0/R6.cfg",
                          "dhcp-option-force=tag:r7,67,http://10.250.0.1/day0/R7.cfg"])
        self.assertIn("interface=eth1", dhcp_lines)
        self.assertIn("except-interface=eth0", dhcp_lines)
        for name, address, mac in (("R6", "172.20.20.30", "aa:c1:ab:da:73:76"),
                                   ("R7", "172.20.20.31", "02:00:00:08:00:07")):
            with self.subTest(device=name):
                device = inventory["devices"][name]
                self.assertEqual(device["onboarding"]["status"], "pending")
                self.assertIs(device["onboarding"]["management_verified"], True)
                self.assertEqual(device["management"]["ipv4"], address)
                self.assertEqual(device["management"]["ipv4_prefix"], address + "/24")
                node = topology["topology"]["nodes"][name]
                self.assertEqual(node["kind"], "ceos")
                self.assertEqual(node["mgmt-ipv4"], address)
                self.assertIs(node["suppress-startup-config"], True)
                self.assertNotIn("startup-config", node)
                links = [link for link in topology["topology"]["links"]
                         if link.get("endpoint", {}).get("node") == name]
                self.assertEqual(len(links), 1)
                self.assertEqual(links[0]["type"], "host")
                self.assertEqual(links[0]["endpoint"]["interface"], "eth1")
                self.assertEqual(links[0]["host-interface"], "npztp-" + name.lower())
                self.assertEqual(device["onboarding"]["bootstrap_mac"], mac)
                self.assertEqual(links[0]["endpoint"]["mac"], mac)
                self.assertIn(f"dhcp-host={mac},set:{name.lower()}", dhcp_lines)
                self.assertNotIn("ssh_username", device["onboarding"])
                self.assertNotIn("ssh_public_key", device["onboarding"])
                output = renderer.render_device(self.env, inventory, name, day0_hashes=HASHES)
                self.assertIn(f"hostname {name}", commands(output))
                self.assertIn(f"ip address {address}/24", commands(output))
                self.assertEqual([line for line in commands(output) if line.startswith("interface ")],
                                 ["interface Management0"])
                self.assertEqual([line for line in commands(output) if line.startswith("username ")], [
                    "username admin privilege 15 role network-admin secret sha512 " + HASHES["admin"],
                    "username netpilot-recovery privilege 15 role network-admin secret sha512 " + HASHES["netpilot-recovery"],
                ])
                self.assertFalse(any(line.startswith(("snmp-server community ", "router ", "vlan "))
                                     for line in commands(output)))
                for secret_marker in ("PRIVATE KEY", "netpilot-onboard", "$5$"):
                    self.assertNotIn(secret_marker, output)

    def test_pilot_additions_preserve_legacy_nodes_links_and_bootstrap_separation(self):
        project = TEMPLATES.parent
        topology = yaml.safe_load((project / "nettopo.clab.yml").read_text())["topology"]
        legacy = {"R1", "R2", "R3", "R4", "R5", "S1", "S2", "S3", "S4",
                  "H1", "H2", "H3", "H4", "web-server"}
        self.assertEqual(set(topology["nodes"]), legacy | {"R6", "R7"})
        self.assertEqual(topology["kinds"]["ceos"]["image"], "ceos:4.36.2F")
        original_links = [
            ["web-server:eth1", "R5:eth1"], ["R5:eth2", "R3:eth1"],
            ["R5:eth3", "R4:eth1"], ["R3:eth3", "R4:eth3"],
            ["R3:eth2", "S3:eth1"], ["R4:eth2", "S4:eth1"],
            ["S3:eth2", "S4:eth2"], ["S3:eth3", "R1:eth1"],
            ["S4:eth3", "R2:eth1"], ["R1:eth2", "S1:eth1"],
            ["R2:eth2", "S2:eth1"], ["S1:eth2", "S2:eth2"],
            ["S1:eth3", "H1:eth1"], ["S1:eth4", "H2:eth1"],
            ["S2:eth3", "H3:eth1"], ["S2:eth4", "H4:eth1"],
        ]
        self.assertEqual([link["endpoints"] for link in topology["links"] if "endpoints" in link],
                         original_links)
        self.assertEqual(len(topology["links"]), 18)
        self.assertEqual({link["endpoint"]["node"] for link in topology["links"] if "endpoint" in link},
                         {"R6", "R7"})
        infra = yaml.safe_load((project / "lab8" / "ztp-infra.clab.yml").read_text())
        self.assertEqual(infra["name"], "netpilot-ztp-infra")
        self.assertEqual(set(infra["topology"]["nodes"]), {"ztp-server"})
        self.assertEqual(infra["mgmt"]["ipv4-subnet"], "172.31.251.0/24")
        self.assertNotEqual(infra["mgmt"]["network"], "clab")
        isolated = yaml.safe_load((project / "lab8" / "ztp-clients.clab.yml").read_text())
        self.assertEqual(isolated["name"], "netpilot-ztp-clients")
        self.assertEqual(isolated["mgmt"]["network"], "netpilot-ztp-clients-mgmt")
        self.assertEqual(isolated["mgmt"]["ipv4-subnet"], "172.31.252.0/24")
        self.assertEqual(set(isolated["topology"]["nodes"]), {"R6"})
        self.assertEqual(isolated["topology"]["nodes"]["R6"]["mgmt-ipv4"], "172.31.252.2")
        self.assertIs(isolated["topology"]["nodes"]["R6"]["suppress-startup-config"], True)
        self.assertNotIn("startup-config", isolated["topology"]["nodes"]["R6"])
        self.assertEqual(isolated["topology"]["links"], [{
            "type": "host",
            "endpoint": {"node": "R6", "interface": "eth1", "mac": "aa:c1:ab:da:73:76"},
            "host-interface": "npztp-r6",
        }])


if __name__ == "__main__":
    unittest.main()

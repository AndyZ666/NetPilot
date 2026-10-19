"""Offline address contracts; expected hosts/prefixes are independently specified.

IPv4 decimal-dot syntax follows Python 3.12 ipaddress documentation (no
leading zeroes); /31 endpoint treatment follows RFC 3021. IPv6 notation follows
RFC 4291. Syntax-only helpers are not assigned a universal reachability policy.
Only pure validators/parsers are called; no diagnostic entry points are run.
"""

from copy import deepcopy
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
import unittest

import yaml

import config_changes as changes
import health_checks
from Functions import check_network_status, configure_snmp_traps
from Functions.maintenance_telemetry import Telemetry, TelemetryError
from security import credential_rotation
from test_inventory_management import InventoryFixture, m as gui


class RegistrationAddressTests(InventoryFixture):
    def test_management_accepts_bare_ipv4_and_rejects_malformed_or_prefixed_text(self):
        for address in ("10.0.0.255", "198.51.100.254", "192.0.2.0"):
            with self.subTest(valid=address):
                self.assertEqual(gui.validate_new_device(self.form(management_ip=address), self.data), {})
        for address in ("256.1.2.3", "1.2.3", "1.2.3.4.5", "1.2.x.4", "", "192.0.02.3",
                        " 192.0.2.3", "192.0.2.3\n", "192.0.2.3/24", "2001:db8::3", "+1.2.3.4"):
            with self.subTest(invalid=address):
                self.assertIn("management_ip", gui.validate_new_device(self.form(management_ip=address), self.data))

    def test_management_duplicates_compare_hosts_across_supported_inventory_forms(self):
        for field, address in (("ipv4", "192.0.2.3/32"), ("ipv4_prefix", "192.0.2.3/24"),
                               ("ipv4_prefix", "192.0.2.3/255.255.255.0")):
            with self.subTest(field=field, address=address):
                inventory = {"devices": {"PEER": {"management": {field: address}}}}
                errors = gui.validate_new_device(self.form(), inventory)
                self.assertEqual(set(errors), {"management_ip"})
                self.assertIn("PEER", errors["management_ip"])
        # Sharing a subnet is not sharing an assigned address.
        inventory = {"devices": {"PEER": {"management": {"ipv4_prefix": "192.0.2.4/24"}}}}
        self.assertEqual(gui.validate_new_device(self.form(), inventory), {})

    def test_router_ids_are_ipv4_even_for_ospfv3_and_reject_forbidden_values(self):
        for protocol in ("ospfv2", "ospfv3", "bgp"):
            number = protocol + ("_local_asn" if protocol == "bgp" else "_process_id")
            for value in ("0.0.0.0", "224.0.0.1", "239.255.255.255", "255.255.255.255",
                          "2001:db8::1", "192.0.2.1/32", "192.0.02.1"):
                with self.subTest(protocol=protocol, invalid=value):
                    form = self.form(protocols=[protocol], **{number: "10", protocol + "_router_id": value})
                    self.assertEqual(set(gui.validate_new_device(form, self.data)), {protocol + "_router_id"})

    def test_router_id_is_a_logical_identifier_not_a_management_reachability_check(self):
        for value in ("0.0.0.1", "127.0.0.1", "169.254.1.1", "223.255.255.255"):
            with self.subTest(value=value):
                form = self.form(protocols=["ospfv2"], ospfv2_process_id="1", ospfv2_router_id=value)
                self.assertEqual(gui.validate_new_device(form, self.data), {})
                self.assertEqual(gui.build_new_device(form)["routing"]["ospfv2"]["router_id"], value)

    def test_routing_number_boundaries_are_checked_before_integer_normalization(self):
        for protocol, field, maximum in (("ospfv2", "ospfv2_process_id", 65535),
                                         ("ospfv3", "ospfv3_process_id", 65535),
                                         ("bgp", "bgp_local_asn", 4294967294)):
            for raw, valid in (("1", True), (str(maximum), True), ("00010", True), ("0", False),
                               (str(maximum + 1), False), ("-1", False), ("1.0", False), (" 10", False)):
                with self.subTest(field=field, value=raw):
                    form = self.form(protocols=[protocol], **{field: raw, protocol + "_router_id": "203.0.113.7"})
                    errors = gui.validate_new_device(form, self.data)
                    self.assertEqual(field not in errors, valid)
                    if valid:
                        record = gui.build_new_device(form)["routing"][protocol]
                        self.assertEqual(record["local_asn" if protocol == "bgp" else "process_id"], int(raw))


class LoopbackAddressTests(InventoryFixture):
    def setUp(self):
        super().setUp()
        self.enterContext(patch.object(changes, "INVENTORY_PATH", self.path))

    def preview(self, **fields):
        form = {"device": "R1", "change_type": "create_loopback", "loopback_id": "7",
                "ipv4": "203.0.113.7", "prefix_length": "32"}
        form.update(fields)
        return changes.validate_change(form)

    def test_every_ipv4_prefix_preserves_address_and_exact_commands(self):
        for prefix in range(33):
            with self.subTest(prefix=prefix):
                preview = self.preview(prefix_length=str(prefix))
                self.assertEqual(preview["new_value"]["ipv4"], [f"203.0.113.7/{prefix}"])
                self.assertEqual(preview["generated_commands"], ["interface Loopback7",
                                 f"ip address 203.0.113.7/{prefix}", "no shutdown"])
                self.assertEqual(preview["request"]["prefix_length"], str(prefix))
        self.assert_unchanged()
        self.assertEqual(self.backups(), [])

    def test_ipv4_31_both_endpoints_and_32_host_are_not_blanket_rejected(self):
        for address, prefix in (("203.0.113.0", "31"), ("203.0.113.1", "31"), ("203.0.113.255", "32")):
            with self.subTest(address=address, prefix=prefix):
                self.assertEqual(self.preview(ipv4=address, prefix_length=prefix)["new_value"]["ipv4"],
                                 [address + "/" + prefix])

    def test_loopback_fields_require_text_not_numeric_boolean_or_container_values(self):
        for field in ("ipv4", "prefix_length", "loopback_id"):
            for value in (None, True, False, 32, 1.5, [], {}):
                with self.subTest(field=field, value=value), self.assertRaises(changes.ChangeError):
                    self.preview(**{field: value})
        self.assert_unchanged()

    def test_bare_ipv4_rejects_octet_format_whitespace_and_ipv6_errors(self):
        for address in ("256.0.0.1", "1.2.3", "1.2.3.4.5", "1..3.4", "1.2.a.4", "",
                        "1.2.03.4", "+1.2.3.4", "1.2.3.4 ", "1.2.3.4\n", " 1.2.3.4",
                        "1.2.3.4/32", "2001:db8::1", "::ffff:192.0.2.1"):
            with self.subTest(address=address), self.assertRaises(changes.ChangeError):
                self.preview(ipv4=address)

    def test_separate_prefix_requires_decimal_length_not_mask_or_signed_notation(self):
        for prefix in ("-1", "33", "128", "255.255.255.0", "0.0.0.255", "+24", " 24", "24 ", "2.4", "/24"):
            with self.subTest(prefix=prefix), self.assertRaises(changes.ChangeError):
                self.preview(prefix_length=prefix)
        self.assertEqual(self.preview(prefix_length="08")["new_value"]["ipv4"], ["203.0.113.7/8"])

    def test_equivalent_assigned_hosts_block_creation_despite_different_masks(self):
        for assigned in ("203.0.113.7/24", "203.0.113.7/255.255.255.0", "203.0.113.7/0.0.0.255"):
            with self.subTest(assigned=assigned):
                data = deepcopy(self.data)
                data["devices"]["R2"]["interfaces"] = {"Vlan30": {"ipv4": [assigned]}}
                self.path.write_text(yaml.safe_dump(data), encoding="utf-8")
                with self.assertRaisesRegex(changes.ChangeError, "R2 Vlan30"):
                    self.preview()
                # No unrelated host in the same subnet should block this one.
                self.assertEqual(self.preview(ipv4="203.0.113.8")["new_value"]["ipv4"], ["203.0.113.8/32"])

    def test_assigned_collector_normalizes_masks_and_ignores_malformed_field_types(self):
        inventory = {"devices": {"R1": {"management": {"interface": "Management0",
            "ipv4": " 192.0.2.1/255.255.255.0 ", "ipv4_prefix": "192.0.2.1/32"}, "interfaces": {
                "Ethernet1": {"ipv4": ["198.51.100.7/24", "198.51.100.7/0.0.0.255", "bad", True, 7]},
                "Ethernet2": {"ipv4": "198.51.100.7/32"}, "Ethernet3": {"ipv4": {"address": "203.0.113.1"}},
                "Ethernet4": {"ipv4": ["2001:db8::1/64", "198.51.100.8/255.0.255.0"]},
                "Ethernet5": None}}, "R2": None}}
        self.assertEqual(changes.collect_assigned_ipv4_addresses(inventory), {
            "192.0.2.1": ["R1:Management0"], "198.51.100.7": ["R1:Ethernet1", "R1:Ethernet2"]})


class ReadOnlyAddressParsingTests(InventoryFixture):
    def test_health_address_preserves_hosts_for_cidr_and_contiguous_masks(self):
        for value, expected in (("192.0.2.7", "192.0.2.7"), ("192.0.2.7/0", "192.0.2.7"),
                                ("192.0.2.0/31", "192.0.2.0"), ("192.0.2.1/31", "192.0.2.1"),
                                ("192.0.2.255/32", "192.0.2.255"), ("192.0.2.0/24", "192.0.2.0"),
                                ("192.0.2.255/24", "192.0.2.255"),
                                ("192.0.2.7/255.255.255.0", "192.0.2.7"), ("192.0.2.7/0.0.0.255", "192.0.2.7")):
            with self.subTest(value=value):
                self.assertEqual(health_checks._address({"management_ip": value}), expected)

    def test_health_address_rejects_invalid_masks_ipv6_and_bad_text(self):
        for value in ("192.0.2.7/-1", "192.0.2.7/33", "192.0.2.7/255.0.255.0",
                      "192.0.2.7/255.255.255.1", "2001:db8::7/128", "192.0.02.7", "192.0.2.7 ", ""):
            with self.subTest(value=value), self.assertRaises(ValueError):
                health_checks._address({"management_ip": value})

    def test_configuration_parser_supports_full_compressed_ipv6_and_all_prefixes(self):
        for prefix in range(129):
            with self.subTest(prefix=prefix):
                config = f"interface Ethernet1\n   ipv6 address 2001:0DB8:0000:0000:0000:0000:0000:0007/{prefix}\n!\n"
                addresses = check_network_status.parse_config(config)[2]
                self.assertEqual([str(value) for value in addresses["Ethernet1"]], [f"2001:db8::7/{prefix}"])
        config = "interface Ethernet1\n   ip address 192.0.2.0/31\n   ipv6 address 2001:db8::7/128\n!\n"
        self.assertEqual([str(value) for value in check_network_status.parse_config(config)[2]["Ethernet1"]],
                         ["192.0.2.0/31", "2001:db8::7/128"])

    def test_configuration_parser_ignores_invalid_addresses_without_losing_valid_ones(self):
        invalid = ("2001:db8::1/129", "2001:db8::1/-1", "2001::db8::1/64", "2001:gg::1/64",
                   "1:2:3:4:5:6:7/64", "192.0.2.1/33", "192.0.02.1/24", "256.0.0.1/32")
        lines = "".join("   ipv6 address " + address + "\n" for address in invalid)
        config = "interface Ethernet1\n" + lines + "   ip address 192.0.2.1/32\n!\n"
        self.assertEqual([str(value) for value in check_network_status.parse_config(config)[2]["Ethernet1"]], ["192.0.2.1/32"])

    def test_configuration_parser_excludes_management_vrf_link_local_and_loopback_hosts(self):
        config = ("interface Management0\n   ip address 192.0.2.1/24\n!\n"
                  "interface Ethernet2\n   vrf BLUE\n   ip address 198.51.100.1/24\n!\n"
                  "interface Ethernet1\n   ip address 169.254.1.1/16\n   ip address 127.0.0.1/8\n"
                  "   ipv6 address fe80::1/64\n   ipv6 address ::1/128\n   ipv6 address 2001:db8::7/64\n!\n")
        addresses = check_network_status.parse_config(config)[2]
        self.assertEqual(set(addresses), {"Ethernet1"})
        self.assertEqual([str(value) for value in addresses["Ethernet1"]], ["2001:db8::7/64"])


class LegacyAndFleetValidationTests(InventoryFixture):
    def test_legacy_ipv4_syntax_accepts_octet_boundaries_without_inventing_address_policy(self):
        for address in ("0.0.0.0", "255.255.255.255", "127.0.0.1", "169.254.1.1", "224.0.0.1", "192.0.2.7"):
            with self.subTest(address=address):
                self.assertIs(configure_snmp_traps.validate_ipv4(address), True)

    def test_legacy_ipv4_rejects_bad_octets_and_nonstring_inputs(self):
        for address in ("256.1.2.3", "-1.2.3.4", "1.2.3", "1.2.3.4.5", "1..3.4", "1.x.3.4",
                        "", "2001:db8::1", "192.0.2.7/24", None, True, False, 1234, [], {}):
            with self.subTest(address=address):
                self.assertIs(configure_snmp_traps.validate_ipv4(address), False)

    def test_legacy_ipv4_rejects_noncanonical_decimal_dot_forms(self):
        # int(octet) is insufficient: these are not strict dotted IPv4 strings.
        malformed = ("01.2.3.4", "+1.2.3.4", " 1.2.3.4", "1.2.3.4 ", "1.2.3.4\n", "١.2.3.4")
        accepted = [value for value in malformed if configure_snmp_traps.validate_ipv4(value)]
        self.assertEqual(accepted, [], "Malformed IPv4 forms must not reach deployment address selection")

    def fleet(self):
        names = ("R1", "R2", "R3", "R4", "R5", "S1", "S2", "S3", "S4")
        return {"devices": {name: {"hostname": name, "vendor": "Arista", "platform": "cEOSLab",
                "management": {"ipv4": f"192.0.2.{index}"}} for index, name in enumerate(names, 1)}}

    def test_rotation_inventory_rejects_wrong_identity_platform_and_record_structure(self):
        for record in (None, [], True, {"hostname": "R2", "vendor": "Arista", "platform": "cEOSLab", "management": {"ipv4": "192.0.2.1"}},
                       {"vendor": "Cisco", "platform": "cEOSLab", "management": {"ipv4": "192.0.2.1"}},
                       {"vendor": "Arista", "platform": "unknown", "management": {"ipv4": "192.0.2.1"}},
                       {"vendor": "Arista", "platform": "cEOSLab", "management": []}):
            with self.subTest(record=record):
                data = self.fleet()
                data["devices"]["R1"] = record
                self.path.write_text(yaml.safe_dump(data), encoding="utf-8")
                with self.assertRaisesRegex(credential_rotation.RotationError, "inventory"):
                    credential_rotation.discover_inventory(self.path)

    def test_rotation_inventory_rejects_ipv6_unspecified_and_multicast_management(self):
        for address in ("0.0.0.0", "224.0.0.1", "239.255.255.255", "2001:db8::1", "::ffff:192.0.2.1"):
            with self.subTest(address=address):
                data = self.fleet()
                data["devices"]["R1"]["management"]["ipv4"] = address
                self.path.write_text(yaml.safe_dump(data), encoding="utf-8")
                with self.assertRaisesRegex(credential_rotation.RotationError, "inventory"):
                    credential_rotation.discover_inventory(self.path)


class TelemetryAddressTests(InventoryFixture):
    def telemetry(self):
        config = self.root / "telegraf.conf"
        config.write_text('''[[inputs.gnmi]]
[[inputs.gnmi.subscription]]
name = "fixture_counters"
path = "/interfaces/interface/state/counters"
subscription_mode = "sample"
sample_interval = "10s"
[[outputs.influxdb_v2]]
urls = ["http://example.invalid:8086"]
organization = "fixture"
bucket = "fixture"
''', encoding="utf-8")
        self.enterContext(patch.dict("os.environ", {"INFLUX_TOKEN": "synthetic-token"}, clear=True))
        self.client = MagicMock()
        self.enterContext(patch("Functions.maintenance_telemetry.InfluxDBClient", return_value=self.client))
        self.enterContext(patch("Functions.maintenance_telemetry.time.time", return_value=1800000000))
        instance = Telemetry(config)
        self.addCleanup(instance.close)
        return instance

    def test_telemetry_queries_canonical_host_for_ipv4_and_ipv6_interface_notations(self):
        telemetry = self.telemetry()
        for source, expected in (("192.0.2.7/255.255.255.0", "192.0.2.7"),
                                 ("2001:0DB8:0000:0000:0000:0000:0000:0007/0", "2001:db8::7"),
                                 ("2001:db8::7/128", "2001:db8::7")):
            with self.subTest(source=source):
                records = [SimpleNamespace(values={"_measurement": "fixture_counters", "_field": field,
                    "source": expected, "name": "Ethernet1", "_value": value,
                    "_time": datetime.fromtimestamp(stamp, timezone.utc)})
                    for field in ("in_octets", "out_octets") for stamp, value in ((1799999980, 1000), (1799999990, 1200))]
                self.client.query_api.return_value.query.return_value = [SimpleNamespace(records=records)]
                result = telemetry.rates({"R1": source}, {"R1": ["Ethernet1"]})
                self.assertEqual(result["R1"]["Ethernet1"]["rx_bps"], 160)
                query = self.client.query_api.return_value.query.call_args.kwargs["query"]
                self.assertIn('r["source"] == "' + expected + '"', query)
                self.assertNotIn(source, query)

    def test_telemetry_rejects_equivalent_sources_before_querying(self):
        telemetry = self.telemetry()
        for first, second in (("192.0.2.7/24", "192.0.2.7/32"),
                              ("2001:0db8:0:0:0:0:0:7/64", "2001:db8::7/128")):
            with self.subTest(first=first), self.assertRaises(TelemetryError):
                telemetry.rates({"R1": first, "R2": second}, {"R1": ["Ethernet1"], "R2": ["Ethernet1"]})
        self.client.query_api.assert_not_called()

    def test_telemetry_rejects_bad_prefixes_before_querying(self):
        telemetry = self.telemetry()
        for source in ("2001:db8::7/129", "2001:db8::7/-1", "2001::db8::7/64", "192.0.2.7/33", "192.0.2.7/255.0.255.0"):
            with self.subTest(source=source), self.assertRaises(TelemetryError):
                telemetry.rates({"R1": source}, {"R1": ["Ethernet1"]})
        self.client.query_api.assert_not_called()


if __name__ == "__main__":
    unittest.main()

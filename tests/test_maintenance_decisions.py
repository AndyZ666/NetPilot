"""Real maintenance decisions with synthetic EOS/Flux evidence and temporary NSOT.

The older FixtureMaintenance tests intentionally replace health/precheck helpers.
These tests instantiate Maintenance itself; only external I/O is substituted.
No real inventory, Golden Config, credential, device, or telemetry data is read.
"""

from copy import deepcopy
from datetime import datetime, timezone
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, call, patch

import yaml

import challenge_maintenance as m
from Functions.maintenance_telemetry import Telemetry, TelemetryError


NOW = 1_800_000_000
CORE_PREFIXES = ("10.0.10.0/24", "10.0.20.0/24", "2001:db8:10::/64",
                 "2001:db8:20::/64", "2001:db8:30::/64")
ACCESS_PREFIXES = ("203.0.113.0/30", "2001:db8:203:113::/64")


def synthetic_inventory():
    """A reciprocal two-router topology; all identities are documentation values."""
    devices = {}
    for number, name, core, access in ((1, "R1", "S1", "S3"), (2, "R2", "S2", "S4")):
        devices[name] = {
            "management": {"interface": "Management0", "ipv4": f"192.0.2.{10 + number}"},
            "interfaces": {
                "Ethernet1": {"peer": {"device": core, "interface": "Ethernet3"},
                              "forwarding_model": "routed", "ipv4": [f"198.51.100.{number}/30"],
                              "ipv6": [f"2001:db8:{number}::1/64"]},
                "Ethernet2": {"peer": {"device": access, "interface": "Ethernet1"},
                              "forwarding_model": "routed", "ipv4": [f"198.51.100.{number + 10}/30"],
                              "ipv6": [f"2001:db8:{number + 10}::1/64"]},
            },
            "routing": {
                "ospfv2": {"enabled": True, "process_id": 10, "router_id": f"{number}.0.0.1",
                           "interfaces": [{"name": "Ethernet1", "network_type": "point-to-point"}]},
                "ospfv3": {"enabled": True, "router_id": f"{number}.0.0.1",
                           "interfaces": [{"name": "Ethernet1"}, {"name": "Ethernet2"}]},
                "ripv2": {"enabled": True, "interfaces": ["Ethernet2"]},
            },
        }
        for switch, own_port, router_port in ((core, "Ethernet3", "Ethernet1"),
                                               (access, "Ethernet1", "Ethernet2")):
            rid = {"S1": "11.0.0.1", "S2": "12.0.0.1", "S3": "13.0.0.1", "S4": "14.0.0.1"}[switch]
            devices[switch] = {
                "interfaces": {own_port: {"peer": {"device": name, "interface": router_port}}},
                "routing": {"ospfv2": {"router_id": rid}, "ospfv3": {"router_id": rid}},
            }
    return {"network": {"defaults": {"vendor": "arista", "platform": "eos"}}, "devices": devices}


def running_config(name):
    """Minimal sanitized config containing the settings capture() must protect."""
    return f"""hostname {name}
interface Management0
   description isolated test management
interface Ethernet1
   description core
   no shutdown
interface Ethernet2
   description access
   no shutdown
route-map RIP-TO-OSPF permit 10
route-map OSPF-TO-RIP permit 10
router ospf 10
   redistribute rip route-map RIP-TO-OSPF
router rip
   redistribute ospf 10 route-map OSPF-TO-RIP
end
"""


def route_reply(prefixes, port="Ethernet1", address="192.0.2.200"):
    return {"vrfs": {"default": {"routes": {
        prefix: {"routeAction": "forward", "vias": [{"interface": port, "nexthopAddr": address}]}
        for prefix in prefixes if ":" not in prefix
    }}}}


def ipv6_reply(prefixes, port):
    return "\n".join(f"O3 {prefix} [110/20]\n  via fe80::100, {port}"
                     for prefix in prefixes if ":" in prefix)


class DecisionFixtureAPI:
    """Command-output boundary, never a replacement for a Maintenance decision."""

    def __init__(self, inventory):
        self.replies = {}
        for name in ("R1", "R2"):
            device = inventory["devices"][name]
            core = device["interfaces"]["Ethernet1"]["peer"]["device"]
            rid = inventory["devices"][core]["routing"]["ospfv2"]["router_id"]
            self.replies[name, "show version"] = {"version": "4.30.2F"}
            self.replies[name, "show running-config"] = running_config(name)
            self.replies[name, "show interfaces description"] = {"interfaceDescriptions": {
                port: {"interfaceStatus": "up", "lineProtocolStatus": "up"}
                for port in ("Ethernet1", "Ethernet2", "Management0")
            }}
            self.replies[name, "show ip ospf neighbor"] = {"vrfs": {"default": {"instList": {
                "10": {"ospfNeighborEntries": [{"interfaceName": "Ethernet1", "routerId": rid,
                                               "adjacencyState": "full"}]}
            }}}}
            blocks = []
            for port in ("Ethernet1", "Ethernet2"):
                peer = device["interfaces"][port]["peer"]["device"]
                rid = inventory["devices"][peer]["routing"]["ospfv3"]["router_id"]
                blocks.append(f"Neighbor {rid} priority is 1, state is Full\n  In area 0.0.0.0 interface {port}")
            self.replies[name, "show ipv6 ospf neighbor vrf default"] = "\n".join(blocks)
            self.replies[name, "show ip route"] = route_reply(CORE_PREFIXES)
        for peer, prefixes, port in (("S1", CORE_PREFIXES, "Ethernet3"),
                                     ("S2", CORE_PREFIXES, "Ethernet3"),
                                     ("S3", ACCESS_PREFIXES, "Ethernet1"),
                                     ("S4", ACCESS_PREFIXES, "Ethernet1")):
            self.replies[peer, "show ip route"] = route_reply(prefixes, port)
            self.replies[peer, "show ipv6 route vrf default"] = ipv6_reply(prefixes, port)
        self.show = MagicMock(side_effect=self.read)
        self.configure = MagicMock(side_effect=AssertionError("Configuration forbidden in read-only decision tests"))

    def read(self, name, command, text=False):
        if (name, command) not in self.replies:
            raise AssertionError(f"Unexpected command: {name} {command}")
        value = self.replies[name, command]
        if isinstance(value, Exception):
            raise value
        if text != isinstance(value, str):
            raise AssertionError(f"Wrong encoding for {command}")
        return deepcopy(value)

    def avoid_r2(self):
        # S2/S4 no longer forward to R2; S1/S3 exclusively use their R1-facing links.
        self.replies["S2", "show ip route"] = route_reply(CORE_PREFIXES, "Ethernet2")
        self.replies["S2", "show ipv6 route vrf default"] = ipv6_reply(CORE_PREFIXES, "Ethernet2")
        self.replies["S4", "show ip route"] = route_reply(ACCESS_PREFIXES, "Vlan900")
        self.replies["S4", "show ipv6 route vrf default"] = ipv6_reply(ACCESS_PREFIXES, "Vlan900")


def attach_test_telemetry(app, test):
    """Use real counter parsing/rate decisions; bypass credential-bearing construction."""
    telemetry = object.__new__(Telemetry)
    telemetry.max_age, telemetry.measurement = 30, "fixture_counters"
    telemetry.bucket, telemetry.org = "fixture_bucket", "fixture_org"
    telemetry.client = MagicMock()
    rows = [SimpleNamespace(values={
        "_measurement": "fixture_counters", "source": source, "name": port,
        "_field": field, "_time": datetime.fromtimestamp(NOW - age, timezone.utc), "_value": value,
    }) for source in ("192.0.2.11", "192.0.2.12") for port in ("Ethernet1", "Ethernet2")
        for field in ("in_octets", "out_octets") for age, value in ((20, 1000), (10, 1200))]
    telemetry.client.query_api.return_value.query.return_value = [SimpleNamespace(records=rows)]
    test.enterContext(patch("Functions.maintenance_telemetry.time.time", return_value=NOW))
    app.telemetry = telemetry
    return rows


class MaintenanceDecisionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path, self.runtime = self.root / "devices.yml", self.root / "runtime"
        self.runtime.mkdir()
        self.inventory = synthetic_inventory()
        self.write_inventory(self.inventory)
        for boundary in ("socket.socket.connect", "socket.socket.connect_ex", "socket.create_connection",
                         "subprocess.Popen", "urllib.request.OpenerDirector.open",
                         "Functions.maintenance_telemetry.InfluxDBClient"):
            self.enterContext(patch(boundary, side_effect=AssertionError("External I/O forbidden")))
        self.enterContext(patch.object(m.credential_provider, "get_credentials", side_effect=AssertionError("Credentials forbidden")))
        self.enterContext(patch.object(m.storage, "ConnectHandler", side_effect=AssertionError("SSH forbidden")))
        self.backup = self.enterContext(patch.object(m.storage, "_save_prechange_backup", side_effect=AssertionError("Backup forbidden")))
        self.write = self.enterContext(patch.object(m.storage, "_atomic_write", side_effect=AssertionError("State writes forbidden")))
        self.update = self.enterContext(patch.object(m, "update_nsot", side_effect=AssertionError("NSOT update forbidden")))
        self.output = self.enterContext(patch("sys.stdout", new_callable=io.StringIO))
        self.api = DecisionFixtureAPI(self.inventory)
        self.sleep = MagicMock()
        args = m.defaults()
        args.timeout, args.interval = 10, 2
        self.app = m.Maintenance(self.path, self.runtime, api=self.api, args=args, sleep=self.sleep)
        self.rows = attach_test_telemetry(self.app, self)
        _, _, self.plans = m.discover(self.inventory, "R2")

    def write_inventory(self, inventory):
        self.path.write_text(yaml.safe_dump(inventory))

    def assert_readonly(self):
        self.api.configure.assert_not_called()
        self.backup.assert_not_called()
        self.write.assert_not_called()
        self.update.assert_not_called()
        self.assertEqual(list(self.runtime.iterdir()), [])

    def neighbors(self, name="R2"):
        return self.api.replies[name, "show ip ospf neighbor"]["vrfs"]["default"]["instList"]["10"]["ospfNeighborEntries"]

    def test_live_captures_real_configuration_settings_and_guard(self):
        config = running_config("R2").replace("interface Ethernet1\n", "interface Ethernet1\n   ipv6 ospf cost 27\n")
        config = config.replace("route-map RIP-TO-OSPF permit 10\n", "route-map RIP-TO-OSPF permit 10\n   set metric 42\n")
        self.api.replies["R2", "show running-config"] = config
        result = self.app.live("R2", self.plans["R2"])
        self.assertEqual(result["metrics"], {"route-map RIP-TO-OSPF permit 10": "set metric 42",
                                             "route-map OSPF-TO-RIP permit 10": None})
        self.assertEqual(result["costs"], {"Ethernet1": "ipv6 ospf cost 27", "Ethernet2": None})
        self.assertEqual(result["admin"], {"Ethernet1": "up", "Ethernet2": "up"})
        self.api.replies["R2", "show running-config"] = config.replace("description core", "description changed")
        self.assertNotEqual(self.app.live("R2", self.plans["R2"])["guard"], result["guard"])
        self.api.show.assert_has_calls([call("R2", "show running-config", text=True)] * 2)
        self.assert_readonly()

    def test_live_rejects_wrong_identity_incomplete_and_unsupported_configuration(self):
        config = running_config("R2")
        for invalid in (config.replace("hostname R2", "hostname R1"), config.replace("end\n", ""),
                        config.replace("interface Ethernet2", "interface Ethernet9"),
                        config.replace("route-map RIP-TO-OSPF permit 10\n", "route-map RIP-TO-OSPF permit 10\n   set metric +42\n")):
            with self.subTest(config=invalid):
                self.api.replies["R2", "show running-config"] = invalid
                with self.assertRaises(m.MaintenanceError):
                    self.app.live("R2", self.plans["R2"])
        self.assert_readonly()

    def test_health_accepts_full_expected_neighbors_and_returns_captured_state(self):
        for name in ("R1", "R2"):
            with self.subTest(router=name):
                self.neighbors(name)[0]["adjacencyState"] = "FULL"
                config, state = self.app.health(name, self.plans)
                self.assertEqual(config, running_config(name))
                self.assertEqual(state["admin"], {"Ethernet1": "up", "Ethernet2": "up"})
                self.assertEqual(state["costs"], {"Ethernet1": None, "Ethernet2": None})
        self.assert_readonly()

    def test_health_rejects_administrative_shutdown_even_if_status_claims_up(self):
        self.api.replies["R2", "show running-config"] = running_config("R2").replace("description access\n   no shutdown", "description access\n   shutdown")
        with self.assertRaisesRegex(m.MaintenanceError, "administratively down"):
            self.app.health("R2", self.plans)
        self.assertEqual(self.api.show.call_args_list, [call("R2", "show running-config", text=True)])
        self.assert_readonly()

    def test_health_requires_both_status_fields_on_production_and_management_ports(self):
        healthy = deepcopy(self.api.replies["R2", "show interfaces description"])
        for port in ("Ethernet1", "Ethernet2", "Management0"):
            for field, value in (("interfaceStatus", "down"), ("lineProtocolStatus", "down"),
                                 ("lineProtocolStatus", None)):
                with self.subTest(port=port, field=field, value=value):
                    reply = deepcopy(healthy)
                    reply["interfaceDescriptions"][port][field] = value
                    self.api.replies["R2", "show interfaces description"] = reply
                    with self.assertRaisesRegex(m.MaintenanceError, f"{port} is not operationally up"):
                        self.app.health("R2", self.plans)
        self.api.replies["R2", "show interfaces description"] = {}
        with self.assertRaisesRegex(m.MaintenanceError, "Ethernet1 is not operationally up"):
            self.app.health("R2", self.plans)
        self.assert_readonly()

    def test_health_requires_expected_full_ospfv2_neighbor_identity_and_port(self):
        # The ticket requires FULL on these named links; this is not a general ban
        # on OSPF 2-WAY between two DROTHERs on other broadcast topologies.
        valid = deepcopy(self.neighbors()[0])
        invalid = [dict(valid, adjacencyState=state) for state in ("init", "down", "2-way", None)]
        invalid += [dict(valid, routerId="99.0.0.1"), dict(valid, interfaceName="Ethernet2"), {}]
        for neighbor in invalid:
            with self.subTest(neighbor=neighbor):
                self.neighbors()[:] = [neighbor]
                with self.assertRaisesRegex(m.MaintenanceError, "expected OSPFv2 neighbor not FULL"):
                    self.app.health("R2", self.plans)
        self.neighbors().clear()
        with self.assertRaisesRegex(m.MaintenanceError, "expected OSPFv2 neighbor not FULL"):
            self.app.health("R2", self.plans)
        self.assert_readonly()

    def test_health_requires_both_expected_full_ospfv3_adjacencies(self):
        valid = self.api.replies["R2", "show ipv6 ospf neighbor vrf default"]
        invalid = [valid.replace("state is Full", f"state is {state}") for state in ("Init", "Down", "2-Way")]
        invalid += [valid.replace("14.0.0.1", "99.0.0.1"), valid.replace("Ethernet2", "Ethernet9"),
                    valid.split("Neighbor 14.0.0.1")[0], "Neighbor unavailable: malformed output"]
        for text in invalid:
            with self.subTest(output=text):
                self.api.replies["R2", "show ipv6 ospf neighbor vrf default"] = text
                with self.assertRaisesRegex(m.MaintenanceError, "expected OSPFv3 neighbor"):
                    self.app.health("R2", self.plans)
        self.assert_readonly()

    def test_health_rejects_missing_drop_and_unresolved_required_host_routes(self):
        healthy = route_reply(CORE_PREFIXES)
        for invalid in (None, {"routeAction": "drop", "vias": [{"interface": "Ethernet1"}]},
                        {"vias": []}, {"vias": [{}]}):
            with self.subTest(route=invalid):
                reply = deepcopy(healthy)
                reply["vrfs"]["default"]["routes"]["10.0.20.0/24"] = invalid
                self.api.replies["R2", "show ip route"] = reply
                with self.assertRaises(m.MaintenanceError):
                    self.app.health("R2", self.plans)
        self.assert_readonly()

    def test_precheck_runs_real_health_routing_and_telemetry_for_either_target(self):
        for target, alternate in (("R2", "R1"), ("R1", "R2")):
            with self.subTest(target=target):
                self.api.show.reset_mock()
                result = self.app.precheck(target)
                self.assertEqual((result["target"], result["alternate"]), (target, alternate))
                self.assertEqual(result["config"], running_config(target))
                self.assertEqual(result["dhcp"], {"enabled": False, "scopes": [], "leases": [], "interfaces": []})
                self.assertEqual(result["baseline"][target]["Ethernet2"]["tx_bps"], 160.0)
                self.assertEqual(len(result["routes"]), 14)
                self.assertEqual(result["routes"]["S4:203.0.113.0/30"], ["Ethernet1"])
                versions = [entry.args[0] for entry in self.api.show.call_args_list if entry.args[1] == "show version"]
                self.assertEqual(versions, [alternate, target])
        self.assert_readonly()

    def test_precheck_rejects_pending_target_or_unavailable_alternate_before_api(self):
        for name in ("R1", "R2"):
            for state in ("precheck", "draining", "drained", "out_of_service", "restoring", "rollback", "error"):
                with self.subTest(router=name, state=state):
                    inventory = deepcopy(self.inventory)
                    inventory["maintenance"] = {"ticket": "RCN-5840", "routers": {name: {"state": state}}}
                    self.write_inventory(inventory)
                    with self.assertRaises(m.MaintenanceError):
                        self.app.precheck("R2")
        self.api.show.assert_not_called()
        self.assert_readonly()

    def test_precheck_warns_about_dhcp_dependency_without_inventing_a_health_failure(self):
        config = running_config("R2").replace("description access\n", "description access\n   dhcp server ipv4\n")
        config = config.replace("end\n", "dhcp server\n   subnet 10.0.10.0/24\n   lease time ipv4 1 days 0 hours 0 minutes\nend\n")
        self.api.replies["R2", "show running-config"] = config
        result = self.app.precheck("R2")
        self.assertEqual(result["dhcp"], {
            "enabled": True, "scopes": ["10.0.10.0/24"],
            "leases": ["lease time ipv4 1 days 0 hours 0 minutes"], "interfaces": ["Ethernet2"],
        })
        self.assertIn("R2 serves DHCP without known redundancy", self.output.getvalue())
        self.assertIn("New leases/renewals may be unavailable", self.output.getvalue())
        self.assert_readonly()

    def test_precheck_rejects_disabled_required_routing_protocols_before_api(self):
        for name in ("R1", "R2"):
            for protocol in ("ospfv2", "ospfv3", "ripv2"):
                with self.subTest(router=name, protocol=protocol):
                    inventory = deepcopy(self.inventory)
                    inventory["devices"][name]["routing"][protocol]["enabled"] = False
                    self.write_inventory(inventory)
                    with self.assertRaisesRegex(m.MaintenanceError, "routing design differs from ticket"):
                        self.app.precheck("R2")
        self.api.show.assert_not_called()
        self.assert_readonly()

    def test_precheck_rejects_missing_invalid_or_unrecognized_version_on_either_router(self):
        for name in ("R1", "R2"):
            for response in ({}, {"version": None}, {"version": 4}, {"version": "3.9.0"}, {"version": "EOS"}):
                with self.subTest(router=name, response=response):
                    self.api.replies[name, "show version"] = response
                    with self.assertRaisesRegex(m.MaintenanceError, "unrecognized EOS platform/version"):
                        self.app.precheck("R2")
                    self.api.replies[name, "show version"] = {"version": "4.30.2F"}
        self.assert_readonly()

    def test_precheck_rejects_existing_drain_preferences_on_either_router(self):
        for name in ("R1", "R2"):
            for header, setting in (("route-map RIP-TO-OSPF permit 10", "set metric 50000"),
                                    ("route-map OSPF-TO-RIP permit 10", "set metric 10"),
                                    ("interface Ethernet2", "ospfv3 cost 60000")):
                with self.subTest(router=name, setting=setting):
                    self.api.replies[name, "show running-config"] = running_config(name).replace(header + "\n", header + "\n   " + setting + "\n")
                    with self.assertRaisesRegex(m.MaintenanceError, "preferences already meet/exceed"):
                        self.app.precheck("R2")
                    self.api.replies[name, "show running-config"] = running_config(name)
        self.assert_readonly()

    def test_precheck_rejects_invalid_or_missing_management_identity_without_api(self):
        for management in ({"interface": "Management00", "ipv4": "192.0.2.12"},
                           {"interface": "Management0"}, {"interface": "Management0", "ipv4": "not-an-address"}):
            with self.subTest(management=management):
                inventory = deepcopy(self.inventory)
                inventory["devices"]["R2"]["management"] = management
                self.write_inventory(inventory)
                with self.assertRaises((m.MaintenanceError, m.storage.ChangeError)):
                    self.app.precheck("R2")
        self.api.show.assert_not_called()
        self.assert_readonly()

    def test_precheck_rejects_missing_routes_on_alternate_gateway(self):
        self.api.replies["S1", "show ip route"] = route_reply(("10.0.10.0/24",))
        with self.assertRaisesRegex(m.MaintenanceError, "Missing forwarding route: 10.0.20.0/24"):
            self.app.precheck("R2")
        self.app.telemetry.client.query_api.assert_not_called()
        self.assert_readonly()

    def test_drain_unhealthy_alternate_fails_real_precheck_before_backup_or_configuration(self):
        self.api.replies["R1", "show interfaces description"]["interfaceDescriptions"]["Ethernet1"]["lineProtocolStatus"] = "down"
        with self.assertRaisesRegex(m.MaintenanceError, "R1: Ethernet1 is not operationally up"):
            self.app.drain("R2")
        self.assertNotIn(call("R2", "show version"), self.api.show.call_args_list)
        self.assertEqual(yaml.safe_load(self.path.read_text()), self.inventory)
        self.assert_readonly()

    def test_drain_wrong_target_hostname_fails_real_precheck_before_any_write(self):
        self.api.replies["R2", "show running-config"] = running_config("R1")
        with self.assertRaisesRegex(m.MaintenanceError, "incomplete/wrong running configuration"):
            self.app.drain("R2")
        self.assertEqual(yaml.safe_load(self.path.read_text()), self.inventory)
        self.assert_readonly()

    def test_precheck_connection_failure_propagates_without_writes_or_telemetry(self):
        self.api.replies["R1", "show version"] = m.MaintenanceError("R1: eAPI unavailable/authentication/TLS failure")
        with self.assertRaisesRegex(m.MaintenanceError, "eAPI unavailable"):
            self.app.drain("R2")
        self.app.telemetry.client.query_api.assert_not_called()
        self.assert_readonly()

    def test_rates_maps_only_router_management_addresses_and_production_interfaces(self):
        rates = self.app.rates(self.plans)
        self.assertEqual(set(rates), {"R1", "R2"})
        for name in ("R1", "R2"):
            self.assertEqual(set(rates[name]), {"Ethernet1", "Ethernet2"})
            self.assertEqual(rates[name]["Ethernet1"], {
                "rx_bps": 160.0, "tx_bps": 160.0, "rx_start": NOW - 20, "rx_end": NOW - 10,
                "tx_start": NOW - 20, "tx_end": NOW - 10, "start": NOW - 20, "end": NOW - 10,
            })
        query = self.app.telemetry.client.query_api.return_value.query.call_args.kwargs["query"]
        for expected in ('"192.0.2.11"', '"192.0.2.12"', '"Ethernet1"', '"Ethernet2"'):
            self.assertIn(expected, query)
        self.assertNotIn("Management0", query)
        self.assert_readonly()

    def test_drain_missing_transmit_telemetry_fails_real_precheck_before_writes(self):
        self.rows[:] = [row for row in self.rows if not (row.values["source"] == "192.0.2.12"
                       and row.values["name"] == "Ethernet2" and row.values["_field"] == "out_octets")]
        with self.assertRaisesRegex(TelemetryError, "Two distinct RX and TX samples"):
            self.app.drain("R2")
        self.assert_readonly()

    def test_drain_stale_telemetry_fails_real_precheck_before_writes(self):
        for row in self.rows:
            row.values["_time"] = datetime.fromtimestamp(row.values["_time"].timestamp() - 60, timezone.utc)
        with self.assertRaisesRegex(TelemetryError, "stale"):
            self.app.drain("R2")
        self.assert_readonly()

    def test_drain_malformed_telemetry_fails_real_precheck_before_writes(self):
        self.rows[-1].values["_value"] = "not-a-counter"
        with self.assertRaisesRegex(TelemetryError, "counter is invalid"):
            self.app.drain("R2")
        self.assert_readonly()

    def test_drain_evidence_halts_when_either_router_becomes_unhealthy(self):
        data = self.app.precheck("R2")
        self.app.telemetry.client.query_api.reset_mock()
        for name in ("R1", "R2"):
            with self.subTest(router=name):
                entry = self.api.replies[name, "show interfaces description"]["interfaceDescriptions"]["Ethernet1"]
                entry["lineProtocolStatus"] = "down"
                with patch.object(m.time, "monotonic", side_effect=[100, 101]):
                    with self.assertRaisesRegex(m.MaintenanceError, f"{name}: Ethernet1 is not operationally up"):
                        self.app.drain_evidence(data, applied_at=NOW)
                entry["lineProtocolStatus"] = "up"
        self.app.telemetry.client.query_api.assert_not_called()
        self.assert_readonly()

    def test_verify_inventory_allows_only_maintenance_metadata_changes(self):
        inventory = deepcopy(self.inventory)
        inventory["maintenance"] = {"ticket": "RCN-5840", "routers": {"R2": {"state": "draining"}}}
        self.write_inventory(inventory)
        self.assertIsNone(self.app.verify_inventory())
        self.assert_readonly()

    def test_verify_inventory_rejects_device_identity_topology_and_unrelated_drift(self):
        for change in ("address", "peer", "defaults"):
            with self.subTest(change=change):
                inventory = deepcopy(self.inventory)
                if change == "address":
                    inventory["devices"]["R2"]["management"]["ipv4"] = "192.0.2.99"
                elif change == "peer":
                    inventory["devices"]["R2"]["interfaces"]["Ethernet1"]["peer"]["interface"] = "Ethernet4"
                else:
                    inventory["network"]["defaults"]["platform"] = "ceoslab"
                self.write_inventory(inventory)
                with self.assertRaisesRegex(m.MaintenanceError, "NSOT changed after precheck"):
                    self.app.verify_inventory()
        self.assert_readonly()

    def test_verify_inventory_fails_safely_when_current_file_is_missing_or_corrupt(self):
        self.path.write_text("devices: [unterminated")
        with self.assertRaises(m.storage.ChangeError):
            self.app.verify_inventory()
        self.path.unlink()
        with self.assertRaises(m.storage.ChangeError):
            self.app.verify_inventory()
        self.assert_readonly()

    def test_wait_health_healthy_returns_without_sleeping(self):
        with patch.object(m.time, "monotonic", return_value=100):
            self.assertIsNone(self.app.wait_health("R2", self.plans))
        self.sleep.assert_not_called()
        self.assertIn(call("R2", "show ip route"), self.api.show.call_args_list)
        self.assert_readonly()

    def test_wait_health_retries_real_adjacency_check_until_recovery(self):
        self.neighbors()[0]["adjacencyState"] = "init"
        self.sleep.side_effect = lambda seconds: self.neighbors()[0].update(adjacencyState="full")
        with patch.object(m.time, "monotonic", side_effect=[100, 101]):
            self.app.wait_health("R2", self.plans)
        self.sleep.assert_called_once_with(2)
        self.assertEqual(self.api.show.call_args_list.count(call("R2", "show running-config", text=True)), 2)
        self.assertIn(call("R2", "show ip route"), self.api.show.call_args_list)
        self.assert_readonly()

    def test_wait_health_connection_timeouts_stop_at_deadline_without_configuration(self):
        self.api.replies["R2", "show running-config"] = m.MaintenanceError("R2: eAPI unavailable/authentication/TLS failure")
        with patch.object(m.time, "monotonic", side_effect=[100, 101, 110]):
            with self.assertRaisesRegex(m.MaintenanceError, "R2: routing/adjacency recovery timed out"):
                self.app.wait_health("R2", self.plans)
        self.sleep.assert_called_once_with(2)
        self.assertEqual(self.api.show.call_count, 2)
        self.assert_readonly()

    def test_wait_health_operator_interrupt_is_not_retried(self):
        self.api.show.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.app.wait_health("R2", self.plans)
        self.sleep.assert_not_called()
        self.assert_readonly()

    def test_routing_accepts_exclusive_alternate_path_and_interface_aliases(self):
        self.api.avoid_r2()
        self.api.replies["S1", "show ip route"] = route_reply(CORE_PREFIXES, "Et3")
        self.api.replies["S3", "show ipv6 route vrf default"] = ipv6_reply(ACCESS_PREFIXES, "eth1")
        evidence = self.app.routing("R2", "R1", self.plans, avoid=True)
        self.assertEqual(len(evidence), 14)
        self.assertEqual(evidence["S1:10.0.10.0/24"], ["Ethernet3"])
        self.assertEqual(evidence["S3:2001:db8:203:113::/64"], ["Ethernet1"])
        self.assertEqual(evidence["S2:10.0.20.0/24"], ["Ethernet2"])
        self.assertEqual(evidence["S4:203.0.113.0/30"], ["Vlan900"])
        self.assert_readonly()

    def test_routing_rejects_target_next_hop_even_on_different_interface(self):
        self.api.avoid_r2()
        for address in ("198.51.100.2", "198.51.100.12"):
            with self.subTest(next_hop=address):
                self.api.replies["S2", "show ip route"] = route_reply(CORE_PREFIXES, "Ethernet2", address)
                with self.assertRaisesRegex(m.MaintenanceError, "still selects target next hop"):
                    self.app.routing("R2", "R1", self.plans, avoid=True)
        self.api.replies["S2", "show ip route"] = route_reply(CORE_PREFIXES, "Ethernet2")
        self.api.replies["S2", "show ipv6 route vrf default"] = ipv6_reply(CORE_PREFIXES, "Ethernet2").replace("fe80::100", "2001:db8:2::1")
        with self.assertRaisesRegex(m.MaintenanceError, "still selects target next hop"):
            self.app.routing("R2", "R1", self.plans, avoid=True)
        self.assert_readonly()

    def test_routing_recognizes_equivalent_ipv6_target_next_hop_spellings(self):
        # IPv6 text compression and hex case do not change the next-hop identity.
        # The S2 output interface alone is safe-looking; the target address must
        # still block isolation even when EOS renders it differently from NSOT.
        self.api.avoid_r2()
        for address in ("2001:DB8:2::1", "2001:0db8:0002:0000:0000:0000:0000:0001"):
            with self.subTest(next_hop=address):
                self.api.replies["S2", "show ipv6 route vrf default"] = ipv6_reply(CORE_PREFIXES, "Ethernet2").replace("fe80::100", address)
                with self.assertRaisesRegex(m.MaintenanceError, "still selects target next hop"):
                    self.app.routing("R2", "R1", self.plans, avoid=True)
        self.assert_readonly()

    def test_routing_rejects_alternate_gateway_ecmp_to_unproven_link(self):
        self.api.avoid_r2()
        self.api.replies["S1", "show ip route"]["vrfs"]["default"]["routes"]["10.0.10.0/24"]["vias"].append(
            {"interface": "Ethernet9", "nexthopAddr": "192.0.2.201"})
        with self.assertRaisesRegex(m.MaintenanceError, "not exclusively using alternate R1"):
            self.app.routing("R2", "R1", self.plans, avoid=True)
        self.assert_readonly()

    def test_routing_rejects_unresolved_and_nonproduction_next_hop_interfaces(self):
        self.api.avoid_r2()
        for port in ("Null0", "Management0", "Loopback0", "unresolved", ""):
            with self.subTest(port=port):
                self.api.replies["S2", "show ip route"] = route_reply(CORE_PREFIXES, port)
                with self.assertRaises(m.MaintenanceError):
                    self.app.routing("R2", "R1", self.plans, avoid=True)
        self.assert_readonly()

    def test_routing_requires_exact_ipv4_prefix_not_covering_or_more_specific_route(self):
        for prefix in ("10.0.0.0/8", "10.0.10.0/25"):
            with self.subTest(prefix=prefix):
                self.api.replies["S1", "show ip route"] = route_reply((prefix, "10.0.20.0/24"), "Ethernet3")
                with self.assertRaisesRegex(m.MaintenanceError, "Missing forwarding route: 10.0.10.0/24"):
                    self.app.routing("R2", "R1", self.plans)
        self.assert_readonly()


if __name__ == "__main__":
    unittest.main()

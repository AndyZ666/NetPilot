"""Offline topology contracts; no collector, device, renderer or service runs.

The legacy realtime_topology_static.py and test_influx_status.py scripts execute
at import time and are deliberately not imported here. The real NetworkX graph
and YAML/JSON parsing are exercised, while plotting and Influx are isolated.
Known defects remain ordinary failing assertions, not expectedFailure markers.
"""

from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import yaml


SOURCE = Path(__file__).resolve().parents[1] / "Functions" / "realtime_topology.py"
ADDRESSES = {"R1": "192.0.2.1", "R2": "192.0.2.2"}


def record(source, interface, status, timestamp=None):
    return SimpleNamespace(
        values={"source": source, "name": interface, "_time": timestamp},
        get_value=lambda: status,
        get_time=lambda: timestamp,
    )


class RealtimeTopologyTests(unittest.TestCase):
    def setUp(self):
        self.directory = self.enterContext(tempfile.TemporaryDirectory(prefix="netpilot-topology-tests-"))
        self.root = Path(self.directory)
        self.enterContext(patch.dict(os.environ, {
            "MPLCONFIGDIR": str(self.root / "matplotlib"),
            "INFLUX_TOKEN": "synthetic-influx-token",
        }, clear=True))
        self.blocked = [self.enterContext(patch(target, side_effect=AssertionError("External operation prohibited")))
                        for target in (
                            "socket.create_connection", "socket.socket.connect", "subprocess.run",
                            "subprocess.Popen", "security.credential_provider.get_credentials",
                            "security.credential_provider._read_token", "security.credential_provider._run_op",
                        )]
        # Loading an isolated module avoids contaminating an existing GUI import.
        # A stub pyplot also guarantees font discovery/cache writes cannot happen.
        matplotlib = ModuleType("matplotlib")
        matplotlib.__path__ = []
        matplotlib.use = Mock()
        self.pyplot = Mock(name="pyplot")
        matplotlib.pyplot = self.pyplot
        influx = ModuleType("influxdb_client")
        self.client_factory = Mock(side_effect=AssertionError("Live Influx access prohibited"))
        influx.InfluxDBClient = self.client_factory
        with patch.dict(sys.modules, {
            "matplotlib": matplotlib,
            "matplotlib.pyplot": self.pyplot,
            "influxdb_client": influx,
        }):
            spec = importlib.util.spec_from_file_location("_netpilot_topology_unit", SOURCE)
            self.topology = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.topology)
        self.topology.DEVICE_IPS = ADDRESSES.copy()
        self.output = self.enterContext(redirect_stdout(io.StringIO()))

    def write_json(self, value, filename="devices.json"):
        path = self.root / filename
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def graph(self, nodes=None, endpoints=None):
        path = self.root / "lab.clab.yml"
        data = {"topology": {
            "nodes": dict.fromkeys(nodes or ["R1", "R2"], {}),
            "links": [{"endpoints": endpoints or ["R1:eth1", "R2:eth2"]}],
        }}
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        return self.topology.build_topology_graph(path)

    def query(self, *rows):
        return Mock(query=Mock(return_value=[SimpleNamespace(records=list(rows))]))

    def status(self, states, nodes=("R1", "R2"), interfaces=("Ethernet1", "Ethernet2")):
        edge = {"endpoint1": nodes[0] + ":" + interfaces[0],
                "endpoint2": nodes[1] + ":" + interfaces[1],
                "interface1": interfaces[0], "interface2": interfaces[1]}
        return self.topology.determine_link_status(*nodes, edge, states)

    def test_import_performs_no_external_operations_or_plotting(self):
        self.client_factory.assert_not_called()
        self.pyplot.figure.assert_not_called()
        self.pyplot.savefig.assert_not_called()
        for boundary in self.blocked:
            boundary.assert_not_called()
        self.assertFalse((self.root / "matplotlib").exists())

    def test_devices_json_wrapped_list_accepts_documented_name_and_address_aliases(self):
        path = self.write_json({"devices": [
            {"name": "R1", "mgmt_ip": "198.51.100.1"},
            {"device": "R2", "management_ip": "198.51.100.2"},
            {"hostname": "S1", "host": "198.51.100.3"},
            {"name": "S2", "ip": "198.51.100.4"},
            None, "ignored", {"name": "no-address"},
        ]})
        self.topology.load_devices_json(path)
        self.assertEqual(self.topology.DEVICE_IPS, {
            "R1": "198.51.100.1", "R2": "198.51.100.2",
            "S1": "198.51.100.3", "S2": "198.51.100.4",
        })

    def test_devices_json_mapping_updates_known_devices_and_preserves_other_defaults(self):
        path = self.write_json({"R1": {"ip": "198.51.100.10"}, "ignored": None})
        self.topology.load_devices_json(path)
        self.assertEqual(self.topology.DEVICE_IPS, {"R1": "198.51.100.10", "R2": "192.0.2.2"})

    def test_missing_devices_json_preserves_fallback_mapping(self):
        self.topology.load_devices_json(self.root / "missing.json")
        self.assertEqual(self.topology.DEVICE_IPS, ADDRESSES)
        self.assertIn("using built-in management IP mapping", self.output.getvalue())

    def test_invalid_empty_and_directory_devices_json_preserve_fallback(self):
        malformed = self.root / "invalid.json"
        malformed.write_text("{broken", encoding="utf-8")
        empty = self.root / "empty.json"
        empty.write_text("", encoding="utf-8")
        for path in (malformed, empty, self.root):
            with self.subTest(path=path.name):
                self.topology.load_devices_json(path)
                self.assertEqual(self.topology.DEVICE_IPS, ADDRESSES)
        self.assertEqual(self.output.getvalue().count("unable to parse devices.json"), 3)

    def test_devices_json_permission_error_preserves_existing_mapping(self):
        path = self.write_json({"R1": {"ip": "198.51.100.1"}})
        with patch("builtins.open", side_effect=PermissionError("synthetic denied")):
            self.topology.load_devices_json(path)
        self.assertEqual(self.topology.DEVICE_IPS, ADDRESSES)
        self.assertIn("unable to parse devices.json", self.output.getvalue())

    def test_eth_alias_normalizes_to_eos_ethernet_name(self):
        for value, expected in (("eth1", "Ethernet1"), ("Eth12", "Ethernet12"), ("ETH3", "Ethernet3")):
            with self.subTest(value=value):
                self.assertEqual(self.topology.normalize_interface(value), expected)

    def test_canonical_ethernet_names_are_not_corrupted_by_normalization(self):
        # Containerlab may already supply EOS names; normalization must be idempotent.
        self.assertEqual(self.topology.normalize_interface("Ethernet1"), "Ethernet1")
        self.assertEqual(self.topology.normalize_interface("Ethernet1/1"), "Ethernet1/1")

    def test_other_interface_names_are_preserved_without_inventing_aliases(self):
        for value in ("Port-Channel10", "PortChannel10", "Management0", "lo", "veth0"):
            with self.subTest(value=value):
                self.assertEqual(self.topology.normalize_interface(value), value)

    def test_graph_contains_declared_nodes_links_and_endpoint_interfaces(self):
        graph = self.graph(nodes=["R1", "R2", "H1"])
        self.assertEqual(set(graph.nodes), {"R1", "R2", "H1"})
        self.assertEqual({frozenset(edge) for edge in graph.edges}, {frozenset(("R1", "R2"))})
        self.assertEqual(graph["R1"]["R2"], {
            "endpoint1": "R1:eth1", "endpoint2": "R2:eth2",
            "interface1": "Ethernet1", "interface2": "Ethernet2",
        })

    def test_graph_ignores_links_that_do_not_have_two_endpoints(self):
        path = self.root / "links.yml"
        path.write_text(yaml.safe_dump({"topology": {"nodes": {"R1": {}, "H1": {}}, "links": [
            {}, {"endpoints": ["R1:eth1"]},
            {"endpoints": ["R1:eth1", "H1:eth1", "H2:eth1"]},
        ]}}), encoding="utf-8")
        graph = self.topology.build_topology_graph(path)
        self.assertEqual(set(graph.nodes), {"R1", "H1"})
        self.assertEqual(graph.number_of_edges(), 0)

    def test_graph_file_and_yaml_errors_do_not_produce_a_successful_graph(self):
        missing = self.root / "missing.yml"
        with self.assertRaises(FileNotFoundError):
            self.topology.build_topology_graph(missing)
        with self.assertRaises(IsADirectoryError):
            self.topology.build_topology_graph(self.root)
        malformed = self.root / "broken.yml"
        malformed.write_text("topology: [broken", encoding="utf-8")
        with self.assertRaises(yaml.YAMLError):
            self.topology.build_topology_graph(malformed)
        malformed.write_text("unrelated: {}", encoding="utf-8")
        with self.assertRaises(KeyError):
            self.topology.build_topology_graph(malformed)

    def test_endpoint_status_uses_selected_devices_management_address(self):
        states = {("192.0.2.1", "Ethernet1"): "UP", ("192.0.2.2", "Ethernet1"): "DOWN"}
        self.assertEqual(self.topology.endpoint_status("R1", "Ethernet1", states), "UP")
        self.assertEqual(self.topology.endpoint_status("R2", "Ethernet1", states), "DOWN")
        self.assertIsNone(self.topology.endpoint_status("R1", "Ethernet9", states))
        self.assertIsNone(self.topology.endpoint_status("H1", "Ethernet1", states))

    def test_link_up_requires_up_for_all_available_monitored_endpoints(self):
        states = {("192.0.2.1", "Ethernet1"): "UP", ("192.0.2.2", "Ethernet2"): "UP"}
        self.assertEqual(self.status(states), "UP")

    def test_down_states_override_up_peer(self):
        for value in ("DOWN", "LOWER_LAYER_DOWN", "DORMANT", "NOT_PRESENT"):
            with self.subTest(value=value):
                self.assertEqual(self.status({("192.0.2.1", "Ethernet1"): "UP",
                                              ("192.0.2.2", "Ethernet2"): value}), "DOWN")

    def test_missing_all_telemetry_and_malformed_states_are_unknown(self):
        self.assertEqual(self.status({}), "UNKNOWN")
        for value in ("", "NOT-A-STATUS", "NONE", "7"):
            with self.subTest(value=value):
                self.assertEqual(self.status({("192.0.2.1", "Ethernet1"): value}), "UNKNOWN")

    def test_unmonitored_host_link_uses_available_network_device_status(self):
        self.assertEqual(self.status({("192.0.2.1", "Ethernet1"): "UP"}, nodes=("R1", "H1")), "UP")
        self.assertEqual(self.status({("192.0.2.1", "Ethernet1"): "DOWN"}, nodes=("R1", "H1")), "DOWN")
        self.assertEqual(self.status({}, nodes=("H1", "H2")), "UNKNOWN")

    def test_reversed_networkx_edge_order_preserves_interface_ownership(self):
        # Graph iteration follows node insertion order, not YAML endpoint order.
        graph = self.graph(nodes=["R2", "R1"])
        node1, node2, edge = next(iter(graph.edges(data=True)))
        self.assertEqual((node1, node2), ("R2", "R1"))
        states = {("192.0.2.1", "Ethernet1"): "DOWN", ("192.0.2.2", "Ethernet2"): "UP",
                  ("192.0.2.1", "Ethernet2"): "UP", ("192.0.2.2", "Ethernet1"): "UP"}
        self.assertEqual(self.topology.determine_link_status(node1, node2, edge, states), "DOWN")

    def test_influx_rows_are_keyed_by_source_and_interface_and_status_is_uppercase(self):
        query = self.query(record("192.0.2.1", "Ethernet1", "up"), record("192.0.2.2", "Ethernet2", "down"))
        self.assertEqual(self.topology.get_interface_states(query), {
            ("192.0.2.1", "Ethernet1"): "UP", ("192.0.2.2", "Ethernet2"): "DOWN"})
        arguments = query.query.call_args.kwargs
        self.assertEqual(arguments["org"], "NetPilot")
        self.assertIn('from(bucket: "telemetry")', arguments["query"])
        self.assertIn('"interface_oper_status"', arguments["query"])
        self.assertIn('"oper_status"', arguments["query"])
        self.assertNotIn("synthetic-influx-token", arguments["query"])

    def test_influx_missing_keys_and_empty_tables_do_not_invent_statuses(self):
        query = self.query(record(None, "Ethernet1", "UP"), record("192.0.2.1", None, "UP"))
        self.assertEqual(self.topology.get_interface_states(query), {})
        query.query.return_value = []
        self.assertEqual(self.topology.get_interface_states(query), {})

    def test_null_or_unrecognized_influx_status_does_not_report_up(self):
        for value in (None, {}, 4, "not-a-status"):
            with self.subTest(value=value):
                states = self.topology.get_interface_states(self.query(record("192.0.2.1", "Ethernet1", value)))
                self.assertEqual(self.status(states), "UNKNOWN")

    def test_week_old_up_sample_cannot_prove_current_link_is_up(self):
        # This is inside the current -30d query. No precise age cutoff is imposed;
        # a seven-day-old observation is insufficient evidence of real-time UP.
        now = datetime.now(timezone.utc)
        timestamp = now - timedelta(days=7)
        historical = record("192.0.2.1", "Ethernet1", "UP", timestamp)

        def historical_query(*, query, org):
            # Model Flux's relative range so either a shorter query window or
            # timestamp-aware parsing can correctly exclude historical data.
            match = re.search(r"\brange\(\s*start:\s*-(\d+)\s*([smhd])\s*\)", query)
            self.assertIsNotNone(match, "Fixture requires an explicit relative Flux range")
            seconds = int(match.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]
            rows = [historical] if timestamp >= now - timedelta(seconds=seconds) else []
            return [SimpleNamespace(records=rows)]

        query_api = Mock(query=Mock(side_effect=historical_query))
        states = self.topology.get_interface_states(query_api)
        self.assertEqual(self.status(states), "UNKNOWN")

    def test_query_failure_propagates_without_synthesizing_healthy_states(self):
        query = Mock()
        query.query.side_effect = RuntimeError("synthetic query unavailable")
        with self.assertRaisesRegex(RuntimeError, "synthetic query unavailable"):
            self.topology.get_interface_states(query)

    def test_once_query_failure_closes_client_and_does_not_draw_or_print_success(self):
        graph = self.graph()
        client = Mock()
        client.query_api.return_value.query.side_effect = RuntimeError("synthetic query unavailable")
        self.client_factory.side_effect = None
        self.client_factory.return_value = client
        with patch.object(sys, "argv", ["realtime_topology.py", "fixture.yml", "--once"]), \
                patch.object(self.topology, "load_devices_json"), \
                patch.object(self.topology, "build_topology_graph", return_value=graph), \
                patch.object(self.topology.nx, "kamada_kawai_layout", return_value={}), \
                patch.object(self.topology, "draw_topology") as draw:
            with self.assertRaisesRegex(RuntimeError, "synthetic query unavailable"):
                self.topology.main()
        client.close.assert_called_once_with()
        draw.assert_not_called()
        self.assertNotIn('"up":', self.output.getvalue())
        for boundary in self.blocked:
            boundary.assert_not_called()

    def test_draw_counts_and_colors_correspond_to_actual_link_states_without_image_write(self):
        graph = self.topology.nx.Graph()
        for first, second, interface in (("R1", "H1", "Ethernet1"), ("R1", "H2", "Ethernet2"), ("R2", "H3", "Ethernet3")):
            graph.add_edge(first, second, endpoint1=first + ":" + interface, endpoint2=second + ":eth1",
                           interface1=interface, interface2="Ethernet1")
        states = {("192.0.2.1", "Ethernet1"): "UP", ("192.0.2.1", "Ethernet2"): "DOWN"}
        output = str(self.root / "never-created.png")
        with patch.object(self.topology.nx, "draw_networkx_nodes"), \
                patch.object(self.topology.nx, "draw_networkx_labels"), \
                patch.object(self.topology.nx, "draw_networkx_edge_labels"), \
                patch.object(self.topology.nx, "draw_networkx_edges") as draw_edges:
            result = self.topology.draw_topology(graph, {}, states, output)
        self.assertEqual(result, (output, 1, 1, 1))
        self.assertEqual(draw_edges.call_args.kwargs["edge_color"], ["green", "red", "gray"])
        self.assertEqual(draw_edges.call_args.kwargs["width"], [3, 5, 2])
        self.pyplot.savefig.assert_called_once_with(output, dpi=180, bbox_inches="tight")
        self.pyplot.close.assert_called_once_with()
        self.assertFalse(Path(output).exists())


if __name__ == "__main__":
    unittest.main()

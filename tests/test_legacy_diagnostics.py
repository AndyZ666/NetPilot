"""Offline script integration tests for diagnostics that execute on import.

runpy is used only after synthetic environment/client/render boundaries are in
place. Graph construction, YAML parsing, Flux construction, and report logic
remain real; no script is imported during unittest discovery.
"""

from contextlib import redirect_stdout
from datetime import datetime, timezone
import io
import os
from pathlib import Path
import runpy
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import networkx as nx
import yaml

from security import credential_provider


SCRIPTS = Path(__file__).resolve().parents[1] / "Functions"


class LegacyDiagnosticTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="netpilot-diagnostic-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        original_directory = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, original_directory)
        self.enterContext(patch.dict(os.environ, {}, clear=True))
        for target in ("socket.socket.connect", "socket.create_connection",
                       "subprocess.run", "subprocess.Popen"):
            self.enterContext(patch(target, side_effect=AssertionError("No live diagnostic operations")))
        for name in ("_read_token", "_run_op", "get_credentials"):
            self.enterContext(patch.object(credential_provider, name,
                                          side_effect=AssertionError("No real credential access")))

        # Substitute both module names before execution: importing the script
        # must not select a GUI backend or create a matplotlib cache directory.
        matplotlib = ModuleType("matplotlib")
        self.pyplot = ModuleType("matplotlib.pyplot")
        for name in ("figure", "title", "axis", "tight_layout", "savefig"):
            setattr(self.pyplot, name, MagicMock(name=name))
        matplotlib.pyplot = self.pyplot
        influx = ModuleType("influxdb_client")
        self.client_factory = MagicMock(name="synthetic_influx_client")
        influx.InfluxDBClient = self.client_factory
        self.client = self.client_factory.return_value
        self.query_api = self.client.query_api.return_value
        self.enterContext(patch.dict(sys.modules, {
            "matplotlib": matplotlib, "matplotlib.pyplot": self.pyplot,
            "influxdb_client": influx,
        }))
        self.layout = self.enterContext(patch.object(nx, "kamada_kawai_layout", return_value={}))
        self.draw_nodes = self.enterContext(patch.object(nx, "draw_networkx_nodes"))
        self.draw_edges = self.enterContext(patch.object(nx, "draw_networkx_edges"))
        self.draw_labels = self.enterContext(patch.object(nx, "draw_networkx_labels"))
        self.output = io.StringIO()

    def execute(self, filename, *arguments):
        script = SCRIPTS / filename
        with patch.object(sys, "argv", [str(script), *map(str, arguments)]), redirect_stdout(self.output):
            return runpy.run_path(str(script), run_name="__main__")

    def test_static_topology_builds_real_graph_and_preserves_endpoint_mapping(self):
        path = self.root / "synthetic.clab.yml"
        path.write_text(yaml.safe_dump({"topology": {
            "nodes": {"R1": {}, "S1": {}, "S2": {}, "isolated": {}},
            "links": [
                {"endpoints": ["R1:eth1", "S1:eth3"]},
                {"endpoints": ["S1:eth2", "S2:eth4"]},
                {}, {"endpoints": ["R1:eth9"]},
                {"endpoints": ["R1:eth7", "S1:eth7", "S2:eth7"]},
            ],
        }}), encoding="utf-8")
        result = self.execute("realtime_topology_static.py", path)
        graph = result["G"]
        self.assertIsInstance(graph, nx.Graph)
        self.assertEqual(set(graph.nodes), {"R1", "S1", "S2", "isolated"})
        self.assertEqual({frozenset(edge) for edge in graph.edges},
                         {frozenset(("R1", "S1")), frozenset(("S1", "S2"))})
        self.assertEqual(graph["R1"]["S1"], {"endpoint1": "R1:eth1", "endpoint2": "S1:eth3"})
        self.assertEqual(graph["S1"]["S2"], {"endpoint1": "S1:eth2", "endpoint2": "S2:eth4"})
        self.layout.assert_called_once_with(graph)
        for render in (self.draw_nodes, self.draw_edges, self.draw_labels):
            self.assertIs(render.call_args.args[0], graph)
        self.pyplot.savefig.assert_called_once_with("netpilot_topology.png", dpi=200, bbox_inches="tight")
        output = self.output.getvalue()
        self.assertIn("R1:eth1 <--> S1:eth3", output)
        self.assertIn("Total devices: 4", output)
        self.assertIn("Total links:   2", output)
        self.assertFalse((self.root / "netpilot_topology.png").exists())

    def test_static_topology_usage_exits_before_file_or_render_work(self):
        for arguments in ((), ("absent-one.yml", "absent-two.yml")):
            with self.subTest(argument_count=len(arguments)):
                with self.assertRaises(SystemExit) as caught:
                    self.execute("realtime_topology_static.py", *arguments)
                self.assertEqual(caught.exception.code, 1)
        self.assertIn("Usage:", self.output.getvalue())
        self.layout.assert_not_called()
        self.pyplot.savefig.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_static_topology_missing_or_malformed_file_never_reports_saved_image(self):
        path = self.root / "synthetic.clab.yml"
        cases = ((None, FileNotFoundError), ("topology: [unterminated", yaml.YAMLError),
                 ("name: fixture-only\n", KeyError))
        for content, exception in cases:
            with self.subTest(error=exception.__name__):
                if content is not None:
                    path.write_text(content, encoding="utf-8")
                with self.assertRaises(exception):
                    self.execute("realtime_topology_static.py", path)
                self.layout.assert_not_called()
                self.pyplot.savefig.assert_not_called()
        self.assertNotIn("Topology image saved", self.output.getvalue())

    def test_influx_diagnostic_flattens_sorts_and_counts_real_query_results(self):
        timestamp = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)

        def record(source, interface, status):
            return SimpleNamespace(values={"source": source, "name": interface},
                                   get_value=lambda: status, get_time=lambda: timestamp)

        self.query_api.query.return_value = [
            SimpleNamespace(records=[record("192.0.2.2", "Ethernet2", 2)]),
            SimpleNamespace(records=[]),
            SimpleNamespace(records=[record("192.0.2.1", "Ethernet2", 1),
                                     record("192.0.2.1", "Ethernet1", 2)]),
        ]
        with patch.dict(os.environ, {"INFLUX_TOKEN": "synthetic-influx-token"}):
            result = self.execute("test_influx_status.py")
        self.client_factory.assert_called_once_with(url="http://127.0.0.1:8086",
                                                   token="synthetic-influx-token", org="NetPilot")
        self.query_api.query.assert_called_once()
        options = self.query_api.query.call_args.kwargs
        self.assertEqual(options["org"], "NetPilot")
        query = " ".join(options["query"].split())
        for fragment in ('from(bucket: "telemetry")', 'range(start: -30d)',
                         'r["_measurement"] == "interface_oper_status"',
                         'r["_field"] == "oper_status"', 'group(columns: ["source", "name"])',
                         'last()', 'keep(columns: ["_time", "source", "name", "_value"])'):
            self.assertIn(fragment, query)
        self.assertEqual(result["results"], [
            {"source": "192.0.2.1", "interface": "Ethernet1", "status": 2, "time": timestamp},
            {"source": "192.0.2.1", "interface": "Ethernet2", "status": 1, "time": timestamp},
            {"source": "192.0.2.2", "interface": "Ethernet2", "status": 2, "time": timestamp},
        ])
        self.assertEqual(result["sources"], ["192.0.2.1", "192.0.2.2"])
        output = self.output.getvalue()
        self.assertIn("Interfaces found: 3", output)
        self.assertIn("Devices found:    2", output)
        self.assertNotIn("synthetic-influx-token", output)
        self.client.close.assert_called_once_with()

    def test_influx_diagnostic_requires_token_before_client_creation(self):
        for environment in ({}, {"INFLUX_TOKEN": ""}):
            with self.subTest(token_present="INFLUX_TOKEN" in environment), \
                    patch.dict(os.environ, environment, clear=True):
                with self.assertRaisesRegex(RuntimeError, "INFLUX_TOKEN is not set"):
                    self.execute("test_influx_status.py")
                self.client_factory.assert_not_called()
                self.query_api.query.assert_not_called()
        self.assertEqual(self.output.getvalue(), "")

    def test_influx_diagnostic_empty_tables_report_zero_counts_and_close(self):
        for tables in ([], [SimpleNamespace(records=[])]):
            with self.subTest(table_count=len(tables)), \
                    patch.dict(os.environ, {"INFLUX_TOKEN": "synthetic-influx-token"}):
                self.query_api.query.return_value = tables
                self.client.close.reset_mock()
                self.output.seek(0)
                self.output.truncate(0)
                result = self.execute("test_influx_status.py")
                self.assertEqual(result["results"], [])
                self.assertEqual(result["sources"], [])
                self.assertIn("Interfaces found: 0", self.output.getvalue())
                self.assertIn("Devices found:    0", self.output.getvalue())
                self.client.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()

"""Offline monitoring integration; no real services, credentials, or Influx queries."""

from datetime import datetime, timezone
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from security import rotation_monitoring as monitor
from security.rotation_state import FLEET


NOW = 1800000000
TARGETS = {name: f"192.0.2.{index}" for index, name in enumerate(FLEET, 1)}
CONFIG = '''
[[inputs.gnmi]]
[[inputs.gnmi.subscription]]
name = "fixture_counters"
path = "/interfaces/interface/state/counters"
subscription_mode = "sample"
sample_interval = "10s"
[[outputs.influxdb_v2]]
urls = ["http://192.0.2.100:8086"]
organization = "fixture-org"
bucket = "fixture-bucket"
token = "must-not-use-config-token"
'''


def rows(at=NOW):
    return [SimpleNamespace(values={
        "source": address, "name": "Ethernet1", "_measurement": "fixture_counters",
        "_field": "in_octets", "_time": datetime.fromtimestamp(at, timezone.utc),
        "_value": 100,
    }) for address in TARGETS.values()]


class RotationMonitoringTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "telegraf.conf"
        self.path.write_text(CONFIG)
        self.enterContext(patch.dict("os.environ", {"INFLUX_TOKEN": "synthetic-token"}, clear=True))
        self.enterContext(patch.object(monitor.time, "time", return_value=NOW))
        self.run = self.enterContext(patch.object(monitor.subprocess, "run"))
        self.sleep = self.enterContext(patch.object(monitor.time, "sleep"))
        self.client = MagicMock()
        self.factory = self.enterContext(patch.object(monitor, "InfluxDBClient", return_value=self.client))
        self.private_token = self.enterContext(patch.object(monitor, "read_influx_file", return_value="private-fixture-token"))
        self.data = rows()
        self.client.query_api.return_value.query.return_value = [SimpleNamespace(records=self.data)]
        self.monitor = monitor.ManagedTelegrafMonitoring(self.path, timeout=0)

    def test_constructor_is_offline(self):
        self.factory.assert_not_called()
        self.run.assert_not_called()
        self.private_token.assert_not_called()

    def test_current_health_reads_existing_schema_and_never_restarts(self):
        self.assertTrue(self.monitor.verify_current("fixture", TARGETS))
        self.run.assert_called_once_with(
            ["systemctl", "--user", "--no-ask-password", "is-active", "--quiet", monitor.SERVICE],
            check=True, capture_output=True, timeout=45, shell=False)
        self.factory.assert_called_once_with(url="http://192.0.2.100:8086", org="fixture-org",
                                            token="synthetic-token", timeout=10000)
        query = self.client.query_api.return_value.query.call_args.kwargs["query"]
        self.assertIn('"fixture_counters"', query)
        self.assertIn('"fixture-bucket"', query)
        self.assertNotIn("synthetic-token", query)
        for address in TARGETS.values():
            self.assertIn(address, query)
        self.client.close.assert_called_once()

    def test_restart_only_fixed_user_service_then_checks_new_data(self):
        self.assertTrue(self.monitor.refresh_and_verify("fixture", TARGETS))
        commands = [invocation.args[0] for invocation in self.run.call_args_list]
        self.assertEqual(commands[0], ["systemctl", "--user", "--no-ask-password", "restart", monitor.SERVICE])
        self.assertEqual(commands[1][3], "is-active")
        query = self.client.query_api.return_value.query.call_args.kwargs["query"]
        self.assertIn(datetime.fromtimestamp(NOW, timezone.utc).isoformat(), query)

    def test_missing_stale_future_and_pre_restart_data_fail(self):
        for invalid in (rows()[:-1], rows(NOW - 31), rows(NOW + 3)):
            with self.subTest(data=len(invalid)):
                self.data[:] = invalid
                with self.assertRaises(monitor.MonitoringError):
                    self.monitor.verify_current("fixture", TARGETS)
        self.data[:] = rows(NOW - 1)
        with self.assertRaises(monitor.MonitoringError):
            self.monitor.refresh_and_verify("fixture", TARGETS)

    def test_reconnect_poll_can_recover_before_deadline(self):
        self.monitor.timeout = 90
        self.client.query_api.return_value.query.side_effect = [
            [SimpleNamespace(records=rows(NOW - 1))], [SimpleNamespace(records=rows())],
        ]
        self.assertTrue(self.monitor.refresh_and_verify("fixture", TARGETS))
        self.sleep.assert_called_once_with(5)
        self.assertEqual(sum(invocation.args[0][3] == "restart" for invocation in self.run.call_args_list), 1)

    def test_external_influx_source_and_config_overrides_are_reused(self):
        with patch.dict("os.environ", {"INFLUX_URL": "https://example.invalid", "INFLUX_ORG": "override-org",
                                      "INFLUX_BUCKET": "override-bucket"}, clear=True):
            self.assertTrue(self.monitor.verify_current("fixture", TARGETS))
        self.private_token.assert_called_once_with(Path.home() / ".config/netpilot/secrets/influx-token")
        self.factory.assert_called_once_with(url="https://example.invalid", org="override-org",
                                            token="private-fixture-token", timeout=10000)
        self.assertIn('"override-bucket"', self.client.query_api.return_value.query.call_args.kwargs["query"])

    def test_unavailable_service_or_query_errors_are_sanitized(self):
        self.run.side_effect = RuntimeError("private error body synthetic-token")
        with self.assertRaises(monitor.MonitoringError) as failed:
            self.monitor.verify_current("fixture", TARGETS)
        self.assertNotIn("synthetic-token", str(failed.exception))
        self.client.query_api.assert_not_called()
        self.run.side_effect = None
        self.client.query_api.return_value.query.side_effect = RuntimeError("private synthetic-token")
        with self.assertRaises(monitor.MonitoringError) as failed:
            self.monitor.verify_current("fixture", TARGETS)
        self.assertNotIn("synthetic-token", str(failed.exception))

    def test_partial_fleet_is_not_reported_as_verified(self):
        with self.assertRaises(monitor.MonitoringError):
            self.monitor.verify_current("fixture", {"R1": TARGETS["R1"]})
        self.factory.assert_not_called()
        self.run.assert_not_called()


if __name__ == "__main__":
    unittest.main()

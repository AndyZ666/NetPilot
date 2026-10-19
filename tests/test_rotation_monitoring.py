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
        self.enterContext(patch("socket.socket.connect", side_effect=AssertionError("No live network")))
        self.enterContext(patch("socket.create_connection", side_effect=AssertionError("No live network")))
        self.enterContext(patch("security.credential_provider.get_credentials",
                                side_effect=AssertionError("No real Vault access")))
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


    def test_wrong_fleet_names_and_duplicate_addresses_fail_before_external_access(self):
        wrong_name = dict(TARGETS)
        wrong_name["unexpected-device"] = wrong_name.pop("R1")
        duplicate = dict(TARGETS, R2=TARGETS["R1"])
        for targets in (wrong_name, duplicate):
            with self.subTest(targets=targets), self.assertRaises(monitor.MonitoringError):
                self.monitor.verify_current("fixture", targets)
        self.factory.assert_not_called()
        self.run.assert_not_called()
        self.private_token.assert_not_called()

    def test_invalid_target_addresses_cannot_be_verified_by_matching_source_labels(self):
        # The fleet contract identifies devices by management IP, not arbitrary
        # Influx source labels. A matching label is not proof of a valid target.
        for address in ("not-an-ip", "192.0.2.999", "192.0.2.1/24", None):
            with self.subTest(address=address):
                targets = dict(TARGETS, R1=address)
                self.data[:] = rows()
                self.data[0].values["source"] = address
                with self.assertRaises(monitor.MonitoringError):
                    self.monitor.verify_current("fixture", targets)

    def test_freshness_accepts_exact_age_and_future_allowance_boundaries(self):
        for stamp in (NOW - 30, NOW + 2):
            with self.subTest(stamp=stamp):
                self.data[:] = rows(stamp)
                self.assertTrue(self.monitor.verify_current("fixture", TARGETS))
        self.assertEqual(self.client.close.call_count, 2)

    def test_offset_timestamps_are_compared_as_instants(self):
        self.data[:] = rows()
        self.data[0].values["_time"] = datetime.fromisoformat("2027-01-15T11:00:00+03:00")
        self.assertEqual(self.data[0].values["_time"].timestamp(), NOW)
        self.assertTrue(self.monitor.verify_current("fixture", TARGETS))

    def test_schema_and_timestamp_errors_prevent_fleet_verification(self):
        for key, value in (("_measurement", "other_measurement"), ("_field", "out_octets"),
                           ("_time", None), ("_time", "private-timestamp-marker"),
                           ("_time", datetime(2027, 1, 15))):
            with self.subTest(field=key, value=value):
                self.data[:] = rows()
                self.data[0].values[key] = value
                with self.assertRaises(monitor.MonitoringError) as failed:
                    self.monitor.verify_current("fixture", TARGETS)
                self.assertNotIn("private-timestamp-marker", str(failed.exception))
        self.assertEqual(self.client.close.call_count, 5)

    def test_missing_malformed_and_unexpected_sources_do_not_prove_full_fleet(self):
        duplicates = rows()[:-1] + [rows()[0]]
        unexpected = rows() + [SimpleNamespace(values=dict(rows()[0].values, source="192.0.2.250"))]
        for tables in ([], None, [SimpleNamespace()],
                       [SimpleNamespace(records=[SimpleNamespace(values=None)])],
                       [SimpleNamespace(records=duplicates)], [SimpleNamespace(records=unexpected)]):
            with self.subTest(tables=tables):
                self.client.query_api.return_value.query.return_value = tables
                with self.assertRaises(monitor.MonitoringError):
                    self.monitor.verify_current("fixture", TARGETS)
        self.assertEqual(self.client.close.call_count, 6)

    def test_one_fresh_interface_per_device_is_sufficient_even_with_stale_other_interfaces(self):
        # Rotation proves renewed collection from each device, not every port's
        # health. A stale second interface cannot erase the fresh device sample.
        self.data[:] = rows(NOW - 31) + rows()
        for record in self.data[len(TARGETS):]:
            record.values["name"] = "Ethernet2"
        self.assertTrue(self.monitor.verify_current("fixture", TARGETS))

    def test_invalid_settings_fail_before_credentials_client_or_service_access(self):
        invalid = (
            CONFIG.replace("[[inputs.gnmi]]", "[inputs.gnmi]"),
            CONFIG.replace('name = "fixture_counters"', 'name = 42'),
            CONFIG.replace('urls = ["http://192.0.2.100:8086"]', 'urls = []'),
            CONFIG.replace('http://192.0.2.100:8086', 'https://private-marker@example.invalid'),
            CONFIG.replace('http://192.0.2.100:8086', 'https://example.invalid/?token=private-marker'),
            CONFIG + '\n[[outputs.influxdb_v2]]\nurls = ["http://192.0.2.101"]\n',
        )
        for config in invalid:
            with self.subTest(config=config):
                self.path.write_text(config)
                with self.assertRaises(monitor.MonitoringError) as failed:
                    self.monitor.verify_current("fixture", TARGETS)
                self.assertNotIn("private-marker", str(failed.exception))
        self.factory.assert_not_called()
        self.run.assert_not_called()
        self.private_token.assert_not_called()

    def test_client_construction_failure_is_sanitized_before_service_access(self):
        self.factory.side_effect = RuntimeError("private-client-marker synthetic-token")
        with self.assertRaises(monitor.MonitoringError) as failed:
            self.monitor.verify_current("fixture", TARGETS)
        self.assertNotIn("private-client-marker", str(failed.exception))
        self.assertNotIn("synthetic-token", str(failed.exception))
        self.assertTrue(failed.exception.__suppress_context__)
        self.run.assert_not_called()
        self.client.close.assert_not_called()

    def test_close_failure_does_not_change_verified_or_failed_result(self):
        self.client.close.side_effect = RuntimeError("private-close-marker")
        self.assertTrue(self.monitor.verify_current("fixture", TARGETS))
        self.data.clear()
        with self.assertRaises(monitor.MonitoringError) as failed:
            self.monitor.verify_current("fixture", TARGETS)
        self.assertNotIn("private-close-marker", str(failed.exception))
        self.assertEqual(self.client.close.call_count, 2)

    def test_poll_stops_at_exact_deadline_and_closes_client(self):
        self.monitor.timeout = 5
        self.data.clear()
        with patch.object(monitor.time, "monotonic", side_effect=[0, 0, 5]):
            with self.assertRaises(monitor.MonitoringError):
                self.monitor.refresh_and_verify("fixture", TARGETS)
        self.sleep.assert_called_once_with(5)
        actions = [invocation.args[0][3] for invocation in self.run.call_args_list]
        self.assertEqual(actions, ["restart", "is-active", "is-active"])
        self.assertEqual(self.client.query_api.return_value.query.call_count, 2)
        self.client.close.assert_called_once()

    def test_refresh_queries_from_restart_completion_and_does_not_verify_failed_restart(self):
        clock = [NOW]

        def complete_restart(arguments, **kwargs):
            if arguments[3] == "restart":
                clock[0] = NOW + 10

        self.run.side_effect = complete_restart
        self.data[:] = rows(NOW + 10)
        with patch.object(monitor.time, "time", side_effect=lambda: clock[0]):
            self.assertTrue(self.monitor.refresh_and_verify("fixture", TARGETS))
        query = self.client.query_api.return_value.query.call_args.kwargs["query"]
        self.assertIn('range(start: time(v: "2027-01-15T08:00:10+00:00"))', query)
        self.factory.reset_mock()
        self.run.side_effect = RuntimeError("private-restart-marker")
        with self.assertRaises(monitor.MonitoringError) as failed:
            self.monitor.refresh_and_verify("fixture", TARGETS)
        self.assertNotIn("private-restart-marker", str(failed.exception))
        self.factory.assert_not_called()

    def test_interrupted_poll_closes_client_and_does_not_retry_restart(self):
        self.client.query_api.return_value.query.side_effect = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.monitor.refresh_and_verify("fixture", TARGETS)
        self.sleep.assert_not_called()
        self.client.close.assert_called_once()
        self.assertEqual([call.args[0][3] for call in self.run.call_args_list], ["restart", "is-active"])


if __name__ == "__main__":
    unittest.main()

"""Maintenance telemetry checks use synthetic Flux records, never live services."""

from datetime import datetime, timezone
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from Functions.maintenance_telemetry import Telemetry, TelemetryError


NOW = 1800000000
SOURCES = {"R1": "172.20.20.13", "R2": "172.20.20.14"}
INTERFACES = {name: ["Ethernet1", "Ethernet2"] for name in SOURCES}
CONFIG = '''
[[inputs.gnmi]]
[[inputs.gnmi.subscription]]
name = "fixture_interface_counters"
path = "/interfaces/interface/state/counters"
subscription_mode = "sample"
sample_interval = "10s"
[[outputs.influxdb_v2]]
urls = ["http://127.0.0.1:8086"]
organization = "NetPilot"
bucket = "telemetry"
token = "must-never-use-configuration-token"
'''


def records():
    return [SimpleNamespace(values={
        "_measurement": "fixture_interface_counters", "_field": field,
        "_time": datetime.fromtimestamp(NOW - age, timezone.utc),
        "_value": value, "source": source, "name": interface,
        "host": "fixture-collector", "path": "/interfaces/interface/state/counters",
    }) for source in SOURCES.values() for interface in ["Ethernet1", "Ethernet2"]
        for field in ["in_octets", "out_octets"] for age, value in [(20, 1000), (10, 1200)]]


class TelemetryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config = Path(self.directory.name) / "telegraf.conf"
        self.config.write_text(CONFIG)
        self.environment = patch.dict("os.environ", {"INFLUX_TOKEN": "fixture-env-only"}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.client = MagicMock()
        self.factory = patch("Functions.maintenance_telemetry.InfluxDBClient", return_value=self.client)
        self.factory_mock = self.factory.start()
        self.addCleanup(self.factory.stop)
        self.clock = patch("Functions.maintenance_telemetry.time.time", return_value=NOW)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.data = records()
        self.client.query_api.return_value.query.return_value = [SimpleNamespace(records=self.data)]

    def telemetry(self, **kwargs):
        instance = Telemetry(self.config, **kwargs)
        self.addCleanup(instance.close)
        return instance

    def assert_bad_records(self):
        with self.assertRaises(TelemetryError):
            self.telemetry().rates(SOURCES, INTERFACES)

    def test_rate_uses_timestamp_delta_and_reports_bits_per_second(self):
        telemetry = self.telemetry()
        result = telemetry.rates(SOURCES, INTERFACES)
        self.assertEqual(result["R1"]["Ethernet1"], {
            "rx_bps": 160.0, "tx_bps": 160.0, "start": NOW - 20, "end": NOW - 10,
            "rx_start": NOW - 20, "rx_end": NOW - 10, "tx_start": NOW - 20, "tx_end": NOW - 10,
        })
        self.assertEqual(set(result), {"R1", "R2"})
        query = self.client.query_api.return_value.query.call_args.kwargs["query"]
        self.assertIn('fixture_interface_counters', query)
        self.assertNotIn('aggregateWindow', query)
        self.assertIn('range(start: -120s)', query)

    def test_measurement_and_sample_interval_come_from_existing_toml(self):
        telemetry = self.telemetry()
        self.assertEqual(telemetry.measurement, "fixture_interface_counters")
        self.assertEqual(telemetry.sample_interval, 10)
        self.factory_mock.assert_called_once_with(url="http://127.0.0.1:8086", org="NetPilot", token="fixture-env-only", timeout=10000)

    def test_environment_destination_overrides(self):
        with patch.dict("os.environ", {"INFLUX_URL": "https://influx.example", "INFLUX_ORG": "fixture-org", "INFLUX_BUCKET": "fixture-bucket"}):
            telemetry = self.telemetry()
        self.assertEqual((telemetry.url, telemetry.org, telemetry.bucket), ("https://influx.example", "fixture-org", "fixture-bucket"))

    def test_missing_environment_token_never_falls_back_to_toml_secret(self):
        with patch.dict("os.environ", {}, clear=True), self.assertRaisesRegex(TelemetryError, "INFLUX_TOKEN"):
            self.telemetry()
        self.factory_mock.assert_not_called()

    def test_missing_transmit_counter_is_not_zero_filled(self):
        self.data[:] = [row for row in self.data if row.values["_field"] != "out_octets"]
        self.assert_bad_records()

    def test_one_point_and_repeated_identical_point_are_not_two_samples(self):
        self.data[:] = [row for row in self.data if row.values["_value"] == 1200]
        self.data.extend(self.data[:])
        self.assert_bad_records()

    def test_valid_duplicate_samples_do_not_change_rates(self):
        self.data.extend(self.data[:])
        self.assertEqual(self.telemetry().rates(SOURCES, INTERFACES)["R2"]["Ethernet2"]["tx_bps"], 160)

    def test_conflicting_duplicate_is_rejected(self):
        duplicate = dict(self.data[0].values, _value=9999)
        self.data.append(SimpleNamespace(values=duplicate))
        self.assert_bad_records()

    def test_counter_reset_is_rejected(self):
        self.data[1].values["_value"] = 1
        self.assert_bad_records()

    def test_uint64_subtraction_preserves_small_deltas(self):
        for row in self.data:
            row.values["_value"] += 2**63
        self.assertEqual(self.telemetry().rates(SOURCES, INTERFACES)["R1"]["Ethernet1"]["rx_bps"], 160)

    def test_non_numeric_nonfinite_negative_or_fractional_values_fail(self):
        for value in ["1200", None, True, float("nan"), float("inf"), -1, 1.5]:
            with self.subTest(value=value):
                self.data[1].values["_value"] = value
                self.assert_bad_records()

    def test_stale_end_timestamp_is_rejected(self):
        for row in self.data:
            row.values["_time"] = datetime.fromtimestamp(row.values["_time"].timestamp() - 60, timezone.utc)
        self.assert_bad_records()

    def test_sampling_gap_is_rejected(self):
        self.data[0].values["_time"] = datetime.fromtimestamp(NOW - 80, timezone.utc)
        self.assert_bad_records()

    def test_future_or_timezone_naive_timestamp_is_rejected(self):
        for stamp in [datetime.fromtimestamp(NOW + 10, timezone.utc), datetime.fromtimestamp(NOW - 10), "not a timestamp"]:
            with self.subTest(stamp=stamp):
                self.data[1].values["_time"] = stamp
                self.assert_bad_records()

    def test_multiple_collectors_for_same_counter_are_rejected(self):
        self.data[1].values["host"] = "second-collector"
        self.assert_bad_records()

    def test_changed_optional_path_tag_is_ambiguous(self):
        self.data[1].values.pop("path")
        self.assert_bad_records()

    def test_missing_or_unexpected_schema_tags_fail(self):
        for key in ["source", "name", "_measurement"]:
            with self.subTest(key=key):
                previous = self.data[0].values.pop(key)
                self.assert_bad_records()
                self.data[0].values[key] = previous

    def test_server_errors_are_sanitized(self):
        self.client.query_api.return_value.query.side_effect = RuntimeError("fixture-env-only private response")
        with self.assertRaises(TelemetryError) as caught:
            self.telemetry().rates(SOURCES, INTERFACES)
        self.assertNotIn("fixture-env-only", str(caught.exception))
        self.assertNotIn("private response", str(caught.exception))

    def test_ambiguous_or_unsupported_subscription_fails(self):
        self.config.write_text(CONFIG.replace("/interfaces/interface/state/counters", "/unknown"))
        with self.assertRaises(TelemetryError):
            self.telemetry()

    def test_missing_config_and_bad_max_age_fail_safely(self):
        for max_age in [0, -1, float("nan"), float("inf"), True, 121]:
            with self.subTest(max_age=max_age), self.assertRaises(TelemetryError):
                self.telemetry(max_age=max_age)
        self.config.unlink()
        with self.assertRaises(TelemetryError):
            self.telemetry()

    def test_duplicate_addresses_or_missing_interface_selection_fails(self):
        for sources, interfaces in [({"R1": SOURCES["R1"], "R2": SOURCES["R1"]}, INTERFACES), (SOURCES, {"R1": []}), ({}, {})]:
            with self.subTest(sources=sources), self.assertRaises(TelemetryError):
                self.telemetry().rates(sources, interfaces)

    def test_direction_intervals_report_oldest_start_and_end(self):
        for row in self.data:
            if row.values["_field"] == "out_octets":
                row.values["_time"] = datetime.fromtimestamp(row.values["_time"].timestamp() - 2, timezone.utc)
        result = self.telemetry().rates(SOURCES, INTERFACES)["R1"]["Ethernet1"]
        self.assertEqual((result["start"], result["end"]), (NOW - 22, NOW - 12))
        self.assertEqual((result["rx_start"], result["rx_end"]), (NOW - 20, NOW - 10))
        self.assertEqual((result["tx_start"], result["tx_end"]), (NOW - 22, NOW - 12))


if __name__ == "__main__":
    unittest.main()

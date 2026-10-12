"""Fresh counter evidence for maintenance; reuse the existing Telegraf/Influx stack."""

from datetime import datetime
import ipaddress
import json
import math
import os
from pathlib import Path
import time
import tomllib
from urllib.parse import urlsplit

from influxdb_client import InfluxDBClient


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "telegraf" / "telegraf-gnmi-influx.conf"
# Verified in query.csv and Functions/realtime_topology.py; live queries below
# must contain these tags/fields for every requested device and interface.
SOURCE_TAG = "source"
INTERFACE_TAG = "name"
COUNTER_FIELDS = {"rx_bps": "in_octets", "tx_bps": "out_octets"}
_RECORD_COLUMNS = {
    "result", "table", "_start", "_stop", "_time", "_value", "_field",
    "_measurement", SOURCE_TAG, INTERFACE_TAG,
}


class TelemetryError(RuntimeError):
    """A safe explanation that never includes credentials or server responses."""


class Telemetry:
    """Read rates in bits/second; constructor and queries require INFLUX_TOKEN."""

    def __init__(self, config_path=DEFAULT_CONFIG, max_age=30):
        try:
            self.max_age = float(max_age)
            if isinstance(max_age, bool) or not 1 <= self.max_age <= 120:
                raise ValueError
            with Path(config_path).open("rb") as handle:
                config = tomllib.load(handle)
            subscriptions = [
                sub for plugin in config["inputs"]["gnmi"]
                for sub in plugin.get("subscription", [])
                if sub.get("path", "").rstrip("/") == "/interfaces/interface/state/counters"
            ]
            if len(subscriptions) != 1 or subscriptions[0].get("subscription_mode") != "sample":
                raise ValueError
            subscription = subscriptions[0]
            self.measurement = subscription["name"]
            if not isinstance(self.measurement, str) or not self.measurement:
                raise ValueError
            interval = str(subscription["sample_interval"])
            units = {"ms": .001, "s": 1, "m": 60}
            unit = next(unit for unit in units if interval.endswith(unit))
            self.sample_interval = float(interval[:-len(unit)]) * units[unit]
            if not math.isfinite(self.sample_interval) or self.sample_interval <= 0:
                raise ValueError
            outputs = config["outputs"]["influxdb_v2"]
            if len(outputs) != 1:
                raise ValueError
            output = outputs[0]
            self.url = os.environ.get("INFLUX_URL", "").strip() or output["urls"][0]
            self.org = os.environ.get("INFLUX_ORG", "").strip() or output["organization"]
            self.bucket = os.environ.get("INFLUX_BUCKET", "").strip() or output["bucket"]
            address = urlsplit(self.url)
            if (address.scheme not in {"http", "https"} or not address.hostname
                    or address.username or address.password or address.query or address.fragment
                    or not isinstance(self.org, str) or not self.org
                    or not isinstance(self.bucket, str) or not self.bucket):
                raise ValueError
        except (OSError, ValueError, TypeError, KeyError, IndexError, StopIteration):
            raise TelemetryError("The existing Telegraf counter configuration is unavailable or invalid.") from None
        token = os.environ.get("INFLUX_TOKEN")
        if not token:
            raise TelemetryError("INFLUX_TOKEN must be exported before checking maintenance telemetry.")
        try:
            self.client = InfluxDBClient(url=self.url, token=token, org=self.org, timeout=10000)
        except Exception:
            raise TelemetryError("The InfluxDB telemetry client could not be initialized.") from None

    def close(self):
        try:
            self.client.close()
        except Exception:
            pass

    def rates(self, sources, interfaces):
        """Return hostname -> interface -> rx_bps, tx_bps, start, end (UTC epochs).

        Both directions require their own complete, fresh, increasing sample
        pair. start/end are the oldest start/end across the two directions, so
        callers can require post-change evidence and new consecutive windows.
        Missing TX/RX, resets, conflicting duplicates or ambiguous series fail.
        """
        try:
            addresses = {name: str(ipaddress.ip_interface(ip).ip) for name, ip in sources.items()}
            requested = {(addresses[name], interface) for name in addresses for interface in interfaces[name]}
            if (not addresses or len(set(addresses.values())) != len(addresses)
                    or any(not interfaces[name] for name in addresses)
                    or any(not isinstance(iface, str) or not iface for _, iface in requested)):
                raise ValueError
        except (AttributeError, ValueError, TypeError, KeyError):
            raise TelemetryError("Telemetry requires unique management addresses and production interfaces.") from None
        ip_filter = " or ".join(f'r[{json.dumps(SOURCE_TAG)}] == {json.dumps(ip)}' for ip in sorted(set(addresses.values())))
        interface_filter = " or ".join(f'r[{json.dumps(INTERFACE_TAG)}] == {json.dumps(iface)}' for iface in sorted({iface for _, iface in requested}))
        field_filter = " or ".join(f'r._field == {json.dumps(field)}' for field in COUNTER_FIELDS.values())
        lookback = math.ceil(max(120, self.max_age * 2))
        query = (
            f'from(bucket: {json.dumps(self.bucket)}) |> range(start: -{lookback}s) '
            f'|> filter(fn: (r) => r._measurement == {json.dumps(self.measurement)}) '
            f'|> filter(fn: (r) => ({ip_filter}) and ({interface_filter}) and ({field_filter}))'
        )
        series, tags = {}, {}
        try:
            tables = self.client.query_api().query(query=query, org=self.org)
            for table in tables:
                for record in table.records:
                    row = record.values
                    source, interface, field = row.get(SOURCE_TAG), row.get(INTERFACE_TAG), row.get("_field")
                    if ((source, interface) not in requested or field not in COUNTER_FIELDS.values()
                            or row.get("_measurement") != self.measurement):
                        raise TelemetryError("InfluxDB returned an unexpected counter schema.")
                    key = source, interface, field
                    signature = tuple(sorted((name, str(value)) for name, value in row.items() if name not in _RECORD_COLUMNS))
                    if key in tags and tags[key] != signature:
                        raise TelemetryError("Multiple telemetry series describe the same interface counter.")
                    tags[key] = signature
                    stamp, value = row.get("_time"), row.get("_value")
                    if not isinstance(stamp, datetime) or stamp.utcoffset() is None:
                        raise TelemetryError("Counter timestamps are missing or invalid.")
                    stamp = stamp.timestamp()
                    if (isinstance(value, bool) or not isinstance(value, (int, float))
                            or not math.isfinite(value) or value < 0 or int(value) != value):
                        raise TelemetryError("A cumulative interface counter is invalid.")
                    samples = series.setdefault(key, {})
                    if stamp in samples and samples[stamp] != int(value):
                        raise TelemetryError("Conflicting duplicate telemetry samples were received.")
                    samples[stamp] = int(value)
        except TelemetryError:
            raise
        except Exception:
            raise TelemetryError("Fresh interface counters could not be read from InfluxDB.") from None

        now, result = time.time(), {}
        for hostname, address in addresses.items():
            result[hostname] = {}
            for interface in interfaces[hostname]:
                rate, starts, ends = {}, [], []
                for direction, field in COUNTER_FIELDS.items():
                    samples = sorted(series.get((address, interface, field), {}).items())
                    if len(samples) < 2:
                        raise TelemetryError("Two distinct RX and TX samples are required for every production interface.")
                    (start, first), (end, last) = samples[-2:]
                    elapsed = end - start
                    if end > now + 2 or now - end > self.max_age or not 0 < elapsed <= self.max_age:
                        raise TelemetryError("Interface counters are stale, future-dated, or separated by a sampling gap.")
                    if last < first:
                        raise TelemetryError("An interface counter reset or wrapped; drain evidence is invalid.")
                    rate[direction] = (last - first) * 8 / elapsed
                    rate[direction.split('_')[0] + '_start'] = start
                    rate[direction.split('_')[0] + '_end'] = end
                    if not math.isfinite(rate[direction]):
                        raise TelemetryError("An interface traffic rate is invalid.")
                    starts.append(start)
                    ends.append(end)
                rate.update(start=min(starts), end=min(ends))
                result[hostname][interface] = rate
        return result

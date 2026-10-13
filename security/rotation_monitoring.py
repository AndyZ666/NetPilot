"""Refresh the existing user-managed collector and prove fresh fleet telemetry.

No import/constructor contacts services or reads credentials. Only the rotation
controller calls refresh_and_verify, after verified Current promotion.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import time
import tomllib
from urllib.parse import urlsplit

from influxdb_client import InfluxDBClient

from Functions.maintenance_telemetry import COUNTER_FIELDS, DEFAULT_CONFIG, SOURCE_TAG
from security.rotation_state import FLEET
from security.telegraf_launcher import influx_token, interpolation_value, read_influx_file


SERVICE = "netpilot-telegraf.service"


class MonitoringError(RuntimeError):
    category = "monitoring"

    def __init__(self):
        super().__init__("Managed Telegraf or fresh telemetry from all nine devices could not be verified.")


class ManagedTelegrafMonitoring:
    available = True
    verification_available = True

    def __init__(self, config_path=DEFAULT_CONFIG, timeout=90, poll_interval=5, max_age=30):
        self.config_path = Path(config_path)
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.max_age = max_age

    @staticmethod
    def _service(action):
        # This is the installed user unit, not the unrelated system telegraf.service.
        arguments = ["systemctl", "--user", "--no-ask-password", action]
        if action == "is-active":
            arguments.append("--quiet")
        arguments.append(SERVICE)
        subprocess.run(arguments, check=True, capture_output=True, timeout=45, shell=False)

    def _settings(self):
        with self.config_path.open("rb") as source:
            config = tomllib.load(source)
        subscriptions = [sub for plugin in config["inputs"]["gnmi"]
                         for sub in plugin.get("subscription", [])
                         if sub.get("path", "").rstrip("/") == "/interfaces/interface/state/counters"]
        outputs = config["outputs"]["influxdb_v2"]
        if len(subscriptions) != 1 or len(outputs) != 1:
            raise MonitoringError()
        measurement = subscriptions[0]["name"]
        output = outputs[0]
        url = os.environ.get("INFLUX_URL", "").strip() or output["urls"][0]
        org = os.environ.get("INFLUX_ORG", "").strip() or output["organization"]
        bucket = os.environ.get("INFLUX_BUCKET", "").strip() or output["bucket"]
        parsed = urlsplit(url)
        if (not all(isinstance(value, str) and value for value in (measurement, org, bucket))
                or parsed.scheme not in ("http", "https") or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment):
            raise MonitoringError()
        if os.environ.get("CREDENTIALS_DIRECTORY") or os.environ.get("INFLUX_TOKEN"):
            token = influx_token(os.environ)
        else:
            # Same private source configured by LoadCredential in the managed unit.
            token = interpolation_value(read_influx_file(
                Path.home() / ".config/netpilot/secrets/influx-token"))
        return measurement, url, org, bucket, token

    def _fresh(self, client, measurement, org, bucket, targets, since):
        source_filter = " or ".join(f'r[{json.dumps(SOURCE_TAG)}] == {json.dumps(address)}'
                                    for address in targets.values())
        start = datetime.fromtimestamp(since, timezone.utc).isoformat()
        query = (
            f'from(bucket: {json.dumps(bucket)}) |> range(start: time(v: {json.dumps(start)})) '
            f'|> filter(fn: (r) => r._measurement == {json.dumps(measurement)} '
            f'and r._field == {json.dumps(COUNTER_FIELDS["rx_bps"])} and ({source_filter})) '
            f'|> group(columns: [{json.dumps(SOURCE_TAG)}]) |> last()'
        )
        found = set()
        tables = client.query_api().query(query=query, org=org)
        now = time.time()
        for table in tables:
            for record in table.records:
                row = record.values
                stamp = row.get("_time")
                if (row.get("_measurement") != measurement
                        or row.get("_field") != COUNTER_FIELDS["rx_bps"]
                        or not isinstance(stamp, datetime) or stamp.utcoffset() is None):
                    raise MonitoringError()
                if max(since, now - self.max_age) <= stamp.timestamp() <= now + 2:
                    found.add(row.get(SOURCE_TAG))
        return found == set(targets.values())

    def _verify(self, targets, since, wait):
        client = None
        try:
            if set(targets) != set(FLEET) or len(set(targets.values())) != len(FLEET):
                raise MonitoringError()
            measurement, url, org, bucket, token = self._settings()
            client = InfluxDBClient(url=url, token=token, org=org, timeout=10000)
            deadline = time.monotonic() + wait
            while True:
                try:
                    self._service("is-active")
                    if self._fresh(client, measurement, org, bucket, targets, since):
                        return True
                except Exception:
                    pass  # Restart/reconnect may take a few sample intervals.
                if time.monotonic() >= deadline:
                    raise MonitoringError()
                time.sleep(self.poll_interval)
        except Exception:
            raise MonitoringError() from None
        finally:
            if client is not None:
                try:
                    client.close()
                except Exception:
                    pass

    def verify_current(self, rotation_id, targets):
        """Read-only baseline: active managed service and recent data for every device."""
        return self._verify(targets, time.time() - self.max_age, wait=0)

    def refresh_and_verify(self, rotation_id, targets):
        """Restart once, then require samples collected after restart completion."""
        try:
            self._service("restart")
            return self._verify(targets, time.time(), wait=self.timeout)
        except Exception:
            raise MonitoringError() from None

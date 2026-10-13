"""Read-only EOS health checks for the existing Flask GUI; no configuration writes."""

from datetime import datetime, timezone
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import threading
import tomllib
from urllib.parse import urlsplit

from influxdb_client import InfluxDBClient
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException
from netmiko.utilities import get_structured_data_textfsm

from Functions.maintenance_telemetry import SOURCE_TAG
from security import credential_provider
from security.setup_recovery_accounts import quiet_transport
from security.telegraf_launcher import CONFIG, influx_token, interpolation_value, read_influx_file


_LOCK = threading.Lock()
CPU_PATH = "/components/component/cpu/utilization/state/instant"
COMMANDS = {"OSPFv2": "show ip ospf neighbor", "BGP": "show ip bgp summary"}


def _address(device):
    return str(ipaddress.IPv4Interface(device["management_ip"]).ip)


def _output(text, password):
    # The fixed show/ping commands do not request secrets. Redact credentials
    # defensively before any output can reach a template; never return exceptions.
    text = str(text).replace(password, "[redacted]") if password else str(text)
    lines = ["[sensitive output hidden]" if re.search(
        r"\b(?:password|secret|token|community|private.key)\b|\$6\$", line, re.I
    ) else line for line in text.splitlines()]
    limited = "\n".join(lines[:120])[:12000]
    if len(lines) > 120 or len("\n".join(lines[:120])) > 12000:
        limited += "\n[Output limited to 120 lines / 12,000 characters]"
    return limited


def _read(connection, command, password):
    output = connection.send_command(command, read_timeout=12)
    if not isinstance(output, str) or re.search(r"(?m)^\s*%", output):
        raise ValueError("Read-only command unavailable.")
    return _output(output, password)


def _neighbors(protocol, output):
    command = COMMANDS[protocol]
    try:
        records = get_structured_data_textfsm(output, platform="arista_eos", command=command)
    except Exception:
        records = None
    rows = []
    if isinstance(records, list):
        for record in records:
            address = record.get("ip_address" if protocol == "OSPFv2" else "bgp_neigh")
            state = record.get("state", "")
            if protocol == "BGP" and (state.isdigit() or not state and record.get("state_pfxrcd", "").isdigit()):
                state = "Established"
            try:
                rows.append({"ip": str(ipaddress.IPv4Address(address)), "state": state or "Unknown"})
            except (ValueError, TypeError):
                continue
    return {"protocol": protocol, "rows": rows, "output": output,
            "status": "OK" if rows else "Review Output" if output.strip() else "No Neighbors",
            "message": "Observed adjacency states; see details below." if rows else
                       "No neighbor rows recognized; review the command output." if output.strip() else
                       "The protocol is configured but reports no neighbors."}


def cpu_sample(address, config_path=CONFIG):
    """Read the existing gNMI CPU subscription; never start a collector/service."""
    unavailable = {"status": "N/A", "percent": None, "timestamp": None,
                   "message": "No fresh CPU telemetry is available (last 2 minutes)."}
    client = None
    try:
        address = str(ipaddress.IPv4Address(address))
        with Path(config_path).open("rb") as handle:
            config = tomllib.load(handle)
        subscriptions = [sub for plugin in config["inputs"]["gnmi"]
                         for sub in plugin.get("subscription", [])
                         if sub.get("path", "").rstrip("/") == CPU_PATH]
        outputs = config["outputs"]["influxdb_v2"]
        if len(subscriptions) != 1 or len(outputs) != 1:
            return unavailable
        measurement = subscriptions[0]["name"]
        field = subscriptions[0]["path"].rstrip("/").rsplit("/", 1)[-1]
        output = outputs[0]
        url = os.environ.get("INFLUX_URL", "").strip() or output["urls"][0]
        org = os.environ.get("INFLUX_ORG", "").strip() or output["organization"]
        bucket = os.environ.get("INFLUX_BUCKET", "").strip() or output["bucket"]
        parsed = urlsplit(url)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment):
            return unavailable
        # Same protected token sources used by the existing managed collector.
        if os.environ.get("CREDENTIALS_DIRECTORY") or os.environ.get("INFLUX_TOKEN"):
            token = influx_token(os.environ)
        else:
            token = interpolation_value(read_influx_file(
                Path.home() / ".config/netpilot/secrets/influx-token"))
        client = InfluxDBClient(url=url, org=org, token=token, timeout=5000)
        query = (
            f'from(bucket: {json.dumps(bucket)}) |> range(start: -2m) '
            f'|> filter(fn: (r) => r._measurement == {json.dumps(measurement)} '
            f'and r._field == {json.dumps(field)} '
            f'and r[{json.dumps(SOURCE_TAG)}] == {json.dumps(address)}) |> last()'
        )
        samples = []
        now = datetime.now(timezone.utc)
        for table in client.query_api().query(query=query, org=org):
            for record in table.records:
                row = record.values
                value, stamp = row.get("_value"), row.get("_time")
                if (row.get("_measurement") != measurement or row.get("_field") != field
                        or row.get(SOURCE_TAG) != address or type(value) not in (int, float)
                        or not math.isfinite(value) or not 0 <= value <= 100
                        or not isinstance(stamp, datetime) or stamp.utcoffset() is None
                        or not -2 <= (now - stamp).total_seconds() <= 120):
                    return unavailable
                samples.append((float(value), stamp))
        if not samples:
            return unavailable
        # Multiple component series are explicitly labelled, not presented as
        # a single observed chassis metric. Timestamp is the oldest used sample.
        return {"status": "Available", "percent": round(sum(v for v, _ in samples) / len(samples), 2),
                "timestamp": min(t for _, t in samples).astimezone(timezone.utc).isoformat(),
                "message": "Latest reported CPU utilization." if len(samples) == 1 else
                           f"Mean of {len(samples)} reported CPU series; oldest sample time shown."}
    except Exception:
        return dict(unavailable, message="CPU telemetry could not be read. Check InfluxDB access and the existing CPU subscription.")
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def run(source, destination):
    """Accept inventory records selected by Flask, never user-supplied commands/IPs."""
    address, destination_ip = _address(source), _address(destination)
    if str(source.get("vendor", "")).lower() != "arista":
        raise ValueError("Health checks require an Arista inventory device.")
    unavailable = {"status": "Unavailable", "output": "", "message": "Device checks could not run."}
    report = {"device": source["hostname"], "management_ip": address,
              "checked_at": datetime.now(timezone.utc).isoformat(), "error": None,
              "neighbors": [dict(unavailable, protocol=p, rows=[]) for p in COMMANDS],
              "routes": dict(unavailable),
              "cpu": {"status": "N/A", "percent": None, "timestamp": None, "message": "Not queried."},
              "connectivity": dict(unavailable, source=source["hostname"], destination=destination["hostname"],
                                   destination_ip=destination_ip, packet_loss=None)}
    if not _LOCK.acquire(blocking=False):
        report["error"] = "A health check is already running. Please try again shortly."
        return report
    try:
        # Reuse the project's transport log protection, with one check at a time.
        with quiet_transport():
            report["cpu"] = cpu_sample(address)
            connection = None
            stage = "credentials"
            try:
                username, password = credential_provider.get_credentials()
                stage = "connection"
                connection = ConnectHandler(
                    device_type="arista_eos", host=address, username=username,
                    password=password, secret=password, conn_timeout=8, auth_timeout=8,
                    banner_timeout=8, fast_cli=False, use_keys=False, allow_agent=False,
                    # Existing isolated Containerlab host-key policy; SSH stays encrypted.
                    ssh_strict=False, system_host_keys=False, session_log=None,
                )
                stage = "privilege"
                if not connection.check_enable_mode():
                    connection.enable()
                if not connection.check_enable_mode():
                    raise ValueError("Privileged read access unavailable.")
                # Read only top-level routing headers, not account/AAA configuration.
                headers = None
                try:
                    headers = _read(connection, "show running-config | include ^router", password)
                except Exception:
                    pass
                for index, protocol in enumerate(COMMANDS):
                    key = "ospf" if protocol == "OSPFv2" else "bgp"
                    if headers is not None and not re.search(r"(?m)^router " + key + r"\s+\d+\b", headers):
                        report["neighbors"][index] = dict(unavailable, protocol=protocol, rows=[],
                            status="Not Configured", message="No routing process found in the live configuration.")
                        continue
                    try:
                        output = _read(connection, COMMANDS[protocol], password)
                        report["neighbors"][index] = _neighbors(protocol, output)
                    except Exception:
                        report["neighbors"][index]["message"] = "Neighbor command failed or timed out."
                try:
                    output = _read(connection, "show ip route", password)
                    report["routes"] = {"status": "OK", "output": output,
                                        "message": "IPv4 routes, route codes and next hops from EOS (default VRF)."}
                except Exception:
                    report["routes"]["message"] = "Route table command failed or timed out."
                try:
                    # Same bounded EOS ping syntax as Functions/check_network_status.py.
                    command = f"ping {destination_ip} source {address} repeat 3 timeout 1"
                    output = _read(connection, command, password)
                    match = re.search(r"([\d.]+)%\s+packet loss", output)
                    loss = float(match.group(1)) if match else None
                    if loss is not None and not 0 <= loss <= 100:
                        loss = None
                    report["connectivity"].update(output=output, packet_loss=loss,
                        status="Unavailable" if loss is None else "PASS" if loss == 0 else "FAIL",
                        message="Ping output did not report packet loss." if loss is None else
                                "All three replies received." if loss == 0 else "One or more ping replies were lost.")
                except Exception:
                    report["connectivity"]["message"] = "Management ping command failed or timed out."
            except NetmikoAuthenticationException:
                report["error"] = "SSH authentication failed. Check current 1Password device credentials."
            except NetmikoTimeoutException:
                report["error"] = "Device unreachable or SSH timed out. Check management reachability."
            except Exception:
                report["error"] = {"credentials": "Device credentials are unavailable from 1Password.",
                                   "connection": "Unable to connect to the device over SSH.",
                                   "privilege": "The device did not permit privileged read access."}.get(
                                       stage, "The health check could not be completed.")
            finally:
                if connection is not None:
                    try:
                        connection.disconnect()
                    except Exception:
                        pass
    finally:
        _LOCK.release()
    return report

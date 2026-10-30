#!/usr/bin/python3 -I
"""Restricted, standalone local helper; install a root-owned copy before use.

No project modules are imported and no caller-supplied paths or commands are
accepted. An administrator must install the approved Lab 8 safe topology as
/etc/netpilot/ztp-baseline.json. All reconciliation artifacts stay root-owned.
Containerlab 0.79 JSON ApplyResult is checked before *every* apply. In that
version node-filter is explicitly unsupported for an already deployed lab.
"""

import copy
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


BASELINE = Path("/etc/netpilot/ztp-baseline.json")
BASELINE_STATE = Path("/etc/netpilot/ztp-baseline-state.json")
STATE = Path("/var/lib/netpilot-ztp")
PROJECT = Path("/home/student/Documents/NetPilot")
SERVER = "clab-netpilot-ztp-infra-ztp-server"
BRIDGE = "br-netpilot-ztp"
IMAGE = "ceos:4.36.2F"
SERVER_IMAGE = "netpilot-lab8-ztp:gui"
NETWORK = ipaddress.IPv4Network("172.20.20.0/24")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root",
       "LANG": "C.UTF-8", "CLAB_VERSION_CHECK": "disable"}
FIELDS = {"hostname", "management_ip", "bootstrap_mac", "host_interface", "job_id"}
NAME = re.compile(r"[A-Za-z](?:[A-Za-z0-9-]{0,30}[A-Za-z0-9])?\Z")


class ProvisionError(RuntimeError):
    """Only fixed, non-sensitive messages cross the helper boundary."""


def identities(hostname):
    digest = hashlib.sha256(hostname.casefold().encode("ascii")).hexdigest()
    return "npztp-" + digest[:8], "02:08:" + ":".join(
        digest[index:index + 2] for index in range(0, 8, 2))


def validate_request(request):
    if not isinstance(request, dict) or set(request) != FIELDS:
        raise ProvisionError("Invalid provisioning request.")
    name = request["hostname"]
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise ProvisionError("Invalid device hostname.")
    try:
        raw = request["management_ip"]
        address = ipaddress.IPv4Address(raw) if isinstance(raw, str) else None
    except ValueError:
        address = None
    if address is None or address not in NETWORK or int(address) - int(NETWORK.network_address) not in range(2, 255):
        raise ProvisionError("Invalid management address.")
    interface, mac = identities(name)
    if request["host_interface"] != interface or request["bootstrap_mac"] != mac:
        raise ProvisionError("Invalid bootstrap identity.")
    if not isinstance(request["job_id"], str) or not re.fullmatch(r"[0-9a-f]{32}", request["job_id"]):
        raise ProvisionError("Invalid provisioning identifier.")
    return dict(request)


def _run(arguments, *, timeout=30):
    try:
        result = subprocess.run(arguments, capture_output=True, text=True,
                                timeout=timeout, check=False, env=ENV, cwd="/")
    except (OSError, subprocess.SubprocessError):
        raise ProvisionError("Local provisioning command failed.") from None
    if result.returncode:
        raise ProvisionError("Local provisioning command failed; check administrator diagnostics.")
    return result.stdout


def _json(arguments):
    try:
        return json.loads(_run(arguments))
    except (ValueError, TypeError):
        raise ProvisionError("Invalid local runtime response.") from None


def _secure_directory(path):
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise ProvisionError("Provisioning state directory is not root-owned and private.")


def _read_root_json(path):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ProvisionError("Trusted provisioning file permissions are unsafe.")
            return json.load(stream)
    except (OSError, ValueError, TypeError):
        raise ProvisionError("Trusted provisioning setup is missing or invalid.") from None


def _write_root_text(path, value, *, mode=0o600):
    temporary = path.with_name(path.name + ".new")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(value)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _write_root_json(path, value):
    _write_root_text(path, json.dumps(value) + "\n")


def _records():
    path = STATE / "jobs.json"
    result = _read_root_json(path) if path.exists() else {}
    if not isinstance(result, dict):
        raise ProvisionError("Provisioning ownership state is invalid.")
    return result


def _docker_state():
    network = _json(["/usr/bin/docker", "network", "inspect", "clab"])
    if not isinstance(network, list) or len(network) != 1:
        raise ProvisionError("The existing clab management network is unavailable.")
    network = network[0]
    ipam = [entry for entry in network.get("IPAM", {}).get("Config", [])
            if entry.get("Subnet") == str(NETWORK)]
    if len(ipam) != 1 or ipam[0].get("Gateway") != "172.20.20.1":
        raise ProvisionError("The clab management IPAM does not match the approved network.")
    ids = _run(["/usr/bin/docker", "ps", "-aq"]).split()
    if any(not re.fullmatch(r"[0-9a-f]{12,64}", identifier) for identifier in ids):
        raise ProvisionError("Invalid Docker node identifiers.")
    containers = _json(["/usr/bin/docker", "inspect", *ids]) if ids else []
    if not isinstance(containers, list):
        raise ProvisionError("Invalid Docker inventory response.")
    return network, containers


def snapshot():
    network, containers = _docker_state()
    names, addresses, macs = set(), {"172.20.20.1"}, set()
    for values in network.get("IPAM", {}).get("Config", []):
        addresses.update(values.get("AuxiliaryAddresses", {}).values())
    server_ready = False
    for container in containers:
        name = container.get("Name", "").lstrip("/")
        config = container.get("Config", {})
        labels = config.get("Labels") or {}
        names.add(name)
        names.update(value for value in (config.get("Hostname"), labels.get("clab-node-name")) if value)
        for values in container.get("NetworkSettings", {}).get("Networks", {}).values():
            if values.get("IPAddress"):
                addresses.add(values["IPAddress"])
            if values.get("MacAddress"):
                macs.add(values["MacAddress"].lower())
        if name == SERVER:
            mounts = {mount.get("Destination"): mount for mount in container.get("Mounts", [])}
            required = {"/srv/ztp/day0": PROJECT / "runtime/lab8-ztp/http",
                        "/srv/ztp-dhcp": STATE / "dhcp"}
            server_ready = (container.get("State", {}).get("Running") is True
                            and config.get("Image") == SERVER_IMAGE
                            and all(mounts.get(target, {}).get("Source") == str(source)
                                    and mounts[target].get("RW") is False
                                    for target, source in required.items()))
    for values in network.get("Containers", {}).values():
        if values.get("IPv4Address"):
            addresses.add(values["IPv4Address"].split("/")[0])
    if server_ready:
        try:
            bridge = _json(["/usr/sbin/ip", "-j", "-d", "link", "show", "dev", BRIDGE])
            endpoint = _json(["/usr/sbin/ip", "-j", "-d", "link", "show", "dev", "npztp-srv"])
            server_ready = (len(bridge) == 1 and len(endpoint) == 1
                            and bridge[0].get("linkinfo", {}).get("info_kind") == "bridge"
                            and endpoint[0].get("master") == BRIDGE)
        except ProvisionError:
            server_ready = False
    records = _records()
    for value in records.values():
        device = validate_request(value["request"])
        names.add(device["hostname"])
        addresses.add(device["management_ip"])
        macs.add(device["bootstrap_mac"])
    owned = {key: {"job_id": value["request"]["job_id"],
                   "management_ip": value["request"]["management_ip"],
                   "node_id": value.get("node_id")}
             for key, value in records.items()}
    return {"network": str(NETWORK), "gateway": "172.20.20.1", "names": sorted(names),
            "addresses": sorted(addresses), "macs": sorted(macs),
            "server_ready": server_ready, "owned": owned}


def check_plan(plan, request, *, retry=False):
    """Validate actual v0.79 ApplyResult, including absence of unknown actions."""
    required = {"dry-run", "deployed-lab", "added-nodes", "deleted-nodes",
                "recreated-nodes", "started-nodes", "added-links", "deleted-endpoints",
                "restarted-nodes"}
    if (not isinstance(plan, dict) or not required <= set(plan)
            or set(plan) - required - {"lab-name", "node-change-reasons"}
            or plan["dry-run"] is not True or plan["deployed-lab"] is not False
            or plan.get("lab-name", "pilot-network") != "pilot-network"):
        raise ProvisionError("Unrecognized or unsafe Containerlab reconciliation plan.")
    for key in required - {"dry-run", "deployed-lab"}:
        if not isinstance(plan[key], list) or any(not isinstance(item, str) for item in plan[key]):
            raise ProvisionError("Unrecognized Containerlab action list.")
    if any(plan[key] for key in ("deleted-nodes", "recreated-nodes", "started-nodes",
                                 "deleted-endpoints", "restarted-nodes")) or plan.get("node-change-reasons"):
        raise ProvisionError("Refusing a plan that changes an existing node or endpoint.")
    expected_link = " -- ".join(sorted((request["hostname"] + ":eth1", "host:" + request["host_interface"])))
    if retry:
        valid_nodes = plan["added-nodes"] == []
        valid_links = plan["added-links"] in ([], [expected_link])
    else:
        valid_nodes = plan["added-nodes"] == [request["hostname"]]
        valid_links = plan["added-links"] == [expected_link]
    if not valid_nodes or not valid_links:
        raise ProvisionError("Only the requested new node and its bootstrap link may be deployed.")
    return plan


def candidate(baseline, request):
    value = copy.deepcopy(baseline)
    if value.get("name") != "pilot-network" or value.get("mgmt", {}).get("network") != "clab":
        raise ProvisionError("The approved topology does not describe pilot-network.")
    if value["mgmt"].get("ipv4-subnet") != str(NETWORK):
        raise ProvisionError("The approved topology has a different management subnet.")
    topology = value.get("topology", {})
    nodes, links = topology.get("nodes"), topology.get("links")
    if not isinstance(nodes, dict) or not nodes or not isinstance(links, list):
        raise ProvisionError("The approved topology is incomplete.")
    name = request["hostname"]
    if name.casefold() in {existing.casefold() for existing in nodes}:
        raise ProvisionError("Hostname already exists in the approved topology.")
    for node in nodes.values():
        if node.get("mgmt-ipv4") == request["management_ip"]:
            raise ProvisionError("Management address already exists in the approved topology.")
    if request["host_interface"] in json.dumps(links) or request["bootstrap_mac"] in json.dumps(links).lower():
        raise ProvisionError("Bootstrap identity is already allocated.")
    nodes[name] = {"kind": "ceos", "image": IMAGE, "image-pull-policy": "Never",
                   "mgmt-ipv4": request["management_ip"], "suppress-startup-config": True,
                   "labels": {"netpilot-ztp-job-id": request["job_id"]}}
    links.append({"type": "host", "endpoint": {"node": name, "interface": "eth1",
                  "mac": request["bootstrap_mac"]}, "host-interface": request["host_interface"]})
    return value


def _node(container_list, name):
    matches = [item for item in container_list
               if item.get("Name", "").lstrip("/") == "clab-pilot-network-" + name]
    if len(matches) > 1:
        raise ProvisionError("Ambiguous Docker node identity.")
    return matches[0] if matches else None


def _owned(request, records, *, require_node=False):
    entry = records.get(request["hostname"].casefold())
    if not entry or entry.get("request") != request:
        raise ProvisionError("This node is not owned by the requested onboarding attempt.")
    _, containers = _docker_state()
    node = _node(containers, request["hostname"])
    if node:
        _verify_node(node, request, entry.get("node_id"))
    if require_node and not node:
        raise ProvisionError("The onboarding node is not present.")
    return entry, node


def _verify_node(node, request, identifier=None):
    if identifier and identifier != node.get("Id"):
        raise ProvisionError("Onboarding node identity changed; refusing to continue.")
    config = node.get("Config", {})
    labels = config.get("Labels") or {}
    if (not re.fullmatch(r"[0-9a-f]{64}", node.get("Id", ""))
            or labels.get("netpilot-ztp-job-id") != request["job_id"]
            or labels.get("containerlab") != "pilot-network"
            or labels.get("clab-node-name") != request["hostname"]
            or config.get("Image") != IMAGE
            or node.get("NetworkSettings", {}).get("Networks", {}).get("clab", {}).get("IPAddress")
            != request["management_ip"]):
        raise ProvisionError("Onboarding node identity or management assignment is unverified.")


def _host_endpoint(name):
    interfaces = _json(["/usr/sbin/ip", "-j", "-d", "link", "show"])
    if not isinstance(interfaces, list):
        raise ProvisionError("Invalid host interface metadata.")
    matches = [item for item in interfaces if item.get("ifname") == name]
    if len(matches) > 1:
        raise ProvisionError("Ambiguous host interface identity.")
    return matches[0] if matches else None


def _verify_endpoint(endpoint, node, request):
    pid = node.get("State", {}).get("Pid")
    if (type(pid) is not int or pid <= 0 or endpoint.get("linkinfo", {}).get("info_kind") != "veth"
            or endpoint.get("master") not in (None, BRIDGE)):
        raise ProvisionError("Bootstrap endpoint does not belong to the running onboarding node.")
    # Enter only the verified new node's network namespace; execute the host's
    # fixed ip binary, never a command or filesystem from the device container.
    peers = _json(["/usr/bin/nsenter", "--target", str(pid), "--net", "/usr/sbin/ip",
                   "-j", "-d", "link", "show", "dev", "eth1"])
    if (not isinstance(peers, list) or len(peers) != 1
            or type(endpoint.get("ifindex")) is not int
            or type(endpoint.get("link_index")) is not int
            or peers[0].get("ifindex") != endpoint["link_index"]
            or peers[0].get("link_index") != endpoint["ifindex"]
            or peers[0].get("address", "").lower() != request["bootstrap_mac"]):
        raise ProvisionError("Bootstrap host interface peer identity is unverified.")


def _runtime_claim(request, records):
    """Check current collisions again, including an earlier preview reservation."""
    network, containers = _docker_state()
    node = _node(containers, request["hostname"])
    entry = records.get(request["hostname"].casefold())
    if entry and entry.get("request") != request:
        raise ProvisionError("Another onboarding attempt owns this hostname.")
    for key, reservation in records.items():
        if key == request["hostname"].casefold():
            continue
        reserved = validate_request(reservation["request"])
        if (reserved["management_ip"] == request["management_ip"]
                or reserved["bootstrap_mac"] == request["bootstrap_mac"]
                or reserved["host_interface"] == request["host_interface"]):
            raise ProvisionError("Another onboarding attempt reserved this address or bootstrap identity.")
    if node:
        if not entry:
            raise ProvisionError("Hostname already exists in Docker.")
        _verify_node(node, request, entry.get("node_id"))
    owned_id = node.get("Id") if node else None
    for item in containers:
        if item.get("Id") == owned_id and owned_id:
            continue
        config = item.get("Config", {})
        labels = config.get("Labels") or {}
        names = (item.get("Name", "").lstrip("/"), config.get("Hostname", ""),
                 labels.get("clab-node-name", ""))
        if request["hostname"].casefold() in {name.casefold() for name in names}:
            raise ProvisionError("Hostname already exists in Docker.")
        for values in item.get("NetworkSettings", {}).get("Networks", {}).values():
            if values.get("IPAddress") == request["management_ip"]:
                raise ProvisionError("Management address is already allocated in Docker.")
            if values.get("MacAddress", "").lower() == request["bootstrap_mac"]:
                raise ProvisionError("Bootstrap MAC is already allocated in Docker.")
    for identifier, values in network.get("Containers", {}).items():
        if identifier != owned_id and values.get("IPv4Address", "").split("/")[0] == request["management_ip"]:
            raise ProvisionError("Management address is already allocated in Docker IPAM.")
    for values in network.get("IPAM", {}).get("Config", []):
        if request["management_ip"] in values.get("AuxiliaryAddresses", {}).values():
            raise ProvisionError("Management address is reserved in Docker IPAM.")
    endpoint = _host_endpoint(request["host_interface"])
    if endpoint:
        if not node:
            raise ProvisionError("The requested host interface already exists; it will not be reused.")
        _verify_endpoint(endpoint, node, request)
    return node


def _existing_fingerprint(request):
    _, containers = _docker_state()
    # Identity and start time detect a concurrent replacement/restart. No
    # credentials or environment values are included in this private comparison.
    return sorted((item.get("Id", ""), item.get("Name", ""),
                   item.get("State", {}).get("StartedAt", ""),
                   item.get("State", {}).get("Status", ""))
                  for item in containers if item.get("Name", "").lstrip("/")
                  != "clab-pilot-network-" + request["hostname"])


def reconcile(request, *, apply=False):
    request = validate_request(request)
    records = _records()
    key = request["hostname"].casefold()
    baseline_path = STATE / "approved.json"
    baseline = _read_root_json(baseline_path if baseline_path.exists() else BASELINE)
    node = _runtime_claim(request, records)
    retry = node is not None
    # Keep subsequent approved additions when retrying an older owned node. A
    # labelled node may exist after an interrupted apply before approved.json was
    # saved; rebuild its candidate without claiming unrelated runtime containers.
    already_approved = key in {name.casefold() for name in baseline.get("topology", {}).get("nodes", {})}
    prepared = baseline if retry and already_approved else candidate(baseline, request)
    existing = _existing_fingerprint(request)
    labdir = STATE / "clab-pilot-network"
    _secure_directory(labdir)
    statefile = labdir / ".state.clab.yaml"
    if not statefile.exists():
        observed_state = _read_root_json(BASELINE_STATE)
        if observed_state.get("topology", {}).get("nodes") != baseline["topology"]["nodes"]:
            raise ProvisionError("Approved topology differs from the installed running-lab state.")
        _write_root_json(statefile, {"topology": observed_state["topology"]})
    path = STATE / "candidate.clab.yml"
    _write_root_json(path, prepared)
    command = ["/usr/bin/containerlab", "deploy", "--topo", str(path), "--format", "json",
               "--skip-post-deploy", "--skip-labdir-acl", "--max-workers", "1"]
    try:
        plan = json.loads(_run(command + ["--dry-run"], timeout=120))
    except (ValueError, TypeError):
        raise ProvisionError("Containerlab did not return a valid JSON dry-run plan.") from None
    check_plan(plan, request, retry=retry)
    if key not in records:
        # Reservation proof allows the fixed DHCP reload before native ZTP starts.
        records[key] = {"request": request, "node_id": None}
        _write_root_json(STATE / "jobs.json", records)
    if node and not records[key].get("node_id"):
        records[key]["node_id"] = node["Id"]
        _write_root_json(STATE / "jobs.json", records)
    if not apply:
        return {"plan": plan, "retry": retry}
    failure = None
    try:
        _runtime_claim(request, records)
        if _existing_fingerprint(request) != existing:
            raise ProvisionError("Docker state changed after the preview; retry after other operations finish.")
        if plan["added-nodes"] or plan["added-links"]:
            _run(command, timeout=240)
    except ProvisionError as error:
        failure = error
    # Record the created container even if deploy failed after container creation.
    _, containers = _docker_state()
    node = _node(containers, request["hostname"])
    if node:
        _verify_node(node, request, records[key].get("node_id"))
        records[key]["node_id"] = node.get("Id")
        _write_root_json(STATE / "jobs.json", records)
        _write_root_json(baseline_path, prepared)
    if failure:
        raise failure
    if not node:
        raise ProvisionError("Deployment did not create the requested node.")
    if _existing_fingerprint(request) != existing:
        raise ProvisionError("Existing runtime nodes changed; further provisioning is blocked.")
    return {"node_id": node["Id"], "retry": retry}


def attach(request):
    request = validate_request(request)
    _, node = _owned(request, _records(), require_node=True)
    bridge = _json(["/usr/sbin/ip", "-j", "-d", "link", "show", "dev", BRIDGE])
    endpoint = _host_endpoint(request["host_interface"])
    if (len(bridge) != 1 or bridge[0].get("linkinfo", {}).get("info_kind") != "bridge"
            or not endpoint):
        raise ProvisionError("Bootstrap bridge or endpoint is missing or unsafe.")
    _verify_endpoint(endpoint, node, request)
    _run(["/usr/sbin/ip", "link", "set", "dev", request["host_interface"], "master", BRIDGE])
    _run(["/usr/sbin/ip", "link", "set", "dev", request["host_interface"], "up"])
    return {"attached": True}


def reload_dhcp(request):
    request = validate_request(request)
    records = _records()
    if records.get(request["hostname"].casefold(), {}).get("request") != request:
        raise ProvisionError("A safe preview must reserve this onboarding attempt first.")
    if not snapshot()["server_ready"]:
        raise ProvisionError("The ZTP server has not been prepared for GUI onboarding.")
    directory = STATE / "dhcp"
    directory.mkdir(mode=0o755, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ProvisionError("DHCP state directory permissions are unsafe.")
    hosts, options = [], []
    for entry in records.values():
        device = validate_request(entry["request"])
        tag = "npztp" + device["host_interface"][6:]
        hosts.append(device["bootstrap_mac"] + ",set:" + tag + "\n")
        options.append("tag:" + tag + ",67,http://10.250.0.1/day0/" + device["hostname"] + ".cfg\n")
    # No credentials here; dnsmasq drops privileges and needs read access.
    _write_root_text(directory / "hosts", "".join(hosts), mode=0o644)
    _write_root_text(directory / "options", "".join(options), mode=0o644)
    # start.sh execs dnsmasq as PID 1. HUP rereads the dedicated hosts/options
    # files without restarting the container or changing the main config.
    _run(["/usr/bin/docker", "kill", "--signal", "HUP", SERVER])
    return {"reloaded": True}


def main():
    try:
        info = Path(__file__).lstat()
        if os.geteuid() != 0 or info.st_uid != 0 or info.st_mode & 0o022:
            raise ProvisionError("Install and invoke the root-owned restricted provisioning helper.")
        if len(sys.argv) != 1:
            raise ProvisionError("The provisioning helper accepts no command-line arguments.")
        if _run(["/usr/bin/containerlab", "version", "--short"]).strip() != "0.79.0":
            raise ProvisionError("This helper requires the reviewed Containerlab 0.79.0 plan format.")
        request = json.loads(sys.stdin.read(4097))
        if not isinstance(request, dict):
            raise ProvisionError("Invalid provisioning request.")
        action = request.pop("action", None)
        if action not in {"snapshot", "preview", "deploy", "attach", "reload-dhcp"}:
            raise ProvisionError("Unsupported provisioning operation.")
        if action == "snapshot" and request:
            raise ProvisionError("Invalid snapshot request.")
        _secure_directory(STATE)
        descriptor = os.open(STATE / ".lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            if action == "snapshot":
                result = snapshot()
            elif action in {"preview", "deploy"}:
                result = reconcile(request, apply=action == "deploy")
            elif action == "attach":
                result = attach(request)
            else:
                result = reload_dhcp(request)
        print(json.dumps({"ok": True, **result}))
        return 0
    except ProvisionError as error:
        print(json.dumps({"ok": False, "error": str(error)}))
    except Exception:
        print(json.dumps({"ok": False, "error": "Local provisioning helper failed safely."}))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

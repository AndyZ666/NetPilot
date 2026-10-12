#!/usr/bin/env python3
"""RCN-5840 drain-first maintenance. eAPI only; never opens a device CLI session.

Use --dry-run on any action before class. No module-level network/file writes.
The two instructor checkpoints intentionally leave the target out of service.
"""

import argparse
import base64
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import signal
import ssl
import threading
import time
import urllib.request
import uuid

import yaml

import config_changes as storage
from Functions.maintenance_telemetry import Telemetry, TelemetryError


ROOT = Path(__file__).resolve().parent
INVENTORY = ROOT / "inventory" / "devices.yml"
RUNTIME = ROOT / "runtime" / "maintenance" / "RCN-5840"
TICKET = "RCN-5840"
ROUTERS = ("R1", "R2")
BEGIN = "# BEGIN NETPILOT MAINTENANCE STATE"
END = "# END NETPILOT MAINTENANCE STATE"
METRICS = {"RIP-TO-OSPF": 50000, "OSPF-TO-RIP": 10}
COST = 60000
PREFIXES = {
    "access": ("203.0.113.0/30", "2001:db8:203:113::/64"),
    "core": ("10.0.10.0/24", "10.0.20.0/24", "2001:db8:10::/64",
             "2001:db8:20::/64", "2001:db8:30::/64"),
}
TRANSITIONS = {
    "in_service": {"precheck"}, "precheck": {"draining", "restoring", "rollback", "error"},
    "draining": {"drained", "restoring", "rollback", "error"},
    "drained": {"out_of_service", "restoring", "rollback", "error"},
    "out_of_service": {"restoring", "rollback", "error"},
    "restoring": {"in_service", "rollback", "error"},
    "rollback": {"in_service", "restoring", "error"},
    "error": {"restoring", "rollback"},
}


class MaintenanceError(RuntimeError):
    """Only sanitized operational messages may be displayed."""


def require(condition, message):
    if not condition:
        raise MaintenanceError(message)


def stamp():
    return datetime.now(timezone.utc).isoformat()


def report(level, message):
    print(f"{stamp()} [{level}] {message}", flush=True)


def transition(old, new):
    require(new in TRANSITIONS.get(old, set()), f"Unsafe state transition: {old} -> {new}")
    return new


def discover(inventory, target):
    require(target in ROUTERS, "Target must be R1 or R2.")
    plans = {}
    for name in ROUTERS:
        device = storage.get_device(inventory, name)
        interfaces = device.get("interfaces", {})
        management = device.get("management", {}).get("interface")
        require(management == "Management0", f"{name}: unrecognized management interface.")
        ports = [port for port, facts in interfaces.items()
                 if re.fullmatch(r"Ethernet[0-9]+", port) and facts.get("peer")
                 and facts.get("forwarding_model") == "routed"]
        require(set(ports) == {"Ethernet1", "Ethernet2"},
                f"{name}: expected exactly two NSOT production links; review topology.")
        routing = device.get("routing", {})
        require(all(routing.get(kind, {}).get("enabled") is True
                    for kind in ("ospfv2", "ospfv3", "ripv2")), f"{name}: routing design differs from ticket.")
        require({entry['name'] for entry in routing['ospfv3']['interfaces']} == set(ports),
                f"{name}: OSPFv3 production interfaces differ from ticket.")
        core = [entry['name'] for entry in routing['ospfv2']['interfaces']]
        access = routing['ripv2']['interfaces']
        require(len(core) == len(access) == 1 and set(core + access) == set(ports),
                f"{name}: cannot uniquely identify core/access interfaces.")
        peers = {}
        for role, port in (("core", core[0]), ("access", access[0])):
            peer = interfaces[port]['peer']
            peer_device = inventory['devices'].get(peer['device'], {})
            reverse = peer_device.get('interfaces', {}).get(peer['interface'], {}).get('peer')
            require(reverse == {'device': name, 'interface': port}, f"{name}: NSOT peer link is not reciprocal.")
            peers[role] = dict(peer)
        plans[name] = {"device": device, "ports": sorted(ports), "peers": peers,
                       "process": str(routing['ospfv2']['process_id'])}
    return target, next(name for name in ROUTERS if name != target), plans


def maintenance_block(original, target, state, updated_at):
    """Change only our delimited block; compare all other parsed values too."""
    require(target in ROUTERS and state in {"in_service", "draining", "drained", "out_of_service", "restoring", "error"},
            "Invalid NSOT maintenance state.")
    source = original.decode('utf-8')
    before = yaml.load(source, Loader=storage._InventoryLoader)
    require(isinstance(before, dict) and isinstance(before.get('devices'), dict), "Invalid NSOT mapping.")
    starts = list(re.finditer(rf'(?m)^{re.escape(BEGIN)}\r?$', source))
    ends = list(re.finditer(rf'(?m)^{re.escape(END)}\r?$', source))
    require(len(starts) == len(ends) and len(starts) <= 1, "Malformed or duplicate maintenance block.")
    if starts:
        require(starts[0].start() < ends[0].start(), "Reversed maintenance markers.")
        start, end = starts[0].start(), ends[0].end()
        if source[end:end+1] == '\n':
            end += 1
        outside = source[:start] + source[end:]
        require('maintenance' not in (yaml.safe_load(outside) or {}), "Unmanaged maintenance data conflicts with block.")
    else:
        require('maintenance' not in before, "An unmanaged maintenance section already exists.")
        start = end = len(source)
    current = deepcopy(before.get('maintenance', {"ticket": TICKET, "routers": {}}))
    require(isinstance(current, dict) and current.get('ticket') == TICKET
            and isinstance(current.get('routers'), dict), "Maintenance ticket/schema conflict.")
    current['routers'][target] = {'state': state, 'updated_at': updated_at}
    prefix = '\n' if start and source[start-1] != '\n' else ''
    block = prefix + BEGIN + '\n' + yaml.safe_dump({'maintenance': current}, sort_keys=False) + END + '\n'
    updated = (source[:start] + block + source[end:]).encode()
    expected = deepcopy(before)
    expected['maintenance'] = current
    require(yaml.safe_load(updated) == expected, "Maintenance block failed YAML validation.")
    return updated


def update_nsot(path, target, state):
    with storage._directory_lock(Path(path).parent, threading.Lock()):
        original, _ = storage._read_inventory(path)
        updated = maintenance_block(original, target, state, stamp())
        filename = f"devices_{datetime.now():%Y%m%d_%H%M%S}_{uuid.uuid4().hex[:8]}_maintenance.yml"
        storage._exclusive_backup(Path(path).parent / 'backups', filename, original)

        def validate(temporary):
            require(yaml.safe_load(temporary.read_bytes()) == yaml.safe_load(updated), "Temporary NSOT validation failed.")
            require(Path(path).read_bytes() == original, "NSOT changed concurrently; replacement cancelled.")

        # Invalid candidates never replace the original, so no destructive restore is needed.
        storage._atomic_write(path, updated, mode=Path(path).stat().st_mode & 0o777, validate=validate)


class EAPI:
    """Small HTTP adapter for the already-enabled EOS command API. No SSH fallback."""

    def __init__(self, inventory, insecure=False, timeout=10):
        username, password = os.getenv('NETPILOT_USERNAME'), os.getenv('NETPILOT_PASSWORD')
        require(bool(username and password), "Export NETPILOT_USERNAME and NETPILOT_PASSWORD before live inspection.")
        self.authorization = 'Basic ' + base64.b64encode(f'{username}:{password}'.encode()).decode()
        self.inventory, self.timeout = inventory, timeout
        context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None  # Never forward device credentials to another endpoint.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                  urllib.request.HTTPSHandler(context=context), NoRedirect())

    def call(self, name, commands, encoding='json'):
        address = str(ipaddress.IPv4Address(self.inventory['devices'][name]['management']['ipv4']))
        payload = {'jsonrpc': '2.0', 'id': 1, 'method': 'runCmds',
                   'params': {'version': 1, 'cmds': commands, 'format': encoding}}
        request = urllib.request.Request(f'https://{address}/command-api', data=json.dumps(payload).encode(),
                                         headers={'Content-Type': 'application/json', 'Authorization': self.authorization})
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                result = json.load(response)
            require(not result.get('error') and isinstance(result.get('result'), list)
                    and len(result['result']) == len(commands), f"{name}: eAPI command failed or reply is incomplete.")
            return result['result']
        except MaintenanceError:
            raise
        except Exception:
            raise MaintenanceError(f"{name}: eAPI unavailable/authentication/TLS failure; device outcome must be verified.") from None

    def show(self, name, command, text=False):
        require(command.startswith('show ') and not any(c in command for c in '\r\n;|'), "Invalid read-only API command.")
        result = self.call(name, ['enable', command], 'text' if text else 'json')[-1]
        if text:
            require(isinstance(result, dict) and isinstance(result.get('output'), str), f"{name}: unexpected text reply.")
            return result['output']
        require(isinstance(result, dict), f"{name}: unexpected structured reply.")
        return result

    def configure(self, name, commands):
        require(name in ROUTERS, "Only R1/R2 can be changed.")
        allowed = r'(?:interface Ethernet[12]|route-map (?:RIP-TO-OSPF|OSPF-TO-RIP) permit [0-9]+|(?:no )?set metric(?: [0-9]+)?|(?:no )?(?:ospfv3|ipv6 ospf) cost(?: [0-9]+)?|(?:no )?shutdown|exit)'
        require(commands and all(re.fullmatch(allowed, line) for line in commands), "Configuration command outside maintenance allowlist.")
        context = None
        for line in commands:
            if line.startswith(('interface ', 'route-map ')):
                context = line
            elif line == 'exit':
                context = None
            elif 'set metric' in line:
                require(context is not None and context.startswith('route-map '), 'Metric outside route-map context.')
                if line.startswith('set metric '):
                    limit = 15 if 'OSPF-TO-RIP' in context else 16777214
                    require(0 <= int(line.split()[-1]) <= limit, 'Unsafe redistribution metric; RIP 16 is forbidden.')
            else:
                require(context in {'interface Ethernet1', 'interface Ethernet2'}, 'Interface change outside production context.')
                if ' cost ' in line:
                    require(1 <= int(line.split()[-1]) <= 65535, 'Invalid OSPFv3 cost.')
        self.call(name, ['enable', 'configure terminal', *commands, 'end'], 'text')


def config_sections(config):
    sections, current = {}, None
    for line in config.splitlines():
        if not line.strip() or line.startswith('!'):
            continue
        if not line[0].isspace():
            current = line.strip()
            require(current not in sections, "Duplicate configuration section; cannot capture exact rollback.")
            sections[current] = []
        elif current:
            sections[current].append(line.strip())
    return sections


def capture(config, target, plan):
    """Capture only non-secret changed settings plus a guard for unrelated configuration."""
    sections = config_sections(config)
    require(f'hostname {target}' in sections and 'end' in sections, f"{target}: incomplete/wrong running configuration.")
    original = {'metrics': {}, 'costs': {}, 'admin': {}}
    for name in METRICS:
        for header, lines in sections.items():
            if re.fullmatch(rf'route-map {name} permit [0-9]+', header):
                metric = [line for line in lines if line.startswith('set metric ')]
                require(len(metric) <= 1 and all(re.fullmatch(r'set metric [0-9]+', line) for line in metric),
                        f"{target}: unsupported original metric expression.")
                original['metrics'][header] = metric[0] if metric else None
        require(any(h.startswith(f'route-map {name} ') for h in original['metrics']), f"{target}: missing {name} permit entry.")
    require(any(re.fullmatch(r'redistribute rip route-map RIP-TO-OSPF', line)
                for line in sections.get(f"router ospf {plan['process']}", [])), f"{target}: RIP-to-OSPF binding differs.")
    rip = sections.get('router rip', [])
    require(any('redistribute ospf' in line and line.endswith('route-map OSPF-TO-RIP') for line in rip)
            and 'shutdown' not in rip, f"{target}: OSPF-to-RIP binding or process state differs.")
    for port in plan['ports']:
        lines = sections.get(f'interface {port}')
        require(lines is not None, f"{target}: missing {port} in live configuration.")
        costs = [line for line in lines if re.match(r'(?:ipv6 ospf|ospfv3) cost\b', line)]
        require(len(costs) <= 1 and all(re.fullmatch(r'(?:ipv6 ospf|ospfv3) cost [0-9]+', line) for line in costs),
                f"{target}: unsupported OSPFv3 cost configuration.")
        original['costs'][port] = costs[0] if costs else None
        original['admin'][port] = 'down' if 'shutdown' in lines else 'up'
    guarded = {}
    for header, lines in sections.items():
        if header in original['metrics']:
            lines = [line for line in lines if not line.startswith('set metric ')]
        if header in {f'interface {port}' for port in plan['ports']}:
            lines = [line for line in lines if line not in {'shutdown', 'no shutdown'}
                     and not re.match(r'(?:ipv6 ospf|ospfv3) cost\b', line)]
        guarded[header] = lines
    original['guard'] = hashlib.sha256(json.dumps(guarded, sort_keys=True).encode()).hexdigest()
    return original


def preference_commands(original, drain):
    result = []
    for header, previous in original['metrics'].items():
        command = f"set metric {METRICS[header.split()[1]]}" if drain else (previous or 'no set metric')
        result.extend([header, command, 'exit'])
    for port, previous in original['costs'].items():
        result.extend([f'interface {port}', 'ospfv3 cost 60000' if drain else 'no ospfv3 cost'])
        if not drain and previous:
            result.append(previous)
        result.append('exit')
    return result


def interface_commands(original, isolate):
    require(set(original['admin']) == {'Ethernet1', 'Ethernet2'}, "Unsafe interface rollback data.")
    return [line for port, state in original['admin'].items()
            for line in (f'interface {port}', 'shutdown' if isolate or state == 'down' else 'no shutdown', 'exit')]


def verify_preferences(current, original, drained):
    require(current['guard'] == original['guard'], "Unrelated live configuration drift detected; exact rollback cannot be assured.")
    expected = {h: f"set metric {METRICS[h.split()[1]]}" for h in original['metrics']} if drained else original['metrics']
    require(current['metrics'] == expected, "Route-map metric verification failed.")
    def normalized(cost):
        return int(cost.rsplit(' ', 1)[1]) if cost else None
    for port, cost in original['costs'].items():
        require(normalized(current['costs'][port]) == (COST if drained else normalized(cost)), "OSPFv3 cost verification failed.")


def dhcp_dependency(config):
    sections = config_sections(config)
    lines = sections.get('dhcp server', [])
    return {'enabled': 'dhcp server' in sections,
            'scopes': [line.split()[1] for line in lines if re.fullmatch(r'subnet [0-9a-fA-F:./]+', line)],
            'leases': [line for line in lines if re.fullmatch(r'lease time ipv[46] [0-9]+ days [0-9]+ hours [0-9]+ minutes', line)],
            'interfaces': [header.split()[1] for header, entries in sections.items()
                           if header.startswith('interface ') and any(x in entries for x in ('dhcp server ipv4', 'dhcp server ipv6'))]}


def normalize_interface(name):
    return re.sub(r'^(?:eth|et)(?=\d)', 'Ethernet', str(name), flags=re.I)


def ipv6_routes(text):
    """Parse documented EOS FIB blocks, retaining every ECMP next-hop interface."""
    routes, current = {}, None
    for line in text.splitlines():
        match = re.match(r'^\s*[A-Z0-9 *]+\s+([0-9a-fA-F:]+/[0-9]+)(?:\s|$)', line)
        if match:
            current = str(ipaddress.IPv6Network(match[1]))
            require(current not in routes, "Duplicate IPv6 FIB prefix; unsupported output.")
            routes[current] = []
        if current and 'via ' in line:
            hop = re.search(r'\bvia ([0-9a-fA-F:%]+),\s*([A-Za-z]+[0-9/.:-]+)', line)
            require(hop is not None, "Unrecognized IPv6 next hop; cannot prove drain.")
            require('backup' not in line.lower(), "IPv6 backup-path output is unsupported for drain proof.")
            routes[current].append({'nexthopAddr': hop[1], 'interface': normalize_interface(hop[2])})
    require(routes, "No recognized IPv6 FIB routes.")
    return routes


def ospfv3_full_neighbors(text):
    found = set()
    text = '\n'.join(line.strip() for line in text.splitlines())
    for block in re.split(r'(?m)(?=^Neighbor )', text):
        neighbor = re.match(r'Neighbor ([0-9.]+).*?state is Full\b', block, re.I)
        port = re.search(r'\binterface ([A-Za-z]+[0-9/.:-]+)', block, re.I)
        if neighbor and port:
            found.add((normalize_interface(port[1]), neighbor[1]))
    return found


def route_vias(response, prefix):
    require(isinstance(response, dict), 'Unrecognized IPv4 route reply.')
    route = response.get('vrfs', {}).get('default', {}).get('routes', {}).get(prefix)
    require(isinstance(route, dict) and route.get('routeAction', 'forward') == 'forward', f'Missing forwarding route: {prefix}')
    vias = route.get('vias')
    require(isinstance(vias, list) and vias and all(isinstance(v, dict) and v.get('interface') for v in vias),
            f'Unrecognized or unresolved next hops: {prefix}')
    return vias


def traffic_gate(rates, baseline, target, alternate, max_bps=512, max_share=0.10, retained=0.20):
    for samples in (rates, baseline):
        require(set(samples) == {target, alternate}, 'Incomplete traffic evidence.')
        for ports in samples.values():
            require(set(ports) == {'Ethernet1', 'Ethernet2'}, 'Both production interfaces require traffic evidence.')
            for value in ports.values():
                for direction in ('rx_bps', 'tx_bps'):
                    number = value.get(direction)
                    require(not isinstance(number, bool) and isinstance(number, (int, float))
                            and math.isfinite(number) and number >= 0, 'Invalid per-direction traffic rate.')
    totals = {name: sum(v['rx_bps'] + v['tx_bps'] for v in entries.values()) for name, entries in rates.items()}
    require(all(math.isfinite(value) and value >= 0 for value in totals.values()), 'Invalid traffic rates.')
    if totals[alternate] <= 0 or totals[target] > totals[alternate] * max_share:
        return False
    for port, value in rates[target].items():
        now = value['rx_bps'] + value['tx_bps']
        previous = baseline[target][port]['rx_bps'] + baseline[target][port]['tx_bps']
        if now > max_bps or (previous > max_bps and now > previous * retained):
            return False
    old_alternate = sum(v['rx_bps'] + v['tx_bps'] for v in baseline[alternate].values())
    return totals[alternate] >= old_alternate * 0.5


class Maintenance:
    def __init__(self, inventory_path=INVENTORY, runtime=RUNTIME, api=None, telemetry=None,
                 args=None, acknowledge=input, sleep=time.sleep):
        self.path, self.runtime = Path(inventory_path), Path(runtime)
        self.inventory = storage.load_inventory(self.path)
        self.api, self.telemetry, self.args = api, telemetry, args or defaults()
        self.acknowledge, self.sleep = acknowledge, sleep

    def record_path(self, name):
        require(name in ROUTERS, 'Invalid rollback target.')
        return self.runtime / f'{name}.json'

    def record(self, name):
        path = self.record_path(name)
        if not path.exists():
            return None
        require(not path.is_symlink(), 'Unsafe rollback file.')
        try:
            record = json.loads(path.read_bytes())
            require(record['ticket'] == TICKET and record['target'] == name
                    and record['state'] in TRANSITIONS, 'Invalid rollback metadata.')
            return record
        except (KeyError, ValueError, TypeError):
            raise MaintenanceError('Rollback metadata cannot be read safely.') from None

    def state(self, name):
        record = self.record(name)
        if record and record['state'] != 'in_service':
            return record['state']
        data = storage.load_inventory(self.path).get('maintenance', {})
        require(not data or data.get('ticket') == TICKET, 'Different NSOT maintenance ticket is active.')
        value = data.get('routers', {}).get(name, {}).get('state', 'in_service')
        require(value in TRANSITIONS, 'Unknown NSOT maintenance state.')
        return value

    def save(self, record, state=None):
        if state and state != record['state']:
            record['state'] = transition(record['state'], state)
        record['updated_at'] = stamp()
        storage._atomic_write(self.record_path(record['target']), (json.dumps(record, indent=2) + '\n').encode())
        report('STAGE', f"{record['target']} {record['state'].upper()} | alternate {record['alternate']} | rollback YES")

    def live(self, target, plan):
        return capture(self.api.show(target, 'show running-config', text=True), target, plan)

    def verify_inventory(self):
        latest = storage.load_inventory(self.path)
        require({k: v for k, v in latest.items() if k != 'maintenance'}
                == {k: v for k, v in self.inventory.items() if k != 'maintenance'},
                'NSOT changed after precheck; refusing further maintenance changes.')

    def health(self, name, plans):
        plan = plans[name]
        config = self.api.show(name, 'show running-config', text=True)
        original = capture(config, name, plan)
        require(all(state == 'up' for state in original['admin'].values()), f'{name}: production interface administratively down.')
        descriptions = self.api.show(name, 'show interfaces description').get('interfaceDescriptions', {})
        for port in [*plan['ports'], 'Management0']:
            entry = descriptions.get(port, {})
            require(str(entry.get('interfaceStatus')).lower() == 'up'
                    and str(entry.get('lineProtocolStatus')).lower() == 'up', f'{name}: {port} is not operationally up.')
        neighbors = self.api.show(name, 'show ip ospf neighbor').get('vrfs', {}).get('default', {}).get('instList', {}).get(plan['process'], {}).get('ospfNeighborEntries', [])
        for entry in plan['device']['routing']['ospfv2']['interfaces']:
            peer = plan['device']['interfaces'][entry['name']]['peer']['device']
            rid = self.inventory['devices'][peer]['routing']['ospfv2']['router_id']
            require(any(n.get('interfaceName') == entry['name'] and n.get('routerId') == rid
                        and str(n.get('adjacencyState')).lower() == 'full' for n in neighbors), f'{name}: expected OSPFv2 neighbor not FULL.')
        v3 = ospfv3_full_neighbors(self.api.show(name, 'show ipv6 ospf neighbor vrf default', text=True))
        for port in plan['ports']:
            peer = plan['device']['interfaces'][port]['peer']['device']
            rid = self.inventory['devices'][peer]['routing']['ospfv3']['router_id']
            require((port, rid) in v3, f'{name}: expected OSPFv3 neighbor on {port} not FULL.')
        # RIP has no FULL state: learned host routes and access-side FIB checks prove participation.
        routes = self.api.show(name, 'show ip route')
        for prefix in PREFIXES['core'][:2]:
            route_vias(routes, prefix)
        report('PASS', f'{name}: management reachable; production interfaces UP; OSPFv2/v3 FULL; host routes installed')
        return config, original

    def routing(self, target, alternate, plans, avoid=False):
        """Check both access gateways and both core gateways; reject every ECMP target hop."""
        target_ips = {str(ipaddress.ip_interface(address).ip)
                      for port in plans[target]['ports'] for family in ('ipv4', 'ipv6')
                      for address in plans[target]['device']['interfaces'][port].get(family, [])}
        evidence = {}
        for owner in ROUTERS:
            for role, peer in plans[owner]['peers'].items():
                name = peer['device']
                v4 = self.api.show(name, 'show ip route')
                v6 = ipv6_routes(self.api.show(name, 'show ipv6 route vrf default', text=True))
                for prefix in PREFIXES[role]:
                    vias = route_vias(v4, prefix) if ':' not in prefix else v6.get(prefix)
                    require(vias and all(v.get('interface') for v in vias), f'{name}: exact route {prefix} not proven.')
                    ports = {normalize_interface(v['interface']) for v in vias}
                    require(all(re.fullmatch(r'(?:Ethernet[0-9/]+|Vlan[0-9]+)', port) for port in ports), f'{name}: unresolved/non-production next hop.')
                    if avoid:
                        require(not any(str(v.get('nexthopAddr', '')).split('%')[0] in target_ips for v in vias), f'{name}: {prefix} still selects target next hop.')
                        if owner == target:
                            require(peer['interface'] not in ports, f'{name}: {prefix} still selects {target} (including ECMP).')
                        else:
                            require(ports == {peer['interface']}, f'{name}: {prefix} is not exclusively using alternate {alternate}.')
                    evidence[f'{name}:{prefix}'] = sorted(ports)
        return evidence

    def rates(self, plans):
        return self.telemetry.rates({name: plan['device']['management']['ipv4'] for name, plan in plans.items()},
                                    {name: plan['ports'] for name, plan in plans.items()})

    def precheck(self, target):
        self.inventory = storage.load_inventory(self.path)
        target, alternate, plans = discover(self.inventory, target)
        require(self.state(target) == 'in_service', f'{target} has pending maintenance; use restore/rollback, not another drain.')
        require(self.state(alternate) == 'in_service', f'{alternate} is not IN_SERVICE; refusing to drain both routers.')
        report('PRECHECK', f'Ticket {TICKET} | target {target} | alternate {alternate} | R1 {self.state("R1")} | R2 {self.state("R2")}')
        configs = {}
        for name in (alternate, target):
            version = self.api.show(name, 'show version').get('version')
            require(isinstance(version, str) and version.startswith('4.'), f'{name}: unrecognized EOS platform/version.')
            configs[name], original = self.health(name, plans)
            require(all(value is None or int(value.split()[-1]) < METRICS[header.split()[1]]
                        for header, value in original['metrics'].items())
                    and all(value is None or int(value.split()[-1]) < COST for value in original['costs'].values()),
                    f'{name}: preferences already meet/exceed drain settings; reconcile pending maintenance first.')
            if name == target:
                captured = original
            report('PASS', f'{name}: EOS {version}; eAPI reachable')
        evidence = self.routing(target, alternate, plans)
        rates = self.rates(plans)
        report('PASS', 'Fresh RX/TX telemetry for all four production interfaces; exact IPv4/IPv6 routes installed')
        dependency = dhcp_dependency(configs['R2'])
        if dependency['enabled']:
            report('WARN', 'DHCP DEPENDENCY: WARNING — R2 serves DHCP without known redundancy')
            report('WARN', 'Challenge hosts must already have active leases; existing leases normally survive this short window.')
            report('WARN', 'New leases/renewals may be unavailable while R2 is isolated. This is a service dependency, not routing redundancy.')
            report('INFO', 'Live DHCP leases: ' + ', '.join(dependency['leases']) + '; interfaces: ' + ', '.join(dependency['interfaces']))
        report('OPERATOR', 'Verify all four continuous ping windows are still healthy. This application does not run host tests.')
        for command in preference_commands(captured, True):
            report('PLAN', f'{target}: {command}')
        report('PLAN', f'{target}: shutdown only {", ".join(plans[target]["ports"])} AFTER all drain gates and PINGS-HEALTHY acknowledgement')
        return {'plans': plans, 'target': target, 'alternate': alternate, 'config': configs[target],
                'original': captured, 'baseline': rates, 'routes': evidence, 'dhcp': dependency}

    def confirm_pings(self):
        report('OPERATOR', 'Verify all four continuous ping windows are still healthy. Enter PINGS-HEALTHY; any other response cancels and rolls back.')
        require(self.acknowledge('Customer evidence> ') == 'PINGS-HEALTHY', 'Customer ping evidence was not confirmed.')

    def wait_health(self, target, plans):
        deadline = time.monotonic() + self.args.timeout
        while True:
            try:
                self.health(target, plans)
                return
            except MaintenanceError:
                if time.monotonic() >= deadline:
                    raise MaintenanceError(f'{target}: routing/adjacency recovery timed out.') from None
                report('WAIT', f'{target}: waiting for interfaces and routing adjacencies')
                self.sleep(self.args.interval)

    def drain_evidence(self, data, applied_at):
        target, alternate, plans = data['target'], data['alternate'], data['plans']
        deadline = time.monotonic() + self.args.timeout
        stable, previous = 0, {}
        while time.monotonic() < deadline:
            self.sleep(self.args.interval)
            self.health(alternate, plans)
            self.health(target, plans)
            try:
                rates = self.rates(plans)
                for name, ports in rates.items():
                    for port, rate in ports.items():
                        report('RATE', f"{name} {port}: RX {rate['rx_bps']:.1f} TX {rate['tx_bps']:.1f} bit/s")
                samples = {(name, port, direction): (value[f'{direction}_start'], value[f'{direction}_end'])
                           for name, ports in rates.items() for port, value in ports.items() for direction in ('rx', 'tx')}
                require(all(start >= applied_at + self.args.settle and end > previous.get(key, 0)
                            and start >= previous.get(key, 0) for key, (start, end) in samples.items()),
                        'Waiting for new post-convergence RX/TX telemetry windows.')
                previous = {key: end for key, (start, end) in samples.items()}
                self.routing(target, alternate, plans, avoid=True)
                require(traffic_gate(rates, data['baseline'], target, alternate, self.args.max_target_bps), 'Target traffic is not sufficiently drained.')
                stable += 1
                report('PASS', f'Stable drain samples {stable}/{self.args.samples}')
                if stable >= self.args.samples:
                    return
            except (MaintenanceError, TelemetryError) as error:
                stable = 0
                report('WAIT', str(error))
        raise MaintenanceError('Drain verification timed out. Interface isolation is prohibited.')

    def drain(self, target):
        data = self.precheck(target)
        if self.args.dry_run or self.args.precheck_only:
            report('PASS', 'Read-only inspection complete; no backups, journals, NSOT updates, or device changes.')
            return
        # Reuse the existing verified, private Golden backup writer, with eAPI input.
        # Reuse GUI credential redaction so new backups/runtime never persist secrets.
        from app import _redact_configuration
        config, _ = _redact_configuration(data['config'])
        change_id = uuid.uuid4().hex
        backup = storage._save_prechange_backup({'device': target, 'change_id': change_id}, config)
        record = {'ticket': TICKET, 'target': target, 'alternate': data['alternate'], 'state': 'precheck',
                  'change_id': change_id, 'original': data['original'], 'production_ports': data['plans'][target]['ports'],
                  'management_ip': data['plans'][target]['device']['management']['ipv4'],
                  'backup': str(backup), 'backup_sha256': hashlib.sha256(Path(backup).read_bytes()).hexdigest(),
                  'baseline_routes': data['routes'], 'baseline_rates': data['baseline'],
                  'created_at': stamp(), 'preference_attempted': False, 'isolation_attempted': False}
        self.save(record)
        report('PASS', 'Pre-change Golden backup saved (secrets redacted); exact maintenance rollback metadata durable')
        try:
            self.save(record, 'draining')
            update_nsot(self.path, target, 'draining')
            self.verify_inventory()
            require(self.live(target, data['plans'][target]) == record['original'],
                    'Live configuration changed after capture; refusing to overwrite it.')
            record['preference_attempted'] = True
            self.save(record)
            self.api.configure(target, preference_commands(record['original'], True))
            applied_at = time.time()
            verify_preferences(self.live(target, data['plans'][target]), record['original'], True)
            self.drain_evidence(data, applied_at)
            report('PASS', 'ROUTING DRAIN: VERIFIED')
            self.confirm_pings()
            # Operator input can take time: recheck every gate immediately before isolation.
            self.verify_inventory()
            require(self.state(data['alternate']) == 'in_service', 'Alternate maintenance state changed.')
            self.health(data['alternate'], data['plans'])
            self.health(target, data['plans'])
            self.routing(target, data['alternate'], data['plans'], avoid=True)
            rates = self.rates(data['plans'])
            require(all(v['start'] >= applied_at + self.args.settle for ports in rates.values() for v in ports.values())
                    and traffic_gate(rates, data['baseline'], target, data['alternate'], self.args.max_target_bps), 'Drain evidence no longer holds.')
            verify_preferences(self.live(target, data['plans'][target]), record['original'], True)
            require(self.record(target) == record and Path(record['backup']).is_file()
                    and hashlib.sha256(Path(record['backup']).read_bytes()).hexdigest() == record['backup_sha256'],
                    'Rollback data is unavailable or changed.')
            self.save(record, 'drained')
            record['isolation_attempted'] = True  # Persist BEFORE the first possible shutdown.
            self.save(record)
            self.api.configure(target, interface_commands(record['original'], True))
            isolated = self.live(target, data['plans'][target])
            require(all(state == 'down' for state in isolated['admin'].values()), 'Production interface isolation failed.')
            descriptions = self.api.show(target, 'show interfaces description').get('interfaceDescriptions', {})
            require(all(descriptions.get(port, {}).get('interfaceStatus') == 'adminDown' for port in data['plans'][target]['ports']), 'Administrative isolation not confirmed by live API.')
            self.health(data['alternate'], data['plans'])
            self.routing(target, data['alternate'], data['plans'], avoid=True)
            self.confirm_pings()
            update_nsot(self.path, target, 'out_of_service')
            self.save(record, 'out_of_service')
            report('PASS', f'{target}: Ethernet1/Ethernet2 ADMIN DOWN; management reachable; NSOT OUT_OF_SERVICE (drain verified)')
            report('PASS', 'CURRENT PRODUCTION FLOWS: operator confirmed healthy; no independent host test performed')
        except (Exception, KeyboardInterrupt) as error:
            report('FAIL', 'Maintenance failed; attempting exact rollback. No further isolation will be attempted.')
            try:
                self.restore(target, rollback=True, emergency=True)
            except (Exception, KeyboardInterrupt):
                record['state'] = 'error'
                self.save(record)
                try:
                    update_nsot(self.path, target, 'error')
                except Exception:
                    report('FAIL', 'NSOT error-state write also failed; runtime rollback journal is authoritative.')
                report('FAIL', f'Rollback incomplete; run rollback {target} after management recovery. Original snapshot retained.')
            raise MaintenanceError('Drain failed; ERROR. Check the reported rollback result before proceeding.') from error

    def restore(self, target, rollback=False, emergency=False):
        try:
            inventory = storage.load_inventory(self.path)
        except storage.ChangeError:
            if not emergency:
                raise
            inventory = self.inventory
            report('WARN', 'NSOT unavailable; emergency recovery uses the prechecked in-memory device identities.')
        target, alternate, plans = discover(inventory, target)
        record = self.record(target)
        require(record is not None, f'{target}: no captured rollback state; refusing to guess original settings.')
        require(record['management_ip'] == plans[target]['device']['management']['ipv4']
                and record['production_ports'] == plans[target]['ports'], 'NSOT target identity changed since capture.')
        if not emergency:
            require(self.state(alternate) == 'in_service', f'{alternate} is not IN_SERVICE; normal restore precheck failed.')
            self.health(alternate, plans)
        if record['state'] == 'in_service':
            self.health(target, plans)
            verify_preferences(self.live(target, plans[target]), record['original'], False)
            report('PASS', f'{target} already restored; no device or NSOT writes needed.')
            return
        original = record['original']
        current = self.live(target, plans[target])
        require(current['guard'] == original['guard'], 'Unrelated live configuration changed; review rollback before overwriting settings.')
        require(all(value == 'up' for value in original['admin'].values()), 'Invalid rollback metadata: prechecked interfaces must originally be up.')
        if not record.get('preference_attempted'):
            require(current == original, 'Live settings changed before our first device write; refusing to overwrite them during rollback.')
        if self.args.dry_run or self.args.precheck_only:
            report('PLAN', f'{target}: restore production interfaces while drained, verify adjacencies, then restore captured original preferences')
            for command in preference_commands(original, False):
                report('PLAN', command)
            self.rates(plans)
            return
        try:
            self.save(record, 'rollback' if rollback else 'restoring')
        except Exception:
            if not emergency:
                raise
            report('WARN', 'Runtime state write failed; proceeding with emergency recovery from the captured snapshot.')
        try:
            try:
                update_nsot(self.path, target, 'restoring')
            except Exception:
                # A disk/NSOT error must not prevent restoring an isolated router.
                report('WARN', 'Cannot record RESTORING in NSOT; restoring live connectivity before retrying final state.')
            if current != original and (record.get('isolation_attempted') or any(value == 'down' for value in current['admin'].values())):
                self.api.configure(target, preference_commands(original, True))
                verify_preferences(self.live(target, plans[target]), original, True)
                self.api.configure(target, interface_commands(original, False))
                self.wait_health(target, plans)
            # Before-isolation rollback only removes our preference edits; no shutdown operation.
            if record.get('preference_attempted') and current != original:
                self.api.configure(target, preference_commands(original, False))
            verify_preferences(self.live(target, plans[target]), original, False)
            self.wait_health(target, plans)
            require(self.live(target, plans[target])['admin'] == original['admin'], 'Original admin states were not restored.')
            self.routing(target, alternate, plans)
            update_nsot(self.path, target, 'in_service')
            self.save(record, 'in_service')
            archive = self.runtime / f"{target}_{record['change_id']}_completed.json"
            if not archive.exists():
                storage._exclusive_backup(self.runtime, archive.name, (json.dumps(record, indent=2) + '\n').encode())
            report('PASS', f'{target}: original metrics/costs/admin state restored and verified; NSOT IN_SERVICE')
        except (Exception, KeyboardInterrupt):
            record['state'] = 'error'
            self.save(record)
            report('FAIL', f'{target}: restoration incomplete; rollback snapshot retained. Alternate was not modified.')
            raise

    def status(self):
        report('INFO', f'NetPilot Maintenance — {TICKET}')
        for name in ROUTERS:
            report('STATE', f'{name}: {self.state(name).upper()} | rollback {"YES" if self.record(name) else "NO"}')
        report('INFO', 'States above are recorded intent; live health must pass precheck before any drain.')

    def challenge(self):
        if self.args.dry_run or self.args.precheck_only:
            self.precheck('R2')
            self.precheck('R1')
            report('PLAN', 'R2 drain -> PART1-PASSED -> R2 restore/verify -> R1 drain -> STOP; never auto-restore R1')
            return
        self.drain('R2')
        print('\n' + '=' * 60 + '\nPART 1 READY - R2 OUT OF SERVICE\nRAISE YOUR HAND FOR INSTRUCTOR VERIFICATION\n' + '=' * 60, flush=True)
        while self.acknowledge('Enter PART1-PASSED only after instructor approval> ') != 'PART1-PASSED':
            report('WAIT', 'R2 remains OUT_OF_SERVICE; exact acknowledgement required.')
        self.restore('R2')
        require(self.state('R2') == 'in_service', 'Part 2 blocked: R2 is not IN_SERVICE.')
        self.drain('R1')
        print('\n' + '=' * 60 + '\nPART 2 READY - R1 OUT OF SERVICE\nRAISE YOUR HAND FOR INSTRUCTOR VERIFICATION\nR1 WILL REMAIN OUT OF SERVICE UNTIL EXPLICIT RESTORE\n' + '=' * 60, flush=True)


def defaults():
    return argparse.Namespace(dry_run=False, precheck_only=False, samples=3, interval=11.0,
                              settle=20.0, timeout=240.0, max_target_bps=512.0, insecure=False)


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument('action', choices=('status', 'precheck', 'drain', 'restore', 'rollback', 'challenge'))
    result.add_argument('target', nargs='?', choices=ROUTERS)
    result.add_argument('--dry-run', action='store_true', help='Read-only live inspection; no runtime/NSOT/device writes')
    result.add_argument('--precheck-only', action='store_true')
    result.add_argument('--insecure', action='store_true', help='Explicitly accept the lab eAPI self-signed certificate')
    result.add_argument('--samples', type=int, default=3)
    result.add_argument('--interval', type=float, default=11)
    result.add_argument('--settle', type=float, default=20)
    result.add_argument('--timeout', type=float, default=240)
    result.add_argument('--max-target-bps', type=float, default=512, help='Per-interface RX+TX ceiling, bit/s; max 1024. Routing proof is always required.')
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    telemetry = None
    try:
        require((args.action in ('status', 'challenge')) == (args.target is None), 'Specify R1/R2 for this action only.')
        require(3 <= args.samples <= 20 and 10 <= args.interval <= 60 and 10 <= args.settle <= 120
                and 60 <= args.timeout <= 900 and 0 < args.max_target_bps <= 1024, 'Unsafe sampling/timing/traffic limits.')
        if args.action == 'status':
            Maintenance(args=args).status()
            return 0
        inventory = storage.load_inventory(INVENTORY)
        api = EAPI(inventory, insecure=args.insecure)
        if args.insecure:
            report('WARN', 'Lab eAPI TLS certificate verification explicitly disabled; HTTPS encryption remains enabled.')
        # Emergency recovery must remain usable during an Influx outage/token loss.
        if args.action in ('precheck', 'drain', 'challenge') or args.dry_run or args.precheck_only:
            telemetry = Telemetry()
        app = Maintenance(api=api, telemetry=telemetry, args=args)

        def dispatch():
            if args.action == 'precheck':
                app.precheck(args.target)
            elif args.action == 'challenge':
                app.challenge()
            elif args.action == 'drain':
                app.drain(args.target)
            else:
                app.restore(args.target, rollback=args.action == 'rollback', emergency=args.action == 'rollback')

        if args.action == 'precheck' or args.dry_run or args.precheck_only:
            dispatch()
        else:
            # Directory flock is shared by all challenge invocations; prevents simultaneous drains.
            with storage._directory_lock(RUNTIME, threading.Lock(), create=True):
                dispatch()
        return 0
    except (KeyboardInterrupt, EOFError):
        report('WARN', 'Stopped. At an instructor checkpoint, the isolated router remains OUT_OF_SERVICE. Use status and explicit restore/rollback.')
        return 2
    except (MaintenanceError, storage.ChangeError, TelemetryError) as error:
        report('FAIL', str(error))
        return 1
    except Exception:
        report('FAIL', 'Operation could not complete safely. Inspect status/rollback metadata; raw device or credential errors are suppressed.')
        return 1
    finally:
        if telemetry:
            telemetry.close()


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    raise SystemExit(main())

#!/usr/bin/env python3
"""Read-only Containerlab link, routing, and data-plane connectivity checks.

Run: sudo python3 Functions/check_network_status.py
Requires PyYAML (python3 -m pip install pyyaml), Docker, and the running lab.
No configuration commands, interface changes, or saves are performed.
"""

import ipaddress
import json
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parent.parent
RESULTS = []


def report(section, item, status, detail):
    RESULTS.append((section, item, status, detail))
    print(f"{item:<24} {status:<7} {detail}", flush=True)


def heading(title):
    print(f"\n{title}\n{'-' * 100}")
    print(f"{'Check':<24} {'Status':<7} Evidence")


def cli(container, command):
    # An explicit allowlist prevents this helper from sending configuration.
    if not command.startswith(("show ", "ping ")) or any(c in command for c in "\n\r;"):
        raise ValueError("Only single show/ping commands are allowed.")
    result = subprocess.run(
        ["docker", "exec", container, "Cli", "-p", "15", "-c", command],
        capture_output=True, text=True, timeout=20,
    )
    if result.returncode or re.search(r"(?m)^\s*%", result.stdout):
        # Do not include running-config or other potentially sensitive output.
        raise RuntimeError(f"Command failed: {command}")
    return result.stdout


def parse_config(config):
    """Read interface addresses and routing sections; exclude management/VRFs."""
    interfaces, protocols = {}, {}
    current = None
    for line in config.splitlines():
        if line.startswith("interface "):
            name = line.split()[1]
            current = interfaces.setdefault(name, [])
        elif re.match(r"^(?:ipv6 )?router (?:ospf|rip)\b", line):
            current = protocols.setdefault(line.strip(), [])
        elif line and not line[0].isspace():
            current = None
        elif current is not None:
            current.append(line.strip())
    addresses = {}
    for name, lines in interfaces.items():
        if name.startswith("Management") or any(x.startswith("vrf ") for x in lines):
            continue
        addresses[name] = []
        for line in lines:
            match = re.match(r"(?:ip|ipv6) address (\S+)", line)
            if match:
                try:
                    address = ipaddress.ip_interface(match.group(1))
                    if not address.ip.is_link_local and not address.ip.is_loopback:
                        addresses[name].append(address)
                except ValueError:
                    pass
    return interfaces, protocols, addresses


def routing_checks(device, data):
    name, container = device['name'], data['container']
    specs = [
        ('OSPFv2', r'^router ospf\b', 'show ip ospf neighbor', 'show ip route ospf', 4),
        ('RIP', r'^router rip\b', 'show ip rip neighbors', 'show ip route rip', 4),
        ('OSPFv3', r'^ipv6 router ospf\b', 'show ipv6 ospf neighbor', 'show ipv6 route ospf', 6),
    ]
    for label, pattern, neighbor_cmd, route_cmd, version in specs:
        item = f"{name} / {label}"
        sections = [v for k, v in data['protocols'].items() if re.search(pattern, k)]
        if not sections:
            report('routing', item, 'N/A', 'Not configured in current running-config')
            continue
        if all('shutdown' in section for section in sections):
            report('routing', item, 'FAIL', 'Configured routing process is shut down')
            continue
        try:
            neighbors = cli(container, neighbor_cmd)
            rows = [line.strip() for line in neighbors.splitlines()
                    if re.match(r'^\s*(?:Neighbor\s+)?\d+\.\d+\.\d+\.\d+\s+', line)]
            if not rows:
                report('routing', item, 'WARN', 'No neighbor rows found; review process/interfaces')
            elif label.startswith('OSPF'):
                bad = [row for row in rows if not re.search(r'\bFULL\b', row, re.I)]
                status = 'WARN' if bad else 'PASS'
                report('routing', item, status,
                       f'{len(rows) - len(bad)}/{len(rows)} observed neighbors FULL'
                       + ('; 2-WAY may be normal on broadcast networks' if bad else ''))
            else:
                report('routing', item, 'INFO', f'{len(rows)} RIP neighbor records (RIP has no FULL adjacency)')
            for row in rows:
                print(f"    {row}")
            routes = cli(container, route_cmd)
            prefixes = set()
            for token in re.findall(r'[0-9a-fA-F:.]+/\d+', routes):
                try:
                    prefix = ipaddress.ip_network(token, strict=False)
                    if prefix.version == version:
                        prefixes.add(str(prefix))
                except ValueError:
                    pass
            report('routing', f'{name} / {label} routes', 'PASS' if prefixes else 'WARN',
                   f'{len(prefixes)} learned prefixes in routing table'
                   + ('; absence needs review' if not prefixes else ''))
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
            report('routing', item, 'ERROR', str(error))


def main():
    try:
        import yaml
        with (ROOT / 'Functions/devices.json').open() as file:
            devices = [d for d in json.load(file)['devices']
                       if d.get('type') in ('router', 'switch')]
        with (ROOT / 'nettopo.clab.yml').open() as file:
            topology = yaml.safe_load(file)
        if not devices:
            raise ValueError('No routers/switches found in inventory')
    except ImportError:
        print('Install dependency: python3 -m pip install pyyaml')
        return 1
    except (OSError, ValueError, KeyError) as error:
        print(f'Input error: {error}')
        return 1

    RESULTS.clear()
    print('NETPILOT READ-ONLY NETWORK STATUS')
    print('OSPFv2 = IPv4 OSPF; OSPFv3 = IPv6 OSPF. Default VRF only.')
    live = {}
    heading('1. Device access and management reachability')
    for device in devices:
        name = device['name']
        container = f"clab-{topology['name']}-{name}"
        try:
            config = cli(container, 'show running-config')
            interfaces, protocols, addresses = parse_config(config)
            states = json.loads(cli(container, 'show interfaces | json'))['interfaces']
            live[name] = dict(container=container, interfaces=interfaces,
                              protocols=protocols, addresses=addresses, states=states)
            report('access', name, 'PASS', 'Docker CLI available')
        except (RuntimeError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
            report('access', name, 'ERROR', str(error))
        try:
            ping = subprocess.run(['ping', '-n', '-c', '2', '-W', '1', device['ip']],
                                  capture_output=True, timeout=5)
            report('management', name, 'PASS' if ping.returncode == 0 else 'FAIL', device['ip'])
        except (OSError, subprocess.TimeoutExpired) as error:
            report('management', name, 'ERROR', str(error))

    heading('2. Topology Ethernet links (network-device endpoints)')
    names = {d['name'] for d in devices}
    for link in topology['topology']['links']:
        endpoints = link.get('endpoints', [])
        for endpoint in endpoints:
            name, port = endpoint.split(':', 1)
            if name not in names:
                continue
            interface = re.sub(r'^eth', 'Ethernet', port)
            peer = ' / '.join(x for x in endpoints if x != endpoint)
            state = live.get(name, {}).get('states', {}).get(interface)
            if state is None:
                report('links', f'{name}:{interface}', 'ERROR', f'No interface data; peer {peer}')
            else:
                up = str(state.get('lineProtocolStatus', '')).lower() == 'up'
                report('links', f'{name}:{interface}', 'PASS' if up else 'FAIL',
                       f"{state.get('lineProtocolStatus', 'unknown')}; peer {peer}")

    heading('3. Routing protocols: neighbors and installed routes')
    for device in devices:
        if device['name'] in live:
            routing_checks(device, live[device['name']])
        else:
            report('routing', device['name'], 'ERROR', 'Device unavailable; protocols not checked')

    for version in (4, 6):
        heading(f'{4 if version == 4 else 5}. IPv{version} data-plane connectivity')
        print('Two pings per directed device pair, sourced from a data-plane address.')
        targets = {}
        for name, data in live.items():
            for interface in sorted(data['addresses'], key=lambda x: (not x.startswith('Loopback'), x)):
                if str(data['states'].get(interface, {}).get('lineProtocolStatus', '')).lower() != 'up':
                    continue
                candidates = [str(a.ip) for a in data['addresses'][interface] if a.version == version]
                if candidates:
                    targets[name] = candidates[0]
                    break
        for device in devices:
            name = device['name']
            if name in targets:
                print(f"  Target {name:<8} {targets[name]}")
            else:
                report('connectivity', name, 'WARN', f'No usable IPv{version} data-plane target; not tested')
        for source, source_ip in targets.items():
            for destination, target_ip in targets.items():
                if source == destination:
                    continue
                try:
                    command = f'ping {target_ip} source {source_ip} repeat 2 timeout 1'
                    output = cli(live[source]['container'], command)
                    loss = re.search(r'([\d.]+)% packet loss', output)
                    if loss:
                        status = 'PASS' if float(loss.group(1)) == 0 else 'FAIL'
                        detail = f'{loss.group(1)}% loss'
                    else:
                        status, detail = 'ERROR', 'Unrecognized ping output'
                    report('connectivity', f'{source} -> {destination}', status, f'{target_ip}: {detail}')
                except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
                    report('connectivity', f'{source} -> {destination}', 'ERROR', str(error))

    heading('6. Summary')
    for section in ('access', 'management', 'links', 'routing', 'connectivity'):
        rows = [r for r in RESULTS if r[0] == section]
        counts = {s: sum(r[2] == s for r in rows) for s in ('PASS', 'FAIL', 'WARN', 'ERROR', 'N/A', 'INFO')}
        print(f"{section:<24} " + ' | '.join(f'{s}: {n}' for s, n in counts.items() if n))
    failed = any(r[2] in ('FAIL', 'ERROR') for r in RESULTS)
    warning = any(r[2] == 'WARN' for r in RESULTS)
    print(f"\nFINAL RESULT: {'FAIL' if failed else 'REVIEW' if warning else 'PASS'}")
    print('Scope: observed neighbors/routes and one data-plane target per device/family.')
    print('Missing expected peers require a baseline; host application traffic and BGP are not audited.')
    print('Host-facing links are checked at the network-device endpoint only.')
    return 1 if failed else 2 if warning else 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print('\nCheck interrupted. No configuration changes were made.')
        raise SystemExit(130)

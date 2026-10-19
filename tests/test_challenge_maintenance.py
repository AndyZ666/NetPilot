"""Offline maintenance safety tests. All writes are temporary; no live device calls."""

from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

import yaml

import challenge_maintenance as m


ROOT = Path(__file__).resolve().parents[1]


def original():
    return {'metrics': {'route-map RIP-TO-OSPF permit 10': None, 'route-map OSPF-TO-RIP permit 10': None},
            'costs': {'Ethernet1': None, 'Ethernet2': None},
            'admin': {'Ethernet1': 'up', 'Ethernet2': 'up'}, 'guard': 'fixture'}


def rates(target_rate=50, alternate_rate=2000):
    now = time.time()
    return {name: {port: {'rx_bps': value, 'tx_bps': value, 'start': now, 'end': now + 10,
                          'rx_start': now, 'rx_end': now + 10, 'tx_start': now, 'tx_end': now + 10}
                   for port in ('Ethernet1', 'Ethernet2')}
            for name, value in (('R1', alternate_rate), ('R2', target_rate))}


class FakeAPI:
    def __init__(self):
        self.states = {name: original() for name in m.ROUTERS}
        self.calls = []
        self.fail_on_shutdown = False

    def configure(self, name, commands):
        self.calls.append((name, list(commands)))
        state, context = self.states[name], None
        for command in commands:
            if command.startswith(('route-map ', 'interface ')):
                context = command
            elif command.startswith('set metric '):
                state['metrics'][context] = command
            elif command == 'no set metric':
                state['metrics'][context] = None
            elif command.startswith(('ospfv3 cost ', 'ipv6 ospf cost ')):
                state['costs'][context.split()[1]] = command
            elif command == 'no ospfv3 cost':
                state['costs'][context.split()[1]] = None
            elif command in ('shutdown', 'no shutdown'):
                state['admin'][context.split()[1]] = 'down' if command == 'shutdown' else 'up'
                if command == 'shutdown' and self.fail_on_shutdown:
                    self.fail_on_shutdown = False
                    raise m.MaintenanceError('Simulated partial command failure')

    def show(self, name, command, text=False):
        if command == 'show interfaces description':
            return {'interfaceDescriptions': {port: {'interfaceStatus': 'adminDown' if state == 'down' else 'up',
                                                     'lineProtocolStatus': state}
                                              for port, state in self.states[name]['admin'].items()}}
        raise AssertionError('Unexpected show call in fixture')


class FixtureMaintenance(m.Maintenance):
    def precheck(self, target):
        target, alternate, plans = m.discover(self.inventory, target)
        m.require(self.state(target) == self.state(alternate) == 'in_service', 'Both routers must be in service')
        return {'target': target, 'alternate': alternate, 'plans': plans, 'config': f'hostname {target}\nend\n',
                'original': deepcopy(self.api.states[target]), 'baseline': rates(2000, 2000), 'routes': {}, 'dhcp': {}}

    def health(self, name, plans):
        m.require(all(value == 'up' for value in self.api.states[name]['admin'].values()), 'Fixture interface down')
        return f'hostname {name}\nend\n', deepcopy(self.api.states[name])

    def live(self, target, plan):
        return deepcopy(self.api.states[target])

    def routing(self, *args, **kwargs):
        return {'fixture-route': ['Ethernet1']}

    def rates(self, plans):
        return rates()

    def drain_evidence(self, data, applied_at):
        return None


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = (ROOT / 'inventory/devices.yml').read_bytes()
        self.source_hash = hashlib.sha256(self.source).hexdigest()
        self.path = self.root / 'devices.yml'
        self.path.write_bytes(self.source)
        self.runtime = self.root / 'runtime'
        self.runtime.mkdir()
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Live network forbidden')))
        self.enterContext(patch.object(m.storage, 'ConnectHandler', side_effect=AssertionError('Netmiko forbidden')))
        self.enterContext(patch.object(m.storage, 'GOLDEN_CONFIGS_PATH', self.root / 'golden'))
        self.output = self.enterContext(patch('sys.stdout', new_callable=io.StringIO))
        self.api = FakeAPI()
        args = m.defaults()
        args.settle = 0
        self.app = FixtureMaintenance(self.path, self.runtime, api=self.api, args=args,
                                      acknowledge=lambda _: 'PINGS-HEALTHY', sleep=lambda _: None)

    def tearDown(self):
        self.assertEqual(hashlib.sha256((ROOT / 'inventory/devices.yml').read_bytes()).hexdigest(), self.source_hash)

    def test_discovery_is_device_local_and_uses_nsot(self):
        target, alternate, plans = m.discover(self.app.inventory, 'R2')
        self.assertEqual((target, alternate), ('R2', 'R1'))
        self.assertEqual(plans['R2']['device']['management']['ipv4'], '172.20.20.14')
        self.assertEqual(plans['R2']['ports'], ['Ethernet1', 'Ethernet2'])
        self.assertEqual(m.discover(self.app.inventory, 'R1')[:2], ('R1', 'R2'))
        for target in ('R3', 'Management0', 'R2\nreload'):
            with self.assertRaises(m.MaintenanceError):
                m.discover(self.app.inventory, target)

    def test_discovery_rejects_extra_ports_and_nonreciprocal_peers(self):
        data = deepcopy(self.app.inventory)
        data['devices']['R2']['interfaces']['Ethernet3'] = deepcopy(data['devices']['R2']['interfaces']['Ethernet1'])
        with self.assertRaises(m.MaintenanceError):
            m.discover(data, 'R2')
        data = deepcopy(self.app.inventory)
        data['devices']['S4']['interfaces']['Ethernet3']['peer'] = None
        with self.assertRaises(m.MaintenanceError):
            m.discover(data, 'R2')

    def test_managed_block_preserves_anchored_source_and_other_state(self):
        first = m.maintenance_block(self.source, 'R2', 'out_of_service', 'fixture-time')
        self.assertTrue(first.startswith(self.source))
        second = m.maintenance_block(first, 'R1', 'in_service', 'next-time')
        self.assertTrue(second.startswith(self.source))
        parsed = yaml.safe_load(second)
        self.assertEqual(parsed['devices'], yaml.safe_load(self.source)['devices'])
        self.assertEqual(parsed['maintenance']['routers']['R2']['state'], 'out_of_service')
        self.assertEqual(second.count(m.BEGIN.encode()), 1)
        self.assertEqual(yaml.safe_load(self.source)['devices']['S1'], parsed['devices']['S1'])

    def test_block_rejects_unmanaged_duplicate_or_invalid_yaml(self):
        for source in (self.source + b'\nmaintenance: {}\n', self.source + (m.BEGIN+'\n').encode(),
                       self.source + (m.END+'\n'+m.BEGIN+'\n').encode(),
                       self.source + b'\ndevices: {}\n'):
            with self.subTest(source_size=len(source)), self.assertRaises((m.MaintenanceError, m.storage.ChangeError)):
                m.maintenance_block(source, 'R2', 'draining', 'fixture')

    def test_nsot_write_backs_up_exact_original(self):
        m.update_nsot(self.path, 'R2', 'out_of_service')
        backups = list((self.root / 'backups').glob('*.yml'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), self.source)
        self.assertTrue(self.path.read_bytes().startswith(self.source))

    def test_invalid_temporary_candidate_does_not_replace_nsot(self):
        old_atomic = m.storage._atomic_write
        def corrupt(path, content, **kwargs):
            return old_atomic(path, b'broken: [\n', **kwargs)
        with patch.object(m.storage, '_atomic_write', side_effect=corrupt), self.assertRaises(yaml.YAMLError):
            m.update_nsot(self.path, 'R2', 'draining')
        self.assertEqual(self.path.read_bytes(), self.source)

    def test_saved_configs_capture_absence_dhcp_and_exact_restoration(self):
        _, _, plans = m.discover(self.app.inventory, 'R2')
        for name in m.ROUTERS:
            config = (ROOT / 'golden_configs' / name / f'{name}_20261005_190617.cfg').read_text()
            snapshot = m.capture(config, name, plans[name])
            self.assertTrue(all(value is None for value in snapshot['metrics'].values()))
            self.assertTrue(all(value is None for value in snapshot['costs'].values()))
            self.assertNotIn('password', json.dumps(snapshot))
            commands = m.preference_commands(snapshot, False)
            self.assertIn('no set metric', commands)
            self.assertIn('no ospfv3 cost', commands)
            self.assertNotIn('Management0', '\n'.join(m.interface_commands(snapshot, True)))
            dependency = m.dhcp_dependency(config)
            self.assertEqual(dependency['enabled'], name == 'R2')
            if name == 'R2':
                self.assertEqual(len(dependency['scopes']), 5)
                self.assertEqual(dependency['interfaces'], ['Ethernet2'])
                self.assertTrue(all('1 days' in lease for lease in dependency['leases']))

    def test_explicit_metrics_costs_and_multiple_permits_restore_exactly(self):
        config = (ROOT/'golden_configs/R2/R2_20261005_190617.cfg').read_text()
        config = config.replace('route-map RIP-TO-OSPF permit 10\n', 'route-map RIP-TO-OSPF permit 10\n   set metric 42\n')
        config = config.replace('interface Ethernet1\n', 'interface Ethernet1\n   ipv6 ospf cost 27\n')
        config = config.replace('\nend', '\nroute-map RIP-TO-OSPF permit 20\n   set metric 33\n!\nend')
        _, _, plans = m.discover(self.app.inventory, 'R2')
        snapshot = m.capture(config, 'R2', plans['R2'])
        commands = m.preference_commands(snapshot, False)
        for text in ('set metric 42', 'set metric 33', 'ipv6 ospf cost 27', 'route-map RIP-TO-OSPF permit 20'):
            self.assertIn(text, commands)

    def test_traffic_gate_per_interface_relative_and_alternate_activity(self):
        baseline = rates(2000, 2000)
        self.assertTrue(m.traffic_gate(rates(), baseline, 'R2', 'R1'))
        self.assertFalse(m.traffic_gate(rates(600), baseline, 'R2', 'R1'))
        self.assertFalse(m.traffic_gate(rates(0, 0), baseline, 'R2', 'R1'))
        self.assertFalse(m.traffic_gate(rates(100, 100), baseline, 'R2', 'R1'))
        self.assertTrue(m.traffic_gate(rates(0), rates(0), 'R2', 'R1'))

    def test_invalid_or_missing_individual_traffic_samples_rejected(self):
        for field, value in (('rx_bps', -5), ('tx_bps', float('nan')), ('rx_bps', float('inf')), ('tx_bps', True)):
            for invalid_baseline in (False, True):
                current, baseline = rates(), rates(2000)
                (baseline if invalid_baseline else current)['R2']['Ethernet1'][field] = value
                with self.assertRaises(m.MaintenanceError):
                    m.traffic_gate(current, baseline, 'R2', 'R1')
        current = rates()
        del current['R2']['Ethernet2']
        with self.assertRaises(m.MaintenanceError):
            m.traffic_gate(current, rates(2000), 'R2', 'R1')

    def test_ipv6_fib_parser_keeps_all_ecmp_hops(self):
        routes = m.ipv6_routes('VRF: default\nO3 2001:db8:10::/64 [110/30]\n via fe80::1, Ethernet3\n via fe80::2, Ethernet2\n')
        self.assertEqual({v['interface'] for v in routes['2001:db8:10::/64']}, {'Ethernet2', 'Ethernet3'})
        with self.assertRaises(m.MaintenanceError):
            m.ipv6_routes('unrecognized schema')

    def test_documented_ipv6_neighbor_text_full_only(self):
        text = 'Routing Process "ospf 10":\nNeighbor 22.22.22.22 priority is 1, state is Full\n  In area 0.0.0.0 interface et2\nNeighbor 44.44.44.44 priority is 1, state is Init\n  In area 0.0.0.0 interface et1\n'
        self.assertEqual(m.ospfv3_full_neighbors(text), {('Ethernet2', '22.22.22.22')})

    def test_ipv4_fib_requires_exact_installed_forwarding_route(self):
        response = {'vrfs': {'default': {'routes': {'0.0.0.0/0': {'vias': [{'interface': 'Ethernet1'}]}}}}}
        with self.assertRaises(m.MaintenanceError):
            m.route_vias(response, '203.0.113.0/30')
        response['vrfs']['default']['routes']['203.0.113.0/30'] = {'routeAction': 'drop', 'vias': [{'interface': 'Null0'}]}
        with self.assertRaises(m.MaintenanceError):
            m.route_vias(response, '203.0.113.0/30')

    def test_real_routing_gate_rejects_ecmp_target_and_missing_ipv6_prefix(self):
        _, _, plans = m.discover(self.app.inventory, 'R2')
        corrupt = None
        lookup = {peer['device']: (owner, role, peer['interface'])
                  for owner in m.ROUTERS for role, peer in plans[owner]['peers'].items()}

        def show(name, command, text=False):
            owner, role, target_link = lookup[name]
            output = target_link if owner == 'R1' else ('Vlan900' if role == 'access' else 'Ethernet2')
            if command == 'show ip route':
                routes = {prefix: {'routeAction': 'forward', 'vias': [{'interface': output, 'nexthopAddr': '192.0.2.1'}]}
                          for prefix in m.PREFIXES[role] if ':' not in prefix}
                if corrupt == 'ecmp' and name == plans['R2']['peers']['core']['device']:
                    routes['10.0.10.0/24']['vias'].append({'interface': target_link, 'nexthopAddr': '192.0.2.2'})
                return {'vrfs': {'default': {'routes': routes}}}
            prefixes = [prefix for prefix in m.PREFIXES[role] if ':' in prefix]
            if corrupt == 'missing' and name == plans['R2']['peers']['core']['device']:
                prefixes = prefixes[1:]
            return '\n'.join(f'O3 {prefix} [110/20]\n via fe80::1, {output}' for prefix in prefixes)

        with patch.object(self.api, 'show', side_effect=show):
            evidence = m.Maintenance.routing(self.app, 'R2', 'R1', plans, avoid=True)
            self.assertEqual(len(evidence), 14)
            for corrupt in ('ecmp', 'missing'):
                with self.subTest(corrupt=corrupt), self.assertRaises(m.MaintenanceError):
                    m.Maintenance.routing(self.app, 'R2', 'R1', plans, avoid=True)

    def test_real_drain_gate_requires_three_new_windows_in_each_direction(self):
        data = self.app.precheck('R2')
        self.app.args.settle = 20
        def frame(start):
            data = rates()
            for ports in data.values():
                for value in ports.values():
                    value.update(start=start, end=start+10, rx_start=start, rx_end=start+10, tx_start=start, tx_end=start+10)
            return data
        frames = [frame(start) for start in (20, 30, 40)]
        with patch.object(self.app, 'rates', side_effect=frames), patch.object(m.time, 'monotonic', side_effect=[0, 1, 2, 3]):
            m.Maintenance.drain_evidence(self.app, data, applied_at=0)
        frames = [frame(start) for start in (20, 30, 40)]
        for value in frames[1:]:
            value['R2']['Ethernet1'].update(tx_start=20, tx_end=30)
        with patch.object(self.app, 'rates', side_effect=frames), \
             patch.object(m.time, 'monotonic', side_effect=[0, 1, 2, 3, 241]), self.assertRaises(m.MaintenanceError):
            m.Maintenance.drain_evidence(self.app, data, applied_at=0)
        self.assertEqual(self.api.calls, [])

    def test_state_machine_requires_drained_before_out_of_service(self):
        with self.assertRaises(m.MaintenanceError):
            m.transition('draining', 'out_of_service')
        self.assertEqual(m.transition('draining', 'drained'), 'drained')
        for state in ('precheck', 'draining', 'drained', 'out_of_service', 'error'):
            self.assertEqual(m.transition(state, 'rollback'), 'rollback')

    def test_dry_run_never_changes_devices_nsot_or_runtime(self):
        self.app.args.dry_run = True
        self.app.drain('R2')
        self.assertEqual(self.api.calls, [])
        self.assertEqual(self.path.read_bytes(), self.source)
        self.assertEqual(list(self.runtime.iterdir()), [])
        self.assertFalse((self.root/'golden').exists())

    def test_drain_and_restore_follow_stages_and_preserve_original(self):
        self.app.drain('R2')
        self.assertEqual(self.app.state('R2'), 'out_of_service')
        self.assertEqual(self.api.states['R2']['admin'], {'Ethernet1': 'down', 'Ethernet2': 'down'})
        self.assertEqual(self.api.states['R1'], original())
        self.assertNotIn('shutdown', self.api.calls[0][1])
        self.app.restore('R2')
        self.assertEqual(self.api.states['R2'], original())
        self.assertEqual(self.app.state('R2'), 'in_service')
        before = len(self.api.calls)
        self.app.restore('R2')
        self.assertEqual(len(self.api.calls), before)
        self.assertTrue(list(self.runtime.glob('*_completed.json')))

    def test_failed_drain_evidence_rolls_back_without_any_shutdown(self):
        with patch.object(self.app, 'drain_evidence', side_effect=m.MaintenanceError('fixture failed proof')):
            with self.assertRaises(m.MaintenanceError):
                self.app.drain('R2')
        self.assertEqual(self.api.states['R2'], original())
        self.assertFalse(any('shutdown' in commands for _, commands in self.api.calls))
        self.assertEqual(self.app.state('R2'), 'in_service')

    def test_customer_outage_before_isolation_rolls_back(self):
        self.app.acknowledge = lambda _: 'OUTAGE'
        with self.assertRaises(m.MaintenanceError):
            self.app.drain('R2')
        self.assertEqual(self.api.states['R2'], original())
        self.assertFalse(any('shutdown' in commands for _, commands in self.api.calls))

    def test_partial_shutdown_failure_recovers_links_before_preferences(self):
        self.api.fail_on_shutdown = True
        with self.assertRaises(m.MaintenanceError):
            self.app.drain('R2')
        self.assertEqual(self.api.states['R2'], original())
        commands = [commands for _, commands in self.api.calls]
        isolation = next(i for i, value in enumerate(commands) if 'shutdown' in value)
        recovery = next(i for i, value in enumerate(commands) if 'no shutdown' in value)
        normal = next(i for i, value in enumerate(commands) if 'no set metric' in value)
        self.assertLess(isolation, recovery)
        self.assertLess(recovery, normal)
        self.assertIn('set metric 50000', commands[recovery-1])

    def test_nsot_failure_after_isolation_does_not_block_connectivity_recovery(self):
        real_update = m.update_nsot
        failed = False
        def update(path, target, state):
            nonlocal failed
            if state == 'out_of_service':
                failed = True
            if failed and state != 'in_service':
                raise OSError('fixture disk error')
            return real_update(path, target, state)
        with patch.object(m, 'update_nsot', side_effect=update), self.assertRaises(m.MaintenanceError):
            self.app.drain('R2')
        self.assertEqual(self.api.states['R2'], original())

    def test_alternate_out_of_service_blocks_second_drain(self):
        self.app.drain('R2')
        count = len(self.api.calls)
        with self.assertRaises(m.MaintenanceError):
            self.app.drain('R1')
        self.assertEqual(len(self.api.calls), count)
        self.assertEqual(self.api.states['R1'], original())

    def test_challenge_requires_exact_ack_and_never_auto_restores_r1(self):
        calls, acknowledgements = [], iter(['yes', 'part1-passed', 'PART1-PASSED'])
        self.app.acknowledge = lambda _: next(acknowledgements)
        with patch.object(self.app, 'drain', side_effect=lambda n: calls.append(('drain', n))), \
             patch.object(self.app, 'restore', side_effect=lambda n: calls.append(('restore', n))):
            self.app.challenge()
        self.assertEqual(calls, [('drain', 'R2'), ('restore', 'R2'), ('drain', 'R1')])
        self.assertIn('PART 2 READY', self.output.getvalue())

    def test_checkpoint_interrupt_never_automatically_restores(self):
        self.app.acknowledge = MagicMock(side_effect=KeyboardInterrupt)
        with patch.object(self.app, 'drain') as drain, patch.object(self.app, 'restore') as restore:
            with self.assertRaises(KeyboardInterrupt):
                self.app.challenge()
            drain.assert_called_once_with('R2')
            restore.assert_not_called()

    def test_eapi_has_no_raw_cli_escape_or_management_shutdown(self):
        api = object.__new__(m.EAPI)
        api.call = MagicMock()
        for commands in (['interface Management0', 'shutdown'], ['reload'], ['interface Ethernet1\nshutdown']):
            with self.assertRaises(m.MaintenanceError):
                api.configure('R2', commands)
        with self.assertRaises(m.MaintenanceError):
            api.configure('R2', ['route-map OSPF-TO-RIP permit 10', 'set metric 16', 'exit'])
        with self.assertRaises(m.MaintenanceError):
            api.configure('S1', ['interface Ethernet1', 'shutdown'])
        api.call.assert_not_called()

    def test_explicit_recovery_does_not_require_influx_token(self):
        with patch.object(m, 'INVENTORY', self.path), patch.object(m, 'RUNTIME', self.runtime), \
             patch.object(m, 'EAPI'), patch.object(m, 'Telemetry', side_effect=AssertionError('Recovery must not need telemetry')), \
             patch.object(m, 'Maintenance') as app:
            self.assertEqual(m.main(['rollback', 'R2']), 0)
            app.return_value.restore.assert_called_once_with('R2', rollback=True, emergency=True)

    def test_failed_readonly_cli_precheck_creates_no_runtime(self):
        with patch.dict('os.environ', {}, clear=True), patch.object(m, 'INVENTORY', self.path), \
             patch.object(m, 'RUNTIME', self.root/'must-not-exist'):
            self.assertEqual(m.main(['drain', 'R2', '--dry-run']), 1)
        self.assertFalse((self.root/'must-not-exist').exists())
        self.assertEqual(self.path.read_bytes(), self.source)


class EAPITransportTests(unittest.TestCase):
    """Exercise the real adapter; replace credentials and the HTTP boundary only."""

    def setUp(self):
        for target in ('socket.socket.connect', 'socket.create_connection',
                       'subprocess.run', 'subprocess.Popen',
                       'security.credential_provider._read_token',
                       'security.credential_provider._run_op'):
            self.enterContext(patch(target, side_effect=AssertionError('External operation forbidden')))
        self.password = 'fixture-private-password'
        self.credentials = self.enterContext(patch.object(
            m.credential_provider, 'get_credentials', return_value=('fixture-user', self.password)))
        self.inventory = {'devices': {'R1': {'management': {'ipv4': '192.0.2.10'}}}}
        self.api = m.EAPI(self.inventory, timeout=7)
        self.http = self.enterContext(patch.object(
            self.api.opener, 'open', side_effect=AssertionError('Unscripted HTTP request')))

    def response(self, result):
        self.http.side_effect = None
        self.body = io.BytesIO(json.dumps(result).encode())
        self.http.return_value = self.body

    def test_call_sends_exact_jsonrpc_request_and_closes_response(self):
        self.response({'jsonrpc': '2.0', 'id': 1, 'result': [{}, {'version': '4.31.2F'}]})
        self.assertEqual(self.api.call('R1', ['enable', 'show version']), [{}, {'version': '4.31.2F'}])
        request = self.http.call_args.args[0]
        self.assertEqual(request.full_url, 'https://192.0.2.10/command-api')
        self.assertEqual(request.get_method(), 'POST')
        self.assertEqual(request.get_header('Content-type'), 'application/json')
        self.assertEqual(request.get_header('Authorization'),
                         'Basic Zml4dHVyZS11c2VyOmZpeHR1cmUtcHJpdmF0ZS1wYXNzd29yZA==')
        self.assertEqual(json.loads(request.data), {
            'jsonrpc': '2.0', 'id': 1, 'method': 'runCmds',
            'params': {'version': 1, 'cmds': ['enable', 'show version'], 'format': 'json'}})
        self.assertEqual(self.http.call_args.kwargs, {'timeout': 7})
        self.assertTrue(self.body.closed)

    def test_malformed_incomplete_and_api_error_replies_are_sanitized(self):
        replies = [b'{invalid JSON ' + self.password.encode(), b'null', b'[]',
                   json.dumps({'error': {'message': self.password}, 'result': [{}, {}]}).encode(),
                   b'{}', b'{"result": {}}', b'{"result": [{}]}', b'{"result": [{}, {}, {}]}']
        for reply in replies:
            with self.subTest(reply=reply[:20]):
                self.http.side_effect = None
                body = io.BytesIO(reply)
                self.http.return_value = body
                with self.assertRaises(m.MaintenanceError) as caught:
                    self.api.call('R1', ['enable', 'show version'])
                self.assertNotIn(self.password, str(caught.exception))
                self.assertNotIn(self.api.authorization, str(caught.exception))
                self.assertTrue(body.closed)

    def test_http_authentication_timeout_and_connection_errors_are_sanitized(self):
        errors = [urllib.error.HTTPError('https://192.0.2.10/command-api', code, self.password, {}, None)
                  for code in (401, 403)]
        errors += [TimeoutError(self.password), ConnectionError(self.password),
                   urllib.error.URLError(self.password), m.ssl.SSLError(self.password)]
        for error in errors:
            with self.subTest(error=type(error).__name__, code=getattr(error, 'code', None)):
                self.http.reset_mock()
                self.http.side_effect = error
                with self.assertRaises(m.MaintenanceError) as caught:
                    self.api.show('R1', 'show version')
                self.assertIn('device outcome must be verified', str(caught.exception))
                self.assertNotIn(self.password, str(caught.exception))
                self.http.assert_called_once()

    def test_show_preserves_encoding_and_validates_reply_shape(self):
        for text, answer in ((False, {'version': '4.31.2F'}), (True, {'output': 'hostname R1\nend\n'})):
            with self.subTest(text=text):
                self.response({'result': [{}, answer]})
                self.assertEqual(self.api.show('R1', 'show version', text=text),
                                 answer['output'] if text else answer)
                params = json.loads(self.http.call_args.args[0].data)['params']
                self.assertEqual(params, {'version': 1, 'cmds': ['enable', 'show version'],
                                          'format': 'text' if text else 'json'})
        for text, answer in ((False, None), (False, []), (True, {}), (True, {'output': 7})):
            with self.subTest(text=text, answer=answer):
                self.response({'result': [{}, answer]})
                with self.assertRaisesRegex(m.MaintenanceError, 'unexpected'):
                    self.api.show('R1', 'show version', text=text)

    def test_show_rejects_non_readonly_or_compound_commands_before_http(self):
        for command in ('configure terminal', 'reload', 'show version; reload',
                        'show version\nreload', 'show version\rreload', 'show running-config | include secret'):
            with self.subTest(command=command), self.assertRaises(m.MaintenanceError):
                self.api.show('R1', command)
        self.http.assert_not_called()

    def test_configure_sends_validated_commands_in_explicit_context_order(self):
        commands = ['route-map RIP-TO-OSPF permit 10', 'set metric 50000', 'exit',
                    'route-map OSPF-TO-RIP permit 20', 'set metric 10', 'exit',
                    'interface Ethernet1', 'ospfv3 cost 60000', 'shutdown', 'exit',
                    'interface Ethernet2', 'no shutdown', 'no ospfv3 cost', 'exit']
        self.response({'result': [{} for _ in range(len(commands) + 3)]})
        self.assertIsNone(self.api.configure('R1', commands))
        self.assertEqual(json.loads(self.http.call_args.args[0].data)['params'], {
            'version': 1, 'cmds': ['enable', 'configure terminal', *commands, 'end'], 'format': 'text'})
        self.http.assert_called_once()

    def test_configure_rejects_wrong_context_and_unsafe_metric_or_cost_before_http(self):
        invalid = [[], ['shutdown'], ['set metric 10'],
                   ['interface Ethernet1', 'set metric 10'],
                   ['route-map RIP-TO-OSPF permit 10', 'shutdown'],
                   ['interface Ethernet1', 'exit', 'shutdown'],
                   ['route-map RIP-TO-OSPF permit 10', 'set metric 16777215'],
                   ['route-map OSPF-TO-RIP permit 10', 'set metric 16'],
                   ['interface Ethernet1', 'ipv6 ospf cost 0'],
                   ['interface Ethernet2', 'ospfv3 cost 65536']]
        for commands in invalid:
            with self.subTest(commands=commands), self.assertRaises(m.MaintenanceError):
                self.api.configure('R1', commands)
        self.http.assert_not_called()

    def test_constructor_blocks_redirects_and_environment_proxy_handlers(self):
        with patch.dict('os.environ', {'https_proxy': 'http://192.0.2.99:8888'}, clear=True):
            api = m.EAPI(self.inventory)
        redirect = next(handler for handler in api.opener.handlers
                        if isinstance(handler, m.urllib.request.HTTPRedirectHandler))
        request = m.urllib.request.Request('https://192.0.2.10/command-api')
        self.assertIsNone(redirect.redirect_request(request, None, 302, 'Found', {},
                                                    'https://192.0.2.99/collect'))
        proxies = [handler.proxies for handler in api.opener.handlers
                   if isinstance(handler, m.urllib.request.ProxyHandler)]
        self.assertTrue(all(not mapping for mapping in proxies))
        self.http.assert_not_called()

    def test_credential_lookup_failure_stops_before_http_client_construction(self):
        self.credentials.side_effect = RuntimeError(self.password)
        with patch.object(m.urllib.request, 'build_opener') as build:
            with self.assertRaisesRegex(m.MaintenanceError, 'credentials unavailable') as caught:
                m.EAPI(self.inventory)
        self.assertNotIn(self.password, str(caught.exception))
        build.assert_not_called()
        self.http.assert_not_called()


class RecoveryStorageTests(unittest.TestCase):
    """Real journal/state methods use only an isolated temporary NSOT and runtime."""

    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(prefix='maintenance-state-tests-')))
        self.path = self.root / 'devices.yml'
        self.path.write_text('devices: {}\n')
        self.runtime = self.root / 'runtime'
        self.runtime.mkdir()
        for target in ('socket.socket.connect', 'socket.create_connection', 'subprocess.run',
                       'subprocess.Popen', 'security.credential_provider.get_credentials',
                       'security.credential_provider._read_token', 'security.credential_provider._run_op',
                       'challenge_maintenance.storage.ConnectHandler'):
            self.enterContext(patch(target, side_effect=AssertionError('External operation forbidden')))
        self.output = self.enterContext(patch('sys.stdout', new_callable=io.StringIO))
        self.api = MagicMock()
        self.api.show.side_effect = AssertionError('Journal checks must not query devices')
        self.api.configure.side_effect = AssertionError('Journal checks must not configure devices')
        self.app = m.Maintenance(self.path, self.runtime, api=self.api)

    def journal(self, **changes):
        data = {'ticket': 'RCN-5840', 'target': 'R1', 'alternate': 'R2', 'state': 'precheck'}
        data.update(changes)
        (self.runtime / 'R1.json').write_text(json.dumps(data))
        return data

    def test_record_rejects_corrupt_wrong_ticket_target_and_state_without_device_access(self):
        malformed = ['{broken', 'null', '[]', '{}',
                     json.dumps({'ticket': 'other-ticket', 'target': 'R1', 'state': 'precheck'}),
                     json.dumps({'ticket': 'RCN-5840', 'target': 'R2', 'state': 'precheck'}),
                     json.dumps({'ticket': 'RCN-5840', 'target': 'R1', 'state': 'unrecognized'}),
                     json.dumps({'ticket': 'RCN-5840', 'target': 'R1', 'state': []})]
        for content in malformed:
            with self.subTest(content=content):
                (self.runtime / 'R1.json').write_text(content)
                with self.assertRaises(m.MaintenanceError):
                    self.app.record('R1')
        self.api.show.assert_not_called()
        self.api.configure.assert_not_called()

    def test_record_refuses_symlinks_and_target_path_traversal(self):
        external = self.root / 'unrelated.json'
        external.write_text('{"private": "fixture-only"}')
        (self.runtime / 'R1.json').symlink_to(external)
        with self.assertRaisesRegex(m.MaintenanceError, 'Unsafe rollback file'):
            self.app.record('R1')
        for target in ('../unrelated', 'R3', 'R1/../R2'):
            with self.subTest(target=target), self.assertRaisesRegex(m.MaintenanceError, 'Invalid rollback target'):
                self.app.record(target)
        self.assertEqual(external.read_text(), '{"private": "fixture-only"}')
        self.api.configure.assert_not_called()

    def test_state_uses_active_journal_and_does_not_hide_nsot_outage_after_completed_journal(self):
        self.path.write_text(yaml.safe_dump({'devices': {}, 'maintenance': {
            'ticket': 'RCN-5840', 'routers': {'R1': {'state': 'out_of_service'}}}}))
        self.journal(state='draining')
        self.assertEqual(self.app.state('R1'), 'draining')
        self.journal(state='in_service')
        self.assertEqual(self.app.state('R1'), 'out_of_service')
        self.path.write_text(yaml.safe_dump({'devices': {}, 'maintenance': {
            'ticket': 'another-ticket', 'routers': {}}}))
        with self.assertRaisesRegex(m.MaintenanceError, 'Different NSOT maintenance ticket'):
            self.app.state('R1')
        self.api.configure.assert_not_called()

    def test_save_failure_preserves_last_durable_record_and_does_not_report_success(self):
        data = self.journal()
        before = (self.runtime / 'R1.json').read_bytes()
        with patch.object(m.storage, '_atomic_write', side_effect=OSError('fixture disk unavailable')) as write:
            with self.assertRaises(OSError):
                self.app.save(data, 'draining')
        write.assert_called_once()
        self.assertEqual((self.runtime / 'R1.json').read_bytes(), before)
        self.assertEqual(self.app.record('R1')['state'], 'precheck')
        self.assertNotIn('[STAGE]', self.output.getvalue())
        self.api.configure.assert_not_called()


class RecoveryDecisionTests(unittest.TestCase):
    """Real restore/drain decisions; device replies and persistence failures are synthetic."""

    def setUp(self):
        import test_maintenance_decisions as fixtures
        self.fixtures = fixtures
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path, self.runtime = self.root / 'devices.yml', self.root / 'runtime'
        self.runtime.mkdir()
        self.inventory = fixtures.synthetic_inventory()
        self.path.write_text(yaml.safe_dump(self.inventory))
        for boundary in ('socket.socket.connect', 'socket.socket.connect_ex', 'socket.create_connection',
                         'subprocess.Popen', 'urllib.request.OpenerDirector.open',
                         'Functions.maintenance_telemetry.InfluxDBClient'):
            self.enterContext(patch(boundary, side_effect=AssertionError('External I/O forbidden')))
        self.enterContext(patch.object(m.credential_provider, 'get_credentials', side_effect=AssertionError('Credentials forbidden')))
        self.enterContext(patch.object(m.storage, 'ConnectHandler', side_effect=AssertionError('SSH forbidden')))
        self.backup = self.enterContext(patch.object(m.storage, '_save_prechange_backup', side_effect=AssertionError('Real backups forbidden')))
        self.update = self.enterContext(patch.object(m, 'update_nsot'))
        self.output = self.enterContext(patch('sys.stdout', new_callable=io.StringIO))
        self.api = fixtures.DecisionFixtureAPI(self.inventory)
        self.sleep = MagicMock()
        args = m.defaults()
        args.timeout, args.interval = 10, 2
        self.app = m.Maintenance(self.path, self.runtime, api=self.api, args=args, sleep=self.sleep)
        fixtures.attach_test_telemetry(self.app, self)
        _, _, self.plans = m.discover(self.inventory, 'R2')
        self.original = self.app.live('R2', self.plans['R2'])
        self.api.show.reset_mock()
        self.journal = {
            'ticket': 'RCN-5840', 'target': 'R2', 'alternate': 'R1', 'state': 'out_of_service',
            'change_id': 'fixture-recovery', 'management_ip': '192.0.2.12',
            'production_ports': ['Ethernet1', 'Ethernet2'], 'original': deepcopy(self.original),
            'preference_attempted': True, 'isolation_attempted': True,
        }
        self.write_journal()

    def write_journal(self):
        (self.runtime / 'R2.json').write_text(json.dumps(self.journal))

    def drained_config(self, isolated=True):
        config = self.fixtures.running_config('R2')
        config = config.replace('route-map RIP-TO-OSPF permit 10\n', 'route-map RIP-TO-OSPF permit 10\n   set metric 50000\n')
        config = config.replace('route-map OSPF-TO-RIP permit 10\n', 'route-map OSPF-TO-RIP permit 10\n   set metric 10\n')
        for port in ('Ethernet1', 'Ethernet2'):
            config = config.replace(f'interface {port}\n', f'interface {port}\n   ospfv3 cost 60000\n')
        return config.replace('   no shutdown\n', '   shutdown\n') if isolated else config

    def assert_no_changes(self):
        self.api.configure.assert_not_called()
        self.update.assert_not_called()
        self.backup.assert_not_called()
        self.assertEqual(json.loads((self.runtime / 'R2.json').read_text()), self.journal)
        self.assertEqual(sorted(p.name for p in self.runtime.iterdir()), ['R2.json'])

    def test_restore_rejects_changed_captured_identity_before_device_reads(self):
        for field, value in [('management_ip', '192.0.2.99'), ('production_ports', ['Ethernet1', 'Ethernet9'])]:
            with self.subTest(field=field):
                previous = self.journal[field]
                self.journal[field] = value
                self.write_journal()
                with self.assertRaisesRegex(m.MaintenanceError, 'identity changed'):
                    self.app.restore('R2')
                self.api.show.assert_not_called()
                self.assert_no_changes()
                self.journal[field] = previous

    def test_restore_rejects_unrelated_drift_and_invalid_original_admin_state(self):
        self.api.replies['R2', 'show running-config'] = self.drained_config().replace('description core', 'description operator change')
        with self.assertRaisesRegex(m.MaintenanceError, 'Unrelated live configuration changed'):
            self.app.restore('R2')
        self.assert_no_changes()
        self.api.replies['R2', 'show running-config'] = self.drained_config()
        self.journal['original']['admin']['Ethernet1'] = 'down'
        self.write_journal()
        with self.assertRaisesRegex(m.MaintenanceError, 'originally be up'):
            self.app.restore('R2')
        self.assert_no_changes()

    def test_restore_preserves_edits_that_precede_first_recorded_device_write(self):
        self.journal.update(state='precheck', preference_attempted=False, isolation_attempted=False)
        self.write_journal()
        self.api.replies['R2', 'show running-config'] = self.fixtures.running_config('R2').replace(
            'interface Ethernet1\n', 'interface Ethernet1\n   ospfv3 cost 27\n')
        with self.assertRaisesRegex(m.MaintenanceError, 'before our first device write'):
            self.app.restore('R2', rollback=True)
        self.assert_no_changes()

    def test_restore_blocks_when_alternate_has_active_maintenance(self):
        (self.runtime / 'R1.json').write_text(json.dumps({
            'ticket': 'RCN-5840', 'target': 'R1', 'state': 'draining'}))
        with self.assertRaisesRegex(m.MaintenanceError, 'R1 is not IN_SERVICE'):
            self.app.restore('R2')
        self.api.show.assert_not_called()
        self.api.configure.assert_not_called()
        self.update.assert_not_called()
        self.assertEqual(self.app.record('R2'), self.journal)

    def test_normal_restore_persistence_failure_prevents_device_and_nsot_changes(self):
        self.api.replies['R2', 'show running-config'] = self.drained_config()
        with patch.object(m.storage, '_atomic_write', side_effect=OSError('fixture disk unavailable')) as write:
            with self.assertRaises(OSError):
                self.app.restore('R2')
        write.assert_called_once()
        self.assert_no_changes()

    def test_failed_or_interrupted_restore_retains_snapshot_and_records_error(self):
        self.api.replies['R2', 'show running-config'] = self.drained_config()
        for failure in (m.MaintenanceError('fixture apply failure'), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__):
                self.write_journal()
                self.api.configure.reset_mock()
                self.update.reset_mock()

                def fail_apply(name, commands):
                    self.assertEqual(name, 'R2')
                    self.assertEqual(self.app.record('R2')['state'], 'restoring')
                    self.assertNotIn('shutdown', commands)
                    raise failure

                self.api.configure.side_effect = fail_apply
                with self.assertRaises(type(failure)):
                    self.app.restore('R2')
                self.api.configure.assert_called_once()
                record = self.app.record('R2')
                self.assertEqual(record['state'], 'error')
                self.assertEqual(record['original'], self.original)
                self.assertEqual(record['management_ip'], '192.0.2.12')
                self.update.assert_called_once_with(self.path, 'R2', 'restoring')
                self.assertFalse((self.runtime / 'R2_fixture-recovery_completed.json').exists())

    def test_restore_stops_before_original_preferences_when_real_health_never_recovers(self):
        self.api.replies['R2', 'show running-config'] = self.drained_config()
        self.api.replies['R2', 'show interfaces description']['interfaceDescriptions']['Ethernet1']['lineProtocolStatus'] = 'down'

        def apply(name, commands):
            self.assertEqual(name, 'R2')
            self.assertNotIn('shutdown', commands)
            self.assertNotIn('no set metric', commands)
            if 'no shutdown' in commands:
                self.api.replies[name, 'show running-config'] = self.drained_config(isolated=False)

        self.api.configure.side_effect = apply
        with patch.object(m.time, 'monotonic', side_effect=[0, 0, 11]):
            with self.assertRaisesRegex(m.MaintenanceError, 'recovery timed out'):
                self.app.restore('R2')
        self.assertEqual(self.api.configure.call_count, 2)
        self.assertEqual(self.api.configure.call_args_list[1].args, ('R2', [
            'interface Ethernet1', 'no shutdown', 'exit', 'interface Ethernet2', 'no shutdown', 'exit']))
        self.sleep.assert_called_once_with(2)
        self.assertEqual(self.app.record('R2')['state'], 'error')
        self.assertEqual(self.app.record('R2')['original'], self.original)
        self.update.assert_called_once_with(self.path, 'R2', 'restoring')

    def test_already_restored_record_requires_real_health_and_performs_no_writes(self):
        self.journal['state'] = 'in_service'
        self.write_journal()
        self.app.restore('R2')
        for name in ('R1', 'R2'):
            self.api.show.assert_any_call(name, 'show ip ospf neighbor')
        self.assert_no_changes()
        self.api.replies['R2', 'show interfaces description']['interfaceDescriptions']['Management0']['interfaceStatus'] = 'down'
        with self.assertRaisesRegex(m.MaintenanceError, 'Management0 is not operationally up'):
            self.app.restore('R2')
        self.assert_no_changes()

    def test_drain_cannot_apply_preferences_without_first_durable_journal(self):
        (self.runtime / 'R2.json').unlink()
        backup_path = self.root / 'temporary-backup.cfg'

        def temporary_backup(metadata, config):
            self.assertEqual(metadata['device'], 'R2')
            backup_path.write_text(config)
            return backup_path

        self.backup.side_effect = temporary_backup
        with patch.object(m.storage, '_atomic_write', side_effect=OSError('fixture disk unavailable')) as write:
            with self.assertRaises(OSError):
                self.app.drain('R2')
        self.backup.assert_called_once()
        write.assert_called_once()
        record = json.loads(write.call_args.args[1])
        self.assertEqual(record['state'], 'precheck')
        self.assertFalse(record['preference_attempted'])
        self.assertFalse(record['isolation_attempted'])
        self.assertEqual(record['original'], self.original)
        self.assertEqual(list(self.runtime.iterdir()), [])
        self.api.configure.assert_not_called()
        self.update.assert_not_called()
        self.assertNotIn('rollback metadata durable', self.output.getvalue())


if __name__ == '__main__':
    unittest.main()

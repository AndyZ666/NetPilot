"""Synthetic EOS/ICMP observations through real status and GUI decision logic.

No device, Docker, Vault or monitoring access: every external boundary is
mocked. OSPF 2-WAY is reviewable without assuming DR/BDR topology (RFC 2328).
BGP zero received prefixes is not evidence of an unestablished session.
"""

import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import yaml

from Functions import check_network_status as status
import health_checks as health
from test_health_checks import SOURCE, DESTINATION, OSPF, BGP, NA_CPU, PASSWORD


class OfflineStatusFixture(unittest.TestCase):
    def setUp(self):
        self.output = self.enterContext(patch('sys.stdout', new_callable=io.StringIO))
        for target in ('socket.create_connection', 'socket.socket.connect', 'subprocess.Popen',
                       'security.credential_provider.get_credentials', 'health_checks.ConnectHandler',
                       'health_checks.InfluxDBClient'):
            self.enterContext(patch(target, side_effect=AssertionError('External operation forbidden')))
        self.process = self.enterContext(patch('subprocess.run', side_effect=AssertionError('Unexpected subprocess command')))
        self.enterContext(patch.object(status, 'RESULTS', []))


class ReadOnlyCliTests(OfflineStatusFixture):
    def test_cli_runs_allowlisted_command_and_returns_actual_stdout(self):
        self.process.side_effect = None
        self.process.return_value = subprocess.CompletedProcess([], 0, 'fixture route output\n', '')
        self.assertEqual(status.cli('clab-fixture-R1', 'show ip route'), 'fixture route output\n')
        self.assertEqual(self.process.call_args.args[0],
                         ['docker', 'exec', 'clab-fixture-R1', 'Cli', '-p', '15', '-c', 'show ip route'])
        self.assertFalse(self.process.call_args.kwargs.get('shell', False))

    def test_cli_rejects_configuration_and_multicommand_input_before_execution(self):
        for command in ('configure terminal', 'shutdown', 'show ip route\nshutdown',
                        'show ip route; reload', 'ping 192.0.2.1\rend'):
            with self.subTest(command=command), self.assertRaises(ValueError):
                status.cli('clab-fixture-R1', command)
        self.process.assert_not_called()

    def test_cli_rejects_exit_failure_and_eos_error_output_without_echoing_response(self):
        for code, output in ((1, 'private-marker'), (0, '   % Invalid input private-marker')):
            with self.subTest(code=code):
                self.process.side_effect = None
                self.process.return_value = subprocess.CompletedProcess([], code, output, 'private-marker')
                with self.assertRaises(RuntimeError) as caught:
                    status.cli('clab-fixture-R1', 'show ip route')
                self.assertNotIn('private-marker', str(caught.exception))

    def test_cli_timeout_propagates_to_callers_that_classify_it(self):
        self.process.side_effect = subprocess.TimeoutExpired(['docker'], 20)
        with self.assertRaises(subprocess.TimeoutExpired):
            status.cli('clab-fixture-R1', 'show ip route')


class RoutingObservationTests(OfflineStatusFixture):
    def routing(self, protocols, neighbors='', routes=''):
        responses = {'show ip ospf neighbor': neighbors, 'show ipv6 ospf neighbor': neighbors,
                     'show ip rip neighbors': neighbors, 'show ip route ospf': routes,
                     'show ipv6 route ospf': routes, 'show ip route rip': routes}
        self.process.side_effect = lambda command, **kwargs: subprocess.CompletedProcess(command, 0, responses[command[-1]], '')
        status.RESULTS.clear()
        status.routing_checks({'name': 'LAB'}, {'container': 'clab-fixture-LAB', 'protocols': protocols})
        return {item: (state, detail) for section, item, state, detail in status.RESULTS}

    def test_ospf_full_neighbors_and_valid_routes_are_counted_by_address_family(self):
        rows = self.routing({'router ospf 10': []}, OSPF,
                            'O 203.0.113.0/30 via 198.51.100.2\nO 203.0.113.0/30 via 198.51.100.6\n'
                            'O 10.0.0.0/24 via 198.51.100.2\nO 2001:db8::/64 via fe80::2\ninvalid 300.0.0.0/24')
        self.assertEqual(rows['LAB / OSPFv2'], ('PASS', '1/1 observed neighbors FULL'))
        self.assertEqual(rows['LAB / OSPFv2 routes'], ('PASS', '2 learned prefixes in routing table'))

    def test_ospf_init_down_and_two_way_require_review_not_assumed_full_adjacency(self):
        for neighbor_state in ('INIT', 'DOWN', '2-WAY/DROTHER'):
            with self.subTest(state=neighbor_state):
                rows = self.routing({'router ospf 10': []}, OSPF.replace('FULL/DR', neighbor_state))
                self.assertEqual(rows['LAB / OSPFv2'][0], 'WARN')
                self.assertIn('0/1 observed neighbors FULL', rows['LAB / OSPFv2'][1])
                self.assertIn('2-WAY may be normal on broadcast networks', rows['LAB / OSPFv2'][1])

    def test_absent_protocols_are_na_and_disabled_process_is_fail_without_commands(self):
        rows = self.routing({})
        self.assertEqual({item: state for item, (state, detail) in rows.items()},
                         {'LAB / OSPFv2': 'N/A', 'LAB / RIP': 'N/A', 'LAB / OSPFv3': 'N/A'})
        self.process.assert_not_called()
        rows = self.routing({'router ospf 10': ['shutdown']})
        self.assertEqual(rows['LAB / OSPFv2'][0], 'FAIL')
        self.process.assert_not_called()

    def test_missing_malformed_neighbors_and_absent_routes_do_not_report_pass(self):
        for neighbors in ('', 'Neighbor ID State\nmalformed output'):
            with self.subTest(neighbors=neighbors):
                rows = self.routing({'router ospf 10': []}, neighbors, 'No OSPF routes installed')
                self.assertEqual(rows['LAB / OSPFv2'][0], 'WARN')
                self.assertEqual(rows['LAB / OSPFv2 routes'][0], 'WARN')

    def test_ospfv3_uses_ipv6_route_table_and_rip_is_not_an_ospf_adjacency(self):
        rows = self.routing({'ipv6 router ospf 10': []},
                            'Neighbor 3.3.3.3 FULL Ethernet1 fe80::3',
                            'O 2001:db8:10::/64 via fe80::3\nO 10.0.0.0/24 via 192.0.2.3')
        self.assertEqual(rows['LAB / OSPFv3'][0], 'PASS')
        self.assertEqual(rows['LAB / OSPFv3 routes'], ('PASS', '1 learned prefixes in routing table'))
        rows = self.routing({'router rip': []}, '192.0.2.2 Ethernet1 00:00:05', 'R 10.0.0.0/24 via 192.0.2.2')
        self.assertEqual(rows['LAB / RIP'], ('INFO', '1 RIP neighbor records (RIP has no FULL adjacency)'))

    def test_command_failure_and_timeout_are_reported_as_routing_errors(self):
        for error in (subprocess.TimeoutExpired(['docker'], 20), OSError('synthetic unavailable')):
            with self.subTest(error=type(error).__name__):
                self.process.side_effect = error
                status.RESULTS.clear()
                status.routing_checks({'name': 'LAB'}, {'container': 'clab-fixture-LAB', 'protocols': {'router ospf 10': []}})
                row = next(row for row in status.RESULTS if row[1] == 'LAB / OSPFv2')
                self.assertEqual(row[2], 'ERROR')


class NetworkStatusWorkflowTests(OfflineStatusFixture):
    def setUp(self):
        super().setUp()
        temporary = tempfile.TemporaryDirectory(prefix='netpilot-network-status-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / 'Functions').mkdir()
        self.inventory = self.root / 'Functions' / 'devices.json'
        self.inventory.write_text(json.dumps({'devices': [
            {'name': 'R1', 'ip': '192.0.2.1', 'type': 'router'},
            {'name': 'R2', 'ip': '192.0.2.2', 'type': 'router'}]}))
        (self.root / 'nettopo.clab.yml').write_text(yaml.safe_dump({'name': 'fixture', 'topology': {
            'nodes': {'R1': {}, 'R2': {}}, 'links': [{'endpoints': ['R1:eth1', 'R2:eth1']}]}}))
        self.enterContext(patch.object(status, 'ROOT', self.root))
        self.ping_output = '2 packets transmitted, 2 received, 0% packet loss'
        self.management_code = 0
        self.device_error = None
        self.commands = []
        self.process.side_effect = self.respond

    def respond(self, command, **kwargs):
        self.commands.append(command)
        if command[0] == 'ping':
            return subprocess.CompletedProcess(command, self.management_code, b'', b'')
        if command[:2] != ['docker', 'exec']:
            raise AssertionError('Unexpected external command')
        device = command[2].rsplit('-', 1)[1]
        action = command[-1]
        if device == 'R2' and self.device_error:
            raise self.device_error
        if action == 'show running-config':
            host = '1' if device == 'R1' else '2'
            output = f'hostname {device}\ninterface Ethernet1\n   ip address 198.51.100.{host}/30\n   ipv6 address 2001:db8::{host}/64\n!\n'
        elif action == 'show interfaces | json':
            output = json.dumps({'interfaces': {'Ethernet1': {'lineProtocolStatus': 'up'}}})
        elif action.startswith('ping '):
            output = self.ping_output
        else:
            raise AssertionError('Unexpected device command: ' + action)
        return subprocess.CompletedProcess(command, 0, output, '')

    def test_workflow_selects_both_families_and_uses_two_sourced_probes_per_pair(self):
        self.assertEqual(status.main(), 0)
        expected = {
            'ping 198.51.100.2 source 198.51.100.1 repeat 2 timeout 1',
            'ping 198.51.100.1 source 198.51.100.2 repeat 2 timeout 1',
            'ping 2001:db8::2 source 2001:db8::1 repeat 2 timeout 1',
            'ping 2001:db8::1 source 2001:db8::2 repeat 2 timeout 1',
        }
        self.assertEqual({cmd[-1] for cmd in self.commands if cmd[0] == 'docker' and cmd[-1].startswith('ping ')}, expected)
        self.assertEqual([cmd for cmd in self.commands if cmd[0] == 'ping'],
                         [['ping', '-n', '-c', '2', '-W', '1', '192.0.2.1'], ['ping', '-n', '-c', '2', '-W', '1', '192.0.2.2']])
        self.assertEqual([row[2] for row in status.RESULTS if row[0] == 'connectivity'], ['PASS'] * 4)
        self.assertIn('FINAL RESULT: PASS', self.output.getvalue())

    def test_packet_loss_and_unrecognized_output_change_overall_result(self):
        for output, expected in (('2 transmitted, 1 received, 50% packet loss', 'FAIL'),
                                 ('2 transmitted, 0 received, 100% packet loss', 'FAIL'), ('', 'ERROR'),
                                 ('malformed ping output', 'ERROR')):
            with self.subTest(output=output):
                self.ping_output = output
                self.assertEqual(status.main(), 1)
                self.assertEqual([row[2] for row in status.RESULTS if row[0] == 'connectivity'], [expected] * 4)

    def test_unreachable_management_is_failure_even_when_docker_cli_still_works(self):
        self.management_code = 1
        self.assertEqual(status.main(), 1)
        self.assertEqual([row[2] for row in status.RESULTS if row[0] == 'management'], ['FAIL', 'FAIL'])
        self.assertEqual([row[2] for row in status.RESULTS if row[0] == 'access'], ['PASS', 'PASS'])

    def test_device_access_error_or_timeout_cannot_be_reported_healthy(self):
        for error in (RuntimeError('fixture CLI unavailable'), subprocess.TimeoutExpired(['docker'], 20)):
            with self.subTest(error=type(error).__name__):
                self.device_error = error
                self.assertEqual(status.main(), 1)
                rows = {(section, item): state for section, item, state, detail in status.RESULTS}
                self.assertEqual(rows['access', 'R2'], 'ERROR')
                self.assertEqual(rows['routing', 'R2'], 'ERROR')
                self.assertEqual(rows['links', 'R2:Ethernet1'], 'ERROR')

    def test_missing_or_malformed_inventory_stops_before_device_operations(self):
        for text in ('{bad json', '{"devices": []}'):
            with self.subTest(text=text):
                self.inventory.write_text(text)
                self.assertEqual(status.main(), 1)
                self.process.assert_not_called()
        self.inventory.unlink()
        self.assertEqual(status.main(), 1)
        self.process.assert_not_called()


class GuiProtocolAndPingTests(OfflineStatusFixture):
    def setUp(self):
        super().setUp()
        self.credentials = self.enterContext(patch.object(health.credential_provider, 'get_credentials', return_value=('fixture-user', PASSWORD)))
        self.cpu = self.enterContext(patch.object(health, 'cpu_sample', return_value=NA_CPU.copy()))
        self.connection = Mock()
        self.connection.check_enable_mode.return_value = True
        self.connect = self.enterContext(patch.object(health, 'ConnectHandler', return_value=self.connection))
        self.ping = 'ping 192.0.2.2 source 192.0.2.1 repeat 3 timeout 1'
        self.responses = {'show running-config | include ^router': 'router ospf 10\nrouter bgp 64512',
                          'show ip ospf neighbor': OSPF, 'show ip bgp summary': BGP,
                          'show ip route': 'O 203.0.113.0/30 [110/20] via 198.51.100.2, Ethernet1\n'
                                           'S 10.0.0.0/24 [1/0] via 198.51.100.6, Ethernet2',
                          self.ping: '3 packets transmitted, 3 received, 0% packet loss'}
        self.connection.send_command.side_effect = self.read

    def read(self, command, **kwargs):
        output = self.responses[command]
        if isinstance(output, Exception):
            raise output
        return output

    def test_real_bgp_parser_keeps_session_state_independent_of_received_prefix_count(self):
        header = 'BGP summary information for VRF default\nRouter identifier 192.0.2.1, local AS number 64512\n'
        for state, expected in (('0', 'Established'), ('12', 'Established'), ('Idle', 'Idle'), ('Active', 'Active')):
            with self.subTest(state=state):
                text = header + 'Neighbor V AS MsgRcvd MsgSent InQ OutQ Up/Down State/PfxRcd\n' + '192.0.2.5 4 64513 100 90 0 0 01:02:03 ' + state
                result = health._neighbors('BGP', text)
                self.assertEqual(result['rows'], [{'ip': '192.0.2.5', 'state': expected}])
        text = header + 'Neighbor V AS MsgRcvd MsgSent InQ OutQ Up/Down State PfxRcd PfxAcc\n' + ' 192.0.2.5 4 64513 100 90 0 0 01:02:03 Established 0 0'
        self.assertEqual(health._neighbors('BGP', text)['rows'], [{'ip': '192.0.2.5', 'state': 'Established'}])

    def test_real_ospf_parser_preserves_full_init_down_and_two_way_states(self):
        for state in ('FULL/DR', 'INIT', 'DOWN', '2-WAY/DROTHER'):
            with self.subTest(state=state):
                self.assertEqual(health._neighbors('OSPFv2', OSPF.replace('FULL/DR', state))['rows'],
                                 [{'ip': '10.1.33.2', 'state': state}])

    def test_missing_malformed_and_header_only_neighbor_output_cannot_invent_neighbors(self):
        for protocol in ('BGP', 'OSPFv2'):
            for output, expected in (('', 'No Neighbors'), ('unparseable fixture', 'Review Output'),
                                     ('Neighbor ID State Interface\n', 'Review Output')):
                with self.subTest(protocol=protocol, output=output):
                    result = health._neighbors(protocol, output)
                    self.assertEqual(result['rows'], [])
                    self.assertEqual(result['status'], expected)

    def test_route_table_preserves_prefix_protocol_and_next_hop_associations(self):
        result = health.run(SOURCE, DESTINATION)
        self.assertEqual(result['routes']['status'], 'OK')
        self.assertEqual(result['routes']['output'],
                         'O 203.0.113.0/30 [110/20] via 198.51.100.2, Ethernet1\nS 10.0.0.0/24 [1/0] via 198.51.100.6, Ethernet2')
        self.connection.send_config_set.assert_not_called()
        self.connection.save_config.assert_not_called()

    def test_ping_loss_boundaries_and_missing_output_are_not_fabricated(self):
        for output, expected, loss in (('3 transmitted, 3 received, 0% packet loss', 'PASS', 0),
                                      ('3 transmitted, 0 received, 100% packet loss', 'FAIL', 100),
                                      ('3 transmitted, 2 received, 33.3333% packet loss', 'FAIL', 33.3333),
                                      ('', 'Unavailable', None), ('unrecognized', 'Unavailable', None)):
            with self.subTest(output=output):
                self.responses[self.ping] = output
                result = health.run(SOURCE, DESTINATION)['connectivity']
                self.assertEqual((result['status'], result['packet_loss']), (expected, loss))

    def test_invalid_packet_loss_values_are_unavailable_not_valid_measurements(self):
        accepted = []
        for output in ('101% packet loss', '-1% packet loss', 'nan% packet loss', '0..0% packet loss'):
            self.responses[self.ping] = output
            result = health.run(SOURCE, DESTINATION)['connectivity']
            if result['status'] != 'Unavailable' or result['packet_loss'] is not None:
                accepted.append((output, result['status'], result['packet_loss']))
        self.assertEqual(accepted, [])

    def test_command_timeouts_leave_other_panels_available_and_disconnect(self):
        self.responses[self.ping] = health.NetmikoTimeoutException(PASSWORD)
        self.responses['show ip bgp summary'] = health.NetmikoTimeoutException(PASSWORD)
        result = health.run(SOURCE, DESTINATION)
        self.assertEqual(result['connectivity']['status'], 'Unavailable')
        self.assertEqual(result['neighbors'][1]['status'], 'Unavailable')
        self.assertEqual(result['routes']['status'], 'OK')
        self.assertNotIn(PASSWORD, json.dumps(result))
        self.connection.disconnect.assert_called_once_with()

    def test_invalid_source_or_destination_is_rejected_before_any_external_lookup(self):
        for source, destination in ((dict(SOURCE, management_ip='300.1.2.3'), DESTINATION),
                                    (SOURCE, dict(DESTINATION, management_ip='192.0.2.2; reload')),
                                    (SOURCE, dict(DESTINATION, management_ip='2001:db8::2'))):
            with self.subTest(source=source, destination=destination), self.assertRaises(ValueError):
                health.run(source, destination)
        self.credentials.assert_not_called()
        self.cpu.assert_not_called()
        self.connect.assert_not_called()


if __name__ == '__main__':
    unittest.main()

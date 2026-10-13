"""Offline GUI checks: fake SSH/Influx only, no devices, Vault, or services."""
from datetime import datetime, timedelta, timezone
import io
import json
import logging
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import app as gui
import health_checks as health


PASSWORD = 'fixture-password-that-must-not-leak'
SOURCE = {'hostname': 'R1', 'vendor': 'Arista', 'management_ip': '192.0.2.1'}
DESTINATION = {'hostname': 'R2', 'vendor': 'Arista', 'management_ip': '192.0.2.2'}
NA_CPU = {'status': 'N/A', 'percent': None, 'timestamp': None, 'message': 'No fresh telemetry.'}
OSPF = 'Neighbor ID Instance VRF Pri State Dead Time Address Interface\n3.3.3.3 10 default 1 FULL/DR 00:00:37 10.1.33.2 Ethernet1'
BGP = 'BGP summary information for VRF default\nRouter identifier 1.1.1.1, local AS number 65001\nNeighbor V AS MsgRcvd MsgSent InQ OutQ Up/Down State/PfxRcd\n192.0.2.5 4 65002 100 90 0 0 01:02:03 7'


class DeviceChecks(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch('socket.create_connection', side_effect=AssertionError('No network')))
        self.credentials = self.enterContext(patch.object(health.credential_provider, 'get_credentials', return_value=('admin', PASSWORD)))
        self.cpu = self.enterContext(patch.object(health, 'cpu_sample', return_value=dict(NA_CPU)))
        self.connection = Mock()
        self.connection.check_enable_mode.side_effect = [False, True]
        self.connect = self.enterContext(patch.object(health, 'ConnectHandler', return_value=self.connection))
        self.outputs = {
            'show running-config | include ^router': 'router ospf 10\nrouter bgp 65001',
            'show ip ospf neighbor': OSPF,
            'show ip bgp summary': BGP,
            'show ip route': 'O 203.0.113.0/30 [110/20] via 10.1.33.2, Ethernet1',
            'ping 192.0.2.2 source 192.0.2.1 repeat 3 timeout 1': '3 packets transmitted, 3 received, 0% packet loss',
        }
        self.connection.send_command.side_effect = lambda command, **kwargs: self.outputs[command]

    def test_success_uses_vault_enable_and_only_readonly_inventory_commands(self):
        result = health.run(SOURCE, DESTINATION)
        self.assertIsNone(result['error'])
        self.assertEqual(result['neighbors'][0]['rows'], [{'ip': '10.1.33.2', 'state': 'FULL/DR'}])
        self.assertEqual(result['neighbors'][1]['rows'], [{'ip': '192.0.2.5', 'state': 'Established'}])
        self.assertEqual(result['connectivity']['status'], 'PASS')
        self.assertEqual(result['connectivity']['packet_loss'], 0)
        self.credentials.assert_called_once_with()
        self.connection.enable.assert_called_once_with()
        self.connection.disconnect.assert_called_once_with()
        self.assertEqual([call.args[0] for call in self.connection.send_command.call_args_list], list(self.outputs))
        self.connection.send_config_set.assert_not_called()
        self.connection.save_config.assert_not_called()
        self.assertEqual(self.connect.call_args.kwargs['host'], SOURCE['management_ip'])
        self.assertFalse(self.connect.call_args.kwargs['ssh_strict'])
        self.assertIsNone(self.connect.call_args.kwargs['session_log'])
        self.assertNotIn(PASSWORD, json.dumps(result))

    def test_unconfigured_protocols_are_not_failures_and_ping_loss_is_reported(self):
        self.outputs['show running-config | include ^router'] = 'router rip'
        self.outputs['ping 192.0.2.2 source 192.0.2.1 repeat 3 timeout 1'] = '3 packets transmitted, 2 received, 33.3333% packet loss'
        result = health.run(SOURCE, DESTINATION)
        self.assertEqual([p['status'] for p in result['neighbors']], ['Not Configured'] * 2)
        self.assertEqual(result['routes']['status'], 'OK')
        self.assertEqual(result['connectivity']['status'], 'FAIL')
        self.assertAlmostEqual(result['connectivity']['packet_loss'], 33.3333)
        self.assertNotIn('show ip ospf neighbor', [c.args[0] for c in self.connection.send_command.call_args_list])

    def test_unreachable_and_authentication_errors_are_sanitized(self):
        for exception, message in ((health.NetmikoTimeoutException, 'unreachable'),
                                   (health.NetmikoAuthenticationException, 'authentication failed')):
            with self.subTest(exception=exception):
                self.connect.side_effect = exception(PASSWORD)
                result = health.run(SOURCE, DESTINATION)
                self.assertIn(message, result['error'])
                self.assertNotIn(PASSWORD, json.dumps(result))
                self.assertEqual(result['cpu']['status'], 'N/A')
                self.assertEqual(result['connectivity']['status'], 'Unavailable')
        self.connection.send_command.assert_not_called()

    def test_command_failures_do_not_hide_other_panels_and_secrets_are_not_logged(self):
        self.outputs['show ip ospf neighbor'] = '% Error ' + PASSWORD
        self.outputs['show ip route'] = ('O 203.0.113.0/30 via 192.0.2.3\n' * 200) + PASSWORD
        self.outputs['show ip bgp summary'] = 'password ' + PASSWORD
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger('netmiko')
        logger.addHandler(handler)
        self.addCleanup(logger.removeHandler, handler)
        previous = logging.root.manager.disable
        def connect(**kwargs):
            logger.error(PASSWORD)
            return self.connection
        self.connect.side_effect = connect
        result = health.run(SOURCE, DESTINATION)
        self.assertEqual(result['neighbors'][0]['status'], 'Unavailable')
        self.assertIn('Output limited', result['routes']['output'])
        self.assertEqual(result['connectivity']['status'], 'PASS')
        self.assertNotIn(PASSWORD, json.dumps(result) + stream.getvalue())
        self.assertEqual(logging.root.manager.disable, previous)


class CpuChecks(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.config = Path(temporary.name) / 'telegraf.conf'
        self.config.write_text('''[[inputs.gnmi]]
[[inputs.gnmi.subscription]]
name = "fixture_cpu"
path = "/components/component/cpu/utilization/state/instant"
[[outputs.influxdb_v2]]
urls = ["http://127.0.0.1:8086"]
organization = "fixture_org"
bucket = "fixture_bucket"
''')
        self.enterContext(patch.dict(health.os.environ, {'INFLUX_TOKEN': 'fixture-token'}, clear=True))
        self.enterContext(patch('socket.create_connection', side_effect=AssertionError('No network')))
        self.client = Mock()
        self.factory = self.enterContext(patch.object(health, 'InfluxDBClient', return_value=self.client))
        self.row = {'source': '192.0.2.1', '_measurement': 'fixture_cpu', '_field': 'instant',
                    '_value': 12.5, '_time': datetime.now(timezone.utc)}

    def query(self, rows):
        self.client.query_api.return_value.query.return_value = [SimpleNamespace(records=[SimpleNamespace(values=row) for row in rows])]
        return health.cpu_sample('192.0.2.1', self.config)

    def test_actual_fresh_value_timestamp_and_configured_measurement(self):
        result = self.query([self.row])
        self.assertEqual(result['percent'], 12.5)
        self.assertEqual(result['timestamp'], self.row['_time'].isoformat())
        query = self.client.query_api.return_value.query.call_args.kwargs['query']
        for value in ('fixture_cpu', 'fixture_bucket', 'instant', 'source', '192.0.2.1', 'range(start: -2m)'):
            self.assertIn(value, query)
        self.assertNotIn('fixture-token', query + json.dumps(result))
        self.client.close.assert_called_once_with()

    def test_missing_stale_wrong_device_invalid_and_unavailable_cpu_show_na(self):
        rows = [[], [dict(self.row, _time=self.row['_time'] - timedelta(minutes=3))],
                [dict(self.row, source='192.0.2.99')], [dict(self.row, _value=float('nan'))],
                [dict(self.row, _value=101)], [dict(self.row, _field='unknown')]]
        for candidate in rows:
            with self.subTest(candidate=candidate):
                result = self.query(candidate)
                self.assertEqual(result['status'], 'N/A')
                self.assertIsNone(result['percent'])
        self.factory.side_effect = RuntimeError('fixture-token')
        result = health.cpu_sample('192.0.2.1', self.config)
        self.assertEqual(result['status'], 'N/A')
        self.assertNotIn('fixture-token', json.dumps(result))


class HealthPages(unittest.TestCase):
    def setUp(self):
        gui.app.config.update(TESTING=True)
        self.client = gui.app.test_client()
        data = {'devices': {d['hostname']: {'hostname': d['hostname'], 'vendor': d['vendor'], 'platform': 'cEOSLab',
                            'management': {'ipv4': d['management_ip']}} for d in (SOURCE, DESTINATION)}}
        self.enterContext(patch.object(gui, 'load_inventory', return_value=data))
        self.run = self.enterContext(patch.object(health, 'run'))
        self.enterContext(patch('socket.create_connection', side_effect=AssertionError('No network')))
        self.enterContext(patch.object(health.credential_provider, 'get_credentials', side_effect=AssertionError('No Vault')))
        with self.client.session_transaction() as session:
            session['health_check_csrf'] = 'fixture-csrf'

    def test_get_pages_show_inventory_four_panels_and_placeholder_without_network(self):
        response = self.client.get('/health-check')
        self.assertEqual(response.status_code, 200)
        for value in ('R1', 'R2', 'Neighborships', 'Route Table', 'CPU', 'IP Connectivity', 'Management Network Connectivity'):
            self.assertIn(value, response.text)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        response = self.client.get('/troubleshooting')
        self.assertEqual(response.status_code, 200)
        self.assertIn('Coming Soon — Automated Network Troubleshooting', response.text)
        self.assertIn('href="/health-check"', response.text)
        self.assertIn('href="/monitoring"', response.text)
        self.run.assert_not_called()

    def test_unknown_destinations_and_missing_csrf_cannot_execute(self):
        for data in ({'device': 'R1', 'destination': 'R2'},
                     {'device': 'R1', 'destination': '192.0.2.2; reload', 'csrf_token': 'fixture-csrf'},
                     {'device': 'UNKNOWN', 'destination': 'R2', 'csrf_token': 'fixture-csrf'}):
            response = self.client.post('/health-check', data=data)
            self.assertEqual(response.status_code, 400)
        self.run.assert_not_called()

    def test_post_uses_inventory_records_and_escapes_command_details(self):
        self.run.return_value = {'device': 'R1', 'management_ip': '192.0.2.1', 'checked_at': '2026-10-13T12:00:00+00:00',
            'neighbors': [], 'routes': {'status': 'OK', 'output': '<script>unsafe</script>', 'message': 'IPv4 routes'},
            'cpu': NA_CPU, 'connectivity': {'status': 'PASS', 'source': 'R1', 'destination': 'R2',
            'destination_ip': '192.0.2.2', 'packet_loss': 0, 'output': '0% packet loss', 'message': ''}}
        response = self.client.post('/health-check', data={'device': 'R1', 'destination': 'R2', 'csrf_token': 'fixture-csrf'})
        self.assertEqual(response.status_code, 200)
        self.assertIn('&lt;script&gt;unsafe&lt;/script&gt;', response.text)
        self.assertNotIn('<script>unsafe</script>', response.text)
        self.assertEqual(self.run.call_args.args[1]['management_ip'], DESTINATION['management_ip'])

    def test_unavailable_inventory_and_backend_errors_are_sanitized(self):
        with patch.object(gui, 'load_inventory', return_value=None):
            response = self.client.get('/health-check')
        self.assertEqual(response.status_code, 200)
        self.assertIn('No devices are available', response.text)
        self.run.side_effect = RuntimeError(PASSWORD)
        response = self.client.post('/health-check', data={'device': 'R1', 'destination': 'R2', 'csrf_token': 'fixture-csrf'})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(PASSWORD, response.text)


if __name__ == '__main__':
    unittest.main()

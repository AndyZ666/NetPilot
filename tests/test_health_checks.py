"""Offline GUI checks: fake SSH/Influx only, no devices, Vault, or services."""
from datetime import datetime, timedelta, timezone
import io
import json
import logging
from pathlib import Path
import tempfile
import threading
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


class CpuClock(datetime):
    """A datetime subclass keeps the production timestamp type check real."""
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 10, 19, 12, tzinfo=timezone.utc).astimezone(tz)


def forbid_external_operations(test):
    # Each fixture replaces only the boundaries it intentionally exercises below.
    for target in ('socket.socket.connect', 'subprocess.Popen',
                   'health_checks.ConnectHandler', 'health_checks.InfluxDBClient',
                   'health_checks.credential_provider.get_credentials',
                   'health_checks.read_influx_file', 'security.telegraf_launcher.read_influx_file'):
        test.enterContext(patch(target, side_effect=AssertionError('External operation forbidden')))


class DeviceChecks(unittest.TestCase):
    def setUp(self):
        forbid_external_operations(self)
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

    def test_busy_check_does_not_touch_dependencies_or_release_another_checks_lock(self):
        lock = threading.Lock()
        lock.acquire()
        self.addCleanup(lock.release)
        with patch.object(health, '_LOCK', lock):
            result = health.run(SOURCE, DESTINATION)
        self.assertIn('already running', result['error'])
        self.assertTrue(lock.locked())
        self.assertEqual(result['connectivity']['status'], 'Unavailable')
        self.cpu.assert_not_called()
        self.credentials.assert_not_called()
        self.connect.assert_not_called()

    def test_privilege_denial_blocks_commands_disconnects_and_releases_lock(self):
        self.connection.check_enable_mode.side_effect = [False, False]
        lock = threading.Lock()
        with patch.object(health, '_LOCK', lock):
            result = health.run(SOURCE, DESTINATION)
        self.assertEqual(result['error'], 'The device did not permit privileged read access.')
        self.assertEqual(result['routes']['status'], 'Unavailable')
        self.assertEqual(result['connectivity']['status'], 'Unavailable')
        self.connection.enable.assert_called_once_with()
        self.connection.send_command.assert_not_called()
        self.connection.disconnect.assert_called_once_with()
        self.assertFalse(lock.locked())

    def test_unavailable_routing_headers_still_attempt_neighbor_observation(self):
        # A rejected header command is not evidence that either protocol is absent.
        self.outputs['show running-config | include ^router'] = '% Invalid input'
        result = health.run(SOURCE, DESTINATION)
        self.assertEqual([item['status'] for item in result['neighbors']], ['OK', 'OK'])
        self.assertEqual(result['neighbors'][0]['rows'][0]['state'], 'FULL/DR')
        self.assertEqual(result['neighbors'][1]['rows'][0]['state'], 'Established')
        self.assertEqual(result['connectivity']['status'], 'PASS')

    def test_nontext_command_responses_cannot_become_healthy_panels(self):
        self.connection.check_enable_mode.side_effect = None
        self.connection.check_enable_mode.return_value = True
        for response in (None, {'output': 'synthetic'}, b'fixture output'):
            with self.subTest(response=response):
                self.outputs['show ip ospf neighbor'] = response
                self.outputs['show ip route'] = response
                result = health.run(SOURCE, DESTINATION)
                self.assertEqual(result['neighbors'][0]['status'], 'Unavailable')
                self.assertEqual(result['neighbors'][0]['rows'], [])
                self.assertEqual(result['routes']['status'], 'Unavailable')
                self.assertEqual(result['routes']['output'], '')
                self.assertEqual(result['neighbors'][1]['status'], 'OK')
                self.assertEqual(result['connectivity']['status'], 'PASS')
        self.assertEqual(self.connection.disconnect.call_count, 3)
        self.connection.send_config_set.assert_not_called()
        self.connection.save_config.assert_not_called()

    def test_credential_failure_is_sanitized_and_does_not_block_a_later_check(self):
        self.credentials.side_effect = RuntimeError(PASSWORD)
        lock = threading.Lock()
        with patch.object(health, '_LOCK', lock):
            failed = health.run(SOURCE, DESTINATION)
            self.assertFalse(lock.locked())
            self.connect.assert_not_called()
            self.assertEqual(failed['error'], 'Device credentials are unavailable from 1Password.')
            self.assertNotIn(PASSWORD, json.dumps(failed))
            self.credentials.side_effect = None
            recovered = health.run(SOURCE, DESTINATION)
        self.assertIsNone(recovered['error'])
        self.assertEqual(recovered['connectivity']['status'], 'PASS')
        self.assertFalse(lock.locked())

    def test_disconnect_error_preserves_completed_report_and_releases_lock(self):
        self.connection.disconnect.side_effect = RuntimeError(PASSWORD)
        lock = threading.Lock()
        with patch.object(health, '_LOCK', lock):
            result = health.run(SOURCE, DESTINATION)
        self.assertIsNone(result['error'])
        self.assertEqual(result['routes']['status'], 'OK')
        self.assertEqual(result['connectivity']['status'], 'PASS')
        self.assertNotIn(PASSWORD, json.dumps(result))
        self.assertFalse(lock.locked())


class ReadOnlyOutputChecks(unittest.TestCase):
    def test_output_line_and_character_limits_preserve_exact_boundaries(self):
        limit_message = '\n[Output limited to 120 lines / 12,000 characters]'
        lines = '\n'.join('route-' + str(index) for index in range(120))
        self.assertEqual(health._output(lines, ''), lines)
        self.assertEqual(health._output(lines + '\nexcluded-route', ''), lines + limit_message)
        self.assertEqual(health._output('x' * 12000, ''), 'x' * 12000)
        self.assertEqual(health._output('x' * 12000 + 'y', ''), 'x' * 12000 + limit_message)

    def test_output_redacts_credentials_and_sensitive_lines_without_hiding_routes(self):
        sensitive = ['password fixture', 'SECRET fixture', 'token fixture',
                     'snmp-server community fixture', 'private-key fixture', '$6$fixture']
        output = '\n'.join(['route via 192.0.2.1', 'echo ' + PASSWORD] + sensitive)
        self.assertEqual(health._output(output, PASSWORD), '\n'.join(
            ['route via 192.0.2.1', 'echo [redacted]'] + ['[sensitive output hidden]'] * 6))

    def test_read_rejects_multiline_eos_errors_and_keeps_ordinary_empty_output(self):
        connection = Mock()
        connection.send_command.return_value = 'route header\n   % Error ' + PASSWORD
        with self.assertRaises(ValueError) as caught:
            health._read(connection, 'show ip route', PASSWORD)
        self.assertNotIn(PASSWORD, str(caught.exception))
        connection.send_command.return_value = ''
        self.assertEqual(health._read(connection, 'show ip route', PASSWORD), '')
        connection.send_command.assert_called_with('show ip route', read_timeout=12)


class CpuChecks(unittest.TestCase):
    def setUp(self):
        forbid_external_operations(self)
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

    def test_zero_and_full_utilization_are_available_measurements(self):
        for percent in (0, 100):
            with self.subTest(percent=percent):
                result = self.query([dict(self.row, _value=percent)])
                self.assertEqual(result['status'], 'Available')
                self.assertEqual(result['percent'], percent)
                self.assertEqual(result['timestamp'], self.row['_time'].isoformat())

    def test_cpu_requires_finite_numeric_percent_not_boolean_text_or_missing_values(self):
        candidates = [dict(self.row, _value=value)
                      for value in (True, False, '12.5', None, -1, float('inf'), float('-inf'))]
        candidates.append({key: value for key, value in self.row.items() if key != '_value'})
        for row in candidates:
            with self.subTest(value=row.get('_value', 'missing')):
                result = self.query([row])
                self.assertEqual(result['status'], 'N/A')
                self.assertIsNone(result['percent'])
                self.assertIsNone(result['timestamp'])

    def test_freshness_and_clock_skew_limits_are_inclusive_only_at_the_boundary(self):
        # The GUI promises the last two minutes and permits two seconds of clock skew.
        now = CpuClock.now(timezone.utc)
        with patch.object(health, 'datetime', CpuClock):
            for age, expected in ((120, 'Available'), (120.000001, 'N/A'),
                                  (-2, 'Available'), (-2.000001, 'N/A')):
                with self.subTest(age=age):
                    result = self.query([dict(self.row, _time=now - timedelta(seconds=age))])
                    self.assertEqual(result['status'], expected)
                    self.assertEqual(result['percent'], 12.5 if expected == 'Available' else None)

    def test_timestamps_require_timezone_and_normalize_an_equivalent_offset_to_utc(self):
        now = CpuClock.now(timezone.utc)
        with patch.object(health, 'datetime', CpuClock):
            for stamp in (None, '2026-10-19T12:00:00Z', now.replace(tzinfo=None)):
                with self.subTest(stamp=stamp):
                    result = self.query([dict(self.row, _time=stamp)])
                    self.assertEqual(result['status'], 'N/A')
                    self.assertIsNone(result['timestamp'])
            offset_stamp = now.astimezone(timezone(timedelta(hours=-6)))
            result = self.query([dict(self.row, _time=offset_stamp)])
        self.assertEqual(result['status'], 'Available')
        self.assertEqual(result['timestamp'], '2026-10-19T12:00:00+00:00')

    def test_multiple_cpu_series_report_explicit_mean_and_oldest_utc_timestamp(self):
        now = CpuClock.now(timezone.utc)
        rows = [dict(self.row, _value=10, _time=now),
                dict(self.row, _value=30, _time=now - timedelta(seconds=90))]
        self.client.query_api.return_value.query.return_value = [
            SimpleNamespace(records=[SimpleNamespace(values=row)]) for row in rows]
        with patch.object(health, 'datetime', CpuClock):
            result = health.cpu_sample('192.0.2.1', self.config)
        self.assertEqual(result, {'status': 'Available', 'percent': 20.0,
            'timestamp': '2026-10-19T11:58:30+00:00',
            'message': 'Mean of 2 reported CPU series; oldest sample time shown.'})

    def test_invalid_series_cannot_be_hidden_by_another_valid_cpu_sample(self):
        now = CpuClock.now(timezone.utc)
        good = dict(self.row, _time=now)
        with patch.object(health, 'datetime', CpuClock):
            for bad in (dict(good, _time=now - timedelta(seconds=121)),
                        dict(good, _measurement='unrelated'), dict(good, _value='invalid')):
                with self.subTest(bad=bad):
                    result = self.query([good, bad])
                    self.assertEqual(result['status'], 'N/A')
                    self.assertIsNone(result['percent'])
                    self.assertIsNone(result['timestamp'])

    def test_malformed_or_ambiguous_config_stops_before_token_and_client_access(self):
        valid = self.config.read_text()
        duplicate_subscription = '''\n[[inputs.gnmi.subscription]]
name = "other_cpu"
path = "/components/component/cpu/utilization/state/instant"
'''
        duplicate_output = '''\n[[outputs.influxdb_v2]]
urls = ["http://192.0.2.99:8086"]
organization = "other_org"
bucket = "other_bucket"
'''
        configs = ('not valid TOML', '', 'inputs = "invalid"',
                   valid.replace('[[inputs.gnmi]]', '[inputs.gnmi]'),
                   valid.replace('/state/instant', '/state/unrelated'),
                   valid + duplicate_subscription, valid + duplicate_output)
        with patch.object(health, 'influx_token', side_effect=AssertionError('Token access forbidden')) as token:
            for config in configs:
                with self.subTest(config=config):
                    self.config.write_text(config)
                    result = health.cpu_sample('192.0.2.1', self.config)
                    self.assertEqual(result['status'], 'N/A')
                    self.assertIsNone(result['percent'])
        token.assert_not_called()
        self.factory.assert_not_called()

    def test_unsafe_influx_urls_are_rejected_before_token_and_client_access(self):
        urls = ('ftp://192.0.2.10', 'http:///missing-host',
                'http://user:private-marker@192.0.2.10:8086',
                'http://192.0.2.10:8086?token=private-marker', 'http://192.0.2.10:8086#private-marker')
        with patch.object(health, 'influx_token', side_effect=AssertionError('Token access forbidden')) as token:
            for url in urls:
                with self.subTest(url=url), patch.dict(health.os.environ, {'INFLUX_URL': url}):
                    result = health.cpu_sample('192.0.2.1', self.config)
                    self.assertEqual(result['status'], 'N/A')
                    self.assertNotIn('private-marker', json.dumps(result))
        token.assert_not_called()
        self.factory.assert_not_called()

    def test_query_exception_closes_client_and_suppresses_sensitive_details(self):
        self.client.query_api.return_value.query.side_effect = RuntimeError('fixture-token')
        result = health.cpu_sample('192.0.2.1', self.config)
        self.assertEqual(result['status'], 'N/A')
        self.assertIsNone(result['percent'])
        self.assertIn('could not be read', result['message'])
        self.assertNotIn('fixture-token', json.dumps(result))
        self.client.close.assert_called_once_with()

    def test_close_exception_does_not_discard_a_valid_cpu_measurement(self):
        self.client.close.side_effect = RuntimeError('fixture-token')
        result = self.query([self.row])
        self.assertEqual(result['status'], 'Available')
        self.assertEqual(result['percent'], 12.5)
        self.assertNotIn('fixture-token', json.dumps(result))
        self.client.close.assert_called_once_with()


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

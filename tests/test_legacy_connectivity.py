"""Offline Linux ping contracts; subprocess is always replaced before calls.

iputils ping(8): -W is seconds; without -w, some replies can yield exit 0
although packet loss is nonzero. This checker promises reachability, not a
loss percentage or an independently parsed stdout result.
"""

import io
import subprocess
import unittest
from unittest.mock import patch

from Functions import check_connectivity as connectivity


class LegacyConnectivityTests(unittest.TestCase):
    def setUp(self):
        self.output = self.enterContext(patch('sys.stdout', new_callable=io.StringIO))
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('No network')))
        self.enterContext(patch('subprocess.Popen', side_effect=AssertionError('No real subprocess')))
        self.run = self.enterContext(patch.object(connectivity.subprocess, 'run'))
        self.run.return_value = subprocess.CompletedProcess(['ping'], 0, b'', b'')

    def test_zero_partial_and_total_loss_follow_linux_reachability_exit_status(self):
        for received, code, expected in ((3, 0, ('OK', '')), (2, 0, ('OK', '')),
                                         (0, 1, ('FAILED', 'No response'))):
            with self.subTest(received=received):
                loss = {3: '0', 2: '33.3333', 0: '100'}[received]
                self.run.return_value = subprocess.CompletedProcess(['ping'], code,
                    f'3 packets transmitted, {received} received, {loss}% packet loss'.encode(), b'')
                self.assertEqual(connectivity.LabConnectivityChecker(packet_count=3).check_device('LAB', '192.0.2.7'), expected)

    def test_linux_timeout_argument_is_seconds_not_milliseconds(self):
        result = connectivity.LabConnectivityChecker(timeout=2, packet_count=3).check_device('LAB', '192.0.2.7')
        self.assertEqual(result, ('OK', ''))
        self.assertEqual(self.run.call_args.args[0], ['ping', '-c', '3', '-W', '2', '192.0.2.7'])

    def test_packet_count_is_preserved_and_external_budget_allows_probe_intervals(self):
        # Ten default-interval probes require at least nine seconds even when
        # every response is immediate; the Python watchdog must allow them.
        connectivity.LabConnectivityChecker(timeout=2, packet_count=10).check_device('LAB', '192.0.2.7')
        command = self.run.call_args.args[0]
        self.assertEqual(command[command.index('-c') + 1], '10')
        self.assertGreaterEqual(self.run.call_args.kwargs['timeout'], 9)

    def test_nonzero_exit_is_failure_even_if_stdout_contains_old_success_text(self):
        for code in (1, 2, -9):
            with self.subTest(code=code):
                self.run.return_value = subprocess.CompletedProcess(['ping'], code, b'0% packet loss', b'failure')
                self.assertEqual(connectivity.LabConnectivityChecker().check_device('LAB', '192.0.2.7'), ('FAILED', 'No response'))

    def test_missing_or_unrecognized_stdout_does_not_invent_a_loss_parser(self):
        for output in (b'', b'unrecognized localized output'):
            with self.subTest(output=output):
                self.run.return_value = subprocess.CompletedProcess(['ping'], 0, output, b'')
                self.assertEqual(connectivity.LabConnectivityChecker().check_device('LAB', '192.0.2.7'), ('OK', ''))

    def test_timeout_and_missing_binary_return_failure(self):
        for error, expected in ((subprocess.TimeoutExpired(['ping'], 3), 'Timeout'),
                                (FileNotFoundError('synthetic ping unavailable'), 'synthetic ping unavailable')):
            with self.subTest(error=type(error).__name__):
                self.run.side_effect = error
                self.assertEqual(connectivity.LabConnectivityChecker().check_device('LAB', '192.0.2.7'), ('FAILED', expected))

    def test_invalid_destination_reported_by_ping_is_failed_without_shell_execution(self):
        self.run.return_value = subprocess.CompletedProcess(['ping'], 2, b'', b'Name or service not known')
        result = connectivity.LabConnectivityChecker().check_device('LAB', 'not-an-address')
        self.assertEqual(result, ('FAILED', 'No response'))
        self.assertEqual(self.run.call_args.args[0][-1], 'not-an-address')
        self.assertFalse(self.run.call_args.kwargs.get('shell', False))

    def test_check_all_and_main_report_per_device_status_and_nonzero_failure(self):
        devices = {'LAB1': '192.0.2.1', 'LAB2': '192.0.2.2'}
        def respond(command, **kwargs):
            return subprocess.CompletedProcess(command, int(command[-1] == '192.0.2.2'), b'', b'')
        self.run.side_effect = respond
        with patch.object(connectivity.LabConnectivityChecker, 'DEVICES', devices):
            checker = connectivity.LabConnectivityChecker()
            checker.check_all_devices()
            self.assertEqual(checker.get_results(), {'LAB1': ('192.0.2.1', 'OK'), 'LAB2': ('192.0.2.2', 'FAILED')})
            self.assertIn('Total: 2 devices | Online: 1 | Offline: 1', self.output.getvalue())
            self.assertEqual(connectivity.main(), 1)
            self.run.side_effect = None
            self.assertEqual(connectivity.main(), 0)


if __name__ == '__main__':
    unittest.main()

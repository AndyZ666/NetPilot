"""Offline SNMP parsing and verification contracts using synthetic command output.

Only subprocess boundaries are replaced for verifier tests, so the actual parsers
and status aggregation run together. Trap matching tests replace command reads
and clocks. Recovery tests execute the real diagnostic entry point against
temporary inventory and simulated subprocess replies; no real device, service,
or interface operation occurs. Invalid SNMP values remain failing assertions
if the implementation accepts them.
"""

from contextlib import ExitStack
import io
import itertools
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch


# Both source files have guarded main functions and standard-library imports.
# Keep process/network boundaries closed even while importing those modules.
with ExitStack() as _imports:
    for _target in ("subprocess.run", "subprocess.Popen", "socket.socket",
                    "socket.create_connection", "os.system", "time.sleep"):
        _imports.enter_context(patch(_target, side_effect=AssertionError(
            "External activity during SNMP test import is forbidden")))
    from Functions import verify_snmp as snmp
    from Functions import test_snmp_trap as traps


IP = "192.0.2.10"
DEVICE = {"name": "R1", "ip": IP, "type": "router"}
NAME = "1.3.6.1.2.1.1.5.0"
DESCR = "1.3.6.1.2.1.1.1.0"
UPTIME = "1.3.6.1.2.1.1.3.0"
CPU = "1.3.6.1.2.1.25.3.3.1.2"
INTERFACES = "1.3.6.1.2.1.2.2.1.2"
ADMIN = "1.3.6.1.2.1.2.2.1.7"
OPER = "1.3.6.1.2.1.2.2.1.8"
IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"
OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"


def healthy_responses():
    """Independent Net-SNMP fixtures for two sparse interface indexes."""
    return {
        ("snmpget", NAME): 'SNMPv2-MIB::sysName.0 = STRING: "r1"',
        ("snmpget", DESCR): 'SNMPv2-MIB::sysDescr.0 = STRING: "Fixture OS"',
        ("snmpget", UPTIME): "DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (9006100) 1 day, 1:01:01.00",
        ("snmpwalk", CPU): "HOST-RESOURCES-MIB::hrProcessorLoad.7 = INTEGER: 10\nHOST-RESOURCES-MIB::hrProcessorLoad.8 = INTEGER: 30",
        ("snmpwalk", INTERFACES): 'IF-MIB::ifDescr.2 = STRING: "Ethernet1"\nIF-MIB::ifDescr.11 = STRING: "Ethernet2"',
        ("snmpwalk", ADMIN): "IF-MIB::ifAdminStatus.11 = INTEGER: 1\nIF-MIB::ifAdminStatus.2 = INTEGER: 1",
        ("snmpwalk", OPER): "IF-MIB::ifOperStatus.2 = INTEGER: 1\nIF-MIB::ifOperStatus.11 = INTEGER: 1",
        ("snmpget", IN_OCTETS + ".1"): "IF-MIB::ifHCInOctets.1 = Counter64: 0",
        ("snmpget", OUT_OCTETS + ".1"): "IF-MIB::ifHCOutOctets.1 = Counter64: 18446744073709551615",
    }


class OfflineSNMPTestCase(unittest.TestCase):
    def setUp(self):
        self.process = self.enterContext(patch.object(
            subprocess, "run", side_effect=AssertionError("Unexpected command")))
        for target in ("subprocess.Popen", "socket.socket", "socket.create_connection",
                       "os.system", "time.sleep"):
            self.enterContext(patch(target, side_effect=AssertionError(
                "External activity is forbidden in SNMP unit tests")))
        for module, name in ((snmp, "main"), (traps, "main"),
                             (traps, "set_interface_state"), (traps, "eos")):
            self.enterContext(patch.object(module, name, side_effect=AssertionError(
                "SNMP unit tests must never operate devices or run main")))

    def install_responses(self, responses):
        def respond(command, **kwargs):
            self.assertEqual(command[-2], IP)
            self.assertEqual(kwargs, {"capture_output": True, "text": True,
                                      "timeout": snmp.SNMP_TIMEOUT + 1})
            key = (command[0], command[-1])
            if key not in responses:
                raise AssertionError("No fixture for command: " + repr(command))
            output = responses[key]
            if isinstance(output, BaseException):
                raise output
            if isinstance(output, subprocess.CompletedProcess):
                return output
            return subprocess.CompletedProcess(command, 0, output, "")
        self.process.reset_mock()
        self.process.side_effect = respond

    def one_response(self, command, oid, output):
        self.install_responses({(command, oid): output})


class SNMPCommandTests(OfflineSNMPTestCase):
    def test_command_arguments_timeout_and_trimmed_output(self):
        self.process.side_effect = None
        self.process.return_value = subprocess.CompletedProcess([], 0, "  value\n", "")
        self.assertEqual(snmp.run_snmp_command("snmpget", IP, NAME, timeout=7),
                         (True, "value"))
        self.process.assert_called_once_with(
            ["snmpget", "-v", "2c", "-c", snmp.SNMP_COMMUNITY,
             "-t", "7", "-r", str(snmp.SNMP_RETRIES), IP, NAME],
            capture_output=True, text=True, timeout=8)

    def test_command_errors_include_timeout_missing_tool_and_stderr(self):
        cases = [
            (subprocess.CompletedProcess([], 1, "", " denied \n"), "denied"),
            (subprocess.CompletedProcess([], 1, "", ""), "SNMP query failed"),
            (subprocess.TimeoutExpired("snmpget", 4), "SNMP command timeout"),
            (FileNotFoundError(), "Command 'snmpget' not found"),
        ]
        for response, error in cases:
            with self.subTest(error=error):
                self.one_response("snmpget", NAME, response)
                self.assertEqual(snmp.run_snmp_command("snmpget", IP, NAME),
                                 (False, error))


class SNMPParsingTests(OfflineSNMPTestCase):
    def test_identity_and_description_parse_quoted_and_unquoted_strings(self):
        for function, oid, value in ((snmp.get_hostname, NAME, "R1"),
                                     (snmp.get_sysdescr, DESCR, "Fixture OS 1.0")):
            for quoted in (False, True):
                with self.subTest(function=function.__name__, quoted=quoted):
                    wire_value = '"' + value + '"' if quoted else value
                    self.one_response("snmpget", oid, oid + " = STRING: " + wire_value)
                    self.assertEqual(function(IP), (True, value))

    def test_identity_and_description_reject_missing_or_malformed_values(self):
        for function, oid in ((snmp.get_hostname, NAME), (snmp.get_sysdescr, DESCR)):
            for output in ("", oid + " = No Such Instance currently exists at this OID",
                           oid + " = INTEGER: 7", subprocess.TimeoutExpired("snmpget", 4)):
                with self.subTest(function=function.__name__, output=output):
                    self.one_response("snmpget", oid, output)
                    success, error = function(IP)
                    self.assertFalse(success)
                    self.assertTrue(error)

    def test_uptime_converts_centiseconds_and_discards_fractional_seconds(self):
        for ticks, expected in ((0, "0d 00h 00m"), (5999, "0d 00h 00m"),
                                (6000, "0d 00h 01m"), (9006199, "1d 01h 01m"),
                                (4294967295, "497d 02h 27m")):
            with self.subTest(ticks=ticks):
                self.one_response("snmpget", UPTIME,
                                  UPTIME + " = Timeticks: (" + str(ticks) + ")")
                self.assertEqual(snmp.get_uptime(IP), (True, expected))

    def test_uptime_rejects_malformed_and_out_of_range_timeticks(self):
        # TimeTicks is an unsigned 32-bit value measured in hundredths of a second.
        for value in ("", "Timeticks: missing", "Timeticks: (abc)",
                      "Timeticks: (-1)", "Timeticks: (4294967296)"):
            with self.subTest(value=value):
                self.one_response("snmpget", UPTIME, UPTIME + " = " + value)
                success, error = snmp.get_uptime(IP)
                self.assertFalse(success, "Invalid TimeTicks must not become a valid uptime")
                self.assertTrue(error)

    def test_cpu_boundaries_and_multiple_processors_have_correct_statistics(self):
        self.one_response("snmpwalk", CPU,
                          "HOST-RESOURCES-MIB::hrProcessorLoad.4 = INTEGER: 0\n\n"
                          "HOST-RESOURCES-MIB::hrProcessorLoad.9 = INTEGER: 50\n"
                          "HOST-RESOURCES-MIB::hrProcessorLoad.12 = INTEGER: 100")
        success, stats, error = snmp.get_cpu_stats(IP)
        self.assertTrue(success)
        self.assertEqual(error, "")
        self.assertEqual((stats.avg, stats.min, stats.max, stats.processor_count),
                         (50.0, 0.0, 100.0, 3))
        self.assertEqual(stats.raw_values, [0.0, 50.0, 100.0])

    def test_cpu_rejects_missing_malformed_and_out_of_range_percentages(self):
        # hrProcessorLoad has INTEGER (0..100) syntax; negative and >100 are invalid.
        for value in ("", "No Such Object available on this agent at this OID",
                      "INTEGER: many", "INTEGER: 1.5", "INTEGER: -1", "INTEGER: 101"):
            with self.subTest(value=value):
                self.one_response("snmpwalk", CPU, CPU + ".4 = " + value)
                success, stats, error = snmp.get_cpu_stats(IP)
                self.assertFalse(success, "Invalid processor load must be rejected")
                self.assertIsNone(stats)
                self.assertTrue(error)

    def test_interface_names_use_sparse_indexes_with_numeric_and_named_oids(self):
        self.one_response("snmpwalk", INTERFACES,
                          'IF-MIB::ifDescr.11 = STRING: "Ethernet2"\n\n'
                          '.1.3.6.1.2.1.2.2.1.2.2 = STRING: Ethernet1\n'
                          'IF-MIB::ifDescr.29 = STRING: "Loopback0"')
        self.assertEqual(snmp.get_interfaces(IP),
                         (True, {"11": "Ethernet2", "2": "Ethernet1", "29": "Loopback0"}, ""))

    def test_interface_names_require_at_least_one_description(self):
        for output in ("", "garbled output", INTERFACES + " = No Such Object"):
            with self.subTest(output=output):
                self.one_response("snmpwalk", INTERFACES, output)
                success, interfaces, error = snmp.get_interfaces(IP)
                self.assertFalse(success)
                self.assertEqual(interfaces, {})
                self.assertTrue(error)

    def test_numeric_admin_and_oper_states_correlate_by_index(self):
        self.install_responses({
            ("snmpwalk", ADMIN): "IF-MIB::ifAdminStatus.3 = INTEGER: 3\nIF-MIB::ifAdminStatus.2 = INTEGER: 2\nIF-MIB::ifAdminStatus.1 = INTEGER: 1",
            ("snmpwalk", OPER): "IF-MIB::ifOperStatus.2 = INTEGER: 1\nIF-MIB::ifOperStatus.1 = INTEGER: 2\nIF-MIB::ifOperStatus.3 = INTEGER: 3",
        })
        success, statuses, error = snmp.get_interface_status(
            IP, {"1": "Ethernet1", "2": "Ethernet2", "3": "Ethernet3"})
        self.assertTrue(success)
        self.assertEqual(error, "")
        self.assertEqual([(s.index, s.name, s.admin_status, s.oper_status, s.is_operational())
                          for s in statuses],
                         [("1", "Ethernet1", "UP", "DOWN", False),
                          ("2", "Ethernet2", "DOWN", "UP", True),
                          ("3", "Ethernet3", "TESTING", "TESTING", False)])

    def test_textual_admin_and_oper_states_match_the_numeric_representation(self):
        self.install_responses({
            ("snmpwalk", ADMIN): "IF-MIB::ifAdminStatus.1 = INTEGER: up(1)\nIF-MIB::ifAdminStatus.2 = INTEGER: down(2)\nIF-MIB::ifAdminStatus.3 = INTEGER: testing(3)",
            ("snmpwalk", OPER): "IF-MIB::ifOperStatus.1 = INTEGER: up(1)\nIF-MIB::ifOperStatus.2 = INTEGER: down(2)\nIF-MIB::ifOperStatus.3 = INTEGER: testing(3)",
        })
        success, statuses, error = snmp.get_interface_status(
            IP, {"1": "Ethernet1", "2": "Ethernet2", "3": "Ethernet3"})
        self.assertTrue(success)
        self.assertEqual(error, "")
        self.assertEqual([(s.admin_status, s.oper_status) for s in statuses],
                         [("UP", "UP"), ("DOWN", "DOWN"), ("TESTING", "TESTING")])
        self.assertEqual([s.is_operational() for s in statuses], [True, False, False])

    def test_missing_and_malformed_interface_rows_are_unknown_and_not_operational(self):
        self.install_responses({
            ("snmpwalk", ADMIN): "IF-MIB::ifAdminStatus.1 = INTEGER: 1\ngarbled",
            ("snmpwalk", OPER): "IF-MIB::ifOperStatus.1 = STRING: missing\ngarbled",
        })
        success, statuses, error = snmp.get_interface_status(
            IP, {"1": "Ethernet1", "2": "Ethernet2"})
        self.assertTrue(success)
        self.assertEqual(error, "")
        self.assertEqual([(s.admin_status, s.oper_status) for s in statuses],
                         [("UP", "UNKNOWN"), ("UNKNOWN", "UNKNOWN")])
        self.assertFalse(any(s.is_operational() for s in statuses))

    def test_either_interface_status_walk_failure_is_reported(self):
        for failed_oid in (ADMIN, OPER):
            with self.subTest(failed_oid=failed_oid):
                responses = {( "snmpwalk", ADMIN): "IF-MIB::ifAdminStatus.1 = INTEGER: 1",
                             ("snmpwalk", OPER): "IF-MIB::ifOperStatus.1 = INTEGER: 1"}
                responses[("snmpwalk", failed_oid)] = subprocess.TimeoutExpired("snmpwalk", 4)
                self.install_responses(responses)
                self.assertEqual(snmp.get_interface_status(IP, {"1": "Ethernet1"}),
                                 (False, [], "SNMP command timeout"))


class SNMPCounterTests(OfflineSNMPTestCase):
    def test_counter64_accepts_zero_and_maximum_unsigned_value(self):
        responses = healthy_responses()
        self.install_responses(responses)
        self.assertEqual(snmp.check_traffic_counters(IP), (True, ""))
        self.assertEqual([(call.args[0][0], call.args[0][-1])
                          for call in self.process.call_args_list],
                         [("snmpget", IN_OCTETS + ".1"), ("snmpget", OUT_OCTETS + ".1")])

    def test_counter64_rejects_invalid_payloads_even_when_command_succeeds(self):
        for payload in ("Counter64: -1", "Counter64: 18446744073709551616",
                        "Counter64: 1.5", "Counter64: invalid", "",
                        "No Such Instance currently exists at this OID"):
            with self.subTest(payload=payload):
                responses = {}
                for oid in (IN_OCTETS, OUT_OCTETS):
                    responses[("snmpget", oid + ".1")] = oid + ".1 = " + payload
                    responses[("snmpwalk", oid)] = oid + ".2 = " + payload
                self.install_responses(responses)
                success, error = snmp.check_traffic_counters(IP)
                self.assertFalse(success, "Counter availability requires a valid unsigned Counter64")
                self.assertTrue(error)

    def test_counter_walk_fallback_handles_interface_one_not_existing(self):
        self.install_responses({
            ("snmpget", IN_OCTETS + ".1"): subprocess.CompletedProcess([], 1, "", "missing index 1"),
            ("snmpget", OUT_OCTETS + ".1"): subprocess.CompletedProcess([], 1, "", "missing index 1"),
            ("snmpwalk", IN_OCTETS): "IF-MIB::ifHCInOctets.7 = Counter64: 200",
            ("snmpwalk", OUT_OCTETS): "IF-MIB::ifHCOutOctets.7 = Counter64: 300",
        })
        self.assertEqual(snmp.check_traffic_counters(IP), (True, ""))
        self.assertEqual([(call.args[0][0], call.args[0][-1])
                          for call in self.process.call_args_list],
                         [("snmpget", IN_OCTETS + ".1"), ("snmpget", OUT_OCTETS + ".1"),
                          ("snmpwalk", IN_OCTETS), ("snmpwalk", OUT_OCTETS)])

    def test_counter_availability_requires_both_directions(self):
        for failed_oid in (IN_OCTETS, OUT_OCTETS):
            with self.subTest(failed_oid=failed_oid):
                responses = {}
                for oid in (IN_OCTETS, OUT_OCTETS):
                    for command, suffix in (("snmpget", ".1"), ("snmpwalk", "")):
                        responses[(command, oid + suffix)] = (
                            subprocess.TimeoutExpired(command, 4) if oid == failed_oid
                            else oid + ".1 = Counter64: 50")
                self.install_responses(responses)
                self.assertEqual(snmp.check_traffic_counters(IP),
                                 (False, "Cannot retrieve traffic counters"))


class SNMPDeviceVerificationTests(OfflineSNMPTestCase):
    def test_healthy_device_passes_with_identity_uptime_cpu_and_interface_details(self):
        self.install_responses(healthy_responses())
        result = snmp.verify_device(DEVICE)
        self.assertEqual((result.name, result.ip, result.status), ("R1", IP, "PASS"))
        self.assertTrue(result.hostname_match)
        self.assertEqual(result.sys_descr, "Fixture OS")
        self.assertEqual(result.uptime_human, "1d 01h 01m")
        self.assertEqual((result.cpu_stats.avg, result.cpu_stats.processor_count), (20.0, 2))
        self.assertEqual((result.interfaces_up, result.interfaces_total), (2, 2))
        self.assertEqual([interface.name for interface in result.interface_details],
                         ["Ethernet1", "Ethernet2"])
        self.assertTrue(result.traffic_counters_ok)
        self.assertEqual(result.error_message, "")

    def test_mismatched_or_unreachable_identity_fails_before_other_queries(self):
        for output, error in ((NAME + ' = STRING: "R2"', "Hostname mismatch"),
                              (subprocess.TimeoutExpired("snmpget", 4), "timeout")):
            with self.subTest(output=output):
                self.one_response("snmpget", NAME, output)
                result = snmp.verify_device(DEVICE)
                self.assertEqual(result.status, "FAIL")
                self.assertFalse(result.hostname_match)
                self.assertIn(error, result.error_message)
                self.process.assert_called_once()

    def test_required_query_failure_fails_device_with_context(self):
        for command, oid, prefix in (("snmpget", UPTIME, "SNMP command timeout"),
                                     ("snmpwalk", CPU, "CPU query failed"),
                                     ("snmpwalk", INTERFACES, "Interface query failed"),
                                     ("snmpwalk", OPER, "Interface status query failed")):
            with self.subTest(oid=oid):
                responses = healthy_responses()
                responses[(command, oid)] = subprocess.TimeoutExpired(command, 4)
                self.install_responses(responses)
                result = snmp.verify_device(DEVICE)
                self.assertEqual(result.status, "FAIL")
                self.assertTrue(result.hostname_match)
                self.assertIn(prefix, result.error_message)
                self.assertNotIn(IN_OCTETS + ".1",
                                 [call.args[0][-1] for call in self.process.call_args_list])

    def test_down_interface_warns_while_retaining_other_successful_checks(self):
        responses = healthy_responses()
        responses[("snmpwalk", OPER)] = "IF-MIB::ifOperStatus.2 = INTEGER: 1\nIF-MIB::ifOperStatus.11 = INTEGER: 2"
        self.install_responses(responses)
        result = snmp.verify_device(DEVICE)
        self.assertEqual(result.status, "WARN")
        self.assertEqual((result.interfaces_up, result.interfaces_total), (1, 2))
        self.assertTrue(result.traffic_counters_ok)

    def test_missing_traffic_counters_warns_with_interfaces_still_up(self):
        responses = healthy_responses()
        for oid in (IN_OCTETS, OUT_OCTETS):
            responses[("snmpget", oid + ".1")] = subprocess.TimeoutExpired("snmpget", 4)
            responses[("snmpwalk", oid)] = subprocess.TimeoutExpired("snmpwalk", 4)
        self.install_responses(responses)
        result = snmp.verify_device(DEVICE)
        self.assertEqual(result.status, "WARN")
        self.assertEqual((result.interfaces_up, result.interfaces_total), (2, 2))
        self.assertFalse(result.traffic_counters_ok)

    def test_optional_system_description_failure_does_not_fail_healthy_device(self):
        responses = healthy_responses()
        responses[("snmpget", DESCR)] = subprocess.TimeoutExpired("snmpget", 4)
        self.install_responses(responses)
        result = snmp.verify_device(DEVICE)
        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.sys_descr, "")
        self.assertEqual(result.uptime_human, "1d 01h 01m")

    def test_textual_up_states_produce_a_passing_device(self):
        responses = healthy_responses()
        for oid in (ADMIN, OPER):
            responses[("snmpwalk", oid)] = responses[("snmpwalk", oid)].replace(
                "INTEGER: 1", "INTEGER: up(1)")
        self.install_responses(responses)
        result = snmp.verify_device(DEVICE)
        self.assertEqual((result.status, result.interfaces_up), ("PASS", 2))

    def test_invalid_cpu_or_counter_data_cannot_produce_overall_pass(self):
        cases = [
            {("snmpwalk", CPU): CPU + ".7 = INTEGER: 101"},
            {("snmpget", IN_OCTETS + ".1"): IN_OCTETS + ".1 = Counter64: -1",
             ("snmpwalk", IN_OCTETS): IN_OCTETS + ".2 = Counter64: -1",
             ("snmpwalk", OUT_OCTETS): OUT_OCTETS + ".2 = Counter64: 100"},
        ]
        for invalid_responses in cases:
            with self.subTest(invalid_responses=invalid_responses):
                responses = healthy_responses()
                responses.update(invalid_responses)
                self.install_responses(responses)
                self.assertNotEqual(snmp.verify_device(DEVICE).status, "PASS")


class SNMPTrapMatchingTests(OfflineSNMPTestCase):
    def setUp(self):
        super().setUp()
        self.interface = {"name": "Ethernet1", "ifindex": 2}
        self.reader = self.enterContext(patch.object(traps, "run_command"))
        self.clock = self.enterContext(patch.object(time, "monotonic"))
        self.sleep = self.enterContext(patch.object(time, "sleep"))
        self.printed = io.StringIO()
        self.enterContext(patch("sys.stdout", self.printed))

    def check_output(self, output, trap_type="linkDown"):
        self.reader.reset_mock()
        self.reader.return_value = output
        self.clock.side_effect = [100.0, 100.0, 116.0]
        self.sleep.reset_mock()
        matched = traps.check_link_trap(DEVICE, self.interface, "fixture-cursor", trap_type)
        self.reader.assert_called_once_with(
            ["journalctl", "--no-pager", "-u", "snmptrapd.service",
             "--after-cursor", "fixture-cursor", "-o", "cat"])
        self.sleep.assert_called_once_with(2)
        self.process.assert_not_called()
        return matched

    def test_named_trap_matches_multiline_source_and_interface(self):
        output = "UDP: [192.0.2.10]:50000->[192.0.2.20]:162\nSNMPv2-MIB::snmpTrapOID.0 = OID: IF-MIB::linkDown\nIF-MIB::ifIndex.2 = INTEGER: 2\nIF-MIB::ifDescr.2 = STRING: Ethernet1"
        self.assertTrue(self.check_output(output))
        self.assertIn("Interface Match : YES", self.printed.getvalue())

    def test_numeric_and_iso_link_up_oids_match_the_interface_index(self):
        for prefix in ("1.", ".1.", "iso."):
            with self.subTest(prefix=prefix):
                output = ("UDP: [192.0.2.10]:50000\n"
                          + prefix + "3.6.1.6.3.1.1.4.1.0 = OID: "
                          + prefix + "3.6.1.6.3.1.1.5.4\n"
                          + prefix + "3.6.1.2.1.2.2.1.1.2 = INTEGER: 2")
                self.assertTrue(self.check_output(output, "linkUp"))

    def test_trap_rejects_wrong_source_type_interface_and_oid_prefix(self):
        valid = "UDP: [192.0.2.10]:50000\nSNMPv2-MIB::snmpTrapOID.0 = OID: IF-MIB::linkDown\nIF-MIB::ifIndex.2 = INTEGER: 2\nIF-MIB::ifDescr.2 = STRING: Ethernet1"
        invalid = [valid.replace("192.0.2.10", "192.0.2.99"),
                   valid.replace("IF-MIB::linkDown", "IF-MIB::linkUp"),
                   valid.replace("Ethernet1", "Ethernet10"),
                   valid.replace("INTEGER: 2", "INTEGER: 20"),
                   valid.replace("IF-MIB::linkDown", "IF-MIB::linkDownExtra")]
        for output in invalid:
            with self.subTest(output=output):
                self.assertFalse(self.check_output(output))

    def test_trap_records_are_not_combined_across_different_senders(self):
        output = "UDP: [192.0.2.10]:50000\nSNMPv2-MIB::snmpTrapOID.0 = OID: IF-MIB::linkUp\nIF-MIB::ifIndex.2 = INTEGER: 2\nUDP: [192.0.2.99]:50001\nSNMPv2-MIB::snmpTrapOID.0 = OID: IF-MIB::linkDown\nIF-MIB::ifIndex.2 = INTEGER: 2"
        self.assertFalse(self.check_output(output))


class SNMPTrapRecoveryTests(unittest.TestCase):
    """Offline script integration: real trap decisions, synthetic Docker/journal I/O."""

    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (self.root / 'devices.json').write_text(json.dumps({'devices': [DEVICE]}))
        self.enterContext(patch.object(traps, '__file__', str(self.root / 'test_snmp_trap.py')))
        for boundary in ('subprocess.Popen', 'socket.socket.connect', 'socket.create_connection', 'os.system'):
            self.enterContext(patch(boundary, side_effect=AssertionError('External operation forbidden')))
        self.output = self.enterContext(patch('sys.stdout', new_callable=io.StringIO))
        self.enterContext(patch('builtins.input', side_effect=['1', '1']))
        self.enterContext(patch.object(traps.time, 'sleep'))
        self.enterContext(patch.object(traps.time, 'monotonic', side_effect=itertools.count(100)))
        self.config_commands = []
        self.cursor_count = 0
        self.state = 'up'
        self.shutdown_error = self.restore_error = self.checkpoint_error = False
        self.process = self.enterContext(patch.object(traps.subprocess, 'run', side_effect=self.respond))

    def respond(self, command, **kwargs):
        self.assertEqual(kwargs, {'capture_output': True, 'text': True, 'timeout': 15})
        if command[:2] == ['docker', 'exec']:
            self.assertEqual(command[:7], ['docker', 'exec', 'clab-pilot-network-R1', 'Cli', '-p', '15', '-c'])
            cli = command[7]
            if cli == 'show interfaces | json':
                output = json.dumps({'interfaces': {'Ethernet1': {'lineProtocolStatus': self.state, 'ifIndex': 2}}})
            elif cli in ('configure terminal\ninterface Ethernet1\nshutdown\nend',
                         'configure terminal\ninterface Ethernet1\nno shutdown\nend'):
                self.config_commands.append(cli)
                if '\nno shutdown\n' in cli:
                    if self.restore_error:
                        return subprocess.CompletedProcess(command, 1, '', 'fixture restoration failed')
                    self.state = 'up'
                else:
                    self.state = 'down'
                    if self.shutdown_error:
                        raise KeyboardInterrupt
                output = ''
            else:
                raise AssertionError(f'Unexpected device command {cli}')
        elif command == ['journalctl', '--no-pager', '-n', '1', '--show-cursor']:
            self.cursor_count += 1
            if self.cursor_count == 2 and self.checkpoint_error:
                return subprocess.CompletedProcess(command, 1, '', 'fixture checkpoint failed')
            output = f'-- cursor: fixture-{self.cursor_count}'
        elif command == ['journalctl', '--no-pager', '-u', 'snmptrapd.service', '-n', '1', '-o', 'cat']:
            output = ''
        elif command[:5] == ['journalctl', '--no-pager', '-u', 'snmptrapd.service', '--after-cursor']:
            self.assertEqual(command[6:], ['-o', 'cat'])
            trap = 'linkDown' if command[5] == 'fixture-1' else 'linkUp'
            output = f'UDP: [{IP}]:50000\nSNMPv2-MIB::snmpTrapOID.0 = OID: IF-MIB::{trap}\nIF-MIB::ifIndex.2 = INTEGER: 2'
        else:
            raise AssertionError(f'Unexpected external command {command}')
        return subprocess.CompletedProcess(command, 0, output, '')

    def test_complete_diagnostic_requires_both_traps_and_confirmed_restoration(self):
        self.assertEqual(traps.main(), 0)
        self.assertEqual(self.config_commands, ['configure terminal\ninterface Ethernet1\nshutdown\nend',
                                               'configure terminal\ninterface Ethernet1\nno shutdown\nend'])
        self.assertEqual(self.cursor_count, 2)
        self.assertEqual(self.state, 'up')
        self.assertIn('FINAL RESULT       : PASS', self.output.getvalue())

    def test_shutdown_interruption_still_restores_and_cannot_report_success(self):
        self.shutdown_error = True
        self.assertEqual(traps.main(), 1)
        self.assertEqual(len(self.config_commands), 2)
        self.assertIn('\nno shutdown\n', self.config_commands[-1])
        self.assertEqual(self.state, 'up')
        self.assertIn('FINAL RESULT       : FAIL', self.output.getvalue())

    def test_failed_linkup_checkpoint_does_not_prevent_interface_restoration(self):
        self.checkpoint_error = True
        self.assertEqual(traps.main(), 1)
        self.assertEqual(self.state, 'up')
        self.assertIn('\nno shutdown\n', self.config_commands[-1])
        queries = [call.args[0] for call in self.process.call_args_list if '--after-cursor' in call.args[0]]
        self.assertEqual(len(queries), 1)

    def test_failed_restoration_is_failure_even_with_both_trap_records(self):
        self.restore_error = True
        self.assertEqual(traps.main(), 1)
        self.assertEqual(self.state, 'down')
        self.assertIn('Interface Restored : NO', self.output.getvalue())
        self.assertIn('linkUp Received    : YES', self.output.getvalue())

    def test_initially_down_interface_prevents_any_configuration_or_journal_poll(self):
        self.state = 'down'
        with self.assertRaisesRegex(RuntimeError, 'Select an UP interface'):
            traps.main()
        self.assertEqual(self.config_commands, [])
        self.assertEqual(self.cursor_count, 0)
        self.assertEqual(self.process.call_count, 1)

    def test_initial_journal_denial_prevents_shutdown(self):
        original = self.process.side_effect

        def denied(command, **kwargs):
            if command[0] == 'journalctl':
                return subprocess.CompletedProcess(command, 0, '', 'Not seeing messages from other users')
            return original(command, **kwargs)

        self.process.side_effect = denied
        with self.assertRaisesRegex(RuntimeError, 'Journal access denied'):
            traps.main()
        self.assertEqual(self.config_commands, [])

    def test_interface_parser_selects_only_physical_ethernet_and_sorts_numerically(self):
        data = {'interfaces': {name: {'lineProtocolStatus': state, 'ifIndex': index} for name, state, index in (
            ('Ethernet10', 'up', 10), ('Management0', 'up', 1), ('Ethernet2/1', 'down', 21),
            ('Ethernet2', 'up', 2), ('Ethernet2.100', 'up', 100), ('Vlan10', 'up', 110))}}
        self.process.side_effect = None
        self.process.return_value = subprocess.CompletedProcess([], 0, json.dumps(data), '')
        self.assertEqual(traps.get_interfaces(DEVICE), [
            {'name': 'Ethernet2', 'state': 'UP', 'ifindex': 2},
            {'name': 'Ethernet2/1', 'state': 'DOWN', 'ifindex': 21},
            {'name': 'Ethernet10', 'state': 'UP', 'ifindex': 10}])
        self.assertEqual(self.config_commands, [])


if __name__ == "__main__":
    unittest.main()

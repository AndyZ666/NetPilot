"""Observed EOS state: real parsing/cache logic, fake SSH and Vault boundaries."""

from copy import deepcopy
import io
import json
import logging
import unittest
from unittest.mock import Mock, patch

import live_device_state as live


DEVICE = {"hostname": "R6", "vendor": "Arista", "platform": "cEOSLab",
          "management_ip": "172.20.20.30"}
PASSWORD = "offline-password-must-not-appear"
CONFIG = """! Synthetic EOS running configuration
hostname R6
username admin privilege 15 secret sha512 $6$synthetic-not-a-real-hash
interface Management0
   ip address 172.20.20.30/24
!
interface Ethernet2
   ip ospf 10 area 0.0.0.0
!
router ospf 10
   router-id 6.6.6.6
!
router rip
   shutdown
   network 10.0.0.0/8
!
end
"""


class ProtocolParsing(unittest.TestCase):
    def test_r6_running_ospf_and_rip_are_configured_even_when_rip_is_shutdown(self):
        rows = {row["name"]: row for row in live.configured_protocols(CONFIG, "R6")}
        self.assertEqual({name for name, row in rows.items() if row["configured"]}, {"ospfv2", "ripv2"})
        self.assertEqual(rows["ospfv2"]["interfaces"], ["Ethernet2"])
        self.assertNotIn("$6$", json.dumps(rows))
        self.assertNotIn("secret", json.dumps(rows))

    def test_r7_legacy_and_current_ospfv3_interface_syntax_and_bgp(self):
        for stanza in ("ipv6 router ospf 10", "router ospfv3"):
            with self.subTest(stanza=stanza):
                config = """hostname R7
interface Ethernet2
   ipv6 ospf 10 area 0.0.0.0
interface Ethernet3
   ospfv3 ipv6 area 0.0.0.0
{stanza}
   router-id 7.7.7.7
router bgp 65007
   neighbor 192.0.2.2 remote-as 65008
end
""".format(stanza=stanza)
                rows = {row["name"]: row for row in live.configured_protocols(config, "R7")}
                self.assertEqual({name for name, row in rows.items() if row["configured"]}, {"ospfv3", "bgp"})
                self.assertEqual(rows["ospfv3"]["interfaces"], ["Ethernet2", "Ethernet3"])

    def test_interface_settings_are_detected_without_router_headers(self):
        config = """hostname R6
interface Ethernet2
   ip ospf cost 50
   ipv6 ospf 10 area 0
   ip rip send version 2
end
"""
        rows = live.configured_protocols(config, "R6")
        self.assertEqual([row["label"] for row in rows if row["configured"]], ["OSPFv2", "OSPFv3", "RIP"])
        self.assertTrue(all(row["interfaces"] == ["Ethernet2"] for row in rows if row["configured"]))

    def test_literal_comments_banners_descriptions_negations_and_redistribution_are_not_processes(self):
        config = """hostname R6
banner motd
router ospf 10
router rip
interface Ethernet10
   ipv6 ospf 5 area 0
EOF
comment
router bgp 65000
ipv6 router ospf 10
EOF
interface Ethernet2
   description router bgp 65000
   no ip ospf 10 area 0
   no ipv6 ospf 10 area 0
no router bgp 65000
no router ospfv3
router isis CORE
   redistribute ospf 10
end
"""
        rows = live.configured_protocols(config, "R6")
        self.assertFalse(any(row["configured"] for row in rows))

    def test_complete_no_routing_config_is_distinct_from_invalid_or_wrong_identity(self):
        self.assertFalse(any(row["configured"] for row in live.configured_protocols("hostname R6\nend\n", "R6")))
        for output in ("", None, b"hostname R6\nend", "hostname R60\nend",
                       "hostname R6\ninterface Ethernet2", "% Invalid input", "hostname R6\nhostname R7\nend",
                       "hostname R6\ncomment\nrouter bgp 65000\nend"):
            with self.subTest(output=output):
                with self.assertRaises((RuntimeError, ValueError)):
                    live.configured_protocols(output, "R6")


class ObservedState(unittest.TestCase):
    def setUp(self):
        live._CACHE.clear()
        self.addCleanup(live._CACHE.clear)
        self.enterContext(patch("socket.socket.connect", side_effect=AssertionError("No network")))
        self.enterContext(patch("subprocess.Popen", side_effect=AssertionError("No subprocess")))
        self.credentials = self.enterContext(patch.object(live.credential_provider, "get_credentials", return_value=("admin", PASSWORD)))
        self.connection = Mock()
        self.connection.check_enable_mode.return_value = True
        self.connection.send_command.return_value = CONFIG
        self.connect = self.enterContext(patch.object(live, "ConnectHandler", return_value=self.connection))
        self.clock = self.enterContext(patch.object(live.time, "monotonic", return_value=100))

    def test_read_only_refresh_returns_summary_without_configuration_or_credentials(self):
        before = deepcopy(DEVICE)
        result = live.observed_state(DEVICE)
        self.assertEqual(DEVICE, before)
        self.assertEqual(result["status"], "available")
        self.assertTrue(result["reachable"])
        self.assertEqual(result["operational"], "Not checked")
        self.assertEqual(result["last_success"], result["checked_at"])
        self.assertEqual([row["label"] for row in result["protocols"] if row["configured"]], ["OSPFv2", "RIP"])
        self.connection.send_command.assert_called_once_with("show running-config", read_timeout=12)
        self.connection.disconnect.assert_called_once_with()
        self.connection.send_config_set.assert_not_called()
        self.connection.save_config.assert_not_called()
        self.credentials.assert_called_once_with()
        self.assertEqual(self.connect.call_args.kwargs["host"], "172.20.20.30")
        self.assertIsNone(self.connect.call_args.kwargs["session_log"])
        self.assertNotIn(PASSWORD, json.dumps(result))
        self.assertNotIn("$6$", json.dumps(result))

    def test_cache_expires_at_thirty_seconds_and_force_refreshes(self):
        first = live.observed_state(DEVICE)
        first["protocols"][0]["configured"] = False
        self.clock.return_value = 129.99
        cached = live.observed_state(DEVICE)
        self.assertTrue(cached["protocols"][0]["configured"])
        self.assertEqual(self.connect.call_count, 1)
        self.clock.return_value = 130
        live.observed_state(DEVICE)
        self.assertEqual(self.connect.call_count, 2)
        live.observed_state(DEVICE, force=True)
        self.assertEqual(self.connect.call_count, 3)

    def test_unreachable_refresh_clears_current_protocols_but_preserves_last_success(self):
        good = live.observed_state(DEVICE)
        self.connect.side_effect = live.NetmikoTimeoutException(PASSWORD)
        result = live.observed_state(DEVICE, force=True)
        self.assertEqual(result["status"], "unavailable")
        self.assertFalse(result["reachable"])
        self.assertIsNone(result["protocols"])
        self.assertEqual(result["last_success"], good["last_success"])
        self.assertIn("Live status unavailable", result["message"])
        self.assertNotIn(PASSWORD, json.dumps(result))
        live.observed_state(DEVICE)
        self.assertEqual(self.connect.call_count, 2)

    def test_changed_management_address_does_not_reuse_previous_observation(self):
        live.observed_state(DEVICE)
        changed = dict(DEVICE, management_ip="172.20.20.31")
        self.connect.side_effect = live.NetmikoTimeoutException("offline")
        result = live.observed_state(changed)
        self.assertIsNone(result["last_success"])
        self.assertEqual(self.connect.call_count, 2)

    def test_invalid_inventory_targets_stop_before_credentials_or_ssh(self):
        for updates in ({"hostname": "R6;command"}, {"vendor": "unsupported"},
                        {"platform": "linux"}, {"management_ip": True}, {"management_ip": 1234},
                        {"management_ip": b"\xac\x14\x14\x1e"}, {"management_ip": "127.0.0.1"},
                        {"management_ip": "invalid"}):
            with self.subTest(updates=updates):
                result = live.observed_state(dict(DEVICE, **updates))
                self.assertEqual(result["status"], "unavailable")
                self.assertIsNone(result["protocols"])
        self.credentials.assert_not_called()
        self.connect.assert_not_called()

    def test_raw_inventory_management_mapping_and_cidr_are_supported(self):
        device = dict(DEVICE)
        del device["management_ip"]
        device["management"] = {"ipv4": "172.20.20.30/24"}
        self.assertEqual(live.observed_state(device)["status"], "available")
        self.assertEqual(self.connect.call_args.kwargs["host"], "172.20.20.30")

    def test_credential_and_authentication_errors_are_sanitized(self):
        self.credentials.side_effect = RuntimeError(PASSWORD)
        result = live.observed_state(DEVICE)
        self.assertEqual(result["status"], "unavailable")
        self.connect.assert_not_called()
        self.assertNotIn(PASSWORD, json.dumps(result))
        self.credentials.side_effect = None
        self.connect.side_effect = live.NetmikoAuthenticationException(PASSWORD)
        result = live.observed_state(DEVICE, force=True)
        self.assertEqual(result["status"], "unavailable")
        self.assertTrue(result["reachable"])
        self.assertIsNone(result["protocols"])
        self.assertNotIn(PASSWORD, json.dumps(result))

    def test_invalid_output_or_privilege_denial_is_not_no_protocols(self):
        for output in ("hostname R60\nend\n", "% Invalid input " + PASSWORD, "hostname R6\n", None):
            with self.subTest(output=output):
                self.connection.send_command.return_value = output
                result = live.observed_state(DEVICE, force=True)
                self.assertEqual(result["status"], "unavailable")
                self.assertIsNone(result["protocols"])
                self.assertNotIn(PASSWORD, json.dumps(result))
        self.connection.reset_mock()
        self.connection.check_enable_mode.return_value = False
        result = live.observed_state(DEVICE, force=True)
        self.assertEqual(result["status"], "unavailable")
        self.connection.enable.assert_called_once_with()
        self.connection.send_command.assert_not_called()
        self.connection.disconnect.assert_called_once_with()

    def test_transport_debug_logging_cannot_expose_credentials_or_running_configuration(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("netmiko")
        logger.addHandler(handler)
        self.addCleanup(logger.removeHandler, handler)
        before = logging.root.manager.disable

        def connect(**kwargs):
            logger.error(PASSWORD + CONFIG)
            return self.connection

        self.connect.side_effect = connect
        self.assertEqual(live.observed_state(DEVICE)["status"], "available")
        self.assertEqual(stream.getvalue(), "")
        self.assertEqual(logging.root.manager.disable, before)

    def test_concurrent_refresh_does_not_start_another_connection(self):
        live._LOCK.acquire()
        try:
            result = live.observed_state(DEVICE)
        finally:
            live._LOCK.release()
        self.assertEqual(result["status"], "unavailable")
        self.assertIn("in progress", result["message"])
        self.credentials.assert_not_called()
        self.connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()

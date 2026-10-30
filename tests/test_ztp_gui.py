"""Offline ZTP safety decisions; no Docker, Vault, SSH or real inventory writes."""

from copy import deepcopy
import difflib
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

import yaml

from lab8 import ztp_gui as ztp


TOPOLOGY = b'''name: pilot-network
# Existing network settings and formatting must survive.
mgmt:
  network: clab
  ipv4-subnet: 172.20.20.0/24
topology:
  kinds:
    ceos: {image: 'ceos:4.36.2F'}
  nodes:
    R1:
      kind: ceos
      mgmt-ipv4: 172.20.20.2
    H1:
      kind: linux
      mgmt-ipv4: 172.20.20.3
      exec:
        - "echo preserve-existing-command" # Historical drift is not rewritten.
  links:
    - endpoints: ["R1:eth1", "H1:eth1"]
# Preserve the trailing comment too.
'''


def inventory():
    return {"devices": {"R1": {"hostname": "R1", "management": {"ipv4": "172.20.20.2"}}}}


def snapshot():
    return {"network": "172.20.20.0/24", "gateway": "172.20.20.1",
            "names": ["clab-pilot-network-R1", "R1", "H1"],
            "addresses": ["172.20.20.4"], "macs": [], "server_ready": True, "owned": {}}


def target():
    return {"hostname": "R8", "management_ip": "172.20.20.32",
            "bootstrap_mac": "02:08:12:34:56:78", "host_interface": "npztp-12345678",
            "job_id": "8" * 32}


class ZtpAllocationTests(unittest.TestCase):
    def setUp(self):
        for name in ("subprocess.run", "socket.create_connection",
                     "security.credential_provider.get_credentials"):
            forbidden = self.enterContext(patch(name, side_effect=AssertionError("External operation forbidden")))
            self.addCleanup(forbidden.assert_not_called)

    def test_hostname_accepts_safe_names_and_rejects_shell_paths_and_reserved_routes(self):
        for name in ("R8", "R", "site-router-8", "R" * 32):
            self.assertEqual(ztp.validate_hostname(name), name)
        for name in ("", None, True, "r8;id", "../R8", "R8\n", "R 8", "R8_", "R8.",
                     "-R8", "R8-", "8R", "R" * 33, "ADD", "ztp"):
            with self.subTest(name=name), self.assertRaises(ztp.ZtpError):
                ztp.validate_hostname(name)

    def test_duplicate_keys_hostnames_topology_and_docker_names_are_case_insensitive(self):
        cases = []
        records = inventory()
        records["devices"]["r8"] = {"hostname": "Asset", "management": {"ipv4": "172.20.20.8"}}
        cases.append((records, yaml.safe_load(TOPOLOGY), snapshot()))
        records = inventory()
        records["devices"]["Asset"] = {"hostname": "r8", "management": {"ipv4": "172.20.20.8"}}
        cases.append((records, yaml.safe_load(TOPOLOGY), snapshot()))
        topology = yaml.safe_load(TOPOLOGY)
        topology["topology"]["nodes"]["r8"] = {"kind": "ceos"}
        cases.append((inventory(), topology, snapshot()))
        for existing_name in ("r8", "clab-pilot-network-r8", "CLAB-PILOT-NETWORK-R8"):
            current = snapshot()
            current["names"].append(existing_name)
            cases.append((inventory(), yaml.safe_load(TOPOLOGY), current))
        for index, values in enumerate(cases):
            before = deepcopy(values)
            with self.subTest(source=index), self.assertRaisesRegex(ztp.ZtpError, "already exists"):
                ztp.inspect_target("R8", *values)
            self.assertEqual(values, before)

    def test_allocation_excludes_inventory_prefix_topology_docker_and_reserved_addresses(self):
        records = inventory()
        records["devices"]["Other"] = {"hostname": "Other", "management": {"ipv4_prefix": "172.20.20.5/24"}}
        topology, current = yaml.safe_load(TOPOLOGY), snapshot()
        current["addresses"].append("172.20.20.6/24")
        selected = ztp.inspect_target("R8", records, topology, current)
        self.assertNotIn(selected, {"172.20.20.0", "172.20.20.1", "172.20.20.2", "172.20.20.3",
                                    "172.20.20.4", "172.20.20.5", "172.20.20.6", "172.20.20.255"})
        self.assertTrue(selected.startswith("172.20.20."))
        current["addresses"] = [f"172.20.20.{last}" for last in range(2, 254)]
        self.assertEqual(ztp.inspect_target("R8", records, topology, current), "172.20.20.254")
        current["addresses"].append("172.20.20.254")
        with self.assertRaisesRegex(ztp.ZtpError, "No unused"):
            ztp.inspect_target("R8", records, topology, current)

    def test_malformed_or_wrong_network_evidence_does_not_allocate(self):
        for change in ({"network": "172.31.252.0/24"}, {"addresses": ["invalid"]},
                       {"gateway": None}, {"names": [None]}):
            current = snapshot()
            current.update(change)
            with self.subTest(change=change), self.assertRaises(ztp.ZtpError):
                ztp.inspect_target("R8", inventory(), yaml.safe_load(TOPOLOGY), current)
        records = inventory()
        records["devices"]["R1"]["management"]["ipv4"] = True
        with self.assertRaises(ztp.ZtpError):
            ztp.inspect_target("R8", records, yaml.safe_load(TOPOLOGY), snapshot())

    def test_topology_inserts_only_new_native_ztp_node_and_bootstrap_preserving_source(self):
        request = target()
        original = yaml.safe_load(TOPOLOGY)
        for source in (TOPOLOGY, TOPOLOGY.replace(b"\n", b"\r\n")):
            with self.subTest(newline="CRLF" if b"\r\n" in source else "LF"):
                updated = ztp.topology_updated(source, request["hostname"], request["management_ip"],
                                               request["bootstrap_mac"], request["host_interface"])
                changes = difflib.SequenceMatcher(a=source.splitlines(keepends=True), b=updated.splitlines(keepends=True))
                self.assertTrue(all(tag in {"equal", "insert"} for tag, *_ in changes.get_opcodes()))
                result = yaml.safe_load(updated)
                new_node = result["topology"]["nodes"].pop("R8")
                new_link = result["topology"]["links"].pop()
                self.assertEqual(result, original)
                self.assertEqual(new_node["kind"], "ceos")
                self.assertEqual(new_node["mgmt-ipv4"], "172.20.20.32")
                self.assertIs(new_node["suppress-startup-config"], True)
                self.assertNotIn("startup-config", new_node)
                self.assertEqual(new_link, {"type": "host", "endpoint": {"node": "R8", "interface": "eth1",
                                          "mac": "02:08:12:34:56:78"}, "host-interface": "npztp-12345678"})
        with self.assertRaises(ztp.ZtpError):
            ztp.topology_updated(TOPOLOGY, "r1", "172.20.20.32", request["bootstrap_mac"], request["host_interface"])

    def test_device_record_is_pending_and_has_management_only_intent_without_secrets(self):
        request = target()
        before = deepcopy(request)
        record = ztp.build_record(request)
        self.assertEqual(request, before)
        self.assertEqual(record["hostname"], "R8")
        self.assertEqual(record["management"], {"interface": "Management0", "ipv4": "172.20.20.32",
                                              "ipv4_prefix": "172.20.20.32/24"})
        self.assertEqual(record["template"], "templates/arista_day0.j2")
        self.assertEqual(record["onboarding"]["status"], "pending")
        self.assertEqual(record["interfaces"], {})
        self.assertEqual(record["vlans"], {})
        self.assertEqual(record["redistribution"], [])
        self.assertTrue(all(value["enabled"] is False for value in record["routing"].values()))
        for private in ("password", "secret", "$6$", "sshkey"):
            self.assertNotIn(private, json.dumps(record))


class ZtpWorkflowTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="netpilot-ztp-workflow-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.inventory = self.root / "devices.yml"
        self.inventory.write_text(yaml.safe_dump(inventory()))
        self.topology = self.root / "topology.yml"
        self.topology.write_bytes(TOPOLOGY)
        self.runtime = self.root / "runtime"
        for name, value in (("INVENTORY", self.inventory), ("TOPOLOGY", self.topology),
                            ("RUNTIME", self.runtime), ("_LOCK", threading.Lock()), ("_ACTIVE", set())):
            self.enterContext(patch.object(ztp, name, value))
        self.helper = self.enterContext(patch.object(ztp, "helper", return_value={"ok": True}))
        self.render = self.enterContext(patch.object(ztp.day0, "render_one"))
        self.publish = self.enterContext(patch.object(ztp.day0, "publish_one", return_value=1300))
        self.clear = self.enterContext(patch.object(ztp.day0, "clear_one"))
        self.verify = self.enterContext(patch.object(ztp, "verify_device", return_value=True))
        for boundary in ("subprocess.run", "socket.create_connection", "netmiko.ConnectHandler",
                         "security.credential_provider.get_credentials"):
            forbidden = self.enterContext(patch(boundary, side_effect=AssertionError("External operation forbidden")))
            self.addCleanup(forbidden.assert_not_called)
        self.job = {**target(), "state": "Preparing", "started": True, "attempts": 1,
                    "topology_digest": hashlib.sha256(TOPOLOGY).hexdigest()}
        self.register = Mock()

    def work(self):
        self.assertTrue(ztp._LOCK.acquire(blocking=False))
        lock_file = (self.root / "operation.lock").open("w+")
        password_holder = ["synthetic-recovery-do-not-log"]
        ztp._work(self.job, password_holder, self.register, lock_file)
        self.assertEqual(password_holder, [])
        self.assertFalse(ztp._LOCK.locked())
        self.assertTrue(lock_file.closed)
        result = ztp.status(self.job["job_id"])
        self.assertNotIn("synthetic-recovery-do-not-log", json.dumps(result))
        return result

    def test_registration_happens_only_after_verification_and_remains_pending_for_fleet_operations(self):
        self.verify.side_effect = lambda record: (self.register.assert_not_called() is None)
        result = self.work()
        self.assertEqual(result["state"], "Ready")
        self.register.assert_called_once()
        record = self.register.call_args.args[0]
        self.assertEqual(record["onboarding"]["status"], "pending")
        self.assertEqual(record["onboarding"]["ztp_status"], "ready")
        self.assertEqual(record["management"]["ipv4"], "172.20.20.32")
        self.assertIn("verified_at", record["onboarding"])
        self.assertEqual([call.args[0] for call in self.helper.call_args_list],
                         ["preview", "reload-dhcp", "deploy", "attach"])
        self.clear.assert_called_once_with("R8", runtime=self.runtime)
        saved = yaml.safe_load(self.topology.read_bytes())
        self.assertEqual(saved["topology"]["nodes"]["R8"]["mgmt-ipv4"], record["management"]["ipv4"])
        saved["topology"]["nodes"].pop("R8")
        saved["topology"]["links"].pop()
        self.assertEqual(saved, yaml.safe_load(TOPOLOGY))

    def test_unsafe_plan_blocks_rendering_registration_and_topology_changes(self):
        self.helper.side_effect = ztp.ZtpError("Unsafe deployment plan rejected.")
        result = self.work()
        self.assertEqual(result["state"], "Failed")
        self.render.assert_not_called()
        self.publish.assert_not_called()
        self.verify.assert_not_called()
        self.register.assert_not_called()
        self.assertEqual(self.topology.read_bytes(), TOPOLOGY)

    def test_publication_window_starts_after_deploy_before_bootstrap_attachment(self):
        def operation(action, request):
            if action == "deploy":
                self.publish.assert_not_called()
            if action == "attach":
                self.publish.assert_called_once_with("R8", runtime=self.runtime, seconds=300)
            return {"ok": True}
        self.helper.side_effect = operation
        self.assertEqual(self.work()["state"], "Ready")
        self.publish.reset_mock()
        self.register.reset_mock()
        def failed_deploy(action, request):
            if action == "deploy":
                raise ztp.ZtpError("Deployment failed.")
            return {"ok": True}
        self.helper.side_effect = failed_deploy
        self.assertEqual(self.work()["state"], "Failed")
        self.publish.assert_not_called()
        self.register.assert_not_called()

    def test_changed_inventory_ip_reservation_blocks_before_credentials_or_deployment(self):
        records = inventory()
        records["devices"]["New-Inventory-Only"] = {"hostname": "New-Inventory-Only",
                                                 "management": {"ipv4": "172.20.20.32"}}
        self.inventory.write_text(yaml.safe_dump(records))
        original = self.inventory.read_bytes()
        result = self.work()
        self.assertEqual(result["state"], "Failed")
        self.render.assert_not_called()
        self.publish.assert_not_called()
        self.register.assert_not_called()
        self.assertNotIn("deploy", [call.args[0] for call in self.helper.call_args_list])
        self.assertEqual(self.inventory.read_bytes(), original)
        self.assertEqual(self.topology.read_bytes(), TOPOLOGY)

    def test_verification_timeout_cleans_only_target_and_never_registers_or_reports_ready(self):
        self.verify.return_value = False
        with patch.object(ztp.time, "monotonic", side_effect=(1000, 1000, 1300)), patch.object(ztp.time, "sleep"):
            result = self.work()
        self.assertEqual(result["state"], "Failed")
        self.assertIn("timed out", result["message"])
        self.register.assert_not_called()
        self.verify.assert_called_once()
        self.clear.assert_called_once_with("R8", runtime=self.runtime)
        self.assertNotIn("R8", yaml.safe_load(self.inventory.read_bytes())["devices"])

    def test_external_errors_are_sanitized_and_cleanup_failure_cannot_report_ready(self):
        self.verify.side_effect = RuntimeError("synthetic-recovery-do-not-log $6$sensitivehash")
        result = self.work()
        self.assertEqual(result["state"], "Failed")
        self.assertNotIn("$6$", result["message"])
        self.register.assert_not_called()
        self.clear.assert_called_once_with("R8", runtime=self.runtime)
        self.verify.side_effect = None
        self.clear.side_effect = OSError("synthetic-recovery-do-not-log")
        result = self.work()
        self.assertEqual(result["state"], "Failed")
        self.assertIn("cleanup failed", result["message"])


class ZtpSshVerificationTests(unittest.TestCase):
    def setUp(self):
        self.record = ztp.build_record(target())
        self.output = ("hostname R8\n!\ninterface Management0\n ip address 172.20.20.32/24\n!\n"
                       "username admin privilege 15 role network-admin secret sha512 $6$synthetic\n"
                       "username netpilot-recovery privilege 15 role network-admin secret sha512 $6$synthetic\nend\n")
        self.credentials = self.enterContext(patch.object(ztp.credential_provider, "get_credentials",
                                                        return_value=("admin", "synthetic-password")))
        self.connection = Mock()
        self.connection.check_enable_mode.return_value = True
        self.connection.send_command.return_value = self.output
        self.connect = self.enterContext(patch.object(ztp, "ConnectHandler", return_value=self.connection))
        for boundary in ("subprocess.run", "socket.create_connection", "security.credential_provider._read_token"):
            forbidden = self.enterContext(patch(boundary, side_effect=AssertionError("External operation forbidden")))
            self.addCleanup(forbidden.assert_not_called)

    def test_both_running_and_saved_identity_management_and_admin_access_are_required(self):
        self.assertTrue(ztp.verify_device(self.record))
        self.assertEqual([call.args[0] for call in self.connection.send_command.call_args_list],
                         ["show running-config", "show startup-config"])
        self.assertEqual(self.connect.call_args.kwargs["host"], "172.20.20.32")
        self.assertEqual(self.connect.call_args.kwargs["username"], "admin")
        self.assertIsNone(self.connect.call_args.kwargs["session_log"])
        self.connection.disconnect.assert_called_once()

    def test_old_startup_wrong_hostname_management_or_missing_admin_evidence_never_verify(self):
        for invalid in ("", self.output.replace("hostname R8", "hostname R80"),
                        self.output.replace("172.20.20.32/24", "172.20.20.33/24"),
                        self.output.replace("username admin privilege 15", "username admin privilege 1"),
                        self.output.replace("username netpilot-recovery", "username different-recovery"),
                        self.output.removesuffix("end\n")):
            with self.subTest(invalid=invalid):
                self.connection.send_command.side_effect = [self.output, invalid]
                self.assertFalse(ztp.verify_device(self.record))
        self.assertEqual(self.connection.disconnect.call_count, 6)

    def test_banner_text_cannot_supply_false_management_or_account_evidence(self):
        wrong_management = self.output.replace("172.20.20.32/24", "172.20.20.99/24")
        self.connection.send_command.return_value = ("banner login\n" + self.output + "EOF\n" + wrong_management)
        self.assertFalse(ztp.verify_device(self.record))
        self.connection.disconnect.assert_called_once()

    def test_connection_and_authorization_failures_are_unavailable_without_false_success(self):
        self.connect.side_effect = RuntimeError("synthetic-password")
        self.assertFalse(ztp.verify_device(self.record))
        self.connect.side_effect = None
        self.connection.check_enable_mode.return_value = False
        self.assertFalse(ztp.verify_device(self.record))
        self.connection.send_command.assert_not_called()
        self.connection.disconnect.assert_called_once()


if __name__ == "__main__":
    unittest.main()

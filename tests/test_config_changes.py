"""Fixture-only tests: these never connect to a device or edit real NSOT."""

from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

import yaml

import config_changes as changes


INVENTORY = """# Preserve this header exactly.
metadata:
  custom: keep-me
network:
  defaults:
    vendor: Arista
    platform: cEOSLab
devices:
  R1:
    hostname: R1
    management:
      interface: Management0
      ipv4: 192.0.2.1
    interfaces:
      Ethernet2:
        description: old description # keep this comment
        admin_state: up
        ipv4: [10.0.0.1/30]
        ipv6: []
        unknown: preserve-this
      Management0:
        description: null
        admin_state: up
        ipv4: [192.0.2.1/24]
    routing:
      untouched: 'exact formatting'
  R2:
    management:
      ipv4: 192.0.2.2
    interfaces:
      Loopback01:
        ipv4: [10.255.2.1/32]
"""
BEFORE = """! EOS fixture
hostname R1
interface Ethernet2
   description old description
   no shutdown
!
interface Management0
   no shutdown
!
end
"""


class ConfigChangesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.inventory_path = self.root / "inventory" / "devices.yml"
        self.inventory_path.parent.mkdir()
        self.inventory_path.write_text(INVENTORY)
        self.golden = self.root / "golden_configs"
        self.history = self.root / "config_changes" / "change_history.json"
        self.patches = [
            patch.object(changes, "INVENTORY_PATH", self.inventory_path),
            patch.object(changes, "GOLDEN_CONFIGS_PATH", self.golden),
            patch.object(changes, "HISTORY_PATH", self.history),
            patch.dict(os.environ, {"NETPILOT_USERNAME": "fixture-user", "NETPILOT_PASSWORD": "fixture-password"}),
            patch.object(changes, "ConnectHandler"),
        ]
        for item in self.patches:
            item.start()
        self.connection = changes.ConnectHandler.return_value
        self.connection.check_enable_mode.return_value = True
        self.connection.send_config_set.return_value = "interface Ethernet2\ndescription new description\nR1(config)#"
        self.connection.send_command.side_effect = [BEFORE, BEFORE, BEFORE.replace("old description", "new description")]
        self.form = {"device": "R1", "change_type": "interface_description", "interface": "Ethernet2", "new_description": "new description"}

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def preview(self, **fields):
        return changes.validate_change(dict(self.form, **fields))

    def loopback(self, **fields):
        return self.preview(change_type="create_loopback", loopback_id="10", ipv4="10.255.3.1", **fields)

    def assert_unchanged(self):
        self.assertEqual(self.inventory_path.read_text(), INVENTORY)

    def test_preview_is_canonical_and_does_not_connect(self):
        preview = self.preview()
        self.assertEqual(preview["generated_commands"], ["interface Ethernet2", "description new description"])
        self.assertEqual(preview["old_value"], "old description")
        self.assertEqual(len(preview["change_id"]), 32)
        self.assertEqual(set(preview["request"]), {"device", "change_type", "interface", "new_description"})
        changes.ConnectHandler.assert_not_called()
        self.assertFalse(self.history.exists())
        self.assert_unchanged()

    def test_exactly_three_changes_supported(self):
        self.assertEqual(set(changes.SUPPORTED_CHANGES), {"interface_description", "interface_admin_state", "create_loopback"})
        with self.assertRaises(changes.ChangeError):
            self.preview(change_type="raw_cli")

    def test_unknown_device_and_interface_rejected(self):
        for fields in ({"device": "missing"}, {"device": "../R1"}, {"interface": "Ethernet999"}, {"interface": "Ethernet2\nrouter bgp 1"}):
            with self.subTest(fields=fields), self.assertRaises(changes.ChangeError):
                self.preview(**fields)

    def test_description_validation(self):
        for description in ("", "   ", "one\ntwo", "one\rtwo", "x\x1by", "one;two", "one|two", "test?", "!", "x" * 241,
                            "one\u2028two", "one\u0085two", "one\u2029two"):
            with self.subTest(description=repr(description)), self.assertRaises(changes.ChangeError):
                self.preview(new_description=description)
        self.assertEqual(self.preview(new_description=" CORE-LINK-TO-S4 ")["new_value"], "CORE-LINK-TO-S4")

    def test_admin_state_exact_values_and_management_protection(self):
        for value in ("UP", "Up", "down\nend", "enabled", " up "):
            with self.subTest(value=value), self.assertRaises(changes.ChangeError):
                self.preview(change_type="interface_admin_state", new_admin_state=value)
        with self.assertRaisesRegex(changes.ChangeError, "management"):
            self.preview(change_type="interface_admin_state", interface="Management0", new_admin_state="down")
        self.assertEqual(self.preview(change_type="interface_admin_state", new_admin_state="down")["generated_commands"][-1], "shutdown")
        self.assertEqual(self.preview(change_type="interface_admin_state", new_admin_state="up")["generated_commands"][-1], "no shutdown")

    def test_loopback_defaults_and_commands(self):
        preview = self.loopback(description="NetPilot Loopback")
        self.assertEqual(preview["generated_commands"], ["interface Loopback10", "description NetPilot Loopback", "ip address 10.255.3.1/32", "no shutdown"])
        self.assertEqual(self.loopback()["new_value"]["description"], None)
        self.assertEqual(self.loopback(prefix_length="0")["new_value"]["ipv4"], ["10.255.3.1/0"])

    def test_loopback_validation_and_duplicate_addresses(self):
        for fields in ({"loopback_id": "-1"}, {"loopback_id": "1.5"}, {"loopback_id": "1001"},
                       {"ipv4": "300.1.2.3"}, {"ipv4": "2001:db8::1"}, {"ipv4": "1.2.3.4/32"},
                       {"prefix_length": "33"}, {"prefix_length": "-1"}, {"prefix_length": "1.1"},
                       {"ipv4": "192.0.2.2"}, {"ipv4": "10.255.2.1"}, {"ipv4": "10.0.0.1"}):
            with self.subTest(fields=fields), self.assertRaises(changes.ChangeError):
                form = dict(self.form, change_type="create_loopback", loopback_id="10", ipv4="10.255.3.1")
                changes.validate_change(dict(form, **fields))

    def test_loopback_existing_normalizes_case_and_leading_zeros(self):
        form = dict(self.form, device="R2", change_type="create_loopback", loopback_id="001", ipv4="10.255.3.1")
        with self.assertRaisesRegex(changes.ChangeError, "already exists"):
            changes.validate_change(form)

    def test_ipv4_reference_in_unknown_field_is_not_assigned(self):
        self.inventory_path.write_text(INVENTORY + "extra: 'peer 198.51.100.9<->198.51.100.10'\n")
        preview = self.preview(change_type="create_loopback", loopback_id="10", ipv4="198.51.100.10")
        self.assertIn("ip address 198.51.100.10/32", preview["generated_commands"])

    def test_assigned_ip_collector_uses_only_management_and_interface_hosts(self):
        inventory = yaml.safe_load(INVENTORY)
        r1 = inventory["devices"]["R1"]
        r1["management"]["ipv4_prefix"] = "192.0.2.1/24"
        r1["interfaces"]["Ethernet2"]["ipv4"] = ["10.1.33.1/30", "10.1.33.1/32"]
        r1["interfaces"]["Ethernet3"] = {"ipv4": ["10.1.33.1/30", "bad-value", "2001:db8::1/64"]}
        inventory["devices"]["R2"]["management"]["ipv4_prefix"] = "192.0.2.3/24"
        r1["routing"] = {"ospf": {"networks": ["10.1.33.0/30"]},
                         "bgp": {"networks": ["203.0.113.0/24"], "neighbors": ["10.1.33.2"]}}
        r1["prefix_lists"] = {"ignored": ["10.255.1.1/32"]}
        r1["interfaces"]["Ethernet2"]["peer"] = {"ipv4": "10.1.33.2/30"}
        inventory["network"]["ipv4"] = "203.0.113.9"
        inventory["endpoints"] = {"server": {"ipv4": "198.51.100.2", "ipv4_subnet": "198.51.100.0/24"}}
        self.assertEqual(changes.collect_assigned_ipv4_addresses(inventory), {
            "192.0.2.1": ["R1:Management0"],
            "10.1.33.1": ["R1:Ethernet2", "R1:Ethernet3"],
            "192.0.2.2": ["R2:Management"],
            "192.0.2.3": ["R2:Management"],
            "10.255.2.1": ["R2:Loopback01"],
        })

    def test_exact_duplicate_fails_but_unused_hosts_and_routing_references_pass(self):
        inventory = yaml.safe_load(INVENTORY)
        r1 = inventory["devices"]["R1"]
        r1["interfaces"]["Ethernet2"]["ipv4"] = ["10.1.33.1/30"]
        r1["routing"] = {"ospf_network": "10.1.33.0/30", "bgp_network": "10.255.1.1/32",
                         "neighbor": "10.1.33.2", "router_id": "10.255.1.1"}
        inventory["network"]["ipam"] = ["10.1.33.0/30"]
        inventory["endpoints"] = {"ipv4_subnet": "10.255.1.0/24"}
        self.inventory_path.write_text(yaml.safe_dump(inventory, sort_keys=False))
        with self.assertRaisesRegex(changes.ChangeError, "10.1.33.1 is already assigned to R1 Ethernet2"):
            self.preview(change_type="create_loopback", loopback_id="1", ipv4="10.1.33.1")
        for address in ("10.1.33.2", "10.1.33.0", "10.255.1.1"):
            with self.subTest(address=address):
                preview = self.preview(change_type="create_loopback", loopback_id="1", ipv4=address)
                self.assertIn(f"ip address {address}/32", preview["generated_commands"])
        changes.ConnectHandler.assert_not_called()
        self.assertFalse(self.history.exists())

    def test_same_loopback_id_on_another_device_is_allowed(self):
        preview = self.preview(change_type="create_loopback", loopback_id="1", ipv4="10.255.1.1")
        self.assertEqual(preview["interface"], "Loopback1")
        self.assertEqual(preview["device"], "R1")
        inventory = yaml.safe_load(INVENTORY)
        inventory["devices"]["R1"]["interfaces"]["Loopback1"] = {"ipv4": ["10.255.8.1/32"]}
        self.inventory_path.write_text(yaml.safe_dump(inventory, sort_keys=False))
        with self.assertRaisesRegex(changes.ChangeError, "Loopback1 already exists on R1"):
            self.preview(change_type="create_loopback", loopback_id="1", ipv4="10.255.1.1")

    def test_duplicate_yaml_keys_rejected(self):
        self.inventory_path.write_text(INVENTORY + "devices: {}\n")
        with self.assertRaises(changes.ChangeError):
            self.preview()

    def test_non_arista_device_rejected(self):
        self.inventory_path.write_text(INVENTORY.replace("vendor: Arista", "vendor: Cisco"))
        with self.assertRaisesRegex(changes.ChangeError, "Arista"):
            self.preview()

    def test_success_backs_up_then_applies_verifies_updates_and_logs(self):
        preview = self.preview()
        result = changes.apply_change(preview)
        self.assertIsNone(result["error"], result)
        self.assertEqual((result["backup_status"], result["apply_status"], result["verification_status"], result["nsot_status"]),
                         ("saved", "applied", "passed", "updated"))
        self.connection.send_config_set.assert_called_once_with(preview["generated_commands"], read_timeout=60)
        backup = Path(result["backup_file"])
        self.assertIn("prechange", backup.name)
        self.assertIn(BEFORE, backup.read_text())
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.inventory_path.read_text(), INVENTORY.replace("old description #", '"new description" #'))
        inventory_backups = list((self.inventory_path.parent / "backups").glob("*.yml"))
        self.assertEqual(len(inventory_backups), 1)
        self.assertEqual(inventory_backups[0].read_text(), INVENTORY)
        history = changes.recent_changes()
        self.assertEqual(history, [result])
        self.assertNotIn("fixture-password", self.history.read_text())
        self.connection.disconnect.assert_called_once()

    def test_admin_down_verifies_explicit_admin_config(self):
        self.connection.send_command.side_effect = [BEFORE, BEFORE, BEFORE.replace("   no shutdown", "   shutdown", 1)]
        result = changes.apply_change(self.preview(change_type="interface_admin_state", new_admin_state="down"))
        self.assertEqual(result["verification_status"], "passed", result)
        self.assertEqual(yaml.safe_load(self.inventory_path.read_text())["devices"]["R1"]["interfaces"]["Ethernet2"]["admin_state"], "down")

    def test_missing_explicit_admin_state_fails_before_apply(self):
        self.connection.send_command.side_effect = [BEFORE, BEFORE.replace("   no shutdown\n", "")]
        result = changes.apply_change(self.preview(change_type="interface_admin_state", new_admin_state="up"))
        self.assertIn("could not be confirmed", result["error"])
        self.connection.send_config_set.assert_not_called()
        self.assert_unchanged()

    def test_live_loopback_creation_and_narrow_yaml_insertion(self):
        after = BEFORE.replace("end\n", "interface Loopback10\n   description Test loopback\n   ip address 10.255.3.1/32\n   no shutdown\n!\nend\n")
        self.connection.send_command.side_effect = [BEFORE, BEFORE, after]
        result = changes.apply_change(self.loopback(description="Test loopback"))
        self.assertEqual(result["nsot_status"], "updated", result)
        content = self.inventory_path.read_text()
        self.assertIn("    routing:\n      untouched: 'exact formatting'", content)
        self.assertIn("        unknown: preserve-this", content)
        data = yaml.safe_load(content)
        self.assertEqual(data["devices"]["R1"]["interfaces"]["Loopback10"]["ipv4"], ["10.255.3.1/32"])

    def test_live_loopback_exists_aborts_before_apply(self):
        self.connection.send_command.side_effect = [BEFORE, BEFORE + "interface Loopback010\n   no shutdown\n!\n"]
        result = changes.apply_change(self.loopback())
        self.assertIn("already exists on the live device", result["error"])
        self.connection.send_config_set.assert_not_called()
        self.assert_unchanged()

    def test_empty_interfaces_map_can_receive_loopback_without_losing_comments(self):
        source = """network:
  defaults: {vendor: Arista, platform: cEOSLab}
devices:
  R1:
    management: {ipv4: 192.0.2.1}
    interfaces: {} # retain map comment
    custom: keep-this
"""
        self.inventory_path.write_text(source)
        preview = self.loopback()
        updated = changes._prepare_inventory_update(source.encode(), changes.load_inventory(), preview).decode()
        self.assertIn("# retain map comment", updated)
        self.assertIn("    custom: keep-this\n", updated)
        self.assertEqual(yaml.safe_load(updated)["devices"]["R1"]["interfaces"]["Loopback10"], preview["new_value"])

    def test_empty_interface_record_can_receive_description(self):
        source = """network:
  defaults: {vendor: Arista, platform: cEOSLab}
devices:
  R1:
    management: {ipv4: 192.0.2.1}
    interfaces:
      Ethernet2: {} # preserve empty record comment
    custom: keep-this
"""
        self.inventory_path.write_text(source)
        preview = self.preview()
        updated = changes._prepare_inventory_update(source.encode(), changes.load_inventory(), preview).decode()
        self.assertIn("# preserve empty record comment", updated)
        self.assertEqual(yaml.safe_load(updated)["devices"]["R1"]["interfaces"]["Ethernet2"]["description"], "new description")

    def test_error_words_inside_description_echo_are_not_cli_failures(self):
        description = "link failed to recover; error: cable; permission denied"
        # Semicolons are deliberately disallowed; natural language error words are not.
        description = description.replace(";", ",")
        after = BEFORE.replace("old description", description)
        self.connection.send_command.side_effect = [BEFORE, BEFORE, after]
        self.connection.send_config_set.return_value = f"interface Ethernet2\ndescription {description}\nR1(config)#"
        result = changes.apply_change(self.preview(new_description=description))
        self.assertEqual(result["nsot_status"], "updated", result)

    def test_incomplete_running_config_cannot_confirm_loopback_absence(self):
        for response in ("hostname R1\nend\n", BEFORE.removesuffix("end\n")):
            with self.subTest(response=response):
                self.connection.send_command.side_effect = [BEFORE, response]
                result = changes.apply_change(self.loopback())
                self.assertIsNotNone(result["error"])
                self.assertEqual(result["apply_status"], "not_attempted")
        self.connection.send_config_set.assert_not_called()
        self.assert_unchanged()

    def test_nsot_directory_sync_failure_reports_committed_update(self):
        original_atomic = changes._atomic_write

        def failed_directory_sync(path, data, **kwargs):
            original_atomic(path, data, **kwargs)
            return Path(path) != self.inventory_path

        with patch.object(changes, "_atomic_write", side_effect=failed_directory_sync):
            result = changes.apply_change(self.preview())
        self.assertEqual(result["nsot_status"], "updated", result)
        self.assertIn("durability could not be confirmed", result["error"])
        self.assertEqual(yaml.safe_load(self.inventory_path.read_text())["devices"]["R1"]["interfaces"]["Ethernet2"]["description"], "new description")

    def test_missing_live_interface_aborts(self):
        self.connection.send_command.side_effect = [BEFORE, BEFORE.replace("interface Ethernet2", "interface Ethernet3")]
        result = changes.apply_change(self.preview())
        self.assertIn("could not be confirmed", result["error"])
        self.connection.send_config_set.assert_not_called()
        self.assert_unchanged()

    def test_backup_failure_gates_apply_and_hides_raw_errors(self):
        with patch.object(changes, "_save_prechange_backup", side_effect=OSError("private-secret")):
            result = changes.apply_change(self.preview())
        self.assertEqual(result["backup_status"], "failed")
        self.assertNotIn("private-secret", json.dumps(result))
        self.connection.send_config_set.assert_not_called()
        self.assert_unchanged()

    def test_empty_or_error_backup_response_gates_apply(self):
        for response in ("", "% Invalid input", "username fixture-password"):
            with self.subTest(response=response):
                self.connection.send_command.side_effect = [response]
                result = changes.apply_change(self.preview())
                self.assertEqual(result["backup_status"], "failed")
        self.connection.send_config_set.assert_not_called()
        self.assert_unchanged()

    def test_verification_failure_never_updates_inventory(self):
        self.connection.send_command.side_effect = [BEFORE, BEFORE, BEFORE]
        result = changes.apply_change(self.preview())
        self.assertEqual(result["apply_status"], "applied")
        self.assertEqual(result["verification_status"], "failed")
        self.assertEqual(result["nsot_status"], "not_attempted")
        self.assert_unchanged()

    def test_partial_command_error_remains_unknown(self):
        self.connection.send_config_set.return_value = "interface Ethernet2\n% Invalid input (fixture-password)"
        result = changes.apply_change(self.preview())
        self.assertEqual(result["apply_status"], "unknown")
        self.assertEqual(result["verification_status"], "not_attempted")
        self.assertNotIn("fixture-password", json.dumps(result))
        self.assert_unchanged()

    def test_send_timeout_remains_unknown(self):
        self.connection.send_config_set.side_effect = TimeoutError("fixture-password")
        result = changes.apply_change(self.preview())
        self.assertEqual(result["apply_status"], "unknown")
        self.assertNotIn("fixture-password", json.dumps(result))
        self.assert_unchanged()

    def test_missing_credentials_does_not_connect(self):
        with patch.dict(os.environ, {}, clear=True):
            result = changes.apply_change(self.preview())
        self.assertIn("credentials are not currently available", result["error"])
        changes.ConnectHandler.assert_not_called()

    def test_stale_inventory_does_not_connect(self):
        preview = self.preview()
        self.inventory_path.write_text(INVENTORY + "# edited after preview\n")
        result = changes.apply_change(preview)
        self.assertIn("inventory changed after preview", result["error"])
        changes.ConnectHandler.assert_not_called()

    def test_expired_and_tampered_previews_do_not_connect(self):
        preview = self.preview()
        preview["created_at"] = time.time() - 601
        self.assertIn("expired", changes.apply_change(preview)["error"])
        preview = self.preview()
        preview["generated_commands"] = ["router bgp 65001"]
        self.assertIn("no longer matches", changes.apply_change(preview)["error"])
        changes.ConnectHandler.assert_not_called()

    def test_unrelated_inventory_anchors_preserved_without_connection(self):
        source = INVENTORY.replace("metadata:", "metadata: &meta") + "copied_metadata: *meta\n"
        self.inventory_path.write_text(source)
        preview = self.preview()
        updated = changes._prepare_inventory_update(source.encode(), changes.load_inventory(), preview)
        self.assertEqual(updated.decode(), source.replace("old description #", '"new description" #'))
        self.assertEqual(self.inventory_path.read_text(), source)
        changes.ConnectHandler.assert_not_called()

    def test_temporary_inventory_is_validated_before_atomic_replacement(self):
        preview = self.preview()
        original = self.inventory_path.read_bytes()
        updated = changes._prepare_inventory_update(original, changes.load_inventory(), preview)
        original_validate = changes._validate_inventory_update
        validations = []

        def validate(content, expected):
            validations.append(content)
            original_validate(content, expected)
            # The original remains in place both before backup and while checking
            # the on-disk temporary candidate just before its atomic replacement.
            self.assertEqual(self.inventory_path.read_bytes(), original)
            if len(validations) == 2:
                candidates = list(self.inventory_path.parent.glob(".devices.yml-*"))
                self.assertEqual(len(candidates), 1)
                self.assertEqual(candidates[0].read_bytes(), content)
                backups = list((self.inventory_path.parent / "backups").glob("*.yml"))
                self.assertEqual(len(backups), 1)
                self.assertEqual(backups[0].read_bytes(), original)

        with patch.object(changes, "_validate_inventory_update", side_effect=validate):
            changes._update_inventory(original, updated, preview)
        self.assertEqual(validations, [updated, updated])
        self.assertEqual(self.inventory_path.read_bytes(), updated)
        changes.ConnectHandler.assert_not_called()

    def test_invalid_temporary_inventory_cannot_replace_original(self):
        expected = yaml.safe_load(INVENTORY)
        with self.assertRaises(changes.ChangeError):
            changes._atomic_write(self.inventory_path, b"devices: {}\n", validate=lambda path:
                                  changes._validate_inventory_update(path.read_bytes(), expected))
        self.assert_unchanged()
        self.assertFalse(list(self.inventory_path.parent.glob(".devices.yml-*")))

    def test_history_failure_gates_ssh(self):
        with patch.object(changes, "log_change", side_effect=changes.ChangeError("Change history unavailable.")):
            result = changes.apply_change(self.preview())
        self.assertIn("history unavailable", result["error"])
        changes.ConnectHandler.assert_not_called()

    def test_corrupt_history_gates_ssh(self):
        self.history.parent.mkdir()
        self.history.write_text("broken json")
        result = changes.apply_change(self.preview())
        self.assertIn("history could not be read", result["error"])
        changes.ConnectHandler.assert_not_called()

    def test_durable_claim_prevents_replay_after_failed_attempt(self):
        preview = self.preview()
        self.connection.send_command.side_effect = ["empty invalid response"]
        first = changes.apply_change(preview)
        self.assertEqual(first["backup_status"], "failed")
        second = changes.apply_change(preview)
        self.assertIn("already been submitted", second["error"])
        changes.ConnectHandler.assert_called_once()

    def test_pending_claim_prevents_replay_after_restart(self):
        preview = self.preview()
        self.history.parent.mkdir()
        self.history.write_text(json.dumps([{"change_id": preview["change_id"], "apply_status": "unknown"}]))
        result = changes.apply_change(preview)
        self.assertIn("already been submitted", result["error"])
        changes.ConnectHandler.assert_not_called()

    def test_final_history_failure_reports_warning_without_false_nsot_failure(self):
        original_log = changes.log_change

        def failing_final(result, claim=False):
            if claim:
                return original_log(result, claim=True)
            raise changes.ChangeError("history write failed")

        with patch.object(changes, "log_change", side_effect=failing_final):
            result = changes.apply_change(self.preview())
        self.assertEqual(result["nsot_status"], "updated")
        self.assertIn("Final change history could not be saved", result["error"])
        self.assertEqual(changes.recent_changes()[0]["apply_status"], "unknown")

    def test_editor_change_after_apply_is_not_overwritten(self):
        def concurrent_edit(commands, **kwargs):
            self.inventory_path.write_text(INVENTORY + "# external edit\n")
            return "configuration commands accepted"

        self.connection.send_config_set.side_effect = concurrent_edit
        result = changes.apply_change(self.preview())
        self.assertEqual(result["verification_status"], "passed")
        self.assertEqual(result["nsot_status"], "failed")
        self.assertTrue(self.inventory_path.read_text().endswith("# external edit\n"))

    def test_history_and_backup_symlinks_rejected(self):
        self.history.parent.symlink_to(self.inventory_path.parent, target_is_directory=True)
        result = changes.apply_change(self.preview())
        self.assertIsNotNone(result["error"])
        changes.ConnectHandler.assert_not_called()
        self.assert_unchanged()


if __name__ == "__main__":
    unittest.main()

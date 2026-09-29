"""Alias regression checks using temporary inventories only; no live Apply calls."""

import hashlib
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

import config_changes as changes


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REAL_INVENTORY = PROJECT_ROOT / "inventory" / "devices.yml"
REQUIRED_KEYS = {"metadata", "network", "routing_domains", "devices", "endpoints", "validation_notes"}
REAL_DEVICES = {"R1", "R2", "R3", "R4", "R5", "S1", "S2", "S3", "S4"}


def independent_values(value):
    """Copy values per path, deliberately breaking YAML alias object identity."""
    if isinstance(value, dict):
        return {key: independent_values(child) for key, child in value.items()}
    if isinstance(value, list):
        return [independent_values(child) for child in value]
    return value


class InventoryAliasRegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.inventory_path = self.root / "inventory" / "devices.yml"
        self.inventory_path.parent.mkdir()
        self.real_digest = hashlib.sha256(REAL_INVENTORY.read_bytes()).hexdigest()
        self.patches = [
            patch.object(changes, "INVENTORY_PATH", self.inventory_path),
            patch.object(changes, "GOLDEN_CONFIGS_PATH", self.root / "golden_configs"),
            patch.object(changes, "HISTORY_PATH", self.root / "config_changes" / "change_history.json"),
            patch.object(changes, "ConnectHandler", side_effect=AssertionError("SSH is forbidden in inventory regression tests.")),
            patch.object(socket.socket, "connect", side_effect=AssertionError("Networking is forbidden in inventory regression tests.")),
            patch.object(changes, "_save_prechange_backup", side_effect=AssertionError("Preview must not make device backups.")),
            patch.object(changes, "log_change", side_effect=AssertionError("Preview must not write change history.")),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self):
        try:
            self.assertEqual(hashlib.sha256(REAL_INVENTORY.read_bytes()).hexdigest(), self.real_digest,
                             "A test unexpectedly changed the real inventory.")
            changes.ConnectHandler.assert_not_called()
            changes._save_prechange_backup.assert_not_called()
            changes.log_change.assert_not_called()
        finally:
            for item in reversed(self.patches):
                item.stop()
            self.temp.cleanup()

    def _prepare(self, source, form):
        self.inventory_path.write_bytes(source)
        preview = changes.validate_change(form)
        # Preview itself must leave every storage target untouched.
        self.assertEqual(self.inventory_path.read_bytes(), source)
        self.assertFalse((self.root / "golden_configs").exists())
        self.assertFalse((self.root / "config_changes").exists())
        self.assertFalse((self.inventory_path.parent / "backups").exists())
        original = yaml.safe_load(source)
        original_values = independent_values(original)
        updated = changes._prepare_inventory_update(source, original, preview)
        self.assertEqual(original, original_values, "The serialization helper mutated its input inventory.")
        self.assertEqual(self.inventory_path.read_bytes(), source, "Preparing an update must not write inventory.")
        expected = independent_values(original_values)
        interfaces = expected["devices"][preview["device"]]["interfaces"]
        if preview["change_type"] == "create_loopback":
            interfaces[preview["interface"]] = independent_values(preview["new_value"])
        else:
            field = "description" if preview["change_type"] == "interface_description" else "admin_state"
            interfaces[preview["interface"]][field] = preview["new_value"]
        self.assertEqual(yaml.safe_load(updated), expected,
                         "A YAML update changed more than its intended dictionary path.")
        return preview, original, updated

    def _assert_renderable(self, updated, directory_name):
        modified = self.root / f"{directory_name}.yml"
        modified.write_bytes(updated)
        output = self.root / directory_name
        completed = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "render_configs.py"),
             "--inventory", str(modified), "--template-dir", str(PROJECT_ROOT / "templates"),
             "--output-dir", str(output)],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(completed.returncode, 0, "Existing renderer failed against a temporary updated inventory.")
        devices = yaml.safe_load(updated)["devices"]
        self.assertEqual({path.stem for path in output.glob("*.cfg")}, set(devices))
        self.assertTrue(all(path.stat().st_size > 0 for path in output.glob("*.cfg")))

    def test_current_anchored_inventory_all_three_changes_preserve_data_and_render(self):
        source = REAL_INVENTORY.read_bytes()
        tokens = list(yaml.scan(source))
        self.assertGreater(sum(isinstance(token, yaml.AnchorToken) for token in tokens), 0)
        self.assertGreater(sum(isinstance(token, yaml.AliasToken) for token in tokens), 0)
        inventory = yaml.safe_load(source)
        # Add an unknown field only to the temporary copy to prove it survives.
        source += b"\nregression_unknown_field:\n  keep_exact_values: [alpha, null, 17]\n"
        assigned = {str(item).split("/")[0]
                    for device in inventory["devices"].values()
                    for interface in device.get("interfaces", {}).values()
                    for item in interface.get("ipv4", [])}
        candidate_ip = next(f"198.18.255.{last}" for last in range(1, 255)
                            if f"198.18.255.{last}" not in assigned)
        loopback_id = next(number for number in range(1, changes.MAX_LOOPBACK_ID + 1)
                           if f"Loopback{number}" not in inventory["devices"]["R1"]["interfaces"])
        requests = [
            {"device": "R1", "change_type": "interface_description", "interface": "Ethernet1",
             "new_description": "Alias regression description"},
            {"device": "R1", "change_type": "interface_admin_state", "interface": "Ethernet1",
             "new_admin_state": "down"},
            {"device": "R1", "change_type": "create_loopback", "loopback_id": str(loopback_id),
             "ipv4": candidate_ip, "prefix_length": "32", "description": "Alias regression loopback"},
        ]
        for form in requests:
            with self.subTest(change_type=form["change_type"]):
                _, original, updated = self._prepare(source, form)
                result = yaml.safe_load(updated)
                self.assertTrue(REQUIRED_KEYS.issubset(result))
                self.assertEqual(set(result["devices"]), set(original["devices"]))
                self.assertTrue(REAL_DEVICES.issubset(result["devices"]))
                self.assertEqual(result["regression_unknown_field"], original["regression_unknown_field"])
                for device in ("S1", "S2"):
                    self.assertEqual(result["devices"][device], original["devices"][device],
                                     f"{device} VLAN/SVI data must remain unchanged.")
                for hostname, device in original["devices"].items():
                    for interface, data in device.get("interfaces", {}).items():
                        self.assertEqual(result["devices"][hostname]["interfaces"][interface].get("ipv4"), data.get("ipv4"))
                        self.assertEqual(result["devices"][hostname]["interfaces"][interface].get("ipv6"), data.get("ipv6"))
                self._assert_renderable(updated, form["change_type"])

    def test_shared_interface_mapping_only_updates_selected_interface(self):
        source = b"""network:
  defaults: {vendor: Arista, platform: cEOSLab}
devices:
  R1:
    management: {interface: Management0, ipv4: 192.0.2.1}
    interfaces:
      Ethernet1: &shared_interface
        description: shared description
        admin_state: up
        ipv4: [10.1.1.1/30]
        ipv6: []
        custom_field: retain
      Ethernet2: *shared_interface
"""
        for interface in ("Ethernet1", "Ethernet2"):
            for change_type, field, value in (
                ("interface_description", "new_description", "Only selected interface"),
                ("interface_admin_state", "new_admin_state", "down"),
            ):
                with self.subTest(interface=interface, change_type=change_type):
                    _, original, updated = self._prepare(
                        source, {"device": "R1", "change_type": change_type, "interface": interface, field: value})
                    untouched = "Ethernet2" if interface == "Ethernet1" else "Ethernet1"
                    self.assertEqual(yaml.safe_load(updated)["devices"]["R1"]["interfaces"][untouched],
                                     original["devices"]["R1"]["interfaces"][untouched])

    def test_shared_scalar_does_not_change_other_interface(self):
        source = b"""network:
  defaults: {vendor: Arista, platform: cEOSLab}
devices:
  R1:
    management: {ipv4: 192.0.2.1}
    interfaces:
      Ethernet1:
        description: &shared_description original
        admin_state: up
      Ethernet2:
        description: *shared_description
        admin_state: up
"""
        for interface in ("Ethernet1", "Ethernet2"):
            with self.subTest(interface=interface):
                self._prepare(source, {"device": "R1", "change_type": "interface_description",
                                       "interface": interface, "new_description": "Only this description"})

    def test_shared_interfaces_mapping_loopback_is_device_local(self):
        source = b"""network:
  defaults: {vendor: Arista, platform: cEOSLab}
devices:
  R1:
    management: {ipv4: 192.0.2.1}
    interfaces: &shared_interfaces
      Ethernet1:
        description: existing
        admin_state: up
        ipv4: [10.1.1.1/30]
  R2:
    management: {ipv4: 192.0.2.2}
    interfaces: *shared_interfaces
"""
        for device in ("R1", "R2"):
            with self.subTest(device=device):
                _, _, updated = self._prepare(source, {
                    "device": device, "change_type": "create_loopback", "loopback_id": "1",
                    "ipv4": "10.255.1.1", "prefix_length": "32", "description": "NetPilot Loopback",
                })
                untouched = "R2" if device == "R1" else "R1"
                self.assertNotIn("Loopback1", yaml.safe_load(updated)["devices"][untouched]["interfaces"])


if __name__ == "__main__":
    unittest.main()

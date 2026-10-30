"""Pending NSOT devices cannot enter ordinary live operations.

Selection, configuration validation, Golden capture, and Flask routes execute
their real implementations; credentials, SSH, and filesystem paths are fixtures.
"""

from copy import deepcopy
import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import yaml

import app as gui
import config_changes as changes
import save_golden_configs as golden
from security import credential_provider, credential_rotation as rotation


NINE = ("R1", "R2", "R3", "R4", "R5", "S1", "S2", "S3", "S4")
PRIVATE = "synthetic-private-detail"


def device(name, address, **extra):
    return {
        "hostname": name, "vendor": "Arista", "platform": "cEOSLab",
        "role": "edge_router", "management": {"ipv4": address},
        "interfaces": {"Ethernet2": {"description": "old", "admin_state": "up"}},
        **extra,
    }


class PendingOnboardingTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.inventory_path = self.root / "devices.yml"
        self.inventory = {"devices": {
            name: device(name, f"192.0.2.{index}") for index, name in enumerate(NINE, 1)
        }}
        self.inventory["devices"].update({
            "R6": device("R6", "198.51.100.6", onboarding={"status": "pending"}),
            "R7": device("R7", "198.51.100.7", onboarding={"status": "pending"}),
        })
        self.write_inventory()
        self.enterContext(patch.object(changes, "INVENTORY_PATH", self.inventory_path))
        self.enterContext(patch.object(changes, "HISTORY_PATH", self.root / "history.json"))
        self.enterContext(patch.object(changes, "GOLDEN_CONFIGS_PATH", self.root / "backups"))
        self.enterContext(patch.object(golden, "INVENTORY_FILE", self.inventory_path))
        self.enterContext(patch.object(golden, "OUTPUT_DIR", self.root / "golden"))
        self.output = self.enterContext(patch("sys.stdout", new_callable=io.StringIO))
        self.provider = self.enterContext(patch.object(
            credential_provider, "get_credentials", side_effect=AssertionError("No real credentials")))
        self.change_connect = self.enterContext(patch.object(
            changes, "ConnectHandler", side_effect=AssertionError("No configuration SSH")))
        self.golden_connect = self.enterContext(patch.object(
            golden, "ConnectHandler", side_effect=AssertionError("No live Golden SSH")))
        for boundary in ("socket.socket.connect", "socket.create_connection", "subprocess.run",
                         "security.credential_provider._read_token"):
            guard = self.enterContext(patch(boundary, side_effect=AssertionError("External access forbidden")))
            self.addCleanup(guard.assert_not_called)

    def write_inventory(self):
        self.inventory_path.write_text(yaml.safe_dump(self.inventory, sort_keys=False), encoding="utf-8")

    def golden_main(self, *targets):
        self.provider.side_effect = None
        self.provider.return_value = ("fixture-admin", PRIVATE)
        with patch("sys.argv", ["save_golden_configs.py", *targets]):
            return golden.main()

    def test_config_selection_accepts_legacy_and_verified_devices(self):
        for name in NINE:
            self.assertIs(changes.get_device(self.inventory, name), self.inventory["devices"][name])
        self.inventory["devices"]["R6"]["onboarding"]["status"] = "verified"
        self.assertIs(changes.get_device(self.inventory, "R6"), self.inventory["devices"]["R6"])
        self.provider.assert_not_called()
        self.change_connect.assert_not_called()

    def test_pending_or_malformed_lifecycle_is_rejected_with_sanitized_errors(self):
        for onboarding in ({"status": "pending"}, None, [], {}, {"status": PRIVATE}, {"status": True}):
            with self.subTest(onboarding_type=type(onboarding).__name__):
                self.inventory["devices"]["R6"]["onboarding"] = onboarding
                with self.assertRaises(changes.ChangeError) as caught:
                    changes.get_device(self.inventory, "R6")
                self.assertIn("onboarding", str(caught.exception))
                self.assertNotIn(PRIVATE, str(caught.exception))
        self.provider.assert_not_called()
        self.change_connect.assert_not_called()

    def test_apply_cannot_bypass_pending_gate_with_a_fresh_inventory_digest(self):
        # A forged or older preview must not bypass the real lifecycle check,
        # even when its freshness and inventory digest otherwise match.
        del self.inventory["devices"]["R6"]["onboarding"]
        self.write_inventory()
        preview = changes.validate_change({
            "device": "R6", "change_type": "interface_description",
            "interface": "Ethernet2", "new_description": "fixture update",
        })
        self.inventory["devices"]["R6"]["onboarding"] = {"status": "pending"}
        self.write_inventory()
        before = self.inventory_path.read_bytes()
        preview["inventory_digest"] = hashlib.sha256(before).hexdigest()
        result = changes.apply_change(preview)
        self.assertEqual(result["apply_status"], "not_attempted")
        self.assertIn("onboarding", result["error"])
        self.assertEqual(self.inventory_path.read_bytes(), before)
        self.assertFalse((self.root / "backups").exists())
        self.provider.assert_not_called()
        self.change_connect.assert_not_called()

    def test_rotation_keeps_exact_nine_targets_with_pending_r6_r7(self):
        actual = rotation.discover_inventory(self.inventory_path)
        self.assertEqual(actual, {name: f"192.0.2.{index}" for index, name in enumerate(NINE, 1)})
        self.assertEqual(tuple(actual), NINE)
        self.provider.assert_not_called()

    def test_rotation_rejects_unmarked_or_unexpected_active_extra_targets(self):
        original = deepcopy(self.inventory)
        for onboarding in (None, {"status": "verified"}, {}, {"status": PRIVATE}):
            with self.subTest(onboarding=onboarding):
                self.inventory = deepcopy(original)
                if onboarding is None:
                    self.inventory["devices"]["R6"].pop("onboarding")
                else:
                    self.inventory["devices"]["R6"]["onboarding"] = onboarding
                self.write_inventory()
                with self.assertRaises(rotation.RotationError) as caught:
                    rotation.discover_inventory(self.inventory_path)
                self.assertEqual(caught.exception.category, "inventory")
                self.assertNotIn(PRIVATE, str(caught.exception))
        self.provider.assert_not_called()

    def test_rotation_does_not_silently_skip_a_required_fleet_member_marked_pending(self):
        self.inventory["devices"]["R1"]["onboarding"] = {"status": "pending"}
        self.write_inventory()
        with self.assertRaises(rotation.RotationError) as caught:
            rotation.discover_inventory(self.inventory_path)
        self.assertEqual(caught.exception.category, "inventory")
        self.provider.assert_not_called()

    def test_golden_bulk_capture_contacts_only_existing_nine(self):
        def connect(**kwargs):
            name = next(name for name in NINE
                        if self.inventory["devices"][name]["management"]["ipv4"] == kwargs["host"])
            session = Mock()
            session.check_enable_mode.return_value = True
            session.send_command.return_value = f"! synthetic EOS output\nhostname {name}\nend\n"
            return session

        self.golden_connect.side_effect = connect
        self.assertEqual(self.golden_main(), 0)
        self.assertEqual([call.kwargs["host"] for call in self.golden_connect.call_args_list],
                         [f"192.0.2.{index}" for index in range(1, 10)])
        self.assertEqual({path.name for path in (self.root / "golden").iterdir()}, set(NINE))
        self.assertNotIn(PRIVATE, self.output.getvalue())

    def test_golden_explicit_pending_capture_fails_without_ssh_or_snapshot(self):
        self.assertEqual(self.golden_main("R6"), 1)
        self.golden_connect.assert_not_called()
        self.assertFalse((self.root / "golden" / "R6").exists())
        self.assertNotIn(PRIVATE, self.output.getvalue())

    def test_direct_golden_collector_rejects_pending_and_malformed_onboarding(self):
        for onboarding in ({"status": "pending"}, None, [], {}, {"status": PRIVATE}):
            with self.subTest(onboarding_type=type(onboarding).__name__):
                row = device("R6", "198.51.100.6", onboarding=onboarding)
                with self.assertRaises(RuntimeError) as caught:
                    golden.get_running_config("R6", row, "fixture-admin", PRIVATE)
                self.assertIn("onboarding", str(caught.exception))
                self.assertNotIn(PRIVATE, str(caught.exception))
        self.golden_connect.assert_not_called()

    def test_gui_bulk_and_health_selection_excludes_unverified_records(self):
        for onboarding in ({"status": "pending"}, None, [], {}, {"status": PRIVATE}):
            with self.subTest(onboarding_type=type(onboarding).__name__):
                self.inventory["devices"]["R6"]["onboarding"] = onboarding
                self.assertEqual([row["hostname"] for row in gui._operation_devices(self.inventory)], list(NINE))
                with gui.app.test_request_context():
                    context = gui._basic_change_context(self.inventory, "R1")
                self.assertEqual([row["hostname"] for row in context["basic_devices"]], list(NINE))
        self.inventory["devices"]["R6"]["onboarding"] = {"status": "verified"}
        self.assertEqual([row["hostname"] for row in gui._operation_devices(self.inventory)], [*NINE, "R6"])

    def test_pending_health_source_and_destination_never_execute_checks(self):
        client = gui.app.test_client()
        with client.session_transaction() as session:
            session["health_check_csrf"] = "fixture-csrf"
        with patch.object(gui, "load_inventory", return_value=self.inventory), \
                patch.object(gui.health_checks, "run") as checks:
            for source, destination in (("R6", "R1"), ("R1", "R7")):
                response = client.post("/health-check", data={
                    "csrf_token": "fixture-csrf", "device": source, "destination": destination,
                })
                self.assertEqual(response.status_code, 400)
            checks.assert_not_called()
        self.provider.assert_not_called()


if __name__ == "__main__":
    unittest.main()

"""Fixture-only Basic Config Change GUI checks; no live device connections."""

from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import yaml

import config_changes


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("netpilot_basic_gui_test_app", ROOT / "app.py")
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class BasicConfigGuiSafety(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="netpilot-basic-gui-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.inventory = self.root / "devices.yml"
        self.golden = self.root / "golden_configs"
        self.generated = self.root / "generated_configs"
        self.history = self.root / "config_changes" / "change_history.json"
        self.golden.mkdir()
        self.generated.mkdir()
        self.data = {
            "metadata": {"fixture": "preserve me"},
            "network": {"defaults": {"template": "templates/arista_ceos.j2"}},
            "devices": {
                "FIXTURE-R1": {
                    "hostname": "FIXTURE-R1", "vendor": "Arista", "platform": "cEOSLab",
                    "role": "edge_router", "management": {"ipv4": "192.0.2.1"},
                    "template": "templates/arista_ceos.j2",
                    "interfaces": {
                        "Ethernet1": {"description": "Original uplink", "admin_state": "up",
                                      "forwarding_model": "routed", "ipv4": ["198.51.100.1/30"],
                                      "ipv6": [], "peer": None},
                        "Loopback0": {"description": "Router identity", "admin_state": "up",
                                      "ipv4": ["203.0.113.1/32"], "ipv6": []},
                    },
                },
                "FIXTURE-R2": {
                    "hostname": "FIXTURE-R2", "vendor": "Arista", "platform": "cEOSLab",
                    "role": "edge_router", "management": {"ipv4": "192.0.2.2"},
                    "template": "templates/arista_ceos.j2", "interfaces": {},
                },
            },
        }
        self.write_inventory()
        for module, settings in (
            (m, {"INVENTORY_PATH": self.inventory, "GOLDEN_CONFIGS_PATH": self.golden,
                 "GENERATED_CONFIGS_PATH": self.generated}),
            (config_changes, {"INVENTORY_PATH": self.inventory, "GOLDEN_CONFIGS_PATH": self.golden,
                              "HISTORY_PATH": self.history}),
        ):
            for name, value in settings.items():
                self.enterContext(patch.object(module, name, value))
        self.enterContext(patch.dict(os.environ, {}, clear=True))
        self.enterContext(patch("socket.create_connection", side_effect=AssertionError("No live connections in GUI tests")))
        self.enterContext(patch("socket.socket.connect", side_effect=AssertionError("No live connections in GUI tests")))
        self.runner = self.enterContext(patch("subprocess.run", side_effect=AssertionError("No scripts in basic-change GUI tests")))
        self.apply = self.enterContext(patch.object(config_changes, "apply_change"))
        self.apply.return_value = self.result()
        m.app.config.update(TESTING=True, SECRET_KEY="basic-change-fixture-session-key")
        self.client = m.app.test_client()
        with self.client.session_transaction() as session:
            session["basic_change_csrf"] = "fixture-basic-csrf"

    def write_inventory(self):
        self.inventory.write_text(yaml.safe_dump(self.data, sort_keys=False), encoding="utf-8")

    def result(self, **overrides):
        result = {
            "timestamp": "2026-09-29T18:00:00+00:00", "change_id": "a" * 32,
            "device": "FIXTURE-R1",
            "change_type": "interface_description", "interface": "Ethernet1",
            "old_value": "Original uplink", "new_value": "Demo uplink",
            "generated_commands": ["interface Ethernet1", "description Demo uplink"],
            "backup_file": "FIXTURE-R1_20260929_180000_prechange.cfg",
            "backup_status": "saved", "apply_status": "applied",
            "verification_status": "passed", "nsot_status": "updated", "error": None,
        }
        result.update(overrides)
        return result

    def preview(self, **overrides):
        form = {"csrf_token": "fixture-basic-csrf", "device": "FIXTURE-R1",
                "change_type": "interface_description", "interface": "Ethernet1",
                "new_description": "Demo uplink"}
        form.update(overrides)
        return self.client.post("/configuration/basic/preview", data=form, follow_redirects=True)

    def pending(self):
        with self.client.session_transaction() as session:
            return deepcopy(session.get("basic_change_preview"))

    def submit_apply(self, **overrides):
        preview = self.pending() or {}
        form = {"csrf_token": "fixture-basic-csrf", "change_id": preview.get("change_id", ""), "confirm": "yes"}
        form.update(overrides)
        return self.client.post("/configuration/basic/apply", data=form, follow_redirects=True)

    def test_configuration_get_preserves_existing_sections_and_lists_fixture_devices(self):
        before = self.inventory.read_bytes()
        response = self.client.get("/configuration?hostname=FIXTURE-R1")
        self.assertEqual(response.status_code, 200)
        for text in (b"Basic Config Change", b"Recent Changes", b"Desired Configuration",
                     b"Generate Configuration", b"Cisco IOS-XE Sample", b"FIXTURE-R1", b"FIXTURE-R2"):
            self.assertIn(text, response.data)
        self.assertEqual(self.inventory.read_bytes(), before)
        self.assertFalse(self.history.exists())
        self.apply.assert_not_called()
        self.runner.assert_not_called()

    def test_new_actions_are_post_only(self):
        for route in ("/configuration/basic/preview", "/configuration/basic/apply"):
            self.assertEqual(self.client.get(route).status_code, 405)
        self.apply.assert_not_called()

    def test_preview_builds_commands_without_live_apply_or_writes(self):
        before = self.inventory.read_bytes()
        response = self.preview()
        self.assertEqual(response.status_code, 200)
        preview = self.pending()
        self.assertIsNotNone(preview)
        self.assertIn(b"interface Ethernet1", response.data)
        self.assertIn(b"description Demo uplink", response.data)
        self.assertTrue(preview["change_id"])
        self.assertGreater(preview["created_at"], time.time() - 60)
        self.assertEqual(self.inventory.read_bytes(), before)
        self.assertFalse(self.history.exists())
        self.assertEqual(list(self.golden.iterdir()), [])
        self.apply.assert_not_called()
        self.runner.assert_not_called()

    def test_preview_requires_csrf(self):
        for token in ("", "wrong-token"):
            with self.subTest(token=token):
                response = self.preview(csrf_token=token)
                self.assertLess(response.status_code, 500)
                self.assertIsNone(self.pending())
        self.apply.assert_not_called()

    def test_admin_and_loopback_previews_show_only_generated_commands(self):
        cases = [
            ({"change_type": "interface_admin_state", "new_admin_state": "down"},
             ["interface Ethernet1", "shutdown"]),
            ({"change_type": "interface_admin_state", "new_admin_state": "up"},
             ["interface Ethernet1", "no shutdown"]),
            ({"change_type": "create_loopback", "loopback_id": "10", "ipv4": "203.0.113.10",
              "description": "NetPilot Loopback"},
             ["interface Loopback10", "description NetPilot Loopback", "ip address 203.0.113.10/32", "no shutdown"]),
        ]
        for fields, commands in cases:
            with self.subTest(fields=fields):
                response = self.preview(**fields, commands="reload")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(self.pending()["generated_commands"], commands)
                for command in commands:
                    self.assertIn(command.encode(), response.data)
        self.apply.assert_not_called()

    def test_invalid_changes_cannot_create_a_preview(self):
        invalid = [
            {"device": "UNKNOWN"}, {"interface": "Ethernet999"},
            {"change_type": "arbitrary_cli"}, {"new_description": ""},
            {"new_description": "uplink\nrouter bgp 65000"},
            {"change_type": "interface_admin_state", "new_admin_state": "invalid"},
            {"change_type": "create_loopback", "loopback_id": "0", "ipv4": "203.0.113.10", "prefix_length": "32"},
            {"change_type": "create_loopback", "loopback_id": "10", "ipv4": "203.0.113.1", "prefix_length": "32"},
        ]
        before = self.inventory.read_bytes()
        for fields in invalid:
            with self.subTest(fields=fields):
                response = self.preview(**fields)
                self.assertLess(response.status_code, 500)
                self.assertIsNone(self.pending())
        self.assertEqual(self.inventory.read_bytes(), before)
        self.apply.assert_not_called()

    def test_invalid_replacement_preview_invalidates_previous_choice(self):
        self.preview()
        self.assertIsNotNone(self.pending())
        self.preview(new_description="")
        self.assertIsNone(self.pending())
        self.submit_apply()
        self.apply.assert_not_called()

    def test_apply_requires_a_server_validated_preview(self):
        response = self.submit_apply(change_id="invented", device="FIXTURE-R1", commands="reload")
        self.assertLess(response.status_code, 500)
        self.apply.assert_not_called()

    def test_apply_requires_csrf_confirmation_and_matching_id(self):
        for fields in ({"csrf_token": ""}, {"csrf_token": "wrong"}, {"confirm": ""},
                       {"confirm": "no"}, {"change_id": "another-change"}):
            with self.subTest(fields=fields):
                self.preview()
                self.assertIsNotNone(self.pending())
                response = self.submit_apply(**fields)
                self.assertLess(response.status_code, 500)
                self.apply.assert_not_called()

    def test_expired_preview_cannot_apply(self):
        self.preview()
        with self.client.session_transaction() as session:
            preview = dict(session["basic_change_preview"])
            preview["created_at"] = time.time() - 601
            session["basic_change_preview"] = preview
        response = self.submit_apply()
        self.assertLess(response.status_code, 500)
        self.apply.assert_not_called()

    def test_busy_configuration_operation_does_not_apply(self):
        self.preview()
        self.assertTrue(m._CONFIGURATION_LOCK.acquire(blocking=False))
        try:
            response = self.submit_apply()
        finally:
            m._CONFIGURATION_LOCK.release()
        self.assertLess(response.status_code, 500)
        self.assertIsNotNone(self.pending())
        self.apply.assert_not_called()

    def test_apply_uses_confirmed_preview_and_ignores_posted_commands(self):
        self.preview()
        original = self.pending()
        response = self.submit_apply(device="FIXTURE-R2", interface="Ethernet999",
                                     new_description="Different description", commands="reload", generated_commands="write erase")
        self.assertEqual(response.status_code, 200)
        self.apply.assert_called_once()
        submitted = self.apply.call_args.args[0]
        self.assertEqual(submitted, original)
        self.assertNotIn("reload", repr(submitted))
        self.assertNotIn("write erase", repr(submitted))
        self.assertIsNone(self.pending())

    def test_repeated_apply_does_not_execute_twice(self):
        self.preview()
        change_id = self.pending()["change_id"]
        self.submit_apply(change_id=change_id)
        self.submit_apply(change_id=change_id)
        self.apply.assert_called_once()

    def test_failed_apply_consumes_preview_without_exposing_exception(self):
        self.preview()
        self.apply.side_effect = RuntimeError("fixture-private-diagnostic")
        response = self.submit_apply()
        self.assertLess(response.status_code, 500)
        self.assertNotIn(b"fixture-private-diagnostic", response.data)
        self.assertIsNone(self.pending())
        self.submit_apply()
        self.apply.assert_called_once()

    def test_success_result_reports_each_completed_step(self):
        self.preview()
        response = self.submit_apply()
        self.assertEqual(response.status_code, 200)
        for text in (b"Configuration Change Successful", b"Pre-change backup saved",
                     b"Configuration applied", b"Verification passed", b"NSOT updated"):
            self.assertIn(text, response.data)

    def test_failed_verification_does_not_report_success(self):
        self.preview()
        self.apply.return_value = self.result(verification_status="failed", nsot_status="not_updated",
                                             error="Configuration applied but verification failed.")
        response = self.submit_apply()
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"Configuration Change Successful", response.data)
        self.assertIn(b"verification failed", response.data.lower())
        self.assertNotIn(b"NSOT updated", response.data)

    def test_history_and_current_descriptions_are_escaped(self):
        marker = '<img src=x onerror="alert(1)">'
        self.data["devices"]["FIXTURE-R1"]["interfaces"]["Ethernet1"]["description"] = marker
        self.write_inventory()
        self.history.parent.mkdir(parents=True)
        self.history.write_text(json.dumps([self.result(old_value=marker, error=marker)]), encoding="utf-8")
        response = self.client.get("/configuration?hostname=FIXTURE-R1")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(marker.encode(), response.data)
        self.assertNotIn(b'<img src=x onerror=', response.data)
        self.assertIn(b'&lt;img src=x onerror=', response.data)
        self.assertNotIn(b"Change history is unavailable", response.data)
        self.apply.assert_not_called()


if __name__ == "__main__":
    unittest.main()

"""Local Flask onboarding controls with temporary inventory and no live workers."""

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("netpilot_ztp_routes_test_app", ROOT / "app.py")
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)

INVENTORY = """# Existing inventory content must survive registration.
network:
  defaults: {vendor: Arista, platform: cEOSLab, template: templates/arista_ceos.j2}
devices:
  R1:
    hostname: R1
    role: edge_router
    vendor: Arista
    platform: cEOSLab
    management: {ipv4: 172.20.20.2}
    template: templates/arista_ceos.j2
    interfaces: {Ethernet1: {description: "Preserve original interface"}}
    routing: {ospfv2: {enabled: true, process_id: 10}}
metadata:
  note: preserve-this-too
"""


class ZtpRouteTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="netpilot-ztp-routes-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.inventory = self.root / "inventory/devices.yml"
        self.inventory.parent.mkdir()
        self.inventory.write_text(INVENTORY)
        self.original = self.inventory.read_bytes()
        templates = self.root / "templates"
        templates.mkdir()
        (templates / "arista_ceos.j2").write_text("hostname {{ device.hostname }}\n")
        self.enterContext(patch.object(m, "BASE_DIR", self.root))
        self.enterContext(patch.object(m, "INVENTORY_PATH", self.inventory))
        self.enterContext(patch.object(m, "CONFIGURATION_TEMPLATES_PATH", templates))
        self.enterContext(patch.object(m.ztp_gui, "RUNTIME", self.root / "runtime"))
        self.enterContext(patch.object(m.ztp_gui, "INVENTORY", self.inventory))
        for boundary in ("subprocess.run", "socket.create_connection", "getpass.getpass",
                         "security.credential_provider.get_credentials", "netmiko.ConnectHandler"):
            forbidden = self.enterContext(patch(boundary, side_effect=AssertionError("External operation forbidden")))
            self.addCleanup(forbidden.assert_not_called)
        self.helper = self.enterContext(patch.object(m.ztp_gui, "helper", side_effect=AssertionError("Privileged operation forbidden")))
        self.addCleanup(self.helper.assert_not_called)
        self.preview = self.enterContext(patch.object(m.ztp_gui, "preview"))
        self.start = self.enterContext(patch.object(m.ztp_gui, "start"))
        self.logger = self.enterContext(patch.object(m.app, "logger"))
        m.app.config.update(TESTING=True, SECRET_KEY="synthetic-ztp-route-session")
        self.client = m.app.test_client()
        with self.client.session_transaction() as session:
            session["add_device_csrf"] = "csrf-fixture"
        self.job = {"job_id": "8" * 32, "hostname": "R8", "management_ip": "172.20.20.32",
                    "bootstrap_mac": "02:08:12:34:56:78", "host_interface": "npztp-12345678",
                    "state": "Preparing", "started": False, "message": "Review this device.",
                    "updated_at": "2026-10-26T12:00:00+00:00"}
        self.preview.return_value = deepcopy(self.job)

    def form(self, **updates):
        value = {"csrf_token": "csrf-fixture", "hostname": "R9", "management_ip": "172.20.20.33",
                 "role": "edge_router", "vendor": "Arista", "platform": "cEOSLab",
                 "template": "templates/arista_ceos.j2", "protocols": []}
        value.update(updates)
        return value

    def assert_no_secret(self, response, secret="synthetic-recovery-password"):
        self.assertNotIn(secret.encode(), response.data)
        with self.client.session_transaction() as session:
            self.assertNotIn(secret, json.dumps(dict(session)))
        self.assertNotIn(secret, repr(self.logger.mock_calls))

    def review(self):
        return self.client.post("/devices/ztp/preview", data={"csrf_token": "csrf-fixture",
                                "hostname": "R8", "platform": "cEOSLab"}, follow_redirects=True)

    def test_existing_inventory_only_add_remains_offline_and_preserves_old_records(self):
        page = self.client.get("/devices/add")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Inventory only", page.data)
        self.assertIn(b"Provision with ZTP", page.data)
        response = self.client.post("/devices/add", data=self.form())
        self.assertEqual(response.status_code, 303)
        saved = yaml.safe_load(self.inventory.read_bytes())
        self.assertEqual(saved["devices"].pop("R9")["management"], {"ipv4": "172.20.20.33"})
        self.assertEqual(saved, yaml.safe_load(INVENTORY))
        self.assertEqual(len(list((self.inventory.parent / "backups").glob("*.yml"))), 1)
        self.preview.assert_not_called()
        self.start.assert_not_called()

    def test_preview_returns_only_public_identity_and_masked_one_time_input_without_credentials(self):
        self.preview.return_value.update(password="synthetic-recovery-password", configuration="$6$synthetic-hash")
        response = self.review()
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"172.20.20.32/24", response.data)
        self.assertIn(b'type="password" name="recovery_password"', response.data)
        self.assertIn(b"Create &amp; Provision", response.data)
        self.assertNotIn(b"$6$synthetic-hash", response.data)
        self.assertEqual(response.headers.get("Cache-Control"), "no-store")
        self.preview.assert_called_once_with("R8", "cEOSLab")
        self.start.assert_not_called()
        with self.client.session_transaction() as session:
            self.assertEqual(set(session["ztp_preview"]), {"job_id", "hostname", "management_ip"})
        self.assert_no_secret(response)
        self.assertEqual(self.inventory.read_bytes(), self.original)

    def test_missing_csrf_remote_client_or_untrusted_host_cannot_preview_or_start(self):
        for path in ("/devices/ztp/preview", "/devices/ztp/start"):
            for settings in ({"data": {}},
                             {"environ_overrides": {"REMOTE_ADDR": "192.0.2.50"}},
                             {"headers": {"Host": "attacker.invalid"}}):
                arguments = {"data": {"csrf_token": "csrf-fixture", "hostname": "R8",
                                      "platform": "cEOSLab", "job_id": self.job["job_id"]}}
                arguments.update(settings)
                with self.subTest(path=path, settings=settings):
                    self.assertEqual(self.client.post(path, **arguments).status_code, 403)
        self.preview.assert_not_called()
        self.start.assert_not_called()

    def test_create_consumes_review_and_csrf_preventing_repeated_submission(self):
        self.review()
        submitted = {"csrf_token": "csrf-fixture", "job_id": self.job["job_id"],
                     "recovery_password": "synthetic-recovery-password",
                     "hostname": "Unexpected", "management_ip": "172.20.20.254", "command": "ignored"}
        response = self.client.post("/devices/ztp/start", data=submitted)
        self.assertEqual(response.status_code, 303)
        self.start.assert_called_once_with(self.job["job_id"], "synthetic-recovery-password", m._register_ztp_device)
        self.assert_no_secret(response)
        with self.client.session_transaction() as session:
            self.assertNotIn("ztp_preview", session)
            new_token = session["add_device_csrf"]
            self.assertNotEqual(new_token, "csrf-fixture")
        self.assertEqual(self.client.post("/devices/ztp/start", data=submitted).status_code, 403)
        submitted["csrf_token"] = new_token
        self.assertEqual(self.client.post("/devices/ztp/start", data=submitted).status_code, 409)
        self.start.assert_called_once()

    def test_failure_does_not_echo_recovery_or_backend_exception_details(self):
        self.review()
        self.start.side_effect = RuntimeError("synthetic-recovery-password $6$synthetic-hash")
        failed = {**self.job, "state": "Failed", "message": "Onboarding failed safely."}
        with patch.object(m.ztp_gui, "status", return_value=failed):
            response = self.client.post("/devices/ztp/start", data={"csrf_token": "csrf-fixture",
                                       "job_id": self.job["job_id"], "recovery_password": "synthetic-recovery-password"},
                                       follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Onboarding could not start.", response.data)
        self.assertIn(b"Failed", response.data)
        self.assertNotIn(b"$6$synthetic-hash", response.data)
        self.assert_no_secret(response)

    def test_status_returns_only_public_metadata_and_retry_requires_local_csrf(self):
        for state in ("Ready", "Failed"):
            job = {**self.job, "state": state, "message": "Verified." if state == "Ready" else "Verification timed out.",
                   "password": "synthetic-recovery-password", "config": "$6$synthetic-hash"}
            with self.subTest(state=state), patch.object(m.ztp_gui, "status", return_value=job):
                response = self.client.get("/devices/ztp/jobs/" + job["job_id"] + "?format=json")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(set(response.json), {"job_id", "hostname", "management_ip", "state", "message", "updated_at", "started"})
                self.assertEqual(response.json["state"], state)
                self.assertNotIn(b"$6$synthetic-hash", response.data)
                self.assert_no_secret(response)
                self.assertEqual(self.client.post("/devices/ztp/jobs/" + job["job_id"], data={}).status_code, 403)
                self.assertEqual(self.client.get("/devices/ztp/jobs/" + job["job_id"],
                                                 environ_overrides={"REMOTE_ADDR": "192.0.2.50"}).status_code, 403)
        self.start.assert_not_called()

    def test_success_callback_registers_management_and_pending_fleet_state_without_changing_existing_inventory(self):
        job = {**self.job, "started": True, "state": "Waiting for ZTP"}
        m.ztp_gui._save(job)
        record = m.ztp_gui.build_record(job)
        record["onboarding"].update(ztp_status="ready", verified_at="2026-10-26T12:00:00+00:00")
        m._register_ztp_device(record)
        saved = yaml.safe_load(self.inventory.read_bytes())
        added = saved["devices"].pop("R8")
        self.assertEqual(saved, yaml.safe_load(INVENTORY))
        self.assertEqual(added["management"], {"interface": "Management0", "ipv4": "172.20.20.32",
                                             "ipv4_prefix": "172.20.20.32/24"})
        self.assertEqual(added["interfaces"], {"Management0": {"admin_state": "up", "ipv4": ["172.20.20.32/24"]}})
        self.assertEqual(added["onboarding"]["status"], "pending")
        self.assertEqual(added["onboarding"]["ztp_status"], "ready")
        self.assertFalse(m.config_changes.device_is_active(added))
        self.assertEqual(added["template"], "templates/arista_ceos.j2")
        self.assertTrue(all(value["enabled"] is False for value in added["routing"].values()))
        self.assertEqual(len(list((self.inventory.parent / "backups").glob("*.yml"))), 1)

    def test_inventory_only_registration_cannot_take_a_pending_onboarding_name_or_ip(self):
        m.ztp_gui._save(deepcopy(self.job))
        for changes in ({"hostname": "R8"}, {"management_ip": "172.20.20.32"}):
            with self.subTest(changes=changes):
                response = self.client.post("/devices/add", data=self.form(**changes))
                self.assertEqual(response.status_code, 400)
                self.assertIn(b"reserved for an onboarding attempt", response.data)
                self.assertEqual(self.inventory.read_bytes(), self.original)
        self.start.assert_not_called()


if __name__ == "__main__":
    unittest.main()

"""Live Devices routes preserve intended state; all external boundaries are fake."""

from copy import deepcopy
import unittest
from unittest.mock import patch

import app as gui


INVENTORY = {"devices": {
    "R6": {"hostname": "R6", "vendor": "Arista", "platform": "cEOSLab",
           "management": {"ipv4": "172.20.20.30"}, "onboarding": {"status": "pending"}},
    "R7": {"hostname": "R7", "vendor": "Arista", "platform": "cEOSLab",
           "management": {"ipv4": "172.20.20.31"}, "routing": {"ospfv2": {"enabled": True}}},
}}
OBSERVATION = {"status": "available", "reachable": True,
               "protocols": [{"name": "ospfv2", "label": "OSPFv2", "configured": True, "interfaces": []}],
               "last_success": "2026-10-26T12:00:00+00:00", "checked_at": "2026-10-26T12:00:00+00:00",
               "operational": "Not checked", "message": "Observed configuration."}


class LiveDevicesGUI(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch("socket.socket.connect", side_effect=AssertionError("No network")))
        self.enterContext(patch("subprocess.Popen", side_effect=AssertionError("No subprocess")))
        self.enterContext(patch.object(gui.live_device_state.credential_provider, "get_credentials", side_effect=AssertionError("No credentials")))
        self.enterContext(patch.object(gui.live_device_state, "ConnectHandler", side_effect=AssertionError("No SSH")))
        self.inventory = deepcopy(INVENTORY)
        self.load = self.enterContext(patch.object(gui, "load_inventory", return_value=self.inventory))
        self.observe = self.enterContext(patch.object(gui.live_device_state, "observed_state", return_value=deepcopy(OBSERVATION)))
        self.client = gui.app.test_client()

    def test_device_pages_keep_inventory_badges_and_do_not_connect_during_html_rendering(self):
        before = deepcopy(self.inventory)
        for page in ("/devices", "/devices/R6"):
            with self.subTest(page=page):
                response = self.client.get(page)
                self.assertEqual(response.status_code, 200)
                text = response.get_data(as_text=True)
                self.assertIn("Intended / Inventory State", text)
                self.assertIn("Live / Observed State", text)
                self.assertIn("Refresh Live", text)
                self.assertIn("live-devices.js", text)
        list_text = self.client.get("/devices").get_data(as_text=True)
        self.assertIn("No enabled protocols recorded", list_text)
        self.assertIn("protocol-tag\">OSPFv2</span>", list_text)
        self.assertEqual(self.inventory, before)
        self.observe.assert_not_called()
        with self.client.session_transaction() as session:
            self.assertIsInstance(session["live_state_csrf"], str)
            self.assertIsInstance(session["remove_device_csrf"], str)

    def test_live_get_uses_inventory_address_and_does_not_promote_pending_device(self):
        before = deepcopy(self.inventory)
        result = self.client.get("/devices/R6/live?management_ip=192.0.2.100&command=reload")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.get_json(), OBSERVATION)
        self.assertEqual(result.headers["Cache-Control"], "no-store")
        record = self.observe.call_args.args[0]
        self.assertEqual(record["hostname"], "R6")
        self.assertEqual(record["management_ip"], "172.20.20.30")
        self.assertEqual(self.observe.call_args.kwargs, {"force": False})
        self.assertEqual(self.inventory, before)

    def test_forced_refresh_requires_existing_csrf_session(self):
        for token in ("", "wrong"):
            with self.subTest(token=token):
                response = self.client.post("/devices/R6/refresh-live", data={"csrf_token": token})
                self.assertEqual(response.status_code, 403)
        self.client.get("/devices")
        self.assertEqual(self.client.post("/devices/R6/refresh-live", data={"csrf_token": "wrong"}).status_code, 403)
        self.observe.assert_not_called()

    def test_valid_refresh_uses_force_and_leaves_inventory_unchanged(self):
        with self.client.session_transaction() as session:
            session["live_state_csrf"] = "synthetic-csrf"
        before = deepcopy(self.inventory)
        result = self.client.post("/devices/R7/refresh-live", data={"csrf_token": "synthetic-csrf"})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(self.observe.call_args.args[0]["hostname"], "R7")
        self.assertEqual(self.observe.call_args.kwargs, {"force": True})
        self.assertEqual(self.inventory, before)

    def test_remote_clients_untrusted_hosts_and_forwarded_header_bypasses_are_rejected(self):
        for options in ({"environ_overrides": {"REMOTE_ADDR": "192.0.2.1"}},
                        {"headers": {"Host": "untrusted.example"}},
                        {"headers": {"Host": "untrusted.example", "X-Forwarded-Host": "localhost"}},
                        {"environ_overrides": {"REMOTE_ADDR": "192.0.2.1"}, "headers": {"X-Forwarded-For": "127.0.0.1"}}):
            with self.subTest(options=options):
                self.assertEqual(self.client.get("/devices/R6/live", **options).status_code, 403)
        self.observe.assert_not_called()
        self.load.assert_not_called()

    def test_missing_device_or_inventory_prevents_live_observation(self):
        self.assertEqual(self.client.get("/devices/unknown/live").status_code, 404)
        self.load.return_value = None
        self.assertEqual(self.client.get("/devices/R6/live").status_code, 503)
        self.observe.assert_not_called()

    def test_unavailable_state_is_not_returned_as_empty_configured_protocols(self):
        self.observe.return_value = {
            "status": "unavailable", "protocols": None, "reachable": False,
            "last_success": "2026-10-26T12:00:00+00:00", "message": "Live status unavailable. SSH timed out.",
        }
        response = self.client.get("/devices/R6/live")
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.get_json()["protocols"])
        self.assertIn("unavailable", response.get_json()["message"])
        self.assertEqual(response.get_json()["last_success"], "2026-10-26T12:00:00+00:00")


if __name__ == "__main__":
    unittest.main()

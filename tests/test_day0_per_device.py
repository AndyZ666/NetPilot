"""Offline GUI Day-0 preparation uses the existing real renderer and private files."""

import copy
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lab8 import day0


class PerDeviceDay0Tests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="netpilot-per-device-")
        self.addCleanup(temporary.cleanup)
        self.runtime = Path(temporary.name) / "runtime"
        self.record = {
            "hostname": "R8", "template": "templates/arista_day0.j2",
            "vendor": "Arista", "platform": "cEOSLab",
            "management": {"interface": "Management0", "ipv4": "172.20.20.32",
                           "ipv4_prefix": "172.20.20.32/24"},
            "onboarding": {"status": "pending", "management_verified": True},
        }
        self.admin = self.enterContext(patch.object(day0.credential_provider, "get_credentials",
                                                  return_value=("admin", "fake-admin-password")))
        self.enterContext(patch.object(day0, "sha512_crypt", side_effect=lambda value, **kwargs:
                                      "$6$testsalt$" + ("A" if "admin" in value else "B") * 86))
        for target in ("getpass.getpass", "subprocess.run", "socket.create_connection",
                       "security.credential_provider._read_token"):
            boundary = self.enterContext(patch(target, side_effect=AssertionError("External action forbidden")))
            self.addCleanup(boundary.assert_not_called)

    def test_one_device_uses_permanent_accounts_and_existing_services_without_terminal_input(self):
        path = day0.render_one(self.record, "fake-recovery-password", runtime=self.runtime)
        content = path.read_text()
        self.assertEqual(path, self.runtime / "private/R8.cfg")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        for expected in ("hostname R8", "ip address 172.20.20.32/24", "management ssh",
                         "snmp-server local-interface Management0", "management api gnmi",
                         "management api http-commands", "protocol https",
                         "username admin privilege 15 role network-admin secret sha512 $6$",
                         "username netpilot-recovery privilege 15 role network-admin secret sha512 $6$"):
            self.assertIn(expected, content)
        for forbidden in ("fake-admin-password", "fake-recovery-password", "router ospf",
                          "router rip", "router bgp", "interface Ethernet", "netpilot-onboard"):
            self.assertNotIn(forbidden, content)
        self.assertEqual(list((self.runtime / "http").iterdir()), [])

    def test_invalid_names_or_pending_records_are_rejected_before_credentials(self):
        for name in ("../R8", "R8/other", "R8\nend", "", None):
            with self.subTest(hostname=name):
                record = copy.deepcopy(self.record)
                record["hostname"] = name
                with self.assertRaises(day0.Day0Error):
                    day0.render_one(record, "fake-recovery-password", runtime=self.runtime)
        for key, value in (("ipv4", True), ("ipv4_prefix", "172.20.20.99/24")):
            record = copy.deepcopy(self.record)
            record["management"][key] = value
            with self.assertRaises(day0.Day0Error):
                day0.render_one(record, "fake-recovery-password", runtime=self.runtime)
        self.admin.assert_not_called()

    def test_missing_recovery_or_vault_failure_is_sanitized_without_partial_outputs(self):
        for password in (None, "", "  "):
            with self.subTest(password=password), self.assertRaises(day0.Day0Error):
                day0.render_one(self.record, password, runtime=self.runtime)
        self.admin.assert_not_called()
        self.admin.side_effect = RuntimeError("fake-admin-password fake-recovery-password")
        with self.assertRaises(day0.Day0Error) as caught:
            day0.render_one(self.record, "fake-recovery-password", runtime=self.runtime)
        self.assertNotIn("fake-admin-password", str(caught.exception))
        self.assertNotIn("fake-recovery-password", str(caught.exception))
        self.assertEqual(list(self.runtime.rglob("*.cfg")), [])

    def test_independent_publication_and_cleanup_preserves_other_device_and_legacy_lease(self):
        day0.render_one(self.record, "fake-recovery-password", runtime=self.runtime)
        other = copy.deepcopy(self.record)
        other["hostname"] = "R9"
        other["management"].update(ipv4="172.20.20.33", ipv4_prefix="172.20.20.33/24")
        day0.render_one(other, "fake-recovery-password", runtime=self.runtime)
        with patch.object(day0.time, "time", return_value=1000):
            self.assertEqual(day0.publish_one("R8", runtime=self.runtime, seconds=60), 1060)
            self.assertEqual(day0.publish_one("R9", runtime=self.runtime, seconds=300), 1300)
        legacy = self.runtime / "http/.expires"
        legacy.write_text("1300")
        retained = {path: path.read_bytes() for path in self.runtime.rglob("*")
                    if path.is_file() and "R8" not in path.name}
        day0.clear_one("R8", runtime=self.runtime)
        day0.clear_one("R8", runtime=self.runtime)
        self.assertFalse((self.runtime / "private/R8.cfg").exists())
        self.assertFalse((self.runtime / "http/R8.cfg").exists())
        self.assertFalse((self.runtime / "http/.R8.expires").exists())
        self.assertEqual({path: path.read_bytes() for path in retained}, retained)
        self.assertEqual((self.runtime / "http/.R9.expires").read_text().strip(), "1300")
        self.assertEqual(stat.S_IMODE((self.runtime / "http/R9.cfg").stat().st_mode), 0o600)

    def test_existing_device_output_and_legacy_publication_cannot_be_overwritten(self):
        original = day0.render_one(self.record, "fake-recovery-password", runtime=self.runtime).read_bytes()
        self.admin.reset_mock()
        with self.assertRaises(day0.Day0Error):
            day0.render_one(self.record, "fake-recovery-password", runtime=self.runtime)
        self.admin.assert_not_called()
        self.assertEqual((self.runtime / "private/R8.cfg").read_bytes(), original)
        (self.runtime / "http/.expires").write_text("1300")
        (self.runtime / "private/R6.cfg").write_text("legacy fixture")
        (self.runtime / "private/R6.cfg").chmod(0o600)
        with self.assertRaises(day0.Day0Error):
            day0.publish_one("R6", runtime=self.runtime)
        self.assertFalse((self.runtime / "http/R6.cfg").exists())

    def test_publication_rejects_symlink_and_invalid_window_without_exposing_files(self):
        path = day0.render_one(self.record, "fake-recovery-password", runtime=self.runtime)
        for seconds in (0, 601, True, "60"):
            with self.subTest(seconds=seconds), self.assertRaises(day0.Day0Error):
                day0.publish_one("R8", runtime=self.runtime, seconds=seconds)
        unrelated = self.runtime / "unrelated"
        unrelated.write_text("not a device config")
        unrelated.chmod(0o600)
        path.unlink()
        path.symlink_to(unrelated)
        with self.assertRaises(day0.Day0Error):
            day0.publish_one("R8", runtime=self.runtime)
        self.assertEqual(list((self.runtime / "http").iterdir()), [])
        self.assertEqual(unrelated.read_text(), "not a device config")


if __name__ == "__main__":
    unittest.main()

"""Offline permanent Day-0 accounts and bounded, private publication.

Only Vault reads, hidden password input, and hashing are replaced: NSOT validation,
Jinja rendering, file permissions, publication, and cleanup execute normally.
"""

import io
from pathlib import Path
import stat
import tempfile
import time
import traceback
import unittest
import warnings
from unittest.mock import call, patch

import yaml

from lab8 import day0


ADMIN_PASSWORD = "synthetic-admin-password-never-print"
RECOVERY_PASSWORD = "synthetic-recovery-password-never-print"
ADMIN_HASH = "$6$syntheticadmin$" + "A" * 86
RECOVERY_HASH = "$6$syntheticrecover$" + "B" * 86


class Day0CredentialTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="netpilot-day0-credentials-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.runtime = self.root / "runtime"
        self.inventory = self.root / "inventory.yml"
        self.records = {
            "network": {"defaults": {"template": "templates/arista_ceos.j2"}},
            "devices": {
                name: {
                    "hostname": name,
                    "template": "templates/arista_day0.j2",
                    "vendor": "Arista",
                    "platform": "cEOSLab",
                    "management": {
                        "interface": "Management0",
                        "ipv4": address,
                        "ipv4_prefix": address + "/24",
                    },
                    "onboarding": {"status": "pending", "management_verified": True},
                }
                for name, address in (("R6", "172.20.20.30"), ("R7", "172.20.20.31"))
            },
        }
        self.write_inventory()
        self.stdout = self.enterContext(patch("sys.stdout", new_callable=io.StringIO))
        self.stderr = self.enterContext(patch("sys.stderr", new_callable=io.StringIO))
        self.admin = self.enterContext(patch.object(
            day0.credential_provider, "get_credentials", return_value=("admin", ADMIN_PASSWORD)))
        self.recovery = self.enterContext(patch.object(
            day0.getpass, "getpass", return_value=RECOVERY_PASSWORD))
        self.hashes = self.enterContext(patch.object(
            day0, "sha512_crypt", side_effect=(ADMIN_HASH, RECOVERY_HASH)))
        for target in ("security.credential_provider._read_token",
                       "security.credential_provider.read_secret_reference", "socket.socket.connect",
                       "socket.create_connection", "netmiko.ConnectHandler", "subprocess.run"):
            forbidden = self.enterContext(patch(target, side_effect=AssertionError("External action forbidden")))
            self.addCleanup(forbidden.assert_not_called)

    def write_inventory(self):
        self.inventory.write_text(yaml.safe_dump(self.records), encoding="utf-8")

    def render(self):
        return day0.render(inventory=self.inventory, runtime=self.runtime)

    def assert_private(self, path, mode):
        self.assertFalse(path.is_symlink())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)

    def assert_sanitized(self, error=None):
        visible = self.stdout.getvalue() + self.stderr.getvalue()
        if error is not None:
            visible += "".join(traceback.format_exception(type(error), error, error.__traceback__))
        for secret in (ADMIN_PASSWORD, RECOVERY_PASSWORD, ADMIN_HASH, RECOVERY_HASH):
            self.assertNotIn(secret, visible)

    def assert_no_configuration(self):
        self.assertEqual(list(self.runtime.rglob("*.cfg")), [])

    def test_renders_both_permanent_accounts_privately_without_http_publication(self):
        paths = self.render()
        self.assertEqual(tuple(paths), (self.runtime / "private/R6.cfg", self.runtime / "private/R7.cfg"))
        self.admin.assert_called_once_with()
        self.recovery.assert_called_once_with("Existing netpilot-recovery password (hidden): ")
        self.assertEqual(self.hashes.call_args_list, [
            call(ADMIN_PASSWORD, allow_legacy=True), call(RECOVERY_PASSWORD, allow_legacy=True)])
        self.assert_private(self.runtime, 0o700)
        self.assert_private(self.runtime / "private", 0o700)
        for name, address, path in zip(("R6", "R7"), ("172.20.20.30", "172.20.20.31"), paths):
            output = path.read_text(encoding="utf-8")
            self.assert_private(path, 0o600)
            self.assertIn("hostname " + name, output)
            self.assertIn("ip address " + address + "/24", output)
            self.assertIn("username admin privilege 15 role network-admin secret sha512 " + ADMIN_HASH, output)
            self.assertIn("username netpilot-recovery privilege 15 role network-admin secret sha512 " + RECOVERY_HASH, output)
            for forbidden in (ADMIN_PASSWORD, RECOVERY_PASSWORD, "netpilot-onboard", "sshkey ",
                              "router ospf", "router bgp", "router rip", "interface Ethernet", "interface Loopback"):
                self.assertNotIn(forbidden, output)
            for required in ("management ssh", "snmp-server local-interface Management0",
                             "management api gnmi", "management api http-commands", "protocol https"):
                self.assertIn(required, output)
        self.assertEqual(list((self.runtime / "http").glob("*.cfg")), [])
        self.assertFalse((self.runtime / "http/.expires").exists())
        self.assert_sanitized()

    def test_missing_admin_credentials_stop_before_recovery_hashing_or_output(self):
        self.admin.side_effect = RuntimeError(ADMIN_PASSWORD + " " + ADMIN_HASH)
        with self.assertRaises(day0.Day0Error) as caught:
            self.render()
        self.recovery.assert_not_called()
        self.hashes.assert_not_called()
        self.assert_no_configuration()
        self.assert_sanitized(caught.exception)

    def test_failed_or_interrupted_recovery_prompt_stops_before_hashing_or_output(self):
        for error in (RuntimeError(RECOVERY_PASSWORD + " " + RECOVERY_HASH),
                      EOFError(RECOVERY_PASSWORD), KeyboardInterrupt(RECOVERY_PASSWORD)):
            with self.subTest(error=type(error).__name__):
                self.recovery.side_effect = error
                with self.assertRaises(day0.Day0Error) as caught:
                    self.render()
                self.hashes.assert_not_called()
                self.assert_no_configuration()
                self.assert_sanitized(caught.exception)

    def test_empty_recovery_password_stops_before_hashing_or_output(self):
        for password in (None, "", " \t "):
            with self.subTest(password=password):
                self.recovery.return_value = password
                with self.assertRaises(day0.Day0Error) as caught:
                    self.render()
                self.assert_sanitized(caught.exception)
        self.hashes.assert_not_called()
        self.assert_no_configuration()

    def test_getpass_echo_fallback_is_rejected_before_reading_visible_input(self):
        visible_input = []

        def fallback(prompt):
            warnings.warn("Password input may be echoed.", day0.getpass.GetPassWarning)
            visible_input.append("unsafe input reached")
            return RECOVERY_PASSWORD

        self.recovery.side_effect = fallback
        with self.assertRaises(day0.Day0Error) as caught:
            self.render()
        self.assertEqual(visible_input, [])
        self.hashes.assert_not_called()
        self.assert_no_configuration()
        self.assert_sanitized(caught.exception)

    def test_render_cli_requires_no_reference_and_prompts_only_for_recovery(self):
        # Redirect only default paths; execute the real rendering implementation.
        real_render = day0.render
        with patch.object(day0, "render", side_effect=lambda: real_render(
                inventory=self.inventory, runtime=self.runtime)) as render_command:
            self.assertEqual(day0.main(["render"]), 0)
        render_command.assert_called_once_with()
        self.admin.assert_called_once_with()
        self.recovery.assert_called_once_with("Existing netpilot-recovery password (hidden): ")
        self.assertTrue((self.runtime / "private/R6.cfg").exists())
        self.assertTrue((self.runtime / "private/R7.cfg").exists())
        self.assert_sanitized()

    def test_identical_admin_and_recovery_passwords_preserve_existing_separation_rule(self):
        self.recovery.return_value = ADMIN_PASSWORD
        with self.assertRaises(day0.Day0Error) as caught:
            self.render()
        self.hashes.assert_not_called()
        self.assert_no_configuration()
        self.assert_sanitized(caught.exception)

    def test_wrong_admin_identity_is_rejected_without_password_disclosure(self):
        self.admin.return_value = ("unexpected-account", ADMIN_PASSWORD)
        with self.assertRaises(day0.Day0Error) as caught:
            self.render()
        self.hashes.assert_not_called()
        self.assert_no_configuration()
        self.assert_sanitized(caught.exception)

    def test_invalid_management_evidence_blocks_credentials_for_both_devices(self):
        self.records["devices"]["R7"]["management"]["ipv4"] = True
        self.write_inventory()
        with self.assertRaises(day0.Day0Error):
            self.render()
        self.admin.assert_not_called()
        self.recovery.assert_not_called()
        self.assert_no_configuration()

    def test_hash_failure_does_not_leave_partial_config_or_reveal_credentials(self):
        self.hashes.side_effect = [ADMIN_HASH, RuntimeError(RECOVERY_PASSWORD + " " + ADMIN_HASH)]
        with self.assertRaises(day0.Day0Error) as caught:
            self.render()
        self.assert_no_configuration()
        self.assert_sanitized(caught.exception)

    def test_existing_configs_are_not_overwritten_or_credentials_reread(self):
        paths = self.render()
        original = {path: path.read_bytes() for path in paths}
        self.admin.reset_mock()
        self.recovery.reset_mock()
        with self.assertRaises(day0.Day0Error):
            self.render()
        self.assertEqual({path: path.read_bytes() for path in paths}, original)
        self.admin.assert_not_called()
        self.recovery.assert_not_called()

    def test_symlinked_runtime_is_rejected_before_credentials_or_target_write(self):
        target = self.root / "unrelated"
        target.mkdir()
        self.runtime.symlink_to(target, target_is_directory=True)
        with self.assertRaises(day0.Day0Error):
            self.render()
        self.assertEqual(list(target.iterdir()), [])
        self.admin.assert_not_called()
        self.recovery.assert_not_called()

    def test_publish_copies_complete_pair_with_restricted_permissions_and_expiry(self):
        sources = self.render()
        before = time.time()
        expiry = day0.publish(runtime=self.runtime, seconds=120)
        after = time.time()
        self.assertGreaterEqual(expiry, before + 120)
        self.assertLessEqual(expiry, after + 120)
        self.assert_private(self.runtime / "http", 0o700)
        for source in sources:
            public = self.runtime / "http" / source.name
            self.assertEqual(public.read_bytes(), source.read_bytes())
            self.assert_private(public, 0o600)
        marker = self.runtime / "http/.expires"
        self.assertEqual(float(marker.read_text()), expiry)
        self.assert_private(marker, 0o600)
        self.assert_sanitized()

    def test_invalid_publication_window_never_exposes_configs(self):
        self.render()
        for seconds in (0, -1, 601, True, "120"):
            with self.subTest(seconds=seconds):
                with self.assertRaises(day0.Day0Error):
                    day0.publish(runtime=self.runtime, seconds=seconds)
                self.assertEqual(list((self.runtime / "http").glob("*.cfg")), [])
                self.assertFalse((self.runtime / "http/.expires").exists())

    def test_missing_second_config_prevents_partial_http_publication(self):
        paths = self.render()
        paths[1].unlink()
        with self.assertRaises(day0.Day0Error):
            day0.publish(runtime=self.runtime)
        self.assertEqual(list((self.runtime / "http").glob("*.cfg")), [])
        self.assertFalse((self.runtime / "http/.expires").exists())

    def test_symlinked_private_source_cannot_publish_unrelated_sensitive_file(self):
        paths = self.render()
        unrelated = self.root / "unrelated-sensitive-file"
        unrelated.write_text("SYNTHETIC-UNRELATED-SECRET", encoding="utf-8")
        unrelated.chmod(0o600)
        paths[1].unlink()
        paths[1].symlink_to(unrelated)
        with self.assertRaises(day0.Day0Error):
            day0.publish(runtime=self.runtime)
        self.assertEqual(list((self.runtime / "http").glob("*.cfg")), [])
        self.assertFalse((self.runtime / "http/.expires").exists())
        self.assertEqual(unrelated.read_text(), "SYNTHETIC-UNRELATED-SECRET")

    def test_unsafe_private_source_permissions_block_publication(self):
        paths = self.render()
        paths[1].chmod(0o644)
        with self.assertRaises(day0.Day0Error):
            day0.publish(runtime=self.runtime)
        self.assertEqual(list((self.runtime / "http").glob("*.cfg")), [])
        self.assertFalse((self.runtime / "http/.expires").exists())

    def test_clear_removes_only_known_secret_files_and_is_idempotent(self):
        self.render()
        day0.publish(runtime=self.runtime)
        sentinel = self.runtime / "unrelated-note.txt"
        sentinel.write_text("preserve", encoding="utf-8")
        day0.clear(runtime=self.runtime)
        day0.clear(runtime=self.runtime)
        self.assertEqual(sentinel.read_text(), "preserve")
        self.assert_no_configuration()
        self.assertFalse((self.runtime / "http/.expires").exists())
        self.assert_sanitized()


if __name__ == "__main__":
    unittest.main()

"""Offline Golden Config behavior tests; all data and writes are temporary.

Netmiko and the credential provider are replaced at their external boundaries.
The loader, collector, validator, storage function, and CLI orchestration remain
real. No real inventory, credentials, or saved configurations are read.
"""

import io
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import Mock, call, patch

from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
import yaml

import save_golden_configs as golden


TIMESTAMP = "20261019_103045"
USERNAME = "fixture-admin"
PASSWORD = "synthetic-password-not-a-device-secret"
CONFIG = (
    "! synthetic EOS configuration\n"
    "hostname R1\n"
    "interface Ethernet1\n"
    "   description Lab uplink — café\n"
    "   ip address 198.51.100.1/31\n"
    "   ipv6 address 2001:db8:41::1/64\n"
    "!\n"
    "end\n"
)


class GoldenConfigTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.inventory_path = self.root / "devices.yml"
        self.output_dir = self.root / "nested" / "golden_configs"
        self.device = {"hostname": "R1", "management": {"ipv4": "192.0.2.1"}}
        self.inventory = {
            "metadata": {"schema_version": 2},
            "devices": {
                "R1": self.device,
                "R2": {"hostname": "R2", "management": {"ipv4": "192.0.2.2"}},
            },
        }
        self.inventory_path.write_text(yaml.safe_dump(self.inventory), encoding="utf-8")
        self.enterContext(patch.object(golden, "INVENTORY_FILE", self.inventory_path))
        self.enterContext(patch.object(golden, "OUTPUT_DIR", self.output_dir))
        self.output = self.enterContext(patch("sys.stdout", new_callable=io.StringIO))
        self.errors = self.enterContext(patch("sys.stderr", new_callable=io.StringIO))
        self.provider = self.enterContext(patch.object(
            golden.credential_provider, "get_credentials", return_value=(USERNAME, PASSWORD)))
        self.enterContext(patch.object(
            golden.credential_provider, "_read_token",
            side_effect=AssertionError("Real token access is forbidden in offline tests.")))
        self.connect = self.enterContext(patch.object(golden, "ConnectHandler"))
        self.session = self.new_session(CONFIG)
        self.connect.return_value = self.session
        self.enterContext(patch.object(
            socket.socket, "connect",
            side_effect=AssertionError("Live networking is forbidden in offline tests.")))

    @staticmethod
    def new_session(config):
        session = Mock(spec=["check_enable_mode", "enable", "send_command", "disconnect"])
        session.check_enable_mode.return_value = True
        session.send_command.return_value = config
        return session

    def collect(self):
        return golden.get_running_config("R1", self.device, USERNAME, PASSWORD)

    def save(self):
        return golden.save_golden_config("R1", self.device, USERNAME, PASSWORD, TIMESTAMP)

    def run_main(self, *names):
        with patch("sys.argv", ["save_golden_configs.py", *names]), \
                patch.object(golden, "datetime") as clock:
            clock.now.return_value.strftime.return_value = TIMESTAMP
            return golden.main()

    def assert_no_success(self):
        self.assertNotIn("[OK]", self.output.getvalue())
        self.assertNotIn("saved successfully", self.output.getvalue())

    def test_load_inventory_preserves_devices_metadata_and_yaml_alias_values(self):
        self.inventory_path.write_text(
            "metadata:\n  schema_version: 2\n"
            "management_default: &management\n  ipv4: 192.0.2.9\n"
            "devices:\n  R9:\n    hostname: R9\n    management: *management\n",
            encoding="utf-8",
        )
        before = self.inventory_path.read_bytes()
        self.assertEqual(golden.load_inventory(), {
            "metadata": {"schema_version": 2},
            "management_default": {"ipv4": "192.0.2.9"},
            "devices": {"R9": {"hostname": "R9", "management": {"ipv4": "192.0.2.9"}}},
        })
        self.assertEqual(self.inventory_path.read_bytes(), before)
        self.connect.assert_not_called()
        self.provider.assert_not_called()

    def test_load_inventory_missing_file_and_directory_fail(self):
        for path, expected in ((self.root / "missing.yml", FileNotFoundError),
                               (self.root, IsADirectoryError)):
            with self.subTest(path=path.name), patch.object(golden, "INVENTORY_FILE", path):
                with self.assertRaises(expected):
                    golden.load_inventory()

    def test_load_inventory_empty_and_missing_devices_section_fail(self):
        for source, message in (("", "empty"), ("---\n", "empty"), ("{}", "empty"),
                                ("metadata: {schema_version: 2}\n", "devices")):
            with self.subTest(source=source):
                self.inventory_path.write_text(source, encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, message):
                    golden.load_inventory()

    def test_load_inventory_invalid_yaml_and_unsafe_tags_fail(self):
        for source in ("devices: [unterminated", "devices: !!python/tuple [R1]"):
            with self.subTest(source=source):
                self.inventory_path.write_text(source, encoding="utf-8")
                with self.assertRaises(yaml.YAMLError):
                    golden.load_inventory()

    def test_load_inventory_read_permission_error_is_not_hidden(self):
        with patch.object(Path, "open", side_effect=PermissionError("fixture denied")):
            with self.assertRaises(PermissionError):
                golden.load_inventory()
        self.assert_no_success()

    def test_validate_valid_config_accepts_realistic_interface_commands(self):
        self.assertIsNone(golden.validate_running_config("R1", CONFIG))
        self.connect.assert_not_called()

    def test_validate_empty_or_whitespace_responses_fail(self):
        for config in (None, "", " \n\t "):
            with self.subTest(config=config):
                with self.assertRaisesRegex(RuntimeError, "R1:.*empty"):
                    golden.validate_running_config("R1", config)

    def test_validate_cli_errors_are_case_insensitive_and_do_not_echo_response(self):
        for message in ("% Invalid Input", "PRIVILEGED MODE REQUIRED", "% Incomplete Command",
                        "% Ambiguous Command", "Authorization Failed", "Permission Denied"):
            with self.subTest(message=message):
                with self.assertRaisesRegex(RuntimeError, "R1: device returned CLI error") as raised:
                    golden.validate_running_config("R1", f"{message}\n{PASSWORD}")
                self.assertNotIn(PASSWORD, str(raised.exception))

    def test_validate_nonconfiguration_and_incomplete_responses_fail(self):
        for config in ("R1#", "show running-config\n", "! Command: show running-config\n",
                       "interface Ethernet1\n   ip address 192.0.2.1/24\n"):
            with self.subTest(config=config):
                with self.assertRaisesRegex(RuntimeError, "valid running-config"):
                    golden.validate_running_config("R1", config)

    def test_mismatched_device_config_is_not_published_as_requested_device(self):
        # A response from R2 must never be labelled and reported as R1's backup.
        self.session.send_command.return_value = "hostname R2\ninterface Loopback0\nend\n"
        self.assertEqual(self.run_main("R1"), 1)
        self.assertFalse((self.output_dir / "R1" / f"R1_{TIMESTAMP}.cfg").exists())
        self.assert_no_success()

    def test_error_phrase_inside_valid_description_does_not_reject_config(self):
        # EOS descriptions are ordinary configuration data, not CLI error lines.
        config = "hostname R1\ninterface Ethernet1\n   description permission denied test link\nend\n"
        self.session.send_command.return_value = config
        try:
            saved = self.save()
        except RuntimeError:
            self.fail("Valid EOS description text was incorrectly rejected as a CLI error.")
        self.assertTrue(saved.read_text(encoding="utf-8").endswith(config))

    def test_collect_enters_enable_before_reading_and_disconnects(self):
        self.session.check_enable_mode.side_effect = [False, True]
        self.assertEqual(self.collect(), CONFIG)
        self.assertEqual(self.session.method_calls, [
            call.check_enable_mode(), call.enable(), call.check_enable_mode(),
            call.send_command("show running-config", read_timeout=60,
                              strip_prompt=True, strip_command=True),
            call.disconnect(),
        ])

    def test_collect_already_privileged_preserves_output_and_connection_identity(self):
        raw = "\n  \n" + CONFIG + "\n\n"
        self.session.send_command.return_value = raw
        self.assertEqual(self.collect(), raw)
        self.connect.assert_called_once_with(
            device_type="arista_eos", host="192.0.2.1", username=USERNAME,
            password=PASSWORD, secret=PASSWORD, conn_timeout=15,
            auth_timeout=20, banner_timeout=20, fast_cli=False,
        )
        self.session.enable.assert_not_called()
        self.session.disconnect.assert_called_once_with()
        self.provider.assert_not_called()
        self.assertNotIn(PASSWORD, self.output.getvalue())

    def test_collect_failed_enable_prevents_read_and_disconnects(self):
        self.session.check_enable_mode.return_value = False
        with self.assertRaisesRegex(RuntimeError, "unable to enter privileged EXEC"):
            self.collect()
        self.session.enable.assert_called_once_with()
        self.session.send_command.assert_not_called()
        self.session.disconnect.assert_called_once_with()

    def test_collect_authentication_or_connection_timeout_prevents_reads(self):
        for failure in (NetmikoAuthenticationException(PASSWORD), NetmikoTimeoutException(PASSWORD)):
            with self.subTest(error=type(failure).__name__):
                self.connect.side_effect = failure
                with self.assertRaises(type(failure)):
                    self.collect()
        self.session.send_command.assert_not_called()
        self.session.disconnect.assert_not_called()
        self.assertNotIn(PASSWORD, self.output.getvalue())

    def test_collect_enable_command_and_validation_failures_disconnect(self):
        for stage in ("enable", "read", "validation"):
            with self.subTest(stage=stage):
                session = self.new_session(CONFIG)
                self.connect.return_value = session
                if stage == "enable":
                    session.check_enable_mode.return_value = False
                    session.enable.side_effect = RuntimeError("fixture enable failure")
                elif stage == "read":
                    session.send_command.side_effect = TimeoutError("fixture read timeout")
                else:
                    session.send_command.return_value = "% Invalid input"
                with self.assertRaises((RuntimeError, TimeoutError)):
                    self.collect()
                session.disconnect.assert_called_once_with()
                if stage == "enable":
                    session.send_command.assert_not_called()

    def test_disconnect_failure_preserves_success_or_original_read_error(self):
        self.session.disconnect.side_effect = OSError("fixture disconnect failure")
        self.assertEqual(self.collect(), CONFIG)
        self.session.send_command.side_effect = TimeoutError("fixture read timeout")
        with self.assertRaisesRegex(TimeoutError, "fixture read timeout"):
            self.collect()

    def test_save_creates_nested_folder_exact_filename_header_and_body(self):
        self.session.send_command.return_value = "\n\t " + CONFIG + "\n \t"
        saved = self.save()
        self.assertEqual(saved, self.output_dir / "R1" / "R1_20261019_103045.cfg")
        expected = (
            "! ============================================================\n"
            "! NetPilot Golden Configuration\n"
            "! ============================================================\n"
            "! Device: R1\n"
            "! Management IP: 192.0.2.1\n"
            "! Captured: 20261019_103045\n"
            "! Source: live running-config\n"
            "! ============================================================\n"
            "!\n"
            "! synthetic EOS configuration\n"
            "hostname R1\n"
            "interface Ethernet1\n"
            "   description Lab uplink — café\n"
            "   ip address 198.51.100.1/31\n"
            "   ipv6 address 2001:db8:41::1/64\n"
            "!\n"
            "end\n"
        )
        self.assertEqual(saved.read_bytes(), expected.encode("utf-8"))
        self.assertEqual(list(saved.parent.iterdir()), [saved])
        self.assertIn(f"[OK]      R1 -> {saved}", self.output.getvalue())

    def test_save_preserves_interior_whitespace_and_newlines(self):
        self.session.send_command.return_value = "\n hostname R1\r\n!\r\n\r\ninterface Ethernet1\r\n   description x  \r\nend\n\n"
        saved = self.save()
        self.assertTrue(saved.read_bytes().endswith(
            b"hostname R1\r\n!\r\n\r\ninterface Ethernet1\r\n   description x  \r\nend\n"))

    def test_save_publishes_only_after_complete_temporary_write(self):
        final = self.output_dir / "R1" / f"R1_{TIMESTAMP}.cfg"
        final.parent.mkdir(parents=True)
        final.write_bytes(b"previous snapshot must survive until replacement\n")
        original_replace = Path.replace
        observed = []

        def inspect_replace(source, destination):
            self.assertEqual(source, final.with_suffix(".tmp"))
            self.assertEqual(destination, final)
            self.assertEqual(final.read_bytes(), b"previous snapshot must survive until replacement\n")
            self.assertTrue(source.read_bytes().endswith(CONFIG.encode("utf-8")))
            self.assert_no_success()
            observed.append(source)
            return original_replace(source, destination)

        with patch.object(Path, "replace", autospec=True, side_effect=inspect_replace):
            self.assertEqual(self.save(), final)
        self.assertEqual(observed, [final.with_suffix(".tmp")])
        self.assertFalse(final.with_suffix(".tmp").exists())
        self.assertTrue(final.read_bytes().endswith(CONFIG.encode("utf-8")))

    def test_save_retrieval_failure_creates_no_device_directory_or_false_success(self):
        self.session.send_command.return_value = "\n\n"
        with self.assertRaisesRegex(RuntimeError, "empty"):
            self.save()
        self.assertFalse(self.output_dir.exists())
        self.assert_no_success()

    def test_save_output_file_in_place_of_directory_fails_safely(self):
        for location in ("root", "device"):
            with self.subTest(location=location):
                output = self.root / location
                blocking_file = output if location == "root" else output / "R1"
                blocking_file.parent.mkdir(parents=True, exist_ok=True)
                blocking_file.write_bytes(b"existing unrelated file")
                with patch.object(golden, "OUTPUT_DIR", output):
                    with self.assertRaises((FileExistsError, NotADirectoryError)):
                        self.save()
                self.assertEqual(blocking_file.read_bytes(), b"existing unrelated file")
                self.assert_no_success()

    def test_save_write_failures_preserve_previous_snapshot_without_success(self):
        final = self.output_dir / "R1" / f"R1_{TIMESTAMP}.cfg"
        final.parent.mkdir(parents=True)
        final.write_bytes(b"previous valid snapshot\n")
        for failure in (PermissionError("fixture denied"), OSError("fixture disk full")):
            with self.subTest(error=type(failure).__name__):
                with patch.object(Path, "write_text", side_effect=failure), \
                        patch.object(Path, "replace") as replace:
                    with self.assertRaises(type(failure)):
                        self.save()
                replace.assert_not_called()
                self.assertEqual(final.read_bytes(), b"previous valid snapshot\n")
                self.assert_no_success()

    def test_save_replace_failures_preserve_previous_snapshot_without_success(self):
        final = self.output_dir / "R1" / f"R1_{TIMESTAMP}.cfg"
        final.parent.mkdir(parents=True)
        final.write_bytes(b"previous valid snapshot\n")
        for failure in (PermissionError("fixture denied"), OSError("fixture replace failure")):
            with self.subTest(error=type(failure).__name__):
                with patch.object(Path, "replace", side_effect=failure):
                    with self.assertRaises(type(failure)):
                        self.save()
                self.assertEqual(final.read_bytes(), b"previous valid snapshot\n")
                self.assert_no_success()

    def test_main_saves_each_actual_device_with_shared_timestamp_and_correct_content(self):
        r2 = self.new_session("hostname R2\ninterface Loopback9\n   ip address 192.0.2.29/32\nend\n")
        self.connect.side_effect = [self.session, r2]
        self.assertEqual(self.run_main(), 0)
        self.provider.assert_called_once_with()
        self.assertEqual([item.kwargs["host"] for item in self.connect.call_args_list],
                         ["192.0.2.1", "192.0.2.2"])
        self.assertEqual({str(path.relative_to(self.output_dir)) for path in self.output_dir.rglob("*.cfg")},
                         {"R1/R1_20261019_103045.cfg", "R2/R2_20261019_103045.cfg"})
        r1_text = (self.output_dir / "R1" / f"R1_{TIMESTAMP}.cfg").read_text(encoding="utf-8")
        r2_text = (self.output_dir / "R2" / f"R2_{TIMESTAMP}.cfg").read_text(encoding="utf-8")
        self.assertIn("! Device: R1\n! Management IP: 192.0.2.1\n", r1_text)
        self.assertIn("hostname R1\n", r1_text)
        self.assertIn("! Device: R2\n! Management IP: 192.0.2.2\n", r2_text)
        self.assertIn("hostname R2\ninterface Loopback9\n   ip address 192.0.2.29/32\n", r2_text)
        self.assertIn("Saved:  2\nFailed: 0", self.output.getvalue())
        self.assertNotIn(PASSWORD, self.output.getvalue())

    def test_main_selected_device_and_unknown_name_report_actual_counts(self):
        self.session.send_command.return_value = "hostname R2\nend\n"
        self.assertEqual(self.run_main("R2", "R404"), 1)
        self.connect.assert_called_once()
        self.assertEqual(self.connect.call_args.kwargs["host"], "192.0.2.2")
        self.assertFalse((self.output_dir / "R1").exists())
        self.assertFalse((self.output_dir / "R404").exists())
        self.assertIn("R404: device not found in NSOT", self.output.getvalue())
        self.assertIn("Saved:  1\nFailed: 1", self.output.getvalue())

    def test_main_authentication_failure_is_sanitized_and_remaining_device_can_save(self):
        r2 = self.new_session("hostname R2\nend\n")
        self.connect.side_effect = [NetmikoAuthenticationException(PASSWORD), r2]
        self.assertEqual(self.run_main(), 1)
        self.assertFalse((self.output_dir / "R1").exists())
        self.assertTrue((self.output_dir / "R2" / f"R2_{TIMESTAMP}.cfg").is_file())
        self.assertIn("[FAIL]    R1: capture failed", self.output.getvalue())
        self.assertIn("Saved:  1\nFailed: 1", self.output.getvalue())
        self.assertNotIn(PASSWORD, self.output.getvalue() + self.errors.getvalue())

    def test_main_vault_failure_prevents_inventory_read_connection_and_output(self):
        self.provider.side_effect = RuntimeError(PASSWORD)
        with patch.object(golden, "load_inventory") as load:
            self.assertEqual(self.run_main("R1"), 1)
        load.assert_not_called()
        self.connect.assert_not_called()
        self.assertFalse(self.output_dir.exists())
        self.assertIn("credentials unavailable", self.output.getvalue())
        self.assertNotIn(PASSWORD, self.output.getvalue() + self.errors.getvalue())
        self.assert_no_success()

    def test_main_invalid_yaml_stops_before_connection_or_output(self):
        self.inventory_path.write_text(f"devices: [\n{PASSWORD}", encoding="utf-8")
        self.assertEqual(self.run_main("R1"), 1)
        self.connect.assert_not_called()
        self.assertFalse(self.output_dir.exists())
        self.assertIn("Unable to load NSOT", self.output.getvalue())
        self.assertNotIn(PASSWORD, self.output.getvalue() + self.errors.getvalue())
        self.assert_no_success()

    def test_main_failed_publication_reports_failure_without_success(self):
        with patch.object(Path, "replace", side_effect=PermissionError(PASSWORD)):
            self.assertEqual(self.run_main("R1"), 1)
        self.assertFalse((self.output_dir / "R1" / f"R1_{TIMESTAMP}.cfg").exists())
        self.assertIn("Saved:  0\nFailed: 1", self.output.getvalue())
        self.assertNotIn(PASSWORD, self.output.getvalue() + self.errors.getvalue())
        self.assert_no_success()


if __name__ == "__main__":
    unittest.main()

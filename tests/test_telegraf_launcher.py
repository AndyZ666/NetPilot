"""Offline launcher checks; only explicitly identified Python fixtures execute.

All token/configuration/process metadata comes from temporary fixtures. These
tests never run Telegraf or 1Password, read real secrets, or contact a service.
"""

import configparser
import io
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import call, mock_open, patch

from security import telegraf_launcher as launcher


CONFIGURATION = '''
[[inputs.gnmi]]
  addresses = ["192.0.2.1:6030"]
  username = "${NETPILOT_USERNAME}"
  password = "${NETPILOT_PASSWORD}"
[[outputs.influxdb_v2]]
  urls = ["http://192.0.2.2:8086"]
  token = "${INFLUX_TOKEN}"
'''


class TelegrafLauncherTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = self.root / "fixture.conf"
        self.config.write_text(CONFIGURATION)
        self.executable = self.root / "fixture-collector"
        self.executable.write_text("Not a real executable; normal tests mock exec.\n")
        self.executable.chmod(0o700)
        self.token = self.root / "fixture-onepassword-token"
        self.token.write_text("FAKE-TOKEN-NOT-A-CREDENTIAL\n")
        self.token.chmod(0o600)
        self.runtime = self.root / "runtime"
        self.runtime.mkdir(mode=0o700)
        self.proc = self.root / "proc"
        self.proc.mkdir()
        for attribute, value in (("CONFIG", self.config), ("TELEGRAF", self.executable), ("PROC", self.proc)):
            self.enterContext(patch.object(launcher, attribute, value))
        self.enterContext(patch.object(launcher.credential_provider, "TOKEN_FILE", self.token))
        self.provider = self.enterContext(patch.object(
            launcher.credential_provider, "get_credentials",
            return_value=("fixture-user", "fixture-password"),
        ))
        self.exec = self.enterContext(patch.object(launcher, "exec_collector"))
        self.which = self.enterContext(patch.object(launcher.shutil, "which", return_value="/fake/op"))
        # Forbid subprocess.run as an additional guard against real op access.
        self.enterContext(patch.object(subprocess, "run", side_effect=AssertionError("No real CLI calls in unit tests")))
        self.enterContext(patch("socket.create_connection", side_effect=AssertionError("No network in launcher tests")))
        self.output = self.enterContext(patch("sys.stdout", new_callable=io.StringIO))
        self.environment = {
            "PATH": "/fixture/bin", "XDG_RUNTIME_DIR": str(self.runtime),
            "INFLUX_TOKEN": "fixture-influx-token", "UNRELATED_SETTING": "preserved",
            "NETPILOT_USERNAME": "stale-user", "NETPILOT_PASSWORD": "stale-password",
            "OP_SERVICE_ACCOUNT_TOKEN": "stale-op-token", "OP_SESSION_example": "stale-session",
            "OP_DEBUG": "true", "ENCRYPTED_CREDENTIALS_DIRECTORY": "/ignored/credentials",
        }
        self.enterContext(patch.dict(os.environ, self.environment, clear=True))

    @property
    def lock_directory(self):
        return self.runtime / "netpilot-telegraf"

    def managed_token(self, text="managed-influx-token\n", mode=0o600):
        directory = self.root / "managed"
        directory.mkdir(exist_ok=True)
        path = directory / "influx-token"
        path.write_text(text)
        path.chmod(mode)
        os.environ["CREDENTIALS_DIRECTORY"] = str(directory)
        return path

    def add_process(self, pid, name):
        directory = self.proc / str(pid)
        directory.mkdir()
        (directory / "comm").write_text(name + "\n")
        return directory

    def assert_no_secrets(self):
        for marker in ("fixture-password", "fixture-influx-token", "managed-influx-token",
                       "FAKE-TOKEN", "stale-password", "LEAK-MARKER"):
            self.assertNotIn(marker, self.output.getvalue())

    def test_success_fetches_fresh_pair_overrides_stale_env_and_preserves_unrelated(self):
        before = dict(os.environ)
        self.assertEqual(launcher.main([]), 0)
        self.provider.assert_called_once_with()
        self.exec.assert_called_once()
        child, descriptor = self.exec.call_args.args
        self.assertEqual(child["NETPILOT_USERNAME"], "fixture-user")
        self.assertEqual(child["NETPILOT_PASSWORD"], "fixture-password")
        self.assertEqual(child["INFLUX_TOKEN"], "fixture-influx-token")
        self.assertEqual(child["UNRELATED_SETTING"], "preserved")
        self.assertEqual(child["PATH"], "/fixture/bin")
        self.assertFalse(any(key.startswith("OP_") for key in child))
        self.assertNotIn("ENCRYPTED_CREDENTIALS_DIRECTORY", child)
        self.assertEqual(dict(os.environ), before)
        self.assertIsInstance(descriptor, int)
        with self.assertRaises(OSError):
            os.fstat(descriptor)  # Released when mocked exec returns.
        self.assert_no_secrets()

    def test_managed_influx_source_precedes_environment_and_directory_is_not_forwarded(self):
        self.managed_token()
        self.assertEqual(launcher.main([]), 0)
        child = self.exec.call_args.args[0]
        self.assertEqual(child["INFLUX_TOKEN"], "managed-influx-token")
        self.assertNotIn("CREDENTIALS_DIRECTORY", child)
        self.assert_no_secrets()

    def test_provider_failure_never_falls_back_or_executes(self):
        self.provider.side_effect = RuntimeError("LEAK-MARKER")
        self.assertEqual(launcher.main([]), 1)
        self.exec.assert_not_called()
        self.assertIn("Device credentials unavailable from 1Password", self.output.getvalue())
        self.assert_no_secrets()

    def test_check_never_reads_op_token_fetches_vault_executes_or_creates_lock(self):
        original_open = Path.open

        def checked_open(path, *args, **kwargs):
            if path == self.token:
                raise AssertionError("--check must not read the service account token")
            return original_open(path, *args, **kwargs)

        with patch.object(Path, "open", checked_open), \
                patch.object(launcher.credential_provider, "_read_token", side_effect=AssertionError("No token reads")):
            self.assertEqual(launcher.main(["--check"]), 0)
        self.provider.assert_not_called()
        self.exec.assert_not_called()
        self.assertFalse(self.lock_directory.exists())
        self.assertIn("Vault authentication and telemetry health were not tested", self.output.getvalue())
        self.assert_no_secrets()

    def test_check_reports_existing_collector_without_stopping_it(self):
        directory = self.add_process(42, "telegraf")
        self.assertEqual(launcher.main(["--check"]), 0)
        self.assertTrue((directory / "comm").exists())
        self.assertIn("[WARN]", self.output.getvalue())
        self.assertFalse(self.lock_directory.exists())
        self.provider.assert_not_called()
        self.exec.assert_not_called()

    def test_missing_influx_token_blocks_before_vault_or_exec(self):
        os.environ.pop("INFLUX_TOKEN")
        self.assertEqual(launcher.main([]), 1)
        self.provider.assert_not_called()
        self.exec.assert_not_called()

    def test_missing_or_nonexecutable_collector_blocks_before_vault(self):
        for action in (lambda: self.executable.chmod(0o600), self.executable.unlink):
            with self.subTest(action=action.__name__):
                action()
                self.assertEqual(launcher.main([]), 1)
        self.provider.assert_not_called()
        self.exec.assert_not_called()
        self.assertFalse(self.lock_directory.exists())

    def test_missing_configuration_or_cli_blocks_before_vault(self):
        self.which.return_value = None
        self.assertEqual(launcher.main([]), 1)
        self.which.return_value = "/fake/op"
        self.config.unlink()
        self.assertEqual(launcher.main([]), 1)
        self.provider.assert_not_called()
        self.exec.assert_not_called()

    def test_symlink_configuration_is_rejected(self):
        target = self.root / "target.conf"
        self.config.rename(target)
        self.config.symlink_to(target)
        self.assertEqual(launcher.main([]), 1)
        self.provider.assert_not_called()
        self.exec.assert_not_called()

    def test_nonplaceholder_credentials_and_malformed_config_are_rejected(self):
        invalid = (
            CONFIGURATION.replace("${NETPILOT_USERNAME}", "literal-user"),
            CONFIGURATION.replace("${NETPILOT_PASSWORD}", "literal-password"),
            CONFIGURATION.replace("${INFLUX_TOKEN}", "literal-token"),
            "not valid TOML [",
        )
        for text in invalid:
            with self.subTest(text=text):
                self.config.write_text(text)
                self.assertEqual(launcher.main([]), 1)
        self.provider.assert_not_called()
        self.exec.assert_not_called()

    def test_missing_or_insecure_op_token_metadata_blocks_without_read(self):
        self.token.chmod(0o644)
        self.assertEqual(launcher.main(["--check"]), 1)
        self.token.unlink()
        self.assertEqual(launcher.main(["--check"]), 1)
        self.provider.assert_not_called()
        self.exec.assert_not_called()

    def test_managed_source_missing_empty_unsafe_or_symlink_never_falls_back(self):
        path = self.managed_token()
        for case in ("empty", "permissions", "missing", "symlink"):
            with self.subTest(case=case):
                if case == "empty":
                    path.write_text("\r\n")
                elif case == "permissions":
                    path.write_text("managed-influx-token")
                    path.chmod(0o644)
                elif case == "missing":
                    path.unlink()
                else:
                    target = self.root / "other-token"
                    target.write_text("another-fixture-token")
                    target.chmod(0o600)
                    path.symlink_to(target)
                self.assertEqual(launcher.main([]), 1)
        self.provider.assert_not_called()
        self.exec.assert_not_called()
        self.assert_no_secrets()

    def test_relative_managed_directory_does_not_fall_back(self):
        os.environ["CREDENTIALS_DIRECTORY"] = "relative-directory"
        self.assertEqual(launcher.main([]), 1)
        self.provider.assert_not_called()
        self.exec.assert_not_called()

    def test_managed_file_invalid_utf8_or_oversized_is_rejected(self):
        path = self.managed_token()
        for raw in (b"\xff", b"a" * (launcher.MAX_SECRET_BYTES + 1)):
            with self.subTest(length=len(raw)):
                path.write_bytes(raw)
                self.assertEqual(launcher.main([]), 1)
        self.provider.assert_not_called()
        self.exec.assert_not_called()

    def test_interpolation_rejects_empty_controls_quote_and_backslash(self):
        for value in (None, "", "  ", "one\ntwo", "one\rtwo", "one\x00two", "one\ttwo",
                      'one"two', "one\\two", "one\u2028two", "one\u0085two"):
            with self.subTest(value=value), self.assertRaises(launcher.LauncherError):
                launcher.interpolation_value(value)
        self.assertEqual(launcher.interpolation_value(" space !#$%&'()+,-./:;<=>?@[]^_`{|}~ "),
                         " space !#$%&'()+,-./:;<=>?@[]^_`{|}~ ")

    def test_invalid_provider_field_prevents_exec(self):
        for pair in (("", "fixture-password"), ("fixture-user", 'bad"password'), ("bad\\user", "fixture-password")):
            with self.subTest(pair=pair):
                self.provider.return_value = pair
                self.assertEqual(launcher.main([]), 1)
        self.exec.assert_not_called()
        self.assert_no_secrets()

    def test_duplicate_collector_before_vault_is_left_untouched(self):
        self.add_process(999, "telegraf")
        self.assertEqual(launcher.main([]), 1)
        self.provider.assert_not_called()
        self.exec.assert_not_called()
        self.assertEqual((self.proc / "999" / "comm").read_text(), "telegraf\n")

    def test_duplicate_collector_appearing_during_vault_prevents_exec(self):
        with patch.object(launcher, "existing_collectors", side_effect=[[], [77]]) as processes:
            self.assertEqual(launcher.main([]), 1)
        self.assertEqual(processes.call_count, 2)
        self.provider.assert_called_once_with()
        self.exec.assert_not_called()
        self.assertIn("appeared during preflight", self.output.getvalue())

    def test_process_scan_reads_only_comm_and_ignores_noncollector_processes(self):
        self.add_process(33, "python3")
        self.add_process(22, "telegraf")
        self.add_process(11, "telegraf")
        (self.proc / "not-a-pid").mkdir()
        (self.proc / "44").mkdir()  # Process has exited before comm read.
        original_read = Path.read_text

        def checked_read(path, *args, **kwargs):
            self.assertEqual(path.name, "comm")
            return original_read(path, *args, **kwargs)

        with patch.object(Path, "read_text", checked_read):
            self.assertEqual(launcher.existing_collectors(), [11, 22])

    def test_unreadable_process_metadata_refuses_start_safely(self):
        with patch.object(Path, "iterdir", side_effect=PermissionError("LEAK-MARKER")):
            self.assertEqual(launcher.main([]), 1)
        self.provider.assert_not_called()
        self.exec.assert_not_called()
        self.assert_no_secrets()

    def test_missing_or_nonprivate_runtime_directory_refuses_start(self):
        self.runtime.chmod(0o755)
        self.assertEqual(launcher.main([]), 1)
        self.runtime.rmdir()
        self.assertEqual(launcher.main([]), 1)
        self.provider.assert_not_called()
        self.exec.assert_not_called()

    def test_lock_refuses_second_launcher_and_preserves_inode(self):
        with launcher.collector_lock(self.lock_directory) as descriptor:
            inode = os.fstat(descriptor).st_ino
            self.assertEqual(launcher.main([]), 1)
            self.provider.assert_not_called()
            self.exec.assert_not_called()
            with self.assertRaisesRegex(launcher.LauncherError, "active"):
                with launcher.collector_lock(self.lock_directory):
                    self.fail("Second lock must fail")
        with launcher.collector_lock(self.lock_directory) as descriptor:
            self.assertEqual(os.fstat(descriptor).st_ino, inode)
        self.assertTrue((self.lock_directory / "collector.lock").is_file())

    def test_lock_rejects_symlink_and_group_readable_files(self):
        self.lock_directory.mkdir(mode=0o700)
        lock = self.lock_directory / "collector.lock"
        lock.write_text("")
        lock.chmod(0o644)
        with self.assertRaises(launcher.LauncherError):
            with launcher.collector_lock(self.lock_directory):
                self.fail("Unsafe lock accepted")
        lock.unlink()
        lock.symlink_to(self.token)
        with self.assertRaises(launcher.LauncherError):
            with launcher.collector_lock(self.lock_directory):
                self.fail("Symlink lock accepted")

    def test_exec_failure_is_sanitized_and_keyboard_interrupt_has_130_status(self):
        self.exec.side_effect = launcher.LauncherError("Telegraf could not be executed; no retry was attempted.")
        self.assertEqual(launcher.main([]), 1)
        self.exec.side_effect = RuntimeError("LEAK-MARKER")
        self.assertEqual(launcher.main([]), 1)
        self.exec.side_effect = KeyboardInterrupt()
        self.assertEqual(launcher.main([]), 130)
        self.assert_no_secrets()


class CollectorExecTests(unittest.TestCase):
    def test_draft_service_preserves_lock_inode_and_does_not_retry_failed_launch(self):
        # Removing the runtime directory after a failed competing launch would
        # unlink the manual collector's lock and permit a second collector.
        unit = configparser.ConfigParser(interpolation=None, strict=False)
        unit.read(launcher.ROOT / "security" / "systemd" / "netpilot-telegraf.service")
        self.assertEqual(unit["Service"]["RuntimeDirectory"], "netpilot-telegraf")
        self.assertEqual(unit["Service"]["RuntimeDirectoryPreserve"], "yes")
        self.assertEqual(unit["Service"]["Restart"], "no")

    def test_exec_uses_fixed_argv_suppresses_both_streams_and_inherits_lock(self):
        child = {"NETPILOT_PASSWORD": "fixture-password"}
        sink = mock_open()
        sink.return_value.fileno.return_value = 90
        with patch("builtins.open", sink), \
                patch.object(launcher.os, "dup", side_effect=[81, 82]) as dup, \
                patch.object(launcher.os, "dup2") as dup2, \
                patch.object(launcher.os, "close") as close, \
                patch.object(launcher.os, "set_inheritable") as inherit, \
                patch.object(launcher.os, "execve") as execute:
            launcher.exec_collector(child, 73)
        self.assertEqual(dup.call_args_list, [call(1), call(2)])
        self.assertEqual(dup2.call_args_list, [call(90, 1), call(90, 2), call(81, 1), call(82, 2)])
        self.assertEqual(close.call_args_list, [call(81), call(82)])
        inherit.assert_called_once_with(73, True)
        execute.assert_called_once_with(str(launcher.TELEGRAF),
                                       [str(launcher.TELEGRAF), "--config", str(launcher.CONFIG)], child)
        self.assertNotIn("fixture-password", repr(execute.call_args.args[:2]))

    def test_exec_failure_restores_streams_without_exception_text(self):
        sink = mock_open()
        sink.return_value.fileno.return_value = 90
        with patch("builtins.open", sink), \
                patch.object(launcher.os, "dup", side_effect=[81, 82]), \
                patch.object(launcher.os, "dup2") as dup2, \
                patch.object(launcher.os, "close") as close, \
                patch.object(launcher.os, "set_inheritable"), \
                patch.object(launcher.os, "execve", side_effect=OSError("LEAK-MARKER")):
            with self.assertRaises(launcher.LauncherError) as raised:
                launcher.exec_collector({}, 73)
        self.assertNotIn("LEAK-MARKER", str(raised.exception))
        self.assertTrue(raised.exception.__suppress_context__)
        self.assertEqual(dup2.call_args_list[-2:], [call(81, 1), call(82, 2)])
        self.assertEqual(close.call_args_list, [call(81), call(82)])


class DummyCollectorProcessTests(unittest.TestCase):
    """Actual exec/signal checks run a tiny temporary Python program, never Telegraf."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.collector = self.root / "dummy-python-collector"
        self.collector.write_text(f"#!{sys.executable}\n" + '''
import os
from pathlib import Path
import sys
import time

print("FAKE-COLLECTOR-STDOUT", flush=True)
print("FAKE-COLLECTOR-STDERR", file=sys.stderr, flush=True)
Path(os.environ["FIXTURE_MARKER"]).write_text(str(os.getpid()))
if os.environ["FIXTURE_MODE"] == "exit":
    raise SystemExit(23)
while True:
    time.sleep(30)
''')
        self.collector.chmod(0o700)
        self.marker = self.root / "started"
        self.lock = self.root / "lock"
        self.process = None
        self.addCleanup(self.stop_own_fixture)

    def stop_own_fixture(self):
        if self.process is not None and self.process.poll() is None:
            self.process.kill()
            self.process.communicate(timeout=5)

    def launch_fixture(self, mode):
        harness = '''
import os
from pathlib import Path
import sys
sys.path.insert(0, sys.argv[1])
from security import telegraf_launcher as launcher
def forbidden():
    raise AssertionError("The dummy process must never fetch credentials")
launcher.credential_provider.get_credentials = forbidden
launcher.TELEGRAF = Path(sys.argv[2])
launcher.CONFIG = Path(sys.argv[3])
with launcher.collector_lock(Path(sys.argv[4])) as descriptor:
    launcher.exec_collector(dict(os.environ), descriptor)
'''
        environment = {
            "PYTHONDONTWRITEBYTECODE": "1", "FIXTURE_MODE": mode,
            "FIXTURE_MARKER": str(self.marker),
        }
        self.process = subprocess.Popen(
            [sys.executable, "-B", "-c", harness, str(launcher.ROOT),
             str(self.collector), str(self.root / "unused.conf"), str(self.lock)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=self.root, env=environment, text=True,
        )
        return self.process

    def test_exec_preserves_native_exit_status_and_suppresses_dummy_output(self):
        process = self.launch_fixture("exit")
        stdout, stderr = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 23)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        self.assertEqual(int(self.marker.read_text()), process.pid)
        with launcher.collector_lock(self.lock):
            pass  # Lock is released by process exit.

    def test_sigterm_reaches_same_pid_and_lock_survives_exec_until_exit(self):
        process = self.launch_fixture("wait")
        deadline = time.monotonic() + 5
        recorded_pid = ""
        while process.poll() is None and time.monotonic() < deadline:
            try:
                recorded_pid = self.marker.read_text()
            except FileNotFoundError:
                pass
            if recorded_pid.isdigit():
                break
            time.sleep(0.01)
        self.assertTrue(recorded_pid.isdigit(), "Dummy collector did not start")
        self.assertEqual(int(recorded_pid), process.pid)
        with self.assertRaisesRegex(launcher.LauncherError, "active"):
            with launcher.collector_lock(self.lock):
                self.fail("Inherited collector lock should remain held")
        process.terminate()  # Signal only the PID created by this test.
        stdout, stderr = process.communicate(timeout=5)
        self.assertEqual(process.returncode, -signal.SIGTERM)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        with launcher.collector_lock(self.lock):
            pass


if __name__ == "__main__":
    unittest.main()

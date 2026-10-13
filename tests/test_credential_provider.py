"""Mock-only provider tests: no token-file access, subprocesses, or Vault calls."""

from contextlib import redirect_stderr, redirect_stdout
import errno
from io import StringIO
import json
import os
from pathlib import Path
import stat
import subprocess
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from security import credential_provider as provider


class CredentialProviderTests(unittest.TestCase):
    def setUp(self):
        # Patch the actual OS boundaries as well as the path: accidentally
        # removing a provider helper mock cannot access the real token or CLI.
        self.patches = [
            patch.object(provider, "TOKEN_FILE", Path("/fake/token-fixture")),
            patch.object(provider.os, "open", return_value=41),
            patch.object(provider.os, "fstat", return_value=SimpleNamespace(
                st_mode=stat.S_IFREG | 0o600, st_uid=1000,
            )),
            patch.object(provider.os, "geteuid", return_value=1000),
            patch.object(provider.os, "read", return_value=b"fixture-service-token\n"),
            patch.object(provider.os, "close"),
            patch.object(provider.subprocess, "run", return_value=SimpleNamespace(
                stdout=self.fields(), stderr="",
            )),
            patch.dict(provider.os.environ, {
                "PATH": "/fixture/bin",
                "NETPILOT_USERNAME": "ignored-env-user",
                "NETPILOT_PASSWORD": "ignored-env-password",
                "OP_SERVICE_ACCOUNT_TOKEN": "ignored-env-token",
                "OP_CONNECT_HOST": "https://ignored.invalid",
                "OP_CONNECT_TOKEN": "ignored-connect-token",
                "OP_SESSION": "ignored-session",
                "OP_SESSION_fixture": "ignored-session",
                "OP_ACCOUNT": "ignored-account",
                "OP_DEBUG": "true",
                "OP_CACHE": "true",
                "OP_INCLUDE_ARCHIVE": "true",
            }, clear=True),
        ]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    @staticmethod
    def fields(username="fixture-user", password="fixture-password"):
        return json.dumps([
            {"id": "username", "label": "username", "type": "STRING", "value": username},
            {"id": "password", "label": "password", "type": "CONCEALED", "value": password},
        ])

    def assert_safe_failure(self, call, expected):
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                call()
            except RuntimeError as exc:
                self.assertEqual(str(exc), expected)
                formatted = "".join(traceback.format_exception(exc))
                for secret in ("fixture-service-token", "LEAK-MARKER", "fixture-password"):
                    self.assertNotIn(secret, formatted)
            else:
                self.fail("Expected a sanitized RuntimeError")
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")

    def test_pair_read_uses_one_item_request_and_existing_tuple_api(self):
        self.assertEqual(provider.get_credentials(), ("fixture-user", "fixture-password"))
        provider.subprocess.run.assert_called_once()
        args, options = provider.subprocess.run.call_args
        self.assertEqual(args, ([
            "op", "item", "get", "NetPilot-Current", "--vault", "NetPilot-Secrets",
            "--fields", "label=username,label=password", "--format", "json", "--reveal",
        ],))
        self.assertIs(options["shell"], False)
        self.assertIs(options["check"], True)
        self.assertIs(options["capture_output"], True)
        self.assertEqual(options["stdin"], subprocess.DEVNULL)
        self.assertEqual(options["timeout"], 30)
        self.assertEqual(options["encoding"], "utf-8")
        self.assertNotIn("fixture-service-token", repr(args))
        self.assertNotIn("fixture-password", repr(args))

    def test_sensitive_json_write_uses_stdin_without_secret_arguments(self):
        payload = json.dumps({"password": "fixture-password"})
        provider._run_op(["item", "create", "-", "--vault", "NetPilot-Secrets"], input_text=payload)
        args, options = provider.subprocess.run.call_args
        self.assertEqual(options["input"], payload)
        self.assertNotIn("stdin", options)
        self.assertNotIn("fixture-password", repr(args))
        self.assertIs(options["shell"], False)
        self.assertIs(options["capture_output"], True)

    def test_sensitive_write_failure_does_not_expose_payload(self):
        provider.subprocess.run.side_effect = subprocess.CalledProcessError(
            1, ["op"], output="fixture-password LEAK-MARKER", stderr="LEAK-MARKER"
        )
        payload = "fixture-password"
        self.assert_safe_failure(
            lambda: provider._run_op(["item", "edit", "fixture-item"], input_text=payload),
            "Failed to retrieve 1Password credential",
        )

    def test_invalid_stdin_type_is_rejected_before_token_access(self):
        with self.assertRaises(ValueError):
            provider._run_op(["item", "create", "-"], input_text={"password": "fixture-password"})
        provider.os.open.assert_not_called()
        provider.subprocess.run.assert_not_called()

    def test_child_environment_is_isolated_and_service_account_only(self):
        before = dict(os.environ)
        provider.get_credentials()
        env = provider.subprocess.run.call_args.kwargs["env"]
        self.assertEqual(env["OP_SERVICE_ACCOUNT_TOKEN"], "fixture-service-token")
        self.assertEqual(env["PATH"], "/fixture/bin")
        for key in ("OP_CONNECT_HOST", "OP_CONNECT_TOKEN", "OP_SESSION", "OP_SESSION_fixture", "OP_ACCOUNT"):
            self.assertNotIn(key, env)
        for key in ("OP_DEBUG", "OP_CACHE", "OP_BIOMETRIC_UNLOCK_ENABLED", "OP_INCLUDE_ARCHIVE"):
            self.assertEqual(env[key], "false")
        self.assertEqual(dict(os.environ), before)

    def test_every_operation_reads_fresh_credentials_and_token(self):
        provider.subprocess.run.side_effect = [
            SimpleNamespace(stdout=self.fields()),
            SimpleNamespace(stdout=self.fields("next-user", "next-password")),
        ]
        provider.os.read.side_effect = [b"first-fixture-token", b"next-fixture-token"]
        self.assertEqual(provider.get_credentials(), ("fixture-user", "fixture-password"))
        self.assertEqual(provider.get_credentials(), ("next-user", "next-password"))
        self.assertEqual(provider.os.open.call_count, 2)
        self.assertEqual(provider.os.read.call_count, 2)
        self.assertEqual(provider.subprocess.run.call_count, 2)
        self.assertEqual(provider.subprocess.run.call_args.kwargs["env"]["OP_SERVICE_ACCOUNT_TOKEN"], "next-fixture-token")

    def test_pair_fields_matched_by_label_and_password_is_not_stripped(self):
        payload = json.loads(self.fields(password="  fixture,\"password\" with spaces  "))
        provider.subprocess.run.return_value.stdout = json.dumps(list(reversed(payload)))
        self.assertEqual(provider.get_credentials(), ("fixture-user", "  fixture,\"password\" with spaces  "))

    def test_read_secret_keeps_supported_field_api(self):
        for field in ("username", "password"):
            with self.subTest(field=field):
                provider.subprocess.run.return_value.stdout = "  fixture-field  \r\n"
                self.assertEqual(provider.read_secret(field), "  fixture-field  ")
                self.assertEqual(provider.subprocess.run.call_args.args[0], [
                    "op", "read", f"op://NetPilot-Secrets/NetPilot-Current/{field}"
                ])

    def test_unsupported_field_rejected_before_any_secret_access(self):
        for field in (None, "token", "password;anything", "username\npassword", [], {}):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "Unsupported credential field"):
                provider.read_secret(field)
        provider.os.open.assert_not_called()
        provider.subprocess.run.assert_not_called()

    def test_missing_token_has_no_environment_fallback(self):
        provider.os.open.side_effect = FileNotFoundError("LEAK-MARKER")
        self.assert_safe_failure(provider.get_credentials, "1Password token file missing")
        provider.os.read.assert_not_called()
        provider.subprocess.run.assert_not_called()
        provider.os.close.assert_not_called()

    def test_unreadable_or_symlink_token_is_sanitized(self):
        for error in (PermissionError("LEAK-MARKER"), OSError(errno.ELOOP, "LEAK-MARKER")):
            with self.subTest(error_type=type(error).__name__):
                provider.os.open.side_effect = error
                self.assert_safe_failure(provider.get_credentials, "Unable to read 1Password token file")
        provider.os.read.assert_not_called()
        provider.subprocess.run.assert_not_called()

    def test_open_uses_read_only_no_follow_and_no_fifo_blocking(self):
        provider.get_credentials()
        provider.os.open.assert_called_once_with(
            Path("/fake/token-fixture"), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        )
        provider.os.fstat.assert_called_once_with(41)
        provider.os.close.assert_called_once_with(41)

    def test_insecure_permissions_rejected_before_read(self):
        for mode in (0o604, 0o620, 0o640, 0o660, 0o666, 0o700 | 0o007):
            with self.subTest(mode=oct(mode)):
                provider.os.fstat.return_value.st_mode = stat.S_IFREG | mode
                self.assert_safe_failure(provider.get_credentials, "Insecure 1Password token file permissions")
        provider.os.read.assert_not_called()
        provider.subprocess.run.assert_not_called()
        self.assertEqual(provider.os.close.call_count, 6)

    def test_other_owner_rejected_before_read(self):
        provider.os.fstat.return_value.st_uid = 2000
        self.assert_safe_failure(provider.get_credentials, "Insecure 1Password token file permissions")
        provider.os.read.assert_not_called()
        provider.subprocess.run.assert_not_called()

    def test_non_regular_file_rejected_before_read(self):
        for kind in (stat.S_IFDIR, stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFLNK):
            with self.subTest(kind=kind):
                provider.os.fstat.return_value.st_mode = kind | 0o600
                self.assert_safe_failure(provider.get_credentials, "1Password token must be a regular file")
        provider.os.read.assert_not_called()
        provider.subprocess.run.assert_not_called()

    def test_token_stat_read_and_close_errors_are_sanitized(self):
        for operation in (provider.os.fstat, provider.os.read, provider.os.close):
            with self.subTest(operation=operation._mock_name):
                operation.side_effect = OSError("LEAK-MARKER")
                self.assert_safe_failure(provider.get_credentials, "Unable to read 1Password token file")
                operation.side_effect = None
        provider.subprocess.run.assert_not_called()

    def test_empty_token_is_rejected(self):
        for raw in (b"", b" \r\n\t "):
            with self.subTest(raw=raw):
                provider.os.read.return_value = raw
                self.assert_safe_failure(provider.get_credentials, "Empty 1Password token")
        provider.subprocess.run.assert_not_called()

    def test_malformed_and_oversized_tokens_are_rejected(self):
        for raw in (b"part1\npart2", b"part1\x00part2", b"part1 part2", b"\xff", b"x" * 65537):
            with self.subTest(length=len(raw)):
                provider.os.read.return_value = raw
                self.assert_safe_failure(provider.get_credentials, "Invalid 1Password token file")
        provider.subprocess.run.assert_not_called()

    def test_missing_cli_error_is_sanitized(self):
        provider.subprocess.run.side_effect = FileNotFoundError("LEAK-MARKER")
        self.assert_safe_failure(provider.get_credentials, "1Password CLI is not available")

    def test_cli_errors_never_leak_exception_or_captured_output(self):
        errors = [
            PermissionError("LEAK-MARKER"),
            OSError("LEAK-MARKER"),
            subprocess.CalledProcessError(1, ["LEAK-MARKER"], output="LEAK-MARKER", stderr="LEAK-MARKER"),
            subprocess.TimeoutExpired(["LEAK-MARKER"], 30, output="LEAK-MARKER", stderr="LEAK-MARKER"),
            UnicodeDecodeError("utf-8", b"LEAK-MARKER\xff", 11, 12, "LEAK-MARKER"),
        ]
        for error in errors:
            with self.subTest(error_type=type(error).__name__):
                provider.subprocess.run.side_effect = error
                self.assert_safe_failure(provider.get_credentials, "Failed to retrieve 1Password credential")

    def test_cli_response_requires_text(self):
        provider.subprocess.run.return_value.stdout = None
        self.assert_safe_failure(provider.get_credentials, "Invalid 1Password credential response")

    def test_invalid_json_and_shapes_fail_without_output_leak(self):
        for output in ("LEAK-MARKER", "", "null", "{}", '"LEAK-MARKER"', "[null]", "[[]]"):
            with self.subTest(output=output):
                provider.subprocess.run.return_value.stdout = output
                self.assert_safe_failure(provider.get_credentials, "Invalid 1Password credential response")

    def test_duplicate_or_unexpected_labels_fail_closed(self):
        payloads = [
            [{"label": "password", "value": "LEAK-MARKER"}] * 2,
            [{"label": "unexpected", "value": "LEAK-MARKER"}],
            [{"label": [], "value": "LEAK-MARKER"}],
            [{"value": "LEAK-MARKER"}],
        ]
        for fields in payloads:
            with self.subTest(fields=fields):
                provider.subprocess.run.return_value.stdout = json.dumps(fields)
                self.assert_safe_failure(provider.get_credentials, "Ambiguous 1Password credential fields")

    def test_missing_or_empty_fields_fail_closed(self):
        payloads = [[], [{"label": "username", "value": "fixture-user"}]]
        for value in (None, "", " \r\n ", 123, [], {}):
            payloads.append(json.loads(self.fields(password=value)))
            payloads.append(json.loads(self.fields(username=value)))
        for fields in payloads:
            with self.subTest(fields=fields):
                provider.subprocess.run.return_value.stdout = json.dumps(fields)
                self.assert_safe_failure(provider.get_credentials, "Missing device credentials in 1Password")

    def test_read_secret_empty_field_fails_closed(self):
        for output in ("", "\r\n", " \t "):
            with self.subTest(output=output):
                provider.subprocess.run.return_value.stdout = output
                self.assert_safe_failure(lambda: provider.read_secret("password"), "Missing device credentials in 1Password")


if __name__ == "__main__":
    unittest.main()

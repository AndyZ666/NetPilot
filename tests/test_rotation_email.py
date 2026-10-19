"""SMTP is always mocked; no real credentials, mail delivery, or rotation."""

from contextlib import redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import smtplib
import ssl
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from security import rotation_email as email
from security.rotation_state import FLEET


VALUES = {
    "SMTP_HOST": "smtp.example.invalid", "SMTP_PORT": "587", "SMTP_SECURITY": "starttls",
    "SMTP_USERNAME": "fixture-user", "SMTP_PASSWORD": "fixture-app-password",
    "SMTP_FROM": "sender@example.invalid", "SMTP_TO": "operator@example.invalid",
}


def success():
    return {"phase": "COMMITTED", "rotation_id": "a" * 32, "vault_state": "promoted",
            "monitoring_state": "verified",
            "device_states": {name: {"state": "verified_new"} for name in FLEET}}


class EmailSettingsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "smtp.json"

    def write_config(self, values=VALUES):
        self.path.write_text(json.dumps(values))
        self.path.chmod(0o600)

    def test_environment_configuration_and_missing_configuration(self):
        settings = email.load_settings(VALUES, self.path)
        self.assertEqual((settings.host, settings.port, settings.security),
                         ("smtp.example.invalid", 587, "starttls"))
        self.assertNotIn(VALUES["SMTP_PASSWORD"], repr(settings))
        self.assertNotIn(VALUES["SMTP_USERNAME"], repr(settings))
        with self.assertRaisesRegex(email.SettingsError, "not_configured"):
            email.load_settings({}, self.path)

    def test_private_config_and_environment_override(self):
        self.write_config()
        settings = email.load_settings({"SMTP_TO": "other@example.invalid"}, self.path)
        self.assertEqual(settings.recipient, "other@example.invalid")
        self.assertEqual(settings.password, VALUES["SMTP_PASSWORD"])

    def test_tls_defaults_and_no_plaintext_or_header_injection(self):
        for security, port in (("starttls", 587), ("ssl", 465)):
            values = {**VALUES, "SMTP_SECURITY": security}
            del values["SMTP_PORT"]
            self.assertEqual(email.load_settings(values, self.path).port, port)
        for key, value in (("SMTP_SECURITY", "none"), ("SMTP_PORT", "0"), ("SMTP_PORT", True),
                           ("SMTP_FROM", "sender@example.invalid\r\nBcc: attacker@example.invalid"),
                           ("SMTP_TO", "operator@example.invalid,attacker@example.invalid"),
                           ("SMTP_HOST", "https://smtp.example.invalid"), ("SMTP_PASSWORD", "")):
            with self.subTest(key=key, value=value):
                with self.assertRaises(email.SettingsError):
                    email.load_settings({**VALUES, key: value}, self.path)

    def test_unsafe_file_and_symlink_are_rejected(self):
        self.write_config()
        self.path.chmod(0o644)
        with self.assertRaisesRegex(email.SettingsError, "unsafe_configuration_file"):
            email.load_settings({}, self.path)
        self.path.chmod(0o600)
        link = self.path.with_name("link.json")
        link.symlink_to(self.path)
        with self.assertRaises(email.SettingsError):
            email.load_settings({}, link)

    def test_invalid_config_never_reports_its_contents(self):
        for content in ("fixture-secret-invalid-json", json.dumps({"password": "fixture-secret"})):
            self.path.write_text(content)
            self.path.chmod(0o600)
            with self.assertRaises(email.SettingsError) as error:
                email.load_settings({}, self.path)
            self.assertNotIn("fixture-secret", str(error.exception))


class EmailContentTests(unittest.TestCase):
    def test_success_contains_required_metadata_only(self):
        report = success()
        report.update(password="do-not-send", hash="do-not-send", token="do-not-send", error_message="do-not-send")
        subject, body = email.notification_content(report)
        self.assertEqual(subject, "NetPilot Password Rotation Successful")
        for value in ("Execution timestamp (UTC):", "a" * 32, "9/9", "promoted", "verified"):
            self.assertIn(value, body)
        self.assertNotIn("do-not-send", body)

    def test_committed_with_incomplete_evidence_is_not_success(self):
        for field, value in (("device_states", {}), ("vault_state", "unknown"), ("monitoring_state", "failed")):
            with self.subTest(field=field):
                subject, body = email.notification_content({**success(), field: value})
                self.assertEqual(subject, "NetPilot Password Rotation Failed")
                self.assertIn("Manual recovery required: YES", body)

    def test_failure_uses_sanitized_event_and_no_raw_error(self):
        report = {**success(), "phase": "PARTIAL_FAILURE", "vault_state": "pending_staged",
                  "error": "raw-secret", "device": "raw-secret", "stage": "raw-secret",
                  "audit_events": [{"result": "FAIL", "operation": "rotate", "device": "R2", "error": "authentication",
                                    "error_message": "raw-secret"}], "manual_recovery_required": True}
        subject, body = email.notification_content(report)
        self.assertEqual(subject, "NetPilot Password Rotation Failed")
        for value in ("Failed device: R2", "Failed stage: rotate", "Sanitized error category: authentication",
                      "Manual recovery required: YES"):
            self.assertIn(value, body)
        self.assertNotIn("raw-secret", body)

    def test_untrusted_values_and_structures_never_become_message_text(self):
        bad = "raw-secret\nBcc: attacker@example.invalid"
        report = dict.fromkeys(("phase", "rotation_id", "vault_state", "monitoring_state", "device_states",
                                "device", "stage", "error", "audit_events", "manual_recovery_required"), bad)
        subject, body = email.notification_content(report)
        self.assertNotIn("raw-secret", subject + body)
        self.assertNotIn("attacker", subject + body)
        self.assertIn("Rotation ID: unavailable", body)
        self.assertIn("Manual recovery required: YES", body)
        email.notification_content(None)
        email.notification_content({"stage": [], "error": {}})

    def test_extra_devices_cannot_replace_missing_fleet_success_evidence(self):
        report = success()
        del report["device_states"]["R1"]
        report["device_states"]["fixture-private-foreign-device"] = {"state": "verified_new"}
        subject, body = email.notification_content(report)
        self.assertEqual(subject, "NetPilot Password Rotation Failed")
        self.assertIn("Nine-device success count: 8/9", body)
        self.assertNotIn("fixture-private", body)

    def test_latest_failure_event_wins_over_earlier_failure_and_later_information(self):
        report = {"phase": "RECOVERY_REQUIRED", "stage": "precheck", "error": "credentials",
                  "audit_events": [
                      {"result": "FAIL", "operation": "rotate", "device": "R1", "error": "device_write"},
                      {"result": "FAIL", "operation": "rollback", "device": "R2", "error": "unreachable"},
                      {"result": "INFO", "operation": "fixture-private-command", "device": "R3"},
                      "fixture-private-malformed-event",
                  ]}
        subject, body = email.notification_content(report)
        self.assertEqual(subject, "NetPilot Password Rotation Failed")
        for expected in ("Failed device: R2", "Failed stage: rollback", "Sanitized error category: unreachable"):
            self.assertIn(expected, body)
        self.assertNotIn("fixture-private", body)
        self.assertNotIn("Failed device: R1", body)


class EmailDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.settings = email.Settings("smtp.example.invalid", 587, "fixture-user", "fixture-secret",
                                       "sender@example.invalid", "operator@example.invalid", "starttls")
        self.load = self.enterContext(patch.object(email, "load_settings", return_value=self.settings))
        self.smtp = self.enterContext(patch.object(email.smtplib, "SMTP"))
        self.smtp_ssl = self.enterContext(patch.object(email.smtplib, "SMTP_SSL"))
        self.context = self.enterContext(patch.object(email.ssl, "create_default_context"))
        self.connection = self.smtp.return_value.__enter__.return_value

    def test_starttls_precedes_authentication_and_only_safe_message_is_sent(self):
        result = email.send_notification(success())
        self.assertEqual(result, {"status": "sent", "error": None})
        self.smtp.assert_called_once_with("smtp.example.invalid", 587, timeout=20)
        self.smtp_ssl.assert_not_called()
        names = [call[0] for call in self.connection.mock_calls]
        self.assertLess(names.index("starttls"), names.index("login"))
        self.connection.starttls.assert_called_once_with(context=self.context.return_value)
        self.connection.login.assert_called_once_with("fixture-user", "fixture-secret")
        self.connection.set_debuglevel.assert_called_once_with(0)
        message = self.connection.send_message.call_args.args[0]
        self.assertNotIn("fixture-secret", message.as_string())
        self.assertEqual(str(message["Subject"]), "NetPilot Password Rotation Successful")

    def test_ssl_never_downgrades_to_plaintext(self):
        self.load.return_value = email.Settings("smtp.example.invalid", 465, "user", "password",
                                                "a@example.invalid", "b@example.invalid", "ssl")
        self.assertEqual(email.send_test_email()["status"], "sent")
        self.smtp.assert_not_called()
        self.smtp_ssl.assert_called_once_with("smtp.example.invalid", 465, timeout=20, context=self.context.return_value)
        self.smtp_ssl.return_value.__enter__.return_value.starttls.assert_not_called()

    def test_tls_failure_never_authenticates_and_reports_fixed_code(self):
        self.connection.starttls.side_effect = ssl.SSLError("fixture-secret")
        result = email.send_notification(success())
        self.assertEqual(result, {"status": "failed", "error": "smtp_tls_failed"})
        self.connection.login.assert_not_called()
        self.connection.send_message.assert_not_called()

    def test_authentication_and_transport_errors_are_sanitized(self):
        for failure, code in ((smtplib.SMTPAuthenticationError(535, b"fixture-secret"), "smtp_authentication_failed"),
                              (RuntimeError("fixture-secret"), "smtp_delivery_failed")):
            self.connection.login.side_effect = failure
            result = email.send_notification(success())
            self.assertEqual(result, {"status": "failed", "error": code})
            self.assertNotIn("fixture-secret", repr(result))

    def test_missing_config_never_contacts_smtp(self):
        self.load.side_effect = email.SettingsError("not_configured")
        self.assertEqual(email.send_notification(success()), {"status": "not_configured", "error": "not_configured"})
        self.smtp.assert_not_called()
        self.smtp_ssl.assert_not_called()

    def test_test_cli_requires_execute_and_does_not_rotate(self):
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(email.main(["--test"]), 2)
        self.smtp.assert_not_called()
        with redirect_stdout(output):
            self.assertEqual(email.main(["--test", "--execute"]), 0)
        message = self.connection.send_message.call_args.args[0]
        self.assertEqual(str(message["Subject"]), "NetPilot SMTP Test")
        self.assertIn("No password rotation was performed", message.get_content())
        self.assertIn("PASS | notification | status=sent", output.getvalue())
        self.assertNotIn("fixture-secret", output.getvalue())

    def test_connection_failures_do_not_retry_or_switch_transport(self):
        for security, failure in (
                ("starttls", TimeoutError("fixture-secret")),
                ("ssl", smtplib.SMTPConnectError(421, b"fixture-secret"))):
            with self.subTest(security=security):
                self.smtp.reset_mock()
                self.smtp_ssl.reset_mock()
                self.smtp.side_effect = self.smtp_ssl.side_effect = None
                self.load.return_value = email.Settings(
                    "smtp.example.invalid", 587 if security == "starttls" else 465,
                    "fixture-user", "fixture-secret", "sender@example.invalid",
                    "operator@example.invalid", security)
                selected, other = (self.smtp, self.smtp_ssl) if security == "starttls" else (self.smtp_ssl, self.smtp)
                selected.side_effect = failure
                result = email.send_notification(success())
                self.assertEqual(result, {"status": "failed", "error": "smtp_delivery_failed"})
                selected.assert_called_once()
                selected.return_value.__enter__.assert_not_called()
                other.assert_not_called()

    def test_send_failures_are_sanitized_close_connection_and_do_not_retry(self):
        for failure in (smtplib.SMTPRecipientsRefused({"operator@example.invalid": (550, b"fixture-secret")}),
                        smtplib.SMTPDataError(554, b"fixture-secret"),
                        smtplib.SMTPServerDisconnected("fixture-secret")):
            with self.subTest(failure=type(failure).__name__):
                self.smtp.reset_mock()
                self.connection.send_message.side_effect = failure
                result = email.send_notification(success())
                self.assertEqual(result, {"status": "failed", "error": "smtp_delivery_failed"})
                self.connection.login.assert_called_once_with("fixture-user", "fixture-secret")
                self.connection.send_message.assert_called_once()
                self.smtp.return_value.__exit__.assert_called_once()
                self.smtp.assert_called_once()
                self.smtp_ssl.assert_not_called()
                message = self.connection.send_message.call_args.args[0]
                self.assertNotIn("fixture-secret", message.as_string())

    def test_unsupported_starttls_or_ehlo_failure_never_authenticates(self):
        for stage in ("ehlo_before_tls", "starttls", "ehlo_after_tls"):
            with self.subTest(stage=stage):
                self.smtp.reset_mock()
                self.connection.ehlo.side_effect = None
                self.connection.starttls.side_effect = None
                expected = "smtp_delivery_failed"
                if stage == "starttls":
                    self.connection.starttls.side_effect = smtplib.SMTPNotSupportedError("fixture-secret")
                    expected = "smtp_tls_failed"
                else:
                    responses = [] if stage == "ehlo_before_tls" else [None]
                    self.connection.ehlo.side_effect = responses + [smtplib.SMTPHeloError(501, b"fixture-secret")]
                self.assertEqual(email.send_notification(success()), {"status": "failed", "error": expected})
                self.connection.login.assert_not_called()
                self.connection.send_message.assert_not_called()
                self.smtp.return_value.__exit__.assert_called_once()
                self.smtp_ssl.assert_not_called()

    def test_invalid_or_unreadable_configuration_prevents_smtp_construction(self):
        for failure, code in ((email.SettingsError("unsafe_configuration_file"), "unsafe_configuration_file"),
                              (ValueError("fixture-secret"), "invalid_configuration")):
            with self.subTest(failure=type(failure).__name__):
                self.load.side_effect = failure
                self.assertEqual(email.send_notification(success()), {"status": "failed", "error": code})
                self.smtp.assert_not_called()
                self.smtp_ssl.assert_not_called()

    def test_test_cli_returns_failure_for_authentication_error_without_leaking_server_response(self):
        self.connection.login.side_effect = smtplib.SMTPAuthenticationError(535, b"fixture-secret")
        with redirect_stdout(StringIO()) as output:
            code = email.main(["--test", "--execute"])
        self.assertEqual(code, 1)
        self.assertEqual(output.getvalue(), "FAIL | notification | error=smtp_authentication_failed\n")
        self.connection.send_message.assert_not_called()
        self.smtp.assert_called_once()

    def test_uncertain_delivery_on_connection_close_does_not_retry_message(self):
        self.smtp.return_value.__exit__.side_effect = OSError("fixture-secret")
        result = email.send_notification(success())
        self.assertEqual(result, {"status": "failed", "error": "smtp_delivery_failed"})
        self.connection.send_message.assert_called_once()
        self.smtp.assert_called_once()
        self.smtp_ssl.assert_not_called()


if __name__ == "__main__":
    unittest.main()

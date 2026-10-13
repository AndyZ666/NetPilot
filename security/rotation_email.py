"""Small, optional SMTP notifications; messages contain only allowlisted metadata.

Configuration: SMTP_* environment values override the same keys in the private
~/.config/netpilot/smtp.json file. Importing this module does not read secrets or
contact SMTP. Delivery results never alter the password transaction.
"""

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage
import json
import os
from pathlib import Path
import re
import smtplib
import ssl
import stat

from security.rotation_state import ERROR_CATEGORIES, FLEET, OPERATIONS, PHASES


CONFIG_FILE = Path.home() / ".config/netpilot/smtp.json"
KEYS = frozenset({"SMTP_HOST", "SMTP_PORT", "SMTP_USERNAME", "SMTP_PASSWORD",
                  "SMTP_FROM", "SMTP_TO", "SMTP_SECURITY"})
VAULT_STATES = frozenset({"unchanged", "staging", "pending_staged", "promotion_intent", "promoted", "unknown"})
MONITORING_STATES = frozenset({"not_requested", "verification_required", "refresh_required", "verified", "failed"})
STAGES = PHASES | OPERATIONS | {"scheduler", "notification", "unknown"}


class SettingsError(ValueError):
    """Fixed codes only; SMTP responses and configuration values never escape."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    username: str = field(repr=False)
    password: str = field(repr=False)
    sender: str
    recipient: str
    security: str


def _config(path):
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise SettingsError("unsafe_configuration_file")
        content = os.read(descriptor, 65537)
        if len(content) > 65536:
            raise SettingsError("invalid_configuration")
        values = json.loads(content)
        if not isinstance(values, dict) or set(values) - KEYS:
            raise SettingsError("invalid_configuration")
        return values
    except FileNotFoundError:
        return {}
    except SettingsError:
        raise
    except Exception:
        raise SettingsError("configuration_file_unavailable") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _text(value):
    return isinstance(value, str) and bool(value) and all(character.isprintable() for character in value)


def _address(value):
    # One plain mailbox per field; display names and lists are deliberately unsupported.
    return _text(value) and bool(re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+", value))


def load_settings(environment=None, path=None):
    """Read protected local settings, with environment overrides. No network I/O."""
    environment = os.environ if environment is None else environment
    values = _config(CONFIG_FILE if path is None else Path(path))
    values.update({key: environment[key] for key in KEYS if key in environment})
    if not values:
        raise SettingsError("not_configured")
    host = values.get("SMTP_HOST")
    username = values.get("SMTP_USERNAME")
    password = values.get("SMTP_PASSWORD")
    sender, recipient = values.get("SMTP_FROM"), values.get("SMTP_TO")
    security = values.get("SMTP_SECURITY", "starttls")
    if (security not in ("starttls", "ssl") or not _text(host)
            or any(character.isspace() or character in "/@" for character in host)
            or not _text(username) or not _text(password)
            or not _address(sender) or not _address(recipient)):
        raise SettingsError("invalid_configuration")
    try:
        port = int(values.get("SMTP_PORT", 465 if security == "ssl" else 587))
        if isinstance(values.get("SMTP_PORT"), bool) or not 1 <= port <= 65535:
            raise ValueError
    except (TypeError, ValueError, OverflowError):
        raise SettingsError("invalid_configuration") from None
    return Settings(host, port, username, password, sender, recipient, security)


def _choice(value, choices, default="unknown"):
    return value if isinstance(value, str) and value in choices else default


def notification_content(report):
    """Build messages from fixed metadata only, ignoring all free-text payloads."""
    report = report if isinstance(report, dict) else {}
    states = report.get("device_states", {})
    states = states if isinstance(states, dict) else {}
    count = sum(isinstance(states.get(name), dict) and states[name].get("state") == "verified_new"
                for name in FLEET)
    vault = _choice(report.get("vault_state"), VAULT_STATES)
    monitoring = _choice(report.get("monitoring_state"), MONITORING_STATES)
    phase = _choice(report.get("phase"), PHASES)
    success = phase == "COMMITTED" and count == len(FLEET) and vault == "promoted" and monitoring == "verified"
    rotation_id = report.get("rotation_id")
    if not isinstance(rotation_id, str) or not re.fullmatch(r"[0-9a-f]{32}", rotation_id):
        rotation_id = "unavailable"
    timestamp = datetime.now(timezone.utc).isoformat()
    lines = [f"Execution timestamp (UTC): {timestamp}", f"Rotation ID: {rotation_id}",
             f"Nine-device success count: {count}/{len(FLEET)}", f"1Password synchronization: {vault}",
             f"Monitoring verification: {monitoring}"]
    if success:
        subject = "NetPilot Password Rotation Successful"
    else:
        subject = "NetPilot Password Rotation Failed"
        stage = _choice(report.get("stage"), STAGES, phase)
        error = _choice(report.get("error"), ERROR_CATEGORIES, "ambiguous")
        device = _choice(report.get("device"), set(FLEET), "not identified")
        events = report.get("audit_events", [])
        if isinstance(events, list):
            failed = next((event for event in reversed(events)
                           if isinstance(event, dict) and event.get("result") == "FAIL"), None)
            if failed:
                stage = _choice(failed.get("operation"), STAGES, stage)
                error = _choice(failed.get("error"), ERROR_CATEGORIES, error)
                device = _choice(failed.get("device"), set(FLEET), device)
        recovery = report.get("manual_recovery_required")
        if type(recovery) is not bool:
            recovery = phase not in {"IDLE", "ROLLED_BACK"}
        lines.extend([f"Failed device: {device}", f"Failed stage: {stage}",
                      f"Sanitized error category: {error}",
                      "Manual recovery required: " + ("YES" if recovery else "NO"),
                      "Inspect the local rotation status and audit journal before retrying."])
    return subject, "\n".join(lines) + "\n"


def _deliver(subject, body):
    try:
        settings = load_settings()
    except SettingsError as exc:
        return {"status": "not_configured" if exc.code == "not_configured" else "failed", "error": exc.code}
    except Exception:
        return {"status": "failed", "error": "invalid_configuration"}
    try:
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = settings.sender
        message["To"] = settings.recipient
        message.set_content(body)
        context = ssl.create_default_context()
        if settings.security == "ssl":
            connection = smtplib.SMTP_SSL(settings.host, settings.port, timeout=20, context=context)
        else:
            connection = smtplib.SMTP(settings.host, settings.port, timeout=20)
        with connection as smtp:
            smtp.set_debuglevel(0)
            smtp.ehlo()
            if settings.security == "starttls":
                smtp.starttls(context=context)
                smtp.ehlo()
            smtp.login(settings.username, settings.password)
            smtp.send_message(message, from_addr=settings.sender, to_addrs=[settings.recipient])
        return {"status": "sent", "error": None}
    except smtplib.SMTPAuthenticationError:
        return {"status": "failed", "error": "smtp_authentication_failed"}
    except (ssl.SSLError, smtplib.SMTPNotSupportedError):
        return {"status": "failed", "error": "smtp_tls_failed"}
    except Exception:
        return {"status": "failed", "error": "smtp_delivery_failed"}


def send_notification(report):
    """Best-effort result only: an email failure cannot fail a committed rotation."""
    try:
        return _deliver(*notification_content(report))
    except Exception:
        return {"status": "failed", "error": "notification_failed"}


def send_test_email():
    return _deliver("NetPilot SMTP Test", "NetPilot SMTP configuration test. No password rotation was performed.\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Send a NetPilot SMTP test without rotating credentials.")
    parser.add_argument("--test", action="store_true", required=True)
    parser.add_argument("--execute", action="store_true", help="Authorize sending the test email")
    args = parser.parse_args(argv)
    if not args.execute:
        print("FAIL | notification | error=execute_required")
        return 2
    result = send_test_email()
    if result["status"] == "sent":
        print("PASS | notification | status=sent")
        return 0
    print("FAIL | notification | error=" + result["error"])
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

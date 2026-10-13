"""Read device credentials from the existing 1Password service account.

Secrets stay in memory: this module never logs them, writes them, or falls back
to environment-provided device credentials. Importing it does not access Vault.
"""

import json
import os
from pathlib import Path
import stat
import subprocess


TOKEN_FILE = Path.home() / ".config/netpilot/secrets/onepassword-token"
VAULT = "NetPilot-Secrets"
ITEM = "NetPilot-Current"
_FIELDS = ("username", "password")
_TIMEOUT_SECONDS = 30
_MAX_TOKEN_BYTES = 65536


def _read_token():
    """Check the opened file itself, avoiding a check/open symlink race."""
    descriptor = None
    try:
        descriptor = os.open(
            TOKEN_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("1Password token must be a regular file")
        if metadata.st_mode & 0o077 or metadata.st_uid != os.geteuid():
            raise RuntimeError("Insecure 1Password token file permissions")
        raw = os.read(descriptor, _MAX_TOKEN_BYTES + 1)
    except FileNotFoundError:
        raise RuntimeError("1Password token file missing") from None
    except OSError:
        raise RuntimeError("Unable to read 1Password token file") from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                raise RuntimeError("Unable to read 1Password token file") from None

    if len(raw) > _MAX_TOKEN_BYTES:
        raise RuntimeError("Invalid 1Password token file")
    try:
        token = raw.decode("utf-8").strip()
    except UnicodeError:
        raise RuntimeError("Invalid 1Password token file") from None
    if not token:
        raise RuntimeError("Empty 1Password token")
    if any(character.isspace() or not character.isprintable() for character in token):
        raise RuntimeError("Invalid 1Password token file")
    return token


def _run_op(arguments, *, input_text=None):
    """Reuse the authenticated CLI boundary; optional sensitive JSON stays on stdin."""
    if input_text is not None and not isinstance(input_text, str):
        raise ValueError("Invalid 1Password operation input")
    # Only this child receives the token. Do not modify the process environment.
    env = os.environ.copy()
    for key in tuple(env):
        if key in (
            "OP_ACCOUNT", "OP_CONNECT_HOST", "OP_CONNECT_TOKEN", "OP_SESSION"
        ) or key.startswith("OP_SESSION_"):
            env.pop(key)
    env.update({
        "OP_SERVICE_ACCOUNT_TOKEN": _read_token(),
        "OP_BIOMETRIC_UNLOCK_ENABLED": "false",
        "OP_CACHE": "false",
        "OP_DEBUG": "false",
        "OP_INCLUDE_ARCHIVE": "false",
    })
    try:
        result = subprocess.run(
            ["op", *arguments],
            env=env,
            **({"stdin": subprocess.DEVNULL} if input_text is None else {"input": input_text}),
            capture_output=True,
            text=True,
            encoding="utf-8",
            shell=False,
            check=True,
            timeout=_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        raise RuntimeError("1Password CLI is not available") from None
    except (OSError, subprocess.SubprocessError, UnicodeError):
        # CLI stdout/stderr and exception text can contain secrets.
        raise RuntimeError("Failed to retrieve 1Password credential") from None
    if not isinstance(result.stdout, str):
        raise RuntimeError("Invalid 1Password credential response")
    return result.stdout


def _require_value(value):
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError("Missing device credentials in 1Password")
    return value


def read_secret(field):
    """Return one supported field, keeping the existing public API."""
    if field not in _FIELDS:
        raise ValueError("Unsupported credential field")
    reference = f"op://{VAULT}/{ITEM}/{field}"
    return _require_value(_run_op(["read", reference]).rstrip("\r\n"))


def get_credentials():
    """Read a username/password pair from one item response, without caching.

    A single item read avoids mixing fields from two revisions during a future
    rotation. The CLI receives only public item/field names as arguments.
    """
    output = _run_op([
        "item", "get", ITEM, "--vault", VAULT,
        "--fields", "label=username,label=password", "--format", "json",
        "--reveal",
    ])
    try:
        fields = json.loads(output)
    except (ValueError, RecursionError):
        raise RuntimeError("Invalid 1Password credential response") from None
    if not isinstance(fields, list):
        raise RuntimeError("Invalid 1Password credential response")

    values = {}
    for field in fields:
        if not isinstance(field, dict):
            raise RuntimeError("Invalid 1Password credential response")
        label = field.get("label")
        if label not in _FIELDS or label in values:
            raise RuntimeError("Ambiguous 1Password credential fields")
        values[label] = _require_value(field.get("value"))
    if set(values) != set(_FIELDS):
        raise RuntimeError("Missing device credentials in 1Password")
    return values["username"], values["password"]

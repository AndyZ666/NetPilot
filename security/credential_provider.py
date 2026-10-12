import os
import subprocess
from pathlib import Path

TOKEN_FILE = (
    Path.home()
    / ".config/netpilot/secrets/onepassword-token"
)

VAULT = "NetPilot-Secrets"
ITEM = "NetPilot-Current"


def read_secret(field):
    if field not in ("username", "password"):
        raise ValueError("Unsupported credential field")

    if not TOKEN_FILE.is_file():
        raise RuntimeError("1Password token file missing")

    if TOKEN_FILE.stat().st_mode & 0o077:
        raise RuntimeError("Insecure token file permissions")

    token = TOKEN_FILE.read_text().strip()

    if not token:
        raise RuntimeError("Empty 1Password token")

    env = os.environ.copy()
    env["OP_SERVICE_ACCOUNT_TOKEN"] = token

    reference = f"op://{VAULT}/{ITEM}/{field}"

    try:
        result = subprocess.run(
            ["op", "read", reference],
            env=env,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
    except (subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as exc:
        raise RuntimeError(
            "Failed to retrieve 1Password credential"
        ) from None

    return result.stdout.rstrip("\r\n")


def get_credentials():
    username = read_secret("username")
    password = read_secret("password")

    if not username or not password:
        raise RuntimeError("Missing device credentials")

    return username, password

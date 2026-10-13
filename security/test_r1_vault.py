from netmiko import ConnectHandler
if __package__:
    from .credential_provider import get_credentials
else:
    from credential_provider import get_credentials


def main():
    """Explicit live smoke test; importing this module never accesses the Vault."""
    print("NetPilot 1Password Integration Test")

    try:
        username, password = get_credentials()

        print("[PASS] Credentials retrieved from 1Password")

        device = {
            "device_type": "arista_eos",
            "host": "172.20.20.13",
            "username": username,
            "password": password,
            "conn_timeout": 10,
            "auth_timeout": 10,
        }

        with ConnectHandler(**device) as connection:
            result = connection.send_command("show hostname")

        print("[PASS] SSH authentication successful")
        print("Device response:")
        print(result)
        return 0
    except Exception:
        print("[FAIL] Credential retrieval or SSH test failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

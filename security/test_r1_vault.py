from netmiko import ConnectHandler
from credential_provider import get_credentials

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

except Exception:
    print("[FAIL] Credential retrieval or SSH test failed")
    raise SystemExit(1)

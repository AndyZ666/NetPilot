from netmiko import ConnectHandler
if __package__:
    from .credential_provider import get_credentials
else:
    from credential_provider import get_credentials

DEVICES = {
    "R1": "172.20.20.13",
    "R2": "172.20.20.14",
    "R3": "172.20.20.9",
    "R4": "172.20.20.11",
    "R5": "172.20.20.2",
    "S1": "172.20.20.7",
    "S2": "172.20.20.8",
    "S3": "172.20.20.4",
    "S4": "172.20.20.10",
}


def main():
    print("NetPilot - 1Password Authentication Test")
    print("=" * 45)

    try:
        username, password = get_credentials()
    except Exception:
        print("[FAIL] Unable to retrieve credentials")
        return

    passed = 0
    failed = 0

    for name, ip in DEVICES.items():
        try:
            with ConnectHandler(
                device_type="arista_eos",
                host=ip,
                username=username,
                password=password,
                conn_timeout=10,
                auth_timeout=10,
                banner_timeout=10,
            ) as connection:
                output = connection.send_command(
                    "show hostname"
                )

            hostnames = [line.split(":", 1)[1].strip() for line in output.splitlines()
                         if line.strip().startswith("Hostname:")]
            if hostnames == [name]:
                print(f"[PASS] {name} ({ip})")
                passed += 1
            else:
                print(f"[FAIL] {name}: Hostname mismatch")
                failed += 1

        except Exception as exc:
            print(f"[FAIL] {name}: {type(exc).__name__}")
            failed += 1

    print("=" * 45)
    print(f"Successful: {passed}")
    print(f"Failed: {failed}")
    print(f"Total: {len(DEVICES)}")


if __name__ == "__main__":
    main()

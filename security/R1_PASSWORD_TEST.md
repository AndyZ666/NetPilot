# R1 temporary password-change test

Use the existing NetPilot Python environment, 1Password Credential Provider and
OpenSSL installation. From `/home/student/Documents/NetPilot`:

```bash
python3 -m security.test_r1_password_change --dry-run
python3 -m security.test_r1_password_change --execute
```

`--execute` is the only authorization required. There are no confirmation phrases
or password prompts. Development checks are offline; run the live command yourself
when ready. The dry-run never retrieves credentials or opens network connections.

The script targets only R1 (`172.20.20.13`). It refuses a preexisting
`netpilot-rotation-test` account in either running or startup configuration.
It creates a temporary privilege-15/network-admin account, verifies its initial
password through fresh SSH, changes and verifies the password, then restores and
verifies the initial password. Finally it removes the account and checks that
running and startup configurations each match their original snapshots.

Admin and recovery accounts stay unchanged. Passwords and hashes stay in memory;
hashing reuses the recovery script's OpenSSL stdin helper, and transport logs are
suppressed. No Vault writes or startup saves occur. Existing unrelated pending
changes are allowed and preserved. Relaxed host-key validation is for this
isolated Containerlab only. Keep other configuration writers idle during the test.

Any failed step prints FAIL and stops the sequence. After creation is attempted,
cleanup uses fresh admin SSH, including after a timeout or Ctrl-C. It removes only
an account matching one of this run's generated account records. If cleanup cannot
be verified, the script prints **cleanup incomplete** and the privileged test
account may remain. Use your existing admin/recovery access to inspect R1 and
remove only `netpilot-rotation-test` before rerunning; do not save the temporary
account or delete a preexisting account blindly. A process kill or host failure
can also prevent cleanup. No secret-bearing cleanup file is created.

PASS requires initial/change/rollback SSH verification, verified removal and
unchanged original configurations. Exit status is 0 on success, 1 on failure,
or 130 if the test sequence is interrupted before cleanup.

The SHA-512 + Netmiko update + fresh-SSH sequence can later inform
`NetmikoDeviceAdapter.change_password()`. This test does not establish preservation
of every existing admin account attribute or fleet recovery/monitoring behavior.
`rotation_adapters.py` is unchanged: live device writes remain disabled. Its strict
host-key policy and enable-mode handling need separate consideration before reuse.

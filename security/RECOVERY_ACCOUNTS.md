# Recovery accounts on R2–R5 and S1–S4

`security/setup_recovery_accounts.py` uses Netmiko and the existing
`credential_provider.get_credentials()` to read current admin credentials from
1Password. Addresses come from `inventory/devices.yml`. R1 is never contacted.
The script does not change admin credentials, AAA, Vault items, or services.

## Commands

From the project root, using the existing virtual environment:

```bash
cd ~/Documents/NetPilot

# Offline plan: no credentials, prompts, SSH, hashing or file changes.
.venv/bin/python -m security.setup_recovery_accounts --dry-run

# Configure missing accounts and verify existing accounts; requires confirmation.
.venv/bin/python -m security.setup_recovery_accounts configure --execute

# Independent fresh recovery SSH verification; no Vault reads or device writes.
.venv/bin/python -m security.setup_recovery_accounts verify
```

Setup requires an interactive terminal and this exact confirmation:

```text
CONFIGURE EIGHT RECOVERY ACCOUNTS
```

Enter the existing Recovery Password from your Personal Vault at the hidden
`getpass` prompts (twice for setup, once for verification). Use the same password
as R1; the script does not access your Personal Vault or R1 to retrieve/check it.
Passwords must be 16–128 UTF-8 bytes of printable text, without control characters.

## Workflow

Devices are processed sequentially: R2, R3, R4, R5, S1, S2, S3, S4.

1. Connect as admin. Use Netmiko `enable()` if needed and require `show privilege`
   to report level 15. Check the expected hostname and cEOSLab platform.
2. Read running/startup configurations into memory. If `netpilot-recovery` exists,
   test it with a **new SSH connection first**, including enable and privilege 15.
   Never overwrite an existing account, including when the supplied password fails.
3. If missing, first refuse unrelated unsaved changes. Generate a SHA-512 crypt
   hash locally and send only the account command with privilege 15 and role
   `network-admin`. Open a new recovery SSH connection and verify privileged access.
4. Save only after fresh verification and full configuration comparisons confirm
   that the recovery account is the only pending change. Recheck immediately before
   saving and read back running/startup afterward. Already saved accounts require
   no writes; an account-only unsaved creation from an earlier attempt can be saved.
5. Stop on the first failure and report subsequent devices as SKIP.

Existing account records are preserved regardless of their hash format or field
ordering. No `show users accounts` or `show users detail` parsing is required.
The independent `verify` action also checks that the same recovery account records
exist in startup configuration; it never changes or saves configuration.

## Why `local_authentication` failed

The old script parsed `show users detail` after fresh SSH and privilege checks.
It demanded exactly one recovery session, fixed column positions, and the literal
word `local`. Different EOS output or multiple sessions could fail that custom gate
without indicating a failed login. The original response was not captured during
this offline update, so the exact rejected condition is unknown. That parser and
the additional `show users accounts` gate have been removed. Verification now uses
fresh password-authenticated SSH, enable mode, and actual session privilege 15.
It does not claim to independently prove which AAA backend authenticated the user.

## Dependencies and safeguards

No new Python packages are needed. Keep the existing Credential Provider/1Password
setup available for admin login. OpenSSL `passwd -6 -stdin` is needed only to create
missing accounts: plaintext goes through stdin, never command-line arguments.
Passwords, hashes, tokens, raw exceptions and device configurations are not logged
or printed. No separate enable password is guessed or retrieved; denied enable or
insufficient privilege stops processing with a sanitized error.

Relaxed host-key validation (`ssh_strict=False`, `system_host_keys=False`) is allowed
**only for this isolated Containerlab script**, matching `test_all_vault.py`.
No known_hosts prerequisite is added. SSH encryption/password authentication stay
enabled; key/agent fallback and session logging stay disabled. Hostname checks do
not replace cryptographic host authentication on untrusted networks.

Keep other configuration writers idle during setup: EOS saves the entire running
configuration, and client-side comparisons cannot lock out a change between the
last comparison and save. A local advisory lock prevents simultaneous setup runs
from this checkout. Full configuration comparisons preserve unrelated statements;
ambiguous banner/comment blocks are refused. An existing startup recovery account
that differs from running is not overwritten or silently saved.

A timeout can leave a change applied but unverified. UNKNOWN means inspection is
needed; the script never blindly deletes an account, retries writes or rolls back.
The following is an example format, **not live results**:

```text
R2: PASS | verified_and_saved | changed=NO | saved=YES
R3: FAIL | verification | changed=UNKNOWN | saved=UNKNOWN | error=verification
R4: SKIP | not_attempted | changed=NO | saved=UNKNOWN
...
PASS=1 FAIL=1 SKIP=6
```

## Offline checks

```bash
.venv/bin/python -m unittest discover -s tests -p 'test_setup_recovery_accounts.py' -v
.venv/bin/python -m unittest discover -s tests -v
```

Tests mock Vault, hashing and SSH, including enable handling, existing-account
preservation, no AAA table queries, save guards, failures and secret-safe output.
Development validation does not contact or configure any device.

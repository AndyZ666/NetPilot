# Phase 2.4.4C: Vault write/readback verification

This standalone check reuses `OnePasswordStore` and the Credential Provider's
existing Service Account authentication. It targets only the Login item
`NetPilot-Vault-Write-Test` in `NetPilot-Secrets`. It does not read device passwords,
modify Current/Pending, invoke rotation, connect to devices, or restart services.
No new dependencies or environment variables are needed beyond the existing
1Password CLI and Credential Provider setup.

## Run

From the existing project environment:

```bash
cd ~/Documents/NetPilot

# Offline: no token reads, Vault access or writes.
.venv/bin/python -m security.test_vault_write_live --dry-run

# Approved live test: requires an interactive terminal and exact confirmation.
.venv/bin/python -m security.test_vault_write_live --execute
```

Direct script invocation (`.venv/bin/python security/test_vault_write_live.py
--execute`) also works. At the prompt, enter exactly:

```text
WRITE NetPilot-Vault-Write-Test
```

The script generates two random synthetic passwords in memory. It creates the
item, independently retrieves and compares the first credential, updates it to
the second credential, and independently retrieves and compares again. It never
prints either credential or treats a write response as readback proof.

Expected successful results:

```text
PASS | initial write and independent readback
PASS | update and independent readback
PASS | test item retained; no automatic cleanup
```

Exit status is 0 for success/offline planning, 1 for failure, and 130 for an
interrupted confirmation or operation. A FAIL stops further operations. A timeout
may mean a write occurred but could not be verified; inspect the test item before
retrying. No automatic retry, rollback, deletion, or secret-bearing diagnostic is
performed. Live Service Account write permissions are verified only by this run;
passing mocked tests alone does not establish those permissions.

## Existing test item

An existing item is refused by default. To deliberately reuse only that item:

```bash
.venv/bin/python -m security.test_vault_write_live --execute --overwrite-existing
```

After the first confirmation, approve the displayed test-item ID by entering:

```text
OVERWRITE NetPilot-Vault-Write-Test
```

Its username/password will be replaced with synthetic values twice. Other item
metadata is preserved; attachments, passkeys, duplicate titles/credential fields
or an unexpected item shape cause refusal. Approval is bound to the discovered
item ID, and its title/content are rechecked before editing. Keep other writers
away from this test item during verification: the CLI does not provide an atomic
compare-and-swap across these reads and writes.

## Secret handling and cleanup

The existing provider passes the Service Account token only to the CLI child
process environment and disables CLI cache/debug output. Sensitive JSON goes
through captured stdin/stdout pipes, never shell arguments or temporary files.
The implementation follows the documented [1Password JSON stdin create/edit
mechanisms](https://developer.1password.com/docs/cli/reference/management-commands/item/).
If the adapter disallows live writes or the CLI rejects these mechanisms, the
script stops; there is no plaintext-argument or file-based fallback.

The test item remains after success or failure. To clean up manually, open the
1Password app, select **NetPilot-Secrets**, locate **NetPilot-Vault-Write-Test**,
and verify the username is **netpilot-synthetic-test** before moving that item
to Recently Deleted. Do not select **NetPilot-Current** or **NetPilot-Pending**.
If duplicate test titles or an unexpected username exist, inspect each item
before deleting anything. No cleanup command is executed by this script.

## Offline tests

```bash
.venv/bin/python -m unittest discover -s tests -p 'test_vault_write_live.py' -v
.venv/bin/python -m unittest discover -s tests -v
```

Tests mock the CLI boundary and prohibit real token reads and device connections.

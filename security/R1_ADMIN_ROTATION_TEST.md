# R1 admin rotation/rollback test

From the project root with the existing NetPilot Python environment active:

```bash
python3 -m security.test_r1_admin_rotation --dry-run
python3 -m security.test_r1_admin_rotation --execute
```

`--execute` is sufficient authorization: there are no confirmation phrases or
password prompts. Development testing is offline. The live command uses the
existing Service Account, Netmiko and OpenSSL dependencies.

The test targets only R1 (`172.20.20.13`). It reads admin from NetPilot-Current,
archives the original credential as NetPilot-Previous-<rotation_id>, and stages
a generated password in NetPilot-Pending. Independent Vault readback and durable
journal references must succeed before any device change.

It changes only the hash in R1's existing privilege-15/network-admin account
statement, verifies fresh SSH with the new password, then restores the exact
original statement/hash. Fresh original-password SSH and comparison against the
original running/startup configurations must succeed before rollback is marked
verified. Admin ancillary records, AAA and netpilot-recovery are preserved.
Unsupported admin account formats are refused before writes.

No startup save, Current update, other-device access, or service restart occurs.
Existing unrelated pending configuration is preserved. Keep other configuration
writers idle during this test. While the temporary password is active, new
telemetry connections using Current may fail; this test does not certify telemetry
health or restart collectors. It relies on your already verified recovery account
for independent emergency access and does not retrieve or change its password.

The existing private journal at `~/.local/state/netpilot/rotation/journal.json`
records only statuses, timestamps and Vault item IDs. It shares the rotation
engine's lock and schema; the eight uncontacted devices remain unverified. An
unresolved journal or an existing Pending item blocks another test.

On failure or Ctrl-C after device change is attempted, the script attempts to
restore the original account using the held session or fresh admin SSH with the
known original/Pending credentials. It never reports restoration without a fresh
original-password login and configuration comparison. If restoration cannot be
verified, the journal remains RECOVERY_REQUIRED (or retains its last durable
uncertain intent if journal storage fails), and the command returns FAIL.

Pending, Previous and the journal remain after success or failure; nothing is
automatically deleted. An abrupt process/host failure can prevent rollback: keep
these records and use Current/Previous for the original password, Pending for the
new password, or your independent recovery account to recover R1. Inspect the
journal before retrying. Resolve retained Pending deliberately only after R1's
original access is confirmed; a normal rerun refuses to overwrite it.

Example success summary (live verification has not been run during development):

```text
PASS | Pending staged and read back; recovery references persisted
PASS | new admin password verified via fresh SSH; unrelated configuration preserved
PASS | original admin password, permissions and configurations restored via fresh SSH
PASS | NetPilot-Current credentials unchanged; Pending and Previous retained
PASS | R1 admin test | state=ROLLED_BACK
```

A failed test returns nonzero even if automatic rollback succeeds. No passwords,
hashes, configurations or raw exceptions are written to logs/journals. The existing
fleet adapter and all live fleet execution restrictions remain unchanged.

# NetPilot shared admin password rotation

Phase 2.4.5 enables the existing engine for exactly R1–R5 and S1–S4 from
`inventory/devices.yml`. It reuses the tested R1 Netmiko/SHA-512 update, 1Password
Credential Provider, Pending/Previous adapter, and rotation journal. No new Python
dependencies are required. Use the existing project virtual environment.

## Commands

From `/home/student/Documents/NetPilot`:

```bash
# Offline: inventory and stored journal only; no Vault, SSH, Influx or service access.
.venv/bin/python -m security.credential_rotation fleet --dry-run

# Live: verify the completed R1 test, then archive only its owned temporary records.
.venv/bin/python -m security.credential_rotation cleanup-r1 --execute

# Live: prepare, rotate all nine sequentially, promote Current, refresh telemetry.
.venv/bin/python -m security.credential_rotation fleet --execute

# Offline: last recorded state, not a fresh device-health claim.
.venv/bin/python -m security.credential_rotation status
```

`--execute` is sufficient authorization; there are no confirmation phrases or
password prompts. Development validation does not execute the live commands.
The older separate `prepare --fleet`, `rotate --fleet` and `commit` commands
remain available with `--execute`.

## Completed R1 test cleanup

Cleanup accepts only the successful R1-only `ROLLED_BACK` rehearsal, with recorded
new-password verification and original-password restoration, no failure events,
and no attempts on other devices. It checks the exact journal-bound Pending and
Previous item IDs, rotation ownership, Current binding, and Current/Previous
credential equality. It then requires fresh original-admin SSH to R1, enable
access, privilege 15 and configured `network-admin` role.

Only those two items are **archived**, never permanently deleted. Current is
rechecked before each archive. The completed journal is retained immutably under
`~/.local/state/netpilot/rotation/history/<rotation_id>.json`; only its active
`journal.json` slot is cleared. Ambiguity stops cleanup. If one archive succeeds
and another fails, rerun the same command: archived items are verified by their
bound IDs. Unrelated or active recovery records are not cleared. The archived
Vault items remain recoverable through 1Password.

## Fleet execution and save guard

1. Read Current using the existing provider. Unknown or unresolved Pending items
   block a new rotation. A prior healthy full-fleet COMMITTED/ROLLED_BACK Pending
   can be archived by its exact owned ID after fresh fleet and monitoring checks;
   its immutable journal and Previous credential are preserved.
2. Verify Current SSH on all nine, check configured recovery accounts, and require
   the existing managed Telegraf service plus fresh telemetry from all nine.
3. Preserve Current in `NetPilot-Previous-<rotation_id>`, then stage/read back one
   strong shared password in `NetPilot-Pending` before any device change.
4. Process `R1, R2, R3, R4, R5, S1, S2, S3, S4` sequentially. Record intent first;
   preserve the admin account's attributes and every unrelated configuration line;
   change only its SHA-512 hash; verify by fresh SSH with privilege/role checks.
5. Save only after exact expected running/startup checks. Existing unrelated
   pending changes block the operation; drift during verification blocks saving.
   Resume can save an already-applied, freshly verified password only when the
   journal owns that attempt and the only running/startup difference is the admin
   hash. Final startup readback is required.
6. Reverify all nine, promote Current with readback, then restart only the existing
   `systemctl --user` service `netpilot-telegraf.service`. Require new counter
   samples from all nine NSOT addresses collected **after restart completion**.

The independently verified `netpilot-recovery` accounts are preserved. Runtime
checks inspect their configured privilege/role; they do not retest recovery SSH
because the separate recovery password is not available to the service account.
SSH host-key validation remains relaxed **only for this isolated Containerlab**;
SSH encryption, authentication, enable and account checks remain enabled.

Run during exclusive maintenance access. EOS/Vault changes are not a single
transaction; no tool can rule out a concurrent edit between a config check and a
save. The guard detects observed unrelated changes and refuses to save them.
Passwords/hashes are never placed in logs, argv, journal or local secret files.
Existing OpenSSL generates SHA-512 hashes through stdin. The original password
may be shorter than the policy for newly generated passwords. Authentication
and explicit rollback accept an existing nonempty printable password up to 128
UTF-8 bytes; hashing still rejects unsafe stdin input. New/recovery passwords
retain the strict 16–128-byte policy, and rotation generates 32 characters.

## Failure and recovery

A failure stops further rotation. Current remains original until every device is
verified and saved. Pending, Previous and journal are retained on failure and
after completion. Output reports each recorded `verified_old`, `verified_new` or
`unknown` state, plus Vault and monitoring status; it does not claim automatic
rollback. Current can be promoted while monitoring fails: that is reported as
`RECOVERY_REQUIRED`, with Vault `promoted`, rather than as a successful rotation.

```bash
# Live read-only reconciliation; never edits the journal or saves configuration.
.venv/bin/python -m security.credential_rotation verify

# Explicit recovery after reviewing the reported state.
.venv/bin/python -m security.credential_rotation recover --action resume --execute
.venv/bin/python -m security.credential_rotation recover --action rollback --execute

# After resume reaches READY_TO_COMMIT, or to retry a failed commit/monitoring step:
.venv/bin/python -m security.credential_rotation commit --execute
```

Resume verifies startup persistence for devices already using Pending. Rollback
restores the original shared password and verifies/saves it; an unsaved Pending
change is first safely verified/persisted before restoration. Interruptions retain
recovery intent. No recovery succeeds on unknown SSH or save outcomes. Do not
manually delete an unresolved journal or its Vault credentials. The
R1 cleanup command intentionally cannot clean up fleet or failed-test recovery records.

To close a failed fleet attempt when every device is still using the original
password, run the separate guarded cleanup command:

```bash
.venv/bin/python -m security.credential_rotation cleanup-failed --execute
```

This reruns the existing read-only `verify` logic with fresh SSH checks against
both original and Pending credentials. It requires all nine `verified_old`,
complete observations, Current still original, and exactly owned Pending/Previous
records. `verify` may report `passed: false` because a failed rotation expected
New; cleanup explicitly checks the observed Old states instead. Any unknown/New
device, changed Current, or ownership ambiguity blocks cleanup.

The original failed journal is archived unchanged under `history/<rotation_id>.json`;
only its active slot is cleared after the two bound Vault items are archived and
read back. No password changes, startup saves, service restarts or Current writes
occur. Interrupted cleanup can be retried with the same command; it rereads
archived bound items and repeats fresh verification. After `phase: CLEANED`, a
new `fleet --execute` starts a separate transaction with a newly generated password.
Do not run that retry until cleanup succeeds.

During a partial rotation, Current still holds the original password, so new
connections from consumers may fail for devices already changed. Telegraf is not
restarted until promotion; other consumers fetch Current through their existing
provider. The engine does not restart GUI, Golden Config, Grafana or arbitrary
external clients.

## Existing prerequisites

- Working `op`, Netmiko, PyYAML, InfluxDB client and `openssl` in the existing setup.
- Existing private `~/.config/netpilot/secrets/onepassword-token` and service-account
  access to `NetPilot-Secrets`, including item archive permission for cleanup.
- Existing user service `netpilot-telegraf.service` and its credential files.
- Influx settings are read from `telegraf/telegraf-gnmi-influx.conf`; optional
  `INFLUX_URL`, `INFLUX_ORG`, `INFLUX_BUCKET` override them. The token uses existing
  `INFLUX_TOKEN`/`CREDENTIALS_DIRECTORY` handling or the managed service's private
  `~/.config/netpilot/secrets/influx-token`. No new exported secrets are needed.
- Account/AAA behavior and recovery SSH were operator-verified in preceding tests.
  No live fleet, cleanup or service restart was performed during this implementation.

Example final report fields:

```text
result: PASS | phase: COMMITTED | outcome: Success
R1 … S4: verified_new
vault_state: promoted
monitoring_state: verified
```

On a partial failure, expect `FAIL`, `PARTIAL_FAILURE` or `RECOVERY_REQUIRED`, and
per-device states with sanitized error categories. `status` reports stored
history; `verify` explicitly requests fresh SSH observations.

## Offline checks

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests -v
```

Tests mock Vault, SSH, service and Influx operations. They cover cleanup ownership
and interrupted archives, sequential rotation, startup guards, partial failures,
resume/rollback, promotion ordering and fresh all-device telemetry.


## Email and 30-day scheduling

See [ROTATION_SCHEDULING.md](ROTATION_SCHEDULING.md) for protected SMTP settings,
the standalone test email, daily user timer installation, due-date status and
explicit rearming after failure. The timer is not enabled by development.
Manual fleet/commit results also send configured notifications; SMTP delivery
errors are reported separately without changing a committed transaction.

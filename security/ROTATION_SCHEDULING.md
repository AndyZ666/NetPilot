# Scheduled rotation and email

Run these commands from `/home/student/Documents/NetPilot` using the existing
virtual environment. No new Python packages are needed. SMTP uses the standard
library with certificate-verified STARTTLS or implicit TLS; plaintext SMTP is not
supported. Development does not install or enable these units, send email, or
rotate passwords.

## Configure and test email first

Create or edit the private configuration **outside the repository**:

```bash
umask 077
mkdir -p "$HOME/.config/netpilot"
chmod 700 "$HOME/.config/netpilot"
touch "$HOME/.config/netpilot/smtp.json"
chmod 600 "$HOME/.config/netpilot/smtp.json"
nano --ignorercfiles "$HOME/.config/netpilot/smtp.json"
```

Enter your provider's settings in the editor, replacing these placeholders:

```json
{
  "SMTP_HOST": "smtp.example.com",
  "SMTP_PORT": 587,
  "SMTP_USERNAME": "sender@example.com",
  "SMTP_PASSWORD": "ENTER-APP-PASSWORD-IN-THE-EDITOR",
  "SMTP_FROM": "sender@example.com",
  "SMTP_TO": "operator@example.com",
  "SMTP_SECURITY": "starttls"
}
```

Use `"ssl"` with port `465` if required by your provider. Use one plain email
address for each of `SMTP_FROM` and `SMTP_TO`. The file must be a regular file
owned by your user with mode `0600`. Do not paste credentials into shell commands,
unit files, source code, or Git. The same `SMTP_*` environment names can override
the file, but a user service does not automatically inherit your terminal's
exports; the private file is the simplest persistent setup.

Send only the test email:

```bash
.venv/bin/python -m security.rotation_email --test --execute
```

Expect `PASS | notification | status=sent`; also check the recipient inbox.
Failure reports a sanitized category without SMTP responses or credential values.
This command does not contact devices or trigger rotation. Rotation notifications
include only the execution timestamp, rotation ID, device success count, Vault
and monitoring status, and sanitized failure/recovery metadata. Email delivery
failure is reported separately and cannot undo a committed password rotation.

## Check due date and recorded status

```bash
.venv/bin/python -m security.rotation_scheduler status
.venv/bin/python -m security.credential_rotation status
```

These commands inspect local state, not live SSH health. The scheduler uses the
latest successful full-fleet `COMMITTED` timestamp in the active journal or
preserved history. It becomes due after **30 full days**, measured in UTC. If no
successful baseline exists, or recovery is unresolved, it does not start a new
rotation. A daily local-time check may run up to a day after the exact due time.

## Manual rotation

Use the existing fleet command for an immediate real rotation:

```bash
python3 -m security.credential_rotation fleet --execute
```

Manual and scheduled rotations use the same notification helper and existing
Gmail/SMTP settings. Each attempt sends one success or failure notice; delivery
errors are reported separately without changing the password transaction.
Dry-run, status, verify, and skipped scheduled checks do not send email.
The daily timer and 30-day guard are unchanged.

## Install the user timer after the email test passes

The existing `netpilot-telegraf.service`, Containerlab devices, InfluxDB, `op`,
OpenSSL, and the existing virtual environment must be ready. Authentication
reuses the protected files already provisioned for NetPilot:

- `~/.config/netpilot/secrets/onepassword-token`
- `~/.config/netpilot/secrets/influx-token`

No interactive 1Password desktop login or terminal exports are needed. InfluxDB
URL/org/bucket use the existing Telegraf configuration. If your working setup
depends on environment overrides, provide the same non-secret overrides through
a user-service drop-in; secrets remain in the private credential/configuration
files above.

```bash
install -d "$HOME/.config/systemd/user"
install -m 644 security/systemd/netpilot-rotation.service security/systemd/netpilot-rotation.timer "$HOME/.config/systemd/user/"
systemctl --user daemon-reload
sudo loginctl enable-linger "$USER"
systemctl --user enable --now netpilot-rotation.timer
systemctl --user list-timers netpilot-rotation.timer
```

Lingering starts the user manager at boot without an interactive login. The timer
checks daily at 09:00 local time; `Persistent=true` catches a missed daily check
after reboot. Its runner still applies the 30-day guard. A due check can therefore
start shortly after activation or reboot. Review the due date before enabling it.
No initial rearm command is needed when the previous rotation is safely complete.

The unit orders after an already-starting managed Telegraf service but does not
start it or any lab dependency. Ensure your existing lab and telemetry startup
arrangement brings those services up after reboot. This timer does not install
Containerlab/InfluxDB autostart. Missing prerequisites fail safely and require
operator review and rearming rather than an automatic retry.

```bash
systemctl --user status netpilot-rotation.timer netpilot-rotation.service
journalctl --user -u netpilot-rotation.service -n 100 --no-pager

# Disable future scheduled checks; this does not stop an already-running rotation.
systemctl --user disable --now netpilot-rotation.timer
```

The service has no automatic restart. Manual and scheduled rotation use the same
execution lock. Every successful previous transaction retains its audit history
before a later rotation starts. A completed transaction's owned Pending record
can be archived safely by the existing engine; unrelated credentials and
unresolved recovery records are preserved.

## Failed scheduled attempts

A scheduled attempt records its intent before running. Failure or interruption
blocks later automatic attempts until the operator resolves recovery and
explicitly rearms. Do not delete its marker, journal, or Vault recovery records.
Inspect the status and use the existing
[recovery commands](PASSWORD_ROTATION.md#failure-and-recovery). A monitoring
failure after promotion is still a recovery problem; a separate SMTP delivery
failure after `COMMITTED` is not a failed password transaction.

After recovery or guarded failed-transaction cleanup has safely completed:

```bash
.venv/bin/python -m security.rotation_scheduler rearm --execute
.venv/bin/python -m security.rotation_scheduler status
```

Rearm refuses unresolved transactions. It permits a healthy committed or
full-fleet rolled-back transaction, or a journal cleared by guarded cleanup, and
still requires a preserved successful baseline. Rearming does not rotate
immediately; the next daily check applies the original due-date guard. An
overdue attempt will be eligible again. To run that check explicitly after
review, use:

```bash
.venv/bin/python -m security.rotation_scheduler run --execute
```

`--execute` is sufficient authorization. There are no additional confirmation
phrases, automated recovery, or retries of a partial rotation.

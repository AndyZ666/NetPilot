# Phase 2.4.2B — prepared Telegraf integration

This phase adds a launcher, an **uninstalled** systemd user-service draft, and
offline tests. It does not migrate the running collector. No service was
installed, enabled, started, stopped, or restarted. No device, Vault item,
password, service-account token, active Telegraf configuration, GUI, Golden
Config, InfluxDB, Grafana, or topology implementation was changed.

## Confirmed runtime and prerequisites

Read-only host inspection on 2026-10-12 found one Telegraf process owned by
`student`, launched by Bash. Its executable was `/usr/bin/telegraf` and its
configuration was:

`/home/student/Documents/NetPilot/telegraf/telegraf-gnmi-influx.conf`

The process working directory was the project's `telegraf/` directory. Its PID
was discovered at inspection time; **rediscover and verify it before any later
action**. No PID is embedded in the launcher or migration commands.

Installed versions: Telegraf 1.40.0, systemd 255, and Python 3.12.3 (including the
existing `.venv/bin/python`). The provider's `op` executable is `/usr/bin/op`.
The student user manager is active, with `/run/user/1001` as its runtime
directory; lingering is currently disabled. These are observations, not values
hardcoded into the launcher.

**The packaged system-level `telegraf.service` is inactive but enabled.** It uses
the `telegraf` OS account and `/etc/telegraf` configuration, not this collector's
launch command. Its future boot behavior must be resolved before enabling a
user-service replacement. It was not altered during this task.

No new Python package is required; the launcher needs Python 3.11+ for `tomllib`
and uses the existing provider and CLI. The service runs as the existing user,
so the provider continues to use:

`~/.config/netpilot/secrets/onepassword-token`

That token remains outside Git. It must be a private regular file owned by the
service user; the provider's existing ownership, permissions and symlink checks
remain authoritative. It is not imported into systemd's global environment.

## Launcher behavior

`security/telegraf_launcher.py` defaults to the existing absolute executable and
configuration paths. It does not offer arbitrary config or command passthrough.

1. Validate executable/config availability, the configuration's existing secret
   references, the `op` executable, provider token-file metadata, and a private
   user runtime directory.
2. Acquire a nonblocking lock in
   `$XDG_RUNTIME_DIR/netpilot-telegraf/collector.lock`. Without `XDG_RUNTIME_DIR`,
   the existing `/run/user/<effective UID>` directory must be available. There is
   no unsafe shared `/tmp` fallback.
3. Inspect `/proc/*/comm` for any existing process named `telegraf`. Refuse startup
   without signaling or changing that process. No process arguments or
   environments are dumped. Unreadable process metadata causes startup failure.
4. Obtain the Influx token from the managed credential file, or from the existing
   `INFLUX_TOKEN` environment variable for manual use. Retrieve a fresh device
   credential pair through `security.credential_provider.get_credentials()`.
5. Preserve unrelated environment variables, replace stale
   `NETPILOT_USERNAME` / `NETPILOT_PASSWORD`, and set `INFLUX_TOKEN`. Remove `OP_*`
   variables and credential-directory locators from the collector environment.
   Credentials are not written to temporary configs or passed in arguments.
6. Recheck for an existing collector after the Vault lookup, retain the lock
   descriptor across exec, suppress raw collector stdout/stderr, and call
   `os.execve()` with `/usr/bin/telegraf --config <existing absolute config>`.

Exec replaces the launcher with Telegraf under the same PID. There is no Python
supervisor, forwarding loop, or retry loop. SIGTERM/SIGINT and exit status belong
directly to Telegraf; systemd can stop its process group normally. A failed
credential lookup never falls back to old device credentials or starts a
collector. Each new start fetches fresh credentials.

The lock prevents simultaneous cooperating launcher instances. The process scan
also detects the current Bash collector, but cannot stop a separate actor from
starting another collector after the check, or see processes hidden by a PID
namespace. Use the launcher from the normal host/user session, not an isolated
container, and prevent other launch mechanisms from competing. Never delete the
lock file/directory to bypass a failure while a launcher or collector is active.

## Preflight

After the external Influx token source is available, run from the project root:

```bash
.venv/bin/python -B security/telegraf_launcher.py --check
```

If `INFLUX_TOKEN` is not already exported, an operator can check the prepared
external token file without putting its value in the command line:

```bash
CREDENTIALS_DIRECTORY="$HOME/.config/netpilot/secrets" \
  .venv/bin/python -B security/telegraf_launcher.py --check
```

Check mode reads configuration, token-file metadata, the Influx token source,
runtime metadata and process names. It does **not** read the service-account token
contents, contact 1Password, create a lock/directory, execute Telegraf, or perform
network tests. An existing collector produces a warning; a successful check is
not authorization to start a duplicate collector and is not proof of Vault
authentication or working telemetry. The check emits no secret values.

## Influx token provisioning

The active config already references `INFLUX_TOKEN`; its URL, organization,
bucket and subscriptions remain unchanged. The service draft uses:

```ini
LoadCredential=influx-token:%h/.config/netpilot/secrets/influx-token
```

This is a separate external file containing the **existing** Influx token, not a
new token and not the device-management password. During service startup systemd
copies it into the service credential directory, identified by
`CREDENTIALS_DIRECTORY`. The launcher reads only `influx-token` there and injects
it into Telegraf's environment. Missing, empty, unreadable or unsafe managed
credentials cause failure; an explicitly configured managed source never falls
back to an inherited token. The user unit clears inherited credential variables
to avoid ambiguity.

The source file has not been created by this task. During an approved migration,
provision it from the existing trusted token source. Do not extract it from
`/proc`, print it, paste it into a shell command, or commit it. The following
optional preparation uses a hidden prompt (or an already exported token), refuses
to overwrite an existing file, and writes only outside the repository:

```bash
python3 - <<'PY'
import getpass, os
from pathlib import Path
directory = Path.home() / '.config/netpilot/secrets'
directory.mkdir(mode=0o700, parents=True, exist_ok=True)
info = directory.lstat()
if directory.is_symlink() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
    raise SystemExit('Use an owner-only private secrets directory.')
token = os.environ.get('INFLUX_TOKEN') or getpass.getpass('Existing Influx token (hidden): ')
if not token or any(c in '\\"' or not c.isprintable() for c in token):
    raise SystemExit('Token is empty or incompatible with the current config.')
fd = os.open(directory / 'influx-token', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, 'w') as output:
    output.write(token + '\n')
print('Private external Influx credential file prepared.')
PY
```

This preserves the monitoring token rather than rotating it. File permissions
and systemd credential delivery reduce accidental exposure; the Telegraf process
still requires the token and device credentials in its environment. Root and the
same Unix account are not isolated from these secrets. Removing `OP_*` variables
does not make the existing provider token file inaccessible to the same user.
The managed unit disables core dumps; a manual invocation inherits the calling
shell's core-dump policy instead.

## Proposed managed service

Draft: `security/systemd/netpilot-telegraf.service`.

- Runs under the user's systemd manager, using the existing virtual environment
  and `%h/Documents/NetPilot` working directory. No `User=` override is needed.
- Uses `LoadCredential` for Influx, private runtime permissions, `UMask=0077`,
  `NoNewPrivileges=yes`, and `LimitCORE=0`.
- Uses `Restart=no`, plus a start-rate limit. A Vault/network failure requires
  deliberate recovery; there is no authentication-failure restart storm.
- Preserves the runtime directory so a failed service start cannot remove a
  manual launcher's active lock inode. Runtime storage still clears on reboot.
- Uses normal user startup ordering (`basic.target`). A user unit cannot depend
  on the system manager's Docker, Influx or `network-online.target`. The operator
  must ensure network/Vault and the existing monitoring backends are available.
  Telegraf's normal reconnect behavior remains unchanged. With `Restart=no`, an
  early boot Vault failure needs an explicit retry after connectivity returns.
- Has `WantedBy=default.target` as a future installation option only. It is not
  enabled. Without lingering, operation follows the user-manager/login lifecycle.
  Boot operation and persistence after logout require a separate explicit
  decision about `loginctl enable-linger student` and startup readiness.

Only fixed launcher messages reach the journal. Telegraf stdout/stderr are
redirected to `/dev/null` before exec because expanded config/error messages can
contain secrets. Collector diagnostic logs are consequently unavailable through
this launcher; assess health using fresh Influx timestamps and counters. The
start message and systemd `active` status alone do not prove collection works.

Telegraf substitutes environment values before parsing TOML. The current quoted
placeholders cannot safely accept arbitrary quotes, backslashes or control
characters. The launcher rejects those values without printing them rather than
silently transforming credentials. A future password generator must respect
this limitation **before** changing devices, or a separately reviewed secure
secret-input mechanism must replace it. See the official
[Telegraf environment-variable documentation](https://docs.influxdata.com/telegraf/v1/configuration/environment-variables/)
and [systemd v255 credentials documentation](https://github.com/systemd/systemd-stable/blob/v255-stable/docs/CREDENTIALS.md).

## Manual migration — only after explicit approval

Do not execute this procedure as part of the preparation task.

1. Record healthy, fresh telemetry for all nine devices, including interface
   counters, interface status and CPU subscriptions. Preserve access to the
   original Bash launch environment and its existing credentials for rollback;
   do not dump or save that environment. Prepare the private Influx file and run
   the check above. Existing all-nine-device Vault authentication is user-reported;
   this phase did not rerun it.
2. Resolve the inactive-but-enabled **system** Telegraf service's future startup
   with the operator. Do not enable the replacement or lingering until conflicting
   startup mechanisms are addressed. This task does not disable or mask anything.
3. Install the prepared user unit only after approval:

   ```bash
   install -D -m 0644 security/systemd/netpilot-telegraf.service \
     "$HOME/.config/systemd/user/netpilot-telegraf.service"
   systemctl --user daemon-reload
   ```

4. Rediscover the Bash collector with `pgrep -u "$(id -u)" -x telegraf` (PID only).
   Confirm there is exactly one and verify its executable, configuration and
   ownership using read-only inspection. At the approved cutover, send SIGTERM
   **only to that freshly verified PID**. Wait for it to exit and confirm no
   Telegraf remains. Never use `killall`, a stored PID, or start a second collector
   for testing.
5. Start the prepared unit explicitly:

   ```bash
   systemctl --user start netpilot-telegraf.service
   systemctl --user status netpilot-telegraf.service --no-pager
   ```

6. Confirm exactly one collector, correct config and fresh post-start samples for
   every source/subscription. Allow several existing collection/flush intervals.
   Check actual timestamps, not cached dashboard or topology status. Record any
   expected short telemetry gap. If this fails, use the rollback below.
7. Only after successful validation and separate startup approval, enable the
   user unit with `systemctl --user enable netpilot-telegraf.service`. Decide
   lingering/boot readiness separately; enabling alone is not a guaranteed
   boot-time start and does not resolve the packaged system service conflict.

## Rollback after an approved migration

1. Stop only the replacement with `systemctl --user stop netpilot-telegraf.service`.
   Verify its processes exited. If it was enabled, disable it before returning to
   manual operation; otherwise it could return at a future login.
2. Confirm that no collector remains. Do not delete an active lock to force a
   second launch. Restore the original Bash invocation using the existing trusted
   environment, **not** credentials copied from logs or process inspection:

   ```bash
   cd /home/student/Documents/NetPilot/telegraf
   /usr/bin/telegraf --config /home/student/Documents/NetPilot/telegraf/telegraf-gnmi-influx.conf
   ```

   This command is solely the future rollback to the prior launch method. Its
   original logging behavior also returns; do not share unsanitized logs. If the
   original environment is unavailable, first recover current credentials through
   the approved secure source. Do not guess credentials or run without the token.
3. Confirm one collector and fresh telemetry on all nine devices again. Keep the
   managed unit disabled until its failure is investigated. No device, Vault or
   Influx token rollback is needed for this integration phase because none was
   changed. No automatic rollback collector is ever launched by the new code.

## Future rotation controller boundary

Do not implement password rotation or email in this phase. A later controller
must serialize rotation with maintenance/configuration operations and:

1. Prevalidate password compatibility, backup/recovery access and all consumers.
2. Rotate and verify all nine devices; track per-device progress durably. A shared
   item cannot represent a partially rotated fleet. Partial failure must abort
   automatic telemetry credential refresh and enter an explicit recovery plan.
3. Only after complete verification, publish the consistent current credential
   pair to the existing Vault item. Define recovery for Vault-publication failure.
4. After managed-service migration is approved and proven, request
   `systemctl --user restart netpilot-telegraf.service` under the correct user
   manager. Do not start a parallel manual collector. A new start fetches the new
   pair; a running process does not refresh its environment automatically.
5. Verify fresh all-nine-device telemetry against a recorded pre-change baseline
   before declaring success or sending the future email notification. Define
   recovery for restart/telemetry failure without silently reverting to stale
   credentials or looping on Vault authentication.

Before that work begins, complete and rehearse the approved migration/rollback,
resolve boot conflicts and token provisioning, address previously reported
credential exposure, and document trusted management transport and emergency
access. This phase does not claim those operational prerequisites are complete.

## Offline validation

```bash
.venv/bin/python -B -m unittest discover -s tests -p test_telegraf_launcher.py -v
.venv/bin/python -B -m unittest discover -s tests -q
systemd-analyze --user verify security/systemd/netpilot-telegraf.service
```

Tests use temporary fixtures and mocked Vault/process boundaries. Any native
exec/signal checks use a temporary fake Python executable, never Telegraf or
the network. Unit verification checks the draft without installing or starting
it. Live credential lookup, real collector execution, managed-service migration
and telemetry validation remain intentionally unperformed.

Preparation results: **29/29 launcher tests PASS; 209/209 full regression tests
PASS**. Native fake-process tests confirmed exit status 23, direct SIGTERM exit,
same PID across exec, lock inheritance and output suppression. Syntax/parse
checks passed for 34 Python, 23 YAML, two JSON and four Telegraf TOML files.
`systemd-analyze --user verify` accepted the final uninstalled unit. Hash
comparison confirmed all **191 pre-existing project files remained byte-identical**
to the start of this phase, including the active Telegraf configuration and the
previous phase's uncommitted work. Only the four deliverable files were added.

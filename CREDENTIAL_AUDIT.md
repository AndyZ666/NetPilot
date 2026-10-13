# Phase 2.4.1: credential dependency audit and integration

Audit date: 2026-10-12. No live Vault requests, network-device operations,
password rotation, or service restarts were performed. The real service-account
token was not read or modified. Existing inventories, configurations, Golden
snapshots, telemetry, topology, requirements, and CI workflow were preserved.

## Dependencies and resulting authentication flow

| Consumer | Before this change | Current behavior |
| --- | --- | --- |
| `save_golden_configs.py` | `NETPILOT_USERNAME` / `NETPILOT_PASSWORD` | Fetches one provider credential pair per capture job; passes it to the existing Netmiko collectors. Existing function signatures and backup content remain intact. |
| `config_changes.py` | Environment credentials during Apply | Fetches through the provider after preview/inventory validation and before the durable claim, connection, backup, or device write. Preview never accesses the Vault. |
| `app.py` | Golden Config POST required environment credentials | Keeps the existing backend subprocess; that backend retrieves credentials. Basic Config Change still delegates to `config_changes.py`. GET pages, CSRF, locks, result validation, and sessions remain as before. No device credentials are passed in arguments or sessions. |
| `challenge_maintenance.py` | Environment credentials for EOS eAPI | The existing EAPI adapter retrieves a pair when created. Status remains offline. All drain, rollback, routing, telemetry, and instructor gates are unchanged. |
| `Functions/configure_gnmi.py` | Environment credentials read at import | Runtime provider access; one pair per configure/audit batch. Existing Netmiko configuration commands are unchanged. |
| `Functions/configure_netconf.py` | Environment credentials read at import | Runtime provider access shared by existing Netmiko configuration and ncclient audits. |
| `Functions/netconf_edit.py`, `Functions/netconf_s3_test.py` | Fixed username, prompted password, and connections at import | Provider access and NETCONF operations occur only inside explicit `main()` execution. These are standalone examples/diagnostics, not GUI routes. The edit example still changes configuration when explicitly run. |
| `security/test_all_vault.py`, `security/test_r1_vault.py` | Existing provider-based live authentication smoke scripts; R1 ran on import | Both remain explicit live checks; package/direct imports work and imports do not access the Vault or devices. They were not run during this task. |
| `Functions/maintenance_telemetry.py:75`, `Functions/realtime_topology.py:430`, `Functions/test_influx_status.py:7` | `INFLUX_TOKEN` | Unchanged: this is telemetry authentication, separate from device management credentials. The last file is a standalone live diagnostic. |

`inventory/devices.yml` remains the canonical NSOT for the GUI, Golden Config,
configuration changes, and maintenance. The gNMI/NETCONF setup scripts still use
their existing `Functions/devices.json` device list; the S3 examples and live
Vault smoke scripts still contain their existing device addresses. No inventory
migration was attempted. SNMP setup helpers use their existing Docker/device
execution mechanisms and were not converted into a second credential system.

The canonical inventory, `Functions/devices.json`, current topology and archived
topology contain no device credential fields found by this audit. No Python
consumer of the generated Containerlab Ansible/Nornir inventories was found.
Standalone entry points identify potential use; they do not prove which scripts
an operator runs regularly.

## Provider behavior and prerequisites

The public interfaces remain `get_credentials() -> (username, password)` and
`read_secret(field) -> str`. The existing external token location remains
`~/.config/netpilot/secrets/onepassword-token`, for the invoking OS account.
The file must be a regular, non-symlink file owned by that account, without
group/other permission bits (for example mode `0600` or `0400`). No credentials
or token values belong in the repository.

`get_credentials()` retrieves the two labeled fields together using one
`op item get NetPilot-Current --vault NetPilot-Secrets --fields label=username,label=password --format json --reveal`
request. Reading one item response avoids mixing revisions of two independent
field reads. `read_secret()` retains the existing `op read` behavior. These
commands are read-only; neither creates nor updates Vault items. Syntax follows
the [official item command documentation](https://www.1password.dev/cli/reference/management-commands/item).

The provider uses list arguments, no shell, no interactive stdin, a 30-second
timeout, captured output, and fixed sanitized errors. The token is supplied only
in the CLI child's environment. Competing CLI account/session/Connect settings
are removed for that child. Caching, debug output, biometric unlock and archive
selection are disabled for that child; the parent environment is unchanged.
See [1Password CLI environment variables](https://www.1password.dev/cli/environment-variables).

There is no fallback to `NETPILOT_USERNAME` / `NETPILOT_PASSWORD` in the refactored
Python paths. Vault/token/CLI failures stop the requested operation before device
access. Each new operation fetches fresh credentials; an operation keeps its
pair in memory for its lifetime. No persistent credential cache is introduced.
Do not rotate credentials during an in-progress maintenance operation.

No new Python dependency was added. `op --version` reported **2.41.0** without
accessing the Vault. The process running Flask or a CLI must have `op` on PATH
and access to the token under its own home directory. Existing NETCONF scripts
still require their existing optional `ncclient` dependency; offline tests stub
it and do not require its installation. Telemetry still requires separately
provisioned `INFLUX_TOKEN` where it did before.

## Security findings left unchanged

Values are deliberately omitted. Line numbers refer to the unchanged files.
"Tracked" means present in the current Git index; ignored local files can still
expose credentials to anyone with filesystem access. Ignoring a file does not
remove already tracked content or establish anything about historical exposure.

| File and line(s) | Finding | Status / apparent role |
| --- | --- | --- |
| `telegraf/telegraf-before-all-counters.conf:18,19` | Static device username/password | Tracked; historical variant, no active code reference found. |
| `telegraf/telegraf-gnmi-influx-S3-backup.conf:8,9` | Static device username/password | Tracked; backup variant, no active code reference found. |
| `telegraf/telegraf-gnmi-poc.conf:8,9` | Static device username/password | Tracked; proof-of-concept variant, no active code reference found. |
| `AI_HANDOFF.md:193,194,322,323` | Static credential assignment examples | Tracked documentation; treat as potentially sensitive pending review. |
| `Functions/AUTOMATION_SUMMARY.md:51` | SNMP community configuration example | Tracked documentation. |
| `.env:1,2` | Static device username/password | Ignored local file. The refactored code does not load it. |
| `clab-pilot-network/ansible-inventory.yml:11,12` | Generated static device username/password | Ignored Containerlab runtime file. |
| `clab-pilot-network/nornir-simple-inventory.yml:3,4,8,9,13,14,18,19,23,24,28,29,33,34,38,39,43,44` | Nine generated static credential pairs | Ignored runtime file. Additional credential fields at lines 48–69 are null. |
| `startup_configs/*.cfg` | Password hashes and SNMP communities | All nine tracked; individual paths/lines below. Referenced by archived `golden-v1/nettopo.clab.yml:7`, not the current topology. |
| `golden_configs/**/*.cfg` | Password hashes and SNMP communities | 60 tracked saved snapshots; individual paths/lines below. These are not credential-provider inputs. |

Password hashes are sensitive authentication material, but are not plaintext
passwords. Golden collection still preserves full running configurations, so
future snapshots can contain credential commands or communities too. Changing
backup policy, cleaning old files, reviewing Git history exposure, or replacing
these credentials requires a separate approved task; no such action was taken.
The audit did not determine whether the existing literals remain valid.

NETCONF's existing `hostkey_verify=False` and the maintenance CLI's optional
`--insecure` TLS mode remain unchanged. Production hardening should establish
trusted SSH host keys/certificates before relying on these channels for rotation.
The service account is an operational dependency: recovery initiated in a new
process needs Vault availability. A separate recovery/access plan is needed
before automated rotation; silently falling back to stale credentials is unsafe.

## Telegraf recommendation — not deployed

The intended current repository configuration is
`telegraf/telegraf-gnmi-influx.conf`: lines 18/19 already interpolate
`NETPILOT_USERNAME` / `NETPILOT_PASSWORD`, and line 56 interpolates `INFLUX_TOKEN`.
It is referenced by the maintenance telemetry helper and project documentation.
The active monitoring configuration was neither edited nor restarted.

Host inspection found `/lib/systemd/system/telegraf.service:10` referencing
`/etc/default/telegraf`, with startup at line 13. That environment file has no
active assignments for the three variables, and `/etc/telegraf/telegraf.conf`
does not match the repository variants or enable their gNMI input. No Telegraf
process was visible in the inspected namespace. **The actual running collector
launcher and its credential source therefore remain unconfirmed**; this is not
a claim that monitoring is stopped. Docker/process secret environments were not
dumped or copied.

For a future approved deployment:

1. Identify the actual collector launcher and service account before changing it.
2. Add a small startup wrapper that calls this same provider and launches
   Telegraf against the unchanged current configuration. Set the two device
   credential variables only in the child environment; preserve independently
   provisioned `INFLUX_TOKEN`. Remove any service-account token from the Telegraf
   child's environment. Never place secret values in command arguments or logs.
3. Give the wrapper's OS account appropriate access to its private external token
   file. Do not assume a system service inherits the interactive user's home,
   PATH or environment. Fail startup if retrieval fails; do not use stale values.
4. After any future approved rotation, coordinate the Vault update and collector
   restart through that wrapper, then verify fresh telemetry for all nine devices.
   Changing the parent shell's environment cannot refresh a running collector.
   Plan the short telemetry gap and partial-rotation failure recovery explicitly.

This follows Telegraf's documented
[environment substitution](https://docs.influxdata.com/telegraf/v1/configuration/environment-variables/)
and [service startup](https://docs.influxdata.com/telegraf/v1/administer/run-as-service/).
An alternative is a protected `op run` launcher using secret references; see
[runtime secret injection](https://developer.1password.com/docs/cli/secrets-scripts).
Environment injection avoids plaintext configuration copies, but is not
protection against privileged/local process inspection; keep service access
restricted. Neither launcher was implemented in this phase.

## Files changed and validation

| Files | Purpose |
| --- | --- |
| `security/credential_provider.py` | Harden the existing provider; retrieve a consistent credential pair with safe CLI invocation. |
| `save_golden_configs.py`, `config_changes.py`, `challenge_maintenance.py` | Switch runtime authentication to the provider and sanitize failure output. |
| `app.py` | Remove the obsolete environment gate; retain the existing Golden backend and GUI safety checks. |
| `Functions/configure_gnmi.py`, `Functions/configure_netconf.py` | Runtime provider credentials for existing configuration/audit operations. |
| `Functions/netconf_edit.py`, `Functions/netconf_s3_test.py` | Provider credentials and import guards for the existing NETCONF examples. |
| `security/test_r1_vault.py`, `security/test_all_vault.py` | Safe imports and explicit-only live smoke checks. |
| `tests/test_config_changes.py`, `tests/test_configuration_gui.py` | Adapt existing regression tests to provider-based authentication. |
| `tests/test_credential_provider.py`, `tests/test_credential_integration.py`, `tests/test_management_credentials.py` | New mocked provider, caller, failure, and import-safety tests. |
| `CHALLENGE_MAINTENANCE.md`, `CREDENTIAL_AUDIT.md` | Update credential prerequisites and record the audit, risks, and deferred work. |

Run offline tests with:

```bash
.venv/bin/python -B -m unittest discover -s tests -q
```

The baseline was 136 passing tests. Provider tests mock both token-file OS calls
and the CLI subprocess. Caller tests mock the provider and network connections.
No real Vault tokens or lab access are needed. Python syntax is compiled in
memory, tracked YAML/JSON are parsed without printing values, and the renderer
is exercised with temporary output for all nine real devices. Existing generated
configs are not overwritten. Local validation does not claim a GitHub-hosted CI
run or live authentication against the newly refactored paths.

Final results: **180/180 offline tests PASS** (136 existing plus 44 new),
Python syntax PASS, **23 YAML / 2 JSON files PASS**, **9/9 device renders PASS**,
and `git diff --check` PASS. Hash comparison confirmed **126 protected tracked
files are byte-identical**, including inventories, saved/generated device
configs, Telegraf, GUI templates/static files, topology, requirements and CI.

## Before automated password rotation

- Approve and perform read-only live authentication checks through the provider
  for the intended runtime accounts and all required SSH/eAPI/NETCONF consumers.
  Confirm the installed CLI's item response and service-account permissions.
- Approve remediation of tracked credential-bearing files/documentation and
  assess exposure separately; do not assume `.gitignore` removes old secrets.
- Identify and integrate the real Telegraf launcher; rehearse fresh credential
  injection, planned restart, and all-nine-device telemetry health checks.
- Design a per-device progress/rollback strategy for a partially rotated fleet.
  One shared `NetPilot-Current` pair cannot describe mixed old/new device states.
  Define when to publish credentials and how to preserve management recovery.
- Verify least-privilege service-account access, trusted management transports,
  backup confidentiality, and recovery if Vault or a device becomes unavailable.
  Keep concurrent configuration/maintenance operations out of the rotation window.

## Saved configuration findings by file

Every row below is tracked. Columns list line numbers only, never values.

| File | Password-hash line(s) | SNMP-community line(s) |
| --- | --- | --- |
| `golden_configs/R1/R1_20260921_163917.cfg` | 15 | 27 |
| `golden_configs/R1/R1_20260921_164113.cfg` | 15 | 27 |
| `golden_configs/R1/R1_20260921_195709.cfg` | 15 | 27 |
| `golden_configs/R1/R1_20260929_125114_5388bf19_prechange.cfg` | 8 | 20 |
| `golden_configs/R1/R1_20260929_150938.cfg` | 15 | 27 |
| `golden_configs/R1/R1_20260929_151848.cfg` | 15 | 27 |
| `golden_configs/R1/R1_20260929_162248_e2efcc96_prechange.cfg` | 8 | 20 |
| `golden_configs/R1/R1_20260929_162404_8abc86de_prechange.cfg` | 8 | 20 |
| `golden_configs/R1/R1_20260929_162439_1fab086d_prechange.cfg` | 8 | 20 |
| `golden_configs/R1/R1_20260929_164009_a0d5f195_prechange.cfg` | 8 | 20 |
| `golden_configs/R1/R1_20260929_164107_90383519_prechange.cfg` | 8 | 20 |
| `golden_configs/R1/R1_20261005_151122.cfg` | 15 | 27 |
| `golden_configs/R1/R1_20261005_151410.cfg` | 15 | 27 |
| `golden_configs/R1/R1_20261005_190617.cfg` | 15 | 27 |
| `golden_configs/R2/R2_20260921_164113.cfg` | 15 | 53 |
| `golden_configs/R2/R2_20260921_195709.cfg` | 15 | 53 |
| `golden_configs/R2/R2_20260929_131951_941ecfcd_prechange.cfg` | 8 | 46 |
| `golden_configs/R2/R2_20261005_151122.cfg` | 15 | 53 |
| `golden_configs/R2/R2_20261005_151410.cfg` | 15 | 53 |
| `golden_configs/R2/R2_20261005_190617.cfg` | 15 | 53 |
| `golden_configs/R3/R3_20260921_164113.cfg` | 15 | 27 |
| `golden_configs/R3/R3_20260921_195709.cfg` | 15 | 27 |
| `golden_configs/R3/R3_20260921_195818.cfg` | 15 | 27 |
| `golden_configs/R3/R3_20261005_151122.cfg` | 15 | 27 |
| `golden_configs/R3/R3_20261005_151410.cfg` | 15 | 27 |
| `golden_configs/R3/R3_20261005_190617.cfg` | 15 | 27 |
| `golden_configs/R4/R4_20260921_164113.cfg` | 15 | 27 |
| `golden_configs/R4/R4_20260921_195709.cfg` | 15 | 27 |
| `golden_configs/R4/R4_20260929_145043.cfg` | 15 | 27 |
| `golden_configs/R4/R4_20260929_150325.cfg` | 15 | 27 |
| `golden_configs/R4/R4_20261005_151122.cfg` | 15 | 27 |
| `golden_configs/R4/R4_20261005_151410.cfg` | 15 | 27 |
| `golden_configs/R4/R4_20261005_190617.cfg` | 15 | 27 |
| `golden_configs/R5/R5_20260921_164113.cfg` | 15 | 27 |
| `golden_configs/R5/R5_20260921_195709.cfg` | 15 | 27 |
| `golden_configs/R5/R5_20260929_145619.cfg` | 15 | 27 |
| `golden_configs/R5/R5_20261005_151122.cfg` | 15 | 27 |
| `golden_configs/R5/R5_20261005_151410.cfg` | 15 | 27 |
| `golden_configs/R5/R5_20261005_190617.cfg` | 15 | 27 |
| `golden_configs/S1/S1_20260921_164113.cfg` | 15 | 27 |
| `golden_configs/S1/S1_20260921_195709.cfg` | 15 | 27 |
| `golden_configs/S1/S1_20260921_231218.cfg` | 15 | 27 |
| `golden_configs/S1/S1_20261005_151122.cfg` | 15 | 27 |
| `golden_configs/S1/S1_20261005_151410.cfg` | 15 | 27 |
| `golden_configs/S1/S1_20261005_190617.cfg` | 15 | 27 |
| `golden_configs/S2/S2_20260921_164113.cfg` | 15 | 27 |
| `golden_configs/S2/S2_20260921_195709.cfg` | 15 | 27 |
| `golden_configs/S2/S2_20261005_151122.cfg` | 15 | 27 |
| `golden_configs/S2/S2_20261005_151410.cfg` | 15 | 27 |
| `golden_configs/S2/S2_20261005_190617.cfg` | 15 | 27 |
| `golden_configs/S3/S3_20260921_164113.cfg` | 15 | 30 |
| `golden_configs/S3/S3_20260921_195709.cfg` | 15 | 30 |
| `golden_configs/S3/S3_20261005_151122.cfg` | 15 | 30 |
| `golden_configs/S3/S3_20261005_151410.cfg` | 15 | 30 |
| `golden_configs/S3/S3_20261005_190617.cfg` | 15 | 30 |
| `golden_configs/S4/S4_20260921_164113.cfg` | 15 | 27 |
| `golden_configs/S4/S4_20260921_195709.cfg` | 15 | 27 |
| `golden_configs/S4/S4_20261005_151122.cfg` | 15 | 27 |
| `golden_configs/S4/S4_20261005_151410.cfg` | 15 | 27 |
| `golden_configs/S4/S4_20261005_190617.cfg` | 15 | 27 |
| `startup_configs/R1.cfg` | 6 | 18 |
| `startup_configs/R2.cfg` | 6 | 44 |
| `startup_configs/R3.cfg` | 6 | 18 |
| `startup_configs/R4.cfg` | 6 | 18 |
| `startup_configs/R5.cfg` | 6 | 18 |
| `startup_configs/S1.cfg` | 6 | 18 |
| `startup_configs/S2.cfg` | 6 | 18 |
| `startup_configs/S3.cfg` | 6 | 21 |
| `startup_configs/S4.cfg` | 6 | 18 |

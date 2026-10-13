# NetPilot RCN-5840 maintenance

`challenge_maintenance.py` is one terminal application for R1 and R2. It uses
the existing NSOT and enabled EOS eAPI over HTTPS, without SSH sessions or
Netmiko connections. It does not start, stop, or restart host ping processes.

## Before class

Use Python 3.11+ and the existing requirements/environment:

```bash
cd ~/Documents/NetPilot
source .venv/bin/activate
# If dependencies are missing:
python3 -m pip install -r requirements.txt
```

Device credentials now come from `security/credential_provider.py` using the
1Password CLI and the existing private token file at
`~/.config/netpilot/secrets/onepassword-token`. The invoking account must be able
to read that file and access `NetPilot-Secrets` / `NetPilot-Current`.
Legacy `NETPILOT_USERNAME` / `NETPILOT_PASSWORD` exports are no longer used by
this application. Export `INFLUX_TOKEN` for telemetry; it remains separate from
device authentication and is never read from Telegraf's configuration.
Influx URL/org/bucket and the counter measurement come
from `telegraf/telegraf-gnmi-influx.conf`; `INFLUX_URL`, `INFLUX_ORG`, and
`INFLUX_BUCKET` can override the destination. Existing verified `source`/`name`
tags and `in_octets`/`out_octets` fields are checked against fresh live data.

```bash
python3 challenge_maintenance.py status
python3 challenge_maintenance.py challenge --dry-run --insecure
python3 challenge_maintenance.py precheck R2 --insecure
python3 challenge_maintenance.py precheck R1 --insecure
```

`--insecure` explicitly accepts the lab's self-signed eAPI certificate. Omit it
when the certificate is trusted. HTTPS still encrypts the connection. Endpoints
are discovered as `https://<NSOT-management-IP>/command-api`; redirects are
rejected. API credentials must be authorized for the required read/write operations.

Precheck/dry-run read live state but make no backups, runtime records, NSOT
changes, or device changes. `status` reports recorded intent only, without
credentials or live health claims. A normal drain starts with the same precheck.

Checklist:

1. Confirm all four independent continuous H1–H4 ping windows are running and healthy.
2. Confirm both prechecks pass: six devices' eAPI reads, production interfaces,
   expected OSPFv2/v3 adjacencies, exact IPv4/IPv6 FIB routes, and fresh RX/TX counters.
3. Resolve missing/stale counters before class. The historical `query.csv` does
   **not** contain TX counters for all target production links; live completeness
   is mandatory. Zero-filling is prohibited.
4. Read R2's DHCP warning. Hosts must already have leases; the saved/live-reported
   one-day lease normally survives a short window. New leases/renewals may fail
   while R2 is isolated. DHCP is not redundant and its configuration is untouched.
5. Confirm write access to `golden_configs/`, `inventory/backups/`, and
   `runtime/maintenance/RCN-5840/`. Do not remove rollback records while a router
   is drained. Run one maintenance application at a time; its cross-process lock
   prevents concurrent challenge writers. Coordinate other automation/operators.
6. Rehearse a drain and explicit restore in a supervised lab window before class;
   dry-run does not prove that a real preference change will move traffic.

## Real challenge

```bash
python3 challenge_maintenance.py challenge --insecure
```

The application captures the original metric/cost values and their absence,
plus admin state and routing evidence. It reuses NetPilot's private, verified
pre-change Golden backup writer with the already-fetched eAPI configuration.
The existing GUI redactor removes secrets from this backup; exact rollback of
the changed settings comes from the small non-secret JSON journal.

R2 drain: keep links/protocols up; set `RIP-TO-OSPF` permit-entry metrics to
50000, `OSPF-TO-RIP` metrics to 10, and `ospfv3 cost 60000` on both NSOT production
interfaces. Every modified permit entry is captured; no route-map is replaced.

Isolation requires three distinct fresh RX/TX sample windows after convergence,
target traffic reduction, alternate activity, and FIB proof on both access and
both core peers. Exact production prefixes must be present; ECMP through the
target fails verification. IPv4 FIB and interface/OSPFv2 replies use structured
JSON; IPv6 FIB and OSPFv3 neighbors use documented EOS text replies over eAPI.
Unrecognized output fails closed.

Defaults: 11-second polling, 20-second settling, 240-second convergence timeout,
three stable samples. Each target interface must have RX+TX <=512 bit/s; the
target total must be <=10% of alternate traffic and previously active target
interfaces must fall to <=20% of baseline. Alternate traffic must remain at
least half its baseline and greater than zero. These are deliberately strict
conjunctive checks, not proof that every residual packet is control traffic.
`--samples`, `--interval`, `--settle`, `--timeout`, and `--max-target-bps` are
bounded options. Diagnose failures rather than increasing limits to hide pings.

Enter `PINGS-HEALTHY` only after inspecting all four windows. It is requested
before isolation and again after isolation. Other input, EOF, or interruption
during a change triggers rollback. The application labels customer health as
operator-reported; it does not perform independent host tests.

At **PART 1 READY**, R2 is out of service. The program waits indefinitely for
the exact `PART1-PASSED` acknowledgement. Only then does it restore R2, verify
recovery, and drain R1. At **PART 2 READY**, it exits and leaves R1 out of service.
Interrupting the Part 1 instructor wait also leaves R2 out of service; use an
explicit restore/rollback afterward. R1 is never automatically restored after
Part 2.

NSOT's consistent checkpoint value is `out_of_service`, meaning drain was
verified and both production interfaces were administratively isolated. Only
the marked maintenance block is appended/replaced. Other NSOT bytes, including
anchors, are preserved, with a backup and parsed temporary-file validation
before atomic replacement. No rapidly changing telemetry is written to NSOT.

## Explicit recovery / individual actions

```bash
python3 challenge_maintenance.py drain R2 --insecure
python3 challenge_maintenance.py restore R2 --insecure
python3 challenge_maintenance.py drain R1 --insecure
python3 challenge_maintenance.py restore R1 --insecure
python3 challenge_maintenance.py rollback R1 --insecure
python3 challenge_maintenance.py rollback R2 --insecure
```

Restore checks the alternate, brings back isolated interfaces while retaining
drain preferences, waits for health, then restores the captured preferences
(including removal when originally absent). Repeating a completed restore
verifies state without device writes. An interrupted pending operation must be
restored/rolled back before a new drain; its original snapshot is never recaptured.
After interruption at an instructor checkpoint, use the individual actions to
continue deliberately rather than restarting the challenge sequence blindly.

Before isolation, rollback restores only the preference changes. After an
isolation attempt, it restores links while drained, verifies recovery, then
restores preferences. Explicit emergency `rollback` can recover the target even
if the alternate is unhealthy. Normal restore still requires a healthy alternate.
Neither recovery action needs working Influx/token unless `--dry-run` is used.
Management/API loss or unrelated live configuration drift can prevent automatic
recovery: the program reports ERROR and retains the original rollback journal.
It never reports an unverified rollback as success. SIGKILL/host loss requires
explicit recovery after the process/management endpoint returns.

The tool does not issue `write memory`; changes are running-configuration
maintenance only. Do not reload/redeploy containers during a maintenance cycle.

## Verification and limits

```bash
python3 -B -m unittest discover -s tests -v
```

Tests use temporary inventories and fake APIs; no CI runner needs lab access.
The implementation session had no exported device credentials or Influx token,
so live endpoints, counter completeness, current route choices, TLS certificates,
and command execution on the engineering EOS build were not verified.

Saved snapshots identify EOS 4.36.2F with eAPI enabled. Syntax was checked against
the [Arista route-map reference](https://www.arista.com/en/um-eos/eos-acls-and-route-maps),
[OSPFv3 reference](https://www.arista.com/en/um-eos/eos-open-shortest-path-first-version-3),
[IPv6 FIB reference](https://www.arista.com/en/um-eos/eos-ipv6), and
[eAPI specification](https://www.arista.com/assets/data/pdf/Whitepapers/Arista_eAPI_FINAL.pdf).
The modern `ospfv3 cost` spelling is documented for this release; live read-back
accepts its equivalent legacy `ipv6 ospf cost` representation. A command rejection
stops the drain and triggers recovery; it never permits isolation.

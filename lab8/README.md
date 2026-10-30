# Lab 8 Phase 3B: permanent Day-0 accounts

R6/R7 use the existing `pilot-network` topology and a separate centralized ZTP
server. This update prepares files only: no devices, containers, credentials,
Docker networks, or host interfaces were changed.

## Addressing and device selection

| Component | Management network | Address |
| --- | --- | --- |
| Original pilot-network nodes | `clab` | Existing assignments unchanged |
| Pending R6 | `clab` | `172.20.20.30/24` |
| Pending R7 | `clab` | `172.20.20.31/24` |
| Separate ZTP server | `netpilot-ztp-infra-mgmt` | `172.31.251.2/24` |
| Isolated test R6 | `netpilot-ztp-clients-mgmt` | `172.31.252.2/24` |

The earlier IPAM inspection confirmed `clab` is `172.20.20.0/24`, gateway
`172.20.20.1`, with IPv6 subnet `3fff:172:20:20::/64`. Recheck current allocations
before a future deployment; a YAML address does not reserve a Docker IP.
R6/R7 remain `onboarding.status: pending`. Ordinary configuration changes, Golden
Config collection, GUI/health selection, default rendering, and credential
rotation retain their existing pending-device protections.

```text
server eth1 -- npztp-srv -- br-netpilot-ztp -- npztp-r6 -- R6 Ethernet1
                                         -- npztp-r7 -- R7 Ethernet1
```

The server retains bootstrap IP `10.250.0.1/24`, DHCP exclusively on `eth1`, and
HTTP bound to `10.250.0.1:80`; no host ports are published. The host-managed bridge
has no management/physical uplink. Ethernet1 stays reserved for bootstrap.

| Device | Pinned Ethernet1 MAC | DHCP Option 67 |
| --- | --- | --- |
| R6 | `aa:c1:ab:da:73:76` | `http://10.250.0.1/day0/R6.cfg` |
| R7 | `02:00:00:08:00:07` | `http://10.250.0.1/day0/R7.cfg` |

`day0-dnsmasq.conf` and both management addresses are unchanged. Unknown clients
receive no boot URL. The isolated test topology claims R6's same MAC/host endpoint;
it cannot coexist with production R6. Its management address differs, so never
serve production Day-0 to that test client. The original isolated PoC and its
minimal `/R6.cfg` remain available as references.

## Authentication and private rendering

`lab8/day0.py` reuses the existing renderer and `templates/arista_day0.j2`.
It validates both pending NSOT records before credential retrieval, obtains
`admin` through the unchanged `credential_provider.get_credentials()` integration
(`NetPilot-Secrets / NetPilot-Current`), and uses Python `getpass` to prompt once
for the **existing** `netpilot-recovery` password without echo. Admin retrieval
remains automatic; the recovery prompt needs no secret reference or Personal
Vault access by the service account.
Run rendering in an interactive terminal. An empty or interrupted recovery
prompt, or inability to disable echo, aborts rendering safely. Passwords remain
in memory and are never printed or saved as plaintext. No passwords or Vault
records are created or modified. Offline tests use only fake credentials.

The existing `setup_recovery_accounts.sha512_crypt()` helper uses local OpenSSL,
with plaintext on captured subprocess stdin, to generate salted `$6$` hashes.
Both accounts receive `privilege 15 role network-admin secret sha512`:
`admin` and `netpilot-recovery`. Their passwords must differ, preserving the
existing recovery-setup contract. Missing credentials or invalid hashes stop
rendering before either configuration is written; error messages omit secrets.

The temporary account, restricted role, key-based handover script, and public-key
NSOT fields are removed from the new workflow. Existing SSH/AAA, hostname,
Management0, SNMP source interface, gNMI's current no-SSL convention, and HTTPS-only
eAPI settings are preserved. No OSPF, RIP, BGP, business interfaces, VLANs, or
routing policies are added. SNMP communities remain excluded: authenticated SNMP
configuration must still use the existing secure management procedure separately.
NTP remains omitted because no valid server setting exists in the NSOT.

## Restricted runtime and short HTTP window

Real configurations are generated only under ignored `runtime/lab8-ztp/private/`.
Directories are `0700`, files `0600`; unsafe permissions, symlinks, and existing
outputs are rejected. The generic `render_configs.py R6` command fails closed
without hashes, preventing accidental output to ordinary generated-config paths.
Never print/cat these configurations, include them in Git, or attach them to logs.

`publish` copies the complete pair into `runtime/lab8-ztp/http/`, then writes an
expiry marker **last**. The updated Python HTTP handler serves only the exact
Day-0 URLs while the marker is valid (default 300 seconds, maximum 600). It checks
every GET/HEAD, denies directory listings, and sends `Cache-Control: no-store`.
Absent/expired markers return 404 even if a client or publisher crashes. `clear`
removes the marker first, then both private and published configs, preserving
unrelated files and the mount directories. Run these operations serially.

Hash-bearing configs travel over the isolated bootstrap HTTP link during the
window. Any participant on that segment can request them during that time; MAC
selection is DHCP routing, not HTTP authentication. Expiry cannot revoke copies
already downloaded or stop an already accepted transfer. Clear immediately after
successful installation. Saved device flash also contains hashes and must stay
outside Git and HTTP. No router reset or reprovisioning is performed by this tool.

## Existing live server and future activation

Read-only inspection found the running server still mounts `lab8/day0-staged/`
at `/srv/ztp/day0` and `day0-dnsmasq.conf` at `/etc/dnsmasq.conf`. The old staged
public-key configs are deliberately untouched to avoid changing live-mounted
content. They are now ignored and are not inputs or outputs of the new workflow.
The previous temporary private key is also untouched and no longer needed by it.

The prepared infrastructure YAML now uses image
`netpilot-lab8-ztp:gui` and mounts
`runtime/lab8-ztp/http/` read-only at `/srv/ztp/day0`. Build under this new tag to
preserve the working `phase1` image. **Do not publish real hashes until this updated
HTTP handler and the new runtime mount are active and verified.** Editing YAML
alone does not update a running container. The image's original minimal `/R6.cfg`
contains no credentials and remains independently available.

The current infrastructure also mounts `/var/lib/netpilot-ztp/dhcp` read-only at
`/srv/ztp-dhcp` for future per-device DHCP additions. Before the following server
activation commands, prepare that directory and its `hosts`/`options` files with
the permissions shown in [GUI-ZTP.md](GUI-ZTP.md). Existing R6/R7 CLI rendering,
publication and DHCP selections remain supported.

The following are future manual commands, not actions performed by this change.
Run from `/home/student/Documents/NetPilot` as the regular repository owner:

```bash
install -d -m 700 runtime/lab8-ztp runtime/lab8-ztp/private runtime/lab8-ztp/http
sudo docker build -t netpilot-lab8-ztp:gui lab8/ztp-server
sudo env CLAB_VERSION_CHECK=disable containerlab deploy -t lab8/ztp-infra.clab.yml --dry-run
```

Review the plan before applying: only the separate ZTP server and its bootstrap
endpoint may be affected. Activating its changed image/mount replaces that server;
do it outside any ongoing provisioning. Do not apply changes to `pilot-network`:

```bash
sudo env CLAB_VERSION_CHECK=disable containerlab deploy -t lab8/ztp-infra.clab.yml
sudo ./lab8/connect-bootstrap.sh
sudo docker inspect clab-netpilot-ztp-infra-ztp-server --format '{{.Config.Image}} {{range .Mounts}}{{.Source}} -> {{.Destination}} {{end}}'
sudo docker logs clab-netpilot-ztp-infra-ztp-server
```

Require the new image tag and runtime HTTP bind, DHCP initialization, and HTTP
listening on the bootstrap address. Run the HEAD-only Python check shown below
**before rendering or publishing**, and require 404 for both URLs; repeat it after
cleanup. Image/mount inspection is still required because an empty old server can
also return 404. Only after confirming the old staged directory
is no longer mounted may its obsolete configs be removed manually. No changes to
those old files are required to use the new runtime directory.

## Later manual ZTP verification

Run `render` in an interactive terminal and enter the existing recovery password
at its hidden prompt. The admin password is retrieved automatically. Do not put
either password in arguments or pipe it into the command. Do not use sudo for the
Python commands; the provider uses the current user's existing token.

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m lab8.day0 render
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m lab8.day0 publish --seconds 300
sudo docker logs -f clab-netpilot-ztp-infra-ztp-server
```

For devices already in native ZTP, require each pinned MAC to receive its own URL
and HTTP 200 for `/day0/R6.cfg` and `/day0/R7.cfg`. Stop following logs with Ctrl-C.
If R6/R7 already have startup-config, they will not automatically fetch new Day-0;
stop and plan any reprovisioning separately. These commands do not reset them.
After both successful downloads/installations, revoke availability immediately:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m lab8.day0 clear
sudo docker exec clab-netpilot-ztp-infra-ztp-server python3 -c 'import urllib.request, urllib.error
for name in ("R6", "R7"):
    try:
        with urllib.request.urlopen(urllib.request.Request("http://10.250.0.1/day0/" + name + ".cfg", method="HEAD"), timeout=5) as response:
            print(name, response.status)
    except urllib.error.HTTPError as error:
        print(name, error.code)'
sudo docker exec clab-pilot-network-R6 Cli -p 15 -c 'show hostname'
sudo docker exec clab-pilot-network-R6 Cli -p 15 -c 'show ip interface brief'
sudo docker exec clab-pilot-network-R7 Cli -p 15 -c 'show hostname'
sudo docker exec clab-pilot-network-R7 Cli -p 15 -c 'show ip interface brief'
```

Require **404 for both URLs**, correct hostnames, and Management0 `.30/24`/`.31/24`.
Establish SSH host-key trust using public host keys obtained from the trusted
console; never disable host-key checking or blindly trust `ssh-keyscan`. Then test
both accounts against both routers, entering existing passwords only at SSH's
hidden prompt (never in command arguments). For example:

```bash
ssh -o StrictHostKeyChecking=yes -o PreferredAuthentications=password -o PubkeyAuthentication=no admin@172.20.20.30 'show privilege'
ssh -o StrictHostKeyChecking=yes -o PreferredAuthentications=password -o PubkeyAuthentication=no netpilot-recovery@172.20.20.30 'show privilege'
ssh -o StrictHostKeyChecking=yes -o PreferredAuthentications=password -o PubkeyAuthentication=no admin@172.20.20.31 'show privilege'
ssh -o StrictHostKeyChecking=yes -o PreferredAuthentications=password -o PubkeyAuthentication=no netpilot-recovery@172.20.20.31 'show privilege'
```

Verify privilege 15 and the existing SSH/gNMI/eAPI services without displaying full
running/startup configs. Keep both records pending until explicit operational
verification and fleet enrollment. Runtime EOS acceptance and login are manual
checks; offline tests do not establish live authentication success.

## Topology migration, if still needed

Retain `ztp-clients.clab.yml` for isolated tests. Before introducing production R6,
remove only that temporary client lab; do not destroy the central server:

```bash
sudo env CLAB_VERSION_CHECK=disable containerlab destroy -t lab8/ztp-clients.clab.yml
ip link show dev npztp-r6
ip link show dev npztp-srv
```

Require `npztp-r6` absent and the server endpoint intact. Without `--cleanup`, the
test client's flash is retained. Do not copy its startup-config into the final
lab: `suppress-startup-config` does not erase existing flash or force native ZTP.
Never erase `clab-pilot-network` to reset only R6/R7.

Containerlab 0.79.0 reconciles existing labs; an ordinary deployment can recreate
changed nodes, remove omitted definitions, and execute existing host commands.
Do not deploy the main topology as part of this authentication change. A separate
future migration must review the complete topology dry-run and permit only new
R6/R7 nodes/links. Preserve all original nodes/links, avoid `--reconfigure` and
`destroy --all`, and account for cEOS post-deploy management/save actions racing
ZTP (`--skip-post-deploy` was used in the original migration plan).

## Offline checks

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests -p 'test_day0_*.py' -v
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests -p 'test_ztp_http.py' -v
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests -p 'test_credential_provider.py' -v
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests -p 'test_pending_onboarding.py' -v
dnsmasq --test --conf-file=lab8/day0-dnsmasq.conf
```

Tests use fake credentials and temporary directories; real rendering, inventory
validation, permissions, expiry decisions, and cleanup run offline. The obsolete
temporary-account tests were replaced with permanent-account behavior tests.

References: [EOS user security](https://www.arista.com/en/um-eos/eos-user-security),
[Containerlab deployment](https://containerlab.dev/cmd/deploy/).

## GUI ZTP extension and live state

The existing Add Device page now offers optional **Provision with ZTP**, with
automatic management allocation, a reviewed hostname/IP, one masked recovery
password input and per-device progress. Devices pages keep intended inventory
separate from read-only live protocol observations. See
[GUI-ZTP.md](GUI-ZTP.md) for the one-time restricted helper/server setup and the
manual R8 verification steps. This extension does not replace the CLI workflow,
change existing device definitions, or enroll new devices in fleet operations.

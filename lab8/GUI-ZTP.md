# GUI onboarding and observed device state

The existing **Add Device** page retains inventory-only registration. Its optional
**Provision with ZTP** mode adds one Arista cEOS device to `pilot-network`, using
the existing `clab` management network, centralized DHCP/HTTP server and bootstrap
bridge. Existing devices, business links and routing configurations are preserved.

The commands below are manual setup instructions. None are run by installing or
importing the Python modules. Do not run a main-topology deployment, reset a
router, or remove any existing containers to enable this feature.

## One-time administrator setup

Use the existing `student` account and repository path below. The Flask process
must remain an ordinary user process with its existing 1Password provider access.
Do not add it to the Docker group or grant it unrestricted sudo, Docker, shell,
Python or Containerlab permissions. Only the installed helper is allowed through
sudo; it accepts no command-line arguments and validates its small JSON request.

The helper requires the reviewed **Containerlab 0.79.0** reconciliation format.
It refuses other versions. First check the installed version:

```bash
cd /home/student/Documents/NetPilot
containerlab version --short
```

### Install the approved topology and real saved state

Use the existing `.nettopo-lab8-safe.clab.yml` as the approved baseline. It retains
the running node definitions that avoid the historical H1–H4/web-server `exec`
drift. The separate state input must come from the actual running lab's
`clab-pilot-network/.state.clab.yaml`; do not construct replacement state from the
topology YAML. Containerlab's saved state contains resolved endpoint forms used
for reconciliation.

The following exports are offline and contain no password retrieval. Run them as
`student`, then have an administrator install the resulting files:

```bash
umask 077
LAB8_SETUP_DIR=$(mktemp -d)
export LAB8_SETUP_DIR
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python - <<'PY'
import json
import os
from pathlib import Path
import yaml

destination = Path(os.environ['LAB8_SETUP_DIR'])
baseline = yaml.safe_load(Path('.nettopo-lab8-safe.clab.yml').read_text())
state = yaml.safe_load(Path('clab-pilot-network/.state.clab.yaml').read_text())
if (baseline.get('name') != 'pilot-network'
        or baseline.get('mgmt', {}).get('network') != 'clab'
        or baseline.get('mgmt', {}).get('ipv4-subnet') != '172.20.20.0/24'
        or baseline.get('topology', {}).get('nodes') != state.get('topology', {}).get('nodes')):
    raise SystemExit('Stop: approved topology and actual saved node state do not match.')
for name, value in (('ztp-baseline.json', baseline), ('ztp-baseline-state.json', state)):
    path = destination / name
    path.write_text(json.dumps(value) + '\n')
    path.chmod(0o600)
print('Prepared baseline and real state for administrator installation.')
PY

sudo install -d -o root -g root -m 0755 /etc/netpilot /usr/local/libexec
sudo install -o root -g root -m 0600 "$LAB8_SETUP_DIR/ztp-baseline.json" /etc/netpilot/ztp-baseline.json
sudo install -o root -g root -m 0600 "$LAB8_SETUP_DIR/ztp-baseline-state.json" /etc/netpilot/ztp-baseline-state.json
sudo install -o root -g root -m 0755 lab8/ztp_privileged.py /usr/local/libexec/netpilot-ztp-helper
sudo install -d -o root -g root -m 0700 /var/lib/netpilot-ztp
sudo install -d -o root -g root -m 0755 /var/lib/netpilot-ztp/dhcp
sudo touch /var/lib/netpilot-ztp/dhcp/hosts /var/lib/netpilot-ztp/dhcp/options
sudo chown root:root /var/lib/netpilot-ztp/dhcp/hosts /var/lib/netpilot-ztp/dhcp/options
sudo chmod 0644 /var/lib/netpilot-ztp/dhcp/hosts /var/lib/netpilot-ztp/dhcp/options
```

Stop if the export check fails. Review the safe candidate against actual state;
do not remove the check or alter running containers to make it pass. These are
first-install instructions: preserve existing `/var/lib/netpilot-ztp` ownership
records, approved additions and router flash on subsequent updates. `touch`
preserves any existing dynamic DHCP mappings.

The installed helper is standalone and starts with `#!/usr/bin/python3 -I`.
It imports only the Python standard library, uses fixed executable paths, and
does not execute a writable project module as root. After future helper changes,
an administrator must explicitly reinstall its reviewed root-owned copy.

### Allow only the installed helper

Still in the same shell, create and validate this narrowly scoped sudoers entry:

```bash
printf '%s\n' 'student ALL=(root) NOPASSWD: /usr/local/libexec/netpilot-ztp-helper ""' > "$LAB8_SETUP_DIR/netpilot-ztp"
sudo visudo -cf "$LAB8_SETUP_DIR/netpilot-ztp"
sudo install -o root -g root -m 0440 "$LAB8_SETUP_DIR/netpilot-ztp" /etc/sudoers.d/netpilot-ztp
sudo visudo -cf /etc/sudoers
rm -r -- "$LAB8_SETUP_DIR"
unset LAB8_SETUP_DIR
```

Install the entry only after `visudo` reports valid syntax. The final `""`
requires zero command-line arguments; it is part of the rule. No other privilege
grant is required by the Flask process.

### Activate the separate ZTP server once

The updated image adds dynamic DHCP hosts/options files and per-device HTTP
expiry markers. The original R6/R7 commands and MAC mappings still work. The
server continues to bind DHCP to bootstrap `eth1` and HTTP to `10.250.0.1:80`,
without Docker host-port publishing.

Prepare runtime directories as `student`, build the new image, and inspect the
**infrastructure-only** dry-run while no provisioning is in progress:

```bash
install -d -m 0700 runtime/lab8-ztp runtime/lab8-ztp/private runtime/lab8-ztp/http
sudo docker build -t netpilot-lab8-ztp:gui lab8/ztp-server
sudo env CLAB_VERSION_CHECK=disable containerlab deploy -t lab8/ztp-infra.clab.yml --dry-run
```

Require the plan to affect only `clab-netpilot-ztp-infra-ztp-server` and its own
bootstrap endpoint. A changed image or bind mount can replace that separate
server; this is the one-time infrastructure activation, not part of each device
onboarding. Review before applying:

```bash
sudo env CLAB_VERSION_CHECK=disable containerlab deploy -t lab8/ztp-infra.clab.yml
sudo ./lab8/connect-bootstrap.sh
sudo docker inspect clab-netpilot-ztp-infra-ztp-server --format '{{.Config.Image}} {{range .Mounts}}{{.Source}} -> {{.Destination}} (RW={{.RW}}) {{end}}'
sudo docker logs clab-netpilot-ztp-infra-ztp-server
printf '%s\n' '{"action":"snapshot"}' | sudo -n /usr/local/libexec/netpilot-ztp-helper
```

Verify image `netpilot-lab8-ztp:gui`, both read-only directory binds
`runtime/lab8-ztp/http` → `/srv/ztp/day0` and
`/var/lib/netpilot-ztp/dhcp` → `/srv/ztp-dhcp`, and the existing dnsmasq config
bind. The snapshot must report `server_ready: true`. The helper checks the
existing bridge and `npztp-srv` attachment; it does not create the bridge or
restart the server. Per-device additions reread the dynamic DHCP files with
dnsmasq's HUP signal, without restarting its container.
The [EOS 4.36.2F ZTP procedure](https://www.arista.com/en/um-eos/eos-system-reset)
specifies that EOS requests DHCP options 66 and 67 after receiving an offer;
the dynamic tagged option 67 therefore supplies the device's full configuration
URL. The existing forced R6/R7 option mappings remain unchanged.

Do not publish hashes to an older image or mount. Preserve the original PoC,
isolated client topology, existing R6/R7 flash and running network.

## Open the GUI and onboard R8 manually

Use the existing Flask launch procedure, or run this from the repository as
`student` when another GUI process is not already using port 5000:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python app.py
```

Open **http://127.0.0.1:5000/devices/add** in the VM browser. Remote access must use
an SSH tunnel, for example `ssh -L 5000:127.0.0.1:5000 student@VM_HOST`, then open
the same localhost URL. New privileged and live-refresh routes require a real
loopback client and a localhost Host header; forwarded headers do not bypass
that restriction. Keep the existing local application/session security model.

1. Select **Provision with ZTP**, enter `R8`, and leave platform **Arista cEOS**.
2. Select **Review hostname & assigned IP**. Review the automatically allocated
   address in `172.20.20.0/24`. Inventory, topology, Docker/IPAM and previous
   attempts are checked; names are compared case-insensitively.
3. Enter the **existing recovery password** once in the masked field. Admin
   credentials come automatically from the existing NetPilot-Current provider.
   No terminal `getpass`, new credentials, or 1Password writes are involved.
4. Select **Create & Provision** once. The status page shows Preparing, Deploying,
   Waiting for ZTP, then Ready or Failed. Keep the Flask process running until
   completion. Do not run manual Containerlab/Docker changes concurrently.
5. At **Ready**, open the device. Admin SSH, exact running/startup hostname,
   Management0 address and permanent-account configuration were verified before
   inventory registration. The registration remains pending explicit fleet
   enrollment, preserving configuration/Golden protections and the existing
   nine-device rotation selection. Ready does not silently enroll a new target
   into password rotation or monitoring services.

Only the new cEOS node and its bootstrap host link are added to `nettopo.clab.yml`.
No production link, OSPF/RIP/BGP process or business interface is generated. The
new MAC/host-endpoint identity is deterministic, validated against collisions,
and maps to `http://10.250.0.1/day0/R8.cfg`. Assigned management addressing is
shared by the topology, rendered Management0 configuration and final inventory.

Before each incremental apply, the helper builds a root-owned reconciliation
candidate from the approved safe baseline plus owned additions and checks the
actual JSON dry-run. It rejects removals, restarts, recreations, unexpected node
starts and unrelated link changes. Containerlab 0.79.0 does not support
`--node-filter` for an already deployed lab; this workflow instead admits only a
plan adding the requested node/link, uses `--skip-post-deploy`, and never uses
`destroy` or `--reconfigure`. Do not independently deploy the writable main
topology: its historical `exec` drift remains intact for backward compatibility.

New GUI-created router flash is under the helper's root-owned
`/var/lib/netpilot-ztp/clab-pilot-network/` directory. Existing devices keep their
original flash mounts unchanged. Preserve both locations; deleting helper state
is not a retry mechanism. After intentional topology changes outside this
workflow, an administrator must review any stale approved baseline before more
GUI onboarding; an unsafe reconciliation is rejected rather than repaired by
replacing existing nodes.

## Publication, failures and retries

Passwords stay in memory and are not included in jobs, sessions, command-line
arguments, logs or GUI responses. Configurations contain sensitive SHA-512 crypt
hashes, kept only in ignored `0700` runtime directories and `0600` files. The GUI
publishes one device for 300 seconds using its own expiry marker; the server
returns 404 after expiry. Cleanup revokes that device's marker first and removes
only its public/private files. It leaves other onboarding files untouched.

Bootstrap HTTP is isolated but unauthenticated: participants on that segment can
download a configuration during its short window. Expiry cannot revoke copies
already downloaded. GUI cleanup runs after success or failure; if the Flask
process is interrupted, server-enforced expiry still closes the URL. Retained
private files are removed when retrying the same attempt, or can be revoked
manually for a known device using the existing code:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -c "from lab8.day0 import clear_one; clear_one('R8')"
```

A failed attempt remains visible and does not claim successful registration.
Use **Retry this device** from that attempt and enter the existing recovery
password again. Retry accepts only the same owned container identity and never
resets, destroys or recreates it. A saved startup-config is preserved. If its
address, identity or configuration no longer matches, resolve the reported
problem manually; the GUI will not overwrite another device or clear flash.
Do not create a second job for the same hostname to bypass ownership checks.

Optional read-only verification after a manual attempt:

```bash
sudo docker logs --tail 100 clab-netpilot-ztp-infra-ztp-server
sudo docker exec clab-pilot-network-R8 Cli -p 15 -c 'show hostname'
sudo docker exec clab-pilot-network-R8 Cli -p 15 -c 'show ip interface brief'
```

Look for the device's DHCP selection, its own HTTP URL and Management0's reviewed
address. Do not print full startup/running configurations or hash-bearing runtime
files. Never reset existing R6/R7 as part of testing this feature.

## Intended and observed state

Devices and device details retain the original inventory protocol badges under
**Intended / Inventory State**. **Live / Observed State** reads EOS configuration
over the existing SSH/provider integration, recognizes OSPFv2, OSPFv3, RIP and
BGP including interface settings, and shows management reachability and the last
successful refresh. Thus existing R6/R7 can display configured OSPF/RIP without
changing inventory or recreating devices.

Page-load JavaScript refreshes devices sequentially with a 30-second cache;
**Refresh Live** requests a new observation. Unreachable or invalid responses
show **Live status unavailable**, not an empty protocol list. These are
configuration observations, not neighbor/session health claims. No running data
is written back into NSOT. Protected transport operations serialize briefly to
prevent concurrent requests from exposing transport debug logs.

The original CLI `python -m lab8.day0 render`, `publish --seconds 300` and `clear`
remain available for R6/R7 as documented in [README.md](README.md). Do not run a
second publication or independent provisioning operation for the same device
while the GUI is managing it.

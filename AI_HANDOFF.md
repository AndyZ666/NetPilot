# NetPilot AI Handoff

## 1. Project Purpose

NetPilot is a university Network Automation / Infrastructure-as-Code project. It automates an Arista cEOS Containerlab network using a network Source of Truth (NSOT), Jinja2 configuration templates, generated configurations, live Golden Config backups, and a Flask web GUI.

The main lab is the `pilot-network` Containerlab topology with Arista cEOS routers and switches, dual-stack routing, and management access on the Containerlab out-of-band network.

## 2. Current Architecture

The current project is organized around this workflow:

```text
Git/GitHub
    -> GitHub Actions
    -> inventory/devices.yml as NSOT
    -> root Jinja2 templates
    -> generated configurations
    -> live device Golden Config backups
    -> Flask Web GUI
    -> existing Grafana monitoring
    -> existing NetworkX topology
```

The first six stages are connected in the current Flask application. Grafana/InfluxDB monitoring and NetworkX topology tooling exist as separate project tools, but their visualizations are not yet connected to the Flask pages.

## 3. Current Project Structure

Important files and directories:

```text
app.py                         Flask application and GUI/backend integration
render_configs.py              Jinja2 renderer for one or all NSOT devices
save_golden_configs.py         Netmiko live running-config capture
requirements.txt               Declared Python dependencies
README.md                      Project overview and older status notes

inventory/
  devices.yml                  Authoritative Network Source of Truth
  backups/                     Timestamped pre-change NSOT backups created by Add Device

templates/
  arista_ceos.j2               Network configuration Jinja2 template

generated_configs/             Rendered desired configurations, one .cfg per device
golden_configs/                Timestamped live running-config snapshots, by device

golden-v1/                     Older baseline Containerlab/topology and startup-config material

web/
  templates/                   Flask HTML templates
  static/                      Flask CSS and static assets

Functions/                     Standalone network, gNMI, NETCONF, SNMP, monitoring,
                               connectivity, and NetworkX topology utilities
telegraf/                      Telegraf configuration variants for gNMI/InfluxDB telemetry
tests/                         Fixture-only Flask configuration/Golden Config integration tests
.github/workflows/
  netpilot-ci.yml              GitHub Actions validation workflow
nettopo.clab.yml               Current Containerlab topology definition
clab-pilot-network/            Containerlab-generated/runtime lab material; do not treat as NSOT
```

Runtime directories such as `.venv`, `__pycache__`, and Containerlab state/data are intentionally omitted from this handoff structure.

## 4. Completed Phases

### Phase 1: GitHub + GitHub Actions

**Status: implemented.** `.github/workflows/netpilot-ci.yml` runs on pushes and pull requests targeting `main`. It checks out the repository, uses Python 3.13, installs `requirements.txt`, compiles Python files, parses YAML and JSON files, and runs `python render_configs.py` to validate Jinja2 rendering.

**Limitation:** CI is validation-only. It does not deploy configurations to devices, run the live Golden Config workflow, start Containerlab, or validate Grafana/InfluxDB.

### Phase 2: Network Source of Truth

**Status: implemented.** `inventory/devices.yml` is the central NSOT and is consumed by rendering, Golden Config capture, and Flask pages. `app.py` reads it into an ephemeral display model and validates its structure before configuration operations.

**Limitation:** The current NSOT is a YAML file rather than a remote inventory service. It currently contains three temporary test records (`TEST-R10`, `Test-S4`, and `Test-R11`) in addition to the nine cEOS lab devices.

### Phase 3: Jinja2 Configuration Templating

**Status: implemented for Arista cEOS.** `templates/arista_ceos.j2` renders hostname, VLANs, interfaces, IPv4/IPv6 addressing, OSPFv2, OSPFv3, RIPv2, BGP, redistribution, prefix lists, and route maps from the NSOT.

**How it works:** `render_configs.py` loads the YAML NSOT, selects each device's template or the network default, uses a strict Jinja2 environment, and writes `<hostname>.cfg` under `generated_configs/`.

**Limitation:** Only the Arista cEOS template is currently supported/allowlisted by the Add Device GUI. There is no implemented multi-vendor template.

### Phase 4: Golden Config Automation

**Status: implemented.** `save_golden_configs.py` connects to live devices with Netmiko, enters privileged mode, retrieves `show running-config`, validates the response, and writes timestamped snapshots under `golden_configs/<hostname>/` using a temporary file followed by replacement.

**Limitation:** It requires reachable live devices and environment-provided credentials. Test devices in the NSOT may fail because they are not necessarily present in the live Containerlab network.

### Phase 5A: Flask Dashboard

**Status: implemented.** `app.py` and `web/templates/dashboard.html` provide `/`. Dashboard statistics are calculated from the NSOT: device count, router count, switch count, vendor count, and available network template count.

**Limitation:** The dashboard reports availability/status from local files; it is not a live telemetry dashboard.

### Phase 5B: Devices List + Device Details

**Status: implemented.** `/devices` lists normalized NSOT records. `/devices/<hostname>` shows one normalized device or a 404 page. The display model includes role, vendor/platform, management addressing, routing protocol flags, interfaces, VLANs, BGP, redistribution, prefix lists, and route maps where present.

**Limitation:** These pages display NSOT intent and do not poll live device state.

### Phase 5C: Add Device + Validation + NSOT Backup

**Status: implemented.** `/devices/add` accepts a new device registration. `app.py` validates hostname uniqueness, IPv4 uniqueness/format, role, Arista/cEOS/template choices, routing protocol fields, and CSRF tokens. It writes only a device intent record; it does not configure a device. Before an atomic inventory update it creates an exact timestamped backup in `inventory/backups/devices_YYYYMMDD_HHMMSS.yml`.

**Implementation details:** The update is serialized with process/thread locking, YAML duplicate-key checks, temporary-file validation, and atomic replacement. The form redirects to the new device detail page after success.

**Limitation:** Add Device does not automatically render, deploy, or Golden-Config a new device. It also does not make a test record appear in Containerlab.

### Phase 5D: Configuration Management GUI + Golden Config GUI

**Status: implemented.** `/configuration` invokes the existing `render_configs.py` backend through a controlled subprocess and displays generated files from `generated_configs/`. `/golden-configs` invokes the existing `save_golden_configs.py` backend and displays timestamped snapshots from `golden_configs/`.

The GUI supports one-device and all-device operations, CSRF protection, operation locking, timeout handling, partial-success reporting, safe output-path validation, and redaction of sensitive configuration lines before browser display. `tests/test_configuration_gui.py` uses fixtures/mocks and never contacts devices.

**Limitation:** Configuration generation creates files only; it does not deploy generated configuration to live devices. Golden Config capture does connect to devices and can fail for NSOT-only test records or unavailable credentials/devices.

### Phase 5E: Monitoring Status

**Status: standalone monitoring exists; Flask integration is not complete.** The repository has Telegraf configurations, gNMI configuration/audit tooling, InfluxDB status queries, SNMP tooling, and read-only network status checks. The Flask `/monitoring` route currently renders the generic dashboard placeholder and does not query or embed Grafana/InfluxDB data.

## 5. Flask GUI

Routes currently defined in `app.py`:

| Route | Page | Status | Current behavior |
|---|---|---|---|
| `/` | Dashboard | Complete | Shows NSOT-derived summary statistics and local availability indicators. |
| `/devices` | Devices | Complete | Lists normalized devices from `inventory/devices.yml`. |
| `/devices/<hostname>` | Device Details | Complete | Shows one normalized NSOT record; unknown host returns 404. |
| `/devices/add` GET/POST | Add Device | Complete | Validates and safely registers intent in NSOT, creates a backup, then redirects. |
| `/configuration` GET/POST | Configuration | Complete | Generates one/all desired configs through `render_configs.py` and displays redacted output. |
| `/golden-configs` GET/POST | Golden Configs | Complete | Captures one/all live configs through `save_golden_configs.py` and lists snapshots. |
| `/golden-configs/<hostname>/<filename>` | Golden Config Snapshot | Complete | Displays a validated, redacted snapshot file. |
| `/monitoring` | Monitoring | Placeholder | Generic "connected in a later phase" page; no telemetry integration. |
| `/topology` | Topology | Placeholder | Generic "connected in a later phase" page; no NetworkX visualization integration. |

The Flask app uses `web/templates/` for HTML and `web/static/` for CSS/assets. The navigation exposes all eight page areas, including the two placeholder pages.

## 6. NSOT

`inventory/devices.yml` is the single Source of Truth. It has top-level metadata, network defaults and management services, routing domains, and a `devices` mapping.

At a high level, the real schema contains:

- Metadata such as schema version, lab name, topology file, purpose, and collection notes.
- Network management addressing and default Arista/cEOS platform/template values.
- Management service intent for SSH, NETCONF, gNMI, and SNMP.
- Routing domains for OSPFv2, OSPFv3, RIPv2, and BGP.
- Per-device hostname, role, vendor, platform, software version, management addresses, template, interface records, routing settings, redistribution, policy objects, and VLANs.

The current real lab uses Arista cEOS devices: `R1` through `R5` and `S1` through `S4`. The inventory also currently contains `TEST-R10`, `Test-S4`, and `Test-R11`; these are test registrations and may not exist in the live Containerlab network.

Add Device validates against the existing mapping, builds a device intent record with empty interface/policy/VLAN structures as appropriate, creates a timestamped exact pre-change backup in `inventory/backups/`, and atomically updates `inventory/devices.yml`. It does not configure a live device.

No credentials or secret values are part of the NSOT handoff description.

## 7. Configuration Generation

`templates/arista_ceos.j2` is the current network Jinja2 template. It expects the device, network defaults, routing domains, and metadata structures supplied by the NSOT.

`render_configs.py` loads `inventory/devices.yml`, creates a strict `FileSystemLoader` for `templates/`, and writes desired configurations to `generated_configs/`. A positional device renders one device; omitting it renders every key under `devices`.

Valid commands from the repository root:

```bash
python3 render_configs.py R1
python3 render_configs.py
```

Optional overrides remain available:

```bash
python3 render_configs.py R1 --inventory inventory/devices.yml \
  --template-dir templates --output-dir generated_configs
```

Generated configuration is not automatically deployed to devices.

## 8. Golden Config

`save_golden_configs.py` reads `inventory/devices.yml`, gets `NETPILOT_USERNAME` and `NETPILOT_PASSWORD` from the environment, connects with Netmiko using the device management IPv4 address, retrieves and validates the live running configuration, and saves a timestamped file under `golden_configs/<hostname>/`.

`golden-v1/` is the older baseline containing the earlier Containerlab topology/startup-config material. `golden_configs/` is the current snapshot store and contains timestamped `.cfg` files grouped by device.

Valid commands:

```bash
export NETPILOT_USERNAME='...'
export NETPILOT_PASSWORD='...'
python3 save_golden_configs.py R1
python3 save_golden_configs.py R1 R2 R3
python3 save_golden_configs.py
```

The commands above show placeholders only; this handoff intentionally contains no credential values. The script reports per-device failures and does not save a snapshot when the returned configuration fails validation.

## 9. GUI Configuration + Golden Config Integration

The Flask GUI reuses the existing backend scripts rather than duplicating their rendering or connection logic. `app.py` starts `render_configs.py` or `save_golden_configs.py` with a list-based `subprocess.run` call, no shell, and validates that a newly written expected output file exists before reporting success.

The GUI supports single-device and all-device actions. It handles timeouts, missing credentials, invalid/unknown device names, stale output, filesystem safety checks, partial success, and generic error messages that do not expose backend diagnostics or secrets. Fake/test devices can remain in the NSOT for rendering, but Golden Config capture will fail if they are not live/reachable.

## 10. Monitoring

The existing monitoring stack is:

```text
Arista cEOS gNMI -> Telegraf -> InfluxDB -> Grafana
```

Relevant current artifacts include `telegraf/telegraf-gnmi-influx.conf`, other Telegraf variants, `Functions/configure_gnmi.py`, `Functions/test_influx_status.py`, and SNMP-related utilities under `Functions/`.

The current Flask integration is exactly the `/monitoring` route rendering a placeholder description. Flask does not currently query InfluxDB, embed Grafana, show interface status, or expose telemetry charts. The next work is integration of the existing monitoring stack into that page; the monitoring design itself should not be redesigned.

## 11. Topology

`Functions/realtime_topology_static.py` parses a Containerlab YAML topology into a NetworkX graph, prints nodes/links, and saves a static Matplotlib image. `Functions/realtime_topology.py` builds a NetworkX graph from Containerlab topology, normalizes interface names, reads device mapping data, and uses InfluxDB interface telemetry to determine link status for a continuously refreshed visualization.

The current Flask `/topology` page does not call either implementation and only renders a placeholder. Existing topology visualization still needs to be integrated into the Flask GUI, with its current data sources and behavior preserved.

## 12. GitHub Actions

The only workflow currently present is `.github/workflows/netpilot-ci.yml`, named `NetPilot CI`. It runs on `main` pushes and pull requests.

It currently validates:

- Python syntax with `python -m compileall -q .`.
- YAML parsing with PyYAML across repository YAML files.
- Jinja2 rendering by running `python render_configs.py`.
- JSON parsing across repository JSON files.

It does not validate live device connectivity, Containerlab startup, Golden Config capture, InfluxDB, Grafana, or Flask browser behavior.

## 13. Dependencies

`requirements.txt` currently declares:

- `PyYAML>=6.0`: parse and validate the NSOT and other YAML files.
- `Jinja2>=3.1`: render network device configurations.
- `netmiko`: SSH access to Arista devices for live Golden Config capture and related automation.
- `Flask>=3.1,<4.0`: web application and GUI routes/templates.

The standalone `Functions/` tooling also imports packages such as `networkx`, `matplotlib`, and `influxdb_client` in the current source tree. They are not declared in the four-line root `requirements.txt`; install/CI coverage for those standalone tools is therefore separate from the current Flask/renderer dependency set. Some scripts also document optional `ncclient` requirements for NETCONF.

## 14. Important Design Decisions

- `inventory/devices.yml` remains the single NSOT.
- Do not create duplicate inventories.
- Flask should reuse existing backend scripts rather than rewrite them.
- Root `templates/` contains network Jinja2 templates.
- `web/templates/` contains Flask HTML templates.
- Add Device registers intent in the NSOT but does not configure a live device.
- Generated configuration does not automatically deploy to devices.
- Golden Config does connect to live devices.
- Credentials must not be hardcoded.
- Test devices may exist in the NSOT but may not exist in the live Containerlab network.

## 15. Files That Should Not Be Changed Without Good Reason

The following are stable completed backend surfaces and should be reused rather than rewritten unnecessarily:

- `app.py`, especially NSOT validation/backup logic and the configuration/Golden Config subprocess integration.
- `render_configs.py`.
- `save_golden_configs.py`.
- `inventory/devices.yml` schema and `inventory/backups/` behavior.
- `templates/arista_ceos.j2`.
- `.github/workflows/netpilot-ci.yml`.
- `tests/test_configuration_gui.py` safety/integration fixtures.

Changes to `app.py` are appropriate when wiring the unfinished Monitoring or Topology pages, but existing validation, redaction, locking, and backend reuse behavior should remain intact.

## 16. Known Issues / Cleanup

These issues are present in the current repository:

- The Flask Monitoring page is unfinished and is still a placeholder.
- The Flask Topology page is unfinished and is still a placeholder.
- `TEST-R10`, `Test-S4`, and `Test-R11` remain in `inventory/devices.yml`; they may cause all-device Golden Config operations to report failures if they are not live.
- Matching test generated files remain under `generated_configs/` (`TEST-R10.cfg`, `Test-R11.cfg`, and `Test-S4.cfg`).
- Only the Arista cEOS Jinja2 template is implemented; the optional multi-vendor/extra-credit template is not implemented.
- The standalone monitoring/topology imports are not represented in root `requirements.txt`, so those tools may require additional environment setup beyond the Flask/renderer dependencies.
- The root README contains older status wording that still lists automation/validation work as incomplete even though current scripts, CI, GUI, and tests now exist; it should be reconciled before final submission.

## 17. Next Steps

1. Finish Flask Monitoring integration using the existing Telegraf, InfluxDB, Grafana, and gNMI stack.
2. Integrate the existing NetworkX topology visualization into Flask.
3. Add an optional multi-vendor Jinja2 template if extra credit is required.
4. Run final integration tests for rendering, GUI workflows, live devices, monitoring, and topology.
5. Remove temporary test devices and test-generated files after validation.
6. Review the worktree, then commit and push the intended final files.
7. Prepare final screenshots, video, and project write-up.

## 18. Commands

From the project root:

```bash
cd ~/Documents/NetPilot
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

The Flask app listens on `http://127.0.0.1:5000` by default.

Rendering:

```bash
python3 render_configs.py R1
python3 render_configs.py
```

Golden Config capture:

```bash
export NETPILOT_USERNAME='...'
export NETPILOT_PASSWORD='...'
python3 save_golden_configs.py R1
python3 save_golden_configs.py
```

Fixture-only GUI tests:

```bash
python3 -m unittest tests/test_configuration_gui.py -v
```

The GitHub Actions validation sequence can be reproduced locally with:

```bash
python3 -m compileall -q .
python3 render_configs.py
```

Standalone monitoring/topology scripts have their own documented arguments and external service requirements; they are not invoked by `app.py` currently.

## 19. Security

- Never expose secrets in source, logs, screenshots, commits, or handoff documents.
- Do not commit passwords or tokens.
- `NETPILOT_USERNAME` and `NETPILOT_PASSWORD` are environment variables used for live Golden Config and related device automation.
- Monitoring utilities may also require an `INFLUX_TOKEN` environment variable.
- This handoff does not include any secret values.

import os
import sys
import time
import json
import yaml
import networkx as nx
import matplotlib.pyplot as plt

from influxdb_client import InfluxDBClient


# --------------------------------------------------
# Settings
# --------------------------------------------------

INFLUX_URL = "http://127.0.0.1:8086"
INFLUX_ORG = "NetPilot"
INFLUX_BUCKET = "telemetry"
REFRESH_SECONDS = 5

TOKEN = os.getenv("INFLUX_TOKEN")

if not TOKEN:
    raise RuntimeError("INFLUX_TOKEN is not set")


# --------------------------------------------------
# Command-line arguments
# --------------------------------------------------

if len(sys.argv) < 2:
    print(
        "Usage: python realtime_topology.py "
        "<topology.clab.yml> [devices.json]"
    )
    sys.exit(1)

TOPOLOGY_FILE = sys.argv[1]

if len(sys.argv) >= 3:
    DEVICES_FILE = sys.argv[2]
else:
    DEVICES_FILE = os.path.join(
        os.path.dirname(__file__),
        "devices.json"
    )


# --------------------------------------------------
# Known management IP fallback
# --------------------------------------------------

DEVICE_IPS = {
    "R1": "172.20.20.13",
    "R2": "172.20.20.14",
    "R3": "172.20.20.9",
    "R4": "172.20.20.11",
    "R5": "172.20.20.2",
    "S1": "172.20.20.7",
    "S2": "172.20.20.8",
    "S3": "172.20.20.4",
    "S4": "172.20.20.10",
}


# --------------------------------------------------
# Try to load devices.json
# --------------------------------------------------

def load_devices_json(path):
    if not os.path.exists(path):
        print(
            f"devices.json not found at {path}; "
            "using built-in management IP mapping."
        )
        return

    try:
        with open(path, "r") as f:
            data = json.load(f)

        if isinstance(data, dict) and "devices" in data:
            data = data["devices"]

        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue

                name = (
                    item.get("name")
                    or item.get("device")
                    or item.get("hostname")
                )

                ip = (
                    item.get("mgmt_ip")
                    or item.get("management_ip")
                    or item.get("host")
                    or item.get("ip")
                )

                if name and ip:
                    DEVICE_IPS[name] = ip

        elif isinstance(data, dict):
            for name, item in data.items():
                if not isinstance(item, dict):
                    continue

                ip = (
                    item.get("mgmt_ip")
                    or item.get("management_ip")
                    or item.get("host")
                    or item.get("ip")
                )

                if ip:
                    DEVICE_IPS[name] = ip

    except Exception as e:
        print(f"Warning: unable to parse devices.json: {e}")
        print("Using built-in management IP mapping.")


load_devices_json(DEVICES_FILE)


# --------------------------------------------------
# Normalize Containerlab interface names
# eth1 -> Ethernet1
# --------------------------------------------------

def normalize_interface(interface):
    lower = interface.lower()

    if lower.startswith("eth"):
        number = interface[3:]
        return f"Ethernet{number}"

    return interface


# --------------------------------------------------
# Load Containerlab topology
# --------------------------------------------------

with open(TOPOLOGY_FILE, "r") as f:
    topo_data = yaml.safe_load(f)

topology = topo_data["topology"]

nodes = topology.get("nodes", {})
links = topology.get("links", [])

G = nx.Graph()

for node in nodes:
    G.add_node(node)

for link in links:

    endpoints = link.get("endpoints", [])

    if len(endpoints) != 2:
        continue

    ep1 = endpoints[0]
    ep2 = endpoints[1]

    node1, intf1 = ep1.split(":", 1)
    node2, intf2 = ep2.split(":", 1)

    G.add_edge(
        node1,
        node2,
        endpoint1=ep1,
        endpoint2=ep2,
        interface1=normalize_interface(intf1),
        interface2=normalize_interface(intf2),
    )


print("\nLoaded topology")
print("------------------------------")
print(f"Devices: {G.number_of_nodes()}")
print(f"Links:   {G.number_of_edges()}")

for u, v, data in G.edges(data=True):
    print(
        f"{data['endpoint1']} <--> "
        f"{data['endpoint2']}"
    )


# --------------------------------------------------
# Stable layout
# --------------------------------------------------

pos = nx.kamada_kawai_layout(G)


# --------------------------------------------------
# InfluxDB
# --------------------------------------------------

client = InfluxDBClient(
    url=INFLUX_URL,
    token=TOKEN,
    org=INFLUX_ORG
)

query_api = client.query_api()


def get_interface_states():

    query = f'''
from(bucket: "{INFLUX_BUCKET}")
  |> range(start: -30d)
  |> filter(fn: (r) =>
      r["_measurement"] == "interface_oper_status" and
      r["_field"] == "oper_status"
  )
  |> group(columns: ["source", "name"])
  |> last()
  |> keep(columns: ["source", "name", "_value"])
'''

    tables = query_api.query(
        query=query,
        org=INFLUX_ORG
    )

    states = {}

    for table in tables:
        for record in table.records:

            source = record.values.get("source")
            interface = record.values.get("name")
            status = str(record.get_value()).upper()

            if source and interface:
                states[(source, interface)] = status

    return states


# --------------------------------------------------
# Determine endpoint status
# --------------------------------------------------

def endpoint_status(node, interface, states):

    mgmt_ip = DEVICE_IPS.get(node)

    # Hosts such as H1/H2/web-server do not have gNMI
    if not mgmt_ip:
        return None

    return states.get((mgmt_ip, interface))


# --------------------------------------------------
# Determine link status
# --------------------------------------------------

def determine_link_status(node1, node2, edge, states):

    status1 = endpoint_status(
        node1,
        edge["interface1"],
        states
    )

    status2 = endpoint_status(
        node2,
        edge["interface2"],
        states
    )

    known = [
        s for s in (status1, status2)
        if s is not None
    ]

    # No telemetry from either endpoint
    if not known:
        return "UNKNOWN"

    # Any monitored endpoint DOWN means link DOWN
    if any(
        s in (
            "DOWN",
            "LOWER_LAYER_DOWN",
            "DORMANT",
            "NOT_PRESENT"
        )
        for s in known
    ):
        return "DOWN"

    # All known monitored endpoints UP
    if all(s == "UP" for s in known):
        return "UP"

    return "UNKNOWN"


# --------------------------------------------------
# Draw real-time topology
# --------------------------------------------------

def draw_topology(states):

    plt.figure(figsize=(14, 9))

    edge_colors = []
    edge_widths = []

    up_count = 0
    down_count = 0
    unknown_count = 0

    for node1, node2, edge in G.edges(data=True):

        status = determine_link_status(
            node1,
            node2,
            edge,
            states
        )

        if status == "UP":
            edge_colors.append("green")
            edge_widths.append(3)
            up_count += 1

        elif status == "DOWN":
            edge_colors.append("red")
            edge_widths.append(5)
            down_count += 1

        else:
            edge_colors.append("gray")
            edge_widths.append(2)
            unknown_count += 1


    # Network device nodes
    monitored_nodes = [
        n for n in G.nodes
        if n in DEVICE_IPS
    ]

    # Hosts / endpoints
    host_nodes = [
        n for n in G.nodes
        if n not in DEVICE_IPS
    ]


    nx.draw_networkx_nodes(
        G,
        pos,
        nodelist=monitored_nodes,
        node_size=2300,
        node_color="lightblue"
    )

    nx.draw_networkx_nodes(
        G,
        pos,
        nodelist=host_nodes,
        node_size=1500,
        node_color="lightgray"
    )

    nx.draw_networkx_labels(
        G,
        pos,
        font_size=10,
        font_weight="bold"
    )

    nx.draw_networkx_edges(
        G,
        pos,
        edge_color=edge_colors,
        width=edge_widths
    )


    # Interface labels
    edge_labels = {}

    for u, v, edge in G.edges(data=True):

        intf1 = edge["interface1"]
        intf2 = edge["interface2"]

        edge_labels[(u, v)] = (
            f"{intf1} ↔ {intf2}"
        )

    nx.draw_networkx_edge_labels(
        G,
        pos,
        edge_labels=edge_labels,
        font_size=6
    )


    timestamp = time.strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    plt.title(
        "NetPilot Real-Time Network Topology\n"
        f"Last Updated: {timestamp}\n"
        f"UP: {up_count}   "
        f"DOWN: {down_count}   "
        f"UNKNOWN: {unknown_count}",
        fontsize=14
    )

    plt.axis("off")
    plt.tight_layout()

    output_file = "netpilot_realtime_topology.png"

    plt.savefig(
        output_file,
        dpi=180,
        bbox_inches="tight"
    )

    plt.close()

    return (
        output_file,
        up_count,
        down_count,
        unknown_count
    )


# --------------------------------------------------
# Main refresh loop
# --------------------------------------------------

print("\nStarting real-time topology monitor...")
print(
    f"Refreshing every {REFRESH_SECONDS} seconds."
)
print("Press Ctrl+C to stop.\n")


try:

    while True:

        states = get_interface_states()

        output_file, up, down, unknown = (
            draw_topology(states)
        )

        print(
            f"[{time.strftime('%H:%M:%S')}] "
            f"Interfaces loaded: {len(states):3d} | "
            f"Links UP: {up:2d} | "
            f"DOWN: {down:2d} | "
            f"UNKNOWN: {unknown:2d}"
        )

        time.sleep(REFRESH_SECONDS)

except KeyboardInterrupt:

    print("\nStopping topology monitor.")

finally:

    client.close()
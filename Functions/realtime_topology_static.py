import sys
import yaml
import networkx as nx
import matplotlib.pyplot as plt


if len(sys.argv) != 2:
    print("Usage: python realtime_topology.py <topology.clab.yml>")
    sys.exit(1)

topology_file = sys.argv[1]

with open(topology_file, "r") as f:
    data = yaml.safe_load(f)

topology = data["topology"]

nodes = topology.get("nodes", {})
links = topology.get("links", [])

G = nx.Graph()

# Add all devices
for node in nodes:
    G.add_node(node)

# Add links from Containerlab YAML
for link in links:
    endpoints = link.get("endpoints", [])

    if len(endpoints) != 2:
        continue

    # Example:
    # S3:eth2 -> S3
    # S4:eth2 -> S4
    device1 = endpoints[0].split(":")[0]
    device2 = endpoints[1].split(":")[0]

    G.add_edge(
        device1,
        device2,
        endpoint1=endpoints[0],
        endpoint2=endpoints[1],
    )


print("\nNetPilot Topology")
print("-----------------------------")

print("\nDevices:")
for node in G.nodes:
    print(f"  {node}")

print("\nLinks:")
for u, v, info in G.edges(data=True):
    print(f"  {info['endpoint1']} <--> {info['endpoint2']}")

print(f"\nTotal devices: {G.number_of_nodes()}")
print(f"Total links:   {G.number_of_edges()}")


# Draw topology
pos = nx.kamada_kawai_layout(G)

plt.figure(figsize=(12, 8))

nx.draw_networkx_nodes(
    G,
    pos,
    node_size=2200
)

nx.draw_networkx_edges(
    G,
    pos,
    width=2
)

nx.draw_networkx_labels(
    G,
    pos,
    font_size=12,
    font_weight="bold"
)

plt.title("NetPilot Network Topology")
plt.axis("off")
plt.tight_layout()

output_file = "netpilot_topology.png"
plt.savefig(output_file, dpi=200, bbox_inches="tight")

print(f"\nTopology image saved to: {output_file}")
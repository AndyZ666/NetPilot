# NetPilot

Advanced Network Automation semester project.

## Current Architecture

- Containerlab
- Arista cEOS 4.36.2F
- Dual-stack IPv4/IPv6
- VLAN 10 / 20 / 30 / 900
- RIPv2
- OSPFv2
- OSPFv3
- BGP
- DHCPv4
- Stateful DHCPv6
- DHCP Relay
- IPv6 Router Advertisement
- NetBox IPAM
- NMAS / OOB Management
- Wireshark / tcpdump

## Network Services

- R2: DHCPv4/DHCPv6 Server
- S1: DHCP Relay and client VLAN gateways
- R1/R2: RIP/OSPF redistribution boundary
- R3/R4/R5: BGP edge
- Web Server: HTTP test service

## Management Network

Containerlab OOB management:

- IPv4: `172.20.20.0/24`
- IPv6: `3fff:172:20:20::/64`

## Current Status

- [x] Base topology
- [x] IPv4 routing
- [x] IPv6 routing
- [x] DHCPv4
- [x] DHCPv6
- [x] OSPF
- [x] BGP
- [x] NMAS
- [x] NetBox IPAM
- [ ] Network automation scripts
- [ ] Validation automation
- [ ] Final monitoring integration
#!/bin/sh
set -eu

# Containerlab creates the data link after starting the containers.
echo "Waiting for the isolated bootstrap interface eth1"
until ip link show dev eth1 >/dev/null 2>&1; do
    sleep 1
done
ip address add 10.250.0.1/24 dev eth1
ip link set dev eth1 up

# EOS retries ZTP normally if its first DHCP request precedes server readiness.
python3 -u /usr/local/bin/ztp-http.py 80 --bind 10.250.0.1 --directory /srv/ztp &
if [ -f /srv/ztp-dhcp/hosts ] && [ -f /srv/ztp-dhcp/options ]; then
    # HUP rereads these files; GUI onboarding does not restart this container.
    exec dnsmasq --keep-in-foreground --conf-file=/etc/dnsmasq.conf \
        --dhcp-hostsfile=/srv/ztp-dhcp/hosts --dhcp-optsfile=/srv/ztp-dhcp/options
fi
exec dnsmasq --keep-in-foreground --conf-file=/etc/dnsmasq.conf

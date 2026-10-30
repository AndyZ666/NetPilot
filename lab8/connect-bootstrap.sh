#!/bin/sh
set -eu

bridge=br-netpilot-ztp

if [ "$(id -u)" -ne 0 ]; then
    echo "Run with sudo: sudo ./lab8/connect-bootstrap.sh" >&2
    exit 1
fi

if [ ! -e "/sys/class/net/$bridge" ]; then
    ip link add name "$bridge" type bridge
fi
if [ ! -d "/sys/class/net/$bridge/bridge" ]; then
    echo "Refusing to use $bridge: it is not a Linux bridge." >&2
    exit 1
fi

# Only these Containerlab host endpoints belong to the bootstrap network.
for endpoint in npztp-srv npztp-r6 npztp-r7; do
    if [ ! -e "/sys/class/net/$endpoint" ]; then
        echo "Skipping $endpoint (not present)."
        continue
    fi

    master_path="/sys/class/net/$endpoint/master"
    if [ -L "$master_path" ]; then
        master=$(basename "$(readlink "$master_path")")
        if [ "$master" != "$bridge" ]; then
            echo "Refusing to move $endpoint from $master to $bridge." >&2
            exit 1
        fi
    else
        ip link set dev "$endpoint" master "$bridge"
    fi
    ip link set dev "$endpoint" up
    echo "$endpoint attached to $bridge."
done

ip link set dev "$bridge" up

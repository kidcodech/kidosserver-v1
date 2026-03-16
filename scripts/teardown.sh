#!/bin/bash

set -e

# Teardown monitoring namespace first
echo "Tearing down monitoring namespace..."
"$(dirname "$0")/monitoring/teardown.sh"

# ---- Kill dhclient processes (using pid files from init.sh) ----
echo "Stopping DHCP clients..."
for pidfile in /tmp/dhclient-br-wan.pid /tmp/dhclient-ethns-br0.pid /tmp/dhclient-kidosns-br1.pid; do
    if [ -f "$pidfile" ]; then
        kill "$(cat "$pidfile")" 2>/dev/null || true
        rm -f "$pidfile"
    fi
done
# Also kill any stray dhclient processes inside namespaces
for ns in ethns kidosns switchns appsns appsns2; do
    ip netns exec "$ns" pkill dhclient 2>/dev/null || true
done

# ---- Tear down br-wan bridge and restore WAN interface ----
if ip link show br-wan >/dev/null 2>&1; then
    echo "Tearing down br-wan bridge..."

    # Find the physical WAN interface that was enslaved to br-wan
    WAN_IFACE=$(ip link show master br-wan 2>/dev/null \
        | grep -E '^[0-9]+: (en|eth)' | grep -v veth \
        | awk -F': ' '{print $2}' | awk '{print $1}' | head -n1)

    # Remove veth-mgmt from bridge and delete the pair
    ip link set veth-mgmt nomaster 2>/dev/null || true
    ip link del veth-mgmt 2>/dev/null || true   # also removes veth-mgmt-eth in ethns

    # Release WAN interface from bridge
    if [ -n "$WAN_IFACE" ]; then
        ip link set "$WAN_IFACE" nomaster 2>/dev/null || true
    fi

    ip link set br-wan down 2>/dev/null || true
    ip link del br-wan 2>/dev/null || true

    # Hand WAN interface back to NetworkManager and restore DHCP
    if [ -n "$WAN_IFACE" ]; then
        nmcli device set "$WAN_IFACE" managed yes 2>/dev/null || true
        echo "Restoring DHCP on $WAN_IFACE..."
        dhclient "$WAN_IFACE" 2>/dev/null &
        echo "  Waiting for IP on $WAN_IFACE..."
        sleep 3
        ip -4 addr show "$WAN_IFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' \
            && echo "  DHCP restored" || echo "  DHCP still pending (background)"
    fi
fi

# ---- Move physical interfaces back to root namespace ----
echo "Moving physical interfaces back to root namespace..."
for ns in switchns ethns; do
    PHYS=$(ip netns exec "$ns" ip link show 2>/dev/null \
        | grep -E '^[0-9]+: (en|eth)' | grep -v '@' | grep -v veth \
        | awk -F': ' '{print $2}' | awk '{print $1}') || true
    for iface in $PHYS; do
        echo "  Moving $iface from $ns -> root"
        ip netns exec "$ns" ip link set "$iface" netns 1 2>/dev/null || true
    done
done

# ---- Delete all namespaces ----
# Deleting a namespace automatically removes all veth endpoints inside it.
echo "Deleting namespaces..."
for ns in switchns kidosns appsns appsns2 ethns; do
    ip netns del "$ns" 2>/dev/null && echo "  Deleted $ns" || true
done

# ---- Clean up any leftover root-ns veth interfaces ----
for iface in veth-mgmt veth-root; do
    ip link del "$iface" 2>/dev/null || true
done

echo "Teardown complete!"

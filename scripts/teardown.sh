#!/bin/bash

# Teardown monitoring namespace first
echo "Tearing down monitoring namespace..."
./scripts/monitoring/teardown.sh

# Discover all network namespaces starting with ethns
ALL_ETHNS=$(ip netns list | grep -E '^ethns[0-9]*' | awk '{print $1}')

# Kill dhclient processes in all namespaces
echo "Stopping DHCP clients..."
ip netns exec ethns pkill dhclient 2>/dev/null || true
for ns in $ALL_ETHNS; do
    if [ "$ns" != "ethns" ]; then
        ip netns exec "$ns" pkill dhclient 2>/dev/null || true
    fi
done
ip netns exec kidosns pkill dhclient 2>/dev/null || true
ip netns exec switchns pkill dhclient 2>/dev/null || true
ip netns exec appsns pkill dhclient 2>/dev/null || true
ip netns exec appsns2 pkill dhclient 2>/dev/null || true

# Discover all physical ethernet interfaces in namespaces and move them back
echo "Moving physical interfaces back to default namespace..."
# First handle ethns
ALL_ETH_IN_ETHNS=$(ip netns exec ethns ip link show 2>/dev/null | grep -E '^[0-9]+: (en|eth)' | grep -v '@' | grep -v 'veth' | awk -F': ' '{print $2}' | awk '{print $1}') || true
for iface in $ALL_ETH_IN_ETHNS; do
    echo "Moving $iface from ethns back to default namespace..."
    ip netns exec ethns ip link set "$iface" netns 1 2>/dev/null || true
done

# Then handle ethns1, ethns2, etc.
for ns in $ALL_ETHNS; do
    if [ "$ns" != "ethns" ]; then
        ALL_ETH_IN_NS=$(ip netns exec "$ns" ip link show 2>/dev/null | grep -E '^[0-9]+: (en|eth)' | grep -v '@' | grep -v 'veth' | awk -F': ' '{print $2}' | awk '{print $1}') || true
        for iface in $ALL_ETH_IN_NS; do
            echo "Moving $iface from $ns back to default namespace..."
            ip netns exec "$ns" ip link set "$iface" netns 1 2>/dev/null || true
        done
    fi
done

# Delete network namespaces (this automatically removes all interfaces and bridges inside them)
echo "Deleting Switch namespace..."
ip netns del switchns 2>/dev/null || true

echo "Deleting Kidos namespace..."
ip netns del kidosns 2>/dev/null || true

echo "Deleting Apps namespace..."
ip netns del appsns 2>/dev/null || true

echo "Deleting Apps namespace 2..."
ip netns del appsns2 2>/dev/null || true

echo "Deleting Ethernet namespace..."
ip netns del ethns 2>/dev/null || true

# Delete ethns1, ethns2, etc.
for ns in $ALL_ETHNS; do
    if [ "$ns" != "ethns" ]; then
        echo "Deleting $ns namespace..."
        ip netns del "$ns" 2>/dev/null || true
    fi
done

# Bring up all physical interfaces in default namespace
echo "Bringing up physical interfaces..."
ALL_PHYS_ETH=$(ip link show | grep -E '^[0-9]+: (en|eth)' | grep -v '@' | awk -F': ' '{print $2}' | awk '{print $1}')
for iface in $ALL_PHYS_ETH; do
    echo "Bringing up $iface..."
    ip link set "$iface" up 2>/dev/null || true
done

echo "Teardown complete!"

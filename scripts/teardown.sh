#!/bin/bash

# Teardown monitoring namespace first
echo "Tearing down monitoring namespace..."
./scripts/monitoring/teardown.sh

# Kill dhclient processes
echo "Stopping DHCP clients..."
ip netns exec ethns pkill dhclient 2>/dev/null || true
ip netns exec kidosns pkill dhclient 2>/dev/null || true
ip netns exec switchns pkill dhclient 2>/dev/null || true
ip netns exec appsns pkill dhclient 2>/dev/null || true
ip netns exec appsns2 pkill dhclient 2>/dev/null || true

# Move physical interface back to default namespace
echo "Moving enp0s31f6 back to default namespace..."
ip netns exec ethns ip link set enp0s31f6 netns 1 2>/dev/null || true

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

# Bring up the physical interface in default namespace
echo "Bringing up enp0s31f6..."
ip link set enp0s31f6 up 2>/dev/null || true

echo "Teardown complete!"

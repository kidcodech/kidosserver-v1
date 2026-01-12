#!/bin/bash

echo "Tearing down Kidos Hotspot (wifins)..."

# Kill processes in wifins
ip netns exec wifins pkill hostapd 2>/dev/null || true
ip netns exec wifins pkill dhclient 2>/dev/null || true

# Remove veth-wifi-sw from switchns bridge before deleting namespace
ip netns exec switchns ip link del veth-wifi-sw 2>/dev/null || true

# Delete namespace (this automatically moves phy interfaces back to root)
ip netns del wifins 2>/dev/null || true

# Remove config files
rm -f /tmp/kidos-hostapd.conf

echo "✓ Teardown complete. Interfaces returned to host."

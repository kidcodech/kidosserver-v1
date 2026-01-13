#!/bin/bash

echo "Tearing down Kidos Hotspot (wifins)..."

# Move any wifi interfaces back to root namespace before deleting
if ip netns exec wifins ip link show 2>/dev/null | grep -q "^[0-9]*: wl"; then
    EXISTING_IFACE=$(ip netns exec wifins ip link | grep -E "^[0-9]+: wl" | awk -F: '{print $2}' | awk '{print $1}' | head -n1)
    if [ -n "$EXISTING_IFACE" ]; then
        echo "Moving $EXISTING_IFACE back to host namespace..."
        EXISTING_PHY=$(ip netns exec wifins iw dev "$EXISTING_IFACE" info 2>/dev/null | grep wiphy | awk '{print $2}')
        if [ -n "$EXISTING_PHY" ]; then
            ip netns exec wifins iw phy "phy$EXISTING_PHY" set netns 1 2>/dev/null || true
        fi
    fi
fi

# Kill processes in wifins
ip netns exec wifins pkill hostapd 2>/dev/null || true
ip netns exec wifins pkill dhclient 2>/dev/null || true

# Remove veth-wifi-sw from switchns bridge before deleting namespace
ip netns exec switchns ip link del veth-wifi-sw 2>/dev/null || true

# Delete namespace (this automatically moves phy interfaces back to root)
ip netns del wifins 2>/dev/null || true

# Force remove namespace file if it still exists
rm -f /var/run/netns/wifins 2>/dev/null || true

# Remove config files
rm -f /tmp/kidos-hostapd.conf

echo "✓ Teardown complete. Interfaces returned to host."

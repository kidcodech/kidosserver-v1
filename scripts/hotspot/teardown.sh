#!/bin/bash

echo "Tearing down Kidos Hotspot (wifins)..."

# Kill processes in wifins
ip netns exec wifins pkill hostapd 2>/dev/null || true

# Delete namespace (this automatically moves phy interfaces back to root)
ip netns del wifins 2>/dev/null || true

# Remove config files
rm -f /tmp/kidos-hostapd.conf

# Clean up switch integration if needed (veth pair is deleted with ns, but good to be sure)
# veth-wifi-sw might linger in switchns if something went wrong? No, veth pairs delete together.

echo "✓ Teardown complete. Interfaces returned to host."
# Re-enable NetworkManager management if desired
# nmcli device set wlp0s20f0u1 managed yes

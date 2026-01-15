#!/bin/bash

echo "Cleaning up test namespaces..."

# Get physical interface before tearing down
PHYSICAL_IFACE=$(ip link show master br-test 2>/dev/null | grep -E '^[0-9]+: (en|eth)' | awk -F': ' '{print $2}' | awk '{print $1}' | head -n1)

# Stop dhclient processes
pkill -f "dhclient" 2>/dev/null || true
rm -f /var/run/dhclient*.pid

# Delete namespaces (this removes all interfaces inside them)
ip netns del ns1 2>/dev/null || true
ip netns del ns2 2>/dev/null || true

# Remove physical interface from bridge and restore it
if [ -n "$PHYSICAL_IFACE" ]; then
    echo "Restoring $PHYSICAL_IFACE..."
    ip link set "$PHYSICAL_IFACE" nomaster 2>/dev/null || true
fi

# Delete bridge in root namespace
ip link set br-test down 2>/dev/null || true
ip link del br-test 2>/dev/null || true

# Restore internet on physical interface
if [ -n "$PHYSICAL_IFACE" ]; then
    echo "Requesting DHCP on $PHYSICAL_IFACE..."
    dhclient "$PHYSICAL_IFACE" 2>/dev/null &
fi

# Remove DNS configs
rm -rf /etc/netns/ns1 /etc/netns/ns2

echo "Cleanup complete!"

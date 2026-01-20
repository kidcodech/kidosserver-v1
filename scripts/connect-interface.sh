#!/bin/bash

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if interface name is provided
if [ -z "$1" ]; then
    echo -e "${RED}✗ Error: Interface name required${NC}"
    echo "Usage: $0 <interface_name>"
    echo "Example: $0 eth0"
    exit 1
fi

IFACE="$1"

# Verify interface exists
if ! ip link show "$IFACE" &>/dev/null; then
    echo -e "${RED}✗ Error: Interface $IFACE not found${NC}"
    exit 1
fi

# Verify ethns namespace exists
if ! ip netns list | grep -q "^ethns"; then
    echo -e "${RED}✗ Error: ethns namespace not found. Run init.sh first.${NC}"
    exit 1
fi

echo "Connecting interface $IFACE to ethns namespace..."

# Move interface to ethns namespace
echo "Moving $IFACE to ethns namespace..."
ip link set "$IFACE" netns ethns

# Bring up interface in ethns
echo "Bringing up $IFACE in ethns..."
ip netns exec ethns ip link set "$IFACE" up

# Add interface to bridge
echo "Adding $IFACE to br0 bridge..."
ip netns exec ethns ip link set "$IFACE" master br0

echo -e "${GREEN}✓ Interface $IFACE connected to ethns bridge${NC}"

# Request DHCP on ethns bridge
echo "Requesting DHCP for ethns bridge..."
ip netns exec ethns pkill dhclient 2>/dev/null || true
sleep 1
ip netns exec ethns dhclient -v br0

# Check if we got an IP
ETHNS_IP=$(ip netns exec ethns ip -4 addr show br0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
if [ -n "$ETHNS_IP" ]; then
    echo -e "${GREEN}✓ Got IP for ethns: $ETHNS_IP${NC}"
else
    echo -e "${RED}✗ Failed to get DHCP IP for ethns${NC}"
    exit 1
fi

# Request DHCP for kidosns bridge
echo "Requesting DHCP for kidosns bridge..."
ip netns exec kidosns pkill dhclient 2>/dev/null || true
sleep 1
ip netns exec kidosns dhclient -v br1

BR1_IP=$(ip netns exec kidosns ip -4 addr show br1 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
if [ -n "$BR1_IP" ]; then
    echo -e "${GREEN}✓ Got IP for kidosns: $BR1_IP${NC}"
    GATEWAY=$(ip netns exec kidosns ip route | grep default | awk '{print $3}')
    echo -e "${GREEN}✓ Gateway: $GATEWAY${NC}"
else
    echo -e "${RED}✗ Failed to get DHCP IP for kidosns${NC}"
fi

# Request DHCP for switchns bridge
echo "Requesting DHCP for switchns bridge..."
ip netns exec switchns pkill dhclient 2>/dev/null || true
sleep 1
ip netns exec switchns dhclient -v br-switch

BR_SWITCH_IP=$(ip netns exec switchns ip -4 addr show br-switch | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
if [ -n "$BR_SWITCH_IP" ]; then
    echo -e "${GREEN}✓ Got IP for switchns: $BR_SWITCH_IP${NC}"
else
    echo -e "${RED}✗ Failed to get DHCP IP for switchns${NC}"
fi

# Request DHCP for appsns
echo "Requesting DHCP for appsns..."
ip netns exec appsns pkill dhclient 2>/dev/null || true
sleep 1
ip netns exec appsns dhclient -v veth-app

VETH_APP_IP=$(ip netns exec appsns ip -4 addr show veth-app | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
if [ -n "$VETH_APP_IP" ]; then
    echo -e "${GREEN}✓ Got IP for appsns: $VETH_APP_IP${NC}"
else
    echo -e "${RED}✗ Failed to get DHCP IP for appsns${NC}"
fi

# Request DHCP for appsns2
echo "Requesting DHCP for appsns2..."
ip netns exec appsns2 pkill dhclient 2>/dev/null || true
sleep 1
ip netns exec appsns2 dhclient -v veth-app

VETH_APP2_IP=$(ip netns exec appsns2 ip -4 addr show veth-app | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
if [ -n "$VETH_APP2_IP" ]; then
    echo -e "${GREEN}✓ Got IP for appsns2: $VETH_APP2_IP${NC}"
else
    echo -e "${RED}✗ Failed to get DHCP IP for appsns2${NC}"
fi

# Save configuration
IP_CONFIG_FILE="/tmp/kidos-network.conf"
if [ -n "$BR1_IP" ] && [ -n "$VETH_APP_IP" ] && [ -n "$GATEWAY" ]; then
    cat > "$IP_CONFIG_FILE" << EOF
BR1_IP="$BR1_IP"
VETH_APP_IP="$VETH_APP_IP"
VETH_APP2_IP="$VETH_APP2_IP"
GATEWAY="$GATEWAY"
EOF
    echo -e "${GREEN}✓ Saved IP configuration to $IP_CONFIG_FILE${NC}"
fi

echo ""
echo -e "${GREEN}✓ Network configuration complete!${NC}"
echo "Summary:"
echo "  Interface: $IFACE -> ethns"
echo "  ethns:     $ETHNS_IP"
echo "  kidosns:   $BR1_IP"
echo "  switchns:  $BR_SWITCH_IP"
echo "  appsns:    $VETH_APP_IP"
echo "  appsns2:   $VETH_APP2_IP"
echo "  Gateway:   $GATEWAY"

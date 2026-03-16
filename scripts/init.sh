#!/bin/bash

set -e
set -x

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Create Kidos namespace
echo "Creating Kidos namespace (kidosns)..."
ip netns add kidosns

# Create Switch namespace
echo "Creating Switch namespace (switchns)..."
ip netns add switchns

# Create Apps namespace
echo "Creating Apps namespace (appsns)..."
ip netns add appsns

# Create Apps namespace 2
echo "Creating Apps namespace 2 (appsns2)..."
ip netns add appsns2

echo "Core namespaces created successfully!"

# Create ethns namespace
echo "Creating ethns namespace..."
ip netns add ethns

# Create bridge in ethns
echo "Creating bridge in ethns..."
ip netns exec ethns ip link add name br0 type bridge
ip netns exec ethns ip link set br0 up
ip netns exec ethns ip link set lo up

# Create veth pair to connect ethns and kidosns
echo "Creating veth pair between ethns and kidosns..."
ip netns exec ethns ip link add veth-eth type veth peer name veth-kidos netns kidosns
ip netns exec ethns ip link set veth-eth master br0
ip netns exec ethns ip link set veth-eth up
ip netns exec kidosns ip link set veth-kidos up

# Setup DNS for ethns
mkdir -p /etc/netns/ethns
echo "nameserver 8.8.8.8" > /etc/netns/ethns/resolv.conf
echo "hosts: files dns" > /etc/netns/ethns/nsswitch.conf

# Create bridge in kidos namespace
echo "Creating bridge in kidos namespace..."
ip netns exec kidosns ip link add name br1 type bridge

# Add veth-kidos to bridge
echo "Adding veth-kidos to bridge in kidos namespace..."
ip netns exec kidosns ip link set veth-kidos master br1

# Create bridge in switch namespace
echo "Creating bridge in switch namespace..."
ip netns exec switchns ip link add name br-switch type bridge

# Create veth pair to connect kidos and switch namespaces
echo "Creating veth pair between kidos and switch namespaces..."
ip netns exec kidosns ip link add veth-kidos-app type veth peer name veth-sw netns switchns

# Add veth-kidos-app to bridge in kidos
echo "Adding veth-kidos-app to bridge in kidos namespace..."
ip netns exec kidosns ip link set veth-kidos-app master br1

# Add veth-sw to bridge in switch
echo "Adding veth-sw to bridge in switch namespace..."
ip netns exec switchns ip link set veth-sw master br-switch

# Create veth pair to connect switch and apps namespaces
echo "Creating veth pair between switch and apps namespaces..."
ip netns exec switchns ip link add veth-sw-app type veth peer name veth-app netns appsns

# Add veth-sw-app to bridge in switch
echo "Adding veth-sw-app to bridge in switch namespace..."
ip netns exec switchns ip link set veth-sw-app master br-switch

# Create veth pair to connect switch and apps2 namespaces
echo "Creating veth pair between switch and apps2 namespaces..."
ip netns exec switchns ip link add veth-sw-app2 type veth peer name veth-app netns appsns2

# Add veth-sw-app2 to bridge in switch
echo "Adding veth-sw-app2 to bridge in switch namespace..."
ip netns exec switchns ip link set veth-sw-app2 master br-switch

# Bring up the interfaces
echo "Bringing up interfaces..."
ip netns exec ethns ip link set br0 up
ip netns exec kidosns ip link set veth-kidos up
ip netns exec kidosns ip link set veth-kidos-app up
ip netns exec kidosns ip link set br1 up
ip netns exec switchns ip link set veth-sw up
ip netns exec switchns ip link set veth-sw-app up
ip netns exec switchns ip link set veth-sw-app2 up
ip netns exec switchns ip link set br-switch up
ip netns exec appsns ip link set veth-app up
ip netns exec appsns2 ip link set veth-app up

# Setup DNS for appsns
echo "Configuring DNS for appsns..."
mkdir -p /etc/netns/appsns
echo "nameserver 8.8.8.8" > /etc/netns/appsns/resolv.conf
echo "hosts: files dns" > /etc/netns/appsns/nsswitch.conf

# Setup DNS for appsns2
echo "Configuring DNS for appsns2..."
mkdir -p /etc/netns/appsns2
echo "nameserver 8.8.8.8" > /etc/netns/appsns2/resolv.conf
echo "hosts: files dns" > /etc/netns/appsns2/nsswitch.conf

# Setup monitoring namespace
echo "Setting up monitoring namespace..."
"$SCRIPT_DIR/monitoring/init.sh"

# ---- Connect Ethernet to ethns ----
echo "Auto-detecting ethernet interface..."
ETH_IFACE=""

# Check config file first
CONFIG_FILE="/etc/kidos/config"
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
    ETH_IFACE="${ETHERNET_INTERFACE:-}"
fi

# Auto-detect if not configured
if [ -z "$ETH_IFACE" ]; then
    ETH_IFACE=$(ip link show | grep -E '^[0-9]+: (en|eth)' | grep -v '@' | awk -F': ' '{print $2}' | awk '{print $1}' | head -n1)
fi

if [ -z "$ETH_IFACE" ]; then
    echo -e "${YELLOW}⚠ No ethernet interface found, skipping network setup${NC}"
else
    echo "Using ethernet interface: $ETH_IFACE"

    # Move eth to ethns and add to br0
    ip link set "$ETH_IFACE" netns ethns
    ip netns exec ethns ip link set "$ETH_IFACE" up
    ip netns exec ethns ip link set "$ETH_IFACE" master br0
    echo -e "${GREEN}✓ $ETH_IFACE moved to ethns${NC}"

    # Management backhaul: veth-mgmt stays in root ns, veth-mgmt-eth goes into ethns br0
    # This gives the host a permanent IP for SSH
    ip link add veth-mgmt type veth peer name veth-mgmt-eth
    ip link set veth-mgmt-eth netns ethns
    ip netns exec ethns ip link set veth-mgmt-eth master br0
    ip netns exec ethns ip link set veth-mgmt-eth up
    ip link set veth-mgmt up
    echo -e "${GREEN}✓ Management backhaul created (veth-mgmt)${NC}"

    # DHCP for ethns bridge
    ip netns exec ethns dhclient -v -pf /tmp/dhclient-ethns-br0.pid br0
    ETHNS_IP=$(ip netns exec ethns ip -4 addr show br0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || true)
    [ -n "$ETHNS_IP" ] && echo -e "${GREEN}✓ ethns IP: $ETHNS_IP${NC}"

    # DHCP for root namespace management interface (SSH access)
    dhclient -v -pf /tmp/dhclient-veth-mgmt.pid veth-mgmt || true
    MGMT_IP=$(ip -4 addr show veth-mgmt | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || true)
    [ -n "$MGMT_IP" ] && echo -e "${GREEN}✓ Host SSH IP: $MGMT_IP${NC}"

    # DHCP for kidosns
    ip netns exec kidosns dhclient -v -pf /tmp/dhclient-kidosns-br1.pid br1 || true
    BR1_IP=$(ip netns exec kidosns ip -4 addr show br1 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || true)
    [ -n "$BR1_IP" ] && echo -e "${GREEN}✓ kidosns IP: $BR1_IP${NC}"

    # DHCP for switchns
    ip netns exec switchns dhclient -v -pf /tmp/dhclient-switchns-br-switch.pid br-switch || true

    # DHCP for appsns
    ip netns exec appsns dhclient -v -pf /tmp/dhclient-appsns-veth-app.pid veth-app || true
    ip netns exec appsns2 dhclient -v -pf /tmp/dhclient-appsns2-veth-app.pid veth-app || true
fi

echo "Setup complete!"

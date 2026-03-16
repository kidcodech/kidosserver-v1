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
# Disable STP and set forward_delay=0 so bridge forwards immediately (no 30s learning delay)
ip netns exec ethns ip link set br0 type bridge stp_state 0
ip netns exec ethns ip link set br0 type bridge forward_delay 0
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
ip netns exec kidosns ip link set br1 type bridge stp_state 0
ip netns exec kidosns ip link set br1 type bridge forward_delay 0

# Add veth-kidos to bridge
echo "Adding veth-kidos to bridge in kidos namespace..."
ip netns exec kidosns ip link set veth-kidos master br1

# Create bridge in switch namespace
echo "Creating bridge in switch namespace..."
ip netns exec switchns ip link add name br-switch type bridge
ip netns exec switchns ip link set br-switch type bridge stp_state 0
ip netns exec switchns ip link set br-switch type bridge forward_delay 0

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

# Setup DNS for kidosns
echo "Configuring DNS for kidosns..."
mkdir -p /etc/netns/kidosns
echo "nameserver 8.8.8.8" > /etc/netns/kidosns/resolv.conf
echo "hosts: files dns" > /etc/netns/kidosns/nsswitch.conf

# Setup DNS for switchns
echo "Configuring DNS for switchns..."
mkdir -p /etc/netns/switchns
echo "nameserver 8.8.8.8" > /etc/netns/switchns/resolv.conf
echo "hosts: files dns" > /etc/netns/switchns/nsswitch.conf

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

# ---- WAN bridge: bridge enp2s0 + veth-mgmt in root namespace ----
# This makes the setup L2 transparent - ethns and all downstream namespaces
# get real IPs directly from the home router via br-wan -> enp2s0
echo "Creating WAN bridge (br-wan)..."

# Detect WAN interface (the one with internet/default route)
WAN_IFACE=""
CONFIG_FILE="/etc/kidos/config"
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
    WAN_IFACE="${WAN_INTERFACE:-}"
fi
if [ -z "$WAN_IFACE" ]; then
    WAN_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
fi

if [ -z "$WAN_IFACE" ]; then
    echo -e "${RED}✗ No WAN interface found, cannot create br-wan${NC}"
    exit 1
fi

echo "WAN interface: $WAN_IFACE"

# Capture MAC and current IP before bridging (for reconnect info)
WAN_MAC=$(ip link show "$WAN_IFACE" | awk '/ether/ {print $2}')
WAN_IP=$(ip -4 addr show "$WAN_IFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || true)
echo "Current WAN IP: $WAN_IP (will change after bridging, reconnect to new br-wan IP)"

# Create veth-mgmt pair first (before bridging enp2s0)
ip link add veth-mgmt type veth peer name veth-mgmt-eth
ip link set veth-mgmt-eth netns ethns
ip netns exec ethns ip link set veth-mgmt-eth master br0
ip netns exec ethns ip link set veth-mgmt-eth up
ip link set veth-mgmt up

# Create br-wan and bridge enp2s0 + veth-mgmt together
ip link add br-wan type bridge
ip link set br-wan type bridge stp_state 0
ip link set br-wan type bridge forward_delay 0
# Set br-wan MAC to WAN interface MAC so router recognises it
ip link set br-wan address "$WAN_MAC"

# Prevent NetworkManager from re-assigning IP after flush
nmcli device set "$WAN_IFACE" managed no 2>/dev/null || true
# Remove existing IP from WAN interface before adding to bridge
ip addr flush dev "$WAN_IFACE"
ip link set "$WAN_IFACE" master br-wan
ip link set "$WAN_IFACE" up
ip link set veth-mgmt master br-wan
ip link set veth-mgmt up
ip link set br-wan up
echo -e "${GREEN}✓ br-wan bridge: $WAN_IFACE + veth-mgmt${NC}"

# DHCP for br-wan (root namespace gets new IP from router)
dhclient -v -pf /tmp/dhclient-br-wan.pid br-wan || true
BR_WAN_IP=$(ip -4 addr show br-wan | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || true)
[ -n "$BR_WAN_IP" ] && echo -e "${GREEN}✓ br-wan IP: $BR_WAN_IP (SSH here after reconnect)${NC}"

# DHCP for ethns br0 (gets real IP from router via veth-mgmt-eth -> br0 -> veth-eth -> kidosns)
ip netns exec ethns dhclient -v -pf /tmp/dhclient-ethns-br0.pid br0 || true
ETHNS_IP=$(ip netns exec ethns ip -4 addr show br0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || true)
[ -n "$ETHNS_IP" ] && echo -e "${GREEN}✓ ethns IP: $ETHNS_IP${NC}"

# ---- Connect LAN ethernet interface to switchns ----
# enp1s0 (LAN client port) moves to switchns so wired clients go through DNS filtering
LAN_IFACE="${ETHERNET_INTERFACE:-}"

if [ -z "$LAN_IFACE" ]; then
    echo -e "${YELLOW}⚠ No LAN interface configured (ETHERNET_INTERFACE), skipping LAN setup${NC}"
else
    if ip link show "$LAN_IFACE" &>/dev/null; then
        echo "Moving LAN interface $LAN_IFACE to switchns..."
        ip link set "$LAN_IFACE" netns switchns
        ip netns exec switchns ip link set "$LAN_IFACE" up
        ip netns exec switchns ip link set "$LAN_IFACE" master br-switch
        echo -e "${GREEN}✓ $LAN_IFACE moved to switchns and added to br-switch${NC}"
    else
        echo -e "${YELLOW}⚠ Interface $LAN_IFACE not found, skipping${NC}"
    fi
fi

# DHCP for kidosns
ip netns exec kidosns dhclient -v -pf /tmp/dhclient-kidosns-br1.pid br1 || true
BR1_IP=$(ip netns exec kidosns ip -4 addr show br1 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || true)
[ -n "$BR1_IP" ] && echo -e "${GREEN}✓ kidosns IP: $BR1_IP${NC}"

echo "Setup complete!"
echo ""
[ -n "$BR_WAN_IP" ] && echo -e "${YELLOW}⚠ SSH reconnect needed: ssh user@$BR_WAN_IP${NC}"

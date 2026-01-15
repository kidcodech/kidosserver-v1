#!/bin/bash

set -e
set -x

# Detect physical interface
PHYSICAL_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)

if [ -z "$PHYSICAL_IFACE" ]; then
    echo "Error: Could not find an internet interface."
    exit 1
fi

echo "Detected Internet Interface: $PHYSICAL_IFACE"
echo "WARNING: This will temporarily disconnect your network"
sleep 2

echo "Cleaning up old state..."
set +e
pkill -f "dhclient"
ip netns del ns1 2>/dev/null
ip netns del ns2 2>/dev/null
ip link del br-test 2>/dev/null
rm -f /var/run/dhclient*.pid
set -e

echo "Creating namespaces..."
ip netns add ns1
ip netns add ns2

# Create bridge in root and attach physical interface
echo "Creating bridge in root..."
ip link add name br-test type bridge
ip link set br-test up
ip link set "$PHYSICAL_IFACE" master br-test
ip link set "$PHYSICAL_IFACE" up

# Create bridge in ns1
echo "Creating bridge in ns1..."
ip netns exec ns1 ip link add name br-ns1 type bridge
ip netns exec ns1 ip link set br-ns1 up
ip netns exec ns1 ip link set lo up

# Create veth pair between root and ns1
echo "Creating veth pair between root and ns1..."
ip link add veth-root type veth peer name veth-ns1
ip link set veth-root master br-test
ip link set veth-root up
ip link set veth-ns1 netns ns1
ip netns exec ns1 ip link set veth-ns1 master br-ns1
ip netns exec ns1 ip link set veth-ns1 up

# Create veth pair between ns1 and ns2
echo "Creating veth pair between ns1 and ns2..."
ip netns exec ns1 ip link add veth-ns1-ns2 type veth peer name veth-ns2 netns ns2
ip netns exec ns1 ip link set veth-ns1-ns2 master br-ns1
ip netns exec ns1 ip link set veth-ns1-ns2 up
ip netns exec ns2 ip link set veth-ns2 up
ip netns exec ns2 ip link set lo up

# Get DHCP for all (same subnet)
echo "Requesting DHCP for all namespaces..."
dhclient -v -pf /var/run/dhclient-root.pid br-test
ip netns exec ns1 dhclient -v -pf /var/run/dhclient-ns1.pid br-ns1
ip netns exec ns2 dhclient -v -pf /var/run/dhclient-ns2.pid veth-ns2

# Setup DNS
mkdir -p /etc/netns/ns1 /etc/netns/ns2
echo "nameserver 8.8.8.8" > /etc/netns/ns1/resolv.conf
echo "nameserver 8.8.8.8" > /etc/netns/ns2/resolv.conf

sleep 2

echo ""
echo "-------------------------------------"
echo "IP Addresses:"
echo "-------------------------------------"
echo "Root bridge:"
ip -4 addr show br-test | grep inet || echo "No IP yet"
echo "ns1 bridge:"
ip netns exec ns1 ip -4 addr show br-ns1 | grep inet || echo "No IP yet"
echo "ns2 veth-ns2:"
ip netns exec ns2 ip -4 addr show veth-ns2 | grep inet || echo "No IP yet"

echo ""
echo "-------------------------------------"
echo "Testing Ping to Google DNS (8.8.8.8)"
echo "-------------------------------------"

echo "Root:"
ping -c 2 8.8.8.8 || echo "Root Failed"

echo ""
echo "ns1:"
ip netns exec ns1 ping -c 2 8.8.8.8 || echo "ns1 Failed"

echo ""
echo "ns2:"
ip netns exec ns2 ping -c 2 8.8.8.8 || echo "ns2 Failed"

echo ""
echo "Setup complete!"

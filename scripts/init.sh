#!/bin/bash

set -x

# Create Ethernet namespace
echo "Creating Ethernet namespace (ethns)..."
ip netns add ethns

# Create Kidos namespace
echo "Creating Kidos namespace (kidosns)..."
ip netns add kidosns

# Create Apps namespace
echo "Creating Apps namespace (appsns)..."
ip netns add appsns

echo "All namespaces created successfully!"

# Move physical ethernet interface to ethernet namespace
echo "Moving enp0s31f6 to ethernet namespace..."
ip link set enp0s31f6 netns ethns

# Bring up the interface
echo "Bringing up enp0s31f6..."
ip netns exec ethns ip link set enp0s31f6 up

# Create bridge in ethernet namespace
echo "Creating bridge in ethernet namespace..."
ip netns exec ethns ip link add name br0 type bridge

# Add physical interface to bridge
echo "Adding enp0s31f6 to bridge..."
ip netns exec ethns ip link set enp0s31f6 master br0

# Create veth pair to connect ethernet and kidos namespaces
echo "Creating veth pair between ethernet and kidos namespaces..."
ip link add veth-eth type veth peer name veth-kidos

# Move one end to ethernet namespace
echo "Moving veth-eth to ethernet namespace..."
ip link set veth-eth netns ethns

# Add veth-eth to bridge
echo "Adding veth-eth to bridge..."
ip netns exec ethns ip link set veth-eth master br0

# Move other end to kidos namespace
echo "Moving veth-kidos to kidos namespace..."
ip link set veth-kidos netns kidosns

# Create bridge in kidos namespace
echo "Creating bridge in kidos namespace..."
ip netns exec kidosns ip link add name br1 type bridge

# Add veth-kidos to bridge
echo "Adding veth-kidos to bridge in kidos namespace..."
ip netns exec kidosns ip link set veth-kidos master br1

# Create veth pair to connect kidos and apps namespaces
echo "Creating veth pair between kidos and apps namespaces..."
ip link add veth-kidos-app type veth peer name veth-app

# Move one end to kidos namespace
echo "Moving veth-kidos-app to kidos namespace..."
ip link set veth-kidos-app netns kidosns

# Add veth-kidos-app to bridge
echo "Adding veth-kidos-app to bridge in kidos namespace..."
ip netns exec kidosns ip link set veth-kidos-app master br1

# Move other end to apps namespace
echo "Moving veth-app to apps namespace..."
ip link set veth-app netns appsns

# Bring up the interfaces
echo "Bringing up interfaces..."
ip netns exec ethns ip link set veth-eth up
ip netns exec ethns ip link set br0 up
ip netns exec kidosns ip link set veth-kidos up
ip netns exec kidosns ip link set veth-kidos-app up
ip netns exec kidosns ip link set br1 up
ip netns exec appsns ip link set veth-app up

# Run DHCP on bridges
echo "Requesting IP address via DHCP on ethernet bridge..."
ip netns exec ethns pkill dhclient 2>/dev/null || true
sleep 1
ip netns exec ethns dhclient br0

echo "Requesting IP address via DHCP on kidos bridge..."
ip netns exec kidosns pkill dhclient 2>/dev/null || true
sleep 1
ip netns exec kidosns dhclient br1

echo "Requesting IP address via DHCP on apps interface..."
ip netns exec appsns pkill dhclient 2>/dev/null || true
sleep 1
ip netns exec appsns dhclient veth-app

echo "Setup complete!"

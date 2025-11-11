#!/bin/bash

set -x

# Create monitoring namespace
echo "Creating monitoring namespace (monns)..."
ip netns add monns

# Create veth pair to connect kidos and monitoring namespaces
echo "Creating veth pair between kidos and monitoring namespaces..."
ip link add veth-mon-kidos type veth peer name veth-mon

# Move one end to kidos namespace
echo "Moving veth-mon-kidos to kidos namespace..."
ip link set veth-mon-kidos netns kidosns

# Move other end to monitoring namespace
echo "Moving veth-mon to monitoring namespace..."
ip link set veth-mon netns monns

# Bring up the interfaces
echo "Bringing up monitoring veth interfaces..."
ip netns exec kidosns ip link set veth-mon-kidos up
ip netns exec monns ip link set veth-mon up

# Set up tc mirroring on veth-kidos-app (ingress)
echo "Setting up tc ingress mirroring on veth-kidos-app..."
ip netns exec kidosns tc qdisc add dev veth-kidos-app ingress
ip netns exec kidosns tc filter add dev veth-kidos-app parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev veth-mon-kidos

# Set up tc mirroring on veth-kidos-app (egress)
echo "Setting up tc egress mirroring on veth-kidos-app..."
ip netns exec kidosns tc qdisc add dev veth-kidos-app root handle 1: prio
ip netns exec kidosns tc filter add dev veth-kidos-app parent 1: protocol all u32 match u32 0 0 action mirred egress mirror dev veth-mon-kidos

echo "Monitoring namespace setup complete!"

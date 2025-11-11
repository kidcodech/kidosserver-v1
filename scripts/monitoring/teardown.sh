#!/bin/bash

# Remove tc rules from veth-kidos-app
echo "Removing tc mirroring rules..."
ip netns exec kidosns tc qdisc del dev veth-kidos-app ingress 2>/dev/null || true
ip netns exec kidosns tc qdisc del dev veth-kidos-app root 2>/dev/null || true

# Delete monitoring namespace (this automatically removes all interfaces inside it)
echo "Deleting monitoring namespace..."
ip netns del monns 2>/dev/null || true

echo "Monitoring teardown complete!"

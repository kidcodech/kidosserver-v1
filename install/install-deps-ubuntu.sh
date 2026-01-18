#!/bin/bash

# Install all dependencies required for kidosserver-v1
# Run with: sudo ./install-deps.sh

set -e

echo "=== Installing Dependencies for Kidos Server v1 ==="

# Update package list
echo "Updating package list..."
apt-get update -y

# Install network utilities (usually already installed)
echo "Installing network utilities..."
apt-get install -y iproute2 isc-dhcp-client libpcap-dev iw hostapd

# Install eBPF/XDP dependencies
echo "Installing eBPF/XDP tools..."
apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) build-essential

# Install Go 1.21+ if not already installed
if ! command -v go &> /dev/null; then
    echo "Installing Go..."
    # Add PPA for newer Go versions or use snap
    apt-get install -y golang-go
else
    echo "Go already installed: $(go version)"
fi

# Install Node.js and npm if not already installed
if ! command -v node &> /dev/null; then
    echo "Installing Node.js and npm..."
    apt-get install -y nodejs npm
else
    echo "Node.js already installed: $(node --version)"
    echo "npm already installed: $(npm --version)"
fi

echo ""
echo "=== Dependencies Installed Successfully ==="
echo ""
echo "Next steps:"
echo "1. Run ./install/build-all.sh to build all components"
echo "2. Run sudo ./install/start-all.sh to start the system"

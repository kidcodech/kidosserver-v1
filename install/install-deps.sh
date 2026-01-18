#!/bin/bash

# Install all dependencies required for kidosserver-v1
# Run with: sudo ./install-deps.sh

set -e

echo "=== Installing Dependencies for Kidos Server v1 ==="

# Update package list
echo "Updating package list..."
dnf update -y

# Install network utilities (usually already installed)
echo "Installing network utilities..."
dnf install -y iproute dhcp-client libpcap-devel

# Install eBPF/XDP dependencies
echo "Installing eBPF/XDP tools..."
dnf install -y clang llvm libbpf-devel kernel-devel-$(uname -r)

# Install Go 1.21+ if not already installed
if ! command -v go &> /dev/null; then
    echo "Installing Go..."
    dnf install -y golang
else
    echo "Go already installed: $(go version)"
fi

# Install Node.js and npm if not already installed
if ! command -v node &> /dev/null; then
    echo "Installing Node.js and npm..."
    dnf install -y nodejs npm
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

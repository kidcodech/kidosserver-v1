#!/bin/bash

# Build all components of kidosserver-v1
# Run from project root: ./install/build-all.sh
# Note: Network namespaces setup (init.sh) is not included as it's infrastructure

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "=== Building Kidos Server v1 Components ==="
echo "Project root: $PROJECT_ROOT"
echo ""

# Check if we have internet connectivity
echo "Checking internet connectivity..."
if ! ping -c 1 -W 2 8.8.8.8 &> /dev/null; then
    echo "⚠ Warning: No internet connectivity detected!"
    echo "If namespaces are currently active, run: sudo ./scripts/teardown.sh"
    echo "This will restore your network interface to the default namespace."
    echo ""
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi
echo ""

# 1. Build eBPF program
echo "[1/4] Building eBPF XDP program..."
cd monitoring/ebpf
chmod +x build.sh
./build.sh
echo "✓ eBPF program built"
echo ""

# 2. Build Go sniffer daemon
echo "[2/4] Building Go packet sniffer..."
cd "$PROJECT_ROOT/monitoring/sniffer"
go mod tidy
go build -o sniffer main.go
echo "✓ Sniffer daemon built"
echo ""

# 3. Build Go webserver
echo "[3/4] Building Go webserver..."
cd "$PROJECT_ROOT/webserver"
go mod tidy
go build -o webserver main.go
echo "✓ Webserver built"
echo ""

# 4. Build React frontend
echo "[4/4] Building React frontend..."
cd "$PROJECT_ROOT/webserver/frontend"
npm install
npm run build
echo "✓ Frontend built"
echo ""

echo "=== All Components Built Successfully ==="
echo ""
echo "Binaries created:"
echo "  - monitoring/ebpf/xdp_afxdp.o (eBPF object)"
echo "  - monitoring/sniffer/sniffer (Go binary)"
echo "  - webserver/webserver (Go binary)"
echo "  - webserver/frontend/dist/ (React static files)"
echo ""
echo "Note: Run 'sudo ./scripts/init.sh' to set up network namespaces (one-time setup)"
echo "Then run 'sudo ./install/start-all.sh' to start the daemons"

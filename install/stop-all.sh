#!/bin/bash

# Stop all components of kidosserver-v1
# Must be run as root: sudo ./install/stop-all.sh

set -e

if [ "$EUID" -ne 0 ]; then 
    echo "Error: This script must be run as root"
    echo "Usage: sudo ./install/stop-all.sh"
    exit 1
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "=== Stopping Kidos Server v1 ==="
echo ""

# 1. Stop webserver - kill ALL webserver processes first
echo "[1/3] Stopping webserver..."
WEBSERVER_PIDS=$(pgrep -f "webserver" | grep -v "grep" || true)
if [ -n "$WEBSERVER_PIDS" ]; then
    echo "Found webserver processes: $WEBSERVER_PIDS"
    pkill -9 webserver
    echo "✓ All webserver processes killed"
else
    echo "✓ No webserver processes running"
fi
[ -f /tmp/kidos-webserver.pid ] && rm /tmp/kidos-webserver.pid
echo ""

# 2. Stop DNS inspector - kill ALL dns-inspector processes first
echo "[2/3] Stopping DNS inspector..."
DNS_PIDS=$(pgrep -f "parental/dns-inspector/dns-inspector" || true)
if [ -n "$DNS_PIDS" ]; then
    echo "Found DNS inspector processes: $DNS_PIDS"
    pkill -9 -f "parental/dns-inspector/dns-inspector"
    echo "✓ All DNS inspector processes killed"
else
    echo "✓ No DNS inspector processes running"
fi
[ -f /tmp/kidos-dns-inspector.pid ] && rm /tmp/kidos-dns-inspector.pid
echo ""

# 3. Stop sniffer - kill ALL sniffer processes first
echo "[3/3] Stopping packet sniffer..."
SNIFFER_PIDS=$(pgrep -f "monitoring/sniffer/sniffer" || true)
if [ -n "$SNIFFER_PIDS" ]; then
    echo "Found sniffer processes: $SNIFFER_PIDS"
    pkill -9 -f "monitoring/sniffer/sniffer"
    echo "✓ All sniffer processes killed"
else
    echo "✓ No sniffer processes running"
fi
[ -f /tmp/kidos-sniffer.pid ] && rm /tmp/kidos-sniffer.pid

echo ""

# Remove XDP programs
if ip netns list | grep -q "monns"; then
    ip netns exec monns ip link set veth-mon xdp off 2>/dev/null || true
fi

if ip netns list | grep -q "kidosns"; then
    ip netns exec kidosns ip link set veth-kidos-app xdp off 2>/dev/null || true
    ip netns exec kidosns ip link set veth-kidos-app xdpgeneric off 2>/dev/null || true
fi

echo "=== Kidos Server v1 Stopped Successfully ==="
echo ""
echo "Network namespaces are still active. To tear them down, run:"
echo "  sudo ./scripts/teardown.sh"
echo ""
echo "Logs preserved:"
echo "  Sniffer: /tmp/kidos-sniffer.log"
echo "  Webserver: /tmp/kidos-webserver.log"

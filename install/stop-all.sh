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

# 1. Stop webserver
echo "[1/3] Stopping webserver..."
if [ -f /tmp/kidos-webserver.pid ]; then
    WEBSERVER_PID=$(cat /tmp/kidos-webserver.pid)
    if kill -0 "$WEBSERVER_PID" 2>/dev/null; then
        kill "$WEBSERVER_PID"
        echo "✓ Webserver stopped (PID: $WEBSERVER_PID)"
    else
        echo "✓ Webserver already stopped"
    fi
    rm /tmp/kidos-webserver.pid
else
    echo "✓ No webserver PID file found"
fi
echo ""

# 2. Stop DNS inspector
echo "[2/3] Stopping DNS inspector..."
if [ -f /tmp/kidos-dns-inspector.pid ]; then
    DNS_INSPECTOR_PID=$(cat /tmp/kidos-dns-inspector.pid)
    if kill -0 "$DNS_INSPECTOR_PID" 2>/dev/null; then
        kill "$DNS_INSPECTOR_PID"
        echo "✓ DNS inspector stopped (PID: $DNS_INSPECTOR_PID)"
    else
        echo "✓ DNS inspector already stopped"
    fi
    rm /tmp/kidos-dns-inspector.pid
else
    echo "✓ No DNS inspector PID file found"
fi
echo ""

# 3. Stop sniffer
echo "[3/3] Stopping packet sniffer..."
if [ -f /tmp/kidos-sniffer.pid ]; then
    SNIFFER_PID=$(cat /tmp/kidos-sniffer.pid)
    if kill -0 "$SNIFFER_PID" 2>/dev/null; then
        kill "$SNIFFER_PID"
        echo "✓ Sniffer stopped (PID: $SNIFFER_PID)"
    else
        echo "✓ Sniffer already stopped"
    fi
    rm /tmp/kidos-sniffer.pid
else
    echo "✓ No sniffer PID file found"
fi
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

#!/bin/bash

# Start all components of kidosserver-v1
# Must be run as root: sudo ./install/start-all.sh

set -e

if [ "$EUID" -ne 0 ]; then 
    echo "Error: This script must be run as root"
    echo "Usage: sudo ./install/start-all.sh"
    exit 1
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "=== Starting Kidos Server v1 ==="
echo "Project root: $PROJECT_ROOT"
echo ""

# Check if binaries exist
if [ ! -f "monitoring/sniffer/sniffer" ]; then
    echo "Error: Sniffer binary not found. Run ./install/build-all.sh first"
    exit 1
fi

if [ ! -f "webserver/webserver" ]; then
    echo "Error: Webserver binary not found. Run ./install/build-all.sh first"
    exit 1
fi

if [ ! -d "webserver/frontend/dist" ]; then
    echo "Error: Frontend build not found. Run ./install/build-all.sh first"
    exit 1
fi

# Check if namespaces exist
if ! ip netns list | grep -q "monns"; then
    echo "Error: Network namespaces not found. Run 'sudo ./scripts/init.sh' first"
    exit 1
fi

# 1. Start packet sniffer in monitoring namespace
echo "[1/2] Starting packet sniffer daemon..."
# Remove any existing XDP program first
ip netns exec monns ip link set veth-mon xdp off 2>/dev/null || true
ip netns exec monns "$PROJECT_ROOT/monitoring/sniffer/sniffer" > /tmp/kidos-sniffer.log 2>&1 &
SNIFFER_PID=$!
echo "✓ Sniffer started (PID: $SNIFFER_PID)"
echo "  Logs: /tmp/kidos-sniffer.log"
echo ""

# Wait a moment for sniffer to initialize
sleep 2

# 2. Start webserver
echo "[2/2] Starting web server..."
cd "$PROJECT_ROOT/webserver"
./webserver > /tmp/kidos-webserver.log 2>&1 &
WEBSERVER_PID=$!
echo "✓ Webserver started (PID: $WEBSERVER_PID)"
echo "  Logs: /tmp/kidos-webserver.log"
echo ""

# Save PIDs for stop script
echo "$SNIFFER_PID" > /tmp/kidos-sniffer.pid
echo "$WEBSERVER_PID" > /tmp/kidos-webserver.pid

echo "=== Kidos Server v1 Started Successfully ==="
echo ""
echo "Access the monitoring dashboard at: http://localhost:8080"
echo ""
echo "To generate test traffic:"
echo "  sudo ip netns exec appsns ping 8.8.8.8"
echo ""
echo "To stop the system:"
echo "  sudo ./install/stop-all.sh"
echo ""
echo "Process IDs saved:"
echo "  Sniffer: $SNIFFER_PID"
echo "  Webserver: $WEBSERVER_PID"

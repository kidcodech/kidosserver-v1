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

# First, stop any running instances
echo "Stopping any running instances..."
"$PROJECT_ROOT/install/stop-all.sh" 2>/dev/null || true
echo ""

# Check if binaries exist
if [ ! -f "monitoring/sniffer/sniffer" ]; then
    echo "Error: Sniffer binary not found. Run ./install/build-all.sh first"
    exit 1
fi

if [ ! -f "parental/dns-inspector/dns-inspector" ]; then
    echo "Error: DNS inspector binary not found. Run ./install/build-all.sh first"
    exit 1
fi

if [ ! -f "parental/ip-filter/ip-filter-sync" ]; then
    echo "Error: IP filter sync daemon not found. Run ./install/build-all.sh first"
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

if ! ip netns list | grep -q "kidosns"; then
    echo "Error: kidosns namespace not found. Run 'sudo ./scripts/init.sh' first"
    exit 1
fi

# 1. Start packet sniffer in monitoring namespace
echo "[1/3] Starting packet sniffer daemon..."
# Remove any existing XDP program first
ip netns exec monns ip link set veth-mon xdp off 2>/dev/null || true
ip netns exec monns "$PROJECT_ROOT/monitoring/sniffer/sniffer" > /tmp/kidos-sniffer.log 2>&1 &
SNIFFER_PID=$!
echo "✓ Sniffer started (PID: $SNIFFER_PID)"
echo "  Logs: /tmp/kidos-sniffer.log"
echo ""

# Wait a moment for sniffer to initialize
sleep 2

# 2. Load combined XDP program (IP filter + DNS redirection)
echo "[2/4] Loading combined XDP program (IP filter + DNS inspector)..."
# Remove any existing XDP programs first
ip netns exec kidosns ip link set veth-kidos-app xdp off 2>/dev/null || true
ip netns exec kidosns ip link set veth-kidos-app xdpgeneric off 2>/dev/null || true
# Load combined IP filter XDP (includes xsks_map for DNS)
ip netns exec kidosns ip link set veth-kidos-app xdp obj "$PROJECT_ROOT/parental/ip-filter/xdp_ip_filter.o" sec xdp
echo "✓ Combined XDP program loaded"
echo ""

# Wait for XDP to attach
sleep 1

# 3. Start DNS inspector daemon (will find xsks_map and register AF_XDP socket)
echo "[3/4] Starting DNS inspector daemon..."
ip netns exec kidosns "$PROJECT_ROOT/parental/dns-inspector/dns-inspector" veth-kidos-app > /tmp/kidos-dns-inspector.log 2>&1 &
DNS_INSPECTOR_PID=$!
echo "✓ DNS inspector started (PID: $DNS_INSPECTOR_PID)"
echo "  Logs: /tmp/kidos-dns-inspector.log"
echo ""

# Wait for DNS inspector to initialize
sleep 2

# 4. Start IP filter sync daemon (will find maps and sync registered IPs)
echo "[4/4] Starting IP filter sync daemon..."
"$PROJECT_ROOT/parental/ip-filter/ip-filter-sync" > /tmp/kidos-ip-filter.log 2>&1 &
IP_FILTER_PID=$!
echo "✓ IP filter sync daemon started (PID: $IP_FILTER_PID)"
echo "  Logs: /tmp/kidos-ip-filter.log"
echo ""

# Wait for IP filter to initialize
sleep 2
cd "$PROJECT_ROOT/webserver"
ip netns exec kidosns ./webserver > /tmp/kidos-webserver.log 2>&1 &
WEBSERVER_PID=$!
echo "✓ Webserver started (PID: $WEBSERVER_PID)"
echo "  Logs: /tmp/kidos-webserver.log"
echo ""

# Get br1 IP for user information
BR1_IP=$(ip netns exec kidosns ip -4 addr show br1 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

# Save PIDs for stop script
echo "$SNIFFER_PID" > /tmp/kidos-sniffer.pid
echo "$DNS_INSPECTOR_PID" > /tmp/kidos-dns-inspector.pid
echo "$IP_FILTER_PID" > /tmp/kidos-ip-filter.pid
echo "$WEBSERVER_PID" > /tmp/kidos-webserver.pid

echo "=== Kidos Server v1 Started Successfully ==="
echo ""
echo "Access the monitoring dashboard at:"
echo "  http://router.kidos.tools/"
if [ -n "$BR1_IP" ]; then
    echo "  (resolves to $BR1_IP)"
fi
echo ""
echo "Device registration (for clients):"
echo "  http://router.kidos.tools/auth"
echo ""
echo "Captive portal for blocked domains:"
echo "  http://router.kidos.tools/blocked"
echo ""
echo "To generate test traffic:"
echo "  sudo ip netns exec appsns ping 8.8.8.8"
echo "  sudo ip netns exec appsns nslookup example.com 8.8.8.8"
echo ""
echo "To stop the system:"
echo "  sudo ./install/stop-all.sh"
echo ""
echo "Process IDs saved:"
echo "  Sniffer: $SNIFFER_PID"
echo "  DNS Inspector: $DNS_INSPECTOR_PID"
echo "  IP Filter: $IP_FILTER_PID"
echo "  Webserver: $WEBSERVER_PID"

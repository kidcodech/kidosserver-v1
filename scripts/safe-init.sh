#!/bin/bash
# safe-init.sh - Run init.sh with automatic IP restoration on failure

set -e

# Detect active interface and IP
ACTIVE_IFACE=$(ip route get 8.8.8.8 | grep -oP 'dev \K\S+')
ACTIVE_IP=$(ip -4 addr show "$ACTIVE_IFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\d+' | head -n1)
GATEWAY=$(ip route | grep default | awk '{print $3}')

if [ -z "$ACTIVE_IFACE" ] || [ -z "$ACTIVE_IP" ]; then
    echo "ERROR: Could not detect active interface or IP"
    exit 1
fi

echo "Active interface: $ACTIVE_IFACE"
echo "Active IP: $ACTIVE_IP"
echo "Gateway: $GATEWAY"
echo ""
echo "Safety mechanism: If connection drops for >60s, IP will be auto-restored"
echo "Press Ctrl+C in 5 seconds to cancel..."
sleep 5

# Create restoration script
cat > /tmp/restore-network.sh << EOF
#!/bin/bash
# Auto-restore network if init.sh fails
sleep 60
if ! ip addr show br-host 2>/dev/null | grep -q inet; then
    echo "\$(date): Init failed, restoring original IP" >> /tmp/network-restore.log
    ip link set $ACTIVE_IFACE nomaster 2>/dev/null || true
    ip link del br-host 2>/dev/null || true
    ip addr add $ACTIVE_IP dev $ACTIVE_IFACE 2>/dev/null || true
    ip route add default via $GATEWAY 2>/dev/null || true
    dhclient $ACTIVE_IFACE 2>/dev/null || true
    echo "\$(date): Restoration complete" >> /tmp/network-restore.log
fi
rm -f /tmp/restore-network.sh
EOF

chmod +x /tmp/restore-network.sh

# Start watchdog in background
echo "Starting safety watchdog..."
nohup /tmp/restore-network.sh > /dev/null 2>&1 &
WATCHDOG_PID=$!
echo "Watchdog PID: $WATCHDOG_PID"

# Run init.sh
echo ""
echo "Running init.sh..."
./scripts/init.sh

# If we get here, init succeeded
echo ""
echo "Init completed successfully!"
echo "Killing watchdog..."
kill $WATCHDOG_PID 2>/dev/null || true
rm -f /tmp/restore-network.sh

echo ""
echo "New network status:"
ip addr show br-host | grep inet
echo ""
echo "If you can read this, you're still connected!"

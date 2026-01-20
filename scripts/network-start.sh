#!/bin/bash

set -e

# Load configuration
CONFIG_FILE="/etc/kidos/config"
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
fi

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Starting Kidos network configuration..."

# 1. Connect Ethernet
if [ -n "$ETHERNET_INTERFACE" ]; then
    echo "Using configured ethernet interface: $ETHERNET_INTERFACE"
    IFACE="$ETHERNET_INTERFACE"
else
    echo "Auto-detecting ethernet interface..."
    # Find first available ethernet interface
    IFACE=$(ip link show | grep -E '^[0-9]+: (en|eth)' | grep -v '@' | awk -F': ' '{print $2}' | awk '{print $1}' | head -n1)
    
    if [ -z "$IFACE" ]; then
        echo -e "${RED}✗ No ethernet interface found${NC}"
        echo "Continuing without network..."
        exit 0
    fi
    
    echo "Found ethernet interface: $IFACE"
    
    # Save to config for next boot
    mkdir -p /etc/kidos
    if [ ! -f "$CONFIG_FILE" ]; then
        cp "$SCRIPT_DIR/../systemd/kidos.conf.example" "$CONFIG_FILE"
    fi
    sed -i "s/^ETHERNET_INTERFACE=.*/ETHERNET_INTERFACE=\"$IFACE\"/" "$CONFIG_FILE" || true
fi

# Connect ethernet interface
if [ -n "$IFACE" ]; then
    echo "Connecting $IFACE to ethns..."
    "$SCRIPT_DIR/connect-interface.sh" "$IFACE" || {
        echo -e "${YELLOW}⚠ Failed to connect ethernet, continuing anyway${NC}"
    }
fi

# 2. Start Hotspot if enabled
if [ "$HOTSPOT_AUTOSTART" = "true" ]; then
    echo "Auto-starting WiFi hotspot..."
    "$SCRIPT_DIR/hotspot/init.sh" "${HOTSPOT_SSID:-KidosNet}" "${HOTSPOT_PASSWORD:-kidos123}" "${HOTSPOT_CHANNEL:-6}" || {
        echo -e "${YELLOW}⚠ Failed to start hotspot, continuing anyway${NC}"
    }
fi

echo -e "${GREEN}✓ Network configuration complete${NC}"

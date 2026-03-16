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

# Ethernet is now connected automatically during init.sh
# This script only handles optional hotspot autostart

# Start Hotspot if enabled
if [ "$HOTSPOT_AUTOSTART" = "true" ]; then
    echo "Auto-starting WiFi hotspot..."
    "$SCRIPT_DIR/hotspot/init.sh" "${HOTSPOT_SSID:-KidosNet}" "${HOTSPOT_PASSWORD:-kidos123}" "${HOTSPOT_CHANNEL:-6}" || {
        echo -e "${YELLOW}⚠ Failed to start hotspot, continuing anyway${NC}"
    }
fi

echo -e "${GREEN}✓ Network configuration complete${NC}"

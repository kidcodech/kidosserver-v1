#!/bin/bash

set -e

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Usage: sudo $0"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Installing Kidos systemd services..."

# Make scripts executable
chmod +x "$PROJECT_ROOT/scripts/init.sh"
chmod +x "$PROJECT_ROOT/scripts/teardown.sh"
chmod +x "$PROJECT_ROOT/scripts/connect-interface.sh"
chmod +x "$PROJECT_ROOT/scripts/network-start.sh"
chmod +x "$PROJECT_ROOT/scripts/hotspot/init.sh"
chmod +x "$PROJECT_ROOT/scripts/hotspot/teardown.sh"

# Create config directory
mkdir -p /etc/kidos

# Copy default config if it doesn't exist
if [ ! -f /etc/kidos/config ]; then
    echo "Creating default configuration..."
    cp "$PROJECT_ROOT/systemd/kidos.conf.example" /etc/kidos/config
    echo -e "${GREEN}✓ Created /etc/kidos/config${NC}"
    echo -e "${YELLOW}  Edit this file to configure your system${NC}"
else
    echo "Configuration file already exists: /etc/kidos/config"
fi

# Update service files with actual paths
echo "Installing systemd service files..."
for service in kidos-init kidos-network kidos-webserver kidos-dns-inspector kidos-sniffer kidos-ip-filter; do
    sed "s|/home/aigarssu/kidos/kidosserver-v1|$PROJECT_ROOT|g" \
        "$PROJECT_ROOT/systemd/$service.service" > "/etc/systemd/system/$service.service"
    echo -e "${GREEN}✓ Installed $service.service${NC}"
done

# Install udev rule for auto-connect on plug
echo "Installing udev rule for ethernet hotplug..."
cp "$PROJECT_ROOT/systemd/80-kidos-network.rules" /etc/udev/rules.d/
echo -e "${GREEN}✓ Installed udev rule for ethernet hotplug${NC}"

# Reload udev and systemd
echo "Reloading udev rules..."
udevadm control --reload-rules
udevadm trigger

echo "Reloading systemd daemon..."
systemctl daemon-reload

# Enable services
echo "Enabling services..."
systemctl enable kidos-init.service
systemctl enable kidos-network.service
systemctl enable kidos-webserver.service
systemctl enable kidos-dns-inspector.service
systemctl enable kidos-sniffer.service
systemctl enable kidos-ip-filter.service

echo ""
echo -e "${GREEN}✓ Kidos systemd services installed successfully!${NC}"
echo ""
echo "Services installed:"
echo "  • kidos-init         - Network namespaces initialization"
echo "  • kidos-network      - Ethernet and WiFi hotspot"
echo "  • kidos-webserver    - Web interface"
echo "  • kidos-dns-inspector - DNS filtering"
echo "  • kidos-sniffer      - Network monitoring"
echo "  • kidos-ip-filter    - IP filtering"
echo ""
echo "Configuration: /etc/kidos/config"
echo ""
echo "Commands:"
echo "  Start all:    sudo systemctl start kidos-init kidos-network kidos-webserver kidos-dns-inspector kidos-sniffer kidos-ip-filter"
echo "  Stop all:     sudo systemctl stop kidos-ip-filter kidos-sniffer kidos-dns-inspector kidos-webserver kidos-network kidos-init"
echo "  Status:       sudo systemctl status kidos-*"
echo "  View logs:    sudo journalctl -u kidos-webserver -f"
echo "  Restart:      sudo systemctl restart kidos-webserver"
echo ""
echo "Services will start automatically on next boot."
echo "To start now: sudo systemctl start kidos-init kidos-network"

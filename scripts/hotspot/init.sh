#!/bin/bash

# Configuration
IFACE=${1:-wlp0s20f0u1}
SSID="KidosNet"
PASSWORD=${HOTSPOT_PASSWORD:-"kidos123"}

set -e

# Helper to checking/installing hostapd
if ! command -v hostapd &> /dev/null; then
    echo "hostapd not found. Attempting to install..."
    if [ -f /etc/redhat-release ]; then
        yum install -y hostapd
    elif [ -f /etc/debian_version ]; then
        apt-get update && apt-get install -y hostapd
    else
        echo "Error: hostapd not found and cannot detect package manager. Please install hostapd."
        exit 1
    fi
fi

# Cleanup
./scripts/hotspot/teardown.sh 2>/dev/null || true

# Reload kernel modules to ensure clean state (fixes firmware crashes)
echo "Reloading Wi-Fi driver modules..."
modprobe -r rtw88_8822bu || true
modprobe -r rtw88_usb || true
modprobe rtw88_8822bu

# Wait for interface to reappear
echo "Waiting for Wi-Fi interface to initialize..."
timeout=10
while ! ip link show "$IFACE" >/dev/null 2>&1; do
    sleep 1
    timeout=$((timeout-1))
    if [ "$timeout" -le 0 ]; then
        echo "Error: Interface $IFACE failed to appear after module reload"
        exit 1
    fi
done

echo "Setting up Kidos Hotspot in namespace 'wifins' (L2 Bridge Mode)..."

# 1. Prepare Namespaces
# Create wifins
ip netns add wifins

# 2. Network Layout
# Link wifins <-> switchns
echo "Connecting wifins to switchns..."
ip link add veth-wifi type veth peer name veth-wifi-sw
ip link set veth-wifi netns wifins
ip link set veth-wifi-sw netns switchns
ip netns exec switchns ip link set veth-wifi-sw master br-switch
ip netns exec switchns ip link set veth-wifi-sw up

# Create bridge in wifins
echo "Creating bridge br-wifi in wifins..."
ip netns exec wifins ip link add name br-wifi type bridge
# Add the uplink to the bridge
ip netns exec wifins ip link set veth-wifi master br-wifi
ip netns exec wifins ip link set veth-wifi up
ip netns exec wifins ip link set br-wifi up

# Move WiFi adapter to wifins
echo "Moving $IFACE to wifins..."
# Stop NetworkManager from managing it just in case
nmcli device set "$IFACE" managed no 2>/dev/null || true

# Try moving via iw phy (more reliable for wifi)
PHY=$(iw dev "$IFACE" info | grep wiphy | awk '{print $2}')
if [ -n "$PHY" ]; then
    echo "Detected PHY: phy$PHY"
    iw phy "phy$PHY" set netns name wifins
else
    # Fallback to ip link
    ip link set "$IFACE" netns wifins
fi

# We need to find the new interface name inside the namespace
NEW_IFACE=$(ip netns exec wifins ip link | grep -E "^[0-9]+: w" | awk -F: '{print $2}' |  awk '{print $1}' | head -n1)

if [ -z "$NEW_IFACE" ]; then
    echo "Error: Could not find wifi interface in wifins"
    exit 1
fi

echo "Interface in wifins is: $NEW_IFACE"
# hostapd will add the interface to the bridge automatically
ip netns exec wifins ip link set "$NEW_IFACE" up

# 3. Hostapd Configuration
echo "Generating hostapd config..."
cat <<EOF > /tmp/kidos-hostapd.conf
interface=$NEW_IFACE
bridge=br-wifi
driver=nl80211
ssid=$SSID
hw_mode=g
channel=6
wpa=2
wpa_passphrase=$PASSWORD
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
ieee80211n=1
wmm_enabled=1
EOF

# 4. Start Services
echo "Starting hostapd..."
# Run in background
ip netns exec wifins hostapd -B /tmp/kidos-hostapd.conf

echo "Waiting for hostapd to settle..."
sleep 2

echo "✓ Hotspot '$SSID' started in wifins."
echo "  Configuration: L2 Bridge (AP Mode) -> switchns -> kidosns -> ethns."
echo "  Clients will receive DHCP from the main router via WIRE (ethns)."

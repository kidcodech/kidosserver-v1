#!/bin/bash

# Configuration
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

# Detect USB Wi-Fi dongles (exclude internal Wi-Fi)
echo "Detecting USB Wi-Fi dongles..."
USB_WIFI_DEVICES=$(lsusb | grep -iE "802\.11|wifi|wireless|wlan|rtl|realtek|ralink|atheros|mediatek|tp-link" || true)

if [ -z "$USB_WIFI_DEVICES" ]; then
    echo "Error: No USB Wi-Fi dongle detected"
    echo "Available USB devices:"
    lsusb
    exit 1
fi

echo "Found USB Wi-Fi devices:"
echo "$USB_WIFI_DEVICES"

# Detect chipset and determine driver
DRIVER_MODULE=""
if echo "$USB_WIFI_DEVICES" | grep -q "RTL8822BU\|8822bu"; then
    DRIVER_MODULE="rtw88_8822bu"
    echo "Detected RTL8822BU chipset"
elif echo "$USB_WIFI_DEVICES" | grep -q "RTL8821AU\|8821au\|2357:0120"; then
    DRIVER_MODULE="rtw88_8821au"
    echo "Detected RTL8821AU chipset (Archer T2U PLUS)"
elif echo "$USB_WIFI_DEVICES" | grep -q "RTL88"; then
    DRIVER_MODULE="rtw88_usb"
    echo "Detected RTL88xx series chipset"
else
    echo "Warning: Unknown chipset, will try generic drivers"
    DRIVER_MODULE="rtw88_usb"
fi

# Reload kernel modules to ensure clean state (fixes firmware crashes)
echo "Reloading Wi-Fi driver modules for $DRIVER_MODULE..."
modprobe -r rtw88_8822bu 2>/dev/null || true
modprobe -r rtw88_8821au 2>/dev/null || true
modprobe -r rtw88_usb 2>/dev/null || true
modprobe -r rtw_usb 2>/dev/null || true
sleep 1

# Load the detected driver
if [ -n "$DRIVER_MODULE" ]; then
    modprobe "$DRIVER_MODULE" 2>/dev/null || modprobe rtw88_usb 2>/dev/null || modprobe rtw_usb 2>/dev/null || true
else
    modprobe rtw88_usb 2>/dev/null || modprobe rtw_usb 2>/dev/null || true
fi

# Wait for USB interface to appear (exclude internal Wi-Fi)
echo "Waiting for USB Wi-Fi interface to initialize..."
IFACE=""
timeout=10
while [ "$timeout" -gt 0 ]; do
    # Find wireless interfaces with 'u' in name (USB) or via sysfs check
    for iface in $(iw dev 2>/dev/null | grep Interface | awk '{print $2}' || true); do
        # Check if it's a USB device (interface name contains 'u' like wlp0s20f0u1)
        if echo "$iface" | grep -q "u[0-9]"; then
            IFACE="$iface"
            echo "✓ Found USB wireless interface: $IFACE"
            break 2
        fi
    done
    sleep 1
    timeout=$((timeout-1))
done

if [ -z "$IFACE" ]; then
    echo "Error: No USB wireless interface found after module reload"
    echo "Available wireless interfaces:"
    iw dev 2>/dev/null || true
    echo ""
    echo "Available network interfaces:"
    ip link show | grep -E "^[0-9]+:"
    exit 1
fi

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

# Setup DNS for wifins
echo "Configuring DNS for wifins..."
mkdir -p /etc/netns/wifins
echo "nameserver 8.8.8.8" > /etc/netns/wifins/resolv.conf
echo "hosts: files dns" > /etc/netns/wifins/nsswitch.conf

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

echo "Waiting for hostapd to fully initialize the bridge..."
sleep 3

# Request IP for br-wifi bridge via DHCP
echo "Requesting IP address for br-wifi bridge via DHCP..."
ip netns exec wifins pkill dhclient 2>/dev/null || true
sleep 1
# Run dhclient in foreground to wait for completion
ip netns exec wifins dhclient -v br-wifi
sleep 1

# Check if IP was assigned
WIFI_BR_IP=$(ip netns exec wifins ip -4 addr show br-wifi | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || true)
if [ -n "$WIFI_BR_IP" ]; then
    echo "✓ Got IP via DHCP for br-wifi: $WIFI_BR_IP"
else
    echo "✗ Failed to get DHCP IP for br-wifi"
    echo "Debug: Bridge state in wifins:"
    ip netns exec wifins ip link show br-wifi
    echo "Debug: Bridge members in switchns:"
    ip netns exec switchns bridge link show br-switch | grep veth-wifi-sw || echo "veth-wifi-sw not in br-switch!"
fi

echo "✓ Hotspot '$SSID' started in wifins."
echo "  Configuration: L2 Bridge (AP Mode) -> switchns -> kidosns -> ethns."
echo "  Clients will receive DHCP from the main router via WIRE (ethns)."

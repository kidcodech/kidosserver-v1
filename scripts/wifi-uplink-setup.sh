#!/bin/bash
# Reference commands for setting up Wi-Fi uplink in ethns
# Usage: Run these commands manually or adapt as needed

WIFI_IFACE="wlp0s20f0u3"
WIFI_SSID="Robnet"
WIFI_PASSWORD="zakisUNkakis555"
ETHNS_VETH_IP="192.168.68.69/22"
KIDOSNS_BR_IP="192.168.68.70/22"

echo "=== Step 1: Move Wi-Fi interface to ethns ==="
PHY=$(iw dev "$WIFI_IFACE" info | grep wiphy | awk '{print $2}')
sudo iw phy "phy$PHY" set netns name ethns

echo "=== Step 2: Bring up Wi-Fi interface in ethns ==="
sudo ip netns exec ethns ip link set "$WIFI_IFACE" up

echo "=== Step 3: Create wpa_supplicant config and connect to AP ==="
sudo ip netns exec ethns wpa_passphrase "$WIFI_SSID" "$WIFI_PASSWORD" > /tmp/wpa_supplicant_ethns.conf
sudo ip netns exec ethns wpa_supplicant -B -i "$WIFI_IFACE" -c /tmp/wpa_supplicant_ethns.conf

echo "=== Step 4: Wait for connection and get DHCP ==="
sleep 3
sudo ip netns exec ethns pkill dhclient 2>/dev/null || true
sleep 1
sudo ip netns exec ethns dhclient -v "$WIFI_IFACE"

echo "=== Step 5: Remove bridge from ethns (if exists) ==="
sudo ip netns exec ethns ip link set enp1s0 nomaster 2>/dev/null || true
sudo ip netns exec ethns ip link set veth-eth nomaster 2>/dev/null || true
sudo ip netns exec ethns ip link del br0 2>/dev/null || true

echo "=== Step 6: Configure veth-eth in ethns ==="
sudo ip netns exec ethns ip addr add "$ETHNS_VETH_IP" dev veth-eth

echo "=== Step 7: Enable IP forwarding and proxy ARP in ethns ==="
sudo ip netns exec ethns sysctl -w net.ipv4.ip_forward=1
sudo ip netns exec ethns sysctl -w net.ipv4.conf.wlp0s20f0u3.proxy_arp=1
sudo ip netns exec ethns sysctl -w net.ipv4.conf.veth-eth.proxy_arp=1

echo "=== Step 8: Clean old IPs from br1 in kidosns ==="
sudo ip netns exec kidosns pkill dhclient 2>/dev/null || true
sudo ip netns exec kidosns ip addr del 192.168.8.138/24 dev br1 2>/dev/null || true
sudo ip netns exec kidosns ip addr del 192.168.8.235/24 dev br1 2>/dev/null || true
sudo ip netns exec kidosns ip addr del 192.168.8.141/24 dev br1 2>/dev/null || true

echo "=== Step 9: Configure br1 in kidosns ==="
sudo ip netns exec kidosns ip addr add "$KIDOSNS_BR_IP" dev br1

echo "=== Step 10: Add route in ethns for kidosns ==="
sudo ip netns exec ethns ip route add 192.168.68.70 dev veth-eth

echo "=== Step 11: Configure routing in kidosns ==="
sudo ip netns exec kidosns ip route del default 2>/dev/null || true
sudo ip netns exec kidosns ip route add default via 192.168.68.69 dev br1

echo "=== Step 12: Test connectivity ==="
echo "Testing ping from kidosns to 8.8.8.8..."
sudo ip netns exec kidosns ping -c 2 8.8.8.8

echo "✓ Setup complete!"

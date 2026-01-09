#!/bin/bash

set -x

# Create Ethernet namespace
echo "Creating Ethernet namespace (ethns)..."
ip netns add ethns

# Create Kidos namespace
echo "Creating Kidos namespace (kidosns)..."
ip netns add kidosns

# Create Switch namespace
echo "Creating Switch namespace (switchns)..."
ip netns add switchns

# Create Apps namespace
echo "Creating Apps namespace (appsns)..."
ip netns add appsns

# Create Apps namespace 2
echo "Creating Apps namespace 2 (appsns2)..."
ip netns add appsns2

echo "All namespaces created successfully!"

# Move physical ethernet interface to ethernet namespace
echo "Moving enp0s31f6 to ethernet namespace..."
ip link set enp0s31f6 netns ethns

# Bring up the interface
echo "Bringing up enp0s31f6..."
ip netns exec ethns ip link set enp0s31f6 up

# Create bridge in ethernet namespace
echo "Creating bridge in ethernet namespace..."
ip netns exec ethns ip link add name br0 type bridge

# Add physical interface to bridge
echo "Adding enp0s31f6 to bridge..."
ip netns exec ethns ip link set enp0s31f6 master br0

# Create veth pair to connect ethernet and kidos namespaces
echo "Creating veth pair between ethernet and kidos namespaces..."
ip netns exec ethns ip link add veth-eth type veth peer name veth-kidos netns kidosns

# Add veth-eth to bridge
echo "Adding veth-eth to bridge..."
ip netns exec ethns ip link set veth-eth master br0

# Create bridge in kidos namespace
echo "Creating bridge in kidos namespace..."
ip netns exec kidosns ip link add name br1 type bridge

# Add veth-kidos to bridge
echo "Adding veth-kidos to bridge in kidos namespace..."
ip netns exec kidosns ip link set veth-kidos master br1

# Create bridge in switch namespace
echo "Creating bridge in switch namespace..."
ip netns exec switchns ip link add name br-switch type bridge

# Create veth pair to connect kidos and switch namespaces
echo "Creating veth pair between kidos and switch namespaces..."
ip netns exec kidosns ip link add veth-kidos-app type veth peer name veth-sw netns switchns

# Add veth-kidos-app to bridge in kidos
echo "Adding veth-kidos-app to bridge in kidos namespace..."
ip netns exec kidosns ip link set veth-kidos-app master br1

# Add veth-sw to bridge in switch
echo "Adding veth-sw to bridge in switch namespace..."
ip netns exec switchns ip link set veth-sw master br-switch

# Create veth pair to connect switch and apps namespaces
echo "Creating veth pair between switch and apps namespaces..."
ip netns exec switchns ip link add veth-sw-app type veth peer name veth-app netns appsns

# Add veth-sw-app to bridge in switch
echo "Adding veth-sw-app to bridge in switch namespace..."
ip netns exec switchns ip link set veth-sw-app master br-switch

# Create veth pair to connect switch and apps2 namespaces
echo "Creating veth pair between switch and apps2 namespaces..."
ip netns exec switchns ip link add veth-sw-app2 type veth peer name veth-app netns appsns2

# Add veth-sw-app2 to bridge in switch
echo "Adding veth-sw-app2 to bridge in switch namespace..."
ip netns exec switchns ip link set veth-sw-app2 master br-switch

# Bring up the interfaces
echo "Bringing up interfaces..."
ip netns exec ethns ip link set veth-eth up
ip netns exec ethns ip link set br0 up
ip netns exec kidosns ip link set veth-kidos up
ip netns exec kidosns ip link set veth-kidos-app up
ip netns exec kidosns ip link set br1 up
ip netns exec switchns ip link set veth-sw up
ip netns exec switchns ip link set veth-sw-app up
ip netns exec switchns ip link set veth-sw-app2 up
ip netns exec switchns ip link set br-switch up
ip netns exec appsns ip link set veth-app up
ip netns exec appsns2 ip link set veth-app up

# Configure switchns bridge IP via DHCP
echo "Configuring IP for switch bridge via DHCP..."
ip netns exec switchns pkill dhclient 2>/dev/null || true
sleep 1
ip netns exec switchns dhclient br-switch
sleep 2
BR_SWITCH_IP=$(ip netns exec switchns ip -4 addr show br-switch | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
if [ -n "$BR_SWITCH_IP" ]; then
    echo "✓ Got IP via DHCP for br-switch: $BR_SWITCH_IP"
else
    echo "✗ Failed to get DHCP IP for br-switch"
fi

# Smart IP management: DHCP-then-static with fallback
IP_CONFIG_FILE="/tmp/kidos-network.conf"

# Run DHCP on ethernet bridge (always needed for upstream connection)
echo "Requesting IP address via DHCP on ethernet bridge..."
ip netns exec ethns pkill dhclient 2>/dev/null || true
sleep 1
ip netns exec ethns dhclient br0

# Smart IP assignment for kidos bridge
echo "Configuring IP for kidos bridge..."
ip netns exec kidosns pkill dhclient 2>/dev/null || true
sleep 1

if [ -f "$IP_CONFIG_FILE" ]; then
    # Load stored configuration
    source "$IP_CONFIG_FILE"
    echo "Found stored IP configuration:"
    echo "  BR1_IP: $BR1_IP"
    echo "  VETH_APP_IP: $VETH_APP_IP"
    echo "  GATEWAY: $GATEWAY"
    
    # Try to assign static IPs
    if ip netns exec kidosns ip addr add "$BR1_IP/24" dev br1 2>/dev/null; then
        echo "✓ Assigned stored IP to br1: $BR1_IP"
        # Add default gateway
        if [ -n "$GATEWAY" ]; then
            ip netns exec kidosns ip route add default via "$GATEWAY" 2>/dev/null && \
                echo "✓ Added default gateway: $GATEWAY"
        fi
        BR1_SUCCESS=true
    else
        echo "⚠ Failed to assign stored IP to br1 (possible conflict), requesting new DHCP lease..."
        ip netns exec kidosns dhclient br1
        sleep 2
        NEW_BR1_IP=$(ip netns exec kidosns ip -4 addr show br1 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
        if [ -n "$NEW_BR1_IP" ]; then
            BR1_IP="$NEW_BR1_IP"
            # Capture gateway from DHCP-assigned route
            GATEWAY=$(ip netns exec kidosns ip route | grep default | awk '{print $3}')
            echo "✓ Got new IP via DHCP for br1: $BR1_IP"
            echo "✓ Got gateway: $GATEWAY"
            BR1_SUCCESS=true
        fi
    fi
    
    if ip netns exec appsns ip addr add "$VETH_APP_IP/24" dev veth-app 2>/dev/null; then
        echo "✓ Assigned stored IP to veth-app: $VETH_APP_IP"
        # Add default gateway
        if [ -n "$GATEWAY" ]; then
            ip netns exec appsns ip route add default via "$GATEWAY" 2>/dev/null && \
                echo "✓ Added default gateway for appsns: $GATEWAY"
        fi
        VETH_SUCCESS=true
    else
        echo "⚠ Failed to assign stored IP to veth-app (possible conflict), requesting DHCP..."
        ip netns exec appsns dhclient veth-app
        sleep 2
        VETH_APP_IP=$(ip netns exec appsns ip -4 addr show veth-app | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
        if [ -n "$VETH_APP_IP" ]; then
            # Get gateway from DHCP-assigned route
            GATEWAY=$(ip netns exec appsns ip route | grep default | awk '{print $3}')
            echo "✓ Got new IP via DHCP for veth-app: $VETH_APP_IP"
            echo "✓ Got gateway: $GATEWAY"
            VETH_SUCCESS=true
        else
            echo "✗ Failed to get DHCP IP for veth-app"
            VETH_SUCCESS=false
        fi
    fi
    
    # Configure appsns2 with DHCP
    if [ -n "$VETH_APP2_IP" ]; then
        if ip netns exec appsns2 ip addr add "$VETH_APP2_IP/24" dev veth-app 2>/dev/null; then
            echo "✓ Assigned stored IP to veth-app (appsns2): $VETH_APP2_IP"
            # Add default gateway
            if [ -n "$GATEWAY" ]; then
                ip netns exec appsns2 ip route add default via "$GATEWAY" 2>/dev/null && \
                    echo "✓ Added default gateway for appsns2: $GATEWAY"
            fi
        else
            echo "⚠ Failed to assign stored IP to appsns2, requesting DHCP..."
            ip netns exec appsns2 dhclient veth-app
            sleep 2
            VETH_APP2_IP=$(ip netns exec appsns2 ip -4 addr show veth-app | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
            if [ -n "$VETH_APP2_IP" ]; then
                echo "✓ Got new IP via DHCP for veth-app (appsns2): $VETH_APP2_IP"
            else
                echo "✗ Failed to get DHCP IP for appsns2"
            fi
        fi
    else
        echo "Requesting DHCP for appsns2..."
        ip netns exec appsns2 dhclient veth-app
        sleep 2
        VETH_APP2_IP=$(ip netns exec appsns2 ip -4 addr show veth-app | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
        if [ -n "$VETH_APP2_IP" ]; then
            echo "✓ Got IP via DHCP for veth-app (appsns2): $VETH_APP2_IP"
        else
            echo "✗ Failed to get DHCP IP for appsns2"
        fi
    fi
else
    echo "No stored IP configuration found, requesting DHCP leases..."
    # First boot - get IPs via DHCP
    ip netns exec kidosns dhclient br1
    sleep 2
    BR1_IP=$(ip netns exec kidosns ip -4 addr show br1 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
    # Get gateway from DHCP-assigned route
    GATEWAY=$(ip netns exec kidosns ip route | grep default | awk '{print $3}')
    
    ip netns exec appsns pkill dhclient 2>/dev/null || true
    sleep 1
    ip netns exec appsns dhclient veth-app
    sleep 2
    VETH_APP_IP=$(ip netns exec appsns ip -4 addr show veth-app | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
    
    # Request DHCP for appsns2
    ip netns exec appsns2 pkill dhclient 2>/dev/null || true
    sleep 1
    ip netns exec appsns2 dhclient veth-app
    sleep 2
    VETH_APP2_IP=$(ip netns exec appsns2 ip -4 addr show veth-app | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
    
    if [ -n "$BR1_IP" ] && [ -n "$VETH_APP_IP" ] && [ -n "$VETH_APP2_IP" ]; then
        echo "✓ Received DHCP leases:"
        echo "  br1: $BR1_IP"
        echo "  veth-app: $VETH_APP_IP"
        echo "  veth-app2: $VETH_APP2_IP"
        echo "  gateway: $GATEWAY"
        BR1_SUCCESS=true
        VETH_SUCCESS=true
    fi
fi

# Store configuration for next boot
if [ "$BR1_SUCCESS" = true ] && [ "$VETH_SUCCESS" = true ]; then
    # If gateway is still empty, try to detect it from current routes
    if [ -z "$GATEWAY" ]; then
        GATEWAY=$(ip netns exec kidosns ip route | grep default | awk '{print $3}')
        if [ -z "$GATEWAY" ]; then
            # Fallback to standard gateway for 192.168.1.0/24 network
            GATEWAY="192.168.1.1"
        fi
        echo "✓ Detected gateway: $GATEWAY"
    fi
    
    cat > "$IP_CONFIG_FILE" << EOF
BR1_IP="$BR1_IP"
VETH_APP_IP="$VETH_APP_IP"
GATEWAY="$GATEWAY"
EOF
    echo "✓ Saved IP configuration to $IP_CONFIG_FILE"
fi

# Setup DNS for appsns
echo "Configuring DNS for appsns..."
mkdir -p /etc/netns/appsns
echo "nameserver 8.8.8.8" > /etc/netns/appsns/resolv.conf
echo "hosts: files dns" > /etc/netns/appsns/nsswitch.conf

# Setup DNS for appsns2
echo "Configuring DNS for appsns2..."
mkdir -p /etc/netns/appsns2
echo "nameserver 8.8.8.8" > /etc/netns/appsns2/resolv.conf
echo "hosts: files dns" > /etc/netns/appsns2/nsswitch.conf

# Setup monitoring namespace
echo "Setting up monitoring namespace..."
./scripts/monitoring/init.sh

echo "Setup complete!"

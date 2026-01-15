#!/bin/bash

set -x

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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

echo "Core namespaces created successfully!"

# Discover all physical ethernet interfaces (exclude wireless, virtual, loopback)
echo "Discovering physical ethernet interfaces..."
ALL_ETH_INTERFACES=$(ip link show | grep -E '^[0-9]+: (en|eth)' | grep -v '@' | awk -F': ' '{print $2}' | awk '{print $1}')

if [ -z "$ALL_ETH_INTERFACES" ]; then
    echo -e "${RED}✗ No physical ethernet interfaces found!${NC}"
    exit 1
fi

echo "Found interfaces: $ALL_ETH_INTERFACES"

# Test each interface for internet connectivity and detect active ones
INTERNET_IFACES=()
NO_INTERNET_IFACES=()
ACTIVE_IFACE=""
ACTIVE_IP=""

for iface in $ALL_ETH_INTERFACES; do
    echo "Testing connectivity on $iface..."
    ip link set "$iface" up
    sleep 1
    
    # Check if interface already has an IP (active SSH connection)
    ACTIVE_IP=$(ip -4 addr show "$iface" | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\d+' | head -n1)
    if [ -n "$ACTIVE_IP" ]; then
        # Test if this active interface has internet
        if timeout 3 ping -c 1 -I "$iface" 8.8.8.8 >/dev/null 2>&1; then
            echo -e "${GREEN}✓ $iface has internet connectivity (ACTIVE - IP: $ACTIVE_IP)${NC}"
            ACTIVE_IFACE="$iface"
            continue  # Skip to next interface, will handle this specially
        else
            echo -e "${YELLOW}✗ $iface has IP but no internet${NC}"
        fi
    fi
    
    # For interfaces without IP, test with temporary DHCP
    if [ -z "$ACTIVE_IP" ]; then
        pkill -f "dhclient.*$iface" 2>/dev/null || true
        timeout 10 dhclient "$iface" 2>/dev/null
        
        # Test with ping
        if timeout 3 ping -c 1 -I "$iface" 8.8.8.8 >/dev/null 2>&1; then
            echo -e "${GREEN}✓ $iface has internet connectivity${NC}"
            INTERNET_IFACES+=("$iface")
        else
            echo -e "${YELLOW}✗ $iface has no internet connectivity${NC}"
            NO_INTERNET_IFACES+=("$iface")
        fi
        
        # Release DHCP for now
        pkill -f "dhclient.*$iface" 2>/dev/null || true
        ip addr flush dev "$iface"
    fi
done

# Setup based on connectivity results
if [ -n "$ACTIVE_IFACE" ]; then
    echo "Active interface $ACTIVE_IFACE detected - using bridge mode to preserve connectivity..."
    ip netns add ethns
    
    # Create bridge in root namespace
    ip link add name br-host type bridge
    ip link set br-host up
    
    # Kill dhclient and remove IP from physical interface before adding to bridge
    echo "Removing IP from $ACTIVE_IFACE (will be assigned to bridge instead)..."
    pkill -f "dhclient.*$ACTIVE_IFACE" 2>/dev/null || true
    sleep 1
    ip addr del "$ACTIVE_IP" dev "$ACTIVE_IFACE" 2>/dev/null || true
    
    # Connect physical interface to bridge (keep it in root namespace)
    ip link set "$ACTIVE_IFACE" master br-host
    ip link set "$ACTIVE_IFACE" up
    
    # Get/restore IP for root namespace on bridge
    echo "Requesting IP for root namespace bridge..."
    dhclient -v -pf /var/run/dhclient-root.pid br-host
    
    # Create bridge in ethns
    echo "Creating bridge in ethns..."
    ip netns exec ethns ip link add name br0 type bridge
    ip netns exec ethns ip link set br0 up
    ip netns exec ethns ip link set lo up
    
    # Create veth pair between root and ethns
    echo "Creating veth pair between root and ethns..."
    ip link add veth-root type veth peer name veth-eth
    ip link set veth-root master br-host
    ip link set veth-root up
    ip link set veth-eth netns ethns
    ip netns exec ethns ip link set veth-eth master br0
    ip netns exec ethns ip link set veth-eth up
    
    # Get DHCP for ethns bridge (same subnet as root)
    echo "Requesting IP for ethns bridge..."
    ip netns exec ethns dhclient -v -pf /var/run/dhclient-ethns.pid br0
    
    # Create veth pair to connect ethns and kidosns
    echo "Creating veth pair between ethns and kidosns..."
    ip netns exec ethns ip link add veth-eth-kidos type veth peer name veth-kidos netns kidosns
    ip netns exec ethns ip link set veth-eth-kidos master br0
    ip netns exec ethns ip link set veth-eth-kidos up
    ip netns exec kidosns ip link set veth-kidos up
    
    # Setup DNS for ethns
    mkdir -p /etc/netns/ethns
    echo "nameserver 8.8.8.8" > /etc/netns/ethns/resolv.conf
    echo "hosts: files dns" > /etc/netns/ethns/nsswitch.conf
    
    echo -e "${GREEN}✓ Bridge mode configured - all namespaces on same subnet${NC}"
    
elif [ ${#INTERNET_IFACES[@]} -gt 0 ]; then
    echo "Setting up ethns namespace with internet-connected interfaces (moving to namespace)..."
    ip netns add ethns
    
    # Create bridge in ethernet namespace
    ip netns exec ethns ip link add name br0 type bridge
    
    # Move all internet-connected interfaces to ethns
    for iface in "${INTERNET_IFACES[@]}"; do
        echo "Moving $iface to ethns namespace..."
        ip link set "$iface" netns ethns
        ip netns exec ethns ip link set "$iface" up
        ip netns exec ethns ip link set "$iface" master br0
        echo -e "${GREEN}✓ $iface added to ethns bridge${NC}"
    done
    
    # Bring up bridge
    ip netns exec ethns ip link set br0 up
    
    # Create veth pair to connect ethernet and kidos namespaces
    echo "Creating veth pair between ethns and kidosns..."
    ip netns exec ethns ip link add veth-eth type veth peer name veth-kidos netns kidosns
    ip netns exec ethns ip link set veth-eth master br0
    ip netns exec ethns ip link set veth-eth up
    ip netns exec kidosns ip link set veth-kidos up
    
    # Setup DNS for ethns
    mkdir -p /etc/netns/ethns
    echo "nameserver 8.8.8.8" > /etc/netns/ethns/resolv.conf
    echo "hosts: files dns" > /etc/netns/ethns/nsswitch.conf
else
    echo "No internet-connected interfaces found, skipping ethns creation"
fi

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
if [ -n "$ACTIVE_IFACE" ] || [ ${#INTERNET_IFACES[@]} -gt 0 ]; then
    ip netns exec ethns ip link set br0 up
    ip netns exec kidosns ip link set veth-kidos up
fi
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
    echo -e "${GREEN}✓ Got IP via DHCP for br-switch: $BR_SWITCH_IP${NC}"
else
    echo -e "${RED}✗ Failed to get DHCP IP for br-switch${NC}"
fi

# Handle interfaces without internet connectivity (after br-switch has IP)
ETH_COUNTER=1
for iface in "${NO_INTERNET_IFACES[@]}"; do
    NS_NAME="ethns${ETH_COUNTER}"
    BR_NAME="br0-eth${ETH_COUNTER}"
    VETH_NS="veth-eth${ETH_COUNTER}"
    VETH_SW="veth-sw-eth${ETH_COUNTER}"
    
    echo "Setting up $NS_NAME for $iface..."
    ip netns add "$NS_NAME"
    
    # Move interface to namespace
    ip link set "$iface" netns "$NS_NAME"
    ip netns exec "$NS_NAME" ip link set "$iface" up
    
    # Create bridge
    ip netns exec "$NS_NAME" ip link add name "$BR_NAME" type bridge
    ip netns exec "$NS_NAME" ip link set "$iface" master "$BR_NAME"
    ip netns exec "$NS_NAME" ip link set "$BR_NAME" up
    
    # Create veth pair to switchns
    ip netns exec "$NS_NAME" ip link add "$VETH_NS" type veth peer name "$VETH_SW" netns switchns
    ip netns exec "$NS_NAME" ip link set "$VETH_NS" master "$BR_NAME"
    ip netns exec "$NS_NAME" ip link set "$VETH_NS" up
    ip netns exec switchns ip link set "$VETH_SW" master br-switch
    ip netns exec switchns ip link set "$VETH_SW" up
    
    # Setup DNS for ethns{n}
    mkdir -p "/etc/netns/$NS_NAME"
    echo "nameserver 8.8.8.8" > "/etc/netns/$NS_NAME/resolv.conf"
    echo "hosts: files dns" > "/etc/netns/$NS_NAME/nsswitch.conf"
    
    # Request DHCP on bridge (now that br-switch has IP)
    echo "Requesting DHCP for $BR_NAME..."
    ip netns exec "$NS_NAME" pkill dhclient 2>/dev/null || true
    sleep 1
    ip netns exec "$NS_NAME" dhclient "$BR_NAME"
    
    echo -e "${GREEN}✓ $iface configured in $NS_NAME${NC}"
    ETH_COUNTER=$((ETH_COUNTER + 1))
done
sleep 2

# Smart IP management: DHCP-then-static with fallback
IP_CONFIG_FILE="/tmp/kidos-network.conf"

# Run DHCP on ethernet bridge (only if ethns exists and not using active interface bridge mode)
if [ ${#INTERNET_IFACES[@]} -gt 0 ]; then
    echo "Requesting IP address via DHCP on ethernet bridge..."
    ip netns exec ethns pkill dhclient 2>/dev/null || true
    sleep 1
    ip netns exec ethns dhclient br0
fi
# Note: If ACTIVE_IFACE is set, DHCP was already done during bridge setup above

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
        echo -e "${GREEN}✓ Assigned stored IP to br1: $BR1_IP${NC}"
        # Add default gateway
        if [ -n "$GATEWAY" ]; then
            ip netns exec kidosns ip route add default via "$GATEWAY" 2>/dev/null && \
                echo -e "${GREEN}✓ Added default gateway: $GATEWAY${NC}"
        fi
        BR1_SUCCESS=true
    else
        echo -e "${YELLOW}⚠ Failed to assign stored IP to br1 (possible conflict), requesting new DHCP lease...${NC}"
        ip netns exec kidosns dhclient br1
        sleep 2
        NEW_BR1_IP=$(ip netns exec kidosns ip -4 addr show br1 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
        if [ -n "$NEW_BR1_IP" ]; then
            BR1_IP="$NEW_BR1_IP"
            # Capture gateway from DHCP-assigned route
            GATEWAY=$(ip netns exec kidosns ip route | grep default | awk '{print $3}')
            echo -e "${GREEN}✓ Got new IP via DHCP for br1: $BR1_IP${NC}"
            echo -e "${GREEN}✓ Got gateway: $GATEWAY${NC}"
            BR1_SUCCESS=true
        fi
    fi
    
    if ip netns exec appsns ip addr add "$VETH_APP_IP/24" dev veth-app 2>/dev/null; then
        echo -e "${GREEN}✓ Assigned stored IP to veth-app: $VETH_APP_IP${NC}"
        # Add default gateway
        if [ -n "$GATEWAY" ]; then
            ip netns exec appsns ip route add default via "$GATEWAY" 2>/dev/null && \
                echo -e "${GREEN}✓ Added default gateway for appsns: $GATEWAY${NC}"
        fi
        VETH_SUCCESS=true
    else
        echo -e "${YELLOW}⚠ Failed to assign stored IP to veth-app (possible conflict), requesting DHCP...${NC}"
        ip netns exec appsns dhclient veth-app
        sleep 2
        VETH_APP_IP=$(ip netns exec appsns ip -4 addr show veth-app | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
        if [ -n "$VETH_APP_IP" ]; then
            # Get gateway from DHCP-assigned route
            GATEWAY=$(ip netns exec appsns ip route | grep default | awk '{print $3}')
            echo -e "${GREEN}✓ Got new IP via DHCP for veth-app: $VETH_APP_IP${NC}"
            echo -e "${GREEN}✓ Got gateway: $GATEWAY${NC}"
            VETH_SUCCESS=true
        else
            echo -e "${RED}✗ Failed to get DHCP IP for veth-app${NC}"
            VETH_SUCCESS=false
        fi
    fi
    
    # Configure appsns2 with DHCP
    if [ -n "$VETH_APP2_IP" ]; then
        if ip netns exec appsns2 ip addr add "$VETH_APP2_IP/24" dev veth-app 2>/dev/null; then
            echo -e "${GREEN}✓ Assigned stored IP to veth-app (appsns2): $VETH_APP2_IP${NC}"
            # Add default gateway
            if [ -n "$GATEWAY" ]; then
                ip netns exec appsns2 ip route add default via "$GATEWAY" 2>/dev/null && \
                    echo -e "${GREEN}✓ Added default gateway for appsns2: $GATEWAY${NC}"
            fi
        else
            echo -e "${YELLOW}⚠ Failed to assign stored IP to appsns2, requesting DHCP...${NC}"
            ip netns exec appsns2 dhclient veth-app
            sleep 2
            VETH_APP2_IP=$(ip netns exec appsns2 ip -4 addr show veth-app | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
            if [ -n "$VETH_APP2_IP" ]; then
                echo -e "${GREEN}✓ Got new IP via DHCP for veth-app (appsns2): $VETH_APP2_IP${NC}"
            else
                echo -e "${RED}✗ Failed to get DHCP IP for appsns2${NC}"
            fi
        fi
    else
        echo "Requesting DHCP for appsns2..."
        ip netns exec appsns2 dhclient veth-app
        sleep 2
        VETH_APP2_IP=$(ip netns exec appsns2 ip -4 addr show veth-app | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
        if [ -n "$VETH_APP2_IP" ]; then
            echo -e "${GREEN}✓ Got IP via DHCP for veth-app (appsns2): $VETH_APP2_IP${NC}"
        else
            echo -e "${RED}✗ Failed to get DHCP IP for appsns2${NC}"
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
        echo -e "${GREEN}✓ Received DHCP leases:${NC}"
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
        echo -e "${GREEN}✓ Detected gateway: $GATEWAY${NC}"
    fi
    
    cat > "$IP_CONFIG_FILE" << EOF
BR1_IP="$BR1_IP"
VETH_APP_IP="$VETH_APP_IP"
GATEWAY="$GATEWAY"
EOF
    echo -e "${GREEN}✓ Saved IP configuration to $IP_CONFIG_FILE${NC}"
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

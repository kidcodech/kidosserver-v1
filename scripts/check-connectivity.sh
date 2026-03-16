#!/bin/bash

# Kidos connectivity and setup checker
# Checks namespaces, interfaces, IPs, routes, ping and DNS for the full chain.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
WARN=0
FAIL=0

ok()   { echo -e "  ${GREEN}✓${NC} $*";  ((PASS++)); }
warn() { echo -e "  ${YELLOW}⚠${NC} $*"; ((WARN++)); }
fail() { echo -e "  ${RED}✗${NC} $*";   ((FAIL++)); }

section() { echo -e "\n${BOLD}${CYAN}── $* ──${NC}"; }

ns_exists()    { ip netns list 2>/dev/null | grep -qw "$1"; }
iface_exists() { ip link show "$1" &>/dev/null; }
ns_iface()     { ip netns exec "$1" ip link show "$2" &>/dev/null 2>&1; }
ns_ip()        { ip netns exec "$1" ip -4 addr show "$2" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1; }
root_ip()      { ip -4 addr show "$1" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1; }

ping_ns() {
    local ns="$1" target="$2"
    if [ "$ns" = "root" ]; then
        ping -c1 -W2 -q "$target" &>/dev/null
    else
        ip netns exec "$ns" ping -c1 -W2 -q "$target" &>/dev/null 2>&1
    fi
}

dns_ns() {
    local ns="$1" host="$2"
    if [ "$ns" = "root" ]; then
        getent hosts "$host" &>/dev/null
    else
        ip netns exec "$ns" getent hosts "$host" &>/dev/null 2>&1
    fi
}

# ─────────────────────────────────────────
section "Namespaces"
for ns in ethns kidosns switchns appsns appsns2 monns; do
    if ns_exists "$ns"; then ok "$ns exists"
    else fail "$ns missing"; fi
done

# ─────────────────────────────────────────
section "Root namespace — br-wan bridge"

WAN_IFACE=""
CONFIG_FILE="/etc/kidos/config"
[ -f "$CONFIG_FILE" ] && source "$CONFIG_FILE" && WAN_IFACE="${WAN_INTERFACE:-}"
[ -z "$WAN_IFACE" ] && WAN_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)

if iface_exists br-wan; then
    ok "br-wan exists"
    BR_WAN_IP=$(root_ip br-wan)
    if [ -n "$BR_WAN_IP" ]; then ok "br-wan IP: $BR_WAN_IP"
    else fail "br-wan has no IP"; fi

    # Check br-wan members
    MEMBERS=$(ip link show master br-wan 2>/dev/null | awk -F': ' '/^[0-9]+:/{print $2}' | awk '{print $1}')
    FOUND_WAN=0; FOUND_VETH=0
    for m in $MEMBERS; do
        [[ "$m" == veth-mgmt ]] && FOUND_VETH=1
        [[ "$m" != veth-mgmt ]] && FOUND_WAN=1 && WAN_MEMBER="$m"
    done
    [ "$FOUND_WAN" -eq 1 ] && ok "Physical WAN interface ($WAN_MEMBER) in br-wan" \
        || fail "No physical interface in br-wan"
    [ "$FOUND_VETH" -eq 1 ] && ok "veth-mgmt in br-wan" \
        || fail "veth-mgmt not in br-wan"
else
    fail "br-wan bridge missing"
fi

if [ -n "$WAN_IFACE" ]; then
    WAN_OWN_IP=$(root_ip "$WAN_IFACE")
    if [ -z "$WAN_OWN_IP" ]; then ok "$WAN_IFACE has no own IP (correct — bridged)"
    else warn "$WAN_IFACE has duplicate IP $WAN_OWN_IP (NetworkManager may have re-assigned)"; fi

    NM_DROPIN="/etc/NetworkManager/conf.d/kidos-wan-unmanaged.conf"
    if [ -f "$NM_DROPIN" ]; then ok "NM drop-in present ($NM_DROPIN)"
    else warn "NM drop-in missing — $WAN_IFACE may be re-managed after reboot"; fi
fi

# ─────────────────────────────────────────
section "ethns — br0"
if ns_exists ethns; then
    for iface in br0 veth-eth veth-mgmt-eth; do
        if ns_iface ethns "$iface"; then ok "  ethns/$iface exists"
        else fail "  ethns/$iface missing"; fi
    done
    IP=$(ns_ip ethns br0)
    if [ -n "$IP" ]; then ok "ethns/br0 IP: $IP"
    else fail "ethns/br0 has no IP"; fi
    GW=$(ip netns exec ethns ip route | awk '/default/{print $3}' | head -1)
    if [ -n "$GW" ]; then ok "ethns default route via $GW"
    else fail "ethns has no default route"; fi
fi

# ─────────────────────────────────────────
section "kidosns — br1 (XDP enforcement point)"
if ns_exists kidosns; then
    for iface in br1 veth-kidos veth-kidos-app; do
        if ns_iface kidosns "$iface"; then ok "  kidosns/$iface exists"
        else fail "  kidosns/$iface missing"; fi
    done
    IP=$(ns_ip kidosns br1)
    if [ -n "$IP" ]; then ok "kidosns/br1 IP: $IP"
    else fail "kidosns/br1 has no IP"; fi
    GW=$(ip netns exec kidosns ip route | awk '/default/{print $3}' | head -1)
    if [ -n "$GW" ]; then ok "kidosns default route via $GW"
    else fail "kidosns has no default route"; fi
fi

# ─────────────────────────────────────────
section "switchns — br-switch"
if ns_exists switchns; then
    for iface in br-switch veth-sw veth-sw-app veth-sw-app2; do
        if ns_iface switchns "$iface"; then ok "  switchns/$iface exists"
        else warn "  switchns/$iface missing"; fi
    done
    IP=$(ns_ip switchns br-switch)
    if [ -n "$IP" ]; then ok "switchns/br-switch IP: $IP"
    else warn "switchns/br-switch has no IP (L2-only — OK if no local apps here)"; fi

    LAN_IFACE="${ETHERNET_INTERFACE:-}"
    if [ -n "$LAN_IFACE" ]; then
        if ns_iface switchns "$LAN_IFACE"; then ok "  LAN interface $LAN_IFACE in switchns"
        else warn "  LAN interface $LAN_IFACE not in switchns (wired clients won't be filtered)"; fi
    else
        warn "ETHERNET_INTERFACE not set — no LAN port assigned to switchns"
    fi
fi

# ─────────────────────────────────────────
section "appsns / appsns2"
for ns in appsns appsns2; do
    if ns_exists "$ns"; then
        if ns_iface "$ns" veth-app; then ok "  $ns/veth-app exists"
        else fail "  $ns/veth-app missing"; fi
        IP=$(ns_ip "$ns" veth-app)
        if [ -n "$IP" ]; then ok "  $ns/veth-app IP: $IP"
        else warn "  $ns/veth-app has no IP (needs DHCP or static if hosting services)"; fi
    fi
done

# ─────────────────────────────────────────
section "Ping connectivity (8.8.8.8)"
declare -A PING_TARGETS=(
    [root]="root"
    [ethns]="ethns"
    [kidosns]="kidosns"
    [switchns]="switchns"
    [appsns]="appsns"
)
for label in root ethns kidosns switchns appsns; do
    ns="${PING_TARGETS[$label]}"
    if ping_ns "$ns" 8.8.8.8; then ok "$label → 8.8.8.8"
    else fail "$label → 8.8.8.8 UNREACHABLE"; fi
done

# ─────────────────────────────────────────
section "DNS resolution (google.com)"
for ns in root ethns kidosns; do
    if dns_ns "$ns" google.com; then ok "$ns → google.com resolved"
    else fail "$ns → google.com FAILED"; fi
done

# ─────────────────────────────────────────
section "XDP / eBPF"
XDP_PROG=$(ip netns exec kidosns ip link show veth-kidos-app 2>/dev/null | grep -oP 'xdp\w*')
if [ -n "$XDP_PROG" ]; then ok "XDP loaded on kidosns/veth-kidos-app ($XDP_PROG)"
else warn "No XDP program on kidosns/veth-kidos-app (ip-filter not started?)"; fi

# ─────────────────────────────────────────
section "DNS Inspector process"
if pgrep -f "dns-inspector" &>/dev/null; then ok "dns-inspector running"
else warn "dns-inspector not running"; fi

# ─────────────────────────────────────────
section "Summary"
TOTAL=$((PASS + WARN + FAIL))
echo -e "  Total checks : $TOTAL"
echo -e "  ${GREEN}Passed${NC}       : $PASS"
echo -e "  ${YELLOW}Warnings${NC}     : $WARN"
echo -e "  ${RED}Failed${NC}       : $FAIL"
echo ""
if [ "$FAIL" -eq 0 ] && [ "$WARN" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}All checks passed!${NC}"
elif [ "$FAIL" -eq 0 ]; then
    echo -e "${YELLOW}${BOLD}Setup OK with warnings — review above.${NC}"
else
    echo -e "${RED}${BOLD}$FAIL check(s) failed — review above.${NC}"
fi
echo ""

# Kidos Server v1

Advanced network namespace-based router infrastructure with packet monitoring, parental controls, and Wi-Fi hotspot capabilities.

## Overview

This project creates a sophisticated multi-namespace network architecture for ethernet, switching, applications, and Wi-Fi hotspot layers, with built-in traffic monitoring using eBPF/XDP, parental controls via DNS inspection and IP filtering, and a web-based management dashboard.

## Architecture

```
┌─────────────┐
│   ethns     │ (Ethernet namespace - Internet connection)
│   br0       │ - Physical ethernet interface(s)
│             │ - DHCP from upstream router
└──────┬──────┘
       │ veth-eth <-> veth-kidos
       │
┌──────┴──────┐
│   kidosns   │ (Kidos namespace - Central bridge)
│   br1       │ - Connects ethernet to switch layer
│             │ - DHCP from router
│             │ - XDP IP filtering (parental controls)
└──────┬──────┘
       │ veth-kidos-app <-> veth-sw
       │
┌──────┴──────┐
│  switchns   │ (Switch namespace - Central hub)
│  br-switch  │ - DHCP from router
│             │ - Connects apps, monitoring, hotspot
├─────┬───┬───┤
│     │   │   │
│  ┌──┴┐ ┌┴──┐ ┌─────┴──────┐
│  │app│ │mon│ │   wifins   │ (Wi-Fi Hotspot)
│  │sns│ │ns │ │   br-wifi  │ - AP Mode Bridge
│  └───┘ └───┘ │  hostapd   │ - USB Wi-Fi dongle
│              │  KidosNet  │ - DHCP from router
└──────────────┴────────────┘

    Additional namespaces:
    - ethns1, ethns2... (for non-internet ethernet)
    - appsns2 (second app namespace)
```

## Components

### Network Namespaces

- **ethns**: Internet-connected ethernet interface(s) with automatic detection
- **ethns1, ethns2...**: Non-internet ethernet interfaces (e.g., for direct device connections)
- **kidosns**: Central routing layer with XDP-based IP filtering for parental controls
- **switchns**: Central switching hub connecting all services
- **appsns / appsns2**: Application layers for running services
- **wifins**: Wi-Fi hotspot namespace with automatic USB dongle detection
- **monns**: Monitoring namespace for packet capture and analysis

### Core Features

1. **Dynamic Interface Detection**
   - Automatic ethernet interface discovery
   - Internet connectivity testing
   - Smart interface assignment (internet vs local)
   - USB Wi-Fi dongle auto-detection with chipset identification

2. **Parental Controls** (`parental/`)
   - **DNS Inspector**: eBPF/XDP DNS query monitoring on ethernet interfaces
   - **IP Filter**: XDP-based MAC address filtering with allowlist/blocklist
   - User management with device registration
   - Automatic filtering rule synchronization

3. **Wi-Fi Hotspot** (`scripts/hotspot/`)
   - Automatic USB dongle detection (RTL8821AU, RTL8822BU support)
   - Dynamic driver loading based on chipset
   - L2 bridge mode for transparent DHCP
   - hostapd configuration (WPA2)
   - Integrated into main network via switchns

4. **Monitoring System** (`monitoring/`)
   - TC mirroring for packet capture
   - XDP/AF_XDP high-performance packet processing
   - Go-based sniffer daemon
   - In-memory flow aggregation

5. **Web Dashboard** (`webserver/`)
   - REST API on port 8080
   - Real-time packet statistics
   - User and device management
   - Live updates via WebSocket
   - React-based frontend

## Prerequisites

- Linux kernel 5.4+ (for XDP support)
- Root/sudo access
- Fedora/RHEL or Debian/Ubuntu based system
- Hardware:
  - At least one ethernet interface
  - (Optional) USB Wi-Fi dongle for hotspot (RTL8821AU or RTL8822BU recommended)

## Quick Start

```bash
# 1. Install all dependencies
sudo ./install/install-deps.sh

# 2. Build all components
./install/build-all.sh

# 3. Initialize network namespaces
sudo ./scripts/init.sh
# Note: init.sh automatically runs monitoring/init.sh

# 4. (Optional) Start Wi-Fi hotspot
sudo ./scripts/hotspot/init.sh

# 5. Start all services
./install/start-all.sh
```

## Installation

```bash
# Install all dependencies
sudo ./install/install-deps.sh

# Build all components
./install/build-all.sh
```

The install script automatically:
- Detects your OS (Fedora/RHEL or Debian/Ubuntu)
- Installs: iproute2, bridge-utils, dhclient, clang, llvm, libbpf-devel, hostapd, Go 1.21+, Node.js 18+
- Builds: DNS inspector, IP filter, monitoring sniffer, web server, React frontend

## Usage

### Initialize Network Infrastructure

```bash
sudo ./scripts/init.sh
```

This automatically:
- Detects all ethernet interfaces
- Tests internet connectivity per interface
- Creates appropriate namespaces
- Sets up bridges and veth pairs
- Configures DHCP on all interfaces
- Sets up monitoring namespace with TC mirroring
- Stores IP configuration for faster subsequent boots

### Start Wi-Fi Hotspot (Optional)

```bash
sudo ./scripts/hotspot/init.sh
```

This will:
- Auto-detect USB Wi-Fi dongles
- Identify chipset and load appropriate driver
- Create wifins namespace
- Configure hostapd for AP mode
- Bridge to main network (clients get DHCP from main router)
- Default SSID: `KidosNet`, Password: `kidos123`

To stop hotspot:

```bash
sudo ./scripts/hotspot/teardown.sh
```

### Start All Services

```bash
./install/start-all.sh
```

Or manually:

```bash
# Start IP filter (parental controls)
sudo ./parental/ip-filter/bin/ip-filter &

# Start sniffer daemon
sudo ip netns exec monns ./monitoring/sniffer/sniffer &

# Start web server
./webserver/bin/webserver &
```

### Access Dashboard

Open browser to: `http://router.kidos.tools`

Dashboard features:
- Real-time packet statistics and monitoring
- User and device management
- MAC address filtering (allowlist/blocklist)
- Aggregated network flows by IP and protocol
- Live updates via WebSocket
- Wi-Fi hotspot management

> **Note**: The "router.kidos.tools" domain name resolves via systemd-resolved

### Stop All Services

```bash
./install/stop-all.sh
```

### Teardown Network

```bash
sudo ./scripts/teardown.sh
```

This will:
- Stop all running services
- Remove TC mirroring rules
- Delete all namespaces
- Return interfaces to default namespace

## Development

### Project Structure

```
├── install/              # Installation and build scripts
│   ├── install-deps.sh  # Dependency installation
│   ├── build-all.sh     # Build all components
│   ├── start-all.sh     # Start all services
│   └── stop-all.sh      # Stop all services
├── scripts/              # Network setup scripts
│   ├── init.sh          # Initialize all namespaces
│   ├── teardown.sh      # Cleanup all namespaces
│   ├── hotspot/         # Wi-Fi hotspot scripts
│   │   ├── init.sh      # Start hotspot
│   │   └── teardown.sh  # Stop hotspot
│   └── monitoring/      # Monitoring setup
│       ├── init.sh      # Setup monitoring namespace
│       └── teardown.sh  # Cleanup monitoring
├── parental/            # Parental control components
│   ├── dns-inspector/   # eBPF DNS monitoring
│   │   └── ebpf/xdp_dns.c
│   └── ip-filter/       # XDP MAC filtering
│       ├── main.go      # Sync daemon
│       └── xdp_ip_filter.c
├── monitoring/          # Traffic monitoring
│   ├── ebpf/            # XDP packet capture
│   │   └── xdp_afxdp.c
│   └── sniffer/         # Go sniffer daemon
│       ├── main.go
│       └── store/store.go
└── webserver/           # Web dashboard
    ├── main.go          # Backend API
    ├── db/              # Database layer
    └── frontend/        # React frontend
        └── src/App.jsx
```

### Key Scripts

#### Network Initialization (`scripts/init.sh`)
- Dynamic ethernet interface detection
- Internet connectivity testing
- Smart namespace creation
- DHCP-then-static IP management
- IP configuration persistence

#### Hotspot (`scripts/hotspot/init.sh`)
- USB Wi-Fi dongle auto-detection
- Chipset identification (RTL8821AU, RTL8822BU)
- Dynamic driver loading
- hostapd configuration
- L2 bridge mode integration

#### Parental Controls

**DNS Inspector**
- Monitors DNS queries via XDP on ethernet interfaces
- Logs queries for analysis
- Can be extended for filtering

**IP Filter**
- XDP-based MAC address filtering
- Syncs with database for user/device management
- Allowlist and blocklist support
- Automatic rule updates

### API Endpoints

#### Web Server (`webserver/`)

- `GET /api/packets/aggregate` - Aggregated packet statistics
- `POST /api/packets/clear` - Clear packet history
- `GET /api/users` - List all users
- `POST /api/users` - Create user
- `PUT /api/users/:id` - Update user
- `DELETE /api/users/:id` - Delete user
- `POST /api/users/:id/devices` - Add device to user
- `WS /ws` - WebSocket for live updates

## Troubleshooting

### Network Connectivity Issues

**Symptom**: No internet in appsns or other namespaces

Solutions:
- Check DHCP assignments: `sudo ip netns exec <ns> ip addr`
- Verify bridges are up: `sudo ip netns exec <ns> ip link show`
- Test connectivity: `sudo ip netns exec appsns ping 8.8.8.8`
- Check routing: `sudo ip netns exec <ns> ip route`
- Verify IP configuration file: `cat /tmp/kidos-network.conf`

### Wi-Fi Hotspot Issues

**Symptom**: Hotspot not starting or no DHCP for clients

Solutions:
- Check USB dongle detection: `lsusb | grep -i wifi`
- Verify driver loaded: `lsmod | grep rtw`
- Check hostapd status: `sudo ip netns exec wifins ps aux | grep hostapd`
- Verify bridge state: `sudo ip netns exec wifins ip link show br-wifi`
- Check veth connection: `sudo ip netns exec switchns bridge link show br-switch | grep wifi`
- Manual teardown and restart:
  ```bash
  sudo ./scripts/hotspot/teardown.sh
  sudo ./scripts/hotspot/init.sh
  ```

**Symptom**: Error "An interface with the same name exists"

Solution:
```bash
# Clean up lingering interfaces
sudo ip netns exec switchns ip link del veth-wifi-sw 2>/dev/null
sudo ./scripts/hotspot/teardown.sh
sudo ./scripts/hotspot/init.sh
```

### Parental Control Issues

**Symptom**: IP filter not blocking devices

Solutions:
- Check XDP attachment: `sudo ip netns exec kidosns ip link show veth-kidos-app`
- Verify BPF map: `sudo bpftool map list`
- Check ip-filter daemon logs
- Reload eBPF program: restart ip-filter daemon

**Symptom**: DNS queries not being logged

Solutions:
- Verify XDP on ethernet: `sudo ip netns exec ethns ip link show`
- Check kernel logs: `sudo dmesg | grep -i xdp`

### Monitoring System Issues

**Symptom**: No packets in dashboard

Solutions:
- Verify sniffer daemon is running: `sudo ip netns exec monns ps aux | grep sniffer`
- Check TC mirroring: `sudo ip netns exec kidosns tc filter show dev veth-kidos-app`
- Verify XDP attachment: `sudo ip netns exec monns ip link show veth-mon`
- Check WebSocket connection in browser console

### Interface Recovery

**Symptom**: Physical interface missing after teardown

Solutions:
- Check if interface is down: `ip link show`
- Bring it up: `sudo ip link set <interface> up`
- Request DHCP: `sudo dhclient <interface>`
- If still missing, reboot or reload network driver

### General Debugging

Enable verbose logging:
```bash
# Run init with bash debug
sudo bash -x ./scripts/init.sh

# Check namespace list
sudo ip netns list

# Check all interfaces
sudo ip netns exec <ns> ip link show
sudo ip netns exec <ns> ip addr show

# Monitor logs
sudo journalctl -f
sudo dmesg -w
```

## Repository

https://github.com/kidcodech/kidosserver-v1

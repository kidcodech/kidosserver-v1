# Kidos Server v1

Network namespace-based server infrastructure with packet monitoring capabilities.

## Overview

This project creates isolated network namespaces for ethernet, kidos, and applications layers, with built-in traffic monitoring using eBPF/XDP and a web-based dashboard.

## Architecture

```
┌─────────────┐
│   ethns     │ (Ethernet namespace)
│   br0       │ - Physical interface (enp0s31f6)
│             │ - DHCP from router
└──────┬──────┘
       │ veth-eth <-> veth-kidos
       │
┌──────┴──────┐
│   kidosns   │ (Kidos namespace)
│   br1       │ - Bridge connecting ethernet and apps
│             │ - DHCP from router
│             │ - TC mirroring for monitoring
└──────┬──────┘
       │ veth-kidos-app <-> veth-app
       │
┌──────┴──────┐
│   appsns    │ (Apps namespace)
│             │ - DHCP from router
└─────────────┘

       │ (mirrored packets)
       │
┌──────┴──────┐
│   monns     │ (Monitoring namespace)
│  veth-mon   │ - XDP/AF_XDP packet capture
│             │ - Go sniffer daemon
└─────────────┘
```

## Components

### Network Namespaces

- **ethns**: Holds physical ethernet interface with bridge
- **kidosns**: Middle layer with bridge, performs packet mirroring
- **appsns**: Application layer
- **monns**: Monitoring namespace for packet capture

### Monitoring System

1. **TC Mirroring** (`scripts/monitoring/init.sh`)
   - Mirrors ingress/egress traffic on veth-kidos-app
   - Sends copies to monitoring namespace

2. **XDP/AF_XDP** (`monitoring/ebpf/`)
   - High-performance packet capture
   - Redirects packets to userspace via AF_XDP sockets

3. **Sniffer Daemon** (`monitoring/sniffer/`)
   - Go daemon using AF_XDP
   - Captures packets and stores: src_ip, dst_ip, timestamp, protocol, size
   - In-memory storage

4. **Web Server** (`webserver/`)
   - REST API on port 8080
   - WebSocket for live updates
   - React frontend dashboard

## Prerequisites

- Linux kernel 5.4+ (for XDP support)
- Root/sudo access
- Packages:
  - iproute2
  - dhclient
  - tc (traffic control)
  - clang (for eBPF compilation)
  - Go 1.21+
  - Node.js 18+ (for React frontend)

## Installation

### 1. Build eBPF Program

```bash
cd monitoring/ebpf
./build.sh
```

### 2. Build Sniffer Daemon

```bash
cd monitoring/sniffer
go mod tidy
go build -o sniffer
```

### 3. Build Web Server

```bash
cd webserver
go mod tidy
go build -o webserver
```

### 4. Build Frontend

```bash
cd webserver/frontend
npm install
npm run build
```

## Usage

### Start Network Namespaces

```bash
sudo ./scripts/init.sh
```

This will:
- Create all namespaces
- Set up bridges and veth pairs
- Configure DHCP on all interfaces
- Set up monitoring with TC mirroring

### Start Monitoring

```bash
# Start sniffer daemon (in monitoring namespace)
sudo ip netns exec monns ./monitoring/sniffer/sniffer

# Start web server (in another terminal)
./webserver/webserver
```

### Access Dashboard

Open browser to: http://localhost:8080

The dashboard shows:
- Real-time packet statistics
- Aggregated flows by IP pairs and protocol
- Packet counts and total bytes
- Live updates via WebSocket

### Teardown

```bash
sudo ./scripts/teardown.sh
```

This will:
- Remove TC mirroring rules
- Delete monitoring namespace
- Remove all namespaces
- Return physical interface to default namespace

## Development

### Monitoring Scripts

- `scripts/monitoring/init.sh` - Setup monitoring namespace and TC mirroring
- `scripts/monitoring/teardown.sh` - Cleanup monitoring components

### eBPF Program

- `monitoring/ebpf/xdp_afxdp.c` - XDP program for AF_XDP
- Modify and rebuild with `./build.sh`

### Sniffer Daemon

- `monitoring/sniffer/main.go` - Main AF_XDP capture logic
- `monitoring/sniffer/store/store.go` - In-memory packet storage

### Web Server

- `webserver/main.go` - REST API and WebSocket server
- Endpoints:
  - `GET /api/packets/aggregate` - Get aggregated packet stats
  - `POST /api/packets/clear` - Clear all stored packets
  - `WS /ws` - WebSocket for live updates

### Frontend

- `webserver/frontend/src/App.jsx` - Main React component
- `webserver/frontend/src/App.css` - Styling
- Development: `npm run dev`
- Build: `npm run build`

## Troubleshooting

### No packets in dashboard
- Check if sniffer daemon is running in monns namespace
- Verify TC mirroring is active: `sudo ip netns exec kidosns tc filter show dev veth-kidos-app`
- Check XDP attachment: `sudo ip netns exec monns ip link show veth-mon`

### Network connectivity issues
- Verify DHCP obtained IPs: `sudo ip netns exec <ns> ip addr`
- Check bridges are up: `sudo ip netns exec <ns> ip link show`
- Test connectivity: `sudo ip netns exec <ns> ping 8.8.8.8`

### Physical interface missing after teardown
- Check if interface is down: `ip link show enp0s31f6`
- Bring it up: `sudo ip link set enp0s31f6 up`
- If still missing, reboot or reload network driver

## License

MIT

## Repository

https://github.com/kidcodech/kidosserver-v1

# Packet Sniffer Daemon

Go daemon that captures packets using AF_XDP and stores them in memory.

## Build

```bash
go build -o sniffer
```

## Run

The daemon must be run in the monitoring namespace:

```bash
sudo ip netns exec monns ./sniffer [interface_name]
```

Default interface: `veth-mon`

## Dependencies

- Kernel with XDP support
- clang for building eBPF program
- Go 1.21+
- Root privileges

## Storage

Packets are stored in-memory with the following information:
- Source IP
- Destination IP  
- Timestamp
- Protocol (TCP, UDP, ICMP, etc.)
- Packet size

The packet store can be accessed by the web server for aggregation and display.

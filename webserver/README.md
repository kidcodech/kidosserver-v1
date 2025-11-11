# Web Server

REST API and WebSocket server for monitoring packet statistics.

## Build

```bash
go mod tidy
go build -o webserver
```

## Run

```bash
./webserver
```

Server will start on port 8080.

## API Endpoints

### GET /api/packets/aggregate
Returns aggregated packet statistics grouped by source IP, destination IP, and protocol.

Response:
```json
[
  {
    "src_ip": "192.168.1.100",
    "dst_ip": "8.8.8.8",
    "protocol": "TCP",
    "count": 42,
    "total_size": 12345
  }
]
```

### POST /api/packets/clear
Clears all stored packets.

### WebSocket /ws
WebSocket endpoint for real-time packet statistics updates. Broadcasts aggregated stats every second.

## Frontend

The React frontend should be built and placed in `./frontend/dist` directory.

## Integration

The webserver needs access to the packet sniffer's store. This will be handled via shared memory or IPC in production.

# Device Registration & IP Filtering System

## Overview

This system implements a captive portal-style device registration system that blocks all network traffic from unregistered devices. Users must authenticate via a web interface to register their device's IP address before accessing the internet.

## Architecture

### Components

1. **Auth Frontend** (`/auth` page)
   - React-based login page
   - Auto-detects client IP address
   - Allows users to register their device with username/password

2. **Backend API** (`/api/auth/register-device`)
   - Authenticates users against the database
   - Adds client IP to user's device list
   - Notifies sync daemon to update eBPF map

3. **XDP IP Filter** (eBPF program)
   - Runs on `br1` bridge interface in kidosns namespace
   - Checks source IP against allowed IPs hash map
   - **Drops all packets from unregistered IPs**
   - Passes packets from registered IPs

4. **IP Filter Sync Daemon**
   - Reads registered IPs from SQLite database
   - Updates eBPF hash map every 5 seconds
   - Ensures eBPF map stays in sync with database

## User Flow

1. **New Device Connects**
   - All packets are dropped by XDP filter (IP not in map)
   - User cannot access internet

2. **User Visits `/auth` Page**
   - Enters username and password (created by admin in `/users` tab)
   - System auto-detects device IP
   - Optionally provides device name

3. **Authentication & Registration**
   - Backend validates credentials
   - Checks if IP already registered
   - Adds IP to database if new
   - Sync daemon picks up change within 5 seconds

4. **Internet Access Granted**
   - IP is added to eBPF map
   - XDP filter allows packets from this IP
   - User can now access internet

## Database Schema

```sql
-- Users table (admins create accounts)
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- User IPs table (devices registered via /auth)
CREATE TABLE user_ips (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    ip_address TEXT NOT NULL UNIQUE,
    device_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

## eBPF Map Structure

**Map Name:** `allowed_ips`
- **Type:** `BPF_MAP_TYPE_HASH`
- **Key:** IPv4 address (32-bit, network byte order)
- **Value:** Timestamp or flag (1 = allowed)
- **Max Entries:** 10,000 devices

**Map Name:** `stats`
- **Type:** `BPF_MAP_TYPE_ARRAY`
- **Keys:** `STAT_ALLOWED (0)`, `STAT_DROPPED (1)`
- **Values:** Packet counters

## Admin Workflow

1. Admin creates user accounts in `/users` tab of dashboard
2. Users receive username/password from admin
3. Users visit `http://<gateway>/auth` on their device
4. System automatically registers device IP
5. Admin can view all registered devices per user

## Files Modified/Created

### Frontend
- `webserver/frontend/src/components/Auth.jsx` - Auth page
- `webserver/frontend/src/main.jsx` - Added routing
- `webserver/frontend/package.json` - Added react-router-dom

### Backend
- `webserver/main.go` - Added `/api/auth/register-device` endpoint
- `webserver/db/users.go` - Added `AuthenticateUser()` function

### eBPF & Sync Daemon
- `parental/ip-filter/xdp_ip_filter.c` - XDP program
- `parental/ip-filter/main.go` - Sync daemon
- `parental/ip-filter/go.mod` - Dependencies
- `parental/ip-filter/build.sh` - Build script

### Build/Start Scripts
- `install/build-all.sh` - Added IP filter build steps
- `install/start-all.sh` - Added IP filter daemon startup
- `install/stop-all.sh` - Added IP filter cleanup

## Testing

### 1. Build Everything
```bash
sudo ./scripts/teardown.sh  # If namespaces active
./install/build-all.sh
```

### 2. Start System
```bash
sudo ./scripts/init.sh      # First time only
sudo ./install/start-all.sh
```

### 3. Get WebServer URL
Clients access the webserver via DNS: `http://router.kidos.tools/`

(The DNS inspector resolves "kidos" to the br1 bridge IP)

### 4. Create Admin User
Visit `http://router.kidos.tools/` from any device on your network
- Go to "Users" tab
- Click "Add User"
- Create: username=`john`, password=`password123`, display_name=`John Doe`

### 5. Test Device Registration
From a client device on the same network:
```bash
# Visit auth page
http://router.kidos.tools/auth

# Or via curl:
curl -X POST http://router.kidos.tools/api/auth/register-device \
  -H "Content-Type: application/json" \
  -d '{"username":"john","password":"password123","device_name":"My Phone"}'
```

### 6. Verify IP Filter
Check sync daemon logs:
```bash
sudo tail -f /tmp/kidos-ip-filter.log
```

Should see:
```
Synced IPs: 1 total, +1 added, -0 removed
Stats: Allowed=X, Dropped=Y
```

## Troubleshooting

### Packets Still Being Dropped After Registration
- Check if IP was added to database: `sudo sqlite3 /var/lib/kidos/users.db "SELECT * FROM user_ips;"`
- Check sync daemon logs: `sudo tail /tmp/kidos-ip-filter.log`
- Manually trigger sync (daemon syncs every 5 seconds automatically)

### Auth Page Not Loading
- Check webserver logs: `sudo tail /tmp/kidos-webserver.log`
- Verify frontend built: `ls webserver/frontend/dist`
- Check routing: React Router should handle `/auth` route

### XDP Program Not Attached
```bash
# Check if XDP program is loaded
sudo ip netns exec kidosns ip link show br1

# Should show: xdp/id:XXXX
# If not, manually load:
sudo ip netns exec kidosns ip link set br1 xdpgeneric obj parental/ip-filter/xdp_ip_filter.o sec xdp
```

### Database Errors
```bash
# Check database exists
ls -la /var/lib/kidos/users.db

# Check schema
sudo sqlite3 /var/lib/kidos/users.db ".schema"
```

## Security Notes

1. **Password Storage:** Passwords are hashed with bcrypt (cost factor 10-12)
2. **No Session Persistence:** Registration is IP-based only
3. **IP Spoofing:** System trusts source IP (acceptable for local network)
4. **DHCP Changes:** If client gets new IP, must re-register
5. **Admin Access:** No authentication on dashboard (assume trusted network)

## Future Enhancements

1. **Cookie-based sessions** for better UX across IP changes
2. **Device fingerprinting** (MAC address, user-agent)
3. **Automatic re-registration** when IP changes but cookie valid
4. **Rate limiting** on authentication attempts
5. **Admin authentication** for dashboard access
6. **HTTPS** support for secure password transmission

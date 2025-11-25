package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/kidcodech/kidosserver-v1/webserver/db"
)

const (
	dbPath           = "/var/lib/kidos/users.db"
	syncInterval     = 5 * time.Second
	xdpIPFilterPath  = "/home/aigarssu/kidos/kidosserver-v1/parental/ip-filter/xdp_ip_filter.o"
	xdpDNSFilterPath = "/home/aigarssu/kidos/kidosserver-v1/parental/dns-inspector/ebpf/xdp_dns.o"
	interfaceName    = "veth-kidos-app"
	kidosNamespace   = "kidosns"
)

var (
	allowedIPsMap *ebpf.Map
	statsMap      *ebpf.Map
	xsksMap       *ebpf.Map
)

func main() {
	log.Println("Starting IP Filter Sync Daemon...")

	// Initialize database connection
	if err := db.InitDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.DB.Close()

	// Find already-loaded eBPF maps (XDP program must be attached first)
	if err := findLoadedMaps(); err != nil {
		log.Fatalf("Failed to find eBPF maps: %v", err)
	}
	log.Println("✓ Found all required eBPF maps")
	defer allowedIPsMap.Close()
	defer statsMap.Close()

	// Initial sync
	if err := syncIPsFromDatabase(); err != nil {
		log.Printf("Initial sync failed: %v", err)
	}

	// Setup signal handler for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start periodic sync
	ticker := time.NewTicker(syncInterval)
	defer ticker.Stop()

	log.Printf("Sync daemon running (interval: %v)", syncInterval)

	for {
		select {
		case <-ticker.C:
			if err := syncIPsFromDatabase(); err != nil {
				log.Printf("Sync error: %v", err)
			}
		case <-sigChan:
			log.Println("Shutting down...")
			return
		}
	}
}

// findLoadedMaps searches for already-loaded maps by name (XDP program must be attached first)
func findLoadedMaps() error {
	log.Println("Searching for already-loaded eBPF maps...")

	// Search for allowed_ips map
	for mapID := ebpf.MapID(10000); mapID >= 1; mapID-- {
		m, err := ebpf.NewMapFromID(mapID)
		if err != nil {
			continue
		}
		info, err := m.Info()
		if err != nil {
			m.Close()
			continue
		}
		if info.Name == "allowed_ips" && info.Type == ebpf.Hash {
			allowedIPsMap = m
			log.Printf("✓ Found allowed_ips map (ID %d)", mapID)
			break
		}
		m.Close()
	}
	if allowedIPsMap == nil {
		return fmt.Errorf("allowed_ips map not found - is XDP program loaded?")
	}

	// Search for stats map
	for mapID := ebpf.MapID(10000); mapID >= 1; mapID-- {
		m, err := ebpf.NewMapFromID(mapID)
		if err != nil {
			continue
		}
		info, err := m.Info()
		if err != nil {
			m.Close()
			continue
		}
		if info.Name == "stats" && info.Type == ebpf.Array {
			statsMap = m
			log.Printf("✓ Found stats map (ID %d)", mapID)
			break
		}
		m.Close()
	}
	if statsMap == nil {
		return fmt.Errorf("stats map not found - is XDP program loaded?")
	}

	// Search for xsks_map (shared with DNS inspector)
	for mapID := ebpf.MapID(10000); mapID >= 1; mapID-- {
		m, err := ebpf.NewMapFromID(mapID)
		if err != nil {
			continue
		}
		info, err := m.Info()
		if err != nil {
			m.Close()
			continue
		}
		if info.Name == "xsks_map" && info.Type == ebpf.XSKMap {
			xsksMap = m
			log.Printf("✓ Found xsks_map (ID %d) - DNS inspector AF_XDP socket", mapID)
			break
		}
		m.Close()
	}
	if xsksMap == nil {
		log.Println("⚠ xsks_map not found - DNS redirection may not work (DNS inspector not running?)")
	}

	return nil
}

// syncIPsFromDatabase reads all allowed IPs from database and updates the eBPF map
func syncIPsFromDatabase() error {
	// Get all registered IP addresses from database
	rows, err := db.DB.Query("SELECT DISTINCT ip_address FROM user_ips")
	if err != nil {
		return fmt.Errorf("failed to query IPs: %w", err)
	}
	defer rows.Close()

	// Collect all IPs from database
	dbIPs := make(map[uint32]bool)
	var count int

	for rows.Next() {
		var ipStr string
		if err := rows.Scan(&ipStr); err != nil {
			log.Printf("Error scanning IP: %v", err)
			continue
		}

		ipNum, err := ipToUint32(ipStr)
		if err != nil {
			log.Printf("Invalid IP address %s: %v", ipStr, err)
			continue
		}

		dbIPs[ipNum] = true
		count++
	}

	// Get all IPs currently in the eBPF map
	mapIPs := make(map[uint32]bool)
	var key, value uint32
	iter := allowedIPsMap.Iterate()

	for iter.Next(&key, &value) {
		mapIPs[key] = true
	}
	if err := iter.Err(); err != nil {
		log.Printf("Error iterating map: %v", err)
	}

	// Add new IPs to map
	added := 0
	for ip := range dbIPs {
		if !mapIPs[ip] {
			value := uint32(1) // Mark as allowed
			if err := allowedIPsMap.Put(&ip, &value); err != nil {
				log.Printf("Failed to add IP to map: %v", err)
			} else {
				added++
			}
		}
	}

	// Remove IPs that are no longer in database
	removed := 0
	for ip := range mapIPs {
		if !dbIPs[ip] {
			if err := allowedIPsMap.Delete(&ip); err != nil {
				log.Printf("Failed to remove IP from map: %v", err)
			} else {
				removed++
			}
		}
	}

	if added > 0 || removed > 0 {
		log.Printf("Synced IPs: %d total, +%d added, -%d removed", count, added, removed)
	}

	// Log stats
	printStats()

	return nil
}

// ipToUint32 converts an IP string to uint32 in network byte order
func ipToUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP address")
	}

	ip = ip.To4()
	if ip == nil {
		return 0, fmt.Errorf("not an IPv4 address")
	}

	// Convert to uint32 in network byte order (big endian)
	return binary.LittleEndian.Uint32(ip), nil
}

// printStats prints current filter statistics
func printStats() {
	var allowed, dropped uint64
	keyAllowed := uint32(0)
	keyDropped := uint32(1)

	if err := statsMap.Lookup(&keyAllowed, &allowed); err == nil {
		if err := statsMap.Lookup(&keyDropped, &dropped); err == nil {
			if allowed > 0 || dropped > 0 {
				log.Printf("Stats: Allowed=%d, Dropped=%d", allowed, dropped)
			}
		}
	}
}

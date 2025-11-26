package main

import (
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
	allowedMACsMap *ebpf.Map
	droppedMACsMap *ebpf.Map
	statsMap       *ebpf.Map
	xsksMap        *ebpf.Map
)

func main() {
	log.Println("Starting MAC Filter Sync Daemon...")

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
	defer allowedMACsMap.Close()
	defer droppedMACsMap.Close()
	defer statsMap.Close()

	// Initial sync
	if err := syncMACsFromDatabase(); err != nil {
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
			if err := syncMACsFromDatabase(); err != nil {
				log.Printf("Sync error: %v", err)
			}
			if err := processDroppedMACs(); err != nil {
				log.Printf("Process dropped MACs error: %v", err)
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

	// Search for allowed_macs map
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
		if info.Name == "allowed_macs" && info.Type == ebpf.Hash {
			allowedMACsMap = m
			log.Printf("✓ Found allowed_macs map (ID %d)", mapID)
			break
		}
		m.Close()
	}
	if allowedMACsMap == nil {
		return fmt.Errorf("allowed_macs map not found - is XDP program loaded?")
	}

	// Search for dropped_macs map
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
		if info.Name == "dropped_macs" && info.Type == ebpf.Hash {
			droppedMACsMap = m
			log.Printf("✓ Found dropped_macs map (ID %d)", mapID)
			break
		}
		m.Close()
	}
	if droppedMACsMap == nil {
		return fmt.Errorf("dropped_macs map not found - is XDP program loaded?")
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

// syncMACsFromDatabase reads all allowed MAC addresses from database and updates the eBPF map
func syncMACsFromDatabase() error {
	// Get all registered MAC addresses from database
	rows, err := db.DB.Query("SELECT DISTINCT mac_address FROM user_devices")
	if err != nil {
		return fmt.Errorf("failed to query MACs: %w", err)
	}
	defer rows.Close()

	// Collect all MACs from database
	dbMACs := make(map[string]bool)
	var count int

	for rows.Next() {
		var macStr string
		if err := rows.Scan(&macStr); err != nil {
			log.Printf("Error scanning MAC: %v", err)
			continue
		}

		dbMACs[macStr] = true
		count++
	}

	// Get all MACs currently in the eBPF map
	mapMACs := make(map[string]bool)
	var key [6]byte
	var value uint32
	iter := allowedMACsMap.Iterate()

	for iter.Next(&key, &value) {
		macStr := macToString(key[:])
		mapMACs[macStr] = true
	}
	if err := iter.Err(); err != nil {
		log.Printf("Error iterating map: %v", err)
	}

	// Add new MACs to map
	added := 0
	for macStr := range dbMACs {
		if !mapMACs[macStr] {
			macBytes, err := macToBytes(macStr)
			if err != nil {
				log.Printf("Invalid MAC address %s: %v", macStr, err)
				continue
			}
			value := uint32(1) // Mark as allowed
			if err := allowedMACsMap.Put(macBytes, &value); err != nil {
				log.Printf("Failed to add MAC to map: %v", err)
			} else {
				added++
			}
		}
	}

	// Remove MACs that are no longer in database
	removed := 0
	for macStr := range mapMACs {
		if !dbMACs[macStr] {
			macBytes, err := macToBytes(macStr)
			if err != nil {
				continue
			}
			if err := allowedMACsMap.Delete(macBytes); err != nil {
				log.Printf("Failed to remove MAC from map: %v", err)
			} else {
				removed++
			}
		}
	}

	if added > 0 || removed > 0 {
		log.Printf("Synced MACs: %d total, +%d added, -%d removed", count, added, removed)
	}

	// Log stats
	printStats()

	return nil
}

// macToBytes converts MAC string (AA:BB:CC:DD:EE:FF) to 6-byte array
func macToBytes(macStr string) (*[6]byte, error) {
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		return nil, err
	}
	if len(mac) != 6 {
		return nil, fmt.Errorf("invalid MAC length")
	}
	var macBytes [6]byte
	copy(macBytes[:], mac)
	return &macBytes, nil
}

// macToString converts 6-byte MAC to string format (aa:bb:cc:dd:ee:ff)
func macToString(mac []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
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

// processDroppedMACs reads dropped MACs from BPF map and records them in database
func processDroppedMACs() error {
	var key [6]byte
	// Packed struct to match C struct with __attribute__((packed))
	var value struct {
		Mac   [6]byte
		IP    uint32
		Count uint64
	}
	iter := droppedMACsMap.Iterate()

	recorded := 0
	for iter.Next(&key, &value) {
		if value.Count == 0 {
			continue
		}

		// Convert MAC to string
		macStr := macToString(key[:])

		// Convert IP to string (network byte order)
		ipStr := fmt.Sprintf("%d.%d.%d.%d",
			byte(value.IP), byte(value.IP>>8), byte(value.IP>>16), byte(value.IP>>24))

		// Record in database with IP from packet
		if err := db.RecordUnregisteredDevice(macStr, ipStr); err != nil {
			log.Printf("Failed to record unregistered device %s (%s): %v", macStr, ipStr, err)
		} else {
			recorded++
		}

		// Clear the counter for this MAC (we've recorded it)
		value.Count = 0
		if err := droppedMACsMap.Put(&key, &value); err != nil {
			log.Printf("Failed to reset counter for %s: %v", macStr, err)
		}
	}

	if err := iter.Err(); err != nil {
		return fmt.Errorf("error iterating dropped_macs map: %w", err)
	}

	if recorded > 0 {
		log.Printf("Recorded %d unregistered device attempt(s)", recorded)
	}

	return nil
}

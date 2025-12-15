package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/kidcodech/kidosserver-v1/webserver/db"
)

// DNSRequest represents a captured DNS query
type DNSRequest struct {
	Timestamp  time.Time
	SrcIP      string
	Domain     string
	QueryType  string
	QueryClass string
}

var (
	dnsRequests        []DNSRequest
	dnsMutex           sync.RWMutex
	userBlockedDomains map[int]map[string]bool // userID -> domain -> blocked
	userMACMap         map[string]int          // macAddress -> userID
	blockingMutex      sync.RWMutex
	captivePortalIP    string
	kidosIP            string // IP address for kidos domain, loaded from config
	domainSyncInterval = 10 * time.Second
)

func loadKidosIP() {
	configFile := "/tmp/kidos-network.conf"
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatalf("Failed to read network config %s: %v", configFile, err)
	}

	// Parse simple KEY="VALUE" format
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "BR1_IP=") {
			// Extract value between quotes
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				ip := strings.Trim(parts[1], "\"")
				kidosIP = ip
				log.Printf("✓ Loaded kidos IP from config: %s", kidosIP)
				return
			}
		}
	}
	log.Fatalf("BR1_IP not found in config file %s", configFile)
}

// syncBlockedDomainsFromDB loads per-user blocked domains from database
func syncBlockedDomainsFromDB() {
	// Get all blocked domains organized by user
	blockedMap, err := db.GetAllBlockedDomainsMap()
	if err != nil {
		log.Printf("Error loading blocked domains from database: %v", err)
		return
	}

	// Get MAC to user mapping
	macMap := make(map[string]int)
	rows, err := db.DB.Query("SELECT mac_address, user_id FROM user_devices")
	if err != nil {
		log.Printf("Error loading user devices: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var mac string
		var userID int
		if err := rows.Scan(&mac, &userID); err != nil {
			log.Printf("Error scanning MAC: %v", err)
			continue
		}
		macMap[mac] = userID
	}

	// Update global maps
	blockingMutex.Lock()
	userBlockedDomains = blockedMap
	userMACMap = macMap
	blockingMutex.Unlock()

	totalDomains := 0
	for _, domains := range blockedMap {
		totalDomains += len(domains)
	}
	log.Printf("✓ Synced %d blocked domains for %d users, %d MACs mapped",
		totalDomains, len(blockedMap), len(macMap))
}

// logBlockedDomainToServer sends blocked domain log to webserver
func logBlockedDomainToServer(domain, deviceMAC, ipAddress string) {
	blockingMutex.RLock()
	userID, exists := userMACMap[deviceMAC]
	blockingMutex.RUnlock()

	if !exists {
		return // Unknown MAC, skip logging
	}

	// Get user info from database
	user, err := db.GetUser(userID)
	if err != nil {
		log.Printf("Failed to get user for logging: %v", err)
		return
	}

	// Get device info
	devices, err := db.GetUserDevices(userID)
	if err != nil {
		log.Printf("Failed to get devices for logging: %v", err)
		return
	}

	var deviceName string
	for _, dev := range devices {
		if dev.MACAddress == deviceMAC {
			deviceName = dev.DeviceName
			break
		}
	}

	// Prepare log entry
	logEntry := map[string]interface{}{
		"domain":      domain,
		"user_id":     userID,
		"user_name":   user.DisplayName,
		"device_mac":  deviceMAC,
		"device_name": deviceName,
		"ip_address":  ipAddress,
	}

	jsonData, err := json.Marshal(logEntry)
	if err != nil {
		log.Printf("Failed to marshal log entry: %v", err)
		return
	}

	// Send to webserver
	resp, err := http.Post("http://192.168.1.6/api/dns/log-block",
		"application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Failed to log blocked domain: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Printf("Failed to log blocked domain (status %d): %s", resp.StatusCode, string(body))
	}
}

// startDomainSyncWorker periodically syncs blocked domains from database
func startDomainSyncWorker() {
	ticker := time.NewTicker(domainSyncInterval)
	go func() {
		for range ticker.C {
			syncBlockedDomainsFromDB()
		}
	}()
}

// isBlockedForMAC checks if a domain is blocked for the user associated with a MAC
func isBlockedForMAC(srcMAC, domain string) bool {
	blockingMutex.RLock()
	defer blockingMutex.RUnlock()

	// Get user ID from MAC
	userID, exists := userMACMap[srcMAC]
	if !exists {
		return false // Unknown MAC, not blocked
	}

	// Check if domain is blocked for this user
	if userDomains, ok := userBlockedDomains[userID]; ok {
		return userDomains[domain]
	}

	return false
}

// logBlockedDomainAttempt logs a blocked domain to the database
func logBlockedDomainAttempt(domain, srcMAC, srcIP, queryType string) {
	blockingMutex.RLock()
	userID, exists := userMACMap[srcMAC]
	blockingMutex.RUnlock()

	if !exists {
		return // Unknown MAC
	}

	// Perform logging asynchronously to avoid blocking packet processing
	go func() {
		// Get user details from database
		user, err := db.GetUser(userID)
		if err != nil {
			log.Printf("Failed to get user info for logging: %v", err)
			return
		}

		// Get device details from the user's devices
		userWithDevices, err := db.GetUserByMAC(srcMAC)
		if err != nil {
			log.Printf("Failed to get device info for logging: %v", err)
			return
		}

		// Find the specific device
		deviceName := ""
		for _, device := range userWithDevices.Devices {
			if device.MACAddress == srcMAC {
				deviceName = device.DeviceName
				break
			}
		}

		// Log directly to database
		err = db.LogBlockedDomain(domain, userID, user.DisplayName, srcMAC, deviceName, srcIP, queryType)
		if err != nil {
			log.Printf("Failed to log blocked domain to DB: %v", err)
		} else {
			log.Printf("Successfully logged blocked domain to DB: %s (%s)", domain, queryType)
		}
	}()
}

func loadBlockedDomains() {
	// Deprecated: Now loads from database
	log.Println("Loading per-user blocked domains from database...")
	syncBlockedDomainsFromDB()
}

func saveBlockedDomains() {
	// Deprecated: Now saves to database via API
	log.Println("Note: Blocked domains are now managed per-user in database")
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: dns-inspector <interface>")
	}

	ifaceName := os.Args[1]
	log.Printf("Starting DNS inspector on interface: %s", ifaceName)

	// Initialize database connection
	if err := db.InitDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.DB.Close()

	// Initialize per-user blocked domains
	userBlockedDomains = make(map[int]map[string]bool)
	userMACMap = make(map[string]int)
	loadBlockedDomains()
	log.Println("✓ Initialized per-user blocked domains")

	// Start background sync worker
	startDomainSyncWorker()

	// Load kidos IP from network config
	loadKidosIP()

	// Detect br1 IP address for captive portal
	br1Iface, err := net.InterfaceByName("br1")
	if err != nil {
		log.Fatalf("Failed to get br1 interface: %v", err)
	}
	addrs, err := br1Iface.Addrs()
	if err != nil {
		log.Fatalf("Failed to get br1 addresses: %v", err)
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			captivePortalIP = ipnet.IP.String()
			log.Printf("Captive portal IP detected: %s", captivePortalIP)
			break
		}
	}
	if captivePortalIP == "" {
		log.Fatal("Failed to detect br1 IPv4 address")
	}

	// Get interface index
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Failed to get interface %s: %v", ifaceName, err)
	}
	log.Printf("✓ Found interface %s (index: %d)", ifaceName, iface.Index)

	// Find the xsks_map that's already loaded by the XDP program
	// Search from highest ID backwards to get the most recently loaded map
	var xsksMap *ebpf.Map
	var mapID ebpf.MapID
	log.Println("Searching for xsks_map...")
	// Start from a high ID and search backwards to find the latest map
	for mapID = 10000; mapID >= 1; mapID-- {
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
			log.Printf("✓ Found xsks_map with ID %d (type=%v, name=%s)", mapID, info.Type, info.Name)
			break
		}
		m.Close()
	}

	if xsksMap == nil {
		log.Fatal("xsks_map not found - is XDP program loaded?")
	}
	log.Println("✓ xsks_map ready for socket registration")
	defer xsksMap.Close()

	// 1. Create AF_XDP socket for a specific queue (queue 0)
	queueID := uint32(0)
	log.Printf("Creating AF_XDP socket for queue %d...", queueID)
	xsk, err := xdp.NewSocket(iface.Index, int(queueID), nil)
	if err != nil {
		log.Fatalf("Failed to create XDP socket: %v", err)
	}

	log.Println("AF_XDP socket created successfully")

	// 2. Force the socket to finalize its setup by filling the RX ring.
	// This ensures the UMEM is configured and the socket is bound before we access its FD.
	log.Println("Initializing RX ring...")
	if n := xsk.NumFreeFillSlots(); n > 0 {
		xsk.Fill(xsk.GetDescs(n))
		log.Printf("✓ Filled %d initial descriptors to RX ring", n)
	}

	// 3. NOW it is safe to get the FD and register it in the map for the correct queue.
	socketFD := uint32(xsk.FD())
	log.Printf("Registering socket FD %d in xsks_map for queue %d...", socketFD, queueID)
	if err := xsksMap.Put(&queueID, &socketFD); err != nil {
		xsk.Close()
		log.Fatalf("Failed to register socket FD %d in xsks_map for queue %d: %v", socketFD, queueID, err)
	}

	log.Printf("Socket FD %d successfully registered for queue %d", socketFD, queueID)

	// 4. Defer the cleanup: unregister the FD from the map and then close the socket.
	defer func() {
		log.Printf("Cleaning up: unregistering socket from queue %d", queueID)
		if err := xsksMap.Delete(&queueID); err != nil {
			log.Printf("Warning: failed to delete socket from xsks_map: %v", err)
		}
		xsk.Close()
	}()

	log.Println("Socket registered with XDP program")

	// Create reinjection sockets - one for original packets (bridge), one for crafted responses (app interface)
	log.Println("Creating packet reinjection sockets...")
	reinjectSocketFd, reinjectAddr, err := createReinjectSocket("veth-kidos")
	if err != nil {
		log.Fatalf("Failed to create reinjection socket for veth-kidos: %v", err)
	}
	defer syscall.Close(reinjectSocketFd)
	log.Printf("✓ Reinjection socket created for veth-kidos (FD: %d)", reinjectSocketFd)

	craftedSocketFd, craftedAddr, err := createReinjectSocket("veth-kidos-app")
	if err != nil {
		log.Fatalf("Failed to create reinjection socket for veth-kidos-app: %v", err)
	}
	defer syscall.Close(craftedSocketFd)
	log.Printf("✓ Reinjection socket created for veth-kidos-app (FD: %d)", craftedSocketFd)

	// Start Unix socket server
	socketPath := "/tmp/kidos-dns-inspector.sock"
	log.Printf("Starting Unix socket server at %s...", socketPath)
	go startUnixSocketServer(socketPath)

	// Handle signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	log.Println("✓ Signal handlers registered")

	// Start packet processing
	log.Println("Launching packet processing goroutine...")
	go processPackets(xsk, reinjectSocketFd, &reinjectAddr, craftedSocketFd, &craftedAddr)

	log.Println("DNS inspector started, press Ctrl+C to stop")
	log.Println("========================================")
	<-sigChan

	log.Println("Shutting down DNS inspector...")
	os.Remove(socketPath)
}

func processPackets(xsk *xdp.Socket, reinjectFd int, reinjectAddr *syscall.SockaddrLinklayer, craftedFd int, craftedAddr *syscall.SockaddrLinklayer) {
	log.Println("Starting packet processing loop...")

	// Fill the RX ring with available buffers
	numFree := xsk.NumFreeFillSlots()
	if numFree > 0 {
		descs := xsk.GetDescs(numFree)
		xsk.Fill(descs)
		log.Printf("Filled %d descriptors for RX", len(descs))
	}

	for {
		// Receive packet from XDP socket
		numRx, _, err := xsk.Poll(-1)
		if err != nil {
			log.Printf("Poll error: %v", err)
			continue
		}

		if numRx == 0 {
			continue
		}

		log.Printf("Received %d packets from AF_XDP", numRx)

		// Receive the frames from RX ring (this also marks them as consumed)
		rxDescs := xsk.Receive(numRx)
		log.Printf("len(rxDescs) %d", len(rxDescs))

		for i := 0; i < len(rxDescs); i++ {
			// Get packet data - this is the full 2048 byte frame
			frameData := xsk.GetFrame(rxDescs[i])
			log.Printf("frameData %d", len(frameData))
			// The actual packet length is in the IP header
			// Ethernet: 14 bytes
			// IP header starts at byte 14
			// IP total length is at bytes 16-17 (offset 2-3 in IP header)
			if len(frameData) < 34 { // Min: 14 (eth) + 20 (IP)
				continue
			}

			log.Printf("frame data %d %d", int(frameData[16]), int(frameData[17]))

			// Read IP total length (big endian)
			ipTotalLen := int(frameData[16])<<8 | int(frameData[17])
			actualLen := 14 + ipTotalLen // Ethernet header + IP packet

			if actualLen > len(frameData) || actualLen < 34 {
				// Invalid length, skip
				log.Printf("invalid length %d", actualLen)
				continue
			}

			actualPacket := frameData[:actualLen]

			// Parse DNS packet and check if blocked or kidos
			shouldIntercept, domain, srcMAC, srcIP, queryType := checkAndParseDNS(actualPacket)

			if shouldIntercept {
				// Check if it's kidos domain or blocked domain
				normalizedDomain := strings.TrimSuffix(strings.ToLower(domain), ".")
				if normalizedDomain == "kidos" {
					// Kidos domain - craft DNS response pointing to kidos IP
					log.Printf("KIDOS: DNS query for %s - resolving to %s", domain, kidosIP)
					response := craftDNSResponse(actualPacket, kidosIP)
					if response != nil {
						// Reinject crafted response to veth-kidos-app
						err := reinjectPacket(craftedFd, craftedAddr, response)
						if err != nil {
							log.Printf("Failed to reinject kidos DNS response: %v", err)
						} else {
							log.Printf("✓ Kidos DNS response reinjected to veth-kidos-app (%d bytes)", len(response))
						}
					}
				} else {
					// Domain is blocked - craft DNS response pointing to captive portal
					log.Printf("BLOCKED: DNS query for %s - redirecting to captive portal %s", domain, captivePortalIP)

					// Log the blocked domain attempt
					logBlockedDomainAttempt(domain, srcMAC, srcIP, queryType)

					response := craftDNSResponse(actualPacket, captivePortalIP)
					if response != nil {
						// Reinject crafted response to veth-kidos-app
						err := reinjectPacket(craftedFd, craftedAddr, response)
						if err != nil {
							log.Printf("Failed to reinject blocked DNS response: %v", err)
						} else {
							log.Printf("✓ Blocked DNS response reinjected to veth-kidos-app (%d bytes)", len(response))
						}
					}
				}
			} else {
				// Not blocked - parse and log, then reinject original packet
				parseDNSPacket(actualPacket)

				// Debug: log packet details before reinjection
				log.Printf("logPacketDetails")
				logPacketDetails(actualPacket)

				// Reinject original packet to veth-kidos (bridge)
				err := reinjectPacket(reinjectFd, reinjectAddr, actualPacket)
				if err != nil {
					log.Printf("Failed to reinject packet: %v", err)
				} else {
					log.Printf("✓ Original packet reinjected to veth-kidos (%d bytes)", len(actualPacket))
				}
			}
		}

		// CRITICAL: Refill RX ring with the descriptors we just consumed
		// This allows the kernel to reuse these buffers for new packets
		xsk.Fill(rxDescs)
		log.Printf("✓ Refilled %d descriptors to RX ring", len(rxDescs))
	}
}

func parseDNSPacket(data []byte) {
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

	// Extract IP layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)

	// Extract DNS layer
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}
	dns, _ := dnsLayer.(*layers.DNS)

	// Only process queries
	if dns.QR {
		return
	}

	// Extract query information
	if len(dns.Questions) == 0 {
		return
	}

	question := dns.Questions[0]
	domain := string(question.Name)
	queryType := question.Type.String()
	queryClass := question.Class.String()

	// Store DNS request
	req := DNSRequest{
		Timestamp:  time.Now(),
		SrcIP:      ip.SrcIP.String(),
		Domain:     domain,
		QueryType:  queryType,
		QueryClass: queryClass,
	}

	dnsMutex.Lock()
	dnsRequests = append(dnsRequests, req)
	dnsMutex.Unlock()

	log.Printf("DNS Query: %s -> %s [%s/%s]", ip.SrcIP, domain, queryType, queryClass)
}

// checkAndParseDNS checks if a DNS query is for a blocked domain or kidos domain
// Returns (isBlocked/isKidos, domainName, srcMAC, srcIP)
func checkAndParseDNS(data []byte) (bool, string, string, string, string) {
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

	// Extract Ethernet layer to get source MAC
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return false, "", "", "", ""
	}
	eth, _ := ethLayer.(*layers.Ethernet)
	srcMAC := eth.SrcMAC.String()

	// Extract IP layer to get source IP
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	srcIP := ""
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
	}

	// Extract DNS layer
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return false, "", "", "", ""
	}
	dns, _ := dnsLayer.(*layers.DNS)

	// Only check queries (not responses)
	if dns.QR || len(dns.Questions) == 0 {
		return false, "", "", "", ""
	}

	domain := string(dns.Questions[0].Name)
	queryType := dns.Questions[0].Type.String()

	//add domain logging
	log.Printf("Checked DNS query for domain: %s (Type: %s)", domain, queryType)

	// Normalize domain: lowercase and remove trailing dot
	normalizedDomain := strings.TrimSuffix(strings.ToLower(domain), ".")
	log.Printf("DEBUG: normalizedDomain='%s' (len=%d), comparing to 'kidos'", normalizedDomain, len(normalizedDomain))

	// Check for kidos domain (exact match)
	if normalizedDomain == "kidos" {
		log.Printf("KIDOS domain detected: %s - resolving to %s", domain, kidosIP)
		return true, domain, srcMAC, srcIP, queryType
	}

	// Check if domain is blocked for this source MAC
	blockingMutex.RLock()
	defer blockingMutex.RUnlock()

	// Get user ID from source MAC
	userID, exists := userMACMap[srcMAC]
	if !exists {
		return false, domain, srcMAC, srcIP, queryType // Unknown MAC, not blocked
	}

	// Get blocked domains for this user
	userDomains, ok := userBlockedDomains[userID]
	if !ok {
		return false, domain, srcMAC, srcIP, queryType // No blocked domains for this user
	}

	// Check exact match and parent domains using normalized domain
	parts := splitDomain(normalizedDomain)
	for i := 0; i < len(parts); i++ {
		checkDomain := joinDomain(parts[i:])
		log.Printf("Checking domain for user %d: %s", userID, checkDomain)
		if userDomains[checkDomain] {
			log.Printf("Blocked domain detected for user %d: %s", userID, checkDomain)
			return true, domain, srcMAC, srcIP, queryType
		}

		// Also check www. variant
		var wwwVariant string
		if strings.HasPrefix(checkDomain, "www.") {
			// Remove www.
			wwwVariant = strings.TrimPrefix(checkDomain, "www.")
		} else {
			// Add www.
			wwwVariant = "www." + checkDomain
		}
		log.Printf("Checking www variant for user %d: %s", userID, wwwVariant)
		if userDomains[wwwVariant] {
			log.Printf("Blocked domain detected (www variant) for user %d: %s", userID, wwwVariant)
			return true, domain, srcMAC, srcIP, queryType
		}
	}

	return false, domain, srcMAC, srcIP, queryType
}

// splitDomain splits a domain into parts (e.g., "www.example.com" -> ["www", "example", "com"])
func splitDomain(domain string) []string {
	// Remove trailing dot if present
	domain = trimSuffix(domain, ".")
	var parts []string
	current := ""
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(domain[i])
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

// joinDomain joins domain parts with dots
func joinDomain(parts []string) string {
	result := ""
	for i, part := range parts {
		if i > 0 {
			result += "."
		}
		result += part
	}
	return result
}

// trimSuffix removes suffix from string
func trimSuffix(s, suffix string) string {
	if len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix {
		return s[:len(s)-len(suffix)]
	}
	return s
}

// craftDNSResponse creates a DNS response packet pointing to captive portal IP
func craftDNSResponse(requestData []byte, captiveIP string) []byte {
	packet := gopacket.NewPacket(requestData, layers.LayerTypeEthernet, gopacket.Default)

	// Extract layers
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	dnsLayer := packet.Layer(layers.LayerTypeDNS)

	if ethLayer == nil || ipLayer == nil || udpLayer == nil || dnsLayer == nil {
		return nil
	}

	eth := ethLayer.(*layers.Ethernet)
	ip := ipLayer.(*layers.IPv4)
	udp := udpLayer.(*layers.UDP)
	dns := dnsLayer.(*layers.DNS)

	// Swap Ethernet addresses
	eth.SrcMAC, eth.DstMAC = eth.DstMAC, eth.SrcMAC

	// Swap IP addresses
	ip.SrcIP, ip.DstIP = ip.DstIP, ip.SrcIP

	// Swap UDP ports
	udp.SrcPort, udp.DstPort = udp.DstPort, udp.SrcPort

	// Create DNS response
	dns.QR = true // This is a response
	dns.AA = true // Authoritative answer
	dns.RA = true // Recursion available
	dns.ResponseCode = layers.DNSResponseCodeNoErr

	// Add answer for A record queries
	if len(dns.Questions) > 0 && dns.Questions[0].Type == layers.DNSTypeA {
		dns.Answers = []layers.DNSResourceRecord{
			{
				Name:  dns.Questions[0].Name,
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				TTL:   1, // Minimum TTL - 1 second
				IP:    net.ParseIP(captiveIP).To4(),
			},
		}
		dns.ANCount = 1
	}

	// Serialize the packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	udp.SetNetworkLayerForChecksum(ip)

	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, dns); err != nil {
		log.Printf("Failed to serialize DNS response: %v", err)
		return nil
	}

	return buf.Bytes()
}

func logPacketDetails(data []byte) {
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)

	// Extract IP layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		log.Printf("REINJECT: Non-IPv4 packet, len=%d", len(data))
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)

	// Check if DNS
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)
		domain := ""
		if len(dns.Questions) > 0 {
			domain = string(dns.Questions[0].Name)
		}
		log.Printf("REINJECT: %s -> %s | DNS: %s | len=%d", ip.SrcIP, ip.DstIP, domain, len(data))
	} else {
		log.Printf("REINJECT: %s -> %s | Non-DNS | len=%d", ip.SrcIP, ip.DstIP, len(data))
	}
}

func createReinjectSocket(ifaceName string) (int, syscall.SockaddrLinklayer, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return -1, syscall.SockaddrLinklayer{}, fmt.Errorf("failed to get %s interface: %v", ifaceName, err)
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return -1, syscall.SockaddrLinklayer{}, fmt.Errorf("socket creation failed: %v", err)
	}

	addr := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  iface.Index,
	}
	return fd, addr, nil
}

func reinjectPacket(fd int, addr *syscall.SockaddrLinklayer, data []byte) error {
	// Recalculate checksums before reinjection
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

	// Get layers for checksum recalculation
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp := udpLayer.(*layers.UDP)

			// Set checksum to zero before recalculation
			udp.Checksum = 0

			// Recalculate UDP checksum with IP pseudo-header
			if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
				return fmt.Errorf("failed to set network layer: %v", err)
			}

			// Serialize packet with recalculated checksums
			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{
				ComputeChecksums: true,
				FixLengths:       true,
			}

			if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
				eth := ethLayer.(*layers.Ethernet)
				if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(udp.Payload)); err != nil {
					return fmt.Errorf("failed to serialize: %v", err)
				}
				data = buf.Bytes()
			}
		}
	}

	if err := syscall.Sendto(fd, data, 0, addr); err != nil {
		return fmt.Errorf("sendto failed: %v", err)
	}
	return nil
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

func startUnixSocketServer(socketPath string) {
	// Remove existing socket if it exists
	os.Remove(socketPath)

	// Create Unix socket listener
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("Failed to create Unix socket: %v", err)
	}
	defer listener.Close()

	log.Printf("Unix socket server listening on %s", socketPath)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Read command from connection
	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		return
	}

	command := scanner.Text()
	parts := strings.SplitN(command, " ", 2)
	cmd := parts[0]

	switch cmd {
	case "GET_REQUESTS":
		// Send all DNS requests as JSON
		dnsMutex.RLock()
		requests := make([]DNSRequest, len(dnsRequests))
		copy(requests, dnsRequests)
		dnsMutex.RUnlock()

		fmt.Fprintf(conn, "[")
		for i, req := range requests {
			if i > 0 {
				fmt.Fprintf(conn, ",")
			}
			fmt.Fprintf(conn, `{"timestamp":"%s","src_ip":"%s","domain":"%s","query_type":"%s","query_class":"%s"}`,
				req.Timestamp.Format(time.RFC3339),
				req.SrcIP,
				req.Domain,
				req.QueryType,
				req.QueryClass)
		}
		fmt.Fprintf(conn, "]\n")

	case "BLOCK_DOMAIN":
		// Deprecated: Use API endpoint /api/domains/block instead
		fmt.Fprintf(conn, "ERROR: Use API endpoint /api/domains/block for per-user blocking\n")

	case "UNBLOCK_DOMAIN":
		// Deprecated: Use API endpoint /api/domains/unblock instead
		fmt.Fprintf(conn, "ERROR: Use API endpoint /api/domains/unblock for per-user blocking\n")

	case "GET_BLOCKED":
		// Deprecated: Use API endpoint /api/users/:id/blocked-domains instead
		fmt.Fprintf(conn, "ERROR: Use API endpoint /api/users/:id/blocked-domains for per-user blocking\n")

	default:
		// Default behavior for backward compatibility - return DNS requests
		dnsMutex.RLock()
		requests := make([]DNSRequest, len(dnsRequests))
		copy(requests, dnsRequests)
		dnsMutex.RUnlock()

		fmt.Fprintf(conn, "[")
		for i, req := range requests {
			if i > 0 {
				fmt.Fprintf(conn, ",")
			}
			fmt.Fprintf(conn, `{"timestamp":"%s","src_ip":"%s","domain":"%s","query_type":"%s","query_class":"%s"}`,
				req.Timestamp.Format(time.RFC3339),
				req.SrcIP,
				req.Domain,
				req.QueryType,
				req.QueryClass)
		}
		fmt.Fprintf(conn, "]\n")
	}
}

// Helper function to convert uint16 to network byte order
func uint16ToBytes(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

// Helper to get unsafe pointer size
func getPointerSize() int {
	return int(unsafe.Sizeof(uintptr(0)))
}

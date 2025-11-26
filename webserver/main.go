package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/kidcodech/kidosserver-v1/webserver/db"
)

// PacketAggregate represents aggregated packet statistics
type PacketAggregate struct {
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcDomain string `json:"src_domain,omitempty"`
	DstDomain string `json:"dst_domain,omitempty"`
	Protocol  string `json:"protocol"`
	Count     int    `json:"count"`
	TotalSize uint64 `json:"total_size"`
}

// DNSRequest represents a DNS query
type DNSRequest struct {
	Timestamp  string `json:"timestamp"`
	SrcIP      string `json:"src_ip"`
	Domain     string `json:"domain"`
	QueryType  string `json:"query_type"`
	QueryClass string `json:"query_class"`
}

// WebSocketMessage represents a message sent over WebSocket
type WebSocketMessage struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins for development
		},
	}

	clients   = make(map[*websocket.Conn]bool)
	clientsMu sync.RWMutex
	broadcast = make(chan []PacketAggregate)

	socketPath           = "/tmp/kidos-sniffer.sock"
	dnsInspectorSockPath = "/tmp/kidos-dns-inspector.sock"
	serverIP             string // Will be loaded from config
)

func main() {
	// Load server IP from network config
	loadServerIP()

	// Initialize database
	if err := db.InitDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.DB.Close()

	router := mux.NewRouter()

	// API endpoints
	router.HandleFunc("/api/packets/aggregate", getPacketAggregates).Methods("GET")
	router.HandleFunc("/api/packets/clear", clearPackets).Methods("POST")
	router.HandleFunc("/api/dns/requests", getDNSRequests).Methods("GET")
	router.HandleFunc("/api/dns/clear", clearDNSRequests).Methods("POST")
	router.HandleFunc("/api/dns/block", blockDomain).Methods("POST")
	router.HandleFunc("/api/dns/unblock", unblockDomain).Methods("POST")
	router.HandleFunc("/api/dns/blocked", getBlockedDomains).Methods("GET")
	router.HandleFunc("/api/client/info", getClientInfo).Methods("GET")

	// User management endpoints
	router.HandleFunc("/api/users", getUsers).Methods("GET")
	router.HandleFunc("/api/users", createUser).Methods("POST")
	router.HandleFunc("/api/users/{id}", getUser).Methods("GET")
	router.HandleFunc("/api/users/{id}", updateUser).Methods("PUT")
	router.HandleFunc("/api/users/{id}", deleteUser).Methods("DELETE")
	router.HandleFunc("/api/users/{id}/devices", getUserDevices).Methods("GET")
	router.HandleFunc("/api/users/{id}/devices", addUserDevice).Methods("POST")
	router.HandleFunc("/api/users/{id}/devices/{device_id}", deleteUserDevice).Methods("DELETE")
	router.HandleFunc("/api/users/by-mac/{mac}", getUserByMACAddress).Methods("GET")

	// Per-user domain blocking endpoints
	router.HandleFunc("/api/users/{id}/blocked-domains", getUserBlockedDomains).Methods("GET")
	router.HandleFunc("/api/users/{id}/blocked-domains", blockDomainForUser).Methods("POST")
	router.HandleFunc("/api/users/{id}/blocked-domains/{domain_id}", unblockDomainForUser).Methods("DELETE")

	// Device registration endpoints
	router.HandleFunc("/api/devices/unregistered", getUnregisteredDevices).Methods("GET")
	router.HandleFunc("/api/auth/register-device", registerDevice).Methods("POST")

	router.HandleFunc("/ws", handleWebSocket)

	// Captive portal page for blocked domains
	router.HandleFunc("/blocked", serveBlockedPage).Methods("GET")

	// Serve static files from frontend/dist
	router.PathPrefix("/").Handler(http.FileServer(http.Dir("./frontend/dist")))

	// Wrap router with captive portal middleware
	handler := captivePortalMiddleware(router)

	// Start broadcast goroutine
	go handleBroadcast()

	// Start periodic stats broadcaster
	go broadcastStats()

	// Generate self-signed certificate for HTTPS captive portal
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	// Start port 443 HTTPS server for captive portal redirect
	go func() {
		log.Println("Starting HTTPS server on :443")
		server := &http.Server{
			Addr: ":443",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Redirect HTTPS traffic to HTTP captive portal (port 80)
				http.Redirect(w, r, fmt.Sprintf("http://%s/blocked", serverIP), http.StatusFound)
			}),
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
		}
		if err := server.ListenAndServeTLS("", ""); err != nil {
			log.Printf("HTTPS server error: %v", err)
		}
	}()

	log.Println("Starting web server on :80")
	if err := http.ListenAndServe(":80", handler); err != nil {
		log.Fatal("ListenAndServe:", err)
	}
}

// loadServerIP loads the BR1_IP from the network config file
func loadServerIP() {
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
				serverIP = ip
				log.Printf("✓ Loaded server IP from config: %s", serverIP)
				return
			}
		}
	}
	log.Fatalf("BR1_IP not found in config file %s", configFile)
}

// captivePortalMiddleware redirects requests with unknown Host headers to /blocked
func captivePortalMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		// Remove port if present
		if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
			host = host[:colonIndex]
		}

		// Allow requests to server IP, localhost, and kidos domain
		// Also allow if path is already /blocked or starts with /api or /ws
		if host == serverIP || host == "localhost" || host == "127.0.0.1" || host == "kidos" ||
			r.URL.Path == "/blocked" || strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/ws" {
			next.ServeHTTP(w, r)
			return
		}

		// Unknown host (blocked domain) - redirect to captive portal
		log.Printf("Captive portal redirect: Host=%s, Path=%s", r.Host, r.URL.Path)
		http.Redirect(w, r, "/blocked", http.StatusFound)
	})
}

// getPacketAggregates returns aggregated packet statistics
func getPacketAggregates(w http.ResponseWriter, r *http.Request) {
	aggregates, err := fetchPacketsFromSniffer()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch packets: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(aggregates)
}

// clearPackets clears all stored packets
func clearPackets(w http.ResponseWriter, r *http.Request) {
	err := sendCommandToSniffer("CLEAR")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to clear packets: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "cleared"})
}

// getDNSRequests returns DNS request logs from DNS inspector
func getDNSRequests(w http.ResponseWriter, r *http.Request) {
	log.Println("API: getDNSRequests called")
	requests, err := fetchDNSRequests()
	if err != nil {
		log.Printf("ERROR: Failed to fetch DNS requests: %v", err)
		http.Error(w, fmt.Sprintf("Failed to fetch DNS requests: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("SUCCESS: Returning %d DNS requests", len(requests))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(requests)
}

// clearDNSRequests clears all stored DNS requests
func clearDNSRequests(w http.ResponseWriter, r *http.Request) {
	// For now, just return success - DNS inspector doesn't support clear yet
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "cleared"})
}

// blockDomain blocks a domain via DNS inspector
func blockDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Domain == "" {
		http.Error(w, "Domain is required", http.StatusBadRequest)
		return
	}

	err := sendDNSInspectorCommand(fmt.Sprintf("BLOCK_DOMAIN %s", req.Domain))
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to block domain: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "blocked", "domain": req.Domain})
}

// unblockDomain unblocks a domain via DNS inspector
func unblockDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Domain == "" {
		http.Error(w, "Domain is required", http.StatusBadRequest)
		return
	}

	err := sendDNSInspectorCommand(fmt.Sprintf("UNBLOCK_DOMAIN %s", req.Domain))
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to unblock domain: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "unblocked", "domain": req.Domain})
}

// getBlockedDomains returns list of blocked domains
func getBlockedDomains(w http.ResponseWriter, r *http.Request) {
	domains, err := fetchBlockedDomains()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch blocked domains: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(domains)
}

// getClientInfo returns information about the client
func getClientInfo(w http.ResponseWriter, r *http.Request) {
	clientIP := extractClientIP(r)

	// Get MAC address from IP
	clientMAC, err := getMACFromIP(clientIP)

	info := map[string]interface{}{
		"ip":     clientIP,
		"server": serverIP,
	}

	if err == nil {
		info["mac"] = clientMAC
		// Look up user by MAC
		user, _ := db.GetUserByMAC(clientMAC)
		if user != nil {
			info["user"] = map[string]string{
				"username":     user.Username,
				"display_name": user.DisplayName,
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

// extractClientIP extracts the client IP from the request
func extractClientIP(r *http.Request) string {
	// Get client IP from RemoteAddr
	clientIP := r.RemoteAddr
	// Remove port if present
	if colonIndex := strings.LastIndex(clientIP, ":"); colonIndex != -1 {
		clientIP = clientIP[:colonIndex]
	}

	// Check X-Forwarded-For header for proxied requests
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Use the first IP in the list
		if commaIndex := strings.Index(xff, ","); commaIndex != -1 {
			clientIP = strings.TrimSpace(xff[:commaIndex])
		} else {
			clientIP = strings.TrimSpace(xff)
		}
	}

	return clientIP
}

// getMACFromIP resolves IP address to MAC address using ARP table
func getMACFromIP(ip string) (string, error) {
	// Read /proc/net/arp to find MAC address for the given IP
	file, err := ioutil.ReadFile("/proc/net/arp")
	if err != nil {
		return "", fmt.Errorf("failed to read ARP table: %v", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(file)))
	// Skip header line
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			arpIP := fields[0]
			macAddr := fields[3]

			if arpIP == ip && macAddr != "00:00:00:00:00:00" {
				return strings.ToLower(macAddr), nil
			}
		}
	}

	return "", fmt.Errorf("MAC address not found for IP: %s", ip)
}

// serveBlockedPage serves the captive portal page for blocked domains
func serveBlockedPage(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Domain Blocked</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            background: white;
            border-radius: 12px;
            padding: 3rem;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            text-align: center;
            max-width: 500px;
        }
        h1 {
            color: #e53e3e;
            font-size: 2.5rem;
            margin-bottom: 1rem;
        }
        p {
            color: #4a5568;
            font-size: 1.1rem;
            line-height: 1.6;
        }
        .icon {
            font-size: 4rem;
            margin-bottom: 1rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🚫</div>
        <h1>Domain Blocked</h1>
        <p>This domain has been blocked by parental controls.</p>
    </div>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// fetchBlockedDomains fetches blocked domains list from DNS inspector
func fetchBlockedDomains() ([]string, error) {
	conn, err := net.Dial("unix", dnsInspectorSockPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to DNS inspector: %w", err)
	}
	defer conn.Close()

	// Send command
	fmt.Fprintf(conn, "GET_BLOCKED\n")

	// Read response
	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		return nil, fmt.Errorf("failed to read from DNS inspector")
	}

	data := scanner.Text()
	var domains []string
	if err := json.Unmarshal([]byte(data), &domains); err != nil {
		return nil, fmt.Errorf("failed to parse blocked domains: %w", err)
	}

	return domains, nil
}

// sendDNSInspectorCommand sends a command to DNS inspector via Unix socket
func sendDNSInspectorCommand(command string) error {
	conn, err := net.Dial("unix", dnsInspectorSockPath)
	if err != nil {
		return fmt.Errorf("failed to connect to DNS inspector: %w", err)
	}
	defer conn.Close()

	// Send command
	fmt.Fprintf(conn, "%s\n", command)

	// Read response
	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		return fmt.Errorf("no response from DNS inspector")
	}

	response := strings.TrimSpace(scanner.Text())
	if response != "OK" {
		return fmt.Errorf("unexpected response: %s", response)
	}

	return nil
}

// fetchDNSRequests fetches DNS request data from DNS inspector via Unix socket
func fetchDNSRequests() ([]DNSRequest, error) {
	log.Println("Connecting to DNS inspector socket...")
	conn, err := net.Dial("unix", dnsInspectorSockPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to DNS inspector: %w", err)
	}
	defer conn.Close()
	log.Println("Connected to DNS inspector socket")

	// Send command
	log.Println("Sending GET_REQUESTS command...")
	fmt.Fprintf(conn, "GET_REQUESTS\n")

	// Read response - increase buffer size for large responses
	log.Println("Waiting for response...")
	scanner := bufio.NewScanner(conn)
	// Increase buffer to 10MB for large DNS request logs
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("scanner error: %w", err)
		}
		return nil, fmt.Errorf("failed to read from DNS inspector")
	}

	log.Println("Received response, parsing JSON...")
	data := scanner.Text()
	var requests []DNSRequest
	if err := json.Unmarshal([]byte(data), &requests); err != nil {
		return nil, fmt.Errorf("failed to parse DNS requests: %w", err)
	}

	log.Printf("Parsed %d DNS requests", len(requests))
	return requests, nil
}

// fetchPacketsFromSniffer fetches packet data from sniffer via Unix socket
func fetchPacketsFromSniffer() ([]PacketAggregate, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to sniffer: %w", err)
	}
	defer conn.Close()

	// Send command
	fmt.Fprintf(conn, "GET_PACKETS\n")

	// Read response - increase buffer size for large responses
	scanner := bufio.NewScanner(conn)
	// Increase buffer to 10MB for large packet aggregates
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("scanner error: %w", err)
		}
		return nil, fmt.Errorf("no response from sniffer")
	}

	response := scanner.Text()
	if response == "ERROR" {
		return nil, fmt.Errorf("sniffer returned error")
	}

	var aggregates []PacketAggregate
	if err := json.Unmarshal([]byte(response), &aggregates); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return aggregates, nil
}

// sendCommandToSniffer sends a command to sniffer via Unix socket
func sendCommandToSniffer(command string) error {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to connect to sniffer: %w", err)
	}
	defer conn.Close()

	// Send command
	fmt.Fprintf(conn, "%s\n", command)

	// Read response
	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		return fmt.Errorf("no response from sniffer")
	}

	response := strings.TrimSpace(scanner.Text())
	if response != "OK" {
		return fmt.Errorf("unexpected response: %s", response)
	}

	return nil
}

// aggregatePackets is no longer needed - sniffer does aggregation
// Kept for backward compatibility
func aggregatePackets(packets []PacketAggregate) []PacketAggregate {
	return packets
}

// handleWebSocket handles WebSocket connections
func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade error:", err)
		return
	}
	defer conn.Close()

	// Register client
	clientsMu.Lock()
	clients[conn] = true
	clientsMu.Unlock()

	log.Println("New WebSocket client connected")

	// Keep connection alive and handle incoming messages
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			log.Println("WebSocket read error:", err)
			clientsMu.Lock()
			delete(clients, conn)
			clientsMu.Unlock()
			break
		}
	}
}

// handleBroadcast sends messages to all connected WebSocket clients
func handleBroadcast() {
	for {
		aggregates := <-broadcast

		message := WebSocketMessage{
			Type: "packet_stats",
			Data: mustMarshal(aggregates),
		}

		clientsMu.RLock()
		for client := range clients {
			err := client.WriteJSON(message)
			if err != nil {
				log.Println("WebSocket write error:", err)
				client.Close()
				clientsMu.Lock()
				delete(clients, client)
				clientsMu.Unlock()
			}
		}
		clientsMu.RUnlock()
	}
}

// broadcastStats periodically broadcasts packet statistics
func broadcastStats() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		aggregates, err := fetchPacketsFromSniffer()
		if err != nil {
			log.Printf("Failed to fetch packets for broadcast: %v", err)
			continue
		}

		broadcast <- aggregates
	}
}

// mustMarshal marshals data to JSON or panics
func mustMarshal(v interface{}) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

// ===== User Management Handlers =====

// getUsers returns all users with their IP addresses
func getUsers(w http.ResponseWriter, r *http.Request) {
	users, err := db.GetAllUsers()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch users: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// createUser creates a new user
func createUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.DisplayName == "" || req.Password == "" {
		http.Error(w, "Username, display_name, and password are required", http.StatusBadRequest)
		return
	}

	user, err := db.CreateUser(req.Username, req.DisplayName, req.Password)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create user: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

// getUser returns a single user by ID
func getUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	user, err := db.GetUserWithDevices(id)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch user: %v", err), http.StatusInternalServerError)
		return
	}

	if user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// updateUser updates an existing user
func updateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Username    string  `json:"username"`
		DisplayName string  `json:"display_name"`
		Password    *string `json:"password,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.DisplayName == "" {
		http.Error(w, "Username and display_name are required", http.StatusBadRequest)
		return
	}

	if err := db.UpdateUser(id, req.Username, req.DisplayName, req.Password); err != nil {
		http.Error(w, fmt.Sprintf("Failed to update user: %v", err), http.StatusInternalServerError)
		return
	}

	user, _ := db.GetUser(id)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// deleteUser deletes a user
func deleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	if err := db.DeleteUser(id); err != nil {
		http.Error(w, fmt.Sprintf("Failed to delete user: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// getUserDevices returns all MAC addresses for a user
func getUserDevices(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	devices, err := db.GetUserDevices(id)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch devices: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(devices)
}

// addUserDevice adds a MAC address to a user
func addUserDevice(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var req struct {
		MACAddress string `json:"mac_address"`
		IPAddress  string `json:"ip_address"`
		DeviceName string `json:"device_name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.MACAddress == "" {
		http.Error(w, "mac_address is required", http.StatusBadRequest)
		return
	}

	device, err := db.AddUserDevice(id, req.MACAddress, req.IPAddress, req.DeviceName)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to add device: %v", err), http.StatusInternalServerError)
		return
	}

	// Remove from unregistered devices list if it was there
	db.ClearUnregisteredDevice(req.MACAddress)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(device)
}

// deleteUserDevice removes a device from a user
func deleteUserDevice(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	deviceID, err := strconv.Atoi(vars["device_id"])
	if err != nil {
		http.Error(w, "Invalid device ID", http.StatusBadRequest)
		return
	}

	if err := db.DeleteUserDevice(deviceID); err != nil {
		http.Error(w, fmt.Sprintf("Failed to delete device: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// getUserByMACAddress returns user information for a given MAC address
func getUserByMACAddress(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	macAddress := vars["mac"]

	user, err := db.GetUserByMAC(macAddress)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch user: %v", err), http.StatusInternalServerError)
		return
	}

	if user == nil {
		http.Error(w, "No user found for this MAC", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// getUserBlockedDomains returns all blocked domains for a user
func getUserBlockedDomains(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	domains, err := db.GetUserBlockedDomains(id)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch blocked domains: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(domains)
}

// blockDomainForUser blocks a domain for a specific user
func blockDomainForUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Domain string `json:"domain"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Domain == "" {
		http.Error(w, "Domain is required", http.StatusBadRequest)
		return
	}

	domain, err := db.AddBlockedDomain(id, req.Domain)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to block domain: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("✓ User %d blocked domain: %s", id, req.Domain)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(domain)
}

// unblockDomainForUser removes a blocked domain for a user
func unblockDomainForUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	domainID, err := strconv.Atoi(vars["domain_id"])
	if err != nil {
		http.Error(w, "Invalid domain ID", http.StatusBadRequest)
		return
	}

	if err := db.RemoveBlockedDomain(domainID); err != nil {
		http.Error(w, fmt.Sprintf("Failed to unblock domain: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("✓ Removed blocked domain ID: %d", domainID)
	w.WriteHeader(http.StatusNoContent)
}

// getUnregisteredDevices returns all devices trying to access internet without registration
func getUnregisteredDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := db.GetUnregisteredDevices()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch unregistered devices: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(devices)
}

// registerDevice handles device registration from /auth page
func registerDevice(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		DeviceName string `json:"device_name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	// Get client IP and resolve to MAC
	clientIP := extractClientIP(r)
	clientMAC, err := getMACFromIP(clientIP)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": fmt.Sprintf("Could not determine device MAC address: %v", err),
		})
		return
	}

	// Authenticate user
	user, err := db.AuthenticateUser(req.Username, req.Password)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Invalid username or password",
		})
		return
	}

	// Check if MAC already registered
	existingUser, err := db.GetUserByMAC(clientMAC)
	if err == nil && existingUser != nil {
		// MAC already registered
		if existingUser.ID == user.ID {
			// Same user, already registered
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":            true,
				"already_registered": true,
				"message":            "This device is already registered to your account",
			})
			return
		} else {
			// MAC registered to different user - conflict
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{
				"error": fmt.Sprintf("This MAC address is already registered to user: %s", existingUser.Username),
			})
			return
		}
	}

	// Add MAC to user's device list
	deviceName := req.DeviceName
	if deviceName == "" {
		deviceName = "Device"
	}

	_, err = db.AddUserDevice(user.ID, clientMAC, clientIP, deviceName)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to register device: %v", err), http.StatusInternalServerError)
		return
	}

	// Notify sync daemon to update eBPF map (will be implemented)
	notifyIPMapUpdate()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":            true,
		"already_registered": false,
		"message":            "Device registered successfully! You can now access the internet.",
		"user_id":            user.ID,
		"username":           user.Username,
		"mac_address":        clientMAC,
	})
}

// notifyIPMapUpdate notifies the sync daemon to update the eBPF map
// This will be implemented when we create the sync daemon
func notifyIPMapUpdate() {
	// TODO: Send signal to sync daemon via socket or shared memory
	log.Println("IP map update notification (sync daemon not yet implemented)")
}

// generateSelfSignedCert creates a self-signed TLS certificate for captive portal
func generateSelfSignedCert() (tls.Certificate, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:       []string{"Kidos Parental Control System"},
			OrganizationalUnit: []string{"DNS Policy Enforcement"},
			CommonName:         "BLOCKED BY DNS POLICY",
			Country:            []string{"XX"},
			Locality:           []string{"Content Filter"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Encode certificate and key to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	// Load as tls.Certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}

	return cert, nil
}

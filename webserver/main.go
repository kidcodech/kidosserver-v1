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
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
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
	serverIP             = "192.168.1.12" // Default, will be loaded from config
)

func main() {
	// Load server IP from network config
	loadServerIP()

	router := mux.NewRouter()

	// API endpoints
	router.HandleFunc("/api/packets/aggregate", getPacketAggregates).Methods("GET")
	router.HandleFunc("/api/packets/clear", clearPackets).Methods("POST")
	router.HandleFunc("/api/dns/requests", getDNSRequests).Methods("GET")
	router.HandleFunc("/api/dns/clear", clearDNSRequests).Methods("POST")
	router.HandleFunc("/api/dns/block", blockDomain).Methods("POST")
	router.HandleFunc("/api/dns/unblock", unblockDomain).Methods("POST")
	router.HandleFunc("/api/dns/blocked", getBlockedDomains).Methods("GET")
	router.HandleFunc("/ws", handleWebSocket)

	// Captive portal page for blocked domains
	router.HandleFunc("/blocked", serveBlockedPage).Methods("GET")

	// Serve static files from frontend/dist
	router.PathPrefix("/").Handler(http.FileServer(http.Dir("./frontend/dist")))

	// Start broadcast goroutine
	go handleBroadcast()

	// Start periodic stats broadcaster
	go broadcastStats()

	// Generate self-signed certificate for HTTPS captive portal
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	// Start port 80 redirect server for captive portal
	go func() {
		log.Println("Starting HTTP redirect server on :80")
		http.ListenAndServe(":80", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Redirect all port 80 traffic to captive portal
			http.Redirect(w, r, fmt.Sprintf("http://%s:8080/blocked", serverIP), http.StatusFound)
		}))
	}()

	// Start port 443 HTTPS server for captive portal
	go func() {
		log.Println("Starting HTTPS server on :443")
		server := &http.Server{
			Addr: ":443",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Redirect HTTPS traffic to HTTP captive portal
				http.Redirect(w, r, fmt.Sprintf("http://%s:8080/blocked", serverIP), http.StatusFound)
			}),
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
		}
		if err := server.ListenAndServeTLS("", ""); err != nil {
			log.Printf("HTTPS server error: %v", err)
		}
	}()

	log.Println("Starting web server on :8080")
	if err := http.ListenAndServe(":8080", router); err != nil {
		log.Fatal("ListenAndServe:", err)
	}
}

// loadServerIP loads the BR1_IP from the network config file
func loadServerIP() {
	configFile := "/tmp/kidos-network.conf"
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Printf("Warning: Could not read network config %s: %v, using default IP %s", configFile, err, serverIP)
		return
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
	log.Printf("Warning: BR1_IP not found in config, using default IP %s", serverIP)
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

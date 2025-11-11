package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
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
	Protocol  string `json:"protocol"`
	Count     int    `json:"count"`
	TotalSize uint64 `json:"total_size"`
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

	socketPath = "/tmp/kidos-sniffer.sock"
)

func main() {
	router := mux.NewRouter()

	// API endpoints
	router.HandleFunc("/api/packets/aggregate", getPacketAggregates).Methods("GET")
	router.HandleFunc("/api/packets/clear", clearPackets).Methods("POST")
	router.HandleFunc("/ws", handleWebSocket)

	// Serve static files from frontend/dist
	router.PathPrefix("/").Handler(http.FileServer(http.Dir("./frontend/dist")))

	// Start broadcast goroutine
	go handleBroadcast()

	// Start periodic stats broadcaster
	go broadcastStats()

	log.Println("Starting web server on :8080")
	if err := http.ListenAndServe(":8080", router); err != nil {
		log.Fatal("ListenAndServe:", err)
	}
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

// fetchPacketsFromSniffer fetches packet data from sniffer via Unix socket
func fetchPacketsFromSniffer() ([]PacketAggregate, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to sniffer: %w", err)
	}
	defer conn.Close()

	// Send command
	fmt.Fprintf(conn, "GET_PACKETS\n")

	// Read response
	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
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

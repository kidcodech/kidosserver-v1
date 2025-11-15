package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/kidcodech/kidosserver-v1/monitoring/sniffer/store"
)

var packetStore *store.PacketStore
var dnsMap sync.Map // IP address -> domain name mapping

func main() {
	// Initialize packet store
	packetStore = store.NewPacketStore()

	// Get interface name from args or use default
	ifaceName := "veth-mon"
	if len(os.Args) > 1 {
		ifaceName = os.Args[1]
	}

	log.Printf("Starting packet sniffer on interface: %s", ifaceName)

	// Open interface for packet capture using AF_PACKET (pcap)
	handle, err := pcap.OpenLive(ifaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Failed to open interface %s: %v", ifaceName, err)
	}
	defer handle.Close()

	log.Println("Packet capture started successfully")

	// Start Unix domain socket server
	socketPath := "/tmp/kidos-sniffer.sock"
	go startUnixSocketServer(socketPath)

	// Handle signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start packet capture
	go capturePackets(handle)

	log.Println("Packet sniffer started, press Ctrl+C to stop")
	<-sigChan

	log.Println("Shutting down packet sniffer...")
	os.Remove(socketPath)
}

func capturePackets(handle *pcap.Handle) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		// Get actual packet length from metadata
		actualLength := uint32(packet.Metadata().Length)
		parsePacket(packet.Data(), actualLength)
	}
}

func parsePacket(data []byte, actualSize uint32) {
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

	var srcIP, dstIP net.IP
	var protocol string
	size := actualSize // Use actual packet size, not captured size

	// Extract IP layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP
		dstIP = ip.DstIP

		switch ip.Protocol {
		case layers.IPProtocolTCP:
			protocol = "TCP"
		case layers.IPProtocolUDP:
			protocol = "UDP"
			// Check if this is a DNS response
			if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				udp, _ := udpLayer.(*layers.UDP)
				if udp.SrcPort == 53 {
					parseDNS(packet)
				}
			}
		case layers.IPProtocolICMPv4:
			protocol = "ICMP"
		default:
			protocol = fmt.Sprintf("IP-%d", ip.Protocol)
		}
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		srcIP = ip.SrcIP
		dstIP = ip.DstIP

		switch ip.NextHeader {
		case layers.IPProtocolTCP:
			protocol = "TCP"
		case layers.IPProtocolUDP:
			protocol = "UDP"
			// Check if this is a DNS response
			if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				udp, _ := udpLayer.(*layers.UDP)
				if udp.SrcPort == 53 {
					parseDNS(packet)
				}
			}
		case layers.IPProtocolICMPv6:
			protocol = "ICMPv6"
		default:
			protocol = fmt.Sprintf("IPv6-%d", ip.NextHeader)
		}
	} else {
		// Non-IP packet
		return
	}

	// Store packet info
	pktInfo := store.PacketInfo{
		SrcIP:     srcIP,
		DstIP:     dstIP,
		Timestamp: time.Now(),
		Protocol:  protocol,
		Size:      size,
	}

	packetStore.AddPacket(pktInfo)

	// Comment out verbose logging to reduce CPU usage
	// log.Printf("Captured: %s -> %s [%s] %d bytes",
	// 	srcIP, dstIP, protocol, size)
}

func parseDNS(packet gopacket.Packet) {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}

	dns, _ := dnsLayer.(*layers.DNS)

	// Only process responses
	if !dns.QR {
		return
	}

	// Extract domain name from questions
	var domainName string
	if len(dns.Questions) > 0 {
		domainName = string(dns.Questions[0].Name)
	}

	if domainName == "" {
		return
	}

	// Extract IP addresses from answers
	for _, answer := range dns.Answers {
		if answer.Type == layers.DNSTypeA {
			// IPv4 address
			ip := net.IP(answer.IP).String()

			// Don't map forged DNS responses from captive portal
			// Blocked domains resolve to 192.168.1.x (captive portal IPs)
			if strings.HasPrefix(ip, "192.168.1.") {
				log.Printf("DNS: %s -> %s (captive portal - not mapping)", domainName, ip)
				continue
			}

			dnsMap.Store(ip, domainName)
			log.Printf("DNS: %s -> %s", domainName, ip)
		} else if answer.Type == layers.DNSTypeAAAA {
			// IPv6 address
			ip := net.IP(answer.IP).String()

			// Don't map forged DNS responses from captive portal
			if strings.HasPrefix(ip, "192.168.1.") {
				log.Printf("DNS: %s -> %s (captive portal - not mapping)", domainName, ip)
				continue
			}

			dnsMap.Store(ip, domainName)
			log.Printf("DNS: %s -> %s", domainName, ip)
		}
	}
}

// GetStore returns the global packet store
func GetStore() *store.PacketStore {
	return packetStore
}

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

// startUnixSocketServer starts a Unix domain socket server
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

// handleConnection handles a single Unix socket connection
func handleConnection(conn net.Conn) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		command := strings.TrimSpace(scanner.Text())

		switch command {
		case "GET_PACKETS":
			packets := packetStore.GetPackets()
			aggregates := aggregatePackets(packets)

			// Sort by total_size (primary), then by count (secondary)
			sort.Slice(aggregates, func(i, j int) bool {
				if aggregates[i].TotalSize != aggregates[j].TotalSize {
					return aggregates[i].TotalSize > aggregates[j].TotalSize
				}
				return aggregates[i].Count > aggregates[j].Count
			})

			// Limit to top 50 entries
			if len(aggregates) > 50 {
				aggregates = aggregates[:50]
			}

			data, err := json.Marshal(aggregates)
			if err != nil {
				log.Printf("JSON marshal error: %v", err)
				fmt.Fprintf(conn, "ERROR\n")
				continue
			}

			fmt.Fprintf(conn, "%s\n", data)

		case "CLEAR":
			packetStore.Clear()
			fmt.Fprintf(conn, "OK\n")

		default:
			fmt.Fprintf(conn, "UNKNOWN_COMMAND\n")
		}
	}
}

// aggregatePackets aggregates packets by src_ip, dst_ip, and protocol
func aggregatePackets(packets []store.PacketInfo) []PacketAggregate {
	aggMap := make(map[string]*PacketAggregate)

	for _, pkt := range packets {
		key := pkt.SrcIP.String() + "|" + pkt.DstIP.String() + "|" + pkt.Protocol

		if agg, exists := aggMap[key]; exists {
			agg.Count++
			agg.TotalSize += uint64(pkt.Size)
		} else {
			srcIP := pkt.SrcIP.String()
			dstIP := pkt.DstIP.String()

			// Lookup domain names from DNS map
			var srcDomain, dstDomain string
			if val, ok := dnsMap.Load(srcIP); ok {
				srcDomain = val.(string)
			}
			if val, ok := dnsMap.Load(dstIP); ok {
				dstDomain = val.(string)
			}

			aggMap[key] = &PacketAggregate{
				SrcIP:     srcIP,
				DstIP:     dstIP,
				SrcDomain: srcDomain,
				DstDomain: dstDomain,
				Protocol:  pkt.Protocol,
				Count:     1,
				TotalSize: uint64(pkt.Size),
			}
		}
	}

	// Convert map to slice
	result := make([]PacketAggregate, 0, len(aggMap))
	for _, agg := range aggMap {
		result = append(result, *agg)
	}

	return result
}

package store

import (
	"net"
	"sync"
	"time"
)

// PacketInfo stores information about captured packets
type PacketInfo struct {
	SrcIP     net.IP
	DstIP     net.IP
	Timestamp time.Time
	Protocol  string
	Size      uint32
}

// PacketStore holds all captured packets in memory
type PacketStore struct {
	mu      sync.RWMutex
	packets []PacketInfo
}

// NewPacketStore creates a new packet store
func NewPacketStore() *PacketStore {
	return &PacketStore{
		packets: make([]PacketInfo, 0, 10000),
	}
}

// AddPacket adds a packet to the store
func (ps *PacketStore) AddPacket(pkt PacketInfo) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.packets = append(ps.packets, pkt)
}

// GetPackets returns a copy of all packets
func (ps *PacketStore) GetPackets() []PacketInfo {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	pkts := make([]PacketInfo, len(ps.packets))
	copy(pkts, ps.packets)
	return pkts
}

// Clear clears all packets
func (ps *PacketStore) Clear() {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.packets = ps.packets[:0]
}

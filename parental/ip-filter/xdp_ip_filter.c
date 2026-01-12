// SPDX-License-Identifier: GPL-2.0
// XDP MAC Filter - Allows only registered client MAC addresses
//
// This XDP program filters traffic based on source MAC addresses.
// Only MACs present in the allowed_macs map can pass through.
// All other traffic is dropped.
// 
// This program is designed to be chained with DNS filter:
// MAC Filter (first) -> DNS Filter (second)

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// MAC address structure for map key (6 bytes)
struct mac_addr {
    __u8 addr[6];
};

// Structure to store MAC + IP address info (packed to avoid alignment issues)
struct device_info {
    __u8 mac[6];
    __u32 ip;
    __u64 count;
} __attribute__((packed));

// Map to store allowed client MAC addresses
// Key: MAC address (6 bytes)
// Value: 1 if allowed
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);  // Support up to 10k devices
    __type(key, struct mac_addr);
    __type(value, __u32);         // 1 = allowed
} allowed_macs SEC(".maps");

// Statistics map to track dropped packets
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// Map to track dropped (unregistered) devices with MAC and IP
// Key: MAC address, Value: device_info with IP and count
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, struct mac_addr);
    __type(value, struct device_info);
} dropped_macs SEC(".maps");

// XDP socket map for DNS packet redirection to userspace (shared with DNS inspector)
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

// Global settings map
// Key: 0 (block_dot), Value: 1 = Allow, 0 = Block (default)
// Key: 1 (block_doh), Value: 1 = Allow, 0 = Block (default)
// Key: 2 (block_doq), Value: 1 = Allow, 0 = Block (default)
// Key: 3 (gateway_ip), Value: IP address (network byte order)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} global_settings SEC(".maps");

// LPM Trie key for IPv4
struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 data;
};

// Map to store blocked DoH IPs (LPM Trie)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1000);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} doh_ip_list SEC(".maps");

// Event structure for blocked encrypted DNS
struct encrypted_dns_event {
    __u8 mac[6];
    __u32 src_ip;
    __u32 dest_ip;
    __u32 protocol; // 0=DoT, 1=DoH, 2=DoQ
};

// Perf event map for logging
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

#define STAT_ALLOWED 0
#define STAT_DROPPED 1

SEC("xdp")
int xdp_mac_filter_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Extract source MAC address
    struct mac_addr src_mac;
    __builtin_memcpy(src_mac.addr, eth->h_source, 6);

    // Block IPv6 traffic
    if (eth->h_proto == bpf_htons(ETH_P_IPV6))
        return XDP_DROP;

    // Check if this is IPv4 traffic
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS; // Allow non-IPv4 traffic (ARP, etc.)

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS; // Malformed packet

    // Check if this is TCP traffic (for DoT and DoH blocking)
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
            
        // Check for DoT (port 853)
        if (tcp->dest == bpf_htons(853)) {
            __u32 key = 0;
            __u32 *allow_dot = bpf_map_lookup_elem(&global_settings, &key);
            
            // If map entry exists and value is 1, allow. Otherwise (0 or null), block.
            if (allow_dot && *allow_dot == 1) {
                // Allow DoT
            } else {
                struct encrypted_dns_event evt = {};
                __builtin_memcpy(evt.mac, src_mac.addr, 6);
                evt.src_ip = ip->saddr;
                evt.dest_ip = ip->daddr;
                evt.protocol = 0; // DoT
                bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
                
                return XDP_DROP; // Block DoT
            }
        }

        // Check for DoH (port 443)
        if (tcp->dest == bpf_htons(443)) {
            __u32 key = 1; // block_doh setting
            __u32 *allow_doh = bpf_map_lookup_elem(&global_settings, &key);
            
            // If allow_doh is 0 (default/blocked), check the IP list
            if (!allow_doh || *allow_doh == 0) {
                struct ipv4_lpm_key ip_key;
                ip_key.prefixlen = 32; // Lookup with full length
                ip_key.data = ip->daddr;
                
                __u32 *val = bpf_map_lookup_elem(&doh_ip_list, &ip_key);
                if (val) {
                    struct encrypted_dns_event evt = {};
                    __builtin_memcpy(evt.mac, src_mac.addr, 6);
                    evt.src_ip = ip->saddr;
                    evt.dest_ip = ip->daddr;
                    evt.protocol = 1; // DoH
                    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

                    return XDP_DROP; // Block DoH IP
                }
            }
        }
    }

    // Check if this is UDP traffic (for DoQ blocking and DHCP)
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        // Always allow DHCP traffic (ports 67 and 68)
        // DHCP client (68) -> server (67) and vice versa
        if (udp->source == bpf_htons(68) || udp->dest == bpf_htons(67) ||
            udp->source == bpf_htons(67) || udp->dest == bpf_htons(68)) {
            return XDP_PASS;
        }

        // Check for DoQ (port 853 or 784)
        if (udp->dest == bpf_htons(853) || udp->dest == bpf_htons(784)) {
            __u32 key = 2; // block_doq setting
            __u32 *allow_doq = bpf_map_lookup_elem(&global_settings, &key);
            
            // If map entry exists and value is 1, allow. Otherwise (0 or null), block.
            if (allow_doq && *allow_doq == 1) {
                // Allow DoQ
            } else {
                struct encrypted_dns_event evt = {};
                __builtin_memcpy(evt.mac, src_mac.addr, 6);
                evt.src_ip = ip->saddr;
                evt.dest_ip = ip->daddr;
                evt.protocol = 2; // DoQ
                bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

                return XDP_DROP; // Block DoQ
            }
        }

        // Allow all DNS traffic (port 53) - redirect to DNS inspector via AF_XDP
        if (udp->dest == bpf_htons(53) || udp->source == bpf_htons(53)) {
            // Check if source MAC is in the allowed list
            __u32 *allowed = bpf_map_lookup_elem(&allowed_macs, &src_mac);
            
            // If NOT allowed, record it in dropped_macs so it appears in UI
            if (!allowed) {
                struct device_info *dev_info = bpf_map_lookup_elem(&dropped_macs, &src_mac);
                if (dev_info) {
                    dev_info->count = dev_info->count + 1;
                    dev_info->ip = ip->saddr;
                } else {
                    struct device_info new_dev = {};
                    __builtin_memcpy(new_dev.mac, src_mac.addr, 6);
                    new_dev.ip = ip->saddr;
                    new_dev.count = 1;
                    bpf_map_update_elem(&dropped_macs, &src_mac, &new_dev, BPF_ANY);
                }
            }
            
            __u32 index = 0;
            if (bpf_map_lookup_elem(&xsks_map, &index))
                return bpf_redirect_map(&xsks_map, index, 0);
            // If no AF_XDP socket, pass through
            return XDP_PASS;
        }
    }

    // Extract destination IP address
    __u32 dst_ip = ip->daddr;

    // Allow HTTP traffic (port 80) to support Captive Portal redirection
    // This allows unregistered devices to reach the webserver via DNAT
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) <= data_end) {
            if (tcp->dest == bpf_htons(80)) {
                return XDP_PASS;
            }
        }
    }
    
    // Check if destination is the Gateway IP
    __u32 key_gw = 3;
    __u32 *gw_ip = bpf_map_lookup_elem(&global_settings, &key_gw);
    if (gw_ip && *gw_ip != 0) {
        if (dst_ip == *gw_ip) {
             // Allow traffic to gateway (webserver/DNS)
            __u32 stat_key = STAT_ALLOWED;
            __u64 *count = bpf_map_lookup_elem(&stats, &stat_key);
            if (count) {
                __sync_fetch_and_add(count, 1);
            }
            return XDP_PASS;
        }
    }
    
    // Allow all traffic to local network (192.168.0.0/16)
    // Check if destination is 192.168.x.x
    __u8 *dst_bytes = (__u8 *)&dst_ip;
    if (dst_bytes[0] == 192 && dst_bytes[1] == 168) {
        // Local network traffic - always allow
        __u32 stat_key = STAT_ALLOWED;
        __u64 *count = bpf_map_lookup_elem(&stats, &stat_key);
        if (count) {
            __sync_fetch_and_add(count, 1);
        }
        return XDP_PASS;
    }

    // Check if source MAC is in the allowed list
    __u32 *allowed = bpf_map_lookup_elem(&allowed_macs, &src_mac);
    
    if (allowed) {
        // MAC is allowed - update stats and pass
        __u32 stat_key = STAT_ALLOWED;
        __u64 *count = bpf_map_lookup_elem(&stats, &stat_key);
        if (count) {
            __sync_fetch_and_add(count, 1);
        }
        return XDP_PASS;
    }

    // MAC not found in allowed list - drop packet and update stats
    __u32 stat_key = STAT_DROPPED;
    __u64 *count = bpf_map_lookup_elem(&stats, &stat_key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    // Track this dropped device with MAC and IP
    struct device_info *dev_info = bpf_map_lookup_elem(&dropped_macs, &src_mac);
    if (dev_info) {
        // Read-modify-write since we can't use atomic on packed struct
        dev_info->count = dev_info->count + 1;
        // Update IP in case it changed
        dev_info->ip = ip->saddr;
    } else {
        struct device_info new_dev = {};
        __builtin_memcpy(new_dev.mac, src_mac.addr, 6);
        new_dev.ip = ip->saddr;
        new_dev.count = 1;
        bpf_map_update_elem(&dropped_macs, &src_mac, &new_dev, BPF_ANY);
    }

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";

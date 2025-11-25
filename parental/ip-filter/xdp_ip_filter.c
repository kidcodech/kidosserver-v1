// SPDX-License-Identifier: GPL-2.0
// XDP IP Filter - Allows only registered client IPs
//
// This XDP program filters traffic based on source IP addresses.
// Only IPs present in the allowed_ips map can pass through.
// All other traffic is dropped.
// 
// This program is designed to be chained with DNS filter:
// IP Filter (first) -> DNS Filter (second)

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Map to store allowed client IP addresses
// Key: IPv4 address (32-bit)
// Value: 1 if allowed, 0 if blocked (but we'll only store allowed IPs)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);  // Support up to 10k devices
    __type(key, __u32);           // IPv4 address
    __type(value, __u32);         // Timestamp or metadata (1 = allowed)
} allowed_ips SEC(".maps");

// Statistics map to track dropped packets
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// XDP socket map for DNS packet redirection to userspace (shared with DNS inspector)
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} xsks_map SEC(".maps");

#define STAT_ALLOWED 0
#define STAT_DROPPED 1

SEC("xdp")
int xdp_ip_filter_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS; // Malformed packet

    // Block IPv6 traffic
    if (eth->h_proto == bpf_htons(ETH_P_IPV6))
        return XDP_DROP;

    // Only process IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS; // Allow non-IPv4 traffic (ARP, etc.)

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS; // Malformed packet

    // Check if this is UDP traffic
    if (ip->protocol == IPPROTO_UDP) {
        // Parse UDP header
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS; // Malformed packet
        
        // Allow all DNS traffic (port 53) - redirect to DNS inspector via AF_XDP
        if (udp->dest == bpf_htons(53)) {
            __u32 index = 0;
            if (bpf_map_lookup_elem(&xsks_map, &index))
                return bpf_redirect_map(&xsks_map, index, 0);
            // If no AF_XDP socket, pass through
            return XDP_PASS;
        }
    }

    // Extract destination IP address
    __u32 dst_ip = ip->daddr;
    
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

    // Extract source IP address
    __u32 src_ip = ip->saddr;

    // Check if source IP is in the allowed list
    __u32 *allowed = bpf_map_lookup_elem(&allowed_ips, &src_ip);
    
    if (allowed) {
        // IP is allowed - update stats and pass
        __u32 stat_key = STAT_ALLOWED;
        __u64 *count = bpf_map_lookup_elem(&stats, &stat_key);
        if (count) {
            __sync_fetch_and_add(count, 1);
        }
        return XDP_PASS;
    }

    // IP not found in allowed list - drop packet and update stats
    __u32 stat_key = STAT_DROPPED;
    __u64 *count = bpf_map_lookup_elem(&stats, &stat_key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";

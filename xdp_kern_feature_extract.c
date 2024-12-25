#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <arpa/inet.h> 

#include "xdp_common.h"

#define NS_TO_SECOND 1000000000

// Define map with flows data
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_map SEC(".maps");

// Define map with selected features
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct features_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} features_config SEC(".maps");

// Process packet extracting and calculating features
static __always_inline int process_ip(struct xdp_md *ctx, struct flow_key *flow, __u8 ip_version)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u64 pkt_len = data_end - data;
    __u32 key = 0;
    struct features_config *config;

    // Get features config map
    config = bpf_map_lookup_elem(&features_config, &key);

    // Case features map not found or all features disabled
    if (!config || config->features == 0) {
        bpf_printk("erro config");
        return XDP_PASS;
    }

    flow->ip_version = ip_version;

    // Case IPv4
    if (ip_version == 4) {
        // Check if packet have header IPv4
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) {
            bpf_printk("erro ipv4");
            return XDP_PASS;
        }

        // Extract header info
        flow->src_ip.v4 = ip->saddr;
        flow->dst_ip.v4 = ip->daddr;
        flow->protocol = ip->protocol;

        // Case protocol TCP
        if (ip->protocol == 6) {
            // Check ik packet have TCP header
            struct tcphdr *tcp = (void *)(ip + 1);
            if ((void *)(tcp + 1) > data_end) {
                bpf_printk("erro tcp");
                return XDP_PASS;
            }
            // Extract ports info
            flow->src_port = tcp->source;
            flow->dst_port = tcp->dest;
        // Case protocol UDP
        } else if (ip->protocol == 17) {
            // Check ik packet have UDP header
            struct udphdr *udp = (void *)(ip + 1);
            if ((void *)(udp + 1) > data_end) {
                bpf_printk("erro udp");
                return XDP_PASS;
            }
            // Extract ports info
            flow->src_port = udp->source;
            flow->dst_port = udp->dest;
        // Case other protocol
        } else {
            bpf_printk("erro protocolo");
            return XDP_PASS;
        }
    // Case IPv6
    } else if (ip_version == 6) {
        // Check if packet have IPv6 header
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) {
            bpf_printk("erro ipv6");
            return XDP_PASS;
        }
        // Extract header info
        __builtin_memcpy(flow->src_ip.v6, ip6->saddr.in6_u.u6_addr32, sizeof(flow->src_ip.v6));
        __builtin_memcpy(flow->dst_ip.v6, ip6->daddr.in6_u.u6_addr32, sizeof(flow->dst_ip.v6));
        flow->protocol = ip6->nexthdr;

        // Case protocol TCP
        if (ip6->nexthdr == 6) {
            // Check ik packet have TCP header
            struct tcphdr *tcp = (void *)(ip6 + 1);
            if ((void *)(tcp + 1) > data_end) {
                bpf_printk("erro ipv6 tcp");
                return XDP_PASS;
            }
            // Extract ports info
            flow->src_port = tcp->source;
            flow->dst_port = tcp->dest;
        // Case protocol UDP
        } else if (ip6->nexthdr == 17) {
            // Check ik packet have UDP header
            struct udphdr *udp = (void *)(ip6 + 1);
            if ((void *)(udp + 1) > data_end) {
                bpf_printk("erro ipv6 udp");
                return XDP_PASS;
            }
            // Extract ports info
            flow->src_port = udp->source;
            flow->dst_port = udp->dest;
        // Case other protocol
        } else {
            bpf_printk("erro ipv6 protocolo");
            return XDP_PASS;
        }
    } else {
        bpf_printk("erro ip");
        return XDP_PASS;
    }

    // Search if flow exists in the map
    struct flow_stats *stats, new_stats = {};
    stats = bpf_map_lookup_elem(&flow_map, flow);

    // Case flow already exists, update
    if (stats && (bpf_ktime_get_ns() - stats->last_time) < config->timeout) {
        bpf_printk("update flow");
        // PACKETS
        if (config->features & FEATURE_PACKETS) {
            __sync_fetch_and_add(&stats->packets, 1);
        }
        // BYTES
        if (config->features & FEATURE_BYTES) {
            __sync_fetch_and_add(&stats->bytes, pkt_len);
        }
        // LAST TIME IN NANOSECONDS
        if (config->features & FEATURE_LAST_TIME) {
            stats->last_time = bpf_ktime_get_ns();
        }
        // MAXIMUM PACKET LENGTH
        if (config->features & FEATURE_MAX_PKT_LEN) {
            if (pkt_len > stats->max_pkt_len)
                stats->max_pkt_len = pkt_len;
        }
        // MINIMUM PACKET LENGTH
        if (config->features & FEATURE_MIN_PKT_LEN) {
            if (pkt_len < stats->min_pkt_len)
                stats->min_pkt_len = pkt_len;
        }
        // DURATION in seconds scalled by PRECISION
        if ((config->features & (FEATURE_DURATION | FEATURE_LAST_TIME)) ==
         (FEATURE_DURATION | FEATURE_LAST_TIME)) {
            stats->duration = (stats->last_time - stats->start_time) * config->precision / NS_TO_SECOND;
        }
        // PACKETS PER SECOND scalled by PRECISION
        if ((config->features & (FEATURE_PPS | FEATURE_DURATION)) ==
         (FEATURE_PPS | FEATURE_DURATION)) {
            stats->pps = (stats->packets * config->precision * config->precision) / stats->duration;
        }
        // BYTES PER SECOND scalled by PRECISION
        if ((config->features & (FEATURE_BPS | FEATURE_DURATION)) ==
         (FEATURE_BPS | FEATURE_DURATION)) {
            stats->bps = (stats->bytes * config->precision * config->precision) / stats->duration;
        }
        // MAXIMUM PACKETS PER SECOND scalled by PRECISION
        if ((config->features & (FEATURE_MAX_PPS | FEATURE_PPS)) ==
         (FEATURE_MAX_PPS | FEATURE_PPS)) {
            if (stats->pps > stats->max_pps)
                stats->max_pps = stats->pps;
        }
        // MINIMUM PACKETS PER SECOND scalled by PRECISION
        if ((config->features & (FEATURE_MIN_PPS | FEATURE_PPS)) ==
         (FEATURE_MIN_PPS | FEATURE_PPS)) {
            if (stats->pps < stats->min_pps || stats->min_pps == 0)
                stats->min_pps = stats->pps;
        }
        // MAXIMUM BYTES PER SECOND scalled by PRECISION
        if ((config->features & (FEATURE_MAX_BPS | FEATURE_BPS)) ==
         (FEATURE_MAX_BPS | FEATURE_BPS)) {
            if (stats->bps > stats->max_bps)
                stats->max_bps = stats->bps;
        }
        // MINIMUM BYTES PER SECOND scalled by PRECISION
        if ((config->features & (FEATURE_MIN_BPS | FEATURE_BPS)) ==
         (FEATURE_MIN_BPS | FEATURE_BPS)) {
            if (stats->bps < stats->min_bps || stats->min_bps == 0)
                stats->min_bps = stats->bps;
        }
        // SUM PACKETS PER SECOND scalled by PRECISION
        if ((config->features & (FEATURE_SUM_PPS | FEATURE_PPS)) ==
         (FEATURE_SUM_PPS | FEATURE_PPS)) {
            __sync_fetch_and_add(&stats->sum_pps, stats->pps);
        }
        // SUM BYTES PER SECOND scalled by PRECISION
        if ((config->features & (FEATURE_SUM_BPS | FEATURE_BPS)) ==
         (FEATURE_SUM_BPS | FEATURE_BPS)) {
            __sync_fetch_and_add(&stats->sum_bps, stats->bps);
        }
        // AVERAGE PACKETS PER SECOND scalled by PRECISION
        if ((config->features & (FEATURE_AVG_PPS | FEATURE_SUM_PPS | FEATURE_PACKETS)) ==
         (FEATURE_AVG_PPS | FEATURE_SUM_PPS | FEATURE_PACKETS)) {
            stats->avg_pps = stats->sum_pps / stats->packets;
        }
        // AVERAGE BYTES PER SECOND scalled by PRECISION
        if ((config->features & (FEATURE_AVG_BPS | FEATURE_SUM_BPS | FEATURE_PACKETS)) ==
         (FEATURE_AVG_BPS | FEATURE_SUM_BPS | FEATURE_PACKETS)) {
            stats->avg_bps = stats->sum_bps / stats->packets;
        }
        // AVERAGE BYTES PER PACKET scalled by PRECISION
        if ((config->features & (FEATURE_AVG_BPP | FEATURE_BYTES | FEATURE_PACKETS)) == 
         (FEATURE_AVG_BPP | FEATURE_BYTES | FEATURE_PACKETS)) {
            stats->avg_bpp = (stats->bytes * config->precision) / stats->packets;
        }
    // Case flow not exists in the map or timeout, create new 
    } else {
        bpf_printk("new flow");
        // PACKETS
        if (config->features & FEATURE_PACKETS) {
            new_stats.packets = 1;
        }
        // BYTES
        if (config->features & FEATURE_BYTES) {
            new_stats.bytes = pkt_len;
        }
        // START TIME in nanoseconds
        if (config->features & FEATURE_START_TIME) {
            new_stats.start_time = bpf_ktime_get_ns();
        }
        // LAST TIME in nanoseconds
        if (config->features & FEATURE_LAST_TIME) {
            new_stats.last_time = bpf_ktime_get_ns();
        }
        // MAXIMUM PACKET LENGTH
        if (config->features & FEATURE_MAX_PKT_LEN) {
            new_stats.max_pkt_len = pkt_len;
        }
        // MINIMUM PACKET LENGTH
        if (config->features & FEATURE_MIN_PKT_LEN) {
            new_stats.min_pkt_len = pkt_len;
        }
        // DURATION in seconds
        if (config->features & FEATURE_DURATION) {
            new_stats.duration = 0;
        }
        // PACKETS PER SECOND
        if (config->features & FEATURE_PPS) {
            new_stats.pps = 0;
        }
        // BYTES PER SECOND
        if (config->features & FEATURE_BPS) {
            new_stats.bps = 0;
        }
        // MAXIMUM PACKET PER SECOND
        if (config->features & FEATURE_MAX_PPS) {
            new_stats.max_pps = 0;
        }
        // MINIMUM PACKET PER SECOND
        if (config->features & FEATURE_MIN_PPS) {
            new_stats.min_pps = 0;
        }
        // MAXIMUM BYTES PER SECOND
        if (config->features & FEATURE_MAX_BPS) {
            new_stats.max_bps = 0;
        }
        // MINIMUM BYTES PER SECOND
        if (config->features & FEATURE_MIN_BPS) {
            new_stats.min_bps = 0;
        }
        // SUM PACKET PER SECOND
        if (config->features & FEATURE_SUM_PPS) {
            new_stats.sum_pps = 0;
        }
        // SUM BYTES PER SECOND
        if (config->features & FEATURE_SUM_BPS) {
            new_stats.sum_bps = 0;
        }
        // AVERAGE PACKET PER SECOND
        if (config->features & FEATURE_AVG_PPS) {
            new_stats.avg_pps = 0;
        }
        // AVERAGE BYTES PER SECOND
        if (config->features & FEATURE_AVG_BPS) {
            new_stats.avg_bps = 0;
        }
        // AVERAGE BYTES PER PACKET
        if ((config->features & (FEATURE_AVG_BPP | FEATURE_BYTES | FEATURE_PACKETS)) == 
         (FEATURE_AVG_BPP | FEATURE_BYTES | FEATURE_PACKETS)) {
            new_stats.avg_bpp = pkt_len;
        }

        bpf_map_update_elem(&flow_map, flow, &new_stats, BPF_ANY);
    }
    return XDP_PASS;
}

// Principal Function
SEC("xdp")
int xdp_flow_stats(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    // Check if packet is ate least bigger than Ethernet header
    if (data + sizeof(*eth) > data_end) {
        bpf_printk("erro ethernet");
        return XDP_PASS;
    }

    struct flow_key flow = {};

    // Check if packet is IP
    if (eth->h_proto == htons(ETH_P_IP))
        return process_ip(ctx, &flow, 4); // Process IPv4 packet
    else if (eth->h_proto == htons(ETH_P_IPV6))
        return process_ip(ctx, &flow, 6); // Process IPv6 packet
    bpf_printk("erro ip");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
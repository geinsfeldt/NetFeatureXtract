#include "uthash.h"
#ifndef __XDP_COMMON_H
#define __XDP_COMMON_H

// Define union of IPv4 and IPv6 addresses
union ip_addr {
    __be32 v4;
    __be32 v6[4];
};

// Define the struct that identifies the flow
struct flow_key {
    union ip_addr src_ip;
    union ip_addr dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
    __u8 ip_version;
};

// Define the struct to configure features

struct features_config {
    __u32 features;
    __u32 precision;
    __u64 timeout;
};

// Define the features of the flow
#define FEATURE_PACKETS (1 << 0)
#define FEATURE_BYTES (1 << 1)
#define FEATURE_START_TIME (1 << 2)
#define FEATURE_LAST_TIME (1 << 3)
#define FEATURE_MAX_PKT_LEN (1 << 4)
#define FEATURE_MIN_PKT_LEN (1 << 5)
#define FEATURE_DURATION (1 << 6)
#define FEATURE_PPS (1 << 7)
#define FEATURE_BPS (1 << 8)
#define FEATURE_MAX_PPS (1 << 9)
#define FEATURE_MIN_PPS (1 << 10)
#define FEATURE_MAX_BPS (1 << 11)
#define FEATURE_MIN_BPS (1 << 12)
#define FEATURE_SUM_PPS (1 << 13)
#define FEATURE_SUM_BPS (1 << 14)
#define FEATURE_AVG_PPS (1 << 15)
#define FEATURE_AVG_BPS (1 << 16)
#define FEATURE_AVG_BPP (1 << 17)

// Define the struct with the flow features data
struct flow_stats {
    __u64 packets;
    __u64 bytes;
    __u64 start_time;
    __u64 last_time;
    __u32 max_pkt_len;
    __u32 min_pkt_len;
    __u64 duration;
    __u64 pps;
    __u64 bps;
    __u64 max_pps;
    __u64 min_pps;
    __u64 max_bps;
    __u64 min_bps;
    __u64 sum_pps;
    __u64 sum_bps;
    __u64 avg_pps;
    __u64 avg_bps;
    __u32 avg_bpp;
};

#endif

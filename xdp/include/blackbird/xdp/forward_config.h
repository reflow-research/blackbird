#pragma once

#include <stdint.h>

#define BLACKBIRD_XDP_ACTION_NONE 0U
#define BLACKBIRD_XDP_ACTION_REDIRECT 1U
#define BLACKBIRD_XDP_ACTION_PASS 2U
#define BLACKBIRD_XDP_ACTION_DROP 3U
#define BLACKBIRD_XDP_ACTION_MIRROR 4U

struct blackbird_xdp_forward_config {
    uint32_t enabled;
    uint32_t action;
    uint32_t collect_stats;
    uint32_t match_dst_ip_be;
    uint32_t rewrite_dst_ip_be;
    uint16_t match_dst_port_be;
    uint16_t rewrite_dst_port_be;
    uint8_t rewrite_dst_mac[6];
    uint8_t rewrite_src_mac[6];
    uint8_t rewrite_ttl;
    uint8_t reserved0;
    uint16_t reserved1;
};

struct blackbird_xdp_stats {
    uint64_t matched_packets;
    uint64_t matched_bytes;
    uint64_t redirect_packets;
    uint64_t pass_packets;
    uint64_t drop_packets;
};

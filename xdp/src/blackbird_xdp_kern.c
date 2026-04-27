#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include "blackbird/xdp/forward_config.h"

#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value* name
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

static void* (*bpf_map_lookup_elem)(void* map, const void* key) =
    (void*)BPF_FUNC_map_lookup_elem;
static long (*bpf_redirect_map)(void* map, unsigned int key, unsigned long long flags) =
    (void*)BPF_FUNC_redirect_map;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, struct blackbird_xdp_forward_config);
} cfg_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 64);
    __type(key, unsigned int);
    __type(value, unsigned int);
} tx_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, struct blackbird_xdp_stats);
} stats_map SEC(".maps");

static __always_inline unsigned short bswap16(unsigned short v) {
    return __builtin_bswap16(v);
}

static __always_inline unsigned short csum_fold(unsigned int sum) {
    sum = (sum & 0xffffU) + (sum >> 16U);
    sum = (sum & 0xffffU) + (sum >> 16U);
    return (unsigned short)(~sum);
}

static __always_inline unsigned short csum_replace_32(
    unsigned short check,
    unsigned int old_value,
    unsigned int new_value
) {
    unsigned int sum = (~check) & 0xffffU;
    sum += (~old_value) & 0xffffU;
    sum += ((~old_value) >> 16U) & 0xffffU;
    sum += new_value & 0xffffU;
    sum += (new_value >> 16U) & 0xffffU;
    return csum_fold(sum);
}

static __always_inline unsigned short csum_replace_16(
    unsigned short check,
    unsigned short old_value,
    unsigned short new_value
) {
    unsigned int sum = (~check) & 0xffffU;
    sum += (~old_value) & 0xffffU;
    sum += new_value & 0xffffU;
    return csum_fold(sum);
}

SEC("xdp")
int blackbird_xdp_mcast(struct xdp_md* ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    struct ethhdr* eth = data;
    if ((void*)(eth + 1) > data_end) {
        return XDP_PASS;
    }
    if (eth->h_proto != bswap16(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr* ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end) {
        return XDP_PASS;
    }
    if (ip->ihl != 5) {
        return XDP_PASS;
    }
    if (ip->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }

    struct udphdr* udp = (void*)(ip + 1);
    if ((void*)(udp + 1) > data_end) {
        return XDP_PASS;
    }

    unsigned int cfg_key = 0;
    struct blackbird_xdp_forward_config* cfg = bpf_map_lookup_elem(&cfg_map, &cfg_key);
    if (cfg == (void*)0 || cfg->enabled == 0) {
        return XDP_PASS;
    }

    if (cfg->match_dst_ip_be != 0 && ip->daddr != cfg->match_dst_ip_be) {
        return XDP_PASS;
    }
    if (cfg->match_dst_port_be != 0 && udp->dest != cfg->match_dst_port_be) {
        return XDP_PASS;
    }

    struct blackbird_xdp_stats* stats = (void*)0;
    if (cfg->collect_stats != 0) {
        stats = bpf_map_lookup_elem(&stats_map, &cfg_key);
        if (stats != (void*)0) {
            const unsigned int frame_len = (unsigned int)((long)data_end - (long)data);
            stats->matched_packets += 1;
            stats->matched_bytes += frame_len;
        }
    }

    const unsigned int action = cfg->action;
    if (action == BLACKBIRD_XDP_ACTION_REDIRECT) {
        const unsigned int old_daddr = ip->daddr;
        const unsigned short old_dport = udp->dest;

        ip->daddr = cfg->rewrite_dst_ip_be;
        udp->dest = cfg->rewrite_dst_port_be;
        ip->check = csum_replace_32(ip->check, old_daddr, ip->daddr);

        if (cfg->rewrite_ttl != 0 && cfg->rewrite_ttl != ip->ttl) {
            const unsigned short old_ttl_proto =
                bswap16(((unsigned short)ip->ttl << 8U) | ip->protocol);
            ip->ttl = cfg->rewrite_ttl;
            const unsigned short new_ttl_proto =
                bswap16(((unsigned short)ip->ttl << 8U) | ip->protocol);
            ip->check = csum_replace_16(ip->check, old_ttl_proto, new_ttl_proto);
        }

        if (udp->check != 0) {
            unsigned short udp_csum = udp->check;
            udp_csum = csum_replace_32(udp_csum, old_daddr, ip->daddr);
            udp_csum = csum_replace_16(udp_csum, old_dport, udp->dest);
            if (udp_csum == 0) {
                udp_csum = 0xffff;
            }
            udp->check = udp_csum;
        }

#pragma unroll
        for (int i = 0; i < ETH_ALEN; ++i) {
            eth->h_dest[i] = cfg->rewrite_dst_mac[i];
            eth->h_source[i] = cfg->rewrite_src_mac[i];
        }

        if (stats != (void*)0) {
            stats->redirect_packets += 1;
        }
        return bpf_redirect_map(&tx_ports, cfg_key, 0);
    }

    if (action == BLACKBIRD_XDP_ACTION_REWRITE_PASS) {
        const unsigned short old_dport = udp->dest;
        const unsigned short new_dport = cfg->rewrite_dst_port_be;
        if (new_dport == 0) {
            return XDP_PASS;
        }

        udp->dest = new_dport;
        if (udp->check != 0) {
            unsigned short udp_csum = udp->check;
            udp_csum = csum_replace_16(udp_csum, old_dport, udp->dest);
            if (udp_csum == 0) {
                udp_csum = 0xffff;
            }
            udp->check = udp_csum;
        }

        if (stats != (void*)0) {
            stats->pass_packets += 1;
        }
        return XDP_PASS;
    }

    if (action == BLACKBIRD_XDP_ACTION_DROP) {
        if (stats != (void*)0) {
            stats->drop_packets += 1;
        }
        return XDP_DROP;
    }

    if (action == BLACKBIRD_XDP_ACTION_PASS) {
        if (stats != (void*)0) {
            stats->pass_packets += 1;
        }
        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

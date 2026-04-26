#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
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
static long (*bpf_skb_store_bytes)(struct __sk_buff* skb, __u32 offset, const void* from, __u32 len, __u64 flags) =
    (void*)BPF_FUNC_skb_store_bytes;
static long (*bpf_l3_csum_replace)(struct __sk_buff* skb, __u32 offset, __u64 from, __u64 to, __u64 flags) =
    (void*)BPF_FUNC_l3_csum_replace;
static long (*bpf_l4_csum_replace)(struct __sk_buff* skb, __u32 offset, __u64 from, __u64 to, __u64 flags) =
    (void*)BPF_FUNC_l4_csum_replace;
static long (*bpf_redirect)(__u32 ifindex, __u64 flags) = (void*)BPF_FUNC_redirect;
static long (*bpf_clone_redirect)(struct __sk_buff* skb, __u32 ifindex, __u64 flags) =
    (void*)BPF_FUNC_clone_redirect;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct blackbird_xdp_forward_config);
} cfg_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} tx_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct blackbird_xdp_stats);
} stats_map SEC(".maps");

struct blackbird_vlan_hdr {
    __be16 h_vlan_tci;
    __be16 h_vlan_encapsulated_proto;
} __attribute__((packed));

static __always_inline __u16 bswap16(__u16 value) {
    return __builtin_bswap16(value);
}

SEC("tc")
int blackbird_tc_mcast(struct __sk_buff* skb) {
    void* data = (void*)(long)skb->data;
    void* data_end = (void*)(long)skb->data_end;
    __u8* data_u8 = data;

    if ((void*)(data_u8 + 1) > data_end) {
        return TC_ACT_OK;
    }

    __u32 ip_off = 0;
    __u8 has_eth = 0;

    const __u8 first_nibble = (__u8)(data_u8[0] >> 4U);
    if (first_nibble != 4U) {
        struct ethhdr* eth = data;
        if ((void*)(eth + 1) > data_end) {
            return TC_ACT_OK;
        }

        has_eth = 1;
        __u16 proto = eth->h_proto;
        ip_off = (__u32)sizeof(*eth);

        if (proto == bswap16(ETH_P_8021Q) || proto == bswap16(ETH_P_8021AD)) {
            struct blackbird_vlan_hdr* vlan = (void*)(data_u8 + ip_off);
            if ((void*)(vlan + 1) > data_end) {
                return TC_ACT_OK;
            }
            proto = vlan->h_vlan_encapsulated_proto;
            ip_off += (__u32)sizeof(*vlan);
        }
        if (proto == bswap16(ETH_P_8021Q) || proto == bswap16(ETH_P_8021AD)) {
            struct blackbird_vlan_hdr* vlan = (void*)(data_u8 + ip_off);
            if ((void*)(vlan + 1) > data_end) {
                return TC_ACT_OK;
            }
            proto = vlan->h_vlan_encapsulated_proto;
            ip_off += (__u32)sizeof(*vlan);
        }

        if (proto != bswap16(ETH_P_IP)) {
            return TC_ACT_OK;
        }
    }

    struct iphdr* ip = (void*)(data_u8 + ip_off);
    if ((void*)(ip + 1) > data_end) {
        return TC_ACT_OK;
    }
    if (ip->version != 4 || ip->ihl != 5) {
        return TC_ACT_OK;
    }
    if (ip->protocol != IPPROTO_UDP) {
        return TC_ACT_OK;
    }

    struct udphdr* udp = (void*)(ip + 1);
    if ((void*)(udp + 1) > data_end) {
        return TC_ACT_OK;
    }

    const __u32 cfg_key = 0;
    struct blackbird_xdp_forward_config* cfg = bpf_map_lookup_elem(&cfg_map, &cfg_key);
    if (cfg == (void*)0 || cfg->enabled == 0) {
        return TC_ACT_OK;
    }

    if (cfg->match_dst_ip_be != 0 && ip->daddr != cfg->match_dst_ip_be) {
        return TC_ACT_OK;
    }
    if (cfg->match_dst_port_be != 0 && udp->dest != cfg->match_dst_port_be) {
        return TC_ACT_OK;
    }

    struct blackbird_xdp_stats* stats = (void*)0;
    if (cfg->collect_stats != 0) {
        stats = bpf_map_lookup_elem(&stats_map, &cfg_key);
        if (stats != (void*)0) {
            const __u32 frame_len = (__u32)((long)data_end - (long)data);
            stats->matched_packets += 1;
            stats->matched_bytes += frame_len;
        }
    }

    const __u32 action = cfg->action;
    if (action == BLACKBIRD_XDP_ACTION_PASS) {
        if (stats != (void*)0) {
            stats->pass_packets += 1;
        }
        return TC_ACT_OK;
    }
    if (action == BLACKBIRD_XDP_ACTION_DROP) {
        if (stats != (void*)0) {
            stats->drop_packets += 1;
        }
        return TC_ACT_SHOT;
    }
    if (action != BLACKBIRD_XDP_ACTION_REDIRECT && action != BLACKBIRD_XDP_ACTION_MIRROR) {
        return TC_ACT_OK;
    }

    __u32* out_ifindex = bpf_map_lookup_elem(&tx_ports, &cfg_key);
    if (out_ifindex == (void*)0 || *out_ifindex == 0) {
        return TC_ACT_OK;
    }

    const __u32 udp_off = (const __u32)sizeof(struct iphdr);
    const __u32 ip_csum_off = ip_off + 10U;
    const __u32 ip_daddr_off = ip_off + 16U;
    const __u32 ip_ttl_off = ip_off + 8U;
    const __u32 udp_csum_off = ip_off + udp_off + 6U;
    const __u32 udp_dport_off = ip_off + udp_off + 2U;

    const __u32 old_daddr = ip->daddr;
    const __u16 old_dport = udp->dest;
    const __u8 old_ttl = ip->ttl;
    const __u8 ip_protocol = ip->protocol;
    const __u16 old_udp_check = udp->check;
    const __u16 old_ttl_proto = (__u16)(((__u16)old_ttl << 8U) | (__u16)ip_protocol);
    __u8 old_eth_dst[ETH_ALEN] = {0};
    __u8 old_eth_src[ETH_ALEN] = {0};
    if (has_eth) {
        __builtin_memcpy(old_eth_dst, data_u8, ETH_ALEN);
        __builtin_memcpy(old_eth_src, data_u8 + ETH_ALEN, ETH_ALEN);
    }

    if (bpf_l3_csum_replace(skb, ip_csum_off, old_daddr, cfg->rewrite_dst_ip_be, sizeof(__u32)) != 0) {
        return TC_ACT_OK;
    }
    if (bpf_skb_store_bytes(skb, ip_daddr_off, &cfg->rewrite_dst_ip_be, sizeof(cfg->rewrite_dst_ip_be), 0) != 0) {
        return TC_ACT_OK;
    }

    if (cfg->rewrite_ttl != 0 && cfg->rewrite_ttl != old_ttl) {
        const __u16 new_ttl_proto = (__u16)(((__u16)cfg->rewrite_ttl << 8U) | (__u16)ip_protocol);
        if (bpf_l3_csum_replace(skb, ip_csum_off, old_ttl_proto, new_ttl_proto, sizeof(__u16)) != 0) {
            return TC_ACT_OK;
        }
        if (bpf_skb_store_bytes(skb, ip_ttl_off, &cfg->rewrite_ttl, sizeof(cfg->rewrite_ttl), 0) != 0) {
            return TC_ACT_OK;
        }
    }

    if (old_udp_check != 0) {
        if (bpf_l4_csum_replace(
                skb,
                udp_csum_off,
                old_daddr,
                cfg->rewrite_dst_ip_be,
                sizeof(__u32) | BPF_F_PSEUDO_HDR
            ) != 0) {
            return TC_ACT_OK;
        }
        if (bpf_l4_csum_replace(
                skb,
                udp_csum_off,
                old_dport,
                cfg->rewrite_dst_port_be,
                sizeof(__u16)
            ) != 0) {
            return TC_ACT_OK;
        }
    }

    if (bpf_skb_store_bytes(skb, udp_dport_off, &cfg->rewrite_dst_port_be, sizeof(cfg->rewrite_dst_port_be), 0) != 0) {
        return TC_ACT_OK;
    }

    if (has_eth) {
        const __u32 eth_dst_off = 0U;
        const __u32 eth_src_off = (__u32)ETH_ALEN;
        if (bpf_skb_store_bytes(skb, eth_dst_off, cfg->rewrite_dst_mac, ETH_ALEN, 0) != 0) {
            return TC_ACT_OK;
        }
        if (bpf_skb_store_bytes(skb, eth_src_off, cfg->rewrite_src_mac, ETH_ALEN, 0) != 0) {
            return TC_ACT_OK;
        }
    }

    if (action == BLACKBIRD_XDP_ACTION_MIRROR) {
        const long clone_rc = bpf_clone_redirect(skb, *out_ifindex, 0);
        const __u64 csum_flags = BPF_F_RECOMPUTE_CSUM;
        __u8 restore_ok = 1;
        if (bpf_skb_store_bytes(skb, ip_daddr_off, &old_daddr, sizeof(old_daddr), csum_flags) != 0) {
            restore_ok = 0;
        }
        if (cfg->rewrite_ttl != 0 && cfg->rewrite_ttl != old_ttl) {
            if (bpf_skb_store_bytes(skb, ip_ttl_off, &old_ttl, sizeof(old_ttl), csum_flags) != 0) {
                restore_ok = 0;
            }
        }
        if (bpf_skb_store_bytes(skb, udp_dport_off, &old_dport, sizeof(old_dport), csum_flags) != 0) {
            restore_ok = 0;
        }
        if (has_eth) {
            const __u32 eth_dst_off = 0U;
            const __u32 eth_src_off = (__u32)ETH_ALEN;
            if (bpf_skb_store_bytes(skb, eth_dst_off, old_eth_dst, ETH_ALEN, 0) != 0) {
                restore_ok = 0;
            }
            if (bpf_skb_store_bytes(skb, eth_src_off, old_eth_src, ETH_ALEN, 0) != 0) {
                restore_ok = 0;
            }
        }
        if (restore_ok == 0 && stats != (void*)0) {
            stats->drop_packets += 1;
        }
        if (clone_rc != 0 && stats != (void*)0) {
            stats->drop_packets += 1;
        }
        if (clone_rc == 0 && restore_ok != 0 && stats != (void*)0) {
            stats->redirect_packets += 1;
        }
        if (restore_ok == 0) {
            return TC_ACT_SHOT;
        }
        return TC_ACT_OK;
    }

    if (stats != (void*)0) {
        stats->redirect_packets += 1;
    }

    return (int)bpf_redirect(*out_ifindex, 0);
}

char _license[] SEC("license") = "GPL";

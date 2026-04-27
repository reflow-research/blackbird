#include <linux/bpf.h>
#include <linux/if_link.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value* name

static long (*bpf_redirect_map)(void* map, unsigned int key, unsigned long long flags) =
    (void*)BPF_FUNC_redirect_map;

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, unsigned int);
} tx_ports SEC(".maps");

SEC("xdp")
int blackbird_xdp_fast_forward(struct xdp_md* ctx) {
    (void)ctx;
    return (int)bpf_redirect_map(&tx_ports, 0, XDP_PASS);
}

char _license[] SEC("license") = "GPL";

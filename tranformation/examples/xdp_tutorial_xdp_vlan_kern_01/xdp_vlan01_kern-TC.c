#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>
#define VLAN_MAX_DEPTH 10
struct hdr_cursor {
    void *pos;
};

static __always_inline int proto_is_vlan (__u16 h_proto) {
    return !!(h_proto == bpf_htons (ETH_P_8021Q) || h_proto == bpf_htons (ETH_P_8021AD));
}

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

static __always_inline int parse_ethhdr (struct hdr_cursor *nh, void *data_end, struct ethhdr **ethhdr) {
    struct ethhdr *eth = nh->pos;
    int hdrsize = sizeof (*eth);
    struct vlan_hdr *vlh;
    __u16 h_proto;
    int i;
    if (nh->pos + hdrsize > data_end)
        return -1;
    nh->pos += hdrsize;
    *ethhdr = eth;
    vlh = nh->pos;
    h_proto = eth->h_proto;
#pragma unroll
    for (i = 0; i < VLAN_MAX_DEPTH; i++) {
        if (!proto_is_vlan (h_proto))
            break;
        if (vlh + 1 > data_end)
            break;
        h_proto = vlh->h_vlan_encapsulated_proto;
        vlh++;
    }
    nh->pos = vlh;
    return h_proto;
}

SEC ("xdp_vlan01")
int xdp_vlan_01 (struct __sk_buff *ctx) {
    void *data_end = (void *) (long) ctx->data_end;
    void *data = (void *) (long) ctx->data;
    struct hdr_cursor nh;
    int nh_type;
    nh.pos = data;
    struct ethhdr *eth;
    nh_type = parse_ethhdr (&nh, data_end, &eth);
    if (nh_type < 0)
        return TC_ACT_SHOT;
    if (proto_is_vlan (ctx->protocol))
        return TC_ACT_SHOT;
    return TC_ACT_OK;
}


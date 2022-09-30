#define KBUILD_MODNAME "foo"
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20
#define TCP_ECE  0x40
#define TCP_CWR  0x80
#define TCP_FLAGS (TCP_FIN|TCP_SYN|TCP_RST|TCP_ACK|TCP_URG|TCP_ECE|TCP_CWR)
#define ipv4_lo_addr 0x7F
#define ipv6_lo_addr 0x1
#define bpf_printk(fmt, ...)                                    \
({                                                              \
               char ____fmt[] = fmt;                            \
               bpf_trace_printk(____fmt, sizeof(____fmt),       \
                                ##__VA_ARGS__);                 \
})
typedef uint64_t u64;
struct inet_sock_state_ctx {
    u64 __pad;
    const void *skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u8 protocol;
    __u8 saddr [4];
    __u8 daddr [4];
    __u8 saddr_v6 [16];
    __u8 daddr_v6 [16];
};
struct bpf_map_def SEC ("maps")
cl_conn_count = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof (uint32_t),
    .value_size = sizeof (uint64_t),
    .max_entries = 1,
};
struct bpf_map_def SEC ("maps")
cl_max_conn = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof (uint32_t),
    .value_size = sizeof (uint64_t),
    .max_entries = 1,
};
struct bpf_map_def SEC ("maps")
cl_tcp_conns = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof (uint16_t),
    .value_size = sizeof (uint32_t),
    .max_entries = 200,
};
struct bpf_map_def SEC ("maps")
cl_conn_info = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof (uint64_t),
    .value_size = sizeof (uint32_t),
    .max_entries = 30000
};
struct bpf_map_def SEC ("maps")
cl_recv_count_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof (uint32_t),
    .value_size = sizeof (uint64_t),
    .max_entries = 1
};
struct bpf_map_def SEC ("maps")
cl_drop_count_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof (uint32_t),
    .value_size = sizeof (uint64_t),
    .max_entries = 1
};
struct bpf_map_def SEC ("maps")
xdp_cl_ingress_next_prog = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof (int),
    .value_size = sizeof (int),
    .max_entries = 1
};

static __always_inline int is_ipv4_loopback (uint32_t *addr4) {
    if ((*addr4 & 0xff) == ipv4_lo_addr)
        return 1;
    return 0;
}

static __always_inline int is_ipv6_loopback (uint32_t addr6 []) {
    if ((addr6[0] == 0) && (addr6[1] == 0) && (addr6[2] == 0) && (addr6[3] == 1))
        return 1;
    if ((addr6[0] == 0) && (addr6[1] == 0) && (addr6[2] == 0xffff0000) && ((addr6[3] & 0xff) == 0x7f))
        return 1;
    return 0;
}

SEC ("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state (struct inet_sock_state_ctx *args) {
    uint32_t key = 0, map_val = 1, *ret_val;
    uint64_t *val;
    if (args->protocol != IPPROTO_TCP)
        return 0;
    uint64_t skaddr = (uint64_t) args->skaddr;
    uint16_t sport = args->sport;
    if (args->newstate == BPF_TCP_ESTABLISHED) {
        if (args->family == AF_INET6) {
            struct in6_addr src_addr, dst_addr;
            if (bpf_probe_read (&src_addr.s6_addr32, sizeof (src_addr.s6_addr32), args->saddr_v6) != 0)
                return 0;
            if (bpf_probe_read (&dst_addr.s6_addr32, sizeof (dst_addr.s6_addr32), args->daddr_v6) != 0)
                return 0;
            if (is_ipv6_loopback (src_addr.s6_addr32)) {
                return 0;
            }
            if (is_ipv6_loopback (dst_addr.s6_addr32)) {
                return 0;
            }
        }
        if (args->family == AF_INET) {
            uint32_t src_addr, dst_addr;
            if (bpf_probe_read (&src_addr, sizeof (src_addr), args->saddr) != 0)
                return 0;
            if (bpf_probe_read (&dst_addr, sizeof (dst_addr), args->daddr) != 0)
                return 0;
            if (is_ipv4_loopback (&src_addr))
                return 0;
            if (is_ipv4_loopback (&dst_addr))
                return 0;
        }
        if (!bpf_map_lookup_elem (&cl_tcp_conns, &sport))
            return 0;
        if (bpf_map_update_elem (&cl_conn_info, &skaddr, &map_val, BPF_NOEXIST) == 0) {
            val = bpf_map_lookup_elem (&cl_conn_count, &key);
            if (val)
                __sync_fetch_and_add (val, 1);
        }
        return 0;
    }
    if (args->oldstate == BPF_TCP_ESTABLISHED) {
        if (args->family == AF_INET6) {
            struct in6_addr src_addr, dst_addr;
            if (bpf_probe_read (&src_addr.s6_addr32, sizeof (src_addr.s6_addr32), args->saddr_v6) != 0)
                return 0;
            if (bpf_probe_read (&dst_addr.s6_addr32, sizeof (dst_addr.s6_addr32), args->daddr_v6) != 0)
                return 0;
            if (is_ipv6_loopback (src_addr.s6_addr32))
                return 0;
            if (is_ipv6_loopback (dst_addr.s6_addr32))
                return 0;
        }
        if (args->family == AF_INET) {
            uint32_t src_addr, dst_addr;
            if (bpf_probe_read (&src_addr, sizeof (src_addr), args->saddr) != 0)
                return 0;
            if (bpf_probe_read (&dst_addr, sizeof (dst_addr), args->daddr) != 0)
                return 0;
            if (is_ipv4_loopback (&src_addr))
                return 0;
            if (is_ipv4_loopback (&dst_addr))
                return 0;
        }
        if (!bpf_map_lookup_elem (&cl_tcp_conns, &sport))
            return 0;
        if (bpf_map_lookup_elem (&cl_conn_info, &skaddr)) {
            if (bpf_map_delete_elem (&cl_conn_info, &skaddr) == 0) {
                val = bpf_map_lookup_elem (&cl_conn_count, &key);
                if (val && (*val > 0))
                    __sync_fetch_and_add (val, -1);
            }
        }
    }
    return 0;
}

SEC ("xdp_limit_conn")
int _xdp_limit_conn (struct __sk_buff *ctx) {
    void *data_end = (void *) (long) ctx->data_end;
    void *data = (void *) (long) ctx->data;
    if (data + sizeof (struct ethhdr) + 1 > data_end)
        return TC_ACT_OK;
    struct iphdr *iph = (struct iphdr *) (data + sizeof (struct ethhdr));
    if (iph + 1 > data_end)
        return TC_ACT_OK;
    if (iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;
    struct tcphdr *tcph = (struct tcphdr *) (iph + 1);
    if (tcph + 1 > data_end)
        return TC_ACT_OK;
    if (!(tcph->syn & TCP_FLAGS))
        return TC_ACT_OK;
    if (tcph->ack & TCP_FLAGS)
        return TC_ACT_OK;
    uint16_t dstport = bpf_ntohs (tcph->dest);
    if (!bpf_map_lookup_elem (&cl_tcp_conns, &dstport))
        return TC_ACT_OK;
    uint32_t key = 0, rkey = 0, dkey = 0;
    uint64_t *conn_count_val, *max_conn_val, *recv_count_val, *drop_count_val;
    recv_count_val = bpf_map_lookup_elem (&cl_recv_count_map, &rkey);
    if (recv_count_val)
        (*recv_count_val)++;
    max_conn_val = bpf_map_lookup_elem (&cl_max_conn, &key);
    if (!max_conn_val)
        return TC_ACT_OK;
    conn_count_val = bpf_map_lookup_elem (&cl_conn_count, &key);
    if (!conn_count_val)
        return TC_ACT_OK;
    if (*conn_count_val > *max_conn_val) {
        drop_count_val = bpf_map_lookup_elem (&cl_drop_count_map, &dkey);
        if (drop_count_val) {
            (*drop_count_val)++;
        }
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

char _license [] SEC ("license") = "Dual BSD/GPL";

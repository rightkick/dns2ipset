// SPDX-License-Identifier: GPL-2.0
#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define MAX_PAYLOAD 4096

char LICENSE[] SEC("license") = "GPL";

enum dir { DIR_SEND = 0, DIR_RECV = 1 };

struct event {
    __u64 ts_ns;
    __u8  direction;
    __u8  family;
    __u16 src_port;
    __u16 dst_port;
    __u16 payload_len;
    __u8  payload[MAX_PAYLOAD];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MiB
} events SEC(".maps");

// Per-CPU scratch so we don't blow the 512-byte stack with `struct event`.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct event);
    __uint(max_entries, 1);
} scratch SEC(".maps");

static __always_inline int handle(struct sock *sk, struct msghdr *msg, __u8 direction)
{
    if (!sk || !msg) return 0;

    struct inet_sock *inet = (struct inet_sock *)sk;
    __u16 sport = BPF_CORE_READ(inet, inet_sport);
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    __u16 sport_h = bpf_ntohs(sport);
    __u16 dport_h = bpf_ntohs(dport);

    if (sport_h != 53 && dport_h != 53) return 0;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    __u8 fam_short = (family == AF_INET) ? 4 : (family == AF_INET6) ? 6 : 0;
    if (fam_short == 0) return 0;

    __u32 zero = 0;
    struct event *e = bpf_map_lookup_elem(&scratch, &zero);
    if (!e) return 0;
    e->ts_ns = bpf_ktime_get_ns();
    e->direction = direction;
    e->family = fam_short;
    e->src_port = sport_h;
    e->dst_port = dport_h;
    e->payload_len = 0;

    // Walk the iov to copy up to MAX_PAYLOAD bytes.
    struct iov_iter iter;
    if (bpf_core_read(&iter, sizeof(iter), &msg->msg_iter) < 0) return 0;

    // For 5.x kernels with iov_iter using `__iov`, prefer that field; otherwise fall back.
    const struct iovec *iov = NULL;
    if (bpf_core_field_exists(iter.__iov))
        iov = BPF_CORE_READ(&iter, __iov);
    else
        iov = BPF_CORE_READ(&iter, iov);

    if (!iov) return 0;

    void *base;
    __u64 len;
    base = BPF_CORE_READ(iov, iov_base);
    len  = BPF_CORE_READ(iov, iov_len);
    if (len > MAX_PAYLOAD) len = MAX_PAYLOAD;
    if (len == 0) return 0;

    // Read user/kernel memory into our scratch buffer.
    long n = bpf_probe_read(&e->payload, (u32)len, base);
    if (n < 0) {
        // Try kernel-mem variant — for some recv paths the iov is in kernel space.
        n = bpf_probe_read_kernel(&e->payload, (u32)len, base);
        if (n < 0) return 0;
    }
    e->payload_len = (u16)len;

    // Hand a copy off to the ringbuf.
    // bpf_ringbuf_output avoids __builtin_memcpy of a large struct (clang-11 BPF limitation).
    bpf_ringbuf_output(&events, e, sizeof(*e), 0);
    return 0;
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(udp_sendmsg_entry, struct sock *sk, struct msghdr *msg)
{
    return handle(sk, msg, DIR_SEND);
}

SEC("fentry/udp_recvmsg")
int BPF_PROG(udp_recvmsg_entry, struct sock *sk, struct msghdr *msg)
{
    return handle(sk, msg, DIR_RECV);
}

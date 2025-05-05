#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "conn_info.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct whitelist_key);
    __type(value, __u32);
    __uint(max_entries, MAX_WHITELIST);
} whitelist SEC(".maps");

SEC("kprobe/tcp_connect")
int BPF_KPROBE(handle_tcp_connect, struct sock *sk) {
    if (!sk)
        return 0;

    struct conn_info *info;
    __u16 dport;

    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    dport = __builtin_bswap16(dport); // convert from network to host byte order


    info = bpf_ringbuf_reserve(&events, sizeof(*info), 0);
    if (!info)
        return 0;

    info->pid = bpf_get_current_pid_tgid() >> 32;
    info->dport = dport;
    bpf_get_current_comm(info->comm, sizeof(info->comm));

    bpf_ringbuf_submit(info, 0);
    return 0;
}

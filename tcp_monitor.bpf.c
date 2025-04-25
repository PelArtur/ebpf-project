// tcp_monitor.bpf.c

#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_core_read.h"
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

struct conn_info 
{
    __u32 pid;
    __u16 dport;
};


struct 
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");


SEC("kprobe/tcp_connect")
int BPF_KPROBE(handle_tcp_connect, struct sock *sk) {
    struct conn_info *info;

    if (!sk)
        return 0;

    __u16 dport;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    info = bpf_ringbuf_reserve(&events, sizeof(*info), 0);
    if (!info) return 0;

    info->pid = pid;
    info->dport = bpf_ntohs(dport);

    bpf_ringbuf_submit(info, 0);
    return 0;
}

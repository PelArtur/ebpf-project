/* Force complete definition of struct pt_regs for BPF.
   If not targeting aarch64, use the x86 version.
*/
#ifndef __aarch64__
struct pt_regs {
    unsigned long di;
    /* Optionally add additional members if needed */
};
#else
struct pt_regs {
    unsigned long regs[31];
    /* Optionally add additional members if needed */
};
#endif

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>  // for __u32 and __u64

typedef __u32 u32;
typedef __u64 u64;

#if defined(__aarch64__)
static __always_inline u64 PT_REGS_PARM1(struct pt_regs *ctx)
{
    return ctx->regs[0];
}
#else  // For x86 or other architectures
static __always_inline u64 PT_REGS_PARM1(struct pt_regs *ctx)
{
    return ctx->di;
}
#endif

/* Minimal definitions for struct sock */
struct sock_common {
    u32 skc_bound_dev_if;
};

struct sock {
    struct sock_common __sk_common;
    /* Additional fields omitted */
};

#define ETH0_IFINDEX 3

SEC("kprobe/tcp_v4_connect")
int kprobe_tcp_v4_connect(struct pt_regs *ctx)
{
    /* Use the inline function to get the first function parameter */
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u32 bound_ifindex = 0;

    /* Read the interface index */
    bpf_probe_read_kernel(&bound_ifindex, sizeof(bound_ifindex),
                          &sk->__sk_common.skc_bound_dev_if);

    if (bound_ifindex == ETH0_IFINDEX) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        bpf_printk("PID %d connecting on eth0\n", pid);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";


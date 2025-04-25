#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_hello(struct xdp_md *ctx) {
    static const char fmt[] = "yo";
    bpf_trace_printk(fmt, 3);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";


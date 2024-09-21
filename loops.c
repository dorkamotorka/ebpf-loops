//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    int counter = 0;

    // While loop
    while (counter < 10) {
        counter++;
    }

    bpf_printk("Counted %dx times", counter);

    return XDP_PASS;
}

SEC("xdp")
int xdp_prog_for_loop_unroll(struct xdp_md *ctx) {
    int counter = 0;

    // Standard for loop with unroll directive
    #pragma clang loop unroll(full)
    for (int i = 0; i < 10; i++) {
        counter++;
    }

    bpf_printk("Counted %dx times", counter);

    return XDP_PASS;
}

SEC("xdp")
int xdp_prog_for_loop(struct xdp_md *ctx) {
    int counter = 0;

    // Standard for loop, iterating 10 times
    for (int i = 0; i < 10; i++) {
        counter++;
    }

    bpf_printk("Counted %dx times", counter);

    return XDP_PASS;
}

static long (* const bpf_loop)(__u32 nr_loops, void *callback_fn, void *callback_ctx, __u64 flags) = (void *) 181;

// Define the callback function for bpf_loop
static int increment_counter(void *ctx, int *counter) {
    (*counter)++;
    return 0;
}

SEC("xdp")
int xdp_prog_bpf_loop_callback(struct xdp_md *ctx) {
    int counter = 0;

    // Use bpf_loop with the callback function
    bpf_loop(10, increment_counter, &counter, 0);

    bpf_printk("Counted %dx times", counter);

    return XDP_PASS;
}

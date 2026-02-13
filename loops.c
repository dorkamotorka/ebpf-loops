//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define NUM_LOOPS 100

/* loop with unroll directive*/
SEC("tracepoint/syscalls/sys_enter_execve")
int loop_unroll(struct trace_event_raw_sys_enter *ctx) {
    int counter = 0;

    // Standard for loop with unroll directive
#pragma clang loop unroll(full)
    for (int i = 0; i < NUM_LOOPS; i++) {
    	counter++;
    	bpf_printk("Counting in loop_unroll...");
    }

    bpf_printk("Counted %dx times", counter);
    return 0;
}

/* bounded loop */
SEC("tracepoint/syscalls/sys_enter_execve")
int bounded_loop(struct trace_event_raw_sys_enter *ctx) {
    int counter = 0;

    // Standard for loop, iterating NUM_LOOPS times
    for (int i = 0; i < NUM_LOOPS; i++) {
	counter++;
	bpf_printk("Counting in bounded_loop...");
    }

    bpf_printk("Counted %dx times", counter);
    return 0;
}

/* while loop */
SEC("tracepoint/syscalls/sys_enter_execve")
int while_loop(struct trace_event_raw_sys_enter *ctx) {
    int counter = 0;

    // While loop
    while (counter < NUM_LOOPS) {
    	counter++;
    	bpf_printk("Counting in while loop...");
    }

    bpf_printk("Counted %dx times", counter);
    return 0;
}

/* bpf_loop helper function */
// Define the callback function for bpf_loop
static int increment_counter(void *ctx, int *counter) {
    (*counter)++;
    bpf_printk("Counting in bpf_loop_callback...");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_loop_callback(struct trace_event_raw_sys_enter *ctx) {
    int counter = 0;

    // Use bpf_loop with the callback function
    bpf_loop(NUM_LOOPS, increment_counter, &counter, 0);

    bpf_printk("Counted %dx times", counter);
    return 0;
}

/* bpf_for helper function */
extern int bpf_iter_num_new(struct bpf_iter_num *it, int start, int end) __weak __ksym;
extern int *bpf_iter_num_next(struct bpf_iter_num *it) __weak __ksym;
extern void bpf_iter_num_destroy(struct bpf_iter_num *it) __weak __ksym;
#ifndef bpf_for
/* bpf_for(i, start, end) implements a for()-like looping construct that sets
 * provided integer variable *i* to values starting from *start* through,
 * but not including, *end*. It also proves to BPF verifier that *i* belongs
 * to range [start, end), so this can be used for accessing arrays without
 * extra checks.
 *
 * Note: *start* and *end* are assumed to be expressions with no side effects
 * and whose values do not change throughout bpf_for() loop execution. They do
 * not have to be statically known or constant, though.
 *
 * Note: similarly to bpf_for_each(), it relies on C99 feature of declaring
 * for() loop bound variables and cleanup attribute, supported by GCC and Clang.
 */
#define bpf_for(i, start, end)                                                                                                                                                                                          \
  for (/* initialize and define destructor */                                                                                                                                                                           \
       struct bpf_iter_num ___it __attribute__((                                                                                                                                                                        \
           aligned(8),                      /* enforce, just in case */                                                                                                                                                 \
           cleanup(bpf_iter_num_destroy))), /* ___p pointer is necessary to                                                                                                                                             \
                                               call bpf_iter_num_new() *once*                                                                                                                                           \
                                               to init ___it */                                                                                                                                                         \
       *___p                                                                                                                                                                                                            \
       __attribute__((unused)) = (bpf_iter_num_new(&___it, (start), (end)), /* this is a workaround for Clang bug: it currently doesn't emit BTF */ /* for bpf_iter_num_destroy() when used from cleanup() attribute */ \
                                  (void)bpf_iter_num_destroy, (void *)0);                                                                                                                                               \
       ({                                                                                                                                                                                                               \
         /* iteration step */                                                                                                                                                                                           \
         int *___t = bpf_iter_num_next(&___it);                                                                                                                                                                         \
         /* termination and bounds check */                                                                                                                                                                             \
         (___t && ((i) = *___t, (i) >= (start) && (i) < (end)));                                                                                                                                                        \
       });)
#endif /* bpf_for */

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_for_helper(struct trace_event_raw_sys_enter *ctx) {
    int counter = 0;

    // Use bpf_for helper
    bpf_for(counter, 0, NUM_LOOPS) {
    	counter++;
    	bpf_printk("Counting in bpf_for helper...");
    }

    bpf_printk("Counted %dx times", counter);
    return 0;
}

/* bpf_repeat helper function */
#ifndef bpf_repeat
/* bpf_repeat(N) performs N iterations without exposing iteration number
 *
 * Note: similarly to bpf_for_each(), it relies on C99 feature of declaring
 * for() loop bound variables and cleanup attribute, supported by GCC and Clang.
 */
#define bpf_repeat(N)                                                          \
  for (									\
	/* initialize and define destructor */							\
	struct bpf_iter_num ___it __attribute__((aligned(8), /* enforce, just in case */	\
						 cleanup(bpf_iter_num_destroy))),		\
	/* ___p pointer is necessary to call bpf_iter_num_new() *once* to init ___it */		\
			    *___p __attribute__((unused)) = (					\
				bpf_iter_num_new(&___it, 0, (N)),				\
	/* this is a workaround for Clang bug: it currently doesn't emit BTF */			\
	/* for bpf_iter_num_destroy() when used from cleanup() attribute */			\
				(void)bpf_iter_num_destroy, (void *)0);				\
	bpf_iter_num_next(&___it);								\
	/* nothing here  */									\
)
#endif /* bpf_repeat */

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_repeat_helper(struct trace_event_raw_sys_enter *ctx) {
    int counter = 0;

    bpf_repeat(NUM_LOOPS) {
    	counter++;
    	bpf_printk("Counting in bpf_repeat_helper...");
    }

    bpf_printk("Counted %dx times", counter);
    return 0;
}

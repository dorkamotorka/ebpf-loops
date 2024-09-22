# eBPF Loops

Loops are a common concept in almost every programming language, but in eBPF they can be a bit more complicated. 

Not to mention, there are 6+ different ways to loop. To count a few:

- For loop with `#pragma unroll` directive
- Bounded loops
- `bpf_loop` helper function
- Numeric open coded iterators that enable `bpf_for` and `bpf_repeat` helper functions
- `bpf_for_each_map_elem` Map iteration helper

So which one should you use?

## How to Run

https://github.com/user-attachments/assets/340bcd57-d995-497f-aecc-fc4d23b83722

**NOTE**: In other to be able to run this, at minimum kernel `6.4` version is needed, since this is when Numeric open coded iterators were introduced.

First build and run the eBPF program:
```
go generate
go build
sudo ./loop
```

Since there are numerous ways to loop, you can choose one by uncommenting the corresponding line in the `main.go`. 

You can then inspect eBPF logs using `sudo cat /sys/kernel/debug/tracing/trace_pipe` or `sudo bpftool prog trace` and verify the loops indeed were succesfuly attached onto XDP hook and do the counting.

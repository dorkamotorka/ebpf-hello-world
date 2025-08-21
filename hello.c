//go:build ignore

// `vmlinux.h` is explained in the tutorial
#include "vmlinux.h"

// bpf_helpers.h headers is included from libbpf library (https://github.com/libbpf/libbpf/blob/master/src/bpf_helpers.h)
// and imports some useful helpers like SEC(), bpf_printk() and so on
#include <bpf/bpf_helpers.h>

// You need this line in your eBPF program whenever it calls kernel helpers that are marked GPL-only, such as bpf_probe_read* or bpf_trace_printk
// In other words, almost always. 
// If you need to be certain for your target kernel, refer to the kernel source - where each helper’s bpf_func_proto struct defines the gpl_only flag, 
// indicating whether the helper is restricted to GPL-compatible eBPF programs. 
// (e.g. https://codebrowser.dev/linux/linux/kernel/trace/bpf_trace.c.html?utm_source=chatgpt.com#bpf_trace_printk_proto)
char _license[] SEC("license") = "GPL";

// SEC() places the following function into the ELF section that libbpf interprets as a tracepoint program 
// attached to syscalls:sys_enter_execve. That tells the loader what program type/attach point to use.
//
// This is also the eBPF program entry point. 
// The parameter type matches the tracepoint context (from vmlinux.h) so you can read (kernel) arguments if needed.
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_tp(struct trace_event_raw_sys_enter *ctx) {
    // Prints to the kernel trace buffer (view with `sudo bpftool prog trace`). 
    // Useful for debugging but should be avoided in production deployment as it creates unnecessary overhead.
    bpf_printk("Hello world");

    // This type of eBPF (Tracepoint) program typically return 0.
    // But in general the return value is ignored in this case as it is not meant to alter syscall behavior)
    return 0;
}


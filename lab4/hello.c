// go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

#define MAX_PATH 256

struct path_key {
    char path[MAX_PATH];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct path_key);
    __type(value, __u64);
} exec_count SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_tp(struct trace_event_raw_sys_enter *ctx) {
    const char *filename = (const char *)ctx->args[0];

    struct path_key key = {};
    long n = bpf_probe_read_user_str(key.path, sizeof(key.path), filename);
    if (n <= 0) {
        return 0; // couldn't read the path
    }

    __u64 *val = bpf_map_lookup_elem(&exec_count, &key);
    // Step 1: Update this such that the value under the key is updated safely
    // (avoiding race conditions)
    if (val) {
        *val += 1;
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&exec_count, &key, &init, BPF_NOEXIST);
    }

    bpf_printk("execve: %s\n", key.path);

    return 0;
}

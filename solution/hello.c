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
    if (!val) {
        // Initialize counter to zero if the binary is executed for the first
        // time Avoid race, since:
        // * Two CPUs can both see !val (non-existing key), then both try to
        // insert
        // * CPU A succeeds, CPU B fails (BPF_NOEXIST rejects).
        //
        // NOTE: BPF_NOEXIST flag only creates the entry if the key doesn't
        // exist yet
        __u64 zero = 0;
        bpf_map_update_elem(&exec_count, &key, &zero, BPF_NOEXIST);

        // Sanity check since bpf_map_lookup_elem can return NULL if the eBPF
        // map is full NOTE: Ideally we would also report the error here to the
        // developer
        val = bpf_map_lookup_elem(&exec_count, &key);
        if (!val)
            return 0;
    }

    // Atomic increment of the value in the eBPF map
    __sync_fetch_and_add(val, 1);

    bpf_printk("execve: %s\n", key.path);

    return 0;
}

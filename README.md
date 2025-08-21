# eBPF Hello World Example

Every eBPF application usually consists out of at least two parts:

- A user-space program (USP) that declares the kernel space program and attaches it to the relevant tracepoint/probe. -> In this case this is `main.go`.
- A kernel-space program (KSP) is what gets triggered and runs inside the kernel once the tracepoint/probe is met. This is where the actual eBPF logic is implemented. -> In this case this is `hello.c`.

## Install dependencies

To install eBPF dependencies, run:
```bash
sudo apt install llvm clang libbpf-dev 
```

To add `ebpf-go` as a dependency to an existing Go module, run this from within the module's directory:
```bash
go get github.com/cilium/ebpf
```

## Compile & Run

[bpf2go](https://pkg.go.dev/github.com/cilium/ebpf/cmd/bpf2go) makes it extremely easy to compile and run eBPF program. You just have to run:
```bash
go build
go generate
sudo ./hello
```

By running random commands in another terminal, you should be able to see `Hello World` logs under `sudo bpftool prog trace` command.

## Additional Notes

By default, `bpf2go` internally uses `clang` with some helpful default flags. Among them are:

- `-g`: Includes debug information, which is necessary for BTF.

- `-strip llvm-strip`: Uses `llvm-strip` binary to reduce the size of the object file, as the `-g` flag adds DWARF debugging information that isn’t needed by eBPF programs.

- `-O2`: Ensures Clang produces BPF bytecode that passes the verifier. For example, Clang would normally output `callx <register>` for calling helper functions, but eBPF doesn’t support calling addresses from registers.

- `-target bpf`: Specifies the system the program is intended to run on (little-endian or big-endian). By default set to `bpf`, following the endianness of the CPU they’re compiled on.

## What is vmlinux.h?

`vmlinux.h` is a kernel header file, providing access to kernel structures and definitions for eBPF programs.

It was generated using:
```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

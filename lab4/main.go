package main

// The following line is explained in the tutorial
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf hello hello.c

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// By default (for Linux < 5.11), Linux sets a RLIMIT_MEMLOCK (memory lock limit) that restricts how much memory a process can lock into RAM.
	// eBPF maps and programs use pinned memory that counts against this limit.
	// If you don’t raise or remove the limit, loading larger eBPF programs or maps will fail with errors like “operation not permitted” or “memory locked limit exceeded.”
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF into the kernel.
	// These helpers are defined in the generated `hello_bpf.go` file that embeeds the eBPF ELF object file (`hello_bpf.o`)
	var objs helloObjects
	// For printing eBPF verifier logs
	// Ref: https://pkg.go.dev/github.com/cilium/ebpf#ProgramOptions
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     2,       // 1 = basic, 2 = verbose
			LogSizeStart: 1 << 20, // 1MB buffer to avoid truncation
		},
	}
	if err := loadHelloObjects(&objs, opts); err != nil {
		// If verification fails, ebpf-go returns a VerifierError that includes the log.
		// Print it for easier debugging:
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Printf("Verifier error: %+v\n", ve)
		}
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	// Attach the loaded eBPF program to the eBPF Tracepoint Hook point
	// The `objs.HandleExecveTp` variable names, follow to function name in our eBPF kernel program
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecveTp, nil)
	if err != nil {
		log.Fatalf("Attaching Tracepoint: %s", err)
	}
	defer tp.Close()

	log.Println("eBPF program attached to tracepoint. Press Ctrl+C to exit.")

	// Wait for SIGINT/SIGTERM (Ctrl+C) before exiting
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()
	log.Println("Received signal, exiting...")
}

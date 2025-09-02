package main

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
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

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
		// Print it for easier debugging
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Printf("Verifier error: %+v\n", ve)
		}
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecveTp, nil)
	if err != nil {
		log.Fatalf("Attaching Tracepoint: %s", err)
	}
	defer tp.Close()

	log.Println("eBPF program attached to tracepoint. Press Ctrl+C to exit.")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()
	log.Println("Received signal, exiting...")
}

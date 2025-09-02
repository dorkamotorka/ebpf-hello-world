package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf hello hello.c

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	var objs helloObjects
	if err := loadHelloObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.Challenge, nil)
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

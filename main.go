package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf loops loops.c

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
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs loopsObjects
	if err := loadLoopsObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	/*
	// This way you can print number of eBPF instructions
	// Check also: https://github.com/cilium/cilium/blob/main/test/verifier/verifier_test.go#L214-L265
	info, err := objs.XdpProgForLoopUnroll.Info()
	if err != nil {
		log.Fatalf("Failed to get eBPF Program info: %s", err)
	}
	insn, err := info.Instructions()
	if err != nil {
		log.Fatalf("Failed to get Instructions: %s", err)
	}
	log.Printf("Number of instructions in the eBPF Program: %d", len(insn))
	*/

	// Attach Tracepoint
	tp, err := link.Tracepoint(
		"syscalls", 
		"sys_enter_execve", 
		//LoopUnroll,
		objs.BoundedLoop, 
 		//WhileLoop,
		//objs.BpfForHelper,
		//objs.BpfLoopCallback,
		//BpfRepeatHelper,
		nil,
	)
	if err != nil {
		log.Fatalf("Attaching Tracepoint: %s", err)
	}
	defer tp.Close()
	log.Printf("Successfully attached eBPF Tracepoint...")

	// Wait for SIGINT/SIGTERM (Ctrl+C) before exiting
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()
	log.Println("Received signal, exiting...")
}

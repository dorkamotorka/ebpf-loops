package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go loops loops.c

import (
	"flag"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	var ifname string
	flag.StringVar(&ifname, "i", "enp5s0", "Network interface name where the eBPF program will be attached")
	flag.Parse()

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

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Attach XDP program to the network interface.
	xdplink, err := link.AttachXDP(link.XDPOptions{
		Program: objs.XdpProgForLoopUnroll,
		//Program:   objs.XdpProgForLoop,
		//Program:   objs.XdpProgWhileLoop,
		//Program:   objs.XdpProgBpfLoopCallback,
		//Program:   objs.XdpProgBpfForHelper,
		//Program:   objs.XdpProgBpfRepeatHelper,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer xdplink.Close()

	for {
		time.Sleep(time.Second * 1)
	}
}

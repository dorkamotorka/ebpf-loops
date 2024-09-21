package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go loops loops.c

import (
	"log"
	"net"
	"flag"
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

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Attach XDP program to the network interface.
	xdplink, err := link.AttachXDP(link.XDPOptions{
			//Program:   objs.XdpProg,
			//Program:   objs.XdpProgForLoop,
			//Program:   objs.XdpProgForLoopUnroll,
			//Program:   objs.XdpProgBpfLoopCallback,
			//Program:   objs.XdpProgBpfForHelper,
			Program:   objs.XdpProgBpfRepeatHelper,
			Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer xdplink.Close()

	for { time.Sleep(time.Second * 1) }
}

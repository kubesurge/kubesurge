//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	internalebpf "github.com/kubesurge/kubesurge/internal/ebpf"
)

type bpfEvent struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
	Proto   uint8
}

var globalHeaderWritten = false

func getNetnsCookie() (uint64, error) {
	linkStr, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return 0, err
	}
	// Parse net:[12345] -> 12345
	re := regexp.MustCompile(`\d+`)
	match := re.FindString(linkStr)
	if match == "" {
		return 0, fmt.Errorf("failed to parse netns cookie from link: %s", linkStr)
	}
	return strconv.ParseUint(match, 10, 64)
}

func runAgent(sigChan chan os.Signal) {
	// 1. Remove memory lock limit for BPF maps loading
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "  ⚠️ Failed to remove memlock: %v\n", err)
	}

	// 2. Load tracer specs
	spec, err := internalebpf.LoadTracer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ⚠️ Failed to load eBPF tracer specs: %v\n", err)
		return
	}

	// 3. Namespace Isolation: fetch netns cookie and rewrite constant target_netns
	cookie, err := getNetnsCookie()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ⚠️ Failed to retrieve current namespace cookie: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "  ✓ Target network namespace cookie identified: %d\n", cookie)
		if varSpec, ok := spec.Variables["target_netns"]; ok {
			if err := varSpec.Set(cookie); err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠️ Failed to set target_netns constant: %v\n", err)
			}
		} else {
			fmt.Fprintln(os.Stderr, "  ⚠️ Global variable target_netns not found in BPF spec")
		}
	}

	// 4. Load objects with overwritten constants
	objs := internalebpf.TracerObjects{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		fmt.Fprintf(os.Stderr, "  ⚠️ Failed to load eBPF tracer collection: %v\n", err)
		return
	}
	defer objs.Close()

	// 5. Attach kprobe to tcp_v4_connect
	kp, err := link.Kprobe("tcp_v4_connect", objs.KprobeTcpV4Connect, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ⚠️ Failed to attach tcp_v4_connect kprobe: %v\n", err)
		return
	}
	defer kp.Close()

	fmt.Fprintln(os.Stderr, "  ✓ eBPF socket tracer kprobes attached successfully")

	// 6. Open perf/ringbuf reader
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ⚠️ Failed to open ring buffer reader: %v\n", err)
		return
	}
	defer rd.Close()

	// Handle graceful termination signal in a separate goroutine
	go func() {
		<-sigChan
		fmt.Fprintln(os.Stderr, "👋 Stopping eBPF Socket Tracing Agent...")
		rd.Close()
	}()

	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			fmt.Fprintf(os.Stderr, "  ⚠️ Error reading event record: %v\n", err)
			continue
		}

		// Decode the binary event struct from kernel ring buffer
		buf := bytes.NewReader(record.RawSample)
		if err := binary.Read(buf, binary.BigEndian, &event.SrcIP); err != nil {
			continue
		}
		if err := binary.Read(buf, binary.BigEndian, &event.DstIP); err != nil {
			continue
		}
		if err := binary.Read(buf, binary.BigEndian, &event.SrcPort); err != nil {
			continue
		}
		if err := binary.Read(buf, binary.BigEndian, &event.DstPort); err != nil {
			continue
		}
		if err := binary.Read(buf, binary.BigEndian, &event.Proto); err != nil {
			continue
		}

		// Stream as standard PCAP bytes over Stdout
		writePcapEvent(event)
	}
}

func writePcapEvent(ev bpfEvent) {
	if !globalHeaderWritten {
		// PCAP Global Header (24 bytes)
		header := []byte{
			0xd4, 0xc3, 0xb2, 0xa1, // Magic
			0x02, 0x00, 0x04, 0x00, // Version
			0x00, 0x00, 0x00, 0x00, // GMT to local
			0x00, 0x00, 0x00, 0x00, // accuracy of timestamps
			0xff, 0xff, 0x00, 0x00, // max length of captured packets
			0x01, 0x00, 0x00, 0x00, // data link type (1 = Ethernet)
		}
		_, _ = os.Stdout.Write(header)
		globalHeaderWritten = true
	}

	// Ethernet (14) + IPv4 (20) + TCP (20) = 54 bytes
	packetData := make([]byte, 54)
	packetData[12] = 0x08 // IPv4 ethertype
	packetData[13] = 0x00

	packetData[14] = 0x45 // IPv4 header details
	packetData[14+9] = ev.Proto

	// Src & Dst IPs
	binary.BigEndian.PutUint32(packetData[14+12:14+16], ev.SrcIP)
	binary.BigEndian.PutUint32(packetData[14+16:14+20], ev.DstIP)

	// Src & Dst Ports
	binary.BigEndian.PutUint16(packetData[14+20:14+22], ev.SrcPort)
	binary.BigEndian.PutUint16(packetData[14+22:14+24], ev.DstPort)

	// Packet Header (16 bytes)
	now := time.Now()
	sec := uint32(now.Unix())
	usec := uint32(now.UnixNano()/1000) % 1000000

	headerBuf := make([]byte, 16)
	binary.LittleEndian.PutUint32(headerBuf[0:4], sec)
	binary.LittleEndian.PutUint32(headerBuf[4:8], usec)
	binary.LittleEndian.PutUint32(headerBuf[8:12], 54)
	binary.LittleEndian.PutUint32(headerBuf[12:16], 54)

	_, _ = os.Stdout.Write(headerBuf)
	_, _ = os.Stdout.Write(packetData)
	_ = os.Stdout.Sync()
}

//go:build !linux

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"
)

var globalHeaderWritten = false

func runAgent(sigChan chan os.Signal) {
	fmt.Fprintln(os.Stderr, "  ⚠️ eBPF is only supported on Linux kernel hosts.")
	fmt.Fprintln(os.Stderr, "  [Running in Development Mock eBPF Tracer mode...]")

	ticker := time.NewTicker(1000 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-sigChan:
			fmt.Fprintln(os.Stderr, "👋 Stopping mock eBPF Socket Tracing Agent...")
			return
		case <-ticker.C:
			// Stream mock trace data
			writeMockPcapPacket()
		}
	}
}

func writeMockPcapPacket() {
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

	// Mock Ethernet (14) + IPv4 (20) + TCP (20) = 54 bytes
	packetData := make([]byte, 54)
	packetData[12] = 0x08 // IPv4
	packetData[13] = 0x00
	packetData[14] = 0x45 // Version/IHL
	packetData[14+9] = 6  // TCP
	copy(packetData[14+12:14+16], []byte{10, 244, 0, 87})
	copy(packetData[14+16:14+20], []byte{10, 244, 0, 1})

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

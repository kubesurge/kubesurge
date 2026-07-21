package sink

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// PcapStats represents live telemetry captured from a stream.
type PcapStats struct {
	TotalPackets int
	TotalBytes   int64
	IPv4Count    int
	IPv6Count    int
	TCPCount     int
	UDPCount     int
	ICMPCount    int
	DNSCount     int
	HTTPCount    int
	TopTalkers   map[string]int
}

// PcapParser reads a raw PCAP stream and decodes packet headers on the fly.
type PcapParser struct {
	reader     io.Reader
	Stats      PcapStats
	OtlpClient *OtlpClient
}

// NewPcapParser creates a new PCAP parser wrapping an io.Reader.
func NewPcapParser(r io.Reader) *PcapParser {
	return &PcapParser{
		reader: r,
		Stats: PcapStats{
			TopTalkers: make(map[string]int),
		},
	}
}

// Parse loops and parses packets from the reader until EOF or error.
func (p *PcapParser) Parse(packetChan chan<- PcapStats) error {
	defer close(packetChan)

	// 1. Read Global Header (24 bytes)
	globalHeader := make([]byte, 24)
	if _, err := io.ReadFull(p.reader, globalHeader); err != nil {
		return err
	}

	magic := binary.LittleEndian.Uint32(globalHeader[0:4])
	var isLittleEndian bool

	switch magic {
	case 0xa1b2c3d4:
		isLittleEndian = true
	case 0xd4c3b2a1:
		isLittleEndian = false
	case 0xa1b23c4d:
		isLittleEndian = true
	case 0x4d3cb2a1:
		isLittleEndian = false
	default:
		isLittleEndian = true
	}

	linkType := binary.LittleEndian.Uint32(globalHeader[20:24])
	if !isLittleEndian {
		linkType = binary.BigEndian.Uint32(globalHeader[20:24])
	}

	fmt.Printf("  [PCAP Parser: magic=0x%x, linkType=%d, littleEndian=%v]\n", magic, linkType, isLittleEndian)

	headerBuf := make([]byte, 16)

	for {
		// Read packet header (16 bytes)
		if _, err := io.ReadFull(p.reader, headerBuf); err != nil {
			return err
		}

		var inclLen uint32
		if isLittleEndian {
			inclLen = binary.LittleEndian.Uint32(headerBuf[8:12])
		} else {
			inclLen = binary.BigEndian.Uint32(headerBuf[8:12])
		}

		// Read packet payload
		payload := make([]byte, inclLen)
		if _, err := io.ReadFull(p.reader, payload); err != nil {
			return err
		}

		p.Stats.TotalPackets++
		p.Stats.TotalBytes += int64(inclLen)

		// Parse network layer details
		p.parsePacket(payload, linkType)

		// Non-blocking send of update stats
		select {
		case packetChan <- p.Stats:
		default:
		}
	}
}

// parsePacket inspects the link type layer and decodes protocols and talkers.
func (p *PcapParser) parsePacket(payload []byte, linkType uint32) {
	var networkPayload []byte
	var etherType uint16

	switch linkType {
	case 1: // Ethernet (LINKTYPE_ETHERNET)
		if len(payload) < 14 {
			return
		}
		etherType = binary.BigEndian.Uint16(payload[12:14])
		networkPayload = payload[14:]

	case 276: // Linux Cooked v2 (LINKTYPE_LINUX_SLL2)
		if len(payload) < 20 {
			return
		}
		etherType = binary.BigEndian.Uint16(payload[18:20])
		networkPayload = payload[20:]

	default:
		// Unknown link type, skip decoding addresses but increment raw packet/bytes
		return
	}

	switch etherType {
	case 0x0800: // IPv4
		p.Stats.IPv4Count++
		if len(networkPayload) < 20 {
			return
		}
		proto := networkPayload[9]
		srcIP := net.IP(networkPayload[12:16]).String()
		dstIP := net.IP(networkPayload[16:20]).String()

		talker := fmt.Sprintf("%s ⇄ %s", srcIP, dstIP)
		p.Stats.TopTalkers[talker]++

		protoName := "UNKNOWN"
		switch proto {
		case 6: // TCP
			p.Stats.TCPCount++
			p.parseTCP(networkPayload[20:])
			protoName = "TCP"
		case 17: // UDP
			p.Stats.UDPCount++
			p.parseUDP(networkPayload[20:])
			protoName = "UDP"
		case 1: // ICMP
			p.Stats.ICMPCount++
			protoName = "ICMP"
		}

		if p.OtlpClient != nil {
			go func(sip, dip, prt string, sz int64) {
				_ = p.OtlpClient.ExportFlow(context.Background(), sip, dip, prt, sz)
			}(srcIP, dstIP, protoName, int64(len(payload)))
		}

	case 0x86dd: // IPv6
		p.Stats.IPv6Count++
		if len(networkPayload) < 40 {
			return
		}
		proto := networkPayload[6]
		srcIP := net.IP(networkPayload[8:24]).String()
		dstIP := net.IP(networkPayload[24:40]).String()

		talker := fmt.Sprintf("%s ⇄ %s", srcIP, dstIP)
		p.Stats.TopTalkers[talker]++

		protoName := "UNKNOWN"
		switch proto {
		case 6: // TCP
			p.Stats.TCPCount++
			protoName = "TCP"
		case 17: // UDP
			p.Stats.UDPCount++
			protoName = "UDP"
		case 58: // ICMPv6
			p.Stats.ICMPCount++
			protoName = "ICMPv6"
		}

		if p.OtlpClient != nil {
			go func(sip, dip, prt string, sz int64) {
				_ = p.OtlpClient.ExportFlow(context.Background(), sip, dip, prt, sz)
			}(srcIP, dstIP, protoName, int64(len(payload)))
		}
	}
}

func (p *PcapParser) parseTCP(tcpPayload []byte) {
	if len(tcpPayload) < 4 {
		return
	}
	srcPort := binary.BigEndian.Uint16(tcpPayload[0:2])
	dstPort := binary.BigEndian.Uint16(tcpPayload[2:4])

	if srcPort == 53 || dstPort == 53 {
		p.Stats.DNSCount++
	} else if srcPort == 80 || dstPort == 80 || srcPort == 8080 || dstPort == 8080 {
		p.Stats.HTTPCount++
	}
}

func (p *PcapParser) parseUDP(udpPayload []byte) {
	if len(udpPayload) < 4 {
		return
	}
	srcPort := binary.BigEndian.Uint16(udpPayload[0:2])
	dstPort := binary.BigEndian.Uint16(udpPayload[2:4])

	if srcPort == 53 || dstPort == 53 {
		p.Stats.DNSCount++
	}
}

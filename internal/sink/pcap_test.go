package sink

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestPcapParser(t *testing.T) {
	// Create a mock PCAP buffer: Global Header (24 bytes) + Packet Header (16 bytes) + Packet Data (Ethernet header + IPv4 TCP packet)
	var buf bytes.Buffer

	// 1. Global Header: Magic (0xa1b2c3d4 for little-endian on disk), major (2), minor (4), zone (0), sigfigs (0), snaplen (65535), network (1 = LINKTYPE_ETHERNET)
	binary.Write(&buf, binary.LittleEndian, uint32(0xa1b2c3d4))
	binary.Write(&buf, binary.LittleEndian, uint16(2))
	binary.Write(&buf, binary.LittleEndian, uint16(4))
	binary.Write(&buf, binary.LittleEndian, int32(0))
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	binary.Write(&buf, binary.LittleEndian, uint32(65535))
	binary.Write(&buf, binary.LittleEndian, uint32(1))

	// Packet Data: Ethernet header (14 bytes) + IPv4 header (20 bytes) + TCP header (20 bytes)
	// Ethernet: dst mac (6), src mac (6), ethertype (2 bytes = 0x0800 for IPv4)
	packetData := make([]byte, 14+20+20)
	packetData[12] = 0x08
	packetData[13] = 0x00

	// IPv4: version/IHL (0x45), Protocol (9th byte = 6 for TCP), src IP (12-15 = 10.0.0.1), dst IP (16-19 = 192.168.1.1)
	packetData[14] = 0x45
	packetData[14+9] = 6 // TCP
	copy(packetData[14+12:14+16], []byte{10, 0, 0, 1})
	copy(packetData[14+16:14+20], []byte{192, 168, 1, 1})

	// TCP: src port (80), dst port (12345)
	binary.BigEndian.PutUint16(packetData[14+20:14+22], 80)
	binary.BigEndian.PutUint16(packetData[14+22:14+24], 12345)

	// 2. Packet Header: ts_sec (4), ts_usec (4), incl_len (4), orig_len (4)
	binary.Write(&buf, binary.LittleEndian, uint32(1672531199))
	binary.Write(&buf, binary.LittleEndian, uint32(123456))
	binary.Write(&buf, binary.LittleEndian, uint32(len(packetData)))
	binary.Write(&buf, binary.LittleEndian, uint32(len(packetData)))

	// Write payload
	buf.Write(packetData)

	parser := NewPcapParser(&buf)
	statsChan := make(chan PcapStats, 10)

	// We run Parse. Since it will block on the second packet (EOF), we expect Parse to return io.EOF (which is a success check).
	err := parser.Parse(statsChan)
	if err == nil {
		t.Fatal("expected error from parsing, got nil")
	}

	// Verify parser gathered correct statistics
	if parser.Stats.TotalPackets != 1 {
		t.Errorf("expected 1 total packet, got %d", parser.Stats.TotalPackets)
	}
	if parser.Stats.TCPCount != 1 {
		t.Errorf("expected 1 TCP packet, got %d", parser.Stats.TCPCount)
	}
	if parser.Stats.HTTPCount != 1 {
		t.Errorf("expected 1 HTTP/port-80 count, got %d", parser.Stats.HTTPCount)
	}
	if parser.Stats.TopTalkers["10.0.0.1 ⇄ 192.168.1.1"] != 1 {
		t.Errorf("expected 1 talker count for 10.0.0.1 ⇄ 192.168.1.1, got %v", parser.Stats.TopTalkers)
	}
}

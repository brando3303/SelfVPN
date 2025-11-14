package main

import (
    "fmt"
    "log"
    "encoding/binary"

    "github.com/songgao/water"
    "github.com/vishvananda/netlink"
)

type Ipv4Packet struct {
	Version        uint8  // always 4
	IHL            uint8  // header length in 32-bit words
	TOS            uint8
	TotalLength    uint16
	ID             uint16
	Flags          uint8  // 3 bits
	FragmentOffset uint16 // 13 bits
	TTL            uint8
	Protocol       uint8
	Checksum       uint16
	Src            [4]byte
	Dst            [4]byte

	Options []byte // only if IHL > 5
	Data    []byte // payload
}

func main() {
    // Step 1: Create a TUN interface
    cfg := water.Config{
        DeviceType: water.TUN,
    }
    cfg.Name = "tun0"

    iface, err := water.New(cfg)
    if err != nil {
        log.Fatalf("Failed to create TUN: %v", err)
    }
    fmt.Printf("Interface %s created\n", iface.Name())

    // Step 2: Configure it with netlink
    link, err := netlink.LinkByName(iface.Name())
    if err != nil {
        log.Fatalf("Could not find interface: %v", err)
    }

    // Assign IP address
    addr, _ := netlink.ParseAddr("10.0.0.1/24")
    if err := netlink.AddrAdd(link, addr); err != nil {
        log.Fatalf("Failed to add address: %v", err)
    }

    // Bring the interface up
    if err := netlink.LinkSetUp(link); err != nil {
        log.Fatalf("Failed to bring up interface: %v", err)
    }

    fmt.Printf("Interface %s configured with %s\n", iface.Name(), addr)

    // Step 3: Handle packets (for demo, just read and dump)
    packet := make([]byte, 1500)
    for {
        n, err := iface.Read(packet)
        if err != nil {
            log.Fatalf("Error reading from interface: %v", err)
        }
        parsed := parseIpv4(packet[:n])
        printIpv4(parsed)
    }
}

func Uint32ToIPv4(ip uint32) string {
	b1 := byte(ip >> 24)
	b2 := byte(ip >> 16)
	b3 := byte(ip >> 8)
	b4 := byte(ip)

	return fmt.Sprintf("%d.%d.%d.%d", b1, b2, b3, b4)
}

func getAddrs(packet []byte) (string, string) {
    // Dummy implementation for illustration
    return Uint32ToIPv4(binary.BigEndian.Uint32(packet[12:16])), Uint32ToIPv4(binary.BigEndian.Uint32(packet[16:20]))
}

func parseIpv4(packet []byte) *Ipv4Packet {
	if len(packet) < 20 {
		return nil // Not enough data for IPv4 header
	}

	ipv4 := &Ipv4Packet{}

	// First byte contains Version (4 bits) and IHL (4 bits)
	ipv4.Version = packet[0] >> 4
	ipv4.IHL = packet[0] & 0x0F

	ipv4.TOS = packet[1]
	ipv4.TotalLength = binary.BigEndian.Uint16(packet[2:4])
	ipv4.ID = binary.BigEndian.Uint16(packet[4:6])

	// Flags (3 bits) and Fragment Offset (13 bits) are in bytes 6-7
	flagsAndOffset := binary.BigEndian.Uint16(packet[6:8])
	ipv4.Flags = uint8(flagsAndOffset >> 13)
	ipv4.FragmentOffset = flagsAndOffset & 0x1FFF

	ipv4.TTL = packet[8]
	ipv4.Protocol = packet[9]
	ipv4.Checksum = binary.BigEndian.Uint16(packet[10:12])

	// Source and Destination IP addresses
	copy(ipv4.Src[:], packet[12:16])
	copy(ipv4.Dst[:], packet[16:20])

	// Calculate header length in bytes
	headerLen := int(ipv4.IHL) * 4

	// Extract options if IHL > 5 (header > 20 bytes)
	if ipv4.IHL > 5 && len(packet) >= headerLen {
		ipv4.Options = make([]byte, headerLen-20)
		copy(ipv4.Options, packet[20:headerLen])
	}

	// Extract payload data
	if len(packet) > headerLen {
		ipv4.Data = make([]byte, len(packet)-headerLen)
		copy(ipv4.Data, packet[headerLen:])
	}

	return ipv4
}

func printIpv4(ipv4 *Ipv4Packet) {
	if ipv4 == nil {
		fmt.Println("Invalid packet")
		return
	}

	fmt.Printf("Ver: %d | IHL: %d | TOS: %d | Len: %d | ID: %d | Flags: 0x%x | FragOff: %d | TTL: %d | Proto: %d | Chksum: 0x%04x | Src: %d.%d.%d.%d | Dst: %d.%d.%d.%d",
		ipv4.Version,
		ipv4.IHL,
		ipv4.TOS,
		ipv4.TotalLength,
		ipv4.ID,
		ipv4.Flags,
		ipv4.FragmentOffset,
		ipv4.TTL,
		ipv4.Protocol,
		ipv4.Checksum,
		ipv4.Src[0], ipv4.Src[1], ipv4.Src[2], ipv4.Src[3],
		ipv4.Dst[0], ipv4.Dst[1], ipv4.Dst[2], ipv4.Dst[3])

	if len(ipv4.Options) > 0 {
		fmt.Printf(" | Opts: %d bytes", len(ipv4.Options))
	}

	fmt.Println()
}


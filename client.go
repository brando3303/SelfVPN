package main

import (
    "fmt"
    "log"
    "net"
		"os"
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

func initTunnel(deviceName string, ipAddr string) (*water.Interface, error) {
    cfg := water.Config{
        DeviceType: water.TUN,
    }
    cfg.Name = deviceName

    iface, err := water.New(cfg)
    if err != nil {
        log.Printf("Failed to create TUN: %v", err)
        return nil, err
    }
    fmt.Printf("Interface %s created\n", iface.Name())

    // Step 2: Configure it with netlink
    link, err := netlink.LinkByName(iface.Name())
    if err != nil {
        log.Printf("Could not find interface: %v", err)
        return nil, err
    }

    // Assign IP address
    addr, _ := netlink.ParseAddr(ipAddr)
    if err := netlink.AddrAdd(link, addr); err != nil {
        log.Printf("Failed to add address: %v", err)
        return nil, err
    }

    // Bring the interface up
    if err := netlink.LinkSetUp(link); err != nil {
        log.Printf("Failed to bring up interface: %v", err)
        return nil, err
    }

    fmt.Printf("Interface %s configured with %s\n", iface.Name(), addr)

    return iface, nil
}

func SetupUDPConn(addr string) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve addr: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("dial udp: %w", err)
	}

	return conn, nil
}



func main() {

		args := os.Args[1:]
		if len(args) != 1 {
			fmt.Println("Usage: selfVPN <server_ip:port>")
			return
		}
		serverAddr := args[0]

    // Create tunnel interface : 
		// read from tunnel -> reqs from os/user-space (applications etc, the data that will be sent to the VPN)
		// write to tunnel -> send response to os
    iface, err := initTunnel("tun0", "10.0.0.1/24")
    if err != nil {
        log.Fatalf("Failed to initialize tunnel: %v", err)
    }

		conn, err := SetupUDPConn(serverAddr)
		if err != nil {
			log.Fatalf("Failed to set up UDP connection: %v", err)
		}
		defer conn.Close()

    // Step 3: Handle packets (for demo, just read and dump)
		go packetOutLoop(iface, conn)
		go packetInLoop(iface, conn)

}

func packetOutLoop(iface *water.Interface, conn *net.UDPConn) {
	packet := make([]byte, 1024)
  for {
		// read packet from TUN interface
    n, err := iface.Read(packet)
    if err != nil {
        log.Fatalf("Error reading from interface: %v", err)
    }
		// process and send packet to VPN server
		processOutPacket(packet[:n], conn)
		Printf("sent packet to VPN server: ")
    parsed := parseIpv4(packet[:n])
    printIpv4(parsed)
	}
}

// processOutPacket takes in the raw packet bytes recieved from the TUN interface,
// performs all processing steps (encryption, encapsulation), sends the packet to the VPN server,
// returns errors.
func processOutPacket(packet []byte, conn *net.UDPConn) ([]byte, error) {
	// for now just send the raw packet
	_, err := conn.Write(packet)
	return packet, err
}

func packetInLoop(iface *water.Interface, conn *net.UDPConn) {
	packet := make([]byte, 1024)
  for {
		// read packet from VPN server
		n, err := conn.Read(packet)
    if err != nil {
        log.Fatalf("Error reading from connection: %v", err)
    }
		// process and write packet to TUN interface
		processInPacket(packet[:n], iface)
		parsed := parseIpv4(packet[:n])
		Printf("recieved packet from VPN server: ")
		printIpv4(parsed)
	}
}

// processInPacket takes in the raw packet bytes recieved from the VPN server,
// performs all processing steps (decapsulation, decryption), writes the packet to the TUN interface,
// returns errors.
func processInPacket(packet []byte, iface *water.Interface) error {
	// for now just write the raw packet
	_, err := iface.Write(packet)
	return err
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


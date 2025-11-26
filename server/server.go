package server

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	//iptables "github.com/coreos/go-iptables/iptables"
)

type Ipv4Packet struct {
	Version        uint8 // always 4
	IHL            uint8 // header length in 32-bit words
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

// SetupTunAndRouting creates tun0, assigns IP, enables NAT and forwarding.
func SetupServerTunnel(tunName string, tunnel_interface_ip string, outboundIf string) (*water.Interface, error) {

	// ---------------------------
	// 1. Create TUN interface
	// ---------------------------
	cfg := water.Config{
		DeviceType: water.TUN,
	}
	cfg.Name = tunName

	tun, err := water.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create tun: %w", err)
	}

	// Get link reference for netlink ops
	link, err := netlink.LinkByName(tunName)
	if err != nil {
		return nil, fmt.Errorf("netlink cannot find tun: %w", err)
	}

	// 2. Assign IP and bring interface up (netlink)
	addr, err := netlink.ParseAddr(tunnel_interface_ip)
	if err != nil {
		return nil, fmt.Errorf("parse addr: %w", err)
	}

	if err := netlink.AddrAdd(link, addr); err != nil {
		return nil, fmt.Errorf("addr add: %w", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("link up: %w", err)
	}

	// 4. NAT via nftables
	c := &nftables.Conn{}

	// Get or create NAT table
	table := c.AddTable(&nftables.Table{
		Name:   "nat",
		Family: nftables.TableFamilyINet,
	})

	// Get or create POSTROUTING chain
	chain := c.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})

	// Add rule: masquerade outgoing on outboundIf
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// match output iface
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{
				Register: 1,
				Op:       expr.CmpOpEq,
				Data:     []byte(outboundIf + "\x00"),
			},
			// masquerade
			&expr.Masq{},
		},
	})

	if err := c.Flush(); err != nil {
		return nil, fmt.Errorf("nft flush: %w", err)
	}

	return tun, nil
}

// helper for ignoring "file exists" errors from netlink
func isExistsErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "file exists")
}

func SetupUDPConn(listenPort int) (*net.UDPConn, error) {
	addr := &net.UDPAddr{
		IP:   net.IPv4zero, // 0.0.0.0 — accept from any address
		Port: listenPort,
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen udp: %w", err)
	}
	defer conn.Close()

	fmt.Printf("Listening on UDP port %d...\n", listenPort)

	return conn, nil
}

// Run starts the VPN server
// args: listen_port, interface_cidr, outbound_interface
func Run(args []string) {
	if len(args) != 3 {
		fmt.Println("Usage: selfVPN server <listen_port> <interface_cidr> <outbound_interface>")
		return
	}
	listenPort, err := strconv.Atoi(args[0])
	if err != nil {
		log.Fatalf("Invalid listen port: %v", err)
	}
	interfaceCIDR := args[1]
	outboundIf := args[2]

	fmt.Printf("Starting selfVPN server\n")
	fmt.Printf("Listening on port: %d\n", listenPort)
	fmt.Printf("Interface CIDR: %s\n", interfaceCIDR)
	fmt.Printf("Outbound interface: %s\n", outboundIf)

	// Create tunnel interface :
	// read from tunnel -> responses from external sources that must be forwarded to client
	// write to tunnel -> forward client requests to external sources
	iface, err := SetupServerTunnel("tun0", interfaceCIDR, outboundIf)
	if err != nil {
		log.Fatalf("Failed to initialize tunnel: %v", err)
	}

	conn, err := SetupUDPConn(listenPort)
	if err != nil {
		log.Fatalf("Failed to set up UDP connection: %v", err)
	}
	defer conn.Close()

	// Step 3: Handle packets (for demo, just read and dump)
	go packetOutLoop(iface, conn)
	go packetInLoop(iface, conn)
	select {} // block forever

}

func packetOutLoop(iface *water.Interface, conn *net.UDPConn) {
	packet := make([]byte, 1024)
	for {
		// read packet from TUN interface
		n, err := iface.Read(packet)
		if err != nil {
			fmt.Printf("Error reading from interface: %v", err)
			continue
		}
		// process and send packet to VPN server
		processOutPacket(packet[:n], conn)
		fmt.Printf("sent packet to VPN server: ")
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

// handles incoming packets from the VPN clients
func packetInLoop(iface *water.Interface, conn *net.UDPConn) {
	packet := make([]byte, 1024)
	for {
		// read packet from client
		n, err := conn.Read(packet)
		if err != nil {
			fmt.Printf("Error reading from connection: %v", err)
			continue
		}
		// process and write packet to TUN interface
		processInPacket(packet[:n], iface)
		parsed := parseIpv4(packet[:n])
		fmt.Printf("recieved packet from VPN server: ")
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

// returns the source and destination IP addresses from an IPv4 packet
func getAddrs(packet []byte) (string, string) {
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

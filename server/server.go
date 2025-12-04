package server

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"selfVPN/util"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	//iptables "github.com/coreos/go-iptables/iptables"
)

var client net.Addr = nil
var client_addrs = make([]net.Addr, 0)

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

	// 3. add route
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_UNIVERSE,
		Dst:       addr.IPNet, // same subnet as the tun address
	}
	if err := netlink.RouteAdd(route); err != nil && !isExistsErr(err) {
		return nil, fmt.Errorf("route add: %w", err)
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
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Register: 1,
				Op:       expr.CmpOpEq,
				Data:     ifnameBytes(tunName),
			},
			&expr.Masq{},
		},
	})

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "filter",
	})

	fwd := c.AddChain(&nftables.Chain{
		Name:  "forward",
		Table: filter,
	})

	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: fwd,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Register: 1,
				Op:       expr.CmpOpEq,
				Data:     ifnameBytes(tunName),
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: fwd,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{
				Register: 1,
				Op:       expr.CmpOpEq,
				Data:     ifnameBytes(tunName),
			},
			&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           []byte{0, 0, 0, 6}, // ESTABLISHED|RELATED
				Xor:            []byte{0, 0, 0, 0},
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	if err := c.Flush(); err != nil {
		return nil, fmt.Errorf("nft flush: %w", err)
	}

	if err := enableIPForwarding(); err != nil {
		return nil, fmt.Errorf("enable IP forwarding: %w", err)
	}

	return tun, nil
}

func enableIPForwarding() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)
}

func ifnameBytes(name string) []byte {
	b := make([]byte, 16)
	copy(b, []byte(name))
	return b
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

	fmt.Printf("Listening on UDP port %d...\n", listenPort)

	return conn, nil
}

// Run starts the VPN server
// args: listen_port, interface_cidr, outbound_interface
func Run(args []string) {
	if len(args) != 4 {
		fmt.Println("Usage: selfVPN server <key> <listen_port> <interface_cidr> <outbound_interface>")
		return
	}
	listenPort, err := strconv.Atoi(args[1])
	if err != nil {
		log.Fatalf("Invalid listen port: %v", err)
	}
	interfaceCIDR := args[2]
	outboundIf := args[3]
	key := util.KeyFromString(args[0])

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
	go packetOutLoop(iface, conn, key)
	go packetInLoop(iface, conn, key)
	select {} // block forever

}

func packetOutLoop(iface *water.Interface, conn *net.UDPConn, key []byte) {
	packet := make([]byte, 1024)
	for {
		// read packet from TUN interface
		n, err := iface.Read(packet)
		if err != nil {
			fmt.Printf("Error reading from interface: %v", err)
			continue
		}
		// process and send packet to VPN client
		fmt.Printf("sending resp to client: ")
		util.PrintPacketInfo(packet[:n])

		// parsed := util.ParseIpv4(packet[:n])
		// dest_client := net.JoinHostPort(parsed.Dst[0:4], strconv.Itoa(int(parsed.Protocol)))
		// if util.ContainsAddr(client_addrs, ) {
		// 	fmt.Printf("No client connected for dest %s, dropping packet\n", net.JoinHostPort(parsed.Dst[0:4].String(), strconv.Itoa(int(parsed.Protocol))))
		// 	continue
		// }

		encryptedPacket, err := util.Encrypt([]byte(key), packet[:n])
		if err != nil {
			fmt.Printf("Error encrypting packet: %v", err)
			continue
		}
		processOutPacket(encryptedPacket, conn)
	}
}

// processOutPacket takes in the raw packet bytes recieved from the TUN interface,
// performs all processing steps (encryption, encapsulation), sends the packet to the VPN server,
// returns errors.
func processOutPacket(packet []byte, conn *net.UDPConn) ([]byte, error) {
	// for now just send the raw packet
	_, err := conn.WriteTo(packet, client)
	if err != nil {
		fmt.Printf("Error writing to connection: %v", err)
	}
	return packet, err
}

// handles incoming packets from the VPN clients
func packetInLoop(iface *water.Interface, conn *net.UDPConn, key []byte) {
	packet := make([]byte, 1024)
	for {
		// read packet from client
		n, sender, err := conn.ReadFrom(packet)
		client = sender // save client address for responses
		if err != nil {
			fmt.Printf("Error reading from connection: %v", err)
			continue
		}
		// add client to list if new
		found := false
		for _, addr := range client_addrs {
			if addr.String() == sender.String() {
				found = true
				break
			}
		}
		if !found {
			client_addrs = append(client_addrs, sender)
			fmt.Printf("New client connected: %s\n", sender.String())
		}

		// process and write packet to TUN interface
		fmt.Printf("recieved from client, sending to dest: ")
		decryptedPacket, err := util.Decrypt([]byte(key), packet[:n])
		if err != nil {
			fmt.Printf("Error decrypting packet: %v", err)
			continue
		}
		util.PrintPacketInfo(decryptedPacket)
		processInPacket(decryptedPacket, iface)
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

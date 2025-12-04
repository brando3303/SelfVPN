package client

import (
	"fmt"
	"log"
	"net"

	"selfVPN/util"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

// deviceName: "tun0"
// localTunAddr: "10.0.0.1/24"
// routeDest: "98.137.11.164/32"
func initTunnel(deviceName string, localTunAddr string, routeDest string) (*water.Interface, error) {
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
	addr, _ := netlink.ParseAddr(localTunAddr)
	if err := netlink.AddrAdd(link, addr); err != nil {
		log.Printf("Failed to add address: %v", err)
		return nil, err
	}

	// Bring the interface up
	if err := netlink.LinkSetUp(link); err != nil {
		log.Printf("Failed to bring up interface: %v", err)
		return nil, err
	}

	// Step 5: Add a route for destination into TUN
	// Example routeDest: "98.137.11.164/32"
	_, dst, err := net.ParseCIDR(routeDest)
	if err != nil {
		return nil, fmt.Errorf("failed parsing route: %w", err)
	}

	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
	}

	if err := netlink.RouteAdd(route); err != nil {
		return nil, fmt.Errorf("failed to add route: %w", err)
	}

	fmt.Println("Added route:", routeDest, "→", iface.Name())

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

// Run starts the VPN client
// args: server_addr:port, interface_cidr, protected_subnet
func Run(args []string) {
	if len(args) != 4 {
		fmt.Println("Usage: selfVPN client <key> <server_addr:port> <interface_cidr> <protected_subnet>")
		return
	}
	key := util.KeyFromString(args[0])
	serverAddr := args[1]
	interfaceCIDR := args[2]
	protectedSubnet := args[3]
	fmt.Printf("Starting selfVPN client\n")
	fmt.Printf("Server address: %s\n", serverAddr)
	fmt.Printf("Interface CIDR: %s\n", interfaceCIDR)
	fmt.Printf("Protected subnet: %s\n", protectedSubnet)

	// Create tunnel interface :
	// read from tunnel -> reqs from os/user-space (applications etc, the data that will be sent to the VPN)
	// write to tunnel -> send response to os
	iface, err := initTunnel("tun0", interfaceCIDR, protectedSubnet)
	if err != nil {
		log.Fatalf("Failed to initialize tunnel: %v", err)
	}

	conn, err := SetupUDPConn(serverAddr)
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
		// process and send packet to VPN server
		fmt.Printf("sent packet to VPN server: ")
		encryptedPacket, err := util.Encrypt([]byte(key), packet[:n])
		if err != nil {
			fmt.Printf("Error encrypting packet: %v", err)
			continue
		}
		util.PrintPacketInfo(packet[:n])
		processOutPacket(encryptedPacket, conn)
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

func packetInLoop(iface *water.Interface, conn *net.UDPConn, key []byte) {
	packet := make([]byte, 1024)
	for {
		// read packet from VPN server
		n, err := conn.Read(packet)
		if err != nil {
			fmt.Printf("Error reading from connection: %v", err)
			continue
		}
		// process and write packet to TUN interface
		fmt.Printf("recieved packet from VPN server: ")
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

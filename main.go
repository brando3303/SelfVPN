package main

import (
    "fmt"
    "log"
    "encoding/binary"

    "github.com/songgao/water"
    "github.com/vishvananda/netlink"
)

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
        src, dst := getAddrs(packet[:n])
        fmt.Printf("Read %d bytes % x\n", n, packet[:n])
        fmt.Printf("Source: %s, Destination: %s\n", src, dst)
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
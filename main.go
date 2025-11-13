package main

import (
    "fmt"
    "log"

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
        fmt.Printf("Read %d bytes: % x\n", n, packet[:n])
    }
}

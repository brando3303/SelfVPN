package main

import (
	"fmt"
	"os"

	"selfVPN/client"
	"selfVPN/server"
)

/*
 * SelfVPN - A simple VPN solution
 *
 * This program can operate in two modes: client and server.
 *
 * Usage:
 *   selfVPN <client|server> [args...]
 *
 * Client mode:
 *   selfVPN client <server_addr:port> <protected_subnet>
 *
 * Server mode:
 *   selfVPN server <listen_port> <interface_cidr> <outbound_interface>
 *
 * args:
 *   - server_addr:port: The IP address and port of the VPN server to connect to.
 *   - interface_cidr: The CIDR notation for the VPN interface IP address. should be /31 for p2p connection.
 *   - protected_subnet: The subnet(s) to route through the VPN.
 *   - listen_port: The port on which the VPN server listens for incoming connections.
 *   - outbound_interface: The network interface used for outbound traffic on the server.
 *
 * Example:
 *   Server: selfVPN server 1194 10.8.0.1/32 eth0
 * Example:
 *   Client: selfVPN client
 */
func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: selfVPN <client|server> [args...]")
		fmt.Println("\nClient usage: selfVPN client <server_addr:port> <protected_subnet>")
		fmt.Println("Server usage: selfVPN server <listen_port> <interface_cidr> <outbound_interface>")
		os.Exit(1)
	}

	mode := os.Args[1]
	args := os.Args[2:]

	switch mode {
	case "client":
		client.Run(args)
	case "server":
		server.Run(args)
	default:
		fmt.Printf("Unknown mode: %s\n", mode)
		fmt.Println("Use 'client' or 'server'")
		os.Exit(1)
	}
}

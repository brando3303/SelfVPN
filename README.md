# Lightweight UDP-Based VPN

A minimal VPN implemented in Go using a TUN interface, UDP transport, and nftables-based NAT.
This project creates a simple point-to-point VPN tunnel.

## Features

- TUN interface creation via `water`
- IP address assignment & interface bring-up using `netlink`
- NAT + forwarding using `nftables`
- UDP-based transport
- Simple packet routing and inspection

## Requirements

- Linux with TUN support
- `nftables` installed and enabled
- Go 1.20+
- Root/sudo privileges (required for TUN device creation and network configuration)

## Usage

### Run as Server

Creates a TUN device and listens for client packets over UDP.

```bash
sudo go run main.go server <listen_port> <interface_cidr> <outbound_interface>
```

**Example:**
```bash
sudo go run main.go server 1194 10.8.0.1/32 eth0
```

**Parameters:**
- `listen_port`: The UDP port to listen on for incoming client connections
- `interface_cidr`: The IP address to assign to the TUN interface (use /32)
- `outbound_interface`: The network interface for outbound traffic (e.g., `eth0`, `wlan0`)

### Run as Client

Creates a local TUN device and connects to the remote VPN server.

```bash
sudo go run main.go client <server_addr:port> <interface_cidr> <protected_subnet>
```

**Example:**
```bash
sudo go run main.go client 203.0.113.1:1194 10.8.0.2/31 98.137.11.164/31
```

**Parameters:**
- `server_addr:port`: The VPN server's IP address and port
- `interface_cidr`: The IP address to assign to the local TUN interface (use /30, /32 does not work)
- `protected_subnet`: The destination subnet to route through the VPN

## Notes

- Server must have IP forwarding enabled (`/proc/sys/net/ipv4/ip_forward = 1`). The server automatically enables this.
- The server automatically creates nftables rules for masquerading outgoing traffic on the specified outbound interface.
- This is a research/learning project, **not production-ready security software**.
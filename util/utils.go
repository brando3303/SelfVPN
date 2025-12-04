package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

var CLIENT_INIT_MSG = []byte("CLIENT_INIT")

type IPPacket interface {
	IPVersion() uint8 // 4 or 6
	SrcIP() []byte    // return 4 or 16 bytes
	DstIP() []byte
}

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

func (p *Ipv4Packet) IPVersion() uint8 {
	return 4
}

func (p *Ipv4Packet) SrcIP() []byte {
	return p.Src[:]
}

func (p *Ipv4Packet) DstIP() []byte {
	return p.Dst[:]
}

type IPv6Packet struct {
	Version       uint8    // always 6
	TrafficClass  uint8    // 8 bits
	FlowLabel     uint32   // low 20 bits used
	PayloadLength uint16   // length of payload after this header
	NextHeader    uint8    // like Protocol field in IPv4
	HopLimit      uint8    // like TTL
	Src           [16]byte // 128-bit source address
	Dst           [16]byte // 128-bit destination address

	// IPv6 has no checksum in the base header.
	// Options appear only inside extension headers.

	ExtensionHeaders []byte // raw extension header bytes, if present
	Data             []byte // payload (TCP/UDP/ICMPv6/etc)
}

func (p *IPv6Packet) IPVersion() uint8 {
	return 6
}

func (p *IPv6Packet) SrcIP() []byte {
	return p.Src[:]
}

func (p *IPv6Packet) DstIP() []byte {
	return p.Dst[:]
}

func Uint32ToIPv4(ip uint32) string {
	b1 := byte(ip >> 24)
	b2 := byte(ip >> 16)
	b3 := byte(ip >> 8)
	b4 := byte(ip)

	return fmt.Sprintf("%d.%d.%d.%d", b1, b2, b3, b4)
}

func GetAddrs(packet []byte) (string, string) {
	// Dummy implementation for illustration
	return Uint32ToIPv4(binary.BigEndian.Uint32(packet[12:16])), Uint32ToIPv4(binary.BigEndian.Uint32(packet[16:20]))
}

func ParseIpv4(packet []byte) *Ipv4Packet {
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

func PrintIpv4(ipv4 *Ipv4Packet) {
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

func ParseIPv6(packet []byte) *IPv6Packet {
	if len(packet) < 40 {
		return nil // Not enough data for IPv6 fixed header
	}

	ipv6 := &IPv6Packet{}

	// First 4 bytes: Version (4 bits), Traffic Class (8 bits), Flow Label (20 bits)
	firstWord := binary.BigEndian.Uint32(packet[0:4])

	ipv6.Version = uint8(firstWord >> 28)
	ipv6.TrafficClass = uint8((firstWord >> 20) & 0xFF)
	ipv6.FlowLabel = firstWord & 0xFFFFF // low 20 bits

	// Payload Length, Next Header, Hop Limit
	ipv6.PayloadLength = binary.BigEndian.Uint16(packet[4:6])
	ipv6.NextHeader = packet[6]
	ipv6.HopLimit = packet[7]

	// Src and Dst IPv6 addresses
	copy(ipv6.Src[:], packet[8:24])
	copy(ipv6.Dst[:], packet[24:40])

	// Offset begins after fixed header
	offset := 40

	// Pull extension headers (if any)
	// We don't parse them individually — just capture raw bytes.
	// Extension headers continue as long as NextHeader is in the extension header range.
	// Extension header types: 0, 43, 44, 50, 51, 60, etc.
	extHeaders := []byte{}
	next := ipv6.NextHeader

	for {
		// Not an extension header → break.
		if !IsIPv6ExtensionHeader(next) {
			break
		}

		// Need at least 2 bytes for the ext header length field
		if len(packet) < offset+2 {
			return ipv6
		}

		// Extension header length:
		// length field = number of 8-byte units *after* these first 8 bytes.
		extLen := int(packet[offset+1]+1) * 8

		// Copy raw header bytes
		if len(packet) < offset+extLen {
			return ipv6
		}
		extHeaders = append(extHeaders, packet[offset:offset+extLen]...)

		// Advance
		next = packet[offset] // "Next Header" field inside extension header
		offset += extLen
	}

	ipv6.ExtensionHeaders = extHeaders

	// Remaining bytes = payload
	if offset < len(packet) {
		ipv6.Data = make([]byte, len(packet)-offset)
		copy(ipv6.Data, packet[offset:])
	}

	return ipv6
}

func IsIPv6ExtensionHeader(h uint8) bool {
	switch h {
	case 0, 43, 44, 50, 51, 60:
		return true
	default:
		return false
	}
}

func ParseIpPacket(packet []byte) IPPacket {
	if len(packet) < 1 {
		fmt.Println("Packet too short")
		return nil
	}

	version := packet[0] >> 4
	if version == 4 {
		ipv4 := ParseIpv4(packet)
		return ipv4
	} else if version == 6 {
		ipv6 := ParseIPv6(packet)
		return ipv6
	} else {
		fmt.Printf("Unknown IP version: %d\n", version)
	}
	return nil
}

func Ipv6ToString(ip []byte) string {
	if len(ip) != 16 {
		return ""
	}
	result := ""
	for i := 0; i < 16; i += 2 {
		if i > 0 {
			result += ":"
		}
		if ip[i] == 0 && ip[i+1] == 0 {
			continue
		}
		result += fmt.Sprintf("%02x%02x", ip[i], ip[i+1])
	}
	return result
}

func PrintPacketInfo(packet []byte) {
	parsed := ParseIpPacket(packet)
	ver := parsed.IPVersion()
	src := parsed.SrcIP()
	dst := parsed.DstIP()
	if ver == 4 {
		fmt.Printf("Src IP: %d.%d.%d.%d | ", src[0], src[1], src[2], src[3])
		fmt.Printf("Dst IP: %d.%d.%d.%d\n", dst[0], dst[1], dst[2], dst[3])
	} else if ver == 6 {
		fmt.Printf("Src IP: %s | ", Ipv6ToString(src))
		fmt.Printf("Dst IP: %s\n", Ipv6ToString(dst))
	}
}

// Encrypt returns nonce || ciphertext
func Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

func Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce := ciphertext[:nonceSize]
	data := ciphertext[nonceSize:]

	return gcm.Open(nil, nonce, data, nil)
}

func KeyFromString(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:16] // AES-128 key
}

func ContainsAddr(slice []net.Addr, a net.Addr) bool {
	for _, addr := range slice {
		if addr.String() == a.String() {
			return true
		}
	}
	return false
}

func GenerateNewKey() []byte {
	key := make([]byte, 16) // AES-128
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil
	}
	return key
}

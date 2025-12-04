package server

import (
	"log"
	"net"
	"strconv"
	"sync"
)

type Client struct {
	IP         string
	Port       int
	Conn       net.UDPConn // UDP connection to the server
	Addr       net.Addr    // UDP address of the client
	SessionKey []byte
}

// clients maps from internal ip string to client(external connection)
type ClientManager struct {
	mu         sync.Mutex
	clients    map[string]*Client
	lastusedIP []byte
}

func NewClientManager() *ClientManager {
	return &ClientManager{
		clients:    make(map[string]*Client),
		lastusedIP: []byte{10, 8, 0, 1},
	}
}

func (cm *ClientManager) AddClient(internalIP string, addr net.Addr, conn net.UDPConn, sessionKey []byte) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	ip, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		log.Printf("Invalid address: %s", addr.String())
		return
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Printf("Invalid port: %s", portStr)
		return
	}

	client := &Client{
		IP:         ip,
		Port:       port,
		Conn:       conn,
		Addr:       addr,
		SessionKey: sessionKey,
	}

	cm.clients[internalIP] = client
}

func (cm *ClientManager) RemoveClient(addr string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	delete(cm.clients, addr)
}

func (cm *ClientManager) ContainsClientStr(addr string) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	_, exists := cm.clients[addr]
	return exists
}

func (cm *ClientManager) ContainsClientAddr(addr net.Addr) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	_, exists := cm.clients[addr.String()]
	return exists
}

// returns client if exists from internal ip string
func (cm *ClientManager) GetClientInternal(addr string) (*Client, bool) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	client, exists := cm.clients[addr]
	return client, exists
}

func (cm *ClientManager) GetClientExternal(addr net.Addr) (*Client, string, bool) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	for internalip, client := range cm.clients {
		if client.Conn.RemoteAddr().String() == addr.String() {
			return client, internalip, true
		}
	}
	return nil, "", false
}

func (cm *ClientManager) ToString() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	log.Println("Current clients:")
	for addr, client := range cm.clients {
		log.Printf("Addr: %s, IP: %s, Port: %d", addr, client.IP, client.Port)
	}
}

// you better actually use this :( bc it's gonna be used...
func (cm *ClientManager) GenerateNewIP() string {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	// simple increment lastusedIP
	cm.lastusedIP[3]++
	return net.IP(cm.lastusedIP).String()
}

package netdev

import (
	"net/netip"
	"time"
)

// GoNet is the networking interface expected by TinyGo compiler/standard library.
// The methods below define a networking stack as expected by the Go standard library
// when using the TinyGo compiler+stdlib.
type GoNet interface {
	// GetHostByName returns the IP address of either a hostname or IPv4
	// address in standard dot notation
	GetHostByName(name string) (netip.Addr, error)

	// Addr returns IP address assigned to the interface, either by
	// DHCP or statically
	Addr() (netip.Addr, error)

	// Berkely Sockets-like interface, Go-ified.  See man page for socket(2), etc.
	Socket(domain int, stype int, protocol int) (int, error)
	Bind(sockfd int, ip netip.AddrPort) error
	Connect(sockfd int, host string, ip netip.AddrPort) error
	Listen(sockfd int, backlog int) error
	Accept(sockfd int) (int, netip.AddrPort, error)
	Send(sockfd int, buf []byte, flags int, deadline time.Time) (int, error)
	Recv(sockfd int, buf []byte, flags int, deadline time.Time) (int, error)
	Close(sockfd int) error
	SetSockOpt(sockfd int, level int, opt int, value interface{}) error
}

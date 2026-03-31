package xnet

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"
)

const (
	_AF_INET       = 0x2
	_SOCK_STREAM   = 0x1
	_SOCK_DGRAM    = 0x2
	_SOL_SOCKET    = 0x1
	_SO_KEEPALIVE  = 0x9
	_SOL_TCP       = 0x6
	_TCP_KEEPINTVL = 0x5
	_IPPROTO_TCP   = 0x6
	_IPPROTO_UDP   = 0x11
	// Made up, not a real IP protocol number.  This is used to create a
	// TLS socket on the device, assuming the device supports mbed TLS.
	_IPPROTO_TLS = 0xFE
	_F_SETFL     = 0x4
)

// gostack is the stack abstraction for the baremetal proposal.
// family must be syscall.AF_INET. SOCK_STREAM is only one supported for now since is TCP.
// network supported for now is "tcp" or "tcp4". A nil remote address and defined local address means net.Listener is returned.
// if remote address defined then is active connection, returns a net.Conn.
type gostack = func(ctx context.Context, network string, family, sotype int, laddr, raddr net.Addr) (c interface{}, err error)

type socket[T any] struct {
	sockfd int
	sock   T
}

type pendingSocket struct {
	protocol  int
	boundAddr netip.AddrPort
}

// StackBerkeley is a wrapper type for a gostack function to provide typical Berkeley networking stack
// functionality from a Go-like API.
// The Berkeley calling convention depends on file-descriptors returned by the stack which
// the user must keep track of.
type StackBerkeley struct {
	nextFD int
	addr   netip.Addr
	stack  gostack

	pendingFDs   []socket[pendingSocket]
	tcpListeners []socket[net.Listener]
	tcpConns     []socket[net.Conn]
}

// NewBerkeleyStack wraps the gostack with Berkeley-style calling convention. See [StackBerkeley].
func NewBerkeleyStack(stack gostack) *StackBerkeley {
	if stack == nil {
		panic("nil gostack")
	}
	return &StackBerkeley{
		stack:  stack,
		nextFD: 3,
	}
}

// Bind associates sockfd with the given local address and port.
func (s *StackBerkeley) Bind(sockfd int, ip netip.AddrPort) error {
	idx := slices.IndexFunc(s.pendingFDs, func(s socket[pendingSocket]) bool { return s.sockfd == sockfd })
	if idx < 0 {
		return fmt.Errorf("Bind: unknown sockfd %d", sockfd)
	}
	s.pendingFDs[idx].sock.boundAddr = ip
	return nil
}

// SetSockOpt sets a socket option on sockfd. Currently unimplemented.
func (s *StackBerkeley) SetSockOpt(sockfd int, level int, opt int, value interface{}) error {
	return nil
}

// Socket allocates a new socket and returns its file descriptor.
// domain must be AF_INET. stype must be SOCK_STREAM or SOCK_DGRAM.
// protocol must be IPPROTO_TCP, IPPROTO_UDP, or IPPROTO_TLS.
func (s *StackBerkeley) Socket(domain int, stype int, protocol int) (sockfd int, _ error) {
	if domain != _AF_INET {
		return -1, fmt.Errorf("unsupported domain %d", domain)
	}
	sockfd = s.newFD()
	s.pendingFDs = append(s.pendingFDs, socket[pendingSocket]{sockfd: sockfd, sock: pendingSocket{protocol: protocol}})
	return sockfd, nil
}

// Connect establishes an active connection to the given host and address.
// host is used for TLS SNI; ip carries the numeric address and port.
// Promotes sockfd from pending to an active connection.
func (s *StackBerkeley) Connect(sockfd int, host string, ip netip.AddrPort) error {
	pending := s.getPending(sockfd)
	if !pending.isvalid() {
		return fmt.Errorf("Connect: unknown sockfd %d", sockfd)
	}

	var laddr net.Addr
	if pending.sock.boundAddr.IsValid() && pending.sock.boundAddr.Port() > 0 {
		laddr = &net.TCPAddr{IP: pending.sock.boundAddr.Addr().AsSlice(), Port: int(pending.sock.boundAddr.Port())}
	}
	raddr := &net.TCPAddr{IP: ip.Addr().AsSlice(), Port: int(ip.Port())}
	c, err := s.stack(context.Background(), "tcp4", _AF_INET, _SOCK_STREAM, laddr, raddr)
	if err != nil {
		return err
	}
	conn, ok := c.(net.Conn)
	if !ok {
		return fmt.Errorf("Connect: stack returned non-Conn for protocol %d", pending.sock)
	}

	s.pendingFDs = deleteFD(s.pendingFDs, sockfd)
	s.tcpConns = append(s.tcpConns, socket[net.Conn]{sockfd: sockfd, sock: conn})
	return nil
}

// Listen marks sockfd as passive, ready to accept incoming connections.
// backlog is the maximum length of the pending connection queue.
func (s *StackBerkeley) Listen(sockfd int, backlog int) error {
	pending := s.getPending(sockfd)
	if !pending.isvalid() {
		return fmt.Errorf("Listen: unknown sockfd %d", sockfd)
	}

	var laddr net.Addr
	if pending.sock.boundAddr.IsValid() && pending.sock.boundAddr.Port() > 0 {
		laddr = &net.TCPAddr{IP: pending.sock.boundAddr.Addr().AsSlice(), Port: int(pending.sock.boundAddr.Port())}
	}
	c, err := s.stack(context.Background(), "tcp4", _AF_INET, _SOCK_STREAM, laddr, nil)
	if err != nil {
		return err
	}
	ln, ok := c.(net.Listener)
	if !ok {
		return fmt.Errorf("Listen: stack returned non-Listener")
	}

	s.pendingFDs = deleteFD(s.pendingFDs, sockfd)
	s.tcpListeners = append(s.tcpListeners, socket[net.Listener]{sockfd: sockfd, sock: ln})
	return nil
}

// Accept blocks until an incoming connection arrives on sockfd.
// Returns a new file descriptor and the remote address of the peer.
func (s *StackBerkeley) Accept(sockfd int) (int, netip.AddrPort, error) {
	ln := s.getListener(sockfd)
	if !ln.isvalid() {
		return -1, netip.AddrPort{}, fmt.Errorf("Accept: unknown sockfd %d", sockfd)
	}

	conn, err := ln.sock.Accept()
	if err != nil {
		return -1, netip.AddrPort{}, err
	}

	addrPort, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		_ = conn.Close() // Ignore error, more pertinent looking at other error.
		return -1, netip.AddrPort{}, err
	}

	fd := s.newFD()
	s.tcpConns = append(s.tcpConns, socket[net.Conn]{sockfd: fd, sock: conn})
	return fd, addrPort, nil
}

// Send transmits buf on sockfd. deadline is a zero Time for no timeout.
// Returns the number of bytes written.
func (s *StackBerkeley) Send(sockfd int, buf []byte, flags int, deadline time.Time) (int, error) {
	conn := s.getConn(sockfd)
	if !conn.isvalid() {
		return 0, fmt.Errorf("Send: unknown sockfd %d", sockfd)
	}
	if !deadline.IsZero() {
		conn.sock.SetWriteDeadline(deadline)
	}
	return conn.sock.Write(buf)
}

// Recv reads from sockfd into buf. deadline is a zero Time for no timeout.
// Returns the number of bytes read.
func (s *StackBerkeley) Recv(sockfd int, buf []byte, flags int, deadline time.Time) (int, error) {
	conn := s.getConn(sockfd)
	if !conn.isvalid() {
		return 0, fmt.Errorf("Recv: unknown sockfd %d", sockfd)
	}
	if !deadline.IsZero() {
		conn.sock.SetReadDeadline(deadline)
	}
	return conn.sock.Read(buf)
}

// Close shuts down sockfd and releases its resources.
func (s *StackBerkeley) Close(sockfd int) error {
	if conn := s.getConn(sockfd); conn.isvalid() {
		err := conn.sock.Close()
		s.tcpConns = deleteFD(s.tcpConns, sockfd)
		return err
	}
	if ln := s.getListener(sockfd); ln.isvalid() {
		err := ln.sock.Close()
		s.tcpListeners = deleteFD(s.tcpListeners, sockfd)
		return err
	}
	if s.getPending(sockfd).isvalid() {
		s.pendingFDs = deleteFD(s.pendingFDs, sockfd)
		return nil
	}
	return fmt.Errorf("Close: unknown sockfd %d", sockfd)
}

func (s *StackBerkeley) newFD() int {
	fd := s.nextFD
	s.nextFD++
	return fd
}

func (s *StackBerkeley) getConn(fd int) socket[net.Conn]         { return getFD(s.tcpConns, fd) }
func (s *StackBerkeley) getListener(fd int) socket[net.Listener] { return getFD(s.tcpListeners, fd) }
func (s *StackBerkeley) getPending(fd int) socket[pendingSocket] { return getFD(s.pendingFDs, fd) }

func (s socket[T]) isvalid() bool {
	return s.sockfd > 2
}

// getFD finds a socket by fd in a slice, returns a pointer for in-place mutation or nil.
func getFD[T any](socks []socket[T], fd int) socket[T] {
	idx := slices.IndexFunc(socks, func(s socket[T]) bool { return s.sockfd == fd })
	if idx < 0 {
		return socket[T]{}
	}
	return socks[idx]
}

func deleteFD[T any](socks []socket[T], fd int) []socket[T] {
	return slices.DeleteFunc(socks, func(s socket[T]) bool { return s.sockfd == fd })
}

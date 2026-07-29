//go:build !tinygo && darwin

// Package rawsock listens and reads over Darwin sockets through syscalls
// directly, without the net package. It exists so a server can be measured
// without net.TCPConn, its netFD and its poller on the path.
//
// [Conn] and [Listener] implement [net.Conn] and [net.Listener] the way
// TinyGo's net package does: a connection is its file descriptor plus its
// addresses, deadlines live on the struct and are handed to the socket, and
// nothing sits between a Read and the syscall. A server written against these
// interfaces runs unchanged over the net package, over this package and over
// TinyGo's netdev.
package rawsock

import (
	"net"
	"net/netip"
	"syscall"
	"time"
	"unsafe"
)

// The interfaces this package exists to satisfy: an http.Server and a heapless
// router must both accept what Listen hands back.
var (
	_ net.Conn     = (*Conn)(nil)
	_ net.Listener = (*Listener)(nil)
)

// Addr is a socket address. It implements [net.Addr] over a
// [netip.AddrPort], which costs no allocation to carry around, unlike
// [net.TCPAddr] and its IP slice.
type Addr netip.AddrPort

// Network returns "tcp".
func (a Addr) Network() string { return "tcp" }

// String returns the address in host:port form.
func (a Addr) String() string { return netip.AddrPort(a).String() }

// AddrPort returns the address as a [netip.AddrPort].
func (a Addr) AddrPort() netip.AddrPort { return netip.AddrPort(a) }

// Conn is an accepted TCP connection over a raw socket file descriptor. It
// implements [net.Conn], so both an [net/http.Server] and a heapless router can
// be handed the same connection.
//
// Deadlines are enforced by the socket itself through SO_RCVTIMEO and
// SO_SNDTIMEO: a read that runs out of time fails with a [net.Error] that
// reports Timeout, as callers of net.Conn expect.
type Conn struct {
	fd            int
	local, remote Addr
	readDeadline  time.Time
	writeDeadline time.Time
}

// Read reads bytes from the connection into b.
func (c *Conn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	n, err := syscall.Read(c.fd, b)
	if err != nil {
		return 0, c.opError("read", err)
	}
	if n == 0 {
		return 0, syscall.ECONNRESET // Peer closed.
	}
	return n, nil
}

// Write writes b to the connection, looping until all bytes are sent.
func (c *Conn) Write(b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := syscall.Write(c.fd, b[total:])
		if err != nil {
			return total, c.opError("write", err)
		}
		total += n
	}
	return total, nil
}

// Close closes the underlying file descriptor.
func (c *Conn) Close() error {
	return syscall.Close(c.fd)
}

// LocalAddr returns the address the connection was accepted on.
func (c *Conn) LocalAddr() net.Addr { return c.local }

// RemoteAddr returns the peer address of the connection.
func (c *Conn) RemoteAddr() net.Addr { return c.remote }

// SetDeadline sets both the read and write deadline. A zero time removes them.
func (c *Conn) SetDeadline(t time.Time) error {
	err := c.SetReadDeadline(t)
	if err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// SetReadDeadline makes reads after t fail with a timeout error. A zero time
// lets reads block indefinitely.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return c.SetReadTimeout(untilDeadline(t))
}

// SetWriteDeadline makes writes after t fail with a timeout error. A zero time
// lets writes block indefinitely.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	return c.SetWriteTimeout(untilDeadline(t))
}

// SetReadTimeout limits how long a single Read waits for data before failing
// with a timeout error. Zero blocks indefinitely. This is what stops a peer
// that opens a connection and then stalls from holding a server worker: the
// connection, not the HTTP handler, owns the idle policy.
func (c *Conn) SetReadTimeout(timeout time.Duration) error {
	return setSockTimeout(c.fd, syscall.SO_RCVTIMEO, timeout)
}

// SetWriteTimeout limits how long a single Write waits for the send buffer to
// drain before failing with a timeout error. Zero blocks indefinitely.
func (c *Conn) SetWriteTimeout(timeout time.Duration) error {
	return setSockTimeout(c.fd, syscall.SO_SNDTIMEO, timeout)
}

// opError wraps a socket error the way the net package does, so that callers
// which test for a timeout with [net.Error] see one. A deadline that has passed
// surfaces from the kernel as EAGAIN, which on a blocking socket only ever
// means the timeout fired.
func (c *Conn) opError(op string, err error) error {
	if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
		err = errTimeout{}
	}
	return &net.OpError{Op: op, Net: "tcp", Source: c.local, Addr: c.remote, Err: err}
}

// errTimeout is the error a read or write past its deadline fails with.
type errTimeout struct{}

func (errTimeout) Error() string   { return "i/o timeout" }
func (errTimeout) Timeout() bool   { return true }
func (errTimeout) Temporary() bool { return true }

func untilDeadline(t time.Time) time.Duration {
	if t.IsZero() {
		return 0 // No deadline: block indefinitely.
	}
	remaining := time.Until(t)
	if remaining <= 0 {
		return time.Nanosecond // Already past: fail the next call, do not block.
	}
	return remaining
}

func setSockTimeout(fd, option int, timeout time.Duration) error {
	tv := syscall.NsecToTimeval(int64(timeout))
	return syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, option, &tv)
}

// Listener is a listening TCP socket bound to a local port. It implements
// [net.Listener].
type Listener struct {
	fd    int
	local Addr
}

// Listen creates a listening TCP socket bound to port on all interfaces. A
// zero port lets the kernel choose one, see [Listener.Addr].
func (l *Listener) Listen(port uint16) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return err
	}
	// Allow quick rebind after restart.
	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		syscall.Close(fd)
		return err
	}
	addr := &syscall.SockaddrInet4{Port: int(port)}
	if err = syscall.Bind(fd, addr); err != nil {
		syscall.Close(fd)
		return err
	}
	if err = syscall.Listen(fd, syscall.SOMAXCONN); err != nil {
		syscall.Close(fd)
		return err
	}
	l.fd = fd
	l.local = Addr{}
	bound, err := syscall.Getsockname(fd)
	if err != nil {
		syscall.Close(fd)
		return err
	}
	if sa4, ok := bound.(*syscall.SockaddrInet4); ok {
		l.local = Addr(netip.AddrPortFrom(netip.AddrFrom4(sa4.Addr), uint16(sa4.Port)))
	}
	return nil
}

// Accept blocks until an incoming connection arrives and returns it. It
// allocates the connection, as [net.Listener] requires. A server that keeps its
// own connection storage should call [Listener.AcceptConn] instead.
func (l *Listener) Accept() (net.Conn, error) {
	conn := new(Conn)
	err := l.AcceptConn(conn)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// AcceptConn blocks until an incoming connection arrives and stores it in conn,
// reusing whatever conn already held. Nothing is allocated.
//
// The syscall is made by hand because [syscall.Accept] allocates the
// [syscall.Sockaddr] it returns, one per accepted connection: the kernel is
// given address storage this call owns instead, and the address is read out of
// it into conn. Darwin has no accept4, unlike Linux, so this calls the plain
// three-argument accept.
func (l *Listener) AcceptConn(conn *Conn) error {
	var rsa syscall.RawSockaddrAny
	salen := uint32(unsafe.Sizeof(rsa))
	nfd, _, errno := syscall.Syscall(syscall.SYS_ACCEPT, uintptr(l.fd),
		uintptr(unsafe.Pointer(&rsa)), uintptr(unsafe.Pointer(&salen)))
	if errno != 0 {
		return errno
	}
	*conn = Conn{fd: int(nfd), local: l.local}
	if rsa.Addr.Family == syscall.AF_INET {
		sa4 := (*syscall.RawSockaddrInet4)(unsafe.Pointer(&rsa))
		// Port is in network byte order in the sockaddr the kernel filled.
		port := uint16(sa4.Port<<8) | uint16(sa4.Port>>8)
		conn.remote = Addr(netip.AddrPortFrom(netip.AddrFrom4(sa4.Addr), port))
	}
	return nil
}

// Addr returns the address the socket is bound to, which carries the port the
// kernel picked when the listener was created with port zero.
func (l *Listener) Addr() net.Addr { return l.local }

// Port returns the port the socket is bound to.
func (l *Listener) Port() uint16 { return l.local.AddrPort().Port() }

// Close closes the listening socket.
func (l *Listener) Close() error { return syscall.Close(l.fd) }

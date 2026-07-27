//go:build !tinygo && linux

package main

import (
	"net/netip"
	"syscall"
	"time"
)

// Conn wraps an accepted TCP connection from a raw Linux socket file descriptor.
// It implements io.Reader/io.Writer/io.Closer over syscall.Read/Write/Close.
type Conn struct {
	fd     int
	remote netip.AddrPort
}

// Read reads bytes from the connection into b.
func (c *Conn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	n, err := syscall.Read(c.fd, b)
	if err != nil {
		return 0, err
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
			return total, err
		}
		total += n
	}
	return total, nil
}

// Close closes the underlying file descriptor.
func (c *Conn) Close() error {
	return syscall.Close(c.fd)
}

// SetReadTimeout limits how long a single Read waits for data before failing
// with [syscall.EAGAIN]. Zero blocks indefinitely. This is what stops a peer
// that opens a connection and then stalls from holding a server worker: the
// connection, not the HTTP handler, owns the idle policy.
func (c *Conn) SetReadTimeout(timeout time.Duration) error {
	return setSockTimeout(c.fd, syscall.SO_RCVTIMEO, timeout)
}

// SetWriteTimeout limits how long a single Write waits for the send buffer to
// drain before failing with [syscall.EAGAIN]. Zero blocks indefinitely.
func (c *Conn) SetWriteTimeout(timeout time.Duration) error {
	return setSockTimeout(c.fd, syscall.SO_SNDTIMEO, timeout)
}

func setSockTimeout(fd, option int, timeout time.Duration) error {
	tv := syscall.NsecToTimeval(int64(timeout))
	return syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, option, &tv)
}

// RemoteAddr returns the peer address of the connection.
func (c *Conn) RemoteAddr() netip.AddrPort { return c.remote }

// Listener wraps a listening TCP socket bound to a local port.
type Listener struct {
	fd int
}

// Listen creates a listening TCP socket bound to port on all interfaces.
func Listen(port uint16) (*Listener, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, err
	}
	// Allow quick rebind after restart.
	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	addr := &syscall.SockaddrInet4{Port: int(port)}
	if err = syscall.Bind(fd, addr); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	if err = syscall.Listen(fd, syscall.SOMAXCONN); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return &Listener{fd: fd}, nil
}

// Accept blocks until an incoming connection arrives and returns it as a Conn.
func (l *Listener) Accept(conn *Conn) error {
	nfd, sa, err := syscall.Accept(l.fd)
	if err != nil {
		return err
	}

	conn.fd = nfd
	if sa4, ok := sa.(*syscall.SockaddrInet4); ok {
		conn.remote = netip.AddrPortFrom(netip.AddrFrom4(sa4.Addr), uint16(sa4.Port))
	}
	return nil
}

// Close closes the listening socket.
func (l *Listener) Close() error { return syscall.Close(l.fd) }

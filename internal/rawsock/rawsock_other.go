//go:build tinygo || !linux

// Package rawsock listens and reads over Linux sockets through syscalls
// directly, without the net package. Every operation fails with
// [errors.ErrUnsupported] on other platforms, where the net package already
// provides what this one exists to avoid.
package rawsock

import (
	"errors"
	"net"
	"net/netip"
	"time"
)

var (
	_ net.Conn     = (*Conn)(nil)
	_ net.Listener = (*Listener)(nil)
)

// Addr is a socket address implementing [net.Addr].
type Addr netip.AddrPort

func (a Addr) Network() string          { return "tcp" }
func (a Addr) String() string           { return netip.AddrPort(a).String() }
func (a Addr) AddrPort() netip.AddrPort { return netip.AddrPort(a) }

// Conn is an accepted connection. Unsupported on this platform.
type Conn struct{}

func (c *Conn) Read(b []byte) (int, error)  { return 0, errors.ErrUnsupported }
func (c *Conn) Write(b []byte) (int, error) { return 0, errors.ErrUnsupported }
func (c *Conn) Close() error                { return errors.ErrUnsupported }
func (c *Conn) LocalAddr() net.Addr         { return Addr{} }
func (c *Conn) RemoteAddr() net.Addr        { return Addr{} }

func (c *Conn) SetDeadline(t time.Time) error               { return errors.ErrUnsupported }
func (c *Conn) SetReadDeadline(t time.Time) error           { return errors.ErrUnsupported }
func (c *Conn) SetWriteDeadline(t time.Time) error          { return errors.ErrUnsupported }
func (c *Conn) SetReadTimeout(timeout time.Duration) error  { return errors.ErrUnsupported }
func (c *Conn) SetWriteTimeout(timeout time.Duration) error { return errors.ErrUnsupported }

// Listener is a listening socket. Unsupported on this platform.
type Listener struct{}

// Listen is unsupported on this platform.
func Listen(port uint16) (*Listener, error) { return nil, errors.ErrUnsupported }

func (l *Listener) Accept() (net.Conn, error)   { return nil, errors.ErrUnsupported }
func (l *Listener) AcceptConn(conn *Conn) error { return errors.ErrUnsupported }
func (l *Listener) Addr() net.Addr              { return Addr{} }
func (l *Listener) Port() uint16                { return 0 }
func (l *Listener) Close() error                { return errors.ErrUnsupported }

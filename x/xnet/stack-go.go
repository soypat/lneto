package xnet

import (
	"context"
	"errors"
	"math"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/udp"
)

// Socket types
const (
	sockSTREAM = 0x1
	sockDGRAM  = 0x2
)

type StackGoConfig struct {
	ListenerPoolConfig TCPPoolConfig
}

func (s *StackAsync) StackGo(stackProtoBackoff lneto.BackoffStrategy, cfg StackGoConfig) StackGo {
	if stackProtoBackoff == nil || cfg.ListenerPoolConfig.NewBackoff == nil {
		panic("nil backoff to StackGo")
	}
	return s.StackBlocking(stackProtoBackoff).StackGo(cfg)
}

func (s StackBlocking) StackGo(cfg StackGoConfig) StackGo {
	sg := StackGo{
		blk:   s,
		plcfg: cfg.ListenerPoolConfig,
	}
	return sg
}

type StackGo struct {
	blk   StackBlocking
	plcfg TCPPoolConfig
}

func (s StackGo) Socket(ctx context.Context, network string, family, sotype int, laddr, raddr net.Addr) (c any, err error) {
	switch family {
	case syscall.AF_INET:
	default:
		return nil, lneto.ErrUnsupported
	}
	var local, remote netip.AddrPort
	if laddr != nil {
		local, err = parseNetAddr(laddr)
		if err != nil {
			return nil, err
		}
	}
	if raddr != nil {
		remote, err = parseNetAddr(raddr)
		if err != nil {
			return nil, err
		}
	}
	return s.SocketNetip(ctx, network, family, sotype, local, remote)
}

func (s StackGo) SocketNetip(ctx context.Context, network string, family, sotype int, laddr, raddr netip.AddrPort) (c any, err error) {
	switch family {
	case syscall.AF_INET:
	default:
		return nil, lneto.ErrUnsupported
	}
	if laddr.Port() == 0 {
		if raddr.IsValid() && raddr.Addr() != netip.IPv4Unspecified() {
			// Outbound (dial) connection: auto-assign ephemeral port.
			laddr = netip.AddrPortFrom(laddr.Addr(), uint16(49152+s.blk.async.Prand32()%16384))
		} else {
			return nil, lneto.ErrZeroSource
		}
	}
	if laddr.Addr() == netip.IPv4Unspecified() {
		// Specify address.
		laddr = netip.AddrPortFrom(netip.AddrFrom4(s.blk.async.ip4.Addr4()), laddr.Port())
	} else if laddr.Addr().Is6() {
		return nil, lneto.ErrUnsupported
	}
	switch network {
	case "udp", "udp4":
		if sotype != sockDGRAM {
			return nil, lneto.ErrUnsupported
		}
		if !raddr.IsValid() || raddr.Addr() == netip.IPv4Unspecified() {
			// LISTEN UDP: no fixed remote → PacketConn.
			var pc udppktconn
			err = pc.c.Configure(udp.PacketConnConfig{
				TxBuf:       make([]byte, s.plcfg.TxBufSize),
				RxBuf:       make([]byte, s.plcfg.RxBufSize),
				TxQueueSize: s.plcfg.QueueSize,
				RxQueueSize: s.plcfg.QueueSize,
			})
			if err != nil {
				return nil, err
			}
			err = pc.c.Open(laddr)
			if err != nil {
				return nil, err
			}
			pc.laddr = net.UDPAddr{IP: laddr.Addr().AsSlice(), Port: int(laddr.Port())}
			err = s.blk.async.RegisterListenerUDP(&pc.c)
			if err != nil {
				return nil, err
			}
			return &pc, nil
		}
		var conn udp.Conn
		err = conn.Configure(udp.ConnConfig{
			TxBuf:       make([]byte, s.plcfg.TxBufSize),
			RxBuf:       make([]byte, s.plcfg.RxBufSize),
			TxQueueSize: s.plcfg.QueueSize,
			RxQueueSize: s.plcfg.QueueSize,
		})
		if err != nil {
			return nil, err
		}
		err = s.blk.async.DialUDP(&conn, laddr.Port(), raddr)
		if err != nil {
			return nil, err
		}
		uc := udpconn{
			Conn: &conn,
			// TODO: use udpaddr until UDPAddrFromAddrPort added to tinygo.
			// https://github.com/tinygo-org/net/issues/45
			localAddr: udpaddr(laddr),
			raddr:     udpaddr(raddr),
		}
		return uc, nil
	case "tcp", "tcp4":
		if sotype != sockSTREAM {
			return nil, lneto.ErrUnsupported
		}

		if raddr.IsValid() && raddr.Addr() != netip.IPv4Unspecified() {
			var conn tcp.Conn
			// DIAL TCP: active connection a.k.a TCP Client branch.
			err = conn.Configure(tcp.ConnConfig{
				TxBuf:             make([]byte, s.plcfg.TxBufSize),
				RxBuf:             make([]byte, s.plcfg.RxBufSize),
				TxPacketQueueSize: s.plcfg.QueueSize,
			})
			if err != nil {
				return nil, err
			}
			err = s.blk.async.DialTCP(&conn, laddr.Port(), raddr)
			if err != nil {
				return nil, err
			}
			var backoffs uint
			for {
				s.blk.backoff(backoffs)
				backoffs++
				state := conn.State()
				if state == tcp.StateEstablished {
					tc := tcpconn{
						Conn:      &conn,
						localAddr: net.TCPAddrFromAddrPort(laddr),
					}
					return tc, nil
				} else if state == tcp.StateSynSent || state == tcp.StateSynRcvd || conn.InternalHandler().AwaitingSynSend() {
					if err = ctx.Err(); err != nil {
						conn.Abort()
						return nil, err
					}
				} else {
					// Unexpected state, abort and terminate connection.
					conn.Abort()
					return errTCPFailedToConnect, nil
				}
			}
		} else {
			// LISTEN TCP: passive connection. fulfills net.Listener interface.
			pool, err := NewTCPPool(s.plcfg)
			if err != nil {
				return nil, err
			}
			var l tcplistener
			l.localAddr = net.TCPAddrFromAddrPort(laddr)
			l.sleep = s.blk._backoff
			err = l.l.Reset(laddr.Port(), pool)
			if err != nil {
				return nil, err
			}
			err = s.blk.async.RegisterListenerTCP(&l.l)
			if err != nil {
				return nil, err
			}
			return &l, nil
		}
	}
	return nil, lneto.ErrUnsupported
}

// udppktconn implements [net.PacketConn] for [udp.PacketConn].
type udppktconn struct {
	c     udp.PacketConn
	laddr net.UDPAddr
	raddr net.UDPAddr
}

var _ net.PacketConn = (*udppktconn)(nil)

func (u *udppktconn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, ap, err := u.c.ReadFrom(p)
	if err != nil {
		return n, nil, err
	}
	u.raddr.IP, _ = ap.Addr().AppendBinary(u.raddr.IP[:0])
	u.raddr.Port = int(ap.Port())
	u.raddr.Zone = ""
	return n, &u.raddr, nil
}

func (u *udppktconn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	uaddr, ok := addr.(*net.UDPAddr)
	ip, ok2 := netip.AddrFromSlice(uaddr.IP)
	if !ok || !ok2 || uaddr.Port <= 0 || uaddr.Port > math.MaxUint16 {
		return 0, lneto.ErrInvalidAddr
	}
	ap := netip.AddrPortFrom(ip, uint16(uaddr.Port))
	return u.c.WriteTo(p, ap)
}

func (u *udppktconn) Close() error { return u.c.Close() }

func (u *udppktconn) LocalAddr() net.Addr { return &u.laddr }

func (u *udppktconn) SetDeadline(t time.Time) error      { return u.c.SetDeadline(t) }
func (u *udppktconn) SetReadDeadline(t time.Time) error  { return u.c.SetReadDeadline(t) }
func (u *udppktconn) SetWriteDeadline(t time.Time) error { return u.c.SetWriteDeadline(t) }
func (u *udppktconn) LnetoPacketConn() *udp.PacketConn   { return &u.c }

func (u *udppktconn) Read(b []byte) (int, error) { n, _, err := u.ReadFrom(b); return n, err }
func (u *udppktconn) Write(b []byte) (int, error) {
	return 0, errors.New("udp: Write requires WriteTo on a packet conn")
}
func (u *udppktconn) RemoteAddr() net.Addr { return nil }

type tcplistener struct {
	l         tcp.Listener
	closed    bool
	sleep     lneto.BackoffStrategy
	localAddr net.Addr
}

var _ net.Listener = (*tcplistener)(nil)

func (l *tcplistener) LnetoListener() *tcp.Listener {
	return &l.l
}
func (l *tcplistener) Addr() net.Addr {
	return l.localAddr
}

func (l *tcplistener) Shutdown() { l.Close() }

func (l *tcplistener) Accept() (net.Conn, error) {
	if l.closed {
		return nil, net.ErrClosed
	}
	var backoffs uint
	for {
		if l.closed {
			return nil, net.ErrClosed
		}
		n := l.l.NumberOfReadyToAccept()
		if n == 0 {
			backoff(l.sleep, backoffs)
			backoffs++
			continue
		}
		backoffs = 0
		c, _, err := l.l.TryAccept()
		if err != nil {
			return nil, err
		}
		cc := tcpconn{
			Conn:      c,
			localAddr: l.localAddr,
		}
		return cc, nil
	}
}

func (l *tcplistener) Close() error {
	if l.closed {
		return net.ErrClosed
	}
	err := l.l.Close()
	l.closed = true
	return err
}

type tcpconn struct {
	*tcp.Conn
	localAddr net.Addr
}

var _ net.Conn = tcpconn{}

func (c tcpconn) LnetoConn() *tcp.Conn {
	return c.Conn
}

func (c tcpconn) CloseWrite() error { return c.Conn.Close() }

func (c tcpconn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c tcpconn) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   c.Conn.RemoteAddr(),
		Port: int(c.Conn.RemotePort()),
	}
}

type udpconn struct {
	*udp.Conn
	localAddr net.Addr
	raddr     net.Addr
}

var _ net.Conn = udpconn{}

func (c udpconn) LocalAddr() net.Addr  { return c.localAddr }
func (c udpconn) RemoteAddr() net.Addr { return c.raddr }
func (c udpconn) LnetoConn() *udp.Conn { return c.Conn }

func (c udpconn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Conn.Read(b)
	return n, c.raddr, err
}

func (c udpconn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return c.Conn.Write(b) // connected UDP: always writes to dialed remote
}
func udpaddr(addr netip.AddrPort) net.Addr {
	return &net.UDPAddr{
		IP:   addr.Addr().AsSlice(),
		Zone: addr.Addr().Zone(),
		Port: int(addr.Port()),
	}
}

// parseNetAddr converts a [net.Addr] to a [netip.AddrPort]. A nil or empty IP
// (e.g. ":22" from a listen address with no host) is treated as 0.0.0.0 so
// that SocketNetip's IPv4Unspecified check can then fill in the stack's
// configured address. Without this, netip.ParseAddrPort returns "no IP".
func parseNetAddr(addr net.Addr) (netip.AddrPort, error) {
	var ip net.IP
	var port int
	switch a := addr.(type) {
	case *net.TCPAddr:
		ip, port = a.IP, a.Port
	case *net.UDPAddr:
		ip, port = a.IP, a.Port
	default:
		return netip.AddrPort{}, lneto.ErrUnsupported
	}
	if len(ip) == 0 {
		ip = net.IP{0, 0, 0, 0}
	}
	nip, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.AddrPort{}, lneto.ErrInvalidAddr
	}
	return netip.AddrPortFrom(nip.Unmap(), uint16(port)), nil
}

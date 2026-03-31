package xnet

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/tcp"
)

// Socket types
const (
	sockSTREAM = 0x1
)

type StackGoConfig struct {
	ListenerPoolConfig TCPPoolConfig
}

func (s *StackAsync) StackGo(loopSleep time.Duration, cfg StackGoConfig) StackGo {
	return s.StackBlocking(loopSleep).StackGo(cfg)
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

func (s StackGo) Socket(ctx context.Context, network string, family, sotype int, laddr, raddr net.Addr) (c interface{}, err error) {
	switch family {
	case syscall.AF_INET:
	default:
		return nil, lneto.ErrUnsupported
	}
	var local, remote netip.AddrPort
	if laddr != nil {
		local, err = netip.ParseAddrPort(laddr.String())
		if err != nil {
			return nil, err
		}
	}
	if raddr != nil {
		remote, err = netip.ParseAddrPort(raddr.String())
		if err != nil {
			return nil, err
		}
	}
	return s.SocketNetip(ctx, network, family, sotype, local, remote)
}

func (s StackGo) SocketNetip(ctx context.Context, network string, family, sotype int, laddr, raddr netip.AddrPort) (c interface{}, err error) {
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
		laddr = netip.AddrPortFrom(s.blk.async.ip.Addr(), laddr.Port())
	} else if laddr.Addr().Is6() {
		return nil, lneto.ErrUnsupported
	}
	switch network {
	case "udp", "udp4":
		return nil, lneto.ErrUnsupported
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
			for {
				time.Sleep(s.blk.loopSleep)
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
			l.sleep = s.blk.loopSleep
			err = l.l.Reset(laddr.Port(), pool)
			if err != nil {
				return nil, err
			}
			err = s.blk.async.RegisterListener(&l.l)
			if err != nil {
				return nil, err
			}
			return &l, nil
		}
	}
	return nil, lneto.ErrUnsupported
}

type tcplistener struct {
	l         tcp.Listener
	closed    bool
	sleep     time.Duration
	localAddr net.Addr
}

var _ net.Listener = (*tcplistener)(nil)

func (l *tcplistener) Addr() net.Addr {
	return l.localAddr
}

func (l *tcplistener) Accept() (net.Conn, error) {
	if l.closed {
		return nil, net.ErrClosed
	}
	for {
		n := l.l.NumberOfReadyToAccept()
		if n == 0 {
			time.Sleep(l.sleep)
			continue
		}
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

func (c tcpconn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c tcpconn) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   c.Conn.RemoteAddr(),
		Port: int(c.Conn.RemotePort()),
	}
}

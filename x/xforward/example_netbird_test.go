//go:build linux && !tinygo

package xforward_test

import (
	"context"
	csrng "crypto/rand"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/tcp/congestion"
	"github.com/soypat/lneto/tcp/sack"
	"github.com/soypat/lneto/x/xforward"
)

// Example_netbird shows how NetBird's userspace firewall (uspfilter) would drive xforward
// in place of its gVisor forwarder: routed packets that pass the ACL go in through
// InjectIncomingPacket, replies leave through the WireGuard device.
func Example_netbird() {
	fwd, err := newNetbirdForwarder(logDevice{}, 1280)
	if err != nil {
		log.Fatal(err)
	}
	defer fwd.Stop()
	// NetBird's filter calls fwd.InjectIncomingPacket(pkt) from the WireGuard
	// receive path for every routed packet that passes the route ACLs.
}

const (
	// Desktop sizes. NetBird on iOS would use 16KiB/32KiB buffers and 256 pending SYNs.
	rxSize      = 64 << 10
	txSize      = 256 << 10
	dialTimeout = 10 * time.Second // Must be below PendingTimeout.
)

// wgDevice is the part of NetBird's *wgdevice.Device the forwarder writes to.
type wgDevice interface {
	CreateOutboundPacket(pkt, dst []byte) error
}

type logDevice struct{}

func (logDevice) CreateOutboundPacket(pkt, dst []byte) error {
	addr, _ := netip.AddrFromSlice(dst)
	log.Printf("out %d bytes to %s", len(pkt), addr)
	return nil
}

// netbirdForwarder mirrors NetBird's uspfilter/forwarder.Forwarder on xforward.
type netbirdForwarder struct {
	ctx    context.Context
	cancel context.CancelFunc
	dev    wgDevice
	mtu    int
	start  time.Time // Monotonic origin for NanoTime.
	tcp    xforward.TCPForwarder
	wake   chan struct{} // Capacity 1: coalesces pump wakeups.
	// udpMu guards udp and udpConns: Demux runs on WireGuard goroutines, Encapsulate in readers.
	udpMu    sync.Mutex
	udp      xforward.UDPHandler
	udpConns []net.Conn // Indexed by UDPFlow.Slot.
	wg       sync.WaitGroup
}

func newNetbirdForwarder(dev wgDevice, mtu uint16) (*netbirdForwarder, error) {
	var key [16]byte
	if _, err := csrng.Read(key[:]); err != nil {
		return nil, err
	}
	const maxFlows = 4096
	f := &netbirdForwarder{
		dev:      dev,
		mtu:      int(mtu),
		start:    time.Now(),
		wake:     make(chan struct{}, 1),
		udpConns: make([]net.Conn, maxFlows),
	}
	nanotime := func() int64 { return int64(time.Since(f.start)) }
	err := f.tcp.Configure(xforward.TCPForwarderConfig{
		TCPHandlerConfig: xforward.TCPHandlerConfig{
			MaxFlows:          maxFlows,
			MaxPending:        1024, // NetBird's defaultMaxInFlight.
			TxPacketQueueSize: 256,
			NewPolicy: func() tcp.Policy {
				// CUBIC runs its own retransmission timer: install no rto.Timer beside it.
				// SACK goes first since CUBIC excludes options of the Policies before it.
				cubic := new(congestion.CUBIC)
				if err := cubic.Configure(congestion.CUBICConfig{Nanotime: nanotime}); err != nil {
					panic(err)
				}
				return tcp.Policies{new(sack.Policy), cubic}
			},
			PendingTimeout: 30 * time.Second,
			CloseTimeout:   30 * time.Second,
			ReleaseBuffers: nil, // NetBird: return rx, tx to size-class pools under a memory budget.
			NanoTime:       nanotime,
			Key:            key,
		},
		Wake: func() {
			select {
			case f.wake <- struct{}{}:
			default:
			}
		},
		RWBackoff: func(n uint) time.Duration {
			return min(time.Duration(n+1)*50*time.Microsecond, 5*time.Millisecond)
		},
	})
	if err != nil {
		return nil, err
	}
	err = f.udp.Configure(xforward.UDPHandlerConfig{
		MaxFlows:    maxFlows,
		IdleTimeout: 30 * time.Second, // NetBird's udpTimeout.
		NanoTime:    nanotime,
		Key:         key,
	})
	if err != nil {
		return nil, err
	}
	f.ctx, f.cancel = context.WithCancel(context.Background())
	f.wg.Add(2)
	go f.pump()
	go f.udpJanitor()
	return f, nil
}

// InjectIncomingPacket takes a routed IP packet that passed the ACL. It does not block
// and does not retain payload: TCP copies into flow buffers, UDP writes the datagram out before returning.
// ICMP never gets here: NetBird answers it in handleICMPDirect.
func (f *netbirdForwarder) InjectIncomingPacket(payload []byte) error {
	if f.ctx.Err() != nil {
		return net.ErrClosed
	}
	var vld lneto.Validator // Local: calls run concurrently across WireGuard peers.
	pkt, err := xforward.ValidatePacket(payload, &vld)
	if err != nil {
		return err
	}
	switch pkt.Proto() {
	case lneto.IPProtoTCP:
		flow, isNew, err := f.tcp.Demux(pkt)
		if isNew {
			f.wg.Add(1)
			go f.handleTCP(flow) // Dialing blocks: keep it off the WireGuard goroutine.
		}
		return err
	case lneto.IPProtoUDP:
		return f.handleUDP(pkt)
	}
	return lneto.ErrUnsupported
}

// handleTCP dials upstream before completing the peer's handshake, as NetBird does with gVisor's ForwarderRequest.
func (f *netbirdForwarder) handleTCP(flow xforward.TCPFlow) {
	defer f.wg.Done()
	// NetBird: flow-start event; determineDialAddr maps own IP to loopback in netstack mode.
	ctx, cancel := context.WithTimeout(f.ctx, dialTimeout)
	out, err := new(net.Dialer).DialContext(ctx, "tcp", flow.ID.Local.String())
	cancel()
	if err != nil {
		f.tcp.Reject(flow) // Peer sees RST|ACK, like ForwarderRequest.Complete(true).
		return
	}
	in, err := f.tcp.Accept(flow, make([]byte, rxSize), make([]byte, txSize))
	if err != nil {
		out.Close() // SYN expired or peer reset while dialing.
		return
	}
	toUpstream, toPeer := relay(f.ctx, in, out)
	rxPkts, txPkts, _ := in.Stats() // Before Close: a released flow may be reaped any time.
	in.Close()
	out.Close()
	// NetBird: flow-end event with toUpstream, toPeer, rxPkts, txPkts; DeleteRuleID.
	_, _, _, _ = toUpstream, toPeer, rxPkts, txPkts
}

// relay copies both ways and propagates half-close, like NetBird's netrelay.Relay
// minus its idle timeout. Closing is left to the caller.
func relay(ctx context.Context, a, b net.Conn) (aToB, bToA int64) {
	stop := context.AfterFunc(ctx, func() { a.Close(); b.Close() })
	defer stop()
	done := make(chan struct{})
	go func() {
		bToA, _ = io.Copy(a, b)
		closeWrite(a)
		close(done)
	}()
	aToB, _ = io.Copy(b, a)
	closeWrite(b)
	<-done
	return aToB, bToA
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}

func (f *netbirdForwarder) handleUDP(pkt xforward.Packet) error {
	f.udpMu.Lock()
	defer f.udpMu.Unlock()
	flow, payload, isNew, err := f.udp.Demux(pkt)
	if err != nil {
		return err
	}
	if isNew {
		// NetBird: flow-start event. Dialing UDP has no handshake so it runs inline, as in NetBird.
		conn, err := net.Dial("udp", flow.ID.Local.String())
		if err != nil {
			f.udp.Remove(flow)
			return err
		}
		f.udpConns[flow.Slot()] = conn
		f.wg.Add(1)
		go f.udpReader(flow, conn)
	}
	_, err = f.udpConns[flow.Slot()].Write(payload)
	return err
}

// udpReader frames upstream datagrams in place behind the flow's IP+UDP headers.
// Datagrams larger than the MTU are truncated by the read, as in NetBird today.
func (f *netbirdForwarder) udpReader(flow xforward.UDPFlow, conn net.Conn) {
	defer f.wg.Done()
	buf := make([]byte, f.mtu)
	hl := flow.HeaderLen()
	dst := flow.ID.Remote.Addr().AsSlice()
	for {
		n, err := conn.Read(buf[hl:])
		if err != nil {
			return // Closed by udpJanitor or Stop.
		}
		f.udpMu.Lock()
		n, err = f.udp.Encapsulate(buf, 0, flow, n)
		f.udpMu.Unlock()
		if err != nil {
			return // Flow expired or removed.
		}
		f.dev.CreateOutboundPacket(buf[:n], dst)
	}
}

// pump emits TCP segments and drives retransmit and timeout timers.
func (f *netbirdForwarder) pump() {
	defer f.wg.Done()
	out := make([]byte, f.mtu)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		n, _ := f.tcp.Encapsulate(out, 0)
		if n > 0 {
			f.dev.CreateOutboundPacket(out[:n], ipDst(out[:n])) // NetBird: capture.Offer(out[:n], true).
			continue
		}
		wait := time.Hour
		if d := f.tcp.NextDeadline(); d != 0 {
			wait = time.Duration(d - int64(time.Since(f.start)))
		}
		timer.Reset(wait)
		select {
		case <-f.wake:
		case <-timer.C:
		case <-f.ctx.Done():
			return
		}
	}
}

// udpJanitor closes sockets of idle UDP flows, ending their readers.
func (f *netbirdForwarder) udpJanitor() {
	defer f.wg.Done()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
		case <-f.ctx.Done():
			return
		}
		f.udpMu.Lock()
		for {
			flow, ok := f.udp.NextExpired()
			if !ok {
				break
			}
			f.udpConns[flow.Slot()].Close() // NetBird: flow-end event.
			f.udpConns[flow.Slot()] = nil
		}
		f.udpMu.Unlock()
	}
}

// Stop tears down every flow and waits for all goroutines to exit.
func (f *netbirdForwarder) Stop() {
	f.cancel()
	f.tcp.Abort() // Blocked FlowConn calls return net.ErrClosed.
	f.udpMu.Lock()
	for i, conn := range f.udpConns {
		if conn != nil {
			conn.Close()
			f.udpConns[i] = nil
		}
	}
	f.udp.Abort()
	f.udpMu.Unlock()
	f.wg.Wait()
}

// ipDst returns the destination address of an IP packet.
func ipDst(pkt []byte) []byte {
	if pkt[0]>>4 == 4 {
		return pkt[16:20]
	}
	return pkt[24:40]
}

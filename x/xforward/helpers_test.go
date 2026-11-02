package xforward_test

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/ipv6"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/udp"
	"github.com/soypat/lneto/x/xforward"
)

const testMTU = 1500

var testKey = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

// testBackoff waits briefly so blocked FlowConn calls retry quickly in tests.
var testBackoff lneto.BackoffStrategy = func(n uint) time.Duration {
	return min(time.Duration(n+1)*20*time.Microsecond, time.Millisecond)
}

// testClock is a manually advanced monotonic clock.
type testClock struct{ now int64 }

func (c *testClock) nanotime() int64 { return c.now }

func testTCPConfig(nanotime func() int64) xforward.TCPHandlerConfig {
	return xforward.TCPHandlerConfig{
		MaxFlows:          4,
		MaxPending:        4,
		TxPacketQueueSize: 32,
		PendingTimeout:    time.Second,
		CloseTimeout:      time.Second,
		NanoTime:          nanotime,
		Key:               testKey,
	}
}

// pattern returns n bytes unlikely to line up with a shifted copy of themselves.
func pattern(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i) ^ byte(i>>8)*31 ^ seed
	}
	return b
}

// buildIP returns an IP packet from src to dst carrying transport with valid checksums.
// IPv6 packets carry one 8-byte extension header of each type in exts before transport.
func buildIP(src, dst netip.Addr, proto lneto.IPProto, transport []byte, exts ...lneto.IPProto) []byte {
	var crc lneto.CRC791
	var pkt []byte
	var toff int
	if src.Is4() {
		toff = 20
		pkt = make([]byte, toff+len(transport))
		ifrm, _ := ipv4.NewFrame(pkt)
		ifrm.SetVersionAndIHL(4, 5)
		ifrm.SetTotalLength(uint16(len(pkt)))
		ifrm.SetTTL(64)
		ifrm.SetProtocol(proto)
		*ifrm.SourceAddr() = src.As4()
		*ifrm.DestinationAddr() = dst.As4()
		ifrm.SetCRC(ifrm.CalculateHeaderCRC())
		if proto == lneto.IPProtoUDP {
			ifrm.CRCWriteUDPPseudo(&crc, uint16(len(transport)))
		} else {
			ifrm.CRCWriteTCPPseudo(&crc)
		}
	} else {
		toff = 40 + 8*len(exts)
		pkt = make([]byte, toff+len(transport))
		i6, _ := ipv6.NewFrame(pkt)
		i6.SetVersionTrafficAndFlow(6, 0, 0)
		i6.SetPayloadLength(uint16(len(pkt) - 40))
		i6.SetHopLimit(64)
		*i6.SourceAddr() = src.As16()
		*i6.DestinationAddr() = dst.As16()
		next := proto
		for i := len(exts) - 1; i >= 0; i-- {
			off := 40 + 8*i
			pkt[off] = byte(next) // Hdr Ext Len 0: 8 bytes. A PadN option fills the rest.
			pkt[off+2], pkt[off+3] = 1, 4
			next = exts[i]
		}
		i6.SetNextHeader(next)
		crc.WriteEven(pkt[8:40])
		crc.AddUint32(uint32(len(transport)))
		crc.AddUint32(uint32(proto))
	}
	t := pkt[toff:]
	copy(t, transport)
	switch proto {
	case lneto.IPProtoTCP:
		binary.BigEndian.PutUint16(t[16:], 0)
		binary.BigEndian.PutUint16(t[16:], crc.PayloadSum16(t))
	case lneto.IPProtoUDP:
		binary.BigEndian.PutUint16(t[6:], 0)
		binary.BigEndian.PutUint16(t[6:], lneto.NeverZeroSum(crc.PayloadSum16(t)))
	}
	return pkt
}

// tcpSeg returns a TCP segment with a zero checksum.
func tcpSeg(sport, dport uint16, seq, ack tcp.Value, flags tcp.Flags, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	tfrm, _ := tcp.NewFrame(b)
	tfrm.SetSourcePort(sport)
	tfrm.SetDestinationPort(dport)
	tfrm.SetSegment(tcp.Segment{SEQ: seq, ACK: ack, WND: 1024, Flags: flags}, 5)
	copy(b[20:], payload)
	return b
}

// udpDgram returns a UDP datagram with a zero checksum.
func udpDgram(sport, dport uint16, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	ufrm, _ := udp.NewFrame(b)
	ufrm.SetSourcePort(sport)
	ufrm.SetDestinationPort(dport)
	ufrm.SetLength(uint16(len(b)))
	copy(b[8:], payload)
	return b
}

func mustValidate(t testing.TB, pkt []byte) xforward.Packet {
	t.Helper()
	var vld lneto.Validator
	p, err := xforward.ValidatePacket(pkt, &vld)
	if err != nil {
		t.Fatalf("ValidatePacket: %v", err)
	}
	return p
}

// udpPkt returns a validated UDP packet from src to dst.
func udpPkt(t testing.TB, src, dst, payload string) xforward.Packet {
	t.Helper()
	s, d := netip.MustParseAddrPort(src), netip.MustParseAddrPort(dst)
	return mustValidate(t, buildIP(s.Addr(), d.Addr(), lneto.IPProtoUDP, udpDgram(s.Port(), d.Port(), []byte(payload))))
}

// tcpOf returns the TCP frame of a packet.
func tcpOf(t testing.TB, pkt []byte) tcp.Frame {
	t.Helper()
	vp := mustValidate(t, pkt)
	tfrm, _ := tcp.NewFrame(vp.RawData()[vp.TransportOffset():])
	return tfrm
}

// tcpPeer is an overlay peer: a tcp.Handler dialing dst from addr.
type tcpPeer struct {
	h    tcp.Handler
	addr netip.AddrPort
	dst  netip.AddrPort
	vld  lneto.Validator
}

func newPeer(t testing.TB, addr, dst string, bufSize int) *tcpPeer {
	t.Helper()
	p := &tcpPeer{addr: netip.MustParseAddrPort(addr), dst: netip.MustParseAddrPort(dst)}
	err := p.h.SetBuffers(make([]byte, bufSize), make([]byte, bufSize), 32)
	if err == nil {
		err = p.h.OpenActive(p.addr.Port(), p.dst.Port(), 1000)
	}
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// send returns the next IP packet the peer emits, or nil.
func (p *tcpPeer) send() []byte {
	var buf [testMTU]byte
	hl := 20
	if p.addr.Addr().Is6() {
		hl = 40
	}
	n, _ := p.h.Send(buf[hl:])
	if n == 0 {
		return nil
	}
	return buildIP(p.addr.Addr(), p.dst.Addr(), lneto.IPProtoTCP, buf[hl:hl+n])
}

// deliver feeds a forwarder packet to the peer after checking it is valid and sent dst→addr.
func (p *tcpPeer) deliver(pkt []byte) error {
	vp, err := xforward.ValidatePacket(pkt, &p.vld)
	if err != nil {
		return fmt.Errorf("invalid packet from forwarder: %w", err)
	} else if id := vp.ID(); vp.Proto() != lneto.IPProtoTCP || id.Local != p.addr || id.Remote != p.dst {
		return fmt.Errorf("misaddressed packet %v", id)
	}
	p.h.Recv(vp.RawData()[vp.TransportOffset():]) // Errors are flow control drops or teardown.
	return nil
}

// tcpForwarder is implemented by both TCPHandler and TCPForwarder.
type tcpForwarder interface {
	Demux(xforward.Packet) (xforward.TCPFlow, bool, error)
	Encapsulate(carrierData []byte, offsetToIP int) (int, error)
}

// encap returns a copy of the next packet fwd emits, or nil.
func encap(t testing.TB, fwd tcpForwarder) []byte {
	t.Helper()
	var out [testMTU]byte
	n, err := fwd.Encapsulate(out[:], 0)
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		return nil
	}
	return append([]byte(nil), out[:n]...)
}

// exchange moves packets between fwd and p until both are idle.
func exchange(t testing.TB, fwd tcpForwarder, p *tcpPeer) {
	t.Helper()
	for range 10_000 {
		moved := false
		if pkt := p.send(); pkt != nil {
			if _, isNew, _ := fwd.Demux(mustValidate(t, pkt)); isNew {
				t.Fatal("unexpected new flow")
			}
			moved = true
		}
		if pkt := encap(t, fwd); pkt != nil {
			if err := p.deliver(pkt); err != nil {
				t.Fatal(err)
			}
			moved = true
		}
		if !moved {
			return
		}
	}
	t.Fatal("exchange did not settle")
}

// tcpEnv drives a TCPHandler with a manual clock.
type tcpEnv struct {
	clock testClock
	fwd   xforward.TCPHandler
}

func newTCPEnv(t testing.TB, mod func(*tcpEnv, *xforward.TCPHandlerConfig)) *tcpEnv {
	t.Helper()
	env := new(tcpEnv)
	cfg := testTCPConfig(env.clock.nanotime)
	if mod != nil {
		mod(env, &cfg)
	}
	if err := env.fwd.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	return env
}

func (e *tcpEnv) demux(t testing.TB, pkt []byte) (xforward.TCPFlow, bool, error) {
	t.Helper()
	return e.fwd.Demux(mustValidate(t, pkt))
}

// connect completes p's handshake, accepting it with rx and tx.
func (e *tcpEnv) connect(t testing.TB, p *tcpPeer, rx, tx []byte) xforward.TCPFlow {
	t.Helper()
	flow, isNew, err := e.demux(t, p.send())
	if err != nil || !isNew {
		t.Fatalf("SYN: isNew=%v err=%v", isNew, err)
	}
	if err = e.fwd.Accept(flow, rx, tx); err != nil {
		t.Fatal(err)
	}
	exchange(t, &e.fwd, p)
	if st := p.h.State(); st != tcp.StateEstablished {
		t.Fatalf("peer state %s, want established", st)
	}
	return flow
}

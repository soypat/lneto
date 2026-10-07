package xnet

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/udp"
)

// FuzzStackPair drives two stacks with independent MTUs through a script of
// pings, TCP and UDP traffic and closes. Neither stack may panic, write past
// its MTU, fail to settle or return an unexpected error from ingress or egress.
// Pings and TCP writes must be accepted unless refused for a full queue or a
// closed connection, and the TCP bytes read must be a prefix of those written.
// Delivery of every byte is not required: no retransmission timer runs, so a
// segment dropped for a full buffer is never resent. Pings may be larger than
// the receiver's MTU.
func FuzzStackPair(f *testing.F) {
	f.Add(int64(1), uint16(1500), uint16(1500), []byte{0, 100, 2, 50, 3, 0, 4, 10, 5, 0})
	f.Add(int64(2), uint16(1500), uint16(576), []byte{0, 255, 1, 255, 2, 255, 3, 0})
	f.Add(int64(3), uint16(300), uint16(1500), []byte{2, 200, 2, 200, 3, 0, 6, 0, 3, 0})
	f.Add(int64(0x0f0f), uint16(1500-256), uint16(576-256), []byte{0, 100}) // Echo reply above the MTU, #236.
	f.Fuzz(func(t *testing.T, seed int64, mtu1, mtu2 uint16, script []byte) {
		if len(script) > 64 {
			script = script[:64]
		}
		testStackPair(t, seed, mtu1, mtu2, script)
	})
}

func testStackPair(t *testing.T, seed int64, mtu1, mtu2 uint16, script []byte) {
	const minMTU = 256
	clamp := func(m uint16) uint16 { return minMTU + m%(ethernet.MaxMTU-minMTU+1) }
	var stacks [2]StackAsync
	for i, mtu := range []uint16{clamp(mtu1), clamp(mtu2)} {
		id := byte(i + 1)
		randSeed := seed + int64(i)
		if randSeed == 0 {
			randSeed = 1 // Zero is invalid without an entropy source.
		}
		err := stacks[i].Reset(StackConfig{
			Hostname:          "pair-" + string('0'+id),
			RandSeed:          randSeed,
			StaticAddress4:    [4]byte{10, 0, 0, id},
			HardwareAddress:   [6]byte{0xbe, 0xef, 0, 0, 0, id},
			MTU:               mtu,
			MaxActiveTCPPorts: 1,
			MaxActiveUDPPorts: 1,
			ICMPQueueLimit:    1 + int(uint64(seed)>>(8*i)%16), // Above 8 the ring outgrows a small MTU.
			Nanotime:          func() int64 { return 1 },
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := stacks[i].EnableICMP(true); err != nil {
			t.Fatal(err)
		}
	}
	s1, s2 := &stacks[0], &stacks[1]
	s1.SetGatewayHardwareAddr(s2.HardwareAddr())
	s2.SetGatewayHardwareAddr(s1.HardwareAddr())
	addr1, addr2 := netip.AddrFrom4(s1.Addr4()), netip.AddrFrom4(s2.Addr4())

	c1, c2 := newTestTCPConn(t, 512, 4), newTestTCPConn(t, 512, 4)
	if err := s2.ListenTCP4(c2, 80); err != nil {
		t.Fatal(err)
	}
	if err := s1.DialTCP(c1, 1337, netip.AddrPortFrom(addr2, 80)); err != nil {
		t.Fatal(err)
	}
	var u1, u2 udp.Conn
	for i, u := range []*udp.Conn{&u1, &u2} {
		err := u.Configure(udp.ConnConfig{RxBuf: make([]byte, 512), TxBuf: make([]byte, 512), RxQueueSize: 2, TxQueueSize: 2, RWBackoff: backoffYield, MTU: uint16(stacks[i].MTU())})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := s1.DialUDP(&u1, 5000, netip.AddrPortFrom(addr2, 5001)); err != nil {
		t.Fatal(err)
	}
	if err := s2.DialUDP(&u2, 5001, netip.AddrPortFrom(addr1, 5000)); err != nil {
		t.Fatal(err)
	}

	var written, read []byte
	var serial byte
	closed := false
	buf := make([]byte, ethernet.MaxFrameLength)
	pump := func(step int) {
		for range 32 {
			moved := false
			for _, dir := range [2][2]*StackAsync{{s1, s2}, {s2, s1}} {
				// Exactly one frame of the sender's MTU, with no spare capacity,
				// so a write past the MTU panics instead of going unnoticed.
				frame := make([]byte, dir[0].MTU()+ethernet.MaxOverheadSize)
				frame = frame[:len(frame):len(frame)]
				n, err := dir[0].EgressEthernet(frame)
				if err != nil {
					t.Fatalf("step %d: %s egress: %v", step, dir[0].Hostname(), err)
				} else if n == 0 {
					continue
				}
				err = dir[1].IngressEthernet(frame[:n])
				dropped := err == lneto.ErrPacketDrop || err == lneto.ErrExhausted || err == lneto.ErrBufferFull
				if err != nil && !dropped {
					t.Fatalf("step %d: %s ingress: %v", step, dir[1].Hostname(), err)
				}
				moved = true
			}
			if !moved {
				return
			}
		}
		t.Fatalf("step %d: traffic did not settle", step)
	}
	readTCP := func(step int) {
		if c2.BufferedInput() == 0 {
			return // Read blocks.
		}
		n, _ := c2.Read(buf)
		read = append(read, buf[:n]...)
		if !bytes.HasPrefix(written, read) {
			t.Fatalf("step %d: TCP read %x, not a prefix of written %x", step, read, written)
		}
	}
	pump(-1)
	pattern := []byte("lneto-ping")
	for i := 0; i+1 < len(script); i += 2 {
		action, arg := script[i]%7, int(script[i+1])
		switch action {
		case 0, 1: // Ping, up to the sender's MTU.
			src, dst := s1, s2
			if action == 1 {
				src, dst = s2, s1
			}
			size := uint16(len(pattern) + arg*(src.MTU()-28-len(pattern))/255)
			if _, err := src.icmp.PingStart(dst.Addr4(), pattern, size); err != nil && err != lneto.ErrExhausted {
				t.Fatalf("step %d: ping: %v", i, err)
			}
		case 2: // TCP write.
			data := make([]byte, min(1+arg, c1.FreeOutput()))
			for k := range data {
				data[k] = serial
				serial++
			}
			n, err := c1.Write(data)
			if !closed && (err != nil || n != len(data)) {
				t.Fatalf("step %d: TCP write of %d octets that fit: %d, %v", i, len(data), n, err)
			}
			written = append(written, data[:n]...)
		case 3:
			readTCP(i)
		case 4: // UDP write below either MTU. A full queue refuses it, so its error is not checked.
			u1.Write(make([]byte, 1+arg%200))
		case 5:
			if u2.BufferedInput() > 0 {
				u2.Read(buf)
			}
		case 6:
			if err := c1.Close(); err != nil && !closed {
				t.Fatalf("step %d: close: %v", i, err)
			}
			closed = true
		}
		pump(i)
	}
	pump(len(script))
	readTCP(len(script))
}

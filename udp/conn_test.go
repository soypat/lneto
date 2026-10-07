package udp

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
)

// makeUDPFrame builds a minimal UDP frame with the given ports and payload.
func makeUDPFrame(src, dst uint16, payload []byte) []byte {
	buf := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(buf[0:2], src)
	binary.BigEndian.PutUint16(buf[2:4], dst)
	binary.BigEndian.PutUint16(buf[4:6], uint16(8+len(payload)))
	copy(buf[8:], payload)
	return buf
}

func newTestConn(t *testing.T) *Conn {
	t.Helper()
	var conn Conn
	err := conn.Configure(ConnConfig{
		RxBuf:       make([]byte, 256),
		TxBuf:       make([]byte, 256),
		RxQueueSize: 4,
		TxQueueSize: 4,
		RWBackoff:   backoffYield,
		MTU:         ethernet.MaxMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = conn.Open(1234, netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 1}), 8080))
	if err != nil {
		t.Fatal(err)
	}
	return &conn
}

func TestConn_WriteEncapsulateRoundtrip(t *testing.T) {
	conn := newTestConn(t)
	payload := []byte("hello udp")
	n, err := conn.Write(payload)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) {
		t.Fatalf("wrote %d, want %d", n, len(payload))
	}

	var buf [128]byte
	n, err = conn.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal(err)
	}
	wantLen := 8 + len(payload) // UDP header + payload
	if n != wantLen {
		t.Fatalf("encapsulated %d, want %d", n, wantLen)
	}
	ufrm, err := NewFrame(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if !internal.BytesEqual(ufrm.Payload(), payload) {
		t.Fatalf("encapsulated payload mismatch")
	}

	// No more data pending.
	n, err = conn.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("expected no pending data, got %d", n)
	}
}

func TestConn_DemuxReadRoundtrip(t *testing.T) {
	conn := newTestConn(t)
	payload := []byte("incoming datagram")
	frame := makeUDPFrame(8080, 1234, payload) // remote:8080 -> local:1234
	err := conn.Demux(frame, 0)
	if err != nil {
		t.Fatal(err)
	}

	var buf [64]byte
	n, err := conn.Read(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) {
		t.Fatalf("read %d, want %d", n, len(payload))
	}
	if !internal.BytesEqual(buf[:n], payload) {
		t.Fatal("read data mismatch")
	}
}

func TestConn_MultipleDatagrams(t *testing.T) {
	conn := newTestConn(t)
	messages := []string{"first", "second", "third"}
	for _, msg := range messages {
		frame := makeUDPFrame(8080, 1234, []byte(msg))
		err := conn.Demux(frame, 0)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Read back in order.
	var buf [64]byte
	for _, want := range messages {
		n, err := conn.Read(buf[:])
		if err != nil {
			t.Fatal(err)
		}
		got := string(buf[:n])
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}

func TestConn_ReadTruncates(t *testing.T) {
	conn := newTestConn(t)
	payload := []byte("a_longer_datagram")
	frame := makeUDPFrame(8080, 1234, payload)
	err := conn.Demux(frame, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Read into small buffer: truncates, discards remainder.
	var buf [4]byte
	n, err := conn.Read(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	if n != len(buf) {
		t.Fatalf("read %d, want %d", n, len(buf))
	}
	if !internal.BytesEqual(buf[:], payload[:4]) {
		t.Fatal("truncated data mismatch")
	}

	// Next Demux+Read should work cleanly after truncation.
	payload2 := []byte("ok")
	frame2 := makeUDPFrame(8080, 1234, payload2)
	err = conn.Demux(frame2, 0)
	if err != nil {
		t.Fatal(err)
	}
	var buf2 [64]byte
	n, err = conn.Read(buf2[:])
	if err != nil {
		t.Fatal(err)
	}
	if !internal.BytesEqual(buf2[:n], payload2) {
		t.Fatal("post-truncation read mismatch")
	}
}

func TestConn_DemuxExhausted(t *testing.T) {
	conn := newTestConn(t) // queue size 4
	for i := range 4 {
		frame := makeUDPFrame(8080, 1234, []byte{byte(i)})
		err := conn.Demux(frame, 0)
		if err != nil {
			t.Fatal(err)
		}
	}
	// 5th should fail.
	frame := makeUDPFrame(8080, 1234, []byte{0xff})
	err := conn.Demux(frame, 0)
	if err == nil {
		t.Fatal("expected error on exhausted rx queue")
	}
}

func TestConn_ClosedBehavior(t *testing.T) {
	conn := newTestConn(t)
	conn.Close()

	_, err := conn.Write([]byte("data"))
	if err == nil {
		t.Fatal("expected error writing to closed conn")
	}

	err = conn.Demux([]byte("data"), 0)
	if err == nil {
		t.Fatal("expected error demuxing to closed conn")
	}
}

func TestConn_EncapsulateMultiple(t *testing.T) {
	conn := newTestConn(t)
	msgs := []string{"aaa", "bbb"}
	for _, msg := range msgs {
		_, err := conn.Write([]byte(msg))
		if err != nil {
			t.Fatal(err)
		}
	}

	var buf [128]byte
	for _, want := range msgs {
		n, err := conn.Encapsulate(buf[:], -1, 0)
		if err != nil {
			t.Fatal(err)
		}
		ufrm, err := NewFrame(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		got := string(ufrm.Payload())
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}

// TestConn_OversizedDatagramStallsQueue checks that Write rejects a datagram
// that would exceed the MTU, so it never reaches the tx queue where it would
// wedge the datagrams queued behind it (Encapsulate is passed an MTU-bound buffer).
func TestConn_OversizedDatagramStallsQueue(t *testing.T) {
	const (
		mtu         = 92
		carrierSize = mtu - 20 // UDP frame budget after IPv4 header.
	)
	var conn Conn
	err := conn.Configure(ConnConfig{
		RxBuf:       make([]byte, 256),
		TxBuf:       make([]byte, 256),
		RxQueueSize: 4,
		TxQueueSize: 4,
		RWBackoff:   backoffYield,
		MTU:         mtu,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = conn.Open(1234, netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 1}), 8080))
	if err != nil {
		t.Fatal(err)
	}
	maxPayload := make([]byte, carrierSize-sizeHeader)
	oversized := make([]byte, len(maxPayload)+1)
	_, err = conn.Write(oversized)
	if err == nil {
		t.Fatal("expected error writing datagram exceeding MTU")
	}
	small := []byte("small")
	for _, payload := range [][]byte{maxPayload, small} {
		_, err = conn.Write(payload)
		if err != nil {
			t.Fatal(err)
		}
	}

	var buf [carrierSize]byte
	for _, want := range [][]byte{maxPayload, small} {
		n, err := conn.Encapsulate(buf[:], -1, 0)
		if err != nil {
			t.Fatal(err)
		} else if n == 0 {
			t.Fatal("datagram never sent: tx queue stalled")
		}
		ufrm, err := NewFrame(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		got := ufrm.Payload()
		if !internal.BytesEqual(got, want) {
			t.Fatalf("got payload of length %d, want length %d", len(got), len(want))
		}
	}
}

func TestConn_FrameOffset(t *testing.T) {
	conn := newTestConn(t)
	// Demux with an offset simulating IP header before the UDP frame.
	udpFrame := makeUDPFrame(8080, 1234, []byte("hi"))
	carrier := make([]byte, 8+len(udpFrame)) // 8 bytes of "IP header" prefix
	copy(carrier[8:], udpFrame)
	err := conn.Demux(carrier, 8)
	if err != nil {
		t.Fatal(err)
	}
	var buf [8]byte
	n, err := conn.Read(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hi" {
		t.Fatalf("got %q, want %q", string(buf[:n]), "hi")
	}
}

func backoffYield(backoffs uint) time.Duration {
	return lneto.BackoffFlagGosched
}

// TestConn_MTUBounds checks Configure accepts every MTU that fits an IPv6 and UDP
// header, and that Write limits payloads by the IP family of the remote address.
func TestConn_MTUBounds(t *testing.T) {
	var (
		addr4 = netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 1}), 8080)
		addr6 = netip.AddrPortFrom(netip.MustParseAddr("2001:db8::1"), 8080)
	)
	tests := []struct {
		name          string
		mtu           uint16
		raddr         netip.AddrPort
		maxPayload    int
		wantConfigErr bool
	}{
		{name: "zero", mtu: 0, wantConfigErr: true},
		{name: "below-ipv6-udp-headers", mtu: 47, wantConfigErr: true},
		{name: "ipv6-udp-headers-only", mtu: 48, raddr: addr6, maxPayload: 0},
		{name: "ethernet-min-ipv4", mtu: ethernet.MinimumMTU, raddr: addr4, maxPayload: ethernet.MinimumMTU - 28},
		{name: "ethernet-min-ipv6", mtu: ethernet.MinimumMTU, raddr: addr6, maxPayload: ethernet.MinimumMTU - 48},
		{name: "max-ipv4", mtu: 65535, raddr: addr4, maxPayload: 65535 - 28},
		{name: "max-ipv6", mtu: 65535, raddr: addr6, maxPayload: 65535 - 48},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var conn Conn
			err := conn.Configure(ConnConfig{
				RxBuf:       make([]byte, 256),
				TxBuf:       make([]byte, 1<<16), // Larger than any payload so only the MTU limits Write.
				RxQueueSize: 4,
				TxQueueSize: 4,
				RWBackoff:   backoffYield,
				MTU:         tc.mtu,
			})
			if tc.wantConfigErr {
				if err == nil {
					t.Fatalf("Configure(MTU=%d) succeeded, want error", tc.mtu)
				}
				return
			} else if err != nil {
				t.Fatalf("Configure(MTU=%d): %v", tc.mtu, err)
			}
			err = conn.Open(1234, tc.raddr)
			if err != nil {
				t.Fatal(err)
			}
			_, err = conn.Write(make([]byte, tc.maxPayload+1))
			if err != lneto.ErrShortBuffer {
				t.Fatalf("Write(%d) got err=%v, want %v", tc.maxPayload+1, err, lneto.ErrShortBuffer)
			}
			n, err := conn.Write(make([]byte, tc.maxPayload))
			if err != nil || n != tc.maxPayload {
				t.Fatalf("Write(%d) got n=%d err=%v", tc.maxPayload, n, err)
			}
		})
	}
}

// TestConn_MTUReopenFamily checks the payload limit is recomputed from the MTU
// when a conn is reopened to a remote of a different IP family.
func TestConn_MTUReopenFamily(t *testing.T) {
	const mtu = ethernet.MaxMTU
	conn := newTestConnBuf(t, mtu, 2048)
	payload := make([]byte, mtu-28) // Fits IPv4, exceeds IPv6 by 20 bytes.
	err := conn.Open(1234, netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 1}), 8080))
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.Write(payload)
	if err != nil {
		t.Fatal("IPv4 write:", err)
	}
	conn.Close()
	conn.Abort()
	err = conn.Open(1234, netip.AddrPortFrom(netip.MustParseAddr("2001:db8::1"), 8080))
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.Write(payload)
	if err != lneto.ErrShortBuffer {
		t.Fatalf("IPv6 write got err=%v, want %v", err, lneto.ErrShortBuffer)
	}
	_, err = conn.Write(payload[:mtu-48])
	if err != nil {
		t.Fatal("IPv6 write:", err)
	}
}

func newTestConnBuf(t *testing.T, mtu uint16, bufSize int) *Conn {
	t.Helper()
	var conn Conn
	err := conn.Configure(ConnConfig{
		RxBuf:       make([]byte, bufSize),
		TxBuf:       make([]byte, bufSize),
		RxQueueSize: 4,
		TxQueueSize: 4,
		RWBackoff:   backoffYield,
		MTU:         mtu,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &conn
}

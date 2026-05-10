package udp

import (
	"net/netip"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

func newTestSIMO(t *testing.T, localPort uint16) *MuxHandlerSIMO {
	t.Helper()
	var ms MuxHandlerSIMO
	err := ms.Configure(localPort, MuxConfig{
		RxBuf:       make([]byte, 256),
		TxBuf:       make([]byte, 256),
		RxQueueSize: 4,
		TxQueueSize: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &ms
}

func TestMuxSIMO_Configure_ZeroPort(t *testing.T) {
	var ms MuxHandlerSIMO
	err := ms.Configure(0, MuxConfig{
		RxBuf:       make([]byte, 256),
		TxBuf:       make([]byte, 256),
		RxQueueSize: 4,
		TxQueueSize: 4,
	})
	if err != lneto.ErrZeroSource {
		t.Fatalf("want ErrZeroSource, got %v", err)
	}
}

func TestMuxSIMO_LocalPort(t *testing.T) {
	ms := newTestSIMO(t, 1234)
	if ms.LocalPort() != 1234 {
		t.Fatalf("want 1234, got %d", ms.LocalPort())
	}
}

func TestMuxSIMO_WriteToEncapsulateRoundtrip(t *testing.T) {
	const localPort = 1234
	raddr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 1}), 8080)
	ms := newTestSIMO(t, localPort)
	payload := []byte("hello mux")
	if err := ms.WriteTo(payload, raddr); err != nil {
		t.Fatal(err)
	}
	var buf [128]byte
	n, err := ms.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if want := 8 + len(payload); n != want {
		t.Fatalf("encapsulated %d bytes, want %d", n, want)
	}
	ufrm, err := NewFrame(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if ufrm.SourcePort() != localPort {
		t.Fatalf("src port %d, want %d", ufrm.SourcePort(), localPort)
	}
	if ufrm.DestinationPort() != raddr.Port() {
		t.Fatalf("dst port %d, want %d", ufrm.DestinationPort(), raddr.Port())
	}
	if !internal.BytesEqual(ufrm.Payload(), payload) {
		t.Fatal("payload mismatch")
	}
	// No more pending.
	n, err = ms.Encapsulate(buf[:], -1, 0)
	if err != nil || n != 0 {
		t.Fatalf("expected empty encapsulate, got n=%d err=%v", n, err)
	}
}

func TestMuxSIMO_DemuxReadNextRoundtrip(t *testing.T) {
	const localPort = 1234
	const remotePort = 8080
	ms := newTestSIMO(t, localPort)
	payload := []byte("incoming")
	frame := makeUDPFrame(remotePort, localPort, payload)
	if err := ms.Demux(frame, 0); err != nil {
		t.Fatal(err)
	}
	var buf [64]byte
	n, completeRead, raddr := ms.ReadNext(buf[:])
	if n != len(payload) {
		t.Fatalf("read %d bytes, want %d", n, len(payload))
	}
	if !completeRead {
		t.Fatal("want completeRead=true")
	}
	if !internal.BytesEqual(buf[:n], payload) {
		t.Fatal("payload mismatch")
	}
	if raddr.IsValid() {
		t.Fatal("want zero raddr when no IP carrier (frameOffset=0 < 20)")
	}
}

func TestMuxSIMO_DemuxFiltersMismatch(t *testing.T) {
	ms := newTestSIMO(t, 1234)
	frame := makeUDPFrame(8080, 9999, []byte("wrong port"))
	err := ms.Demux(frame, 0)
	if err != lneto.ErrMismatch {
		t.Fatalf("want ErrMismatch, got %v", err)
	}
}

func TestMuxSIMO_ReadNextTruncates(t *testing.T) {
	const localPort = 1234
	ms := newTestSIMO(t, localPort)
	payload := []byte("toolongpayload")
	if err := ms.Demux(makeUDPFrame(8080, localPort, payload), 0); err != nil {
		t.Fatal(err)
	}
	var small [4]byte
	n, completeRead, _ := ms.ReadNext(small[:])
	if n != 4 {
		t.Fatalf("read %d, want 4", n)
	}
	if completeRead {
		t.Fatal("want completeRead=false on truncation")
	}
	if !internal.BytesEqual(small[:], payload[:4]) {
		t.Fatal("truncated data mismatch")
	}
	// Next datagram should work cleanly after truncation.
	payload2 := []byte("ok")
	if err := ms.Demux(makeUDPFrame(8080, localPort, payload2), 0); err != nil {
		t.Fatal(err)
	}
	var buf [64]byte
	n, completeRead, _ = ms.ReadNext(buf[:])
	if !completeRead || !internal.BytesEqual(buf[:n], payload2) {
		t.Fatal("post-truncation read mismatch")
	}
}

func TestMuxSIMO_MultipleDatagrams(t *testing.T) {
	const localPort = 5000
	ms := newTestSIMO(t, localPort)
	type send struct {
		payload string
		raddr   netip.AddrPort
	}
	sends := []send{
		{"alpha", netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 0, 0, 1}), 100)},
		{"beta", netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 0, 0, 2}), 200)},
		{"gamma", netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 0, 0, 3}), 300)},
	}
	for _, s := range sends {
		if err := ms.WriteTo([]byte(s.payload), s.raddr); err != nil {
			t.Fatal(err)
		}
	}
	var buf [128]byte
	for _, s := range sends {
		n, err := ms.Encapsulate(buf[:], -1, 0)
		if err != nil {
			t.Fatal(err)
		}
		ufrm, err := NewFrame(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		if got := string(ufrm.Payload()); got != s.payload {
			t.Fatalf("payload %q, want %q", got, s.payload)
		}
		if ufrm.DestinationPort() != s.raddr.Port() {
			t.Fatalf("dst port %d, want %d", ufrm.DestinationPort(), s.raddr.Port())
		}
	}
}

func TestMuxSIMO_TxQueueExhausted(t *testing.T) {
	ms := newTestSIMO(t, 1234) // queue size 4
	raddr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 1}), 9000)
	for i := range 4 {
		if err := ms.WriteTo([]byte{byte(i)}, raddr); err != nil {
			t.Fatalf("WriteTo %d: %v", i, err)
		}
	}
	if err := ms.WriteTo([]byte{0xff}, raddr); err != lneto.ErrExhausted {
		t.Fatalf("want ErrExhausted, got %v", err)
	}
}

func TestMuxSIMO_RxQueueExhausted(t *testing.T) {
	const localPort = 1234
	ms := newTestSIMO(t, localPort) // queue size 4
	for i := range 4 {
		frame := makeUDPFrame(8080, localPort, []byte{byte(i)})
		if err := ms.Demux(frame, 0); err != nil {
			t.Fatalf("Demux %d: %v", i, err)
		}
	}
	frame := makeUDPFrame(8080, localPort, []byte{0xff})
	if err := ms.Demux(frame, 0); err != lneto.ErrExhausted {
		t.Fatalf("want ErrExhausted, got %v", err)
	}
}

func TestMuxSIMO_ClosedBehavior(t *testing.T) {
	ms := newTestSIMO(t, 1234)
	ms.Close()
	raddr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 1}), 9000)
	if err := ms.WriteTo([]byte("data"), raddr); err == nil {
		t.Fatal("expected error writing to closed handler")
	}
	frame := makeUDPFrame(8080, 1234, []byte("data"))
	if err := ms.Demux(frame, 0); err == nil {
		t.Fatal("expected error demuxing to closed handler")
	}
}

func TestMuxSIMO_WriteToInvalidRaddr(t *testing.T) {
	ms := newTestSIMO(t, 1234)
	zeroPort := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 1}), 0)
	if err := ms.WriteTo([]byte("data"), zeroPort); err != lneto.ErrZeroDestination {
		t.Fatalf("want ErrZeroDestination, got %v", err)
	}
}

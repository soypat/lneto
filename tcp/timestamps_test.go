package tcp

import (
	"math/rand"
	"testing"
	"time"

	"github.com/soypat/lneto/ethernet"
)

// enableTimestamps turns on RFC 7323 timestamps for h and installs a monotonic
// clock reading *nowNS nanoseconds (no loss recovery). Must be called before the
// connection is opened.
func enableTimestamps(t *testing.T, h *Handler, nowNS *int64) {
	t.Helper()
	h.SetLossRecovery(nil, func() int64 { return *nowNS })
	if err := h.EnableTimestamps(true); err != nil {
		t.Fatal("EnableTimestamps:", err)
	}
}

// TestTimestamps_NegotiatedWhenBothEnable verifies the option is negotiated on
// the handshake when both peers permit it and a clock is present.
func TestTimestamps_NegotiatedWhenBothEnable(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(1))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)
	clientNS, serverNS := int64(5*nanosPerMilli), int64(9*nanosPerMilli)
	enableTimestamps(t, client, &clientNS)
	enableTimestamps(t, server, &serverNS)

	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])

	if !client.TimestampsEnabled() {
		t.Error("client did not negotiate timestamps")
	}
	if !server.TimestampsEnabled() {
		t.Error("server did not negotiate timestamps")
	}
}

// TestTimestamps_NotNegotiatedWhenOneSideOff verifies the option stays off for
// the whole connection when either peer does not permit it.
func TestTimestamps_NotNegotiatedWhenOneSideOff(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(2))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)
	clientNS := int64(5 * nanosPerMilli)
	enableTimestamps(t, client, &clientNS) // only the client permits timestamps.

	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])

	if client.TimestampsEnabled() {
		t.Error("client negotiated timestamps without server support")
	}
	if server.TimestampsEnabled() {
		t.Error("server negotiated timestamps though it was disabled")
	}
}

// TestTimestamps_EchoOnDataSegment verifies an established data segment carries
// the Timestamps option: TSval is the sender's current clock and TSecr echoes
// the most recent value received from the peer (RFC 7323 §3.2).
func TestTimestamps_EchoOnDataSegment(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(3))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)
	clientNS, serverNS := int64(5*nanosPerMilli), int64(9*nanosPerMilli)
	enableTimestamps(t, client, &clientNS)
	enableTimestamps(t, server, &serverNS)

	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])

	// The client learned the server's TSval (9) from the SYN-ACK.
	if client.scb.tsRecent != 9 {
		t.Fatalf("client TS.Recent = %d, want server TSval 9", client.scb.tsRecent)
	}

	// Advance the client clock, then send a data segment.
	clientNS = 12 * nanosPerMilli
	data := []byte("payload")
	if _, err := client.Write(data); err != nil {
		t.Fatal("client write:", err)
	}
	clear(buf[:])
	n, err := client.Send(buf[:])
	if err != nil {
		t.Fatal("client send:", err)
	}
	frame, err := NewFrame(buf[:n])
	if err != nil {
		t.Fatal("parse frame:", err)
	}
	tsval, tsecr, present := client.timestampFromOptions(frame.Options())
	if !present {
		t.Fatal("data segment carried no Timestamps option")
	}
	if tsval != 12 {
		t.Errorf("TSval = %d, want current client clock 12", tsval)
	}
	if tsecr != 9 {
		t.Errorf("TSecr = %d, want echoed server TSval 9", tsecr)
	}

	// The server records the client's TSval as its new echo on delivery.
	if err := server.Recv(buf[:n]); err != nil {
		t.Fatal("server recv:", err)
	}
	if server.scb.tsRecent != 12 {
		t.Errorf("server TS.Recent = %d, want client TSval 12", server.scb.tsRecent)
	}
}

// TestTimestamps_MeasuresRTTThroughHandler drives a full data/ack exchange with
// timestamps and an RTO installed on the client, and verifies the round-trip
// time is measured from the echoed timestamp end to end (RFC 7323 §4.2).
func TestTimestamps_MeasuresRTTThroughHandler(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(4))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)

	clientNS := int64(1000 * nanosPerMilli)
	rto := new(RTO)
	client.SetLossRecovery(rto, func() int64 { return clientNS })
	if err := client.EnableTimestamps(true); err != nil {
		t.Fatal("client EnableTimestamps:", err)
	}
	serverNS := int64(9 * nanosPerMilli)
	enableTimestamps(t, server, &serverNS)

	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])

	// Client sends data at ms clock 1000.
	data := []byte("payload")
	if _, err := client.Write(data); err != nil {
		t.Fatal("client write:", err)
	}
	clear(buf[:])
	n, err := client.Send(buf[:])
	if err != nil {
		t.Fatal("client send data:", err)
	}
	if err := server.Recv(buf[:n]); err != nil {
		t.Fatal("server recv data:", err)
	}
	// Server acknowledges, echoing the client's TSval (1000).
	clear(buf[:])
	n, err = server.Send(buf[:])
	if err != nil {
		t.Fatal("server send ack:", err)
	}
	if n < sizeHeaderTCP {
		t.Fatal("expected server to send an ACK")
	}

	// The ACK arrives 40ms later; the RTO measures RTT from the echo.
	clientNS = 1040 * nanosPerMilli
	if err := client.Recv(buf[:n]); err != nil {
		t.Fatal("client recv ack:", err)
	}
	if rto.SmoothedRTT() != 40*time.Millisecond {
		t.Errorf("measured RTT = %v, want 40ms", rto.SmoothedRTT())
	}
}

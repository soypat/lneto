package tcp

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/soypat/lneto/ethernet"
)

// tsOption is a well-formed 10-octet Timestamps option, used as a stand-in for
// whatever a real policy would emit.
var tsOption = []byte{byte(OptTimestamps), 10, 0, 0, 0, 1, 0, 0, 0, 2}

// TestLossRecovery_WriteOptionsPlan verifies the policy is told which kind of
// segment it is writing options for, so it can distinguish handshake
// negotiation from ordinary traffic without tracking the state machine.
func TestLossRecovery_WriteOptionsPlan(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(11))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)
	loss := newRecordingLoss()
	client.SetLossRecovery(loss, func() int64 { return 1 })
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte

	establish(t, client, server, buf[:])
	if len(loss.plans) < 2 {
		t.Fatalf("WriteOptions called %d times during the handshake, want at least 2", len(loss.plans))
	}
	if got := loss.plans[0].Kind; got != TxKindSYN {
		t.Errorf("first plan Kind=%d, want TxKindSYN", got)
	}
	// After the handshake the client emits ordinary segments.
	last := loss.plans[len(loss.plans)-1]
	if last.Kind != TxKindSegment {
		t.Errorf("post-handshake plan Kind=%d, want TxKindSegment", last.Kind)
	}
	if last.State != StateEstablished {
		t.Errorf("post-handshake plan State=%s, want Established", last.State)
	}
	if last.Now != 1 {
		t.Errorf("plan Now=%d, want the connection clock value 1", last.Now)
	}
}

// TestLossRecovery_WriteOptionsServerSeesSYNACK verifies the responding side is
// told it is writing options for a SYN-ACK.
func TestLossRecovery_WriteOptionsServerSeesSYNACK(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(12))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)
	loss := newRecordingLoss()
	server.SetLossRecovery(loss, func() int64 { return 1 })
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])

	var sawSynAck bool
	for _, p := range loss.plans {
		if p.Kind == TxKindSYNACK {
			sawSynAck = true
		}
	}
	if !sawSynAck {
		t.Error("the responding side never saw a TxKindSYNACK plan")
	}
}

// TestLossRecovery_WriteOptionsOnWire verifies injected options reach the wire
// intact, the data offset accounts for them, and the payload still arrives
// correctly at the peer. The last part is the real check: a mistake in payload
// placement corrupts the stream rather than the header.
func TestLossRecovery_WriteOptionsOnWire(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(13))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)
	loss := newRecordingLoss()
	loss.writeOpts = tsOption
	client.SetLossRecovery(loss, func() int64 { return 1 })
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])

	data := []byte("hello seam")
	if _, err := client.Write(data); err != nil {
		t.Fatal("write:", err)
	}
	clear(buf[:])
	n, err := client.Send(buf[:])
	if err != nil {
		t.Fatal("send:", err)
	}
	frame, err := NewFrame(buf[:n])
	if err != nil {
		t.Fatal("parse:", err)
	}
	// The option area must contain what the policy wrote, and the header must
	// have grown past the 20-octet minimum to hold it.
	if hlen := frame.HeaderLength(); hlen <= sizeHeaderTCP {
		t.Fatalf("header length %d did not grow to hold options", hlen)
	}
	if opts := frame.Options(); !bytes.Contains(opts, tsOption) {
		t.Fatalf("option area %x does not contain the injected option %x", opts, tsOption)
	}
	// The option area is padded to a four-octet boundary by construction.
	if len(frame.Options())%4 != 0 {
		t.Errorf("option area length %d is not a multiple of 4", len(frame.Options()))
	}
	// Payload must be intact end to end.
	if err = server.Recv(buf[:n]); err != nil {
		t.Fatal("server recv:", err)
	}
	got := make([]byte, len(data))
	nr, err := server.Read(got)
	if err != nil {
		t.Fatal("server read:", err)
	}
	if !bytes.Equal(got[:nr], data) {
		t.Errorf("server received %q, want %q: payload misplaced by the option area", got[:nr], data)
	}
}

// TestLossRecovery_WriteOptionsReducePayload verifies the option length is
// subtracted from the space available for data, so a full-buffer send cannot
// overflow the frame.
func TestLossRecovery_WriteOptionsReducePayload(t *testing.T) {
	const mtu = 400
	rng := rand.New(rand.NewSource(14))
	newBig := func() *Handler {
		h := new(Handler)
		// A transmit buffer larger than one segment so data is always pending.
		if err := h.SetBuffers(make([]byte, 4*mtu), make([]byte, 4*mtu), 4); err != nil {
			t.Fatal(err)
		}
		return h
	}
	client, server := newBig(), newBig()
	loss := newRecordingLoss()
	loss.writeOpts = tsOption
	client.SetLossRecovery(loss, func() int64 { return 1 })
	setupClientServer(t, rng, client, server)
	buf := make([]byte, mtu)
	establish(t, client, server, buf)

	data := make([]byte, 4*mtu-1)
	for i := range data {
		data[i] = byte(i)
	}
	if _, err := client.Write(data); err != nil {
		t.Fatal("write:", err)
	}
	clear(buf)
	n, err := client.Send(buf)
	if err != nil {
		t.Fatal("send:", err)
	}
	if n > len(buf) {
		t.Fatalf("segment of %d octets overflowed the %d octet buffer", n, len(buf))
	}
	frame, err := NewFrame(buf[:n])
	if err != nil {
		t.Fatal("parse:", err)
	}
	hlen := int(frame.HeaderLength())
	payload := n - hlen
	if want := len(buf) - hlen; payload != want {
		t.Errorf("payload=%d octets, want %d (buffer minus the header with options)", payload, want)
	}
	// Delivering it must still reconstruct the prefix of the stream exactly.
	if err = server.Recv(buf[:n]); err != nil {
		t.Fatal("server recv:", err)
	}
	got := make([]byte, payload)
	nr, err := server.Read(got)
	if err != nil {
		t.Fatal("server read:", err)
	}
	if !bytes.Equal(got[:nr], data[:nr]) {
		t.Error("payload corrupted: option area and data overlap")
	}
}

// TestLossRecovery_WriteOptionsOverrunRejected verifies a policy claiming to
// have written more options than the space it was lent cannot produce a
// segment with an unknown header layout.
func TestLossRecovery_WriteOptionsOverrunRejected(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(15))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)
	loss := newRecordingLoss()
	client.SetLossRecovery(loss, func() int64 { return 1 })
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])

	loss.overrun = true
	if _, err := client.Write([]byte("data")); err != nil {
		t.Fatal("write:", err)
	}
	clear(buf[:])
	_, err := client.Send(buf[:])
	if err != errOptionOverflow {
		t.Fatalf("Send error = %v, want errOptionOverflow", err)
	}
}

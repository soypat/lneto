package tcp

import (
	"math/rand"
	"testing"
	"time"

	"github.com/soypat/lneto/ethernet"
)

// TestHandlerRetransmitsAfterRTO covers the seam between a Handler and its
// LossRecovery, which the RTO unit tests do not: a lost data segment must be
// resent once the timer expires, with nothing arriving to prompt it.
func TestHandlerRetransmitsAfterRTO(t *testing.T) {
	const mtu = ethernet.MaxMTU
	const maxpackets = 4
	rng := rand.New(rand.NewSource(5))
	client, server := newHandler(t, mtu, maxpackets), newHandler(t, mtu, maxpackets)

	var now int64 // injected monotonic clock, in nanoseconds
	client.SetLossRecovery(new(RTO), func() int64 { return now })

	setupClientServer(t, rng, client, server)
	var rawbuf [mtu]byte
	establish(t, client, server, rawbuf[:])

	data := []byte("hello")
	if n, err := client.Write(data); err != nil || n != len(data) {
		t.Fatal("client write:", n, err)
	}
	clear(rawbuf[:])
	n, err := client.Send(rawbuf[:])
	if err != nil || n == 0 {
		t.Fatal("client send:", n, err)
	}
	// That frame is lost: it is never handed to the server.

	// Nothing may come back before the timer expires.
	var probe [mtu]byte
	if n, err := client.Send(probe[:]); err != nil || n != 0 {
		t.Fatalf("client sent %d bytes before the RTO expired (err %v)", n, err)
	}

	now += int64(3 * time.Second) // past the initial RTO and one backoff

	clear(probe[:])
	n, err = client.Send(probe[:])
	if err != nil {
		t.Fatal("client send after RTO:", err)
	}
	if n == 0 {
		t.Fatal("no retransmission after the RTO expired: the loss-recovery directive is never applied")
	}
	if err := server.Recv(probe[:n]); err != nil {
		t.Fatal("server refused the retransmission:", err)
	}
	got := make([]byte, 16)
	nr, err := server.Read(got)
	if err != nil || string(got[:nr]) != string(data) {
		t.Fatalf("server read %q (%v), want %q", got[:nr], err, data)
	}
}

// TestHandlerRetransmitsAfterCloseWithUnackedData is the write-then-close case
// every server performs. With the last data segment lost, the FIN behind it sits
// above a gap the peer cannot cross, so FIN-WAIT-1 must still retransmit that
// data or both sides wait forever.
func TestHandlerRetransmitsAfterCloseWithUnackedData(t *testing.T) {
	const mtu = ethernet.MaxMTU
	const maxpackets = 4
	rng := rand.New(rand.NewSource(9))
	client, server := newHandler(t, mtu, maxpackets), newHandler(t, mtu, maxpackets)

	var now int64
	client.SetLossRecovery(new(RTO), func() int64 { return now })

	setupClientServer(t, rng, client, server)
	var rawbuf [mtu]byte
	establish(t, client, server, rawbuf[:])

	data := []byte("last response bytes")
	if n, err := client.Write(data); err != nil || n != len(data) {
		t.Fatal("client write:", n, err)
	}
	clear(rawbuf[:])
	n, err := client.Send(rawbuf[:]) // this frame is lost in transit
	if err != nil || n == 0 {
		t.Fatal("client send:", n, err)
	}

	// The application closes right after writing.
	if err := client.Close(); err != nil {
		t.Fatal("client close:", err)
	}
	var finbuf [mtu]byte
	nfin, err := client.Send(finbuf[:]) // FIN (also lost, or simply unacked)
	if err != nil {
		t.Fatal("client send FIN:", err)
	}
	t.Logf("state after close: %s (FIN frame %d bytes)", client.State(), nfin)

	now += int64(3 * time.Second) // past the RTO

	var probe [mtu]byte
	n, err = client.Send(probe[:])
	if err != nil {
		t.Fatal("client send after RTO:", err)
	}
	if n == 0 {
		t.Fatalf("no retransmission in %s: unacknowledged data is stranded by the close", client.State())
	}
	if err := server.Recv(probe[:n]); err != nil {
		t.Fatal("server refused the retransmission:", err)
	}
	got := make([]byte, 32)
	nr, err := server.Read(got)
	if err != nil || string(got[:nr]) != string(data) {
		t.Fatalf("server read %q (%v), want %q", got[:nr], err, data)
	}
}

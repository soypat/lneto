package rto

import (
	"math/rand"
	"testing"
	"time"

	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/tcp"
)

// sizeHeaderTCP is the fixed TCP header length. The tcp package's own constant
// is unexported and these tests live outside it.
const sizeHeaderTCP = 20

// TestRTO_HandlerRetransmitsAfterTimeout covers the seam between a Handler and
// its Policy, which the Timer unit tests do not: a lost data segment must be
// resent once the timer expires, with nothing arriving to prompt it.
func TestRTO_HandlerRetransmitsAfterTimeout(t *testing.T) {
	const mtu = ethernet.MaxMTU
	const maxpackets = 4
	rng := rand.New(rand.NewSource(5))
	client, server := newHandler(t, mtu, maxpackets), newHandler(t, mtu, maxpackets)

	var now int64 // injected monotonic clock, in nanoseconds
	client.SetPolicy(newTimer(t, func() int64 { return now }))

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
		t.Fatal("no retransmission after the RTO expired: the Policy directive is never applied")
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

// TestRTO_HandlerRetransmitsAfterCloseWithUnackedData is the write-then-close
// case every server performs. With the last data segment lost, the FIN behind it
// sits above a gap the peer cannot cross, so FIN-WAIT-1 must still retransmit
// that data or both sides wait forever.
func TestRTO_HandlerRetransmitsAfterCloseWithUnackedData(t *testing.T) {
	const mtu = ethernet.MaxMTU
	const maxpackets = 4
	rng := rand.New(rand.NewSource(9))
	client, server := newHandler(t, mtu, maxpackets), newHandler(t, mtu, maxpackets)

	var now int64
	client.SetPolicy(newTimer(t, func() int64 { return now }))

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

// newTimer returns a Timer driven by nanotime, ready to install as a [tcp.Policy].
func newTimer(t *testing.T, nanotime func() int64) *Timer {
	t.Helper()
	r := new(Timer)
	err := r.Configure(nanotime)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The handshake helpers below mirror those in the tcp package's own tests, which
// are unexported and so unavailable here. They drive two Handlers against each
// other over a single packet buffer, with no network in between.

func newHandler(t *testing.T, mtu, minpackets int) *tcp.Handler {
	t.Helper()
	h := new(tcp.Handler)
	err := h.SetBuffers(make([]byte, mtu), make([]byte, mtu), minpackets)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func setupClientServer(t *testing.T, rng *rand.Rand, client, server *tcp.Handler) {
	t.Helper()
	err := server.OpenListen(uint16(rng.Uint32()), 0)
	if err != nil {
		t.Fatal(err)
	}
	err = client.OpenActive(uint16(rng.Uint32()), server.LocalPort(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !client.AwaitingSynSend() {
		t.Fatal("client in wrong state")
	}
	if !server.AwaitingSynAck() {
		t.Fatal("server in wrong state")
	}
}

func establish(t *testing.T, client, server *tcp.Handler, packetBuf []byte) {
	t.Helper()
	if client.State() != tcp.StateClosed {
		t.Fatal("client in wrong state")
	} else if server.State() != tcp.StateListen {
		t.Fatal("server in wrong state")
	}
	clear(packetBuf)

	// Commence 3-way handshake: client sends SYN, server sends SYN-ACK, client sends ACK.
	n, err := client.Send(packetBuf)
	if err != nil {
		t.Fatal("client sending:", err)
	} else if n < sizeHeaderTCP {
		t.Fatal("expected client to send SYN packet")
	} else if client.State() != tcp.StateSynSent {
		t.Fatal("client did not transition to SynSent state:", client.State().String())
	}
	err = server.Recv(packetBuf[:n]) // Server receives SYN.
	if err != nil {
		t.Fatal(err)
	} else if server.State() != tcp.StateSynRcvd {
		t.Fatal("server did not transition to SynReceived state:", server.State().String())
	}

	clear(packetBuf)
	n, err = server.Send(packetBuf) // Server sends SYNACK.
	if err != nil {
		t.Fatal("server sending:", err)
	} else if n < sizeHeaderTCP {
		t.Fatal("expected server to send SYNACK packet")
	}
	err = client.Recv(packetBuf[:n]) // Client receives SYNACK, is established but must send ACK.
	if err != nil {
		t.Fatal(err)
	} else if client.State() != tcp.StateEstablished {
		t.Fatal("client did not transition to Established state:", client.State().String())
	}

	clear(packetBuf)
	n, err = client.Send(packetBuf) // Client sends ACK.
	if err != nil {
		t.Fatal("client sending ACK:", err)
	} else if n < sizeHeaderTCP {
		t.Fatal("expected client to send ACK packet")
	}
	err = server.Recv(packetBuf[:n]) // Server receives ACK.
	if err != nil {
		t.Fatal(err)
	} else if server.State() != tcp.StateEstablished {
		t.Fatal("server did not transition to Established state on ACK receive:", server.State().String())
	}
}

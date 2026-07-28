package tcp

import (
	"math/rand"
	"testing"

	"github.com/soypat/lneto/ethernet"
)

// TestChallengeAckOutOfOrderDoesNotAbort verifies a receiver does not abort a healthy
// connection because segments arrived out of order.
//
// The abort exists to stop an endless acknowledgement exchange between two peers whose
// state has diverged, which an out-of-window segment is evidence of. A segment that is
// in window but not the next expected one is not: it is what every lossy or reordering
// path produces, and it is the normal case for the data arriving behind a dropped
// segment. Counting it toward an abort means loss on a fast path tears the connection
// down instead of being recovered, and the sender is left with a full transmit buffer
// and no peer.
func TestChallengeAckOutOfOrderDoesNotAbort(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(31))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])

	// Feed the server segments from beyond the next expected sequence, more than the
	// abort threshold, each in window. Sent straight to the control block so the
	// handler's reassembly does not absorb them: past its capacity these are what
	// reaches the control block anyway.
	base := server.scb.rcv.NXT
	window := server.scb.rcv.WND
	if window < 200 {
		t.Fatalf("receive window is %d octets, too small to place in-window gaps", window)
	}
	for i := range 3 * maxChallengeRejects {
		// A gap ahead of rcv.NXT but comfortably inside the receive window, so these
		// are ordinary reordered segments and not evidence of diverged state.
		seg := Segment{
			SEQ:     Add(base, 100),
			ACK:     server.scb.snd.NXT,
			WND:     4096,
			DATALEN: 50,
			Flags:   FlagACK,
		}
		err := server.scb.Recv(seg)
		if err == nil {
			t.Fatalf("segment %d at %d was accepted, but it is not the next expected", i, seg.SEQ)
		}
		// The acknowledgement is actually emitted, as a live receiver does: the count
		// toward the abort advances when the challenge ACK is sent, not when it is
		// queued, so a test that never sends never reaches the abort at all.
		clear(buf[:])
		if _, err = server.Send(buf[:]); err != nil {
			t.Fatalf("server send after out-of-order segment %d: %v", i, err)
		}
		if server.State() == StateClosed {
			t.Fatalf("connection aborted after %d out-of-order segments, all in window", i+1)
		}
	}
	if server.State() != StateEstablished {
		t.Fatalf("server state is %s after out-of-order traffic, want ESTABLISHED", server.State())
	}
	// The connection still works: the segment it was waiting for is accepted.
	seg := Segment{SEQ: base, ACK: server.scb.snd.NXT, WND: 4096, DATALEN: 50, Flags: FlagACK}
	if err := server.scb.Recv(seg); err != nil {
		t.Errorf("the awaited segment was refused after out-of-order traffic: %v", err)
	}
}

// TestChallengeAckZeroWindowProbesDoNotAbort verifies a peer probing a closed window
// does not get the connection aborted.
//
// A zero-window probe deliberately carries an octet the receiver cannot accept, which
// is how it forces the window update that unblocks the sender. Counting those probes
// toward an abort means a connection stalled by a slow application is torn down by the
// mechanism that exists to recover it, and the more patient the sender the sooner it
// dies.
func TestChallengeAckZeroWindowProbesDoNotAbort(t *testing.T) {
	var tcb ControlBlock
	tcb.prepareToHandshake(1000, 4096, StateEstablished)
	tcb.snd.WND = 4096
	tcb.rcv.NXT = 5000
	tcb.rcv.WND = 0 // Our receive window is closed: the application has not read.
	tcb.snd.UNA, tcb.snd.NXT = 1000, 1000

	for i := range 3 * maxChallengeRejects {
		probe := Segment{SEQ: tcb.rcv.NXT, ACK: tcb.snd.NXT, WND: 4096, DATALEN: 1, Flags: FlagACK}
		err := tcb.Recv(probe)
		if err == nil {
			t.Fatalf("probe %d was accepted into a zero window", i)
		}
		if tcb.State() == StateClosed {
			t.Fatalf("connection aborted after %d zero-window probes", i+1)
		}
		// Each probe must still draw an acknowledgement, or the sender learns nothing,
		// and it must actually be sent: the count toward the abort advances on send.
		if tcb.pending[0]&FlagACK == 0 && !tcb.pendingChallengeAck() {
			t.Fatalf("probe %d drew no acknowledgement, leaving the sender to guess", i)
		}
		ack, ok := tcb.PendingSegment(0)
		if !ok {
			t.Fatalf("probe %d queued no segment to send", i)
		}
		if err = tcb.Send(ack); err != nil {
			t.Fatalf("send acknowledgement for probe %d: %v", i, err)
		}
	}
	if tcb.State() != StateEstablished {
		t.Errorf("state is %s after zero-window probes, want ESTABLISHED", tcb.State())
	}
}

// TestChallengeAckOutOfWindowStillAborts verifies the abort still fires for what it was
// built for: a peer sending segments outside the window at all, which is evidence the
// two sides no longer agree on the sequence space and would otherwise acknowledge each
// other forever.
func TestChallengeAckOutOfWindowStillAborts(t *testing.T) {
	var tcb ControlBlock
	tcb.prepareToHandshake(1000, 4096, StateEstablished)
	tcb.snd.WND = 4096
	tcb.rcv.NXT = 5000
	tcb.rcv.WND = 4096
	tcb.snd.UNA, tcb.snd.NXT = 1000, 1000

	aborted := false
	for i := range 4 * maxChallengeRejects {
		// Far outside the receive window in both directions of the sequence space.
		seg := Segment{SEQ: tcb.rcv.NXT + 1_000_000, ACK: tcb.snd.NXT, WND: 4096, DATALEN: 50, Flags: FlagACK}
		if err := tcb.Recv(seg); err == nil {
			t.Fatalf("out-of-window segment %d was accepted", i)
		}
		// Sending the challenge ACK is what advances the count.
		if tcb.pendingChallengeAck() {
			ack := tcb.MakeChallengeACK()
			if err := tcb.Send(ack); err != nil {
				t.Fatalf("send challenge ack %d: %v", i, err)
			}
		}
		if tcb.State() == StateClosed {
			aborted = true
			break
		}
	}
	if !aborted {
		t.Error("a peer sending only out-of-window segments never triggered the abort")
	}
}

package tcp

import (
	"math/rand"
	"testing"

	"github.com/soypat/lneto/ethernet"
)

// recordingLoss is a test LossRecovery that records every hook invocation and
// lets the test steer the directives returned to the Handler. It is the
// interface counterpart driven by the Handler under test.
type recordingLoss struct {
	resets   int
	preRx    []hookCall
	preTx    []int64
	postTx   []hookCall
	deadline int64 // value NextDeadline reports back.

	// Directives handed back to the Handler.
	keep bool        // PreRx result. Default true (see newRecordingLoss).
	tx   TxDirective // PreTx result.
}

type hookCall struct {
	seg Segment
	now int64
}

func newRecordingLoss() *recordingLoss { return &recordingLoss{keep: true} }

var _ LossRecovery = (*recordingLoss)(nil)

func (l *recordingLoss) Reset()              { l.resets++ }
func (l *recordingLoss) NextDeadline() int64 { return l.deadline }

func (l *recordingLoss) PreRx(incoming Segment, now int64) RxDirective {
	l.preRx = append(l.preRx, hookCall{seg: incoming, now: now})
	return RxDirective{Keep: l.keep}
}

func (l *recordingLoss) PreTx(now int64) TxDirective {
	l.preTx = append(l.preTx, now)
	return l.tx
}

func (l *recordingLoss) PostTx(outgoing Segment, now int64) {
	l.postTx = append(l.postTx, hookCall{seg: outgoing, now: now})
}

// TestLossRecovery_DisabledByDefault verifies the Handler runs normally with no
// loss recovery installed: NextDeadline reports no deadline and the transmit/
// receive paths never touch a nil LossRecovery.
func TestLossRecovery_DisabledByDefault(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(1))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)
	setupClientServer(t, rng, client, server)

	if d := client.NextDeadline(); d != 0 {
		t.Fatalf("NextDeadline with no loss recovery = %d, want 0", d)
	}
	var buf [mtu]byte
	establish(t, client, server, buf[:]) // must not panic on nil loss recovery.
}

// TestLossRecovery_HooksInvoked verifies the Handler drives the full hook
// contract across a handshake: Reset on open, PreTx+PostTx on every transmit,
// PreRx on every receive, each stamped with the configured monotonic clock.
func TestLossRecovery_HooksInvoked(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(2))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)

	loss := newRecordingLoss()
	const clockNow = 1_000_000
	client.SetLossRecovery(loss, func() int64 { return clockNow })

	setupClientServer(t, rng, client, server) // OpenActive → reset → Reset().
	if loss.resets == 0 {
		t.Fatal("Reset not called on open")
	}

	var buf [mtu]byte
	establish(t, client, server, buf[:])

	// Client emitted SYN and the final ACK: both paths must have hit PreTx/PostTx.
	if len(loss.preTx) == 0 {
		t.Fatal("PreTx never called on transmit")
	}
	if len(loss.postTx) == 0 {
		t.Fatal("PostTx never called on transmit")
	}
	if len(loss.preTx) != len(loss.postTx) {
		t.Fatalf("PreTx calls=%d, PostTx calls=%d, want equal", len(loss.preTx), len(loss.postTx))
	}
	// Client received the SYN-ACK: PreRx must have seen it.
	if len(loss.preRx) == 0 {
		t.Fatal("PreRx never called on receive")
	}

	// The Handler holds no clock: every hook must be stamped from the supplied
	// nanotime source.
	for i, c := range loss.postTx {
		if c.now != clockNow {
			t.Fatalf("PostTx[%d].now = %d, want clock %d", i, c.now, clockNow)
		}
	}
	for i, now := range loss.preTx {
		if now != clockNow {
			t.Fatalf("PreTx[%d].now = %d, want clock %d", i, now, clockNow)
		}
	}
	for i, c := range loss.preRx {
		if c.now != clockNow {
			t.Fatalf("PreRx[%d].now = %d, want clock %d", i, c.now, clockNow)
		}
	}

	// PostTx receives the segment actually emitted: the first is the SYN.
	if !loss.postTx[0].seg.Flags.HasAny(FlagSYN) {
		t.Fatalf("first PostTx segment flags=%s, want SYN", loss.postTx[0].seg.Flags)
	}
}

// TestLossRecovery_NextDeadlineDelegates verifies NextDeadline is forwarded to
// the installed LossRecovery unchanged.
func TestLossRecovery_NextDeadlineDelegates(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(3))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)

	loss := newRecordingLoss()
	loss.deadline = 4242
	client.SetLossRecovery(loss, func() int64 { return 1 })
	setupClientServer(t, rng, client, server)

	if d := client.NextDeadline(); d != 4242 {
		t.Fatalf("NextDeadline = %d, want delegated 4242", d)
	}
}

// TestLossRecovery_PreRxDropsSegment verifies a PreRx directive of Keep=false
// drops the segment before the state machine sees it: the payload is not
// buffered and connection state is untouched.
func TestLossRecovery_PreRxDropsSegment(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(4))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)

	loss := newRecordingLoss()
	server.SetLossRecovery(loss, func() int64 { return 1 })
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:]) // keep=true so handshake completes.

	// Now start dropping everything the server receives.
	loss.keep = false
	preRxBefore := len(loss.preRx)

	data := []byte("dropme")
	if _, err := client.Write(data); err != nil {
		t.Fatal("client write:", err)
	}
	clear(buf[:])
	n, err := client.Send(buf[:])
	if err != nil {
		t.Fatal("client send:", err)
	}

	if err := server.Recv(buf[:n]); err != nil {
		t.Fatalf("dropped segment must return nil, got %v", err)
	}
	if len(loss.preRx) != preRxBefore+1 {
		t.Fatalf("PreRx calls=%d, want %d (segment must reach PreRx)", len(loss.preRx), preRxBefore+1)
	}
	if server.BufferedInput() != 0 {
		t.Fatalf("dropped segment must not be buffered, got %d bytes", server.BufferedInput())
	}
	if server.State() != StateEstablished {
		t.Fatalf("dropped segment must not change state, got %s", server.State())
	}
}

// TestLossRecovery_PreTxRetransmitAll verifies a PreTx directive of
// RetransmitAll drives go-back-N: the Handler rewinds and re-emits already-sent,
// unacknowledged data from snd.UNA on the next transmit.
func TestLossRecovery_PreTxRetransmitAll(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(5))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)

	loss := newRecordingLoss()
	client.SetLossRecovery(loss, func() int64 { return 1 })
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])

	// Emit one data segment; server never ACKs, so it stays unacknowledged.
	data := []byte("payload")
	if _, err := client.Write(data); err != nil {
		t.Fatal("client write:", err)
	}
	clear(buf[:])
	n, err := client.Send(buf[:])
	if err != nil {
		t.Fatal("client send data:", err)
	}
	if n <= sizeHeaderTCP {
		t.Fatal("expected data segment")
	}
	firstSeg := mustSegment(t, buf[:n], n-sizeHeaderTCP)

	// Direct go-back-N on the next transmit.
	loss.tx = TxDirective{RetransmitAll: true}
	clear(buf[:])
	n, err = client.Send(buf[:])
	if err != nil {
		t.Fatal("client send retransmit:", err)
	}
	if n <= sizeHeaderTCP {
		t.Fatal("expected retransmitted data segment")
	}
	rtSeg := mustSegment(t, buf[:n], n-sizeHeaderTCP)

	if rtSeg.SEQ != firstSeg.SEQ {
		t.Fatalf("retransmit SEQ=%d, want original UNA SEQ=%d (go-back-N)", rtSeg.SEQ, firstSeg.SEQ)
	}
	if rtSeg.DATALEN != firstSeg.DATALEN {
		t.Fatalf("retransmit DATALEN=%d, want %d", rtSeg.DATALEN, firstSeg.DATALEN)
	}
}

// TestLossRecovery_ResetOnReopen verifies Reset fires on every (re)open and on
// Abort, so a single LossRecovery value can be reused across connection reuse.
func TestLossRecovery_ResetOnReopen(t *testing.T) {
	const mtu = ethernet.MaxMTU
	client := newHandler(t, mtu, 3)
	loss := newRecordingLoss()
	client.SetLossRecovery(loss, func() int64 { return 1 })

	if err := client.OpenActive(1234, 5678, 0); err != nil {
		t.Fatal("open 1:", err)
	}
	afterOpen := loss.resets
	if afterOpen == 0 {
		t.Fatal("Reset not called on first open")
	}

	client.Abort()
	if loss.resets <= afterOpen {
		t.Fatalf("Reset not called on Abort: resets=%d, want >%d", loss.resets, afterOpen)
	}
	afterAbort := loss.resets

	if err := client.OpenActive(1234, 5678, 0); err != nil {
		t.Fatal("open 2:", err)
	}
	if loss.resets <= afterAbort {
		t.Fatalf("Reset not called on reopen: resets=%d, want >%d", loss.resets, afterAbort)
	}
}

package tcp

import (
	"math/rand"
	"testing"

	"github.com/soypat/lneto/ethernet"
)

// recordingLoss is a test Policy that records every hook invocation and
// lets the test steer the directives returned to the Handler. It is the
// interface counterpart driven by the Handler under test.
type recordingLoss struct {
	resets   int
	preRx    []hookCall
	preTx    []TxIntent
	postTx   []hookCall
	postRx   []RxEvent
	deadline int64 // value NextDeadline reports back.

	// Directives handed back to the Handler.
	keep bool        // PreRx result. Default true (see newRecordingLoss).
	tx   TxDirective // PreTx result.

	// Option injection. plans records every WriteOptions call; writeOpts is
	// copied into the option area offered, and overrun makes the fake claim it
	// wrote more than it did so the Handler's validation can be exercised.
	plans     []TxPlan
	rxMeta    []RxMeta
	writeOpts []byte
	overrun   bool
}

type hookCall struct {
	seg Segment
	now int64
}

func newRecordingLoss() *recordingLoss { return &recordingLoss{keep: true} }

var _ Policy = (*recordingLoss)(nil)

func (l *recordingLoss) Reset()              { l.resets++ }
func (l *recordingLoss) NextDeadline() int64 { return l.deadline }

func (l *recordingLoss) PreRx(rx RxMeta) RxDirective {
	l.preRx = append(l.preRx, hookCall{seg: rx.Segment, now: rx.Now})
	l.rxMeta = append(l.rxMeta, rx)
	return RxDirective{Keep: l.keep}
}

func (l *recordingLoss) PreTx(intent TxIntent) TxDirective {
	l.preTx = append(l.preTx, intent)
	return l.tx
}

func (l *recordingLoss) WriteOptions(plan TxPlan, opts []byte) uint8 {
	l.plans = append(l.plans, plan)
	if l.overrun {
		return uint8(len(opts) + 1)
	}
	return uint8(copy(opts, l.writeOpts))
}

func (l *recordingLoss) PostTx(outgoing Segment, now int64) {
	l.postTx = append(l.postTx, hookCall{seg: outgoing, now: now})
}

func (l *recordingLoss) PostRx(event RxEvent) {
	l.postRx = append(l.postRx, event)
}

// TestPolicy_DisabledByDefault verifies the Handler runs normally with no
// loss recovery installed: NextDeadline reports no deadline and the transmit/
// receive paths never touch a nil Policy.
func TestPolicy_DisabledByDefault(t *testing.T) {
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

// TestPolicy_HooksInvoked verifies the Handler drives the full hook
// contract across a handshake: Reset on open, PreTx+PostTx on every transmit,
// PreRx on every receive, each stamped with the configured monotonic clock.
func TestPolicy_HooksInvoked(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(2))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)

	loss := newRecordingLoss()
	const clockNow = 1_000_000
	client.SetPolicy(loss, func() int64 { return clockNow })

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
	for i, intent := range loss.preTx {
		if intent.Now != clockNow {
			t.Fatalf("PreTx[%d].Now = %d, want clock %d", i, intent.Now, clockNow)
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

// TestPolicy_NextDeadlineDelegates verifies NextDeadline is forwarded to
// the installed Policy unchanged.
func TestPolicy_NextDeadlineDelegates(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(3))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)

	loss := newRecordingLoss()
	loss.deadline = 4242
	client.SetPolicy(loss, func() int64 { return 1 })
	setupClientServer(t, rng, client, server)

	if d := client.NextDeadline(); d != 4242 {
		t.Fatalf("NextDeadline = %d, want delegated 4242", d)
	}
}

// TestPolicy_PreRxDropsSegment verifies a PreRx directive of Keep=false
// drops the segment before the state machine sees it: the payload is not
// buffered and connection state is untouched.
func TestPolicy_PreRxDropsSegment(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(4))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)

	loss := newRecordingLoss()
	server.SetPolicy(loss, func() int64 { return 1 })
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

// TestPolicy_PreTxRetransmitFromUNA verifies a PreTx directive to
// retransmit from snd.UNA drives go-back-N: the Handler rewinds and re-emits
// already-sent, unacknowledged data from the oldest sequence number.
func TestPolicy_PreTxRetransmitFromUNA(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(5))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)

	loss := newRecordingLoss()
	client.SetPolicy(loss, func() int64 { return 1 })
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
	loss.tx = TxDirective{Retransmit: true, RetransmitFrom: firstSeg.SEQ}
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

// TestPolicy_PreTxRetransmitPartial verifies retransmission resumes at the
// requested sequence instead of always at snd.UNA: with two unacknowledged
// segments outstanding, asking to resume at the second one resends only that
// segment and leaves the first accounted for as sent.
func TestPolicy_PreTxRetransmitPartial(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(11))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)

	loss := newRecordingLoss()
	client.SetPolicy(loss, func() int64 { return 1 })
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])

	// Emit two data segments; the server never ACKs so both stay outstanding.
	var segs [2]Segment
	for i := range segs {
		if _, err := client.Write([]byte{byte('a' + i), byte('b' + i)}); err != nil {
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
		segs[i] = mustSegment(t, buf[:n], n-sizeHeaderTCP)
	}
	if segs[0].SEQ == segs[1].SEQ {
		t.Fatal("expected two distinct segments")
	}

	// Resume at the second segment: the first must not be resent.
	loss.tx = TxDirective{Retransmit: true, RetransmitFrom: segs[1].SEQ}
	clear(buf[:])
	n, err := client.Send(buf[:])
	if err != nil {
		t.Fatal("client send retransmit:", err)
	}
	if n <= sizeHeaderTCP {
		t.Fatal("expected retransmitted data segment")
	}
	rtSeg := mustSegment(t, buf[:n], n-sizeHeaderTCP)
	if rtSeg.SEQ != segs[1].SEQ {
		t.Fatalf("retransmit SEQ=%d, want %d (partial, not %d)", rtSeg.SEQ, segs[1].SEQ, segs[0].SEQ)
	}
	if rtSeg.DATALEN != segs[1].DATALEN {
		t.Fatalf("retransmit DATALEN=%d, want %d", rtSeg.DATALEN, segs[1].DATALEN)
	}
}

// TestPolicy_PreTxIntent verifies the send-state snapshot handed to PreTx
// tracks the connection: queued-but-unsent data appears as BufferedUnsent
// before transmission and as InFlight once sent and still unacknowledged. These
// are the quantities congestion control needs to gate new data.
func TestPolicy_PreTxIntent(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(7))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)

	loss := newRecordingLoss()
	client.SetPolicy(loss, func() int64 { return 1 })
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])

	data := []byte("payload")
	if _, err := client.Write(data); err != nil {
		t.Fatal("client write:", err)
	}
	loss.preTx = loss.preTx[:0]
	clear(buf[:])
	n, err := client.Send(buf[:])
	if err != nil {
		t.Fatal("client send data:", err)
	} else if n <= sizeHeaderTCP {
		t.Fatal("expected data segment")
	}
	if len(loss.preTx) != 1 {
		t.Fatalf("PreTx calls=%d, want 1", len(loss.preTx))
	}
	intent := loss.preTx[0]
	if intent.State != StateEstablished {
		t.Errorf("State=%s, want Established", intent.State)
	}
	if intent.BufferedUnsent != Size(len(data)) {
		t.Errorf("BufferedUnsent=%d, want %d", intent.BufferedUnsent, len(data))
	}
	if intent.InFlight != 0 {
		t.Errorf("InFlight=%d before transmission, want 0", intent.InFlight)
	}
	if intent.UNA != intent.NXT {
		t.Errorf("UNA=%d NXT=%d, want equal with nothing in flight", intent.UNA, intent.NXT)
	}

	// The segment is now sent but unacknowledged: it must show up as in flight
	// and no longer as buffered.
	loss.preTx = loss.preTx[:0]
	clear(buf[:])
	if _, err = client.Send(buf[:]); err != nil {
		t.Fatal("client send again:", err)
	}
	if len(loss.preTx) != 1 {
		t.Fatalf("PreTx calls=%d on second send, want 1", len(loss.preTx))
	}
	intent = loss.preTx[0]
	if intent.InFlight != Size(len(data)) {
		t.Errorf("InFlight=%d, want %d", intent.InFlight, len(data))
	}
	if intent.BufferedUnsent != 0 {
		t.Errorf("BufferedUnsent=%d after transmission, want 0", intent.BufferedUnsent)
	}
	if Sizeof(intent.UNA, intent.NXT) != intent.InFlight {
		t.Errorf("UNA=%d NXT=%d inconsistent with InFlight=%d", intent.UNA, intent.NXT, intent.InFlight)
	}
	if intent.SendWindow == 0 {
		t.Error("SendWindow=0, want the window advertised by the peer")
	}
}

// TestPolicy_ResetOnReopen verifies Reset fires on every (re)open and on
// Abort, so a single Policy value can be reused across connection reuse.
func TestPolicy_ResetOnReopen(t *testing.T) {
	const mtu = ethernet.MaxMTU
	client := newHandler(t, mtu, 3)
	loss := newRecordingLoss()
	client.SetPolicy(loss, func() int64 { return 1 })

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

// TestPolicy_PostRxReportsRejection verifies the connection tells the policy
// what it did with a segment, rather than leaving the policy to infer it. PreRx runs
// before the state machine has judged anything, so a policy accounting for
// acknowledgements there would count one for data that was never sent.
func TestPolicy_PostRxReportsRejection(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(17))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)
	loss := newRecordingLoss()
	client.SetPolicy(loss, func() int64 { return 1 })
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])

	// Send data and have it acknowledged: the event must report the acceptance and
	// the octets it acknowledged.
	data := []byte("payload")
	if _, err := client.Write(data); err != nil {
		t.Fatal("write:", err)
	}
	clear(buf[:])
	n, err := client.Send(buf[:])
	if err != nil {
		t.Fatal("send:", err)
	}
	if err = server.Recv(buf[:n]); err != nil {
		t.Fatal("server recv:", err)
	}
	clear(buf[:])
	m, err := server.Send(buf[:])
	if err != nil || m == 0 {
		t.Fatalf("server ack: n=%d err=%v", m, err)
	}
	before := len(loss.postRx)
	if err = client.Recv(buf[:m]); err != nil {
		t.Fatal("client recv ack:", err)
	}
	if len(loss.postRx) != before+1 {
		t.Fatalf("PostRx called %d times for one segment, want 1", len(loss.postRx)-before)
	}
	ack := loss.postRx[len(loss.postRx)-1]
	if !ack.Accepted {
		t.Error("a valid acknowledgement must be reported as accepted")
	}
	if ack.BytesAcked != Size(len(data)) {
		t.Errorf("BytesAcked=%d, want %d", ack.BytesAcked, len(data))
	}

	// Now a segment the state machine refuses: an acknowledgement for data never
	// sent. The policy must be told it did not count.
	bogus := Segment{
		SEQ:   client.scb.rcv.NXT,
		ACK:   client.scb.snd.NXT + 100000,
		WND:   1024,
		Flags: FlagACK,
	}
	clear(buf[:])
	tfrm, err := NewFrame(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	tfrm.SetSourcePort(server.LocalPort())
	tfrm.SetDestinationPort(client.LocalPort())
	tfrm.SetSegment(bogus, 5)
	before = len(loss.postRx)
	if err = client.Recv(buf[:sizeHeaderTCP]); err == nil {
		t.Fatal("expected the bogus acknowledgement to be refused")
	}
	if len(loss.postRx) != before+1 {
		t.Fatalf("PostRx called %d times for a refused segment, want 1", len(loss.postRx)-before)
	}
	got := loss.postRx[len(loss.postRx)-1]
	if got.Accepted {
		t.Error("a refused segment must not be reported as accepted")
	}
	if got.BytesAcked != 0 {
		t.Errorf("BytesAcked=%d for a refused segment, want 0", got.BytesAcked)
	}
}

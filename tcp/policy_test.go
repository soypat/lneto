package tcp

import (
	"math/rand"
	"testing"

	"github.com/soypat/lneto/ethernet"
)

// recordingPolicy records every hook invocation and lets the test steer what is
// returned to the Handler. It is the [Policy] counterpart driven by the Handler
// under test.
type recordingPolicy struct {
	resets int
	preRx  []Segment
	preTx  int
	postRx []Segment
	postTx []txRecord

	// Values handed back to the Handler.
	keep       bool // PreRx result. Default true (see newRecordingPolicy).
	rtxFrom    Value
	retransmit bool
	holdNew    bool
	// writeOpts, when non-empty, is appended as TCP options by PreTx.
	writeOpts []byte
}

// txRecord is what PostTx observed on the emitted frame.
type txRecord struct {
	seg    Segment
	offset uint8
	sport  uint16
	dport  uint16
}

func newRecordingPolicy() *recordingPolicy { return &recordingPolicy{keep: true} }

var _ Policy = (*recordingPolicy)(nil)

func (p *recordingPolicy) Reset() { p.resets++ }

func (p *recordingPolicy) PreRx(h *Handler, incoming Frame) bool {
	p.preRx = append(p.preRx, incoming.Segment(len(incoming.Payload())))
	return p.keep
}

func (p *recordingPolicy) PostRx(h *Handler, prevState State, accepted Frame) {
	p.postRx = append(p.postRx, accepted.Segment(len(accepted.Payload())))
}

func (p *recordingPolicy) PreTx(h *Handler, outgoingOpts Frame) (Value, bool, bool) {
	p.preTx++
	if len(p.writeOpts) > 0 {
		// Raise the offset first: Options() is sized from it.
		words := uint8(5 + (len(p.writeOpts)+3)/4)
		outgoingOpts.SetOffsetAndFlags(words, 0)
		copy(outgoingOpts.Options(), p.writeOpts)
	}
	return p.rtxFrom, p.retransmit, p.holdNew
}

func (p *recordingPolicy) PostTx(h *Handler, outgoing Frame) {
	offset, _ := outgoing.OffsetAndFlags()
	p.postTx = append(p.postTx, txRecord{
		seg:    outgoing.Segment(len(outgoing.Payload())),
		offset: offset,
		sport:  outgoing.SourcePort(),
		dport:  outgoing.DestinationPort(),
	})
}

// TestPolicy_DisabledByDefault verifies the Handler runs normally with no Policy
// installed: the transmit and receive paths never touch a nil Policy.
func TestPolicy_DisabledByDefault(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(1))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)
	setupClientServer(t, rng, client, server)

	var buf [mtu]byte
	establish(t, client, server, buf[:]) // must not panic on nil Policy.
}

// TestPolicy_HooksInvoked verifies the Handler drives the full hook contract
// across a handshake: Reset on open, PreTx+PostTx on transmit, PreRx+PostRx on
// receive.
func TestPolicy_HooksInvoked(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(2))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)

	pol := newRecordingPolicy()
	client.SetPolicy(pol)

	setupClientServer(t, rng, client, server) // OpenActive → reset → Reset().
	if pol.resets == 0 {
		t.Fatal("Reset not called on open")
	}

	var buf [mtu]byte
	establish(t, client, server, buf[:])

	if pol.preTx == 0 {
		t.Fatal("PreTx never called on transmit")
	}
	if len(pol.postTx) == 0 {
		t.Fatal("PostTx never called on transmit")
	}
	if pol.preTx < len(pol.postTx) {
		t.Fatalf("PreTx calls=%d < PostTx calls=%d: PostTx must never fire without PreTx", pol.preTx, len(pol.postTx))
	}
	// Client received the SYN-ACK and accepted it.
	if len(pol.preRx) == 0 {
		t.Fatal("PreRx never called on receive")
	}
	if len(pol.postRx) == 0 {
		t.Fatal("PostRx never called on accepted receive")
	}
	// PostTx receives the segment actually emitted: the first is the SYN.
	if !pol.postTx[0].seg.Flags.HasAny(FlagSYN) {
		t.Fatalf("first PostTx segment flags=%s, want SYN", pol.postTx[0].seg.Flags)
	}
}

// TestPolicy_PostTxSeesWrittenFrame verifies PostTx observes the fully populated
// frame — ports, sequence numbers and payload length as emitted — and not the
// frame as it stood before the segment was written into it.
func TestPolicy_PostTxSeesWrittenFrame(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(6))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)

	pol := newRecordingPolicy()
	client.SetPolicy(pol)
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])

	data := []byte("payload")
	if _, err := client.Write(data); err != nil {
		t.Fatal("client write:", err)
	}
	clear(buf[:])
	n, err := client.Send(buf[:])
	if err != nil {
		t.Fatal("client send:", err)
	}
	last := pol.postTx[len(pol.postTx)-1]
	wantSeg := mustSegment(t, buf[:n], n-int(last.offset)*4)
	if last.seg != wantSeg {
		t.Fatalf("PostTx segment=%+v, want emitted %+v", last.seg, wantSeg)
	}
	if int(last.seg.DATALEN) != len(data) {
		t.Fatalf("PostTx DATALEN=%d, want %d", last.seg.DATALEN, len(data))
	}
	if last.sport != client.LocalPort() || last.dport != client.RemotePort() {
		t.Fatalf("PostTx ports=%d→%d, want %d→%d", last.sport, last.dport, client.LocalPort(), client.RemotePort())
	}
}

// TestPolicy_NoPostTxWithoutSegment verifies a transmit attempt that emits
// nothing still runs PreTx but never PostTx, so a Policy cannot mistake a
// no-op Send for a segment on the wire.
func TestPolicy_NoPostTxWithoutSegment(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(7))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)

	pol := newRecordingPolicy()
	client.SetPolicy(pol)
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])

	preTxBefore, postTxBefore := pol.preTx, len(pol.postTx)
	n, err := client.Send(buf[:]) // Nothing queued: no segment.
	if err != nil {
		t.Fatal("client send:", err)
	}
	if n != 0 {
		t.Fatalf("expected no segment, got %d bytes", n)
	}
	if pol.preTx != preTxBefore+1 {
		t.Fatalf("PreTx calls=%d, want %d: PreTx must run on every attempt", pol.preTx, preTxBefore+1)
	}
	if len(pol.postTx) != postTxBefore {
		t.Fatalf("PostTx calls=%d, want %d: no segment was emitted", len(pol.postTx), postTxBefore)
	}
}

// TestPolicy_PreTxOptions verifies options written by PreTx survive to the wire:
// the data offset accounts for them and the payload starts after them.
func TestPolicy_PreTxOptions(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(8))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)

	pol := newRecordingPolicy()
	client.SetPolicy(pol)
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])

	// One 4-byte option word: NOP,NOP,NOP,EOL.
	opts := []byte{1, 1, 1, 0}
	pol.writeOpts = opts

	data := []byte("payload")
	if _, err := client.Write(data); err != nil {
		t.Fatal("client write:", err)
	}
	clear(buf[:])
	n, err := client.Send(buf[:])
	if err != nil {
		t.Fatal("client send:", err)
	}
	frm, err := NewFrame(buf[:n])
	if err != nil {
		t.Fatal("frame:", err)
	}
	offset, _ := frm.OffsetAndFlags()
	if offset != 6 {
		t.Fatalf("data offset=%d, want 6 (header + one option word)", offset)
	}
	if got := frm.Options(); string(got) != string(opts) {
		t.Fatalf("options=%v, want %v", got, opts)
	}
	if got := frm.Payload(); string(got) != string(data) {
		t.Fatalf("payload=%q, want %q: options must not overlap data", got, data)
	}
	if n != int(offset)*4+len(data) {
		t.Fatalf("frame length=%d, want %d", n, int(offset)*4+len(data))
	}
}

// TestPolicy_PreRxDropsSegment verifies keep=false drops the segment before the
// state machine sees it: the payload is not buffered, connection state is
// untouched and PostRx never fires.
func TestPolicy_PreRxDropsSegment(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(4))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)

	pol := newRecordingPolicy()
	server.SetPolicy(pol)
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:]) // keep=true so handshake completes.

	// Now start dropping everything the server receives.
	pol.keep = false
	preRxBefore, postRxBefore := len(pol.preRx), len(pol.postRx)

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
	if len(pol.preRx) != preRxBefore+1 {
		t.Fatalf("PreRx calls=%d, want %d (segment must reach PreRx)", len(pol.preRx), preRxBefore+1)
	}
	if len(pol.postRx) != postRxBefore {
		t.Fatalf("PostRx calls=%d, want %d: a dropped segment was never accepted", len(pol.postRx), postRxBefore)
	}
	if server.BufferedInput() != 0 {
		t.Fatalf("dropped segment must not be buffered, got %d bytes", server.BufferedInput())
	}
	if server.State() != StateEstablished {
		t.Fatalf("dropped segment must not change state, got %s", server.State())
	}
}

// TestPolicy_PreTxRetransmit verifies a PreTx retransmit directive drives
// go-back-N: the Handler rewinds the send sequence and the transmit buffer
// together and re-emits already-sent, unacknowledged data from snd.UNA.
func TestPolicy_PreTxRetransmit(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(5))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)

	pol := newRecordingPolicy()
	client.SetPolicy(pol)
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
	firstData := append([]byte(nil), buf[sizeHeaderTCP:n]...)

	// Direct go-back-N on the next transmit.
	pol.rtxFrom, pol.retransmit = client.ControlBlock().SendUNA(), true
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
	if got := buf[sizeHeaderTCP:n]; string(got) != string(firstData) {
		t.Fatalf("retransmit payload=%q, want %q", got, firstData)
	}
}

// TestPolicy_PreTxRetransmitOutOfRange verifies an out-of-range rtxFrom is
// refused, leaving the send sequence and transmit buffer untouched.
func TestPolicy_PreTxRetransmitOutOfRange(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(9))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)

	pol := newRecordingPolicy()
	client.SetPolicy(pol)
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])

	if _, err := client.Write([]byte("payload")); err != nil {
		t.Fatal("client write:", err)
	}
	clear(buf[:])
	if _, err := client.Send(buf[:]); err != nil {
		t.Fatal("client send data:", err)
	}
	nxtBefore := client.ControlBlock().SendNext()

	// Well beyond snd.NXT: must be refused.
	pol.rtxFrom, pol.retransmit = nxtBefore+1000, true
	clear(buf[:])
	if _, err := client.Send(buf[:]); err != nil {
		t.Fatal("client send:", err)
	}
	if got := client.ControlBlock().SendNext(); got != nxtBefore {
		t.Fatalf("snd.NXT=%d, want unchanged %d: out-of-range rtxFrom must be refused", got, nxtBefore)
	}
}

// TestPolicy_HoldNew verifies holdNew suppresses new data while leaving control
// segments free to go out.
func TestPolicy_HoldNew(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(10))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)

	pol := newRecordingPolicy()
	client.SetPolicy(pol)
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])

	pol.holdNew = true
	if _, err := client.Write([]byte("payload")); err != nil {
		t.Fatal("client write:", err)
	}
	clear(buf[:])
	n, err := client.Send(buf[:])
	if err != nil {
		t.Fatal("client send:", err)
	}
	if n > sizeHeaderTCP {
		t.Fatalf("holdNew must suppress new data, got %d payload bytes", n-sizeHeaderTCP)
	}

	// Releasing the hold lets the same data out.
	pol.holdNew = false
	clear(buf[:])
	n, err = client.Send(buf[:])
	if err != nil {
		t.Fatal("client send after hold:", err)
	}
	if n <= sizeHeaderTCP {
		t.Fatal("data must flow once holdNew is cleared")
	}
}

// TestPolicy_ResetOnReopen verifies Reset fires on every (re)open and on Abort,
// so a single Policy value can be reused across connection reuse.
func TestPolicy_ResetOnReopen(t *testing.T) {
	const mtu = ethernet.MaxMTU
	client := newHandler(t, mtu, 3)
	pol := newRecordingPolicy()
	client.SetPolicy(pol)

	if err := client.OpenActive(1234, 5678, 0); err != nil {
		t.Fatal("open 1:", err)
	}
	afterOpen := pol.resets
	if afterOpen == 0 {
		t.Fatal("Reset not called on first open")
	}

	client.Abort()
	if pol.resets <= afterOpen {
		t.Fatalf("Reset not called on Abort: resets=%d, want >%d", pol.resets, afterOpen)
	}
	afterAbort := pol.resets

	if err := client.OpenActive(1234, 5678, 0); err != nil {
		t.Fatal("open 2:", err)
	}
	if pol.resets <= afterAbort {
		t.Fatalf("Reset not called on reopen: resets=%d, want >%d", pol.resets, afterAbort)
	}
}

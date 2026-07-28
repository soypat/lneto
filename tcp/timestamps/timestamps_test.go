package timestamps

import (
	"testing"

	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/tcp/rto"
)

const (
	mtu     = 1500
	bufSize = 4000
)

// tsClock returns a clock advancing one millisecond per read, so timestamp
// values are predictable.
func tsClock() func() int64 {
	var now int64
	return func() int64 {
		now += nanosPerMilli
		return now
	}
}

// pair returns two established handlers with the given policies installed and a
// scratch packet buffer.
func pair(t *testing.T, clientPolicy, serverPolicy tcp.Policy) (client, server *tcp.Handler, packet []byte) {
	t.Helper()
	client, server = new(tcp.Handler), new(tcp.Handler)
	for _, h := range []*tcp.Handler{client, server} {
		if err := h.SetBuffers(make([]byte, bufSize), make([]byte, bufSize), 4); err != nil {
			t.Fatal(err)
		}
	}
	if clientPolicy != nil {
		client.SetPolicy(clientPolicy, tsClock())
	}
	if serverPolicy != nil {
		server.SetPolicy(serverPolicy, tsClock())
	}
	if err := server.OpenListen(80, 0); err != nil {
		t.Fatal(err)
	}
	if err := client.OpenActive(1234, 80, 0); err != nil {
		t.Fatal(err)
	}
	packet = make([]byte, mtu)
	move(t, client, server, packet) // SYN
	move(t, server, client, packet) // SYN-ACK
	move(t, client, server, packet) // ACK
	if client.State() != tcp.StateEstablished || server.State() != tcp.StateEstablished {
		t.Fatalf("handshake failed: client=%s server=%s", client.State(), server.State())
	}
	return client, server, packet
}

func move(t *testing.T, from, to *tcp.Handler, packet []byte) int {
	t.Helper()
	clear(packet)
	n, err := from.Send(packet)
	if err != nil {
		t.Fatal("send:", err)
	}
	if n == 0 {
		return 0
	}
	if err = to.Recv(packet[:n]); err != nil {
		t.Fatal("recv:", err)
	}
	return n
}

// findTimestamp reports the Timestamps option in a serialized segment.
func findTimestamp(t *testing.T, packet []byte) (tsval, tsecr uint32, present bool) {
	t.Helper()
	frame, err := tcp.NewFrame(packet)
	if err != nil {
		t.Fatal("parse:", err)
	}
	var codec tcp.OptionCodec
	err = codec.ForEachOption(frame.Options(), func(kind tcp.OptionKind, data []byte) error {
		if kind == tcp.OptTimestamps && len(data) == optDataLen {
			tsval, tsecr, present = get32(data[0:4]), get32(data[4:8]), true
		}
		return nil
	})
	if err != nil {
		t.Fatal("walk options:", err)
	}
	return tsval, tsecr, present
}

// TestTimestamps_NegotiatedBothSides verifies both peers agree to use the option
// after a handshake in which both offered it.
func TestTimestamps_NegotiatedBothSides(t *testing.T) {
	clientTS, serverTS := new(Timestamps), new(Timestamps)
	pair(t, clientTS, serverTS)
	if !clientTS.Enabled() {
		t.Error("client did not negotiate timestamps")
	}
	if !serverTS.Enabled() {
		t.Error("server did not negotiate timestamps")
	}
}

// TestTimestamps_NotNegotiatedWithSilentPeer verifies the option stays disabled
// against a peer that never sends it, and that traffic still flows.
func TestTimestamps_NotNegotiatedWithSilentPeer(t *testing.T) {
	clientTS := new(Timestamps)
	client, server, packet := pair(t, clientTS, nil) // Server has no policy.
	if clientTS.Enabled() {
		t.Error("timestamps must not be enabled when the peer never echoes them")
	}
	data := []byte("still works")
	if _, err := client.Write(data); err != nil {
		t.Fatal("write:", err)
	}
	if n := move(t, client, server, packet); n == 0 {
		t.Fatal("no data segment sent")
	}
	got := make([]byte, len(data))
	n, err := server.Read(got)
	if err != nil {
		t.Fatal("read:", err)
	}
	if string(got[:n]) != string(data) {
		t.Errorf("server read %q, want %q", got[:n], data)
	}
}

// TestTimestamps_OnWireAndEchoed verifies post-handshake segments carry a TSval
// and echo the peer's most recent timestamp, and that an RTT sample is derived
// from the echo coming back.
func TestTimestamps_OnWireAndEchoed(t *testing.T) {
	clientTS, serverTS := new(Timestamps), new(Timestamps)
	client, server, packet := pair(t, clientTS, serverTS)

	if _, err := client.Write([]byte("payload")); err != nil {
		t.Fatal("write:", err)
	}
	clear(packet)
	n, err := client.Send(packet)
	if err != nil {
		t.Fatal("send:", err)
	}
	tsval, tsecr, present := findTimestamp(t, packet[:n])
	if !present {
		t.Fatal("no Timestamps option on an established-phase segment")
	}
	if tsval == 0 {
		t.Error("TSval should advance with the connection clock")
	}
	serverRecent, ok := serverTS.Recent()
	if !ok {
		t.Fatal("server recorded no TS.Recent")
	}
	if tsecr != serverRecent {
		// The client echoes what it last heard from the server.
		clientEcho, _ := clientTS.Recent()
		if tsecr != clientEcho {
			t.Errorf("TSecr=%d echoes neither side's recent value (client %d)", tsecr, clientEcho)
		}
	}

	// Deliver it and bring the server's ACK back: the client should now be able
	// to measure a round trip from its own echoed timestamp.
	if err = server.Recv(packet[:n]); err != nil {
		t.Fatal("server recv:", err)
	}
	if n = move(t, server, client, packet); n == 0 {
		t.Fatal("expected an ACK from the server")
	}
	if _, sampled := clientTS.LastRTT(); !sampled {
		t.Error("no RTT sample taken from the echoed timestamp")
	}
}

// TestTimestamps_RecentDoesNotRegress verifies TS.Recent follows the RFC 7323
// §4.3 rule and is not pulled backwards by an older timestamp.
func TestTimestamps_RecentDoesNotRegress(t *testing.T) {
	ts := new(Timestamps)
	ts.enabled = true
	ts.offered = true
	ts.recent, ts.haveRecent = 1000, true
	ts.haveEpoch = true

	ts.PostRx(acceptedWithTimestamp(500, 0, 100, 100))
	if got, _ := ts.Recent(); got != 1000 {
		t.Errorf("TS.Recent=%d after an older timestamp, want 1000", got)
	}
	ts.PostRx(acceptedWithTimestamp(2000, 0, 100, 100))
	if got, _ := ts.Recent(); got != 2000 {
		t.Errorf("TS.Recent=%d after a newer timestamp, want 2000", got)
	}
	// A newer timestamp on a segment ahead of what has been acknowledged is not
	// eligible to advance TS.Recent.
	ts.PostRx(acceptedWithTimestamp(3000, 0, 500, 100))
	if got, _ := ts.Recent(); got != 2000 {
		t.Errorf("TS.Recent=%d after an out-of-order segment, want it held at 2000", got)
	}
}

// TestTimestamps_PAWSDropsOldTimestamp verifies PAWS rejects a segment whose
// timestamp predates TS.Recent, and only when enabled.
func TestTimestamps_PAWSDropsOldTimestamp(t *testing.T) {
	for _, paws := range []bool{false, true} {
		ts := new(Timestamps)
		ts.Configure(Config{PAWS: paws})
		ts.enabled = true
		ts.offered = true
		ts.recent, ts.haveRecent = 1000, true
		ts.haveEpoch = true

		dir := ts.PreRx(rxWithTimestamp(500, 0, 100, 100))
		if paws && dir.Keep {
			t.Error("PAWS enabled: a segment older than TS.Recent must be dropped")
		}
		if !paws && !dir.Keep {
			t.Error("PAWS disabled: the segment must still be processed")
		}
	}
}

// TestTimestamps_MissingOptionDropped verifies that once negotiated, a segment
// without the option is dropped, while a RST is still honored (RFC 7323 §3.2).
func TestTimestamps_MissingOptionDropped(t *testing.T) {
	ts := new(Timestamps)
	ts.enabled = true
	ts.offered = true
	ts.haveEpoch = true

	plain := tcp.RxMeta{
		Segment: tcp.Segment{SEQ: 100, ACK: 1, Flags: tcp.FlagACK},
		RcvNXT:  100,
		Now:     nanosPerMilli,
	}
	if ts.PreRx(plain).Keep {
		t.Error("a segment missing the negotiated option must be dropped")
	}
	rst := tcp.RxMeta{
		Segment: tcp.Segment{SEQ: 100, Flags: tcp.FlagRST},
		RcvNXT:  100,
		Now:     nanosPerMilli,
	}
	if !ts.PreRx(rst).Keep {
		t.Error("a RST must be honored even without the option")
	}
}

// TestTimestamps_ImplausibleEchoIgnored verifies a nonsensical echo does not
// produce an RTT sample.
func TestTimestamps_ImplausibleEchoIgnored(t *testing.T) {
	ts := new(Timestamps)
	ts.enabled = true
	ts.offered = true
	ts.haveEpoch = true
	ts.epoch = 0

	// An echo from the future relative to our clock.
	ts.PostRx(acceptedWithTimestamp(10, 1_000_000, 100, 100))
	if _, sampled := ts.LastRTT(); sampled {
		t.Error("an echo ahead of our clock must not yield an RTT sample")
	}
	// An echo implausibly far in the past.
	ts.haveEpoch, ts.epoch = true, 0
	ev := acceptedWithTimestamp(10, 1, 100, 100)
	ev.Now = int64(maxPlausibleRTTMillis+10) * nanosPerMilli
	ts.PostRx(ev)
	if _, sampled := ts.LastRTT(); sampled {
		t.Error("an implausibly old echo must not yield an RTT sample")
	}
}

// TestTimestamps_ZeroAlloc verifies the policy keeps the datapath free of
// allocation.
func TestTimestamps_ZeroAlloc(t *testing.T) {
	clientTS, serverTS := new(Timestamps), new(Timestamps)
	client, server, packet := pair(t, clientTS, serverTS)
	data := make([]byte, 256)
	readBuf := make([]byte, 256)
	allocs := testing.AllocsPerRun(100, func() {
		if _, err := client.Write(data); err != nil {
			t.Fatal("write:", err)
		}
		if n := move(t, client, server, packet); n == 0 {
			t.Fatal("no data segment")
		}
		if _, err := server.Read(readBuf); err != nil {
			t.Fatal("read:", err)
		}
		move(t, server, client, packet)
	})
	if allocs != 0 {
		t.Errorf("timestamped exchange allocated %v times, want 0", allocs)
	}
}

// rxWithTimestamp builds received-segment metadata carrying a Timestamps option.
func rxWithTimestamp(tsval, tsecr uint32, seq, rcvNxt tcp.Value) tcp.RxMeta {
	opts := make([]byte, optLen)
	opts[0], opts[1] = byte(tcp.OptTimestamps), optLen
	put32(opts[2:6], tsval)
	put32(opts[6:10], tsecr)
	return tcp.RxMeta{
		Now:     nanosPerMilli,
		Segment: tcp.Segment{SEQ: seq, ACK: 1, Flags: tcp.FlagACK},
		Options: opts,
		RcvNXT:  rcvNxt,
	}
}

// acceptedWithTimestamp builds the post-acceptance event for the same segment
// rxWithTimestamp describes. Recording a timestamp and sampling the round trip are
// tied to a segment being acceptable, so they are driven from here.
func acceptedWithTimestamp(tsval, tsecr uint32, seq, rcvNxt tcp.Value) tcp.RxEvent {
	rx := rxWithTimestamp(tsval, tsecr, seq, rcvNxt)
	return tcp.RxEvent{
		Now:      rx.Now,
		Segment:  rx.Segment,
		Options:  rx.Options,
		RcvNXT:   rx.RcvNXT,
		Accepted: true,
	}
}

// TestTimestamps_NoRoomDoesNotNegotiate verifies the policy does not consider
// the option negotiated when there was no room to write it. Claiming otherwise
// would make this side drop every later segment from a peer that never agreed
// to send timestamps.
func TestTimestamps_NoRoomDoesNotNegotiate(t *testing.T) {
	ts := new(Timestamps)
	ts.recent, ts.haveRecent = 42, true // As if a peer SYN had been received.
	var tiny [optLen - 1]byte
	if n := ts.WriteOptions(tcp.TxPlan{Kind: tcp.TxKindSYNACK, Now: nanosPerMilli}, tiny[:]); n != 0 {
		t.Fatalf("wrote %d octets into a buffer too small for the option", n)
	}
	if ts.Enabled() {
		t.Error("option must not count as negotiated when it was not written")
	}
	var room [optLen]byte
	if n := ts.WriteOptions(tcp.TxPlan{Kind: tcp.TxKindSYNACK, Now: nanosPerMilli}, room[:]); n != optLen {
		t.Fatalf("wrote %d octets, want %d", n, optLen)
	}
	if ts.Enabled() {
		t.Error("writing the option is not yet an agreement; the segment may never be sent")
	}
	// Reporting the SYN-ACK as transmitted is what completes the negotiation.
	ts.PostTx(tcp.Segment{Flags: tcp.FlagSYN | tcp.FlagACK}, nanosPerMilli)
	if !ts.Enabled() {
		t.Error("answering a peer's offer should complete negotiation once sent")
	}
}

// TestTimestamps_SampleReachesEstimator verifies a round-trip sample taken from an
// echoed timestamp is folded into the retransmission timer, which is the point of
// the option for a sender. The documentation claimed this before the estimator had
// any entry point for an externally measured sample, so the timer was running on
// acknowledgement timing alone.
func TestTimestamps_SampleReachesEstimator(t *testing.T) {
	ts := new(Timestamps)
	ts.enabled = true
	ts.offered = true
	ts.haveEpoch = true
	ts.epoch = 0

	if got := ts.SmoothedRTT(); got != 0 {
		t.Fatalf("smoothed RTT is %d before any sample, want 0", got)
	}
	// An echo of the TSval we stamped one tick after our epoch, arriving 40ms of
	// our clock after that tick.
	const rttMillis = 40
	ev := acceptedWithTimestamp(10, 1, 100, 100)
	ev.Now = (rttMillis + 1) * nanosPerMilli
	ts.PostRx(ev)

	sample, ok := ts.LastRTT()
	if !ok {
		t.Fatal("expected an RTT sample from the echo")
	}
	if want := int64(rttMillis) * nanosPerMilli; sample != want {
		t.Errorf("sample = %d ns, want %d", sample, want)
	}
	if got := ts.SmoothedRTT(); got != sample {
		t.Errorf("smoothed RTT = %d, want the first sample %d to have reached the estimator",
			got, sample)
	}
}

// TestTimestamps_SampleBypassesKarn verifies a timestamp-derived sample is applied
// even though the timer's own sampling would have discarded it. An echo dates the
// acknowledgement unambiguously, so unlike acknowledgement timing it stays valid
// across a retransmission (RFC 7323 §4.1).
func TestTimestamps_SampleBypassesKarn(t *testing.T) {
	ts := new(Timestamps)
	ts.enabled = true
	ts.offered = true
	ts.haveEpoch = true
	ts.epoch = 0

	// No segment was ever handed to PostTx, so the timer has taken no sample of its
	// own and is not timing anything.
	const rttMillis = 25
	ev := acceptedWithTimestamp(10, 1, 100, 100)
	ev.Now = (rttMillis + 1) * nanosPerMilli
	ts.PostRx(ev)

	if got, want := ts.SmoothedRTT(), int64(rttMillis)*nanosPerMilli; got != want {
		t.Errorf("smoothed RTT = %d, want %d from the echo alone", got, want)
	}
}

// TestTimestamps_UnsentSynAckDoesNotNegotiate verifies the option is not treated as
// agreed because of a SYN-ACK that was built but never transmitted.
//
// WriteOptions runs before the segment is sized, so the transmit path can still fail
// after the policy has written its option: a buffer with room for the option but not
// for the padded header fails once the data offset is computed. Recording "in use" at
// the point the bytes are written therefore records an agreement the peer never saw.
// That is not a cosmetic error. Once enabled, RFC 7323 §3.2 makes this side drop every
// segment arriving without the option, so a peer that never agreed to send one is cut
// off entirely.
func TestTimestamps_UnsentSynAckDoesNotNegotiate(t *testing.T) {
	serverTS := new(Timestamps)
	client, server := new(tcp.Handler), new(tcp.Handler)
	for _, h := range []*tcp.Handler{client, server} {
		if err := h.SetBuffers(make([]byte, bufSize), make([]byte, bufSize), 4); err != nil {
			t.Fatal(err)
		}
	}
	client.SetPolicy(new(Timestamps), tsClock())
	server.SetPolicy(serverTS, tsClock())
	if err := server.OpenListen(80, 0); err != nil {
		t.Fatal(err)
	}
	if err := client.OpenActive(1234, 80, 0); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, mtu)
	move(t, client, server, packet) // SYN carrying the peer's offer.

	// Reply into a buffer that holds the option but not the padded header. The
	// option area starts at octet 27 (header plus the core's MSS and window scale)
	// and the option needs ten octets, so the write succeeds and the data offset
	// computation then does not fit.
	const tooSmall = 38
	_, err := server.Send(make([]byte, tooSmall))
	if err == nil {
		t.Fatal("expected the undersized buffer to be refused")
	}
	if serverTS.Enabled() {
		t.Error("timestamps recorded as negotiated by a SYN-ACK that was never sent")
	}

	// The consequence: a peer that never agreed to send timestamps must still be
	// heard. A segment without the option has to survive PreRx.
	seg := tcp.Segment{SEQ: 1, ACK: 1, WND: 1024, Flags: tcp.FlagACK}
	if !serverTS.PreRx(tcp.RxMeta{Now: nanosPerMilli, Segment: seg, State: tcp.StateSynRcvd}).Keep {
		t.Error("a segment without the option was dropped, cutting off a peer that never negotiated")
	}
}

// TestTimestamps_SampleReachesSharedTimer verifies a sample lands in the shared
// timer rather than in the private one the policy no longer uses.
//
// The shared timer here is driven by nothing else, so its estimate can only have
// come from this policy. That is the point: a policy sharing a timer whose samples
// went to its own unused timer would look correct in any test where the shared
// timer also samples acknowledgements for itself.
func TestTimestamps_SampleReachesSharedTimer(t *testing.T) {
	shared := new(rto.Timer)
	shared.Reset()
	ts := new(Timestamps)
	ts.SetTimer(shared)
	ts.enabled = true
	ts.offered = true
	ts.haveEpoch = true
	ts.epoch = 0

	if got := shared.SmoothedRTT(); got != 0 {
		t.Fatalf("shared timer has RTT %v before any sample, want 0", got)
	}
	const rttMillis = 40
	ev := acceptedWithTimestamp(10, 1, 100, 100)
	ev.Now = (rttMillis + 1) * nanosPerMilli
	ts.PostRx(ev)

	sample, ok := ts.LastRTT()
	if !ok {
		t.Fatal("expected an RTT sample from the echo")
	}
	if got := int64(shared.SmoothedRTT()); got != sample {
		t.Errorf("shared timer RTT = %d, want the sample %d: it went to the private timer", got, sample)
	}
	// The private timer must be untouched, so nothing is reading a stale estimate.
	if got := ts.timer.SmoothedRTT(); got != 0 {
		t.Errorf("private timer RTT = %v, want 0 while a shared timer is in use", got)
	}
}

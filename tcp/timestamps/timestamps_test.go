package timestamps

import (
	"testing"

	"github.com/soypat/lneto/tcp"
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
func pair(t *testing.T, clientPolicy, serverPolicy tcp.LossRecovery) (client, server *tcp.Handler, packet []byte) {
	t.Helper()
	client, server = new(tcp.Handler), new(tcp.Handler)
	for _, h := range []*tcp.Handler{client, server} {
		if err := h.SetBuffers(make([]byte, bufSize), make([]byte, bufSize), 4); err != nil {
			t.Fatal(err)
		}
	}
	if clientPolicy != nil {
		client.SetLossRecovery(clientPolicy, tsClock())
	}
	if serverPolicy != nil {
		server.SetLossRecovery(serverPolicy, tsClock())
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

	older := rxWithTimestamp(500, 0, 100, 100)
	ts.PreRx(older)
	if got, _ := ts.Recent(); got != 1000 {
		t.Errorf("TS.Recent=%d after an older timestamp, want 1000", got)
	}
	newer := rxWithTimestamp(2000, 0, 100, 100)
	ts.PreRx(newer)
	if got, _ := ts.Recent(); got != 2000 {
		t.Errorf("TS.Recent=%d after a newer timestamp, want 2000", got)
	}
	// A newer timestamp on a segment ahead of what has been acknowledged is not
	// eligible to advance TS.Recent.
	ahead := rxWithTimestamp(3000, 0, 500, 100)
	ts.PreRx(ahead)
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
	ts.PreRx(rxWithTimestamp(10, 1_000_000, 100, 100))
	if _, sampled := ts.LastRTT(); sampled {
		t.Error("an echo ahead of our clock must not yield an RTT sample")
	}
	// An echo implausibly far in the past.
	ts.haveEpoch, ts.epoch = true, 0
	rx := rxWithTimestamp(10, 1, 100, 100)
	rx.Now = int64(maxPlausibleRTTMillis+10) * nanosPerMilli
	ts.PreRx(rx)
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
	if !ts.Enabled() {
		t.Error("answering a peer's offer should complete negotiation")
	}
}

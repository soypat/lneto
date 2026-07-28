package tcp

import (
	"math/rand"
	"testing"

	"github.com/soypat/lneto/ethernet"
)

// TestECNSetupSYNFromPeer verifies a peer offering ECN is not turned away. It sets ECE
// and CWR on its SYN (RFC 3168 §6.1.1), which Linux does by default, so a listener
// that declines ECN must still complete the handshake and simply not use the flags.
//
// Worth pinning separately from ECN itself: this is the common case on the wire
// whether or not this side implements anything, and several control-flag comparisons
// on the transmit path match flags exactly.
func TestECNSetupSYNFromPeer(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(41))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte

	// Client SYN, with the ECN-setup flags a capable peer would add.
	clear(buf[:])
	n, err := client.Send(buf[:])
	if err != nil {
		t.Fatal("client SYN:", err)
	}
	tfrm, err := NewFrame(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	seg := tfrm.Segment(0)
	if seg.Flags != FlagSYN {
		t.Fatalf("client SYN flags = %s, want just SYN", seg.Flags)
	}
	seg.Flags |= FlagECE | FlagCWR
	tfrm.SetSegment(seg, 5+uint8(len(tfrm.Options())/4))
	t.Logf("offering ECN-setup SYN with flags %s", seg.Flags)

	if err = server.Recv(buf[:n]); err != nil {
		t.Fatalf("server refused an ECN-setup SYN: %v", err)
	}
	if server.State() != StateSynRcvd {
		t.Fatalf("server state = %s after an ECN-setup SYN, want SYN-RCVD", server.State())
	}
	clear(buf[:])
	n, err = server.Send(buf[:])
	if err != nil || n == 0 {
		t.Fatalf("server SYN-ACK: n=%d err=%v", n, err)
	}
	if err = client.Recv(buf[:n]); err != nil {
		t.Fatal("client recv SYN-ACK:", err)
	}
	clear(buf[:])
	n, _ = client.Send(buf[:])
	if n > 0 {
		if err = server.Recv(buf[:n]); err != nil {
			t.Fatal("server recv ACK:", err)
		}
	}
	if client.State() != StateEstablished || server.State() != StateEstablished {
		t.Fatalf("handshake failed with an ECN-capable peer: client=%s server=%s", client.State(), server.State())
	}
}

// ecnPair returns two established handlers with ECN enabled as configured, plus a
// scratch buffer. The handshake is driven by hand so the ECN-setup flags on the SYN
// and SYN-ACK can be inspected as they cross.
func ecnPair(t *testing.T, clientECN, serverECN bool) (client, server *Handler, buf []byte) {
	t.Helper()
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(43))
	client, server = newHandler(t, mtu, 3), newHandler(t, mtu, 3)
	client.EnableECN(clientECN)
	server.EnableECN(serverECN)
	setupClientServer(t, rng, client, server)
	buf = make([]byte, mtu)

	// SYN.
	clear(buf)
	n, err := client.Send(buf)
	if err != nil {
		t.Fatal("client SYN:", err)
	}
	syn := segmentOf(t, buf[:n])
	if clientECN != syn.Flags.HasAll(FlagECE|FlagCWR) {
		t.Errorf("SYN flags %s: ECN-setup flags present=%v, want %v",
			syn.Flags, syn.Flags.HasAll(FlagECE|FlagCWR), clientECN)
	}
	if err = server.Recv(buf[:n]); err != nil {
		t.Fatal("server recv SYN:", err)
	}
	// SYN-ACK.
	clear(buf)
	n, err = server.Send(buf)
	if err != nil {
		t.Fatal("server SYN-ACK:", err)
	}
	synack := segmentOf(t, buf[:n])
	wantEcho := clientECN && serverECN
	if got := synack.Flags.HasAny(FlagECE) && !synack.Flags.HasAny(FlagCWR); got != wantEcho {
		t.Errorf("SYN-ACK flags %s: ECN-setup answer present=%v, want %v", synack.Flags, got, wantEcho)
	}
	if err = client.Recv(buf[:n]); err != nil {
		t.Fatal("client recv SYN-ACK:", err)
	}
	// ACK.
	clear(buf)
	n, _ = client.Send(buf)
	if n > 0 {
		if err = server.Recv(buf[:n]); err != nil {
			t.Fatal("server recv ACK:", err)
		}
	}
	if client.State() != StateEstablished || server.State() != StateEstablished {
		t.Fatalf("handshake failed: client=%s server=%s", client.State(), server.State())
	}
	return client, server, buf
}

func segmentOf(t *testing.T, packet []byte) Segment {
	t.Helper()
	tfrm, err := NewFrame(packet)
	if err != nil {
		t.Fatal(err)
	}
	return tfrm.Segment(len(tfrm.Payload()))
}

// sendData writes payload and moves one segment, returning the segment as it went on
// the wire.
func sendData(t *testing.T, from, to *Handler, buf, payload []byte, ecn uint8) Segment {
	t.Helper()
	if len(payload) > 0 {
		if _, err := from.Write(payload); err != nil {
			t.Fatal("write:", err)
		}
	}
	clear(buf)
	n, err := from.Send(buf)
	if err != nil {
		t.Fatal("send:", err)
	}
	if n == 0 {
		t.Fatal("nothing sent")
	}
	seg := segmentOf(t, buf[:n])
	if to != nil {
		if err = to.RecvWithECN(buf[:n], ecn); err != nil {
			t.Fatal("recv:", err)
		}
	}
	return seg
}

// TestECNNegotiation verifies ECN is in use only when both sides asked for it.
func TestECNNegotiation(t *testing.T) {
	for _, test := range []struct {
		name           string
		client, server bool
		want           bool
	}{
		{name: "both", client: true, server: true, want: true},
		{name: "neither"},
		{name: "client only", client: true},
		{name: "server only", server: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, server, _ := ecnPair(t, test.client, test.server)
			if got := client.ECNEnabled(); got != test.want {
				t.Errorf("client ECNEnabled=%v, want %v", got, test.want)
			}
			if got := server.ECNEnabled(); got != test.want {
				t.Errorf("server ECNEnabled=%v, want %v", got, test.want)
			}
		})
	}
}

// TestECNCodepointOnlyWhenNegotiated verifies packets are marked ECN-capable only once
// both sides agreed. Marking otherwise asks routers to mark instead of drop while the
// peer has no way to report the mark, so congestion would go unsignalled entirely.
func TestECNCodepointOnlyWhenNegotiated(t *testing.T) {
	client, _, _ := ecnPair(t, true, true)
	if got := client.ECNCodepoint(); got != ECNECT0 {
		t.Errorf("codepoint=%02b on a negotiated connection, want ECT(0) %02b", got, ECNECT0)
	}
	lone, _, _ := ecnPair(t, true, false)
	if got := lone.ECNCodepoint(); got != ECNNotECT {
		t.Errorf("codepoint=%02b against a peer that declined, want Not-ECT %02b", got, ECNNotECT)
	}
}

// TestECNEchoesUntilAnswered verifies a congestion mark keeps being echoed until the
// peer answers with CWR, so that losing the acknowledgement carrying the echo does not
// lose the congestion signal.
//
// RFC 3168 §6.1.3 requires the repetition, and a dropped acknowledgement is exactly
// the case it exists for: a single ECE that goes missing leaves the sender pushing into
// a congested path having been told nothing. The first echo is deliberately withheld
// from the client here, which also keeps the client from answering it — an answer would
// legitimately stop the echo, which is asserted afterwards.
func TestECNEchoesUntilAnswered(t *testing.T) {
	client, server, buf := ecnPair(t, true, true)
	if !server.ECNEnabled() {
		t.Fatal("negotiation failed")
	}
	payload := []byte("congested")
	got := make([]byte, len(payload))

	// Client data arrives carrying a congestion mark.
	sendData(t, client, server, buf, payload, ECNCE)
	if _, err := server.Read(got); err != nil {
		t.Fatal("read:", err)
	}
	// The server reports it, and that report is lost in transit.
	clear(buf)
	n, err := server.Send(buf)
	if err != nil {
		t.Fatal("server ack:", err)
	}
	if n == 0 {
		t.Fatal("server sent no acknowledgement for marked data")
	}
	if lost := segmentOf(t, buf[:n]); !lost.Flags.HasAny(FlagECE) {
		t.Fatalf("first acknowledgement does not echo the mark: flags %s", lost.Flags)
	}

	// More client data, which cannot answer a report it never received.
	sendData(t, client, server, buf, payload, ECNNotECT)
	if _, err = server.Read(got); err != nil {
		t.Fatal("read:", err)
	}
	clear(buf)
	n, err = server.Send(buf)
	if err != nil {
		t.Fatal("server ack 2:", err)
	}
	if n == 0 {
		t.Fatal("server sent no second acknowledgement")
	}
	second := segmentOf(t, buf[:n])
	if !second.Flags.HasAny(FlagECE) {
		t.Fatalf("the congestion signal was dropped with the lost acknowledgement: flags %s", second.Flags)
	}
	if err = client.Recv(buf[:n]); err != nil {
		t.Fatal("client recv ack:", err)
	}

	// The client now owes a CWR, which must ride on data rather than a bare ACK: a
	// pure acknowledgement makes no claim about the sending rate.
	seg := sendData(t, client, server, buf, payload, ECNNotECT)
	if !seg.Flags.HasAny(FlagCWR) {
		t.Errorf("data segment after being told of congestion has flags %s, want CWR", seg.Flags)
	}
	if _, err = server.Read(got); err != nil {
		t.Fatal("read:", err)
	}
	// Having been answered, the server stops echoing.
	clear(buf)
	n, err = server.Send(buf)
	if err != nil {
		t.Fatal("server ack after CWR:", err)
	}
	if n > 0 {
		if ack := segmentOf(t, buf[:n]); ack.Flags.HasAny(FlagECE) {
			t.Errorf("still echoing after the peer answered with CWR: flags %s", ack.Flags)
		}
	}
	// And the CWR is discharged rather than repeated on every later segment.
	seg = sendData(t, client, server, buf, payload, ECNNotECT)
	if seg.Flags.HasAny(FlagCWR) {
		t.Errorf("CWR repeated on a later segment: flags %s", seg.Flags)
	}
}

// TestECNMarkIgnoredWithoutNegotiation verifies a mark on a connection that never
// negotiated ECN is not echoed. The codepoint would then be whatever the IP header
// happened to contain, and reporting it invents congestion the path never signalled.
func TestECNMarkIgnoredWithoutNegotiation(t *testing.T) {
	client, server, buf := ecnPair(t, false, false)
	payload := []byte("not negotiated")
	sendData(t, client, server, buf, payload, ECNCE)
	got := make([]byte, len(payload))
	if _, err := server.Read(got); err != nil {
		t.Fatal("read:", err)
	}
	clear(buf)
	n, err := server.Send(buf)
	if err != nil {
		t.Fatal("server ack:", err)
	}
	if n > 0 {
		if ack := segmentOf(t, buf[:n]); ack.Flags.HasAny(FlagECE) {
			t.Errorf("echoed a congestion mark without having negotiated ECN: flags %s", ack.Flags)
		}
	}
}

// TestECNResetClearsNegotiation verifies a reused connection renegotiates ECN and does
// not carry a previous peer's congestion state, while keeping the configured request.
func TestECNResetClearsNegotiation(t *testing.T) {
	var tcb ControlBlock
	tcb.EnableECN(true)
	tcb.ecn.peerOffered, tcb.ecn.enabled, tcb.ecn.echoCE, tcb.ecn.sendCWR = true, true, true, true
	tcb.reset()
	if tcb.ECNEnabled() {
		t.Error("negotiation survived a reset, so a new peer is assumed to have agreed")
	}
	if tcb.ecn.echoCE || tcb.ecn.sendCWR {
		t.Error("congestion state survived a reset, so a new connection starts owing a signal")
	}
	if !tcb.ecn.requested {
		t.Error("the configured request was cleared by a reset")
	}
}

// ecnEstablished returns a control block in ESTABLISHED with ECN negotiated, for
// testing the ECN state machine directly.
func ecnEstablished(t *testing.T) *ControlBlock {
	t.Helper()
	var tcb ControlBlock
	tcb.EnableECN(true)
	tcb.prepareToHandshake(1000, 4096, StateEstablished)
	tcb.snd.WND = 4096
	tcb.snd.UNA, tcb.snd.NXT = 1000, 1000
	tcb.rcv.NXT, tcb.rcv.WND = 5000, 4096
	tcb.ecn.peerOffered, tcb.ecn.offered, tcb.ecn.enabled = true, true, true
	return &tcb
}

// TestECNSetupSYNNeedsBothFlags verifies only a SYN carrying both ECE and CWR counts
// as an offer, as RFC 3168 §6.1.1 defines it.
//
// The distinction is what separates an offer from a SYN that happens to carry
// congestion signalling, and RFC 3168 §6.1.1 gives it deliberately so that a middlebox
// setting one flag cannot fabricate a negotiation neither endpoint asked for.
func TestECNSetupSYNNeedsBothFlags(t *testing.T) {
	for _, test := range []struct {
		name  string
		flags Flags
		want  bool
	}{
		{name: "both", flags: FlagSYN | FlagECE | FlagCWR, want: true},
		{name: "ECE only", flags: FlagSYN | FlagECE},
		{name: "CWR only", flags: FlagSYN | FlagCWR},
		{name: "neither", flags: FlagSYN},
	} {
		t.Run(test.name, func(t *testing.T) {
			var tcb ControlBlock
			tcb.EnableECN(true)
			tcb.ecnRecvFlags(Segment{Flags: test.flags, WND: 4096})
			if got := tcb.ecn.peerOffered; got != test.want {
				t.Errorf("peerOffered=%v for SYN flags %s, want %v", got, test.flags, test.want)
			}
		})
	}
}

// TestECNSetupSYNACKMustNotCarryCWR verifies a SYN-ACK with both flags is not taken as
// agreement. RFC 3168 §6.1.1 makes the answer ECE alone; both set is a peer reflecting
// our own SYN flags rather than agreeing, and treating it as agreement would enable ECN
// against a peer that never implemented it.
func TestECNSetupSYNACKMustNotCarryCWR(t *testing.T) {
	for _, test := range []struct {
		name  string
		flags Flags
		want  bool
	}{
		{name: "ECE only", flags: FlagSYN | FlagACK | FlagECE, want: true},
		{name: "both reflected", flags: FlagSYN | FlagACK | FlagECE | FlagCWR},
		{name: "neither", flags: FlagSYN | FlagACK},
	} {
		t.Run(test.name, func(t *testing.T) {
			var tcb ControlBlock
			tcb.EnableECN(true)
			tcb.ecn.offered = true // As if our ECN-setup SYN had gone out.
			tcb.ecnRecvFlags(Segment{Flags: test.flags, WND: 4096})
			if got := tcb.ECNEnabled(); got != test.want {
				t.Errorf("ECNEnabled=%v for SYN-ACK flags %s, want %v", got, test.flags, test.want)
			}
		})
	}
}

// TestECNCWROnlyOnData verifies the CWR answer rides on a data segment and not on a
// bare acknowledgement. CWR states that the sending rate has been reduced (RFC 3168
// §6.1.2), which a segment carrying no data makes no claim about; spending it on one
// would discharge the answer without the peer learning anything, and the peer would
// keep echoing.
func TestECNCWROnlyOnData(t *testing.T) {
	tcb := ecnEstablished(t)
	tcb.ecn.sendCWR = true

	bare := Segment{SEQ: tcb.snd.NXT, ACK: tcb.rcv.NXT, WND: 4096, Flags: FlagACK}
	if flags := tcb.ecnSendFlags(bare); flags.HasAny(FlagCWR) {
		t.Errorf("bare acknowledgement got flags %s, want no CWR", flags)
	}
	if !tcb.ecn.sendCWR {
		t.Error("the owed CWR was discharged by a segment that did not carry it")
	}
	withData := Segment{SEQ: tcb.snd.NXT, ACK: tcb.rcv.NXT, WND: 4096, DATALEN: 100, Flags: FlagACK}
	if flags := tcb.ecnSendFlags(withData); !flags.HasAny(FlagCWR) {
		t.Errorf("data segment got flags %s, want CWR", flags)
	}
}

// TestECNMarkNotRecordedWithoutNegotiation verifies a congestion mark is not recorded
// at all unless ECN was negotiated. Downstream the echo is suppressed anyway, so this
// pins the intent rather than a reachable failure: the state should not carry a
// congestion signal the connection has no right to report.
func TestECNMarkNotRecordedWithoutNegotiation(t *testing.T) {
	var tcb ControlBlock
	tcb.EnableECN(true) // Requested, but the peer never agreed.
	tcb.observeECN(ECNCE)
	if tcb.ecn.echoCE {
		t.Error("recorded a congestion mark on a connection that never negotiated ECN")
	}
	tcb.ecn.enabled = true
	tcb.observeECN(ECNCE)
	if !tcb.ecn.echoCE {
		t.Error("did not record a congestion mark on a negotiated connection")
	}
}

// TestECNUnsentSegmentDoesNotDischargeCWR verifies the owed CWR survives a segment that
// was built and never transmitted, the same rule the timestamp option and the window
// scale offer need. A connection that believed it had answered a congestion report
// would never answer it, and the peer would echo forever.
func TestECNUnsentSegmentDoesNotDischargeCWR(t *testing.T) {
	tcb := ecnEstablished(t)
	tcb.ecn.sendCWR = true
	seg := Segment{SEQ: tcb.snd.NXT, ACK: tcb.rcv.NXT, WND: 4096, DATALEN: 100, Flags: FlagACK}
	seg.Flags |= tcb.ecnSendFlags(seg)
	if !seg.Flags.HasAny(FlagCWR) {
		t.Fatal("no CWR to lose")
	}
	// Choosing the flags must not discharge it; only transmission does.
	if !tcb.ecn.sendCWR {
		t.Error("the owed CWR was discharged where the flags were chosen, not where the segment was sent")
	}
	tcb.ecnSent(seg)
	if tcb.ecn.sendCWR {
		t.Error("the owed CWR survived the segment carrying it being sent")
	}
}

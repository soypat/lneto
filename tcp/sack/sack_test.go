package sack

import (
	"testing"

	"github.com/soypat/lneto/tcp"
)

const (
	mtu     = 1500
	bufSize = 8000
)

// pair returns two established handlers with the given policies installed, plus a
// scratch packet buffer.
func pair(t *testing.T, clientPolicy, serverPolicy tcp.Policy) (client, server *tcp.Handler, packet []byte) {
	t.Helper()
	client, server = new(tcp.Handler), new(tcp.Handler)
	for _, h := range []*tcp.Handler{client, server} {
		if err := h.SetBuffers(make([]byte, bufSize), make([]byte, bufSize), 8); err != nil {
			t.Fatal(err)
		}
	}
	clock := func() int64 { return 1 }
	if clientPolicy != nil {
		client.SetPolicy(clientPolicy, clock)
	}
	if serverPolicy != nil {
		server.SetPolicy(serverPolicy, clock)
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

// hasOption reports whether a serialized segment carries the given option kind.
func hasOption(t *testing.T, packet []byte, want tcp.OptionKind) bool {
	t.Helper()
	frame, err := tcp.NewFrame(packet)
	if err != nil {
		t.Fatal("parse:", err)
	}
	var codec tcp.OptionCodec
	found := false
	err = codec.ForEachOption(frame.Options(), func(kind tcp.OptionKind, _ []byte) error {
		if kind == want {
			found = true
		}
		return nil
	})
	if err != nil {
		t.Fatal("walk options:", err)
	}
	return found
}

// TestSACK_NegotiatedBothSides verifies both peers agree to use the option after a
// handshake in which both offered it, and that the offer is on the wire.
func TestSACK_NegotiatedBothSides(t *testing.T) {
	clientSACK, serverSACK := new(SACK), new(SACK)
	client, server := new(tcp.Handler), new(tcp.Handler)
	for _, h := range []*tcp.Handler{client, server} {
		if err := h.SetBuffers(make([]byte, bufSize), make([]byte, bufSize), 8); err != nil {
			t.Fatal(err)
		}
	}
	clock := func() int64 { return 1 }
	client.SetPolicy(clientSACK, clock)
	server.SetPolicy(serverSACK, clock)
	if err := server.OpenListen(80, 0); err != nil {
		t.Fatal(err)
	}
	if err := client.OpenActive(1234, 80, 0); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, mtu)

	// The SYN must carry the offer.
	clear(packet)
	n, err := client.Send(packet)
	if err != nil {
		t.Fatal("client SYN:", err)
	}
	if !hasOption(t, packet[:n], tcp.OptSACKPermitted) {
		t.Error("the SYN does not carry SACK-Permitted")
	}
	if err = server.Recv(packet[:n]); err != nil {
		t.Fatal("server recv SYN:", err)
	}
	// So must the SYN-ACK answering it.
	clear(packet)
	n, err = server.Send(packet)
	if err != nil {
		t.Fatal("server SYN-ACK:", err)
	}
	if !hasOption(t, packet[:n], tcp.OptSACKPermitted) {
		t.Error("the SYN-ACK does not carry SACK-Permitted")
	}
	if err = client.Recv(packet[:n]); err != nil {
		t.Fatal("client recv SYN-ACK:", err)
	}
	move(t, client, server, packet) // ACK

	if !clientSACK.Enabled() {
		t.Error("client did not negotiate selective acknowledgement")
	}
	if !serverSACK.Enabled() {
		t.Error("server did not negotiate selective acknowledgement")
	}
}

// TestSACK_NotNegotiatedWithSilentPeer verifies the option stays disabled against a
// peer that never offers it, and that traffic still flows. Acting on blocks a peer
// never agreed to send would be reading whatever happened to be in the option area.
func TestSACK_NotNegotiatedWithSilentPeer(t *testing.T) {
	clientSACK := new(SACK)
	client, server, packet := pair(t, clientSACK, nil) // Server has no policy.
	if clientSACK.Enabled() {
		t.Error("selective acknowledgement must not be enabled when the peer never offered it")
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

// TestSACK_ListenerDoesNotOfferUnasked verifies a listener does not put the option
// on a SYN-ACK when the peer's SYN did not offer it. RFC 2018 §2 makes it an answer
// to an offer, not something a responder introduces.
func TestSACK_ListenerDoesNotOfferUnasked(t *testing.T) {
	s := new(SACK)
	var opts [8]byte
	if n := s.WriteOptions(tcp.TxPlan{Kind: tcp.TxKindSYNACK}, opts[:]); n != 0 {
		t.Errorf("wrote %d octets on a SYN-ACK answering a peer that never offered", n)
	}
	if s.Enabled() {
		t.Error("negotiated without the peer having offered")
	}
}

// TestSACK_UnsentOfferDoesNotNegotiate verifies the option is not treated as agreed
// because of a segment that was built and never transmitted, the same rule the
// timestamp option needs. Acting on blocks from a peer that never agreed to send
// them means acting on whatever the option area happened to contain.
func TestSACK_UnsentOfferDoesNotNegotiate(t *testing.T) {
	s := new(SACK)
	s.peerPermitted = true // As if a peer's SYN had arrived.
	var opts [8]byte
	if n := s.WriteOptions(tcp.TxPlan{Kind: tcp.TxKindSYNACK}, opts[:]); n != sizeOptionPermitted {
		t.Fatalf("wrote %d octets, want %d", n, sizeOptionPermitted)
	}
	if s.Enabled() {
		t.Error("writing the option is not yet an agreement; the segment may never be sent")
	}
	// Reporting the SYN-ACK as transmitted is what completes the negotiation.
	s.PostTx(tcp.Segment{Flags: tcp.FlagSYN | tcp.FlagACK}, 1)
	if !s.Enabled() {
		t.Error("a transmitted SYN-ACK answering an offer should complete negotiation")
	}
}

// TestSACK_NoRoomDoesNotNegotiate verifies a cramped option area leaves the option
// unnegotiated rather than half-agreed.
func TestSACK_NoRoomDoesNotNegotiate(t *testing.T) {
	s := new(SACK)
	s.peerPermitted = true
	var tiny [sizeOptionPermitted - 1]byte
	if n := s.WriteOptions(tcp.TxPlan{Kind: tcp.TxKindSYNACK}, tiny[:]); n != 0 {
		t.Fatalf("wrote %d octets into a buffer too small for the option", n)
	}
	s.PostTx(tcp.Segment{Flags: tcp.FlagSYN | tcp.FlagACK}, 1)
	if s.Enabled() {
		t.Error("negotiated although the option was never written")
	}
}

// TestSACK_ResetClearsNegotiation verifies a reused connection renegotiates rather
// than assuming the previous peer's agreement.
func TestSACK_ResetClearsNegotiation(t *testing.T) {
	s := new(SACK)
	s.peerPermitted, s.offered, s.enabled = true, true, true
	s.Reset()
	if s.Enabled() {
		t.Error("negotiation survived a reset, so a new peer is assumed to have agreed")
	}
}

// TestSACK_ZeroAlloc verifies driving the policy allocates nothing.
func TestSACK_ZeroAlloc(t *testing.T) {
	s := new(SACK)
	s.peerPermitted = true
	var opts [40]byte
	seg := tcp.Segment{SEQ: 1000, ACK: 500, WND: 4096, Flags: tcp.FlagACK}
	allocs := testing.AllocsPerRun(200, func() {
		s.PreRx(tcp.RxMeta{Segment: seg, Options: opts[:2]})
		s.PostRx(tcp.RxEvent{Segment: seg, Accepted: true, Options: opts[:2]})
		s.PreTx(tcp.TxIntent{UNA: 500, NXT: 1000})
		s.WriteOptions(tcp.TxPlan{Kind: tcp.TxKindSegment}, opts[:])
		s.PostTx(seg, 1)
		s.NextDeadline()
	})
	if allocs != 0 {
		t.Errorf("policy allocated %v times per iteration, want 0", allocs)
	}
}

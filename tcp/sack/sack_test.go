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

// sackBlocks returns the SACK blocks carried by a serialized segment.
func sackBlocks(t *testing.T, packet []byte) ([]Block, bool) {
	t.Helper()
	frame, err := tcp.NewFrame(packet)
	if err != nil {
		t.Fatal("parse:", err)
	}
	var codec tcp.OptionCodec
	var blocks []Block
	present := false
	err = codec.ForEachOption(frame.Options(), func(kind tcp.OptionKind, data []byte) error {
		if kind != tcp.OptSACK {
			return nil
		}
		present = true
		if len(data)%blockLen != 0 {
			t.Errorf("SACK option data is %d octets, not a multiple of %d", len(data), blockLen)
			return nil
		}
		for off := 0; off+blockLen <= len(data); off += blockLen {
			blocks = append(blocks, Block{
				Left:  tcp.Value(get32(data[off:])),
				Right: tcp.Value(get32(data[off+4:])),
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal("walk options:", err)
	}
	return blocks, present
}

// TestSACK_AdvertisesHeldBlocks verifies a receiver holding out-of-order data reports
// it, so the sender learns which of its segments arrived rather than only where the
// stream stalled.
func TestSACK_AdvertisesHeldBlocks(t *testing.T) {
	clientSACK, serverSACK := new(SACK), new(SACK)
	client, server, packet := pair(t, clientSACK, serverSACK)
	if !serverSACK.Enabled() {
		t.Fatal("negotiation failed")
	}
	const seglen = 100
	payload := make([]byte, seglen)
	for i := range payload {
		payload[i] = byte(i)
	}

	// Send three segments but drop the first, so the server holds the last two out
	// of order behind a hole.
	var dropped []byte
	for i := range 3 {
		if _, err := client.Write(payload); err != nil {
			t.Fatal("write:", err)
		}
		clear(packet)
		n, err := client.Send(packet)
		if err != nil {
			t.Fatal("send:", err)
		}
		if n == 0 {
			t.Fatalf("segment %d not sent", i)
		}
		if i == 0 {
			dropped = append(dropped, packet[:n]...) // Withheld from the server.
			continue
		}
		if err = server.Recv(packet[:n]); err != nil {
			t.Fatal("server recv:", err)
		}
	}

	// The server's acknowledgement must describe what it is holding.
	clear(packet)
	n, err := server.Send(packet)
	if err != nil {
		t.Fatal("server ack:", err)
	}
	if n == 0 {
		t.Fatal("server sent no acknowledgement")
	}
	blocks, present := sackBlocks(t, packet[:n])
	if !present {
		t.Fatal("the acknowledgement carries no SACK option while data is held out of order")
	}
	if len(blocks) == 0 {
		t.Fatal("the SACK option carries no blocks")
	}
	// The held data is contiguous, so it is one block covering the two segments
	// after the hole.
	total := tcp.Size(0)
	for _, b := range blocks {
		if !b.Left.LessThan(b.Right) {
			t.Errorf("block %v is empty or reversed", b)
		}
		total += b.Len()
	}
	if total != 2*seglen {
		t.Errorf("blocks cover %d octets, want %d (the two segments held behind the hole)", total, 2*seglen)
	}

	// Once the hole is filled the option goes away: there is nothing out of order
	// left to describe, and the cumulative acknowledgement says it all.
	if err = server.Recv(dropped); err != nil {
		t.Fatal("server recv the withheld segment:", err)
	}
	clear(packet)
	n, err = server.Send(packet)
	if err != nil {
		t.Fatal("server ack after fill:", err)
	}
	if n > 0 {
		if _, present = sackBlocks(t, packet[:n]); present {
			t.Error("the acknowledgement still carries blocks after the hole was filled")
		}
	}
	// All three segments must have been delivered in order.
	got := make([]byte, 3*seglen)
	read := 0
	for read < len(got) {
		nr, err := server.Read(got[read:])
		if err != nil || nr == 0 {
			break
		}
		read += nr
	}
	if read != 3*seglen {
		t.Errorf("server delivered %d octets, want %d", read, 3*seglen)
	}
}

// TestSACK_NoBlocksWithoutNegotiation verifies blocks are not sent to a peer that
// never agreed to receive them, which would be an unrecognised option at best.
//
// Driven through a real connection because the held-block view cannot be constructed
// from outside the tcp package: a unit call with an empty view returns zero whether
// or not the negotiation is checked, so it cannot tell the two apart.
func TestSACK_NoBlocksWithoutNegotiation(t *testing.T) {
	serverSACK := new(SACK)
	// The client runs no policy, so it never offers and the option stays unnegotiated
	// even though the server would use it.
	client, server, packet := pair(t, nil, serverSACK)
	if serverSACK.Enabled() {
		t.Fatal("negotiated with a peer that never offered")
	}
	const seglen = 100
	payload := make([]byte, seglen)

	// Give the server data out of order, so it is holding blocks it could report.
	var dropped []byte
	for i := range 3 {
		if _, err := client.Write(payload); err != nil {
			t.Fatal("write:", err)
		}
		clear(packet)
		n, err := client.Send(packet)
		if err != nil {
			t.Fatal("send:", err)
		}
		if n == 0 {
			t.Fatalf("segment %d not sent", i)
		}
		if i == 0 {
			dropped = append(dropped, packet[:n]...)
			continue
		}
		if err = server.Recv(packet[:n]); err != nil {
			t.Fatal("server recv:", err)
		}
	}
	clear(packet)
	n, err := server.Send(packet)
	if err != nil {
		t.Fatal("server ack:", err)
	}
	if n == 0 {
		t.Fatal("server sent no acknowledgement")
	}
	if blocks, present := sackBlocks(t, packet[:n]); present {
		t.Errorf("sent %d blocks to a peer that never agreed to receive them: %v", len(blocks), blocks)
	}
	// The connection must still work, holes and all.
	if err = server.Recv(dropped); err != nil {
		t.Fatal("server recv the withheld segment:", err)
	}
	got := make([]byte, 3*seglen)
	read := 0
	for read < len(got) {
		nr, err := server.Read(got[read:])
		if err != nil || nr == 0 {
			break
		}
		read += nr
	}
	if read != 3*seglen {
		t.Errorf("server delivered %d octets, want %d", read, 3*seglen)
	}
}

// TestSACK_BlocksNeverOnASYN verifies the option is not put on a SYN, which RFC 2018
// §3 forbids: a SYN has nothing to acknowledge selectively, and SACK-Permitted is
// the option that belongs there.
func TestSACK_BlocksNeverOnASYN(t *testing.T) {
	s := new(SACK)
	s.enabled, s.peerPermitted = true, true
	var opts [40]byte
	n := s.WriteOptions(tcp.TxPlan{Kind: tcp.TxKindSYN}, opts[:])
	if n != sizeOptionPermitted {
		t.Fatalf("SYN carries %d octets of options, want just SACK-Permitted (%d)", n, sizeOptionPermitted)
	}
	if tcp.OptionKind(opts[0]) != tcp.OptSACKPermitted {
		t.Errorf("SYN carries option kind %d, want SACK-Permitted", opts[0])
	}
}

// TestSACK_MergesAdjacentBlocks verifies data accumulating behind one hole is
// reported as one block rather than one per arriving segment.
//
// The receive path holds a range per segment, so five segments behind a hole are five
// adjacent ranges describing one gap-free region. Reported separately they spend the
// whole option area — four blocks is all that fits — restating a region the sender
// could learn from a single block, crowding out the separate holes it actually needs
// to know about.
func TestSACK_MergesAdjacentBlocks(t *testing.T) {
	clientSACK, serverSACK := new(SACK), new(SACK)
	client, server, packet := pair(t, clientSACK, serverSACK)
	const seglen = 100
	const held = 5
	payload := make([]byte, seglen)

	firstSeq := tcp.Value(0)
	for i := range held + 1 {
		if _, err := client.Write(payload); err != nil {
			t.Fatal("write:", err)
		}
		clear(packet)
		n, err := client.Send(packet)
		if err != nil {
			t.Fatal("send:", err)
		}
		if n == 0 {
			t.Fatalf("segment %d not sent", i)
		}
		if i == 0 {
			frame, err := tcp.NewFrame(packet[:n])
			if err != nil {
				t.Fatal(err)
			}
			firstSeq = frame.Seq()
			continue // Dropped, creating the hole.
		}
		if err = server.Recv(packet[:n]); err != nil {
			t.Fatal("server recv:", err)
		}
	}
	clear(packet)
	n, err := server.Send(packet)
	if err != nil {
		t.Fatal("server ack:", err)
	}
	blocks, present := sackBlocks(t, packet[:n])
	if !present {
		t.Fatal("no SACK option while data is held out of order")
	}
	if len(blocks) != 1 {
		t.Errorf("reported %d blocks for one gap-free region, want 1: %v", len(blocks), blocks)
	}
	// The one block must describe the whole region, starting just after the hole.
	want := Block{Left: tcp.Add(firstSeq, seglen), Right: tcp.Add(firstSeq, (held+1)*seglen)}
	if blocks[0] != want {
		t.Errorf("block = %v, want %v", blocks[0], want)
	}
}

// TestSACK_BlocksFitTheOptionArea verifies the option is only written when it fits,
// and never past the space it was lent. The option area is 40 octets shared with
// every other option, so a policy that overruns it corrupts the header of a segment
// the core would otherwise have to refuse.
func TestSACK_BlocksFitTheOptionArea(t *testing.T) {
	blocks := []Block{{100, 200}, {300, 400}, {500, 600}, {700, 800}}
	for _, test := range []struct {
		space     int
		wantCount int
	}{
		{space: 0, wantCount: 0},
		{space: 2, wantCount: 0},  // Room for the header but no block.
		{space: 9, wantCount: 0},  // One octet short of one block.
		{space: 10, wantCount: 1}, // Exactly one block.
		{space: 17, wantCount: 1},
		{space: 18, wantCount: 2},
		{space: 34, wantCount: 4}, // The most a TCP header has room for.
		{space: 40, wantCount: 4}, // More space cannot mean more blocks.
	} {
		if got := blocksThatFit(test.space); got != test.wantCount {
			t.Errorf("blocksThatFit(%d) = %d, want %d", test.space, got, test.wantCount)
		}
		// Writing that many blocks must fit; writing one more must write nothing.
		var s SACK
		area := make([]byte, test.space)
		guard := make([]byte, test.space)
		copy(guard, area)
		n := int(s.putBlocks(area, blocks[:test.wantCount]))
		if test.wantCount == 0 {
			if n != 0 {
				t.Errorf("space %d: wrote %d octets with no room", test.space, n)
			}
			if string(area) != string(guard) {
				t.Errorf("space %d: option area modified when nothing fits", test.space)
			}
			continue
		}
		if want := 2 + test.wantCount*blockLen; n != want {
			t.Errorf("space %d: wrote %d octets for %d blocks, want %d", test.space, n, test.wantCount, want)
		}
		if n > test.space {
			t.Fatalf("space %d: reported %d octets, past the end of the area", test.space, n)
		}
		if test.wantCount < len(blocks) {
			copy(area, guard)
			if over := s.putBlocks(area, blocks[:test.wantCount+1]); over != 0 {
				t.Errorf("space %d: wrote %d octets for one block too many", test.space, over)
			}
			if string(area) != string(guard) {
				t.Errorf("space %d: option area modified by a write that did not fit", test.space)
			}
		}
	}
}

// TestSACK_PutBlocksRefusesMoreThanFit verifies more blocks than a header can hold
// are refused rather than overrunning the fixed serialization buffer. The block count
// derives from how much data a peer is holding, so it is not a constant this package
// controls.
func TestSACK_PutBlocksRefusesMoreThanFit(t *testing.T) {
	var s SACK
	tooMany := make([]Block, maxBlocks+1)
	for i := range tooMany {
		tooMany[i] = Block{Left: tcp.Value(100 * i), Right: tcp.Value(100*i + 50)}
	}
	area := make([]byte, 60) // Ample room on the wire; the limit is the header's.
	if n := s.putBlocks(area, tooMany); n != 0 {
		t.Errorf("wrote %d octets for %d blocks, want a refusal", n, len(tooMany))
	}
}

// segInfo describes a serialized segment for a test that inspects the wire.
type segInfo struct {
	seq  tcp.Value
	n    int
	data []byte
}

func inspect(t *testing.T, packet []byte) segInfo {
	t.Helper()
	frame, err := tcp.NewFrame(packet)
	if err != nil {
		t.Fatal("parse:", err)
	}
	payload := frame.Payload()
	return segInfo{seq: frame.Seq(), n: len(payload), data: append([]byte(nil), payload...)}
}

// TestSACK_ResendsOnlyTheLostSegment is the point of the whole exercise: a sender told
// which of its segments arrived resends the one that did not, and not the ones that
// did.
//
// Without selective acknowledgement a single loss costs everything sent after it,
// because a cumulative acknowledgement cannot distinguish "nothing else arrived" from
// "only this one is missing". The property asserted here is that distinction: the
// retransmission covers the hole and stops.
func TestSACK_ResendsOnlyTheLostSegment(t *testing.T) {
	clientSACK, serverSACK := new(SACK), new(SACK)
	client, server, packet := pair(t, clientSACK, serverSACK)
	if !clientSACK.Enabled() || !serverSACK.Enabled() {
		t.Fatal("negotiation failed")
	}
	const seglen = 100
	const nseg = 4
	payload := make([]byte, seglen)

	// Send four segments, withholding the first so the server holds three behind a
	// hole and reports them.
	var sent []segInfo
	for i := range nseg {
		for j := range payload {
			payload[j] = byte(i*seglen + j)
		}
		if _, err := client.Write(payload); err != nil {
			t.Fatal("write:", err)
		}
		clear(packet)
		n, err := client.Send(packet)
		if err != nil {
			t.Fatal("send:", err)
		}
		if n == 0 {
			t.Fatalf("segment %d not sent", i)
		}
		info := inspect(t, packet[:n])
		sent = append(sent, info)
		if i == 0 {
			continue // Lost in transit.
		}
		if err = server.Recv(packet[:n]); err != nil {
			t.Fatal("server recv:", err)
		}
	}
	lost := sent[0]

	// The server's acknowledgement reports what it holds; the client reads it.
	clear(packet)
	n, err := server.Send(packet)
	if err != nil {
		t.Fatal("server ack:", err)
	}
	if _, present := sackBlocks(t, packet[:n]); !present {
		t.Fatal("the acknowledgement carries no blocks")
	}
	if err = client.Recv(packet[:n]); err != nil {
		t.Fatal("client recv ack:", err)
	}
	if !clientSACK.Holes() {
		t.Fatal("the sender did not conclude anything was missing from the peer's report")
	}
	if got := len(clientSACK.Acked()); got == 0 {
		t.Fatal("the scoreboard is empty after a report of held data")
	}

	// The next segment must be the lost one, resent.
	clear(packet)
	n, err = client.Send(packet)
	if err != nil {
		t.Fatal("client retransmit:", err)
	}
	if n == 0 {
		t.Fatal("the sender transmitted nothing after being told of the hole")
	}
	resent := inspect(t, packet[:n])
	if resent.seq != lost.seq {
		t.Fatalf("resent segment starts at %d, want the lost segment's %d", resent.seq, lost.seq)
	}
	if resent.n != lost.n {
		t.Errorf("resent %d octets, want the lost segment's %d", resent.n, lost.n)
	}
	if string(resent.data) != string(lost.data) {
		t.Error("the resent payload differs from the lost segment's")
	}
	if err = server.Recv(packet[:n]); err != nil {
		t.Fatal("server recv retransmission:", err)
	}

	// The hole is filled, so everything is deliverable in order and nothing else was
	// resent along the way.
	got := make([]byte, nseg*seglen)
	read := 0
	for read < len(got) {
		nr, err := server.Read(got[read:])
		if err != nil || nr == 0 {
			break
		}
		read += nr
	}
	if read != nseg*seglen {
		t.Fatalf("server delivered %d octets, want %d", read, nseg*seglen)
	}
	for i := range nseg {
		for j := range seglen {
			if want := byte(i*seglen + j); got[i*seglen+j] != want {
				t.Fatalf("octet %d of segment %d = %d, want %d", j, i, got[i*seglen+j], want)
			}
		}
	}

	// Nothing after the hole is resent: the peer acknowledges everything, and the
	// sender has no further retransmission to make.
	clear(packet)
	n, err = server.Send(packet)
	if err != nil {
		t.Fatal("server final ack:", err)
	}
	if err = client.Recv(packet[:n]); err != nil {
		t.Fatal("client recv final ack:", err)
	}
	if clientSACK.Holes() {
		t.Error("the sender still believes something is missing after everything was acknowledged")
	}
	clear(packet)
	if n, err = client.Send(packet); err != nil {
		t.Fatal("client send after recovery:", err)
	}
	if n != 0 {
		extra := inspect(t, packet[:n])
		t.Errorf("sender resent %d octets at %d after full acknowledgement", extra.n, extra.seq)
	}
}

// blockOption builds an option area carrying the given SACK blocks.
func blockOption(blocks ...Block) []byte {
	opts := make([]byte, 2+len(blocks)*blockLen)
	opts[0], opts[1] = byte(tcp.OptSACK), byte(len(opts))
	for i, b := range blocks {
		put32(opts[2+i*blockLen:], uint32(b.Left))
		put32(opts[2+i*blockLen+4:], uint32(b.Right))
	}
	return opts
}

// enabledSACK returns a policy as if the handshake had negotiated the option.
func enabledSACK() *SACK {
	s := new(SACK)
	s.enabled, s.offered, s.peerPermitted = true, true, true
	return s
}

func ackEvent(ack tcp.Value, opts []byte, accepted bool) tcp.RxEvent {
	return tcp.RxEvent{
		Segment:  tcp.Segment{SEQ: 5000, ACK: ack, WND: 4096, Flags: tcp.FlagACK},
		Options:  opts,
		Accepted: accepted,
		Now:      1,
	}
}

// TestSACK_IgnoresRefusedSegment verifies blocks from a segment the connection refused
// are not acted on. A block describes this side's send sequence, so a refused segment
// carries no claim about it worth retransmitting for: a stale duplicate or a forged
// segment would otherwise direct the sender's retransmissions.
func TestSACK_IgnoresRefusedSegment(t *testing.T) {
	s := enabledSACK()
	opts := blockOption(Block{Left: 1200, Right: 1300})
	s.PostRx(ackEvent(1000, opts, false))
	if s.Holes() {
		t.Error("a refused segment's blocks were acted on")
	}
	if got := len(s.Acked()); got != 0 {
		t.Errorf("scoreboard holds %d ranges from a refused segment, want 0", got)
	}
	// The same segment accepted does populate the scoreboard, so the test is not
	// passing merely because nothing works.
	s.PostRx(ackEvent(1000, opts, true))
	if !s.Holes() {
		t.Error("an accepted report of held data did not identify a hole")
	}
	if got := len(s.Acked()); got != 1 {
		t.Errorf("scoreboard holds %d ranges, want 1", got)
	}
}

// TestSACK_ScoreboardRejectsUntrustworthyBlocks verifies a peer's blocks are validated
// before they steer retransmission. The blocks are attacker-controlled input in the
// general case, and every one of these shapes would otherwise turn into a resend
// request or a corrupt scoreboard.
func TestSACK_ScoreboardRejectsUntrustworthyBlocks(t *testing.T) {
	const ack tcp.Value = 1000
	for _, test := range []struct {
		name      string
		blocks    []Block
		wantAcked int
		wantHole  bool
	}{
		{
			name:   "reversed edges",
			blocks: []Block{{Left: 1300, Right: 1200}},
		},
		{
			name:   "empty range",
			blocks: []Block{{Left: 1200, Right: 1200}},
		},
		{
			name:   "entirely below the cumulative acknowledgement",
			blocks: []Block{{Left: 500, Right: 900}},
		},
		{
			name:   "ending exactly at the acknowledgement",
			blocks: []Block{{Left: 500, Right: ack}},
		},
		{
			name:      "straddling the acknowledgement is clamped",
			blocks:    []Block{{Left: 500, Right: 1200}},
			wantAcked: 1,
			// Clamped to start at the acknowledgement, so it reports no hole below
			// itself: the peer has everything from there.
			wantHole: false,
		},
		{
			name:      "a genuine hole",
			blocks:    []Block{{Left: 1200, Right: 1300}},
			wantAcked: 1,
			wantHole:  true,
		},
		{
			name:      "good and bad mixed",
			blocks:    []Block{{Left: 1300, Right: 1200}, {Left: 1400, Right: 1500}},
			wantAcked: 1,
			wantHole:  true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := enabledSACK()
			s.PostRx(ackEvent(ack, blockOption(test.blocks...), true))
			if got := len(s.Acked()); got != test.wantAcked {
				t.Errorf("scoreboard holds %d ranges, want %d: %v", got, test.wantAcked, s.Acked())
			}
			for _, b := range s.Acked() {
				if !b.Left.LessThan(b.Right) {
					t.Errorf("scoreboard holds an empty or reversed range %v", b)
				}
				if b.Left.LessThan(ack) {
					t.Errorf("scoreboard holds %v, which starts below the acknowledgement %d", b, ack)
				}
			}
			if got := s.Holes(); got != test.wantHole {
				t.Errorf("Holes() = %v, want %v", got, test.wantHole)
			}
		})
	}
}

// TestSACK_ScoreboardBoundedByHeaderCapacity verifies more blocks than the fixed
// scoreboard holds are dropped rather than overrunning it. The count comes from the
// peer, and a peer may report an option area full of them.
func TestSACK_ScoreboardBoundedByHeaderCapacity(t *testing.T) {
	s := enabledSACK()
	var blocks []Block
	for i := range maxBlocks + 3 {
		base := tcp.Value(2000 + i*200)
		blocks = append(blocks, Block{Left: base, Right: base + 100})
	}
	s.PostRx(ackEvent(1000, blockOption(blocks...), true))
	if got := len(s.Acked()); got > maxBlocks {
		t.Errorf("scoreboard holds %d ranges, want at most %d", got, maxBlocks)
	}
	if !s.Holes() {
		t.Error("a report of held data above the acknowledgement identified no hole")
	}
}

// TestSACK_StaleAcknowledgementDoesNotRewind verifies an acknowledgement older than one
// already seen is ignored, so a delayed duplicate cannot drag the scoreboard back and
// ask for data already known to have arrived.
func TestSACK_StaleAcknowledgementDoesNotRewind(t *testing.T) {
	s := enabledSACK()
	s.PostRx(ackEvent(2000, blockOption(Block{Left: 2200, Right: 2300}), true))
	if !s.Holes() {
		t.Fatal("no hole identified from the first report")
	}
	before := s.Acked()[0]
	// A stale acknowledgement arriving late, reporting an older view.
	s.PostRx(ackEvent(1000, blockOption(Block{Left: 1200, Right: 1300}), true))
	if got := len(s.Acked()); got != 1 || s.Acked()[0] != before {
		t.Errorf("scoreboard = %v, want it unchanged at %v by a stale acknowledgement", s.Acked(), before)
	}
}

// TestSACK_ResendRequestYieldsToAnAdvancedSendSequence verifies a hole that has since
// been acknowledged is not asked for. The scoreboard is refreshed on receive, so a
// plan made then can be stale by the time the transmit path asks.
func TestSACK_ResendRequestYieldsToAnAdvancedSendSequence(t *testing.T) {
	s := enabledSACK()
	s.PostRx(ackEvent(1000, blockOption(Block{Left: 1200, Right: 1300}), true))
	if !s.Holes() {
		t.Fatal("no hole identified")
	}
	// The send sequence has moved past the hole by the time the transmit runs.
	dir := s.PreTx(tcp.TxIntent{UNA: 1400, NXT: 2000})
	if dir.Retransmit {
		t.Errorf("asked to resend from %d, which is already acknowledged", dir.RetransmitFrom)
	}
	// And a hole with nothing sent past it is not asked for either.
	s.PostRx(ackEvent(1000, blockOption(Block{Left: 1200, Right: 1300}), true))
	dir = s.PreTx(tcp.TxIntent{UNA: 1000, NXT: 1000})
	if dir.Retransmit {
		t.Errorf("asked to resend from %d with nothing sent", dir.RetransmitFrom)
	}
}

package sack

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/tcp/rto"
)

const mtu = ethernet.MaxMTU

// TestNegotiation verifies blocks are enabled only when both sides offer
// SACK-Permitted in the handshake.
func TestNegotiation(t *testing.T) {
	for _, tc := range []struct {
		name           string
		client, server bool
	}{
		{"both", true, true},
		{"client-only", true, false},
		{"server-only", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := newHandler(t), newHandler(t)
			var cp, sp Policy
			if tc.client {
				client.SetPolicy(&cp)
			}
			if tc.server {
				server.SetPolicy(&sp)
			}
			establish(t, client, server)
			want := tc.client && tc.server
			if cp.Enabled() != want || sp.Enabled() != want {
				t.Errorf("enabled client=%v server=%v, want %v", cp.Enabled(), sp.Enabled(), want)
			}
		})
	}
}

// TestReceiverBlocks verifies the ACKs of a receiver holding out-of-order data
// report it, with the block holding the latest arrival first and adjacent
// ranges merged, and carry no blocks once the gap is filled.
func TestReceiverBlocks(t *testing.T) {
	client, server := newHandler(t), newHandler(t)
	var cp, sp Policy
	client.SetPolicy(&cp)
	server.SetPolicy(&sp)
	establish(t, client, server)
	var segs [4][]byte
	for i := range segs {
		segs[i] = sendData(t, client, []byte("DATA"))
	}
	s := server.ControlBlock().RecvNext()
	blk := func(from, to int) Block { return Block{tcp.Add(s, tcp.Size(4*from)), tcp.Add(s, tcp.Size(4*to))} }
	for _, step := range []struct {
		deliver int
		want    []Block
	}{
		{deliver: 3, want: []Block{blk(3, 4)}},
		{deliver: 1, want: []Block{blk(1, 2), blk(3, 4)}}, // Latest arrival first.
		{deliver: 2, want: []Block{blk(1, 4)}},
		{deliver: 0, want: nil},
	} {
		if err := server.Recv(segs[step.deliver]); err != nil {
			t.Fatalf("deliver %d: %v", step.deliver, err)
		}
		ack := send(t, server)
		if got := sackBlocks(t, ack); !equalBlocks(got, step.want) {
			t.Fatalf("after segment %d: blocks %v, want %v", step.deliver, got, step.want)
		}
	}
}

// TestSenderRecovery loses two of six segments. With the retransmission timer
// never expiring, the sender must resend exactly the two lost segments, each
// once, from the receiver's blocks, and the stream must arrive intact.
func TestSenderRecovery(t *testing.T) {
	client, server := newHandler(t), newHandler(t)
	var timer rto.Timer
	if err := timer.Configure(func() int64 { return 0 }); err != nil {
		t.Fatal(err)
	}
	var cp, sp Policy
	client.SetPolicy(tcp.Policies{&timer, &cp})
	server.SetPolicy(&sp)
	establish(t, client, server)

	var want []byte
	var lost []tcp.Value
	for i := range 6 {
		data := bytes.Repeat([]byte{byte('a' + i)}, 100)
		want = append(want, data...)
		seg := sendData(t, client, data)
		if i == 1 || i == 4 {
			lost = append(lost, segmentOf(t, seg).SEQ)
			continue
		}
		if err := server.Recv(seg); err != nil {
			t.Fatal(err)
		}
		if err := client.Recv(send(t, server)); err != nil {
			t.Fatal(err)
		}
	}
	// The sender emits until quiet before any acknowledgement of a resend
	// returns, so a hole requested twice would show up here.
	var resent []tcp.Value
	for range 10 {
		pkt := send(t, client)
		if pkt == nil {
			break
		}
		resent = append(resent, segmentOf(t, pkt).SEQ)
		if err := server.Recv(pkt); err != nil {
			t.Fatal(err)
		}
	}
	if len(resent) != len(lost) || resent[0] != lost[0] || resent[1] != lost[1] {
		t.Fatalf("resent %v, want each lost segment once: %v", resent, lost)
	}
	if err := client.Recv(send(t, server)); err != nil {
		t.Fatal(err)
	}
	if client.ControlBlock().SendUNA() != client.ControlBlock().SendNext() || len(cp.Scoreboard()) != 0 {
		t.Errorf("after recovery: UNA %d, NXT %d, scoreboard %v", client.ControlBlock().SendUNA(), client.ControlBlock().SendNext(), cp.Scoreboard())
	}
	got := make([]byte, len(want)+1)
	n, _ := server.Read(got)
	if !bytes.Equal(got[:n], want) {
		t.Errorf("server read %d octets, want %d intact", n, len(want))
	}
}

// TestScoreboard verifies reported ranges are kept ascending and disjoint,
// merging overlapping and touching ones, that a full scoreboard keeps the
// lowest ranges, and that acknowledged data is pruned.
func TestScoreboard(t *testing.T) {
	b := func(l, r tcp.Value) Block { return Block{l, r} }
	for _, tc := range []struct {
		name   string
		insert []Block
		prune  tcp.Value
		want   []Block
	}{
		{name: "sorted", insert: []Block{b(30, 40), b(10, 20)}, want: []Block{b(10, 20), b(30, 40)}},
		{name: "merge", insert: []Block{b(10, 20), b(20, 30), b(40, 50), b(15, 45)}, want: []Block{b(10, 50)}},
		{name: "prune", insert: []Block{b(10, 20), b(30, 40)}, prune: 35, want: []Block{b(35, 40)}},
		{
			name:   "full-keeps-lowest",
			insert: []Block{b(20, 21), b(30, 31), b(40, 41), b(50, 51), b(60, 61), b(70, 71), b(80, 81), b(90, 91), b(100, 101), b(10, 11)},
			want:   []Block{b(10, 11), b(20, 21), b(30, 31), b(40, 41), b(50, 51), b(60, 61), b(70, 71), b(80, 81)},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var p Policy
			for _, blk := range tc.insert {
				p.insert(blk)
			}
			if tc.prune != 0 {
				p.prune(tc.prune)
			}
			if !equalBlocks(p.Scoreboard(), tc.want) {
				t.Errorf("scoreboard %v, want %v", p.Scoreboard(), tc.want)
			}
		})
	}
}

// TestInvalidBlocksIgnored verifies a peer cannot place reversed blocks, blocks
// past SND.NXT or D-SACK blocks below SND.UNA on the scoreboard.
func TestInvalidBlocksIgnored(t *testing.T) {
	client, server := newHandler(t), newHandler(t)
	var cp, sp Policy
	client.SetPolicy(&cp)
	server.SetPolicy(&sp)
	establish(t, client, server)
	una := client.ControlBlock().SendUNA()
	sendData(t, client, make([]byte, 100)) // Outstanding: [una, una+100).
	var data [maxBlocks * blockLen]byte
	for i, blk := range []Block{{una + 50, una + 40}, {una + 50, una + 200}, {una - 10, una}, {una + 50, una + 60}} {
		put32(data[i*blockLen:], uint32(blk.Left))
		put32(data[i*blockLen+4:], uint32(blk.Right))
	}
	frm, _ := tcp.NewFrame(make([]byte, 60))
	frm.SetSegment(tcp.Segment{SEQ: client.ControlBlock().RecvNext(), ACK: una, Flags: tcp.FlagACK}, 5)
	if !cp.writeOption(frm, 2, tcp.OptSACK, data[:]) {
		t.Fatal("option did not fit")
	}
	cp.PostRx(client, tcp.StateEstablished, frm)
	if want := []Block{{una + 50, una + 60}}; !equalBlocks(cp.Scoreboard(), want) {
		t.Errorf("scoreboard %v, want %v", cp.Scoreboard(), want)
	}
}

// TestResendProgress verifies a resend this policy did not request, such as the
// retransmission timer resending SND.UNA, does not skip unrepaired holes, and
// that a requested resend carrying only the head of its packet is not asked for
// again forever.
func TestResendProgress(t *testing.T) {
	const una = tcp.Value(1000)
	// Holes [1000,1100) and [1300,1400) below SACKed [1100,1300) and [1400,1500).
	newRecovering := func() *Policy {
		p := &Policy{enabled: true, smss: 100, recovering: true, recoverAt: 1500, highRxt: 1100, sndMax: 1500, haveSndMax: true}
		p.insert(Block{1100, 1300})
		p.insert(Block{1400, 1500})
		return p
	}
	resend := func(p *Policy, seq tcp.Value, n tcp.Size) {
		frm, _ := tcp.NewFrame(make([]byte, 20+int(n)))
		frm.SetSegment(tcp.Segment{SEQ: seq, ACK: 1, Flags: tcp.FlagACK, DATALEN: n}, 5)
		p.PostTx(nil, frm)
	}
	t.Run("timer-resend", func(t *testing.T) {
		p := newRecovering()
		resend(p, una, 100)
		if hole, ok := p.nextHole(una, true); !ok || hole != 1300 {
			t.Errorf("next hole %d (ok=%v), want 1300", hole, ok)
		}
	})
	t.Run("requested-head-only", func(t *testing.T) {
		p := newRecovering()
		p.highRxt, p.requested, p.haveRequested = 1300, 1350, true
		resend(p, 1300, 50) // The packet holding 1350 starts at 1300; its head fit.
		if hole, ok := p.nextHole(una, true); ok {
			t.Errorf("hole %d requested again; want it left to the timer", hole)
		}
	})
}

func newHandler(t *testing.T) *tcp.Handler {
	t.Helper()
	h := new(tcp.Handler)
	if err := h.SetBuffers(make([]byte, mtu), make([]byte, mtu), 8); err != nil {
		t.Fatal(err)
	}
	return h
}

// establish opens client and server and completes the three-way handshake.
func establish(t *testing.T, client, server *tcp.Handler) {
	t.Helper()
	rng := rand.New(rand.NewSource(1))
	if err := server.OpenListen(uint16(rng.Uint32()), 100); err != nil {
		t.Fatal(err)
	}
	if err := client.OpenActive(uint16(rng.Uint32()), server.LocalPort(), 300); err != nil {
		t.Fatal(err)
	}
	for _, h := range [][2]*tcp.Handler{{client, server}, {server, client}, {client, server}} {
		if err := h[1].Recv(send(t, h[0])); err != nil {
			t.Fatal(err)
		}
	}
	if client.State() != tcp.StateEstablished || server.State() != tcp.StateEstablished {
		t.Fatalf("handshake: client %s, server %s", client.State(), server.State())
	}
}

// send returns a copy of the next frame h emits, or nil if it emits none.
func send(t *testing.T, h *tcp.Handler) []byte {
	t.Helper()
	var buf [mtu]byte
	n, err := h.Send(buf[:])
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		return nil
	}
	return append([]byte(nil), buf[:n]...)
}

func sendData(t *testing.T, h *tcp.Handler, data []byte) []byte {
	t.Helper()
	if _, err := h.Write(data); err != nil {
		t.Fatal(err)
	}
	return send(t, h)
}

func segmentOf(t *testing.T, pkt []byte) tcp.Segment {
	t.Helper()
	frm, err := tcp.NewFrame(pkt)
	if err != nil {
		t.Fatal(err)
	}
	return frm.Segment(len(frm.Payload()))
}

func sackBlocks(t *testing.T, pkt []byte) (blocks []Block) {
	t.Helper()
	if pkt == nil {
		t.Fatal("no ACK sent")
	}
	frm, err := tcp.NewFrame(pkt)
	if err != nil {
		t.Fatal(err)
	}
	var codec tcp.OptionCodec
	err = codec.ForEachOption(frm.Options(), func(kind tcp.OptionKind, data []byte) error {
		for ; kind == tcp.OptSACK && len(data) >= blockLen; data = data[blockLen:] {
			blocks = append(blocks, Block{tcp.Value(get32(data)), tcp.Value(get32(data[4:]))})
		}
		return nil
	})
	if err != nil {
		t.Fatal("options:", err)
	}
	return blocks
}

func equalBlocks(a, b []Block) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

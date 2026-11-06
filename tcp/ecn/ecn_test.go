package ecn

import (
	"math/rand"
	"testing"

	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/tcp"
)

const mtu = ethernet.MaxMTU

// frame returns a segment of datalen octets at seq with flags.
func frame(t *testing.T, flags tcp.Flags, seq tcp.Value, datalen int) tcp.Frame {
	t.Helper()
	frm, err := tcp.NewFrame(make([]byte, 20+datalen))
	if err != nil {
		t.Fatal(err)
	}
	frm.SetSegment(tcp.Segment{SEQ: seq, ACK: 1, Flags: flags, WND: 1000, DATALEN: tcp.Size(datalen)}, 5)
	return frm
}

func flagsOf(frm tcp.Frame) tcp.Flags {
	_, flags := frm.OffsetAndFlags()
	return flags
}

// TestPostTx verifies the flags and codepoint of each kind of segment sent,
// and that only the first SYN offers ECN (RFC 3168 §6.1).
func TestPostTx(t *testing.T) {
	const nxt = 1000
	on := Policy{echoes: true, ect: true}
	with := func(p Policy, f func(*Policy)) Policy { f(&p); return p }
	for _, tc := range []struct {
		name          string
		p             Policy
		flags         tcp.Flags
		seq           tcp.Value
		datalen       int
		wantFlags     tcp.Flags
		wantCodepoint uint8
		wantOffered   bool
		wantOn        bool // echoes and ect.
		wantCWROwed   bool
		wantCWRSent   bool // Up to the end of the segment.
	}{
		{name: "syn", flags: tcp.FlagSYN, wantFlags: tcp.FlagSYN | tcp.FlagECE | tcp.FlagCWR, wantOffered: true},
		{name: "syn-retransmitted", p: Policy{synSent: true, offered: true}, flags: tcp.FlagSYN, wantFlags: tcp.FlagSYN},
		{name: "syn-ack", p: Policy{peerOffered: true}, flags: tcp.FlagSYN | tcp.FlagACK, wantFlags: tcp.FlagSYN | tcp.FlagACK | tcp.FlagECE, wantOn: true},
		{name: "syn-ack-no-offer", flags: tcp.FlagSYN | tcp.FlagACK, wantFlags: tcp.FlagSYN | tcp.FlagACK},
		{name: "syn-ack-after-fallback", p: on, flags: tcp.FlagSYN | tcp.FlagACK, wantFlags: tcp.FlagSYN | tcp.FlagACK},
		{name: "not-enabled", p: Policy{echo: true, cwr: true}, flags: tcp.FlagACK, seq: nxt, datalen: 10, wantFlags: tcp.FlagACK, wantCWROwed: true},
		{name: "new-data", p: on, flags: tcp.FlagACK, seq: nxt, datalen: 10, wantFlags: tcp.FlagACK, wantCodepoint: ECT0, wantOn: true},
		{name: "new-data-echoing-only", p: Policy{echoes: true}, flags: tcp.FlagACK, seq: nxt, datalen: 10, wantFlags: tcp.FlagACK},
		{name: "echo", p: with(on, func(p *Policy) { p.echo = true }), flags: tcp.FlagACK, seq: nxt, wantFlags: tcp.FlagACK | tcp.FlagECE, wantOn: true},
		{name: "cwr-on-new-data", p: with(on, func(p *Policy) { p.cwr = true }), flags: tcp.FlagACK, seq: nxt, datalen: 10, wantFlags: tcp.FlagACK | tcp.FlagCWR, wantCodepoint: ECT0, wantOn: true, wantCWRSent: true},
		{name: "no-cwr-on-pure-ack", p: with(on, func(p *Policy) { p.cwr = true }), flags: tcp.FlagACK, seq: nxt, wantFlags: tcp.FlagACK, wantOn: true, wantCWROwed: true},
		{name: "resend", p: with(on, func(p *Policy) { p.cwr = true }), flags: tcp.FlagACK, seq: nxt - 10, datalen: 10, wantFlags: tcp.FlagACK, wantOn: true, wantCWROwed: true},
		{name: "window-probe", p: with(on, func(p *Policy) { p.probing = true }), flags: tcp.FlagACK, seq: nxt, datalen: 1, wantFlags: tcp.FlagACK, wantOn: true},
		{name: "rst", p: with(on, func(p *Policy) { p.echo = true }), flags: tcp.FlagRST | tcp.FlagACK, seq: nxt, wantFlags: tcp.FlagRST | tcp.FlagACK, wantOn: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.p
			p.nxt = nxt
			frm := frame(t, tc.flags, tc.seq, tc.datalen)
			p.PostTx(nil, frm)
			if got := flagsOf(frm); got != tc.wantFlags || p.SendECN() != tc.wantCodepoint || p.offered != tc.wantOffered || p.Enabled() != tc.wantOn || p.cwr != tc.wantCWROwed {
				t.Errorf("flags %v, codepoint %02b, offered %v, enabled %v, CWR owed %v; want %v, %02b, %v, %v, %v",
					got, p.SendECN(), p.offered, p.Enabled(), p.cwr, tc.wantFlags, tc.wantCodepoint, tc.wantOffered, tc.wantOn, tc.wantCWROwed)
			}
			if wantEnd := tcp.Add(tc.seq, tcp.Size(tc.datalen)); p.cwrSent != tc.wantCWRSent || tc.wantCWRSent && p.cwrEnd != wantEnd {
				t.Errorf("CWR sent %v up to %d, want %v up to %d", p.cwrSent, p.cwrEnd, tc.wantCWRSent, wantEnd)
			}
		})
	}
}

// TestRx verifies the peer's first SYN offers ECN only with ECE and CWR, and a
// later one can only fall back, its SYN-ACK answers only with ECE alone, so
// marks are echoed if a SYN of ours offered and new data marked if the latest
// did, a CE mark starts the echo, CWR stops it unless its own packet is
// marked, and ECE owes CWR once the peer acknowledged the last.
func TestRx(t *testing.T) {
	for _, tc := range []struct {
		name       string
		p          Policy
		ce         bool
		flags      tcp.Flags
		ack        tcp.Value // 1 if zero.
		wantPeer   bool
		wantEchoes bool
		wantECT    bool
		wantEcho   bool
		wantCWR    bool
	}{
		{name: "syn-offer", flags: tcp.FlagSYN | tcp.FlagECE | tcp.FlagCWR, wantPeer: true},
		{name: "syn-ece-only", flags: tcp.FlagSYN | tcp.FlagECE},
		{name: "syn-fallback", p: Policy{synRcvd: true, peerOffered: true, echoes: true, ect: true}, flags: tcp.FlagSYN},
		{name: "syn-offer-after-fallback", p: Policy{synRcvd: true}, flags: tcp.FlagSYN | tcp.FlagECE | tcp.FlagCWR},
		{name: "syn-ack-answer", p: Policy{offered: true, offeredAny: true}, flags: tcp.FlagSYN | tcp.FlagACK | tcp.FlagECE, wantEchoes: true, wantECT: true},
		{name: "syn-ack-after-plain-syn", p: Policy{offeredAny: true}, flags: tcp.FlagSYN | tcp.FlagACK | tcp.FlagECE, wantEchoes: true},
		{name: "syn-ack-reflected", p: Policy{offered: true, offeredAny: true}, flags: tcp.FlagSYN | tcp.FlagACK | tcp.FlagECE | tcp.FlagCWR},
		{name: "syn-ack-unoffered", flags: tcp.FlagSYN | tcp.FlagACK | tcp.FlagECE},
		{name: "ce", p: Policy{echoes: true}, ce: true, flags: tcp.FlagACK, wantEchoes: true, wantEcho: true},
		{name: "ce-not-echoing", p: Policy{ect: true}, ce: true, flags: tcp.FlagACK, wantECT: true},
		{name: "cwr", p: Policy{echoes: true, echo: true}, flags: tcp.FlagACK | tcp.FlagCWR, wantEchoes: true},
		{name: "cwr-marked-ce", p: Policy{echoes: true, echo: true}, ce: true, flags: tcp.FlagACK | tcp.FlagCWR, wantEchoes: true, wantEcho: true},
		{name: "ece", p: Policy{ect: true}, flags: tcp.FlagACK | tcp.FlagECE, wantECT: true, wantCWR: true},
		{name: "ece-not-sending-ect", p: Policy{echoes: true}, flags: tcp.FlagACK | tcp.FlagECE, wantEchoes: true},
		{name: "ece-before-cwr-acked", p: Policy{ect: true, cwrSent: true, cwrEnd: 100}, flags: tcp.FlagACK | tcp.FlagECE, ack: 99, wantECT: true},
		{name: "ece-after-cwr-acked", p: Policy{ect: true, cwrSent: true, cwrEnd: 100}, flags: tcp.FlagACK | tcp.FlagECE, ack: 100, wantECT: true, wantCWR: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.p
			if tc.ce {
				p.RecvECN(CE)
			}
			frm := frame(t, tc.flags, 1, 0)
			frm.SetAck(max(tc.ack, 1))
			if !p.PreRx(nil, frm) {
				t.Fatal("segment dropped")
			}
			p.PostRx(nil, tcp.StateEstablished, frm)
			if p.peerOffered != tc.wantPeer || p.echoes != tc.wantEchoes || p.ect != tc.wantECT || p.echo != tc.wantEcho || p.cwr != tc.wantCWR || p.ce || p.cwrSent && tc.ack >= 100 {
				t.Errorf("peer offered %v, echoes %v, ECT %v, echo %v, CWR owed %v, CE kept %v, CWR sent %v; want %v, %v, %v, %v, %v, false, %v",
					p.peerOffered, p.echoes, p.ect, p.echo, p.cwr, p.ce, p.cwrSent, tc.wantPeer, tc.wantEchoes, tc.wantECT, tc.wantEcho, tc.wantCWR, tc.p.cwrSent && tc.ack < 100)
			}
		})
	}
}

func newHandler(t *testing.T, policy tcp.Policy) *tcp.Handler {
	t.Helper()
	h := new(tcp.Handler)
	if err := h.SetBuffers(make([]byte, mtu), make([]byte, mtu), 8); err != nil {
		t.Fatal(err)
	}
	if policy != nil {
		h.SetPolicy(policy)
	}
	return h
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

func recv(t *testing.T, h *tcp.Handler, pkt []byte) {
	t.Helper()
	if err := h.Recv(pkt); err != nil {
		t.Fatal(err)
	}
}

func segmentOf(t *testing.T, pkt []byte) tcp.Segment {
	t.Helper()
	frm, err := tcp.NewFrame(pkt)
	if err != nil {
		t.Fatal(err)
	}
	return frm.Segment(len(frm.Payload()))
}

// TestNegotiation verifies ECN is enabled on both sides only if both use it.
func TestNegotiation(t *testing.T) {
	for _, tc := range []struct {
		name           string
		client, server bool
	}{
		{name: "both", client: true, server: true},
		{name: "client-only", client: true},
		{name: "server-only", server: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cp, sp Policy
			client, server := newHandler(t, nil), newHandler(t, nil)
			if tc.client {
				client.SetPolicy(&cp)
			}
			if tc.server {
				server.SetPolicy(&sp)
			}
			establish(t, client, server)
			want := tc.client && tc.server
			if cp.Enabled() != want || sp.Enabled() != want {
				t.Errorf("enabled: client %v, server %v; want %v", cp.Enabled(), sp.Enabled(), want)
			}
		})
	}
}

func establish(t *testing.T, client, server *tcp.Handler) {
	t.Helper()
	rng := rand.New(rand.NewSource(1))
	if err := server.OpenListen(uint16(rng.Uint32()), 100); err != nil {
		t.Fatal(err)
	}
	if err := client.OpenActive(uint16(rng.Uint32()), server.LocalPort(), 300); err != nil {
		t.Fatal(err)
	}
	for _, hop := range [][2]*tcp.Handler{{client, server}, {server, client}, {client, server}} {
		recv(t, hop[1], send(t, hop[0]))
	}
	if client.State() != tcp.StateEstablished || server.State() != tcp.StateEstablished {
		t.Fatalf("handshake: client %s, server %s", client.State(), server.State())
	}
}

// TestCongestionEcho verifies a CE mark on the client's data is echoed with
// ECE on every ACK until the client, which sends a pure ACK without and its
// next new data with CWR, answers it, and resends stay Not-ECT.
func TestCongestionEcho(t *testing.T) {
	var cp, sp Policy
	client, server := newHandler(t, &cp), newHandler(t, &sp)
	establish(t, client, server)
	write := func(h *tcp.Handler, n int) {
		if _, err := h.Write(make([]byte, n)); err != nil {
			t.Fatal(err)
		}
	}
	var data [2][]byte
	for i := range data {
		write(client, 10)
		if data[i] = send(t, client); cp.SendECN() != ECT0 {
			t.Fatalf("data codepoint %02b, want ECT(0)", cp.SendECN())
		}
	}
	sp.RecvECN(CE)
	var ack []byte
	for i, d := range data { // The echo repeats; the first ACK is lost.
		recv(t, server, d)
		if ack = send(t, server); !segmentOf(t, ack).Flags.HasAny(tcp.FlagECE) || sp.SendECN() != NotECT {
			t.Fatalf("server ACK %d: %v, codepoint %02b; want ECE and Not-ECT", i, segmentOf(t, ack), sp.SendECN())
		}
	}
	recv(t, client, ack)
	write(server, 10)
	recv(t, client, send(t, server))
	if ack := send(t, client); segmentOf(t, ack).Flags.HasAny(tcp.FlagCWR) || cp.SendECN() != NotECT {
		t.Fatalf("client pure ACK %v, codepoint %02b; want no CWR and Not-ECT", segmentOf(t, ack), cp.SendECN())
	}
	write(client, 10)
	cwr := send(t, client)
	if !segmentOf(t, cwr).Flags.HasAny(tcp.FlagCWR) {
		t.Fatalf("client data %v, want CWR", segmentOf(t, cwr))
	}
	recv(t, server, cwr)
	write(server, 10)
	if ack := send(t, server); segmentOf(t, ack).Flags.HasAny(tcp.FlagECE) {
		t.Errorf("server segment %v after CWR, want no ECE", segmentOf(t, ack))
	}
	write(client, 10)
	if seg := segmentOf(t, send(t, client)); seg.Flags.HasAny(tcp.FlagCWR) {
		t.Errorf("client data %v after its CWR, want none", seg)
	}
}

// TestResendNotECT verifies a fast retransmit is sent Not-ECT (RFC 3168
// §6.1.5).
func TestResendNotECT(t *testing.T) {
	var cp, sp Policy
	client, server := newHandler(t, &cp), newHandler(t, &sp)
	establish(t, client, server)
	if _, err := client.Write(make([]byte, 40)); err != nil {
		t.Fatal(err)
	}
	var segs [][]byte
	for range 4 {
		var buf [20 + 10]byte
		n, err := client.Send(buf[:])
		if err != nil || n == 0 {
			t.Fatalf("send = %d, %v", n, err)
		}
		segs = append(segs, append([]byte(nil), buf[:n]...))
	}
	for _, seg := range segs[1:] { // The first is lost.
		recv(t, server, seg)
		recv(t, client, send(t, server))
	}
	resend := segmentOf(t, send(t, client))
	if resend.SEQ != segmentOf(t, segs[0]).SEQ || cp.SendECN() != NotECT {
		t.Errorf("resend %v, codepoint %02b; want SEQ %d, Not-ECT", resend, cp.SendECN(), segmentOf(t, segs[0]).SEQ)
	}
}

// TestFallback verifies a connection whose handshake fell back to a SYN
// without the ECN offer: a server seeing it, also as a retransmission it
// drops or before a delayed offer, does not use ECN, and a client whose offer
// was answered after it sent the SYN without echoes marks but sends no ECT
// (RFC 3168 §6.1.1, §6.1.1.1).
func TestFallback(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	open := func(t *testing.T) (client, server *tcp.Handler, cp, sp *Policy) {
		cp, sp = new(Policy), new(Policy)
		client, server = newHandler(t, cp), newHandler(t, sp)
		if err := server.OpenListen(uint16(rng.Uint32()), 100); err != nil {
			t.Fatal(err)
		}
		if err := client.OpenActive(uint16(rng.Uint32()), server.LocalPort(), 300); err != nil {
			t.Fatal(err)
		}
		return client, server, cp, sp
	}
	synAckECE := func(t *testing.T, server *tcp.Handler) bool {
		server.RequeueControl()
		return segmentOf(t, send(t, server)).Flags.HasAny(tcp.FlagECE)
	}
	t.Run("retransmitted-syn", func(t *testing.T) {
		client, server, _, sp := open(t)
		recv(t, server, send(t, client))
		send(t, server) // The ECN-setup SYN-ACK is lost.
		client.RequeueControl()
		server.Recv(send(t, client)) // Dropped in SYN-RECEIVED.
		if synAckECE(t, server) || sp.ect {
			t.Error("server answers with ECE or sends ECT after the client fell back")
		}
	})
	t.Run("delayed-offer", func(t *testing.T) {
		client, server, _, sp := open(t)
		offer := send(t, client) // Delayed.
		client.RequeueControl()
		recv(t, server, send(t, client))
		send(t, server) // The SYN-ACK without ECE is lost.
		server.Recv(offer)
		if synAckECE(t, server) || sp.ect {
			t.Error("server answers with ECE or sends ECT after a SYN without the offer")
		}
	})
	t.Run("late-syn-ack", func(t *testing.T) {
		client, server, cp, _ := open(t)
		recv(t, server, send(t, client))
		synAck := send(t, server) // Delayed past the client's second SYN, which is lost.
		client.RequeueControl()
		send(t, client)
		recv(t, client, synAck)
		if !cp.echoes || cp.ect {
			t.Errorf("client echoes %v, sends ECT %v; want true, false", cp.echoes, cp.ect)
		}
	})
}

func TestReset(t *testing.T) {
	p := Policy{synSent: true, offered: true, offeredAny: true, synRcvd: true, peerOffered: true,
		echoes: true, ect: true, ce: true, echo: true, cwr: true, cwrSent: true, cwrEnd: 1, codepoint: ECT0}
	p.Reset()
	if p != (Policy{}) {
		t.Errorf("Reset left %+v", p)
	}
}

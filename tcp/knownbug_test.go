//go:build knownbug

package tcp

import (
	"math/rand"
	"net"
	"testing"

	"github.com/soypat/lneto/ethernet"
)

// TestKnownBug_LinuxZeroWindowProbeAborts: Linux probes a closed window with
// SEQ=RCV.NXT-1 and no data (tcp_xmit_probe_skb). The segment is unacceptable,
// so it must be acknowledged and dropped (RFC 9293 §3.10.7.4), but it counts
// toward the challenge-ACK abort and the connection is aborted while the
// window stays closed.
func TestKnownBug_LinuxZeroWindowProbeAborts(t *testing.T) {
	const issA, issB, windowB = 100, 300, 1000
	var tcb ControlBlock
	tcb.HelperInitState(StateEstablished, issA, issA, 0)
	tcb.HelperInitRcv(issB, issB, windowB)
	probe := Segment{SEQ: issB - 1, ACK: issA, Flags: FlagACK, WND: windowB}
	for i := range 20 {
		tcb.Recv(probe) // Refusing the probe is correct; aborting is not.
		if tcb.State() != StateEstablished {
			t.Fatalf("probe %d: state %s", i, tcb.State())
		}
		ack, ok := tcb.PendingSegment(0)
		if !ok || !ack.Flags.HasAny(FlagACK) {
			t.Fatalf("probe %d not acknowledged", i)
		}
		if err := tcb.Send(ack); err != nil {
			t.Fatal(err)
		}
	}
}

// TestKnownBug_KeepaliveNotACKed: a keepalive (SEQ=RCV.NXT-1) must be answered
// with an ACK (RFC 9293 §3.8.4, RFC 1122 §4.2.3.6), but Handler.Recv returns
// on IncomingIsKeepalive without queueing one. The peer then counts the
// keepalive as unanswered and eventually drops the connection.
func TestKnownBug_KeepaliveNotACKed(t *testing.T) {
	const mtu = ethernet.MaxMTU
	client, server := newHandler(t, mtu, 4), newHandler(t, mtu, 4)
	setupClientServer(t, rand.New(rand.NewSource(1)), client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])
	scb := server.ControlBlock()
	keepalive := make([]byte, sizeHeaderTCP)
	frame, _ := NewFrame(keepalive)
	frame.SetSourcePort(client.LocalPort())
	frame.SetDestinationPort(server.LocalPort())
	frame.SetSegment(Segment{SEQ: scb.RecvNext() - 1, ACK: scb.SendNext(), WND: mtu, Flags: FlagACK}, 5)
	if err := server.Recv(keepalive); err != nil {
		t.Fatal(err)
	}
	n, err := server.Send(buf[:])
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		t.Fatal("keepalive not acknowledged")
	}
	if got := mustSegment(t, buf[:n], 0); got.ACK != scb.RecvNext() || !got.Flags.HasAny(FlagACK) {
		t.Fatalf("keepalive reply %v, want ACK of RCV.NXT %d", got, scb.RecvNext())
	}
}

// TestKnownBug_ZeroWindowRSTIgnored: an RST at exactly RCV.NXT must reset the
// connection (RFC 5961 §3.2), and a zero window must still accept valid RSTs
// (RFC 9293 §3.10.7.4). An RST carrying data is refused with errZeroWindow
// instead. The RST cases of TestExchangeTest_ZeroWindowProbesDoNotAbort and
// TestHandler_ZeroWindowProbeACKed assert the current behaviour and change
// with the fix.
func TestKnownBug_ZeroWindowRSTIgnored(t *testing.T) {
	const issA, issB, windowB = 100, 300, 1000
	test := ExchangeTest{
		ISSA:       issA,
		ISSB:       issB,
		WindowA:    0,
		WindowB:    windowB,
		InitStateA: StateEstablished,
		InitStateB: StateEstablished,
		Steps: []SegmentStep{{
			Seg:     Segment{SEQ: issB, ACK: issA, Flags: FlagRST | FlagACK, WND: windowB, DATALEN: 1},
			Action:  StepBSends,
			AState:  StateClosed,
			WantErr: net.ErrClosed,
		}},
	}
	test.RunA(t)
}

// TestKnownBug_RefusedProbeDropsACK: a zero window must still accept valid
// ACKs (RFC 9293 §3.10.7.4), but a refused zero-window probe returns before
// ACK processing, so the data it acknowledges stays outstanding and is
// retransmitted needlessly.
func TestKnownBug_RefusedProbeDropsACK(t *testing.T) {
	const issA, issB, windowB, inFlight = 100, 300, 1000, 10
	var tcb ControlBlock
	tcb.HelperInitState(StateEstablished, issA, issA+inFlight, 0)
	tcb.HelperInitRcv(issB, issB, windowB)
	probe := Segment{SEQ: issB, ACK: issA + inFlight, Flags: FlagACK, WND: windowB, DATALEN: 1}
	tcb.Recv(probe)
	if tcb.State() != StateEstablished {
		t.Fatalf("state %s after probe", tcb.State())
	}
	if una := tcb.SendUNA(); una != issA+inFlight {
		t.Errorf("SND.UNA = %d after probe acknowledging %d", una, issA+inFlight)
	}
}

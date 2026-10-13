package tcp_test

import (
	"errors"
	"math/rand"
	"net"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/tcp"
)

const (
	SYNACK = tcp.FlagSYN | tcp.FlagACK
	FINACK = tcp.FlagFIN | tcp.FlagACK
	PSHACK = tcp.FlagPSH | tcp.FlagACK
)

// TestExchangeTest runs each scenario from the perspective of the peers its
// run method selects: ExchangeTest.Run for both, RunA or RunB for one.
func TestExchangeTest(t *testing.T) {
	const issA, issB, windowA, windowB = 100, 300, 1000, 1000
	const badAck = 12336 // Beyond A's SND.NXT.
	for _, tc := range []struct {
		name string
		run  func(tcp.ExchangeTest, *testing.T)
		test tcp.ExchangeTest
	}{
		// PassiveClose_FINACKRegression is a regression test for the bug where
		// Close() in CLOSE-WAIT state set pending = [FlagFIN, FlagACK] (separate slots) instead
		// of pending = [FlagFIN|FlagACK, 0]. This caused PendingSegment() to return only FIN
		// without ACK since it only reads pending[0].
		{
			name: "PassiveClose_FINACKRegression",
			run:  tcp.ExchangeTest.RunB, // Only run B's perspective since that's where Close() is called.
			test: tcp.ExchangeTest{
				ISSA:       issA,
				ISSB:       issB,
				WindowA:    windowA,
				WindowB:    windowB,
				InitStateA: tcp.StateEstablished,
				InitStateB: tcp.StateEstablished,
				Steps: []tcp.SegmentStep{
					0: { // A sends FIN|ACK to B. B goes to CLOSE-WAIT.
						Seg:      tcp.Segment{SEQ: issA, ACK: issB, Flags: FINACK, WND: windowA},
						Action:   tcp.StepASends,
						AState:   tcp.StateFinWait1,
						BState:   tcp.StateCloseWait,
						BPending: &tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: tcp.FlagACK, WND: windowB},
					},
					1: { // B sends ACK to A (RFC 9293 Figure 12 step 3). B stays in CLOSE-WAIT.
						Seg:    tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: tcp.FlagACK, WND: windowB},
						Action: tcp.StepBSends,
						AState: tcp.StateFinWait2,
						BState: tcp.StateCloseWait,
					},
					2: { // B calls Close() (RFC 9293 Figure 12 step 4). Goes to LAST-ACK.
						// Regression check: Close() must queue FIN|ACK as a single combined flag
						// in pending[0], not as [FlagFIN, FlagACK] in separate pending slots.
						Action:   tcp.StepBCloses,
						AState:   tcp.StateFinWait2, // A unchanged.
						BState:   tcp.StateLastAck,
						BPending: &tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: FINACK, WND: windowB},
					},
					3: { // B sends FIN|ACK to A.
						Seg:      tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: FINACK, WND: windowB},
						Action:   tcp.StepBSends,
						AState:   tcp.StateTimeWait,
						BState:   tcp.StateLastAck,
						BPending: nil,
					},
					4: { // A sends final ACK to B. B goes to CLOSED.
						Seg:    tcp.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: tcp.FlagACK, WND: windowA},
						Action: tcp.StepASends,
						AState: tcp.StateTimeWait,
						BState: tcp.StateClosed,
					},
				},
			},
		},
		// TimeWait_RecvDrops walks an active close to TIME-WAIT and then
		// delivers one more segment. RFC 9293 §3.10.7.4: a segment received in TIME-WAIT
		// is dropped without advancing the connection, and a pure ACK draws no reply. It
		// regresses a missing receive-state case that previously panicked.
		{
			name: "TimeWait_RecvDrops",
			run:  tcp.ExchangeTest.RunA,
			test: tcp.ExchangeTest{
				ISSA:       issA,
				ISSB:       issB,
				WindowA:    windowA,
				WindowB:    windowB,
				InitStateA: tcp.StateEstablished,
				InitStateB: tcp.StateEstablished,
				Steps: []tcp.SegmentStep{
					0: { // A sends FIN|ACK, transitioning to FIN-WAIT-1.
						Seg:    tcp.Segment{SEQ: issA, ACK: issB, Flags: FINACK, WND: windowA},
						Action: tcp.StepASends,
						AState: tcp.StateFinWait1,
					},
					1: { // B acknowledges A's FIN.
						Seg:    tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: tcp.FlagACK, WND: windowB},
						Action: tcp.StepBSends,
						AState: tcp.StateFinWait2,
					},
					2: { // B sends its own FIN|ACK. A moves to TIME-WAIT with a final ACK pending.
						Seg:      tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: FINACK, WND: windowB},
						Action:   tcp.StepBSends,
						AState:   tcp.StateTimeWait,
						APending: &tcp.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: tcp.FlagACK, WND: windowA},
					},
					3: { // A sends the final ACK.
						Seg:    tcp.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: tcp.FlagACK, WND: windowA},
						Action: tcp.StepASends,
						AState: tcp.StateTimeWait,
					},
					4: { // A late pure ACK arrives in TIME-WAIT: dropped, no reply, no state change.
						Seg:     tcp.Segment{SEQ: issB + 1, ACK: issA + 1, Flags: tcp.FlagACK, WND: windowB},
						Action:  tcp.StepBSends,
						AState:  tcp.StateTimeWait,
						WantErr: lneto.ErrPacketDrop,
					},
				},
			},
		},
		// figure12 demonstrates ExchangeTest which defines both peers' states
		// symmetrically and runs tests from both perspectives with a single definition.
		{
			name: "figure12",
			run:  tcp.ExchangeTest.Run, // Runs both PeerA and PeerB subtests.
			test: tcp.ExchangeTest{
				ISSA:       issA,
				ISSB:       issB,
				WindowA:    windowA,
				WindowB:    windowB,
				InitStateA: tcp.StateEstablished,
				InitStateB: tcp.StateEstablished,
				Steps: []tcp.SegmentStep{
					0: { // A sends FIN|ACK to B (RFC 9293 Figure 12 step 2).
						Seg:      tcp.Segment{SEQ: issA, ACK: issB, Flags: FINACK, WND: windowA},
						Action:   tcp.StepASends,
						AState:   tcp.StateFinWait1,
						BState:   tcp.StateCloseWait,
						APending: nil,
						BPending: &tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: tcp.FlagACK, WND: windowB},
					},
					1: { // B sends ACK to A (RFC 9293 Figure 12 step 3). B stays in CLOSE-WAIT.
						Seg:      tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: tcp.FlagACK, WND: windowB},
						Action:   tcp.StepBSends,
						AState:   tcp.StateFinWait2,
						BState:   tcp.StateCloseWait,
						APending: nil, // RFC Figure 12 shows no response from A here — bare ACK must not elicit ACK.
					},
					2: { // B calls Close() (RFC 9293 Figure 12 step 4). B goes to LAST-ACK.
						Action:   tcp.StepBCloses,
						AState:   tcp.StateFinWait2,
						BState:   tcp.StateLastAck,
						BPending: &tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: FINACK, WND: windowB},
					},
					3: { // B sends FIN|ACK to A (RFC 9293 Figure 12 step 4 cont).
						Seg:      tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: FINACK, WND: windowB},
						Action:   tcp.StepBSends,
						AState:   tcp.StateTimeWait,
						BState:   tcp.StateLastAck,
						APending: &tcp.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: tcp.FlagACK, WND: windowA},
						BPending: nil,
					},
					4: { // A sends final ACK to B (RFC 9293 Figure 12 step 5).
						Seg:      tcp.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: tcp.FlagACK, WND: windowA},
						Action:   tcp.StepASends,
						AState:   tcp.StateTimeWait,
						BState:   tcp.StateClosed,
						APending: nil,
						BPending: nil,
					},
				},
			},
		},
		{
			name: "rfc9293_figure6",
			run:  tcp.ExchangeTest.Run,
			test: tcp.ExchangeTest{
				ISSA:       issA,
				ISSB:       issB,
				WindowA:    windowA,
				WindowB:    windowB,
				InitStateA: tcp.StateSynSent,
				InitStateB: tcp.StateListen,
				Steps: []tcp.SegmentStep{
					0: { // A sends SYN to B.
						Seg:      tcp.Segment{SEQ: issA, Flags: tcp.FlagSYN, WND: windowA},
						Action:   tcp.StepASends,
						AState:   tcp.StateSynSent,
						BState:   tcp.StateSynRcvd,
						BPending: &tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: SYNACK, WND: windowB},
					},
					1: { // B sends SYNACK to A.
						Seg:      tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: SYNACK, WND: windowB},
						Action:   tcp.StepBSends,
						AState:   tcp.StateEstablished,
						BState:   tcp.StateSynRcvd,
						APending: &tcp.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: tcp.FlagACK, WND: windowA},
					},
					2: { // A sends ACK to B. Three-way handshake complete.
						Seg:    tcp.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: tcp.FlagACK, WND: windowA},
						Action: tcp.StepASends,
						AState: tcp.StateEstablished,
						BState: tcp.StateEstablished,
					},
				},
			},
		},
		// NOTE: Simultaneous SYN can only be tested from one perspective because
		// the "simultaneous" nature means segments cross in flight. In a sequential
		// test, when B receives A's SYN first, B goes to SYN-RECEIVED, not SYN-SENT.
		{
			name: "rfc9293_figure7",
			run:  tcp.ExchangeTest.RunA, // Only A's perspective - B's is fundamentally different in sequential test.
			test: tcp.ExchangeTest{
				ISSA:       issA,
				ISSB:       issB,
				WindowA:    windowA,
				WindowB:    windowB,
				InitStateA: tcp.StateSynSent,
				InitStateB: tcp.StateSynSent,
				Steps: []tcp.SegmentStep{
					0: { // A sends SYN to B (crosses with B's SYN).
						Seg:    tcp.Segment{SEQ: issA, Flags: tcp.FlagSYN, WND: windowA},
						Action: tcp.StepASends,
						AState: tcp.StateSynSent,
					},
					1: { // A receives SYN from B (no ACK - B hasn't received A's SYN yet).
						Seg:      tcp.Segment{SEQ: issB, Flags: tcp.FlagSYN, WND: windowB},
						Action:   tcp.StepBSends,
						AState:   tcp.StateSynRcvd,
						APending: &tcp.Segment{SEQ: issA, ACK: issB + 1, Flags: SYNACK, WND: windowA},
					},
					2: { // A sends SYNACK to B.
						Seg:    tcp.Segment{SEQ: issA, ACK: issB + 1, Flags: SYNACK, WND: windowA},
						Action: tcp.StepASends,
						AState: tcp.StateSynRcvd,
					},
					3: { // A receives SYNACK from B.
						Seg:    tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: SYNACK, WND: windowB},
						Action: tcp.StepBSends,
						AState: tcp.StateEstablished,
					},
				},
			},
		},
		// Passive SYN-RECEIVED must challenge a SYN,ACK at IRS as duplicate SYN (RFC 9293 §3.10.7.4).
		// Previously it took the Figure 7 simultaneous open path and established desynced. Found by lfuzzo.
		{
			name: "passiveSynRcvdRejectsSynAck",
			run:  tcp.ExchangeTest.RunB, // Only B, the passive opener: A is not a valid simultaneous-open peer here.
			test: tcp.ExchangeTest{
				ISSA:       issA,
				ISSB:       issB,
				WindowA:    windowA,
				WindowB:    windowB,
				InitStateA: tcp.StateSynSent,
				InitStateB: tcp.StateListen,
				Steps: []tcp.SegmentStep{
					0: { // B receives SYN from A.
						Seg:      tcp.Segment{SEQ: issA, Flags: tcp.FlagSYN, WND: windowA},
						Action:   tcp.StepASends,
						BState:   tcp.StateSynRcvd,
						BPending: &tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: SYNACK, WND: windowB},
					},
					1: { // B sends SYN,ACK.
						Seg:    tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: SYNACK, WND: windowB},
						Action: tcp.StepBSends,
						BState: tcp.StateSynRcvd,
					},
					2: { // B receives SYN,ACK at IRS acknowledging its SYN: challenged, not established.
						Seg:      tcp.Segment{SEQ: issA, ACK: issB + 1, Flags: SYNACK, WND: windowA},
						Action:   tcp.StepASends,
						BState:   tcp.StateSynRcvd,
						BPending: &tcp.Segment{SEQ: issB + 1, ACK: issA + 1, Flags: tcp.FlagACK, WND: windowB},
					},
				},
			},
		},
		// Drop SYN|FIN in listen, just like linux. Admitting them both would cause rcvnxt desync. lfuzzo found.
		{
			name: "listenDropsSynFin",
			run:  tcp.ExchangeTest.RunB, // Only B, the passive opener: the SYN,FIN models a mutated segment, not A's own send.
			test: tcp.ExchangeTest{
				ISSA:       issA,
				ISSB:       issB,
				WindowA:    windowA,
				WindowB:    windowB,
				InitStateA: tcp.StateSynSent,
				InitStateB: tcp.StateListen,
				Steps: []tcp.SegmentStep{
					0: { // B receives SYN,FIN from A: dropped, no reply, still listening.
						Seg:    tcp.Segment{SEQ: issA, Flags: tcp.FlagSYN | tcp.FlagFIN, WND: windowA},
						Action: tcp.StepASends,
						BState: tcp.StateListen,
					},
				},
			},
		},
		// SYN with text in LISTEN is dropped: text may not be acknowledged before ESTABLISHED (RFC 9293 §3.10.7.2).
		// Previously RCV.NXT advanced past the text, so the SYN,ACK acknowledged unqueued data. lfuzzo found.
		{
			name: "listenDropsSynData",
			run:  tcp.ExchangeTest.RunB, // Only B, the passive opener: the SYN text models a mutated segment, not A's own send.
			test: tcp.ExchangeTest{
				ISSA:       issA,
				ISSB:       issB,
				WindowA:    windowA,
				WindowB:    windowB,
				InitStateA: tcp.StateSynSent,
				InitStateB: tcp.StateListen,
				Steps: []tcp.SegmentStep{
					0: { // B receives SYN carrying 21 octets of text: dropped, no reply, still listening.
						Seg:    tcp.Segment{SEQ: issA, Flags: tcp.FlagSYN | tcp.FlagPSH, WND: windowA, DATALEN: 21},
						Action: tcp.StepASends,
						BState: tcp.StateListen,
					},
				},
			},
		},
		// synSentResetsBadAck: a bad ACK in SYN-SENT must draw RST <SEQ=SEG.ACK> (RFC 9293 §3.10.7.3).
		// Previously SEG.SEQ was checked against the unset receive window, emitting a challenge ACK=0 at SEQ=ISS+1. Found by lfuzzo.
		{
			name: "synSentResetsBadAck",
			run:  tcp.ExchangeTest.RunA, // Only A, the active opener: the ACK models a mutated segment, not B's own send.
			test: tcp.ExchangeTest{
				ISSA:       issA,
				ISSB:       issB,
				WindowA:    windowA,
				WindowB:    windowB,
				InitStateA: tcp.StateSynSent,
				InitStateB: tcp.StateListen,
				Steps: []tcp.SegmentStep{
					0: { // A sends SYN.
						Seg:    tcp.Segment{SEQ: issA, Flags: tcp.FlagSYN, WND: windowA},
						Action: tcp.StepASends,
						AState: tcp.StateSynSent,
					},
					1: { // A receives an ACK acknowledging unsent data: reset, still SYN-SENT.
						Seg:      tcp.Segment{SEQ: badAck, ACK: badAck, Flags: tcp.FlagACK, WND: windowB},
						Action:   tcp.StepBSends,
						AState:   tcp.StateSynSent,
						APending: &tcp.Segment{SEQ: badAck, Flags: tcp.FlagRST, WND: windowA},
					},
				},
			},
		},
		// Drop SYN|FIN in SYN-SENT, as in LISTEN. Admitting it took the simultaneous open path with
		// RCV.NXT=IRS+2, so the SYN,ACK reply acknowledged an unprocessed FIN. lfuzzo found.
		{
			name: "synSentDropsSynFin",
			run:  tcp.ExchangeTest.RunA, // Only A, the active opener: the SYN,FIN models a mutated segment, not B's own send.
			test: tcp.ExchangeTest{
				ISSA:       issA,
				ISSB:       issB,
				WindowA:    windowA,
				WindowB:    windowB,
				InitStateA: tcp.StateSynSent,
				InitStateB: tcp.StateListen,
				Steps: []tcp.SegmentStep{
					0: { // A sends SYN.
						Seg:    tcp.Segment{SEQ: issA, Flags: tcp.FlagSYN, WND: windowA},
						Action: tcp.StepASends,
						AState: tcp.StateSynSent,
					},
					1: { // A receives SYN,FIN: dropped, no reply, still SYN-SENT.
						Seg:    tcp.Segment{SEQ: issB, Flags: tcp.FlagSYN | tcp.FlagFIN, WND: windowB},
						Action: tcp.StepBSends,
						AState: tcp.StateSynSent,
					},
					2: { // A receives SYN,ACK,FIN acknowledging its SYN: also dropped.
						Seg:    tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: SYNACK | tcp.FlagFIN, WND: windowB},
						Action: tcp.StepBSends,
						AState: tcp.StateSynSent,
					},
				},
			},
		},
		// NOTE: Simultaneous close can only be tested from one perspective because
		// the "simultaneous" nature means FINs cross in flight. In a sequential test,
		// when B receives A's FIN first, B goes to CLOSE-WAIT, not CLOSING.
		{
			name: "rfc9293_figure13",
			run:  tcp.ExchangeTest.RunA, // Only A's perspective - B's is fundamentally different in sequential test.
			test: tcp.ExchangeTest{
				ISSA:       issA,
				ISSB:       issB,
				WindowA:    windowA,
				WindowB:    windowB,
				InitStateA: tcp.StateEstablished,
				InitStateB: tcp.StateEstablished,
				Steps: []tcp.SegmentStep{
					0: { // A sends FIN|ACK to B (crosses with B's FIN|ACK).
						Seg:    tcp.Segment{SEQ: issA, ACK: issB, Flags: FINACK, WND: windowA},
						Action: tcp.StepASends,
						AState: tcp.StateFinWait1,
					},
					1: { // A receives FIN|ACK from B (B sent before receiving A's FIN).
						Seg:      tcp.Segment{SEQ: issB, ACK: issA, Flags: FINACK, WND: windowB},
						Action:   tcp.StepBSends,
						AState:   tcp.StateClosing,
						APending: &tcp.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: tcp.FlagACK, WND: windowA},
					},
					2: { // A sends the ACK of B's FIN. Its own FIN is not yet acknowledged, so it stays CLOSING.
						Seg:    tcp.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: tcp.FlagACK, WND: windowA},
						Action: tcp.StepASends,
						AState: tcp.StateClosing,
					},
					3: { // A receives B's ACK of A's FIN (ACK == snd.NXT): enter TIME-WAIT.
						Seg:    tcp.Segment{SEQ: issB + 1, ACK: issA + 1, Flags: tcp.FlagACK, WND: windowB},
						Action: tcp.StepBSends,
						AState: tcp.StateTimeWait,
					},
				},
			},
		},
		// ZeroWindowRSTResets: an RST at RCV.NXT resets the connection despite a zero receive window (RFC 9293 §3.10.7.4, MUST-66).
		// It was refused with ErrZeroWindow and the connection stayed open.
		{
			name: "ZeroWindowRSTResets",
			run:  tcp.ExchangeTest.RunA,
			test: tcp.ExchangeTest{
				ISSA:       issA,
				ISSB:       issB,
				WindowA:    0,
				WindowB:    windowB,
				InitStateA: tcp.StateEstablished,
				InitStateB: tcp.StateEstablished,
				Steps: []tcp.SegmentStep{
					{Seg: tcp.Segment{SEQ: issB, ACK: issA, Flags: tcp.FlagRST | tcp.FlagACK, WND: windowB, DATALEN: 1}, Action: tcp.StepBSends, AState: tcp.StateClosed, WantErr: net.ErrClosed},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) { tc.run(tc.test, t) })
	}
}

// Out-of-window segments past the challenge ACK limit are dropped silently, never aborting (RFC 5961 §7).
// Previously the 10th aborted ESTABLISHED without RST, leaving the peer retransmitting forever. lfuzzo found.
func TestExchangeTest_challengeAckFloodNoAbort(t *testing.T) {
	const issA, issB, windowA, windowB = 100, 300, 1000, 1000
	test := tcp.ExchangeTest{
		ISSA:       issA,
		ISSB:       issB,
		WindowA:    windowA,
		WindowB:    windowB,
		InitStateA: tcp.StateEstablished,
		InitStateB: tcp.StateEstablished,
	}
	oow := tcp.Segment{SEQ: issA + 5000, ACK: issB, Flags: tcp.FlagACK, WND: windowA}
	for i := range 12 {
		if i >= 9 { // Past the challenge ACK limit: dropped silently, still ESTABLISHED.
			test.Steps = append(test.Steps, tcp.SegmentStep{Seg: oow, Action: tcp.StepASends, BState: tcp.StateEstablished, WantErr: tcp.ErrSeqNotInWindow})
			continue
		}
		test.Steps = append(test.Steps,
			tcp.SegmentStep{ // B receives segment beyond its receive window: challenge ACK, still ESTABLISHED.
				Seg:      oow,
				Action:   tcp.StepASends,
				BState:   tcp.StateEstablished,
				BPending: &tcp.Segment{SEQ: issB, ACK: issA, Flags: tcp.FlagACK, WND: windowB},
				WantErr:  tcp.ErrSeqNotInWindow,
			},
			tcp.SegmentStep{ // B sends challenge ACK.
				Seg:    tcp.Segment{SEQ: issB, ACK: issA, Flags: tcp.FlagACK, WND: windowB},
				Action: tcp.StepBSends,
				BState: tcp.StateEstablished,
			},
		)
	}
	test.RunB(t) // Only B: the out-of-window segments model mutations, not A's own sends.
}

// Each fast retransmit owed for duplicate ACKs is cleared when sent; past counter saturation none are owed.
// Previously nRetransmit saturated at 250 below dupack, leaving a retransmit pending forever after the ACKs stopped. lfuzzo found.
func TestExchangeTest_dupackRetransmitSaturation(t *testing.T) {
	const issA, issB, windowA, windowB = 100, 300, 1000, 1000
	const datalen = 10
	test := tcp.ExchangeTest{
		ISSA:       issA,
		ISSB:       issB,
		WindowA:    windowA,
		WindowB:    windowB,
		InitStateA: tcp.StateEstablished,
		InitStateB: tcp.StateEstablished,
		Steps: []tcp.SegmentStep{
			0: { // B receives window update.
				Seg:    tcp.Segment{SEQ: issA, ACK: issB, Flags: tcp.FlagACK, WND: windowA},
				Action: tcp.StepASends,
				BState: tcp.StateEstablished,
			},
			1: { // B sends data, never acknowledged.
				Seg:    tcp.Segment{SEQ: issB, ACK: issA, Flags: tcp.FlagACK, WND: windowB, DATALEN: datalen},
				Action: tcp.StepBSends,
				BState: tcp.StateEstablished,
			},
		},
	}
	dupack := tcp.Segment{SEQ: issA, ACK: issB, Flags: tcp.FlagACK, WND: windowA}
	rtx := tcp.Segment{SEQ: issB, ACK: issA, Flags: tcp.FlagACK, WND: windowB}
	for i := range 300 {
		if i < 2 || i >= 250 { // First two, and those past dupack saturation, owe no retransmit.
			test.Steps = append(test.Steps, tcp.SegmentStep{Seg: dupack, Action: tcp.StepASends, BState: tcp.StateEstablished})
			continue
		}
		test.Steps = append(test.Steps,
			tcp.SegmentStep{Seg: dupack, Action: tcp.StepASends, BState: tcp.StateEstablished, BPending: &rtx},
			tcp.SegmentStep{Seg: rtx, Action: tcp.StepBSends, BState: tcp.StateEstablished}, // Retransmit sent: nothing pending.
		)
	}
	test.RunB(t) // Only B: the duplicate ACK run models mutated traffic, not A's own sends.
}

/*
	 Section 3.5 of RFC 9293: Basic 3-way handshake for connection synchronization.
		TCP Peer A                                           TCP Peer B

		1.  CLOSED                                               LISTEN

		2.  SYN-SENT    --> <SEQ=100><CTL=SYN>               --> SYN-RECEIVED

		3.  ESTABLISHED <-- <SEQ=300><ACK=101><CTL=SYN,ACK>  <-- SYN-RECEIVED

		4.  ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK>       --> ESTABLISHED

		5.  ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK><DATA> --> ESTABLISHED
*/
/*
	 Section 3.5 of RFC 9293: Simultaneous Connection Synchronization (SYN).
		TCP Peer A                                       TCP Peer B

		1.  CLOSED                                           CLOSED

		2.  SYN-SENT     --> <SEQ=100><CTL=SYN>              ...

		3.  SYN-RECEIVED <-- <SEQ=300><CTL=SYN>              <-- SYN-SENT

		4.               ... <SEQ=100><CTL=SYN>              --> SYN-RECEIVED

		5.  SYN-RECEIVED --> <SEQ=100><ACK=301><CTL=SYN,ACK> ...

		6.  ESTABLISHED  <-- <SEQ=300><ACK=101><CTL=SYN,ACK> <-- SYN-RECEIVED

		7.               ... <SEQ=100><ACK=301><CTL=SYN,ACK> --> ESTABLISHED
*/
// TestExchangeTest_dupACKCarryingData: an ACK of SND.UNA carrying data is no duplicate ACK (RFC 5681 §2).
// Previously three such ACKs, as in two-way traffic, triggered a spurious fast retransmit.
func TestExchangeTest_dupACKCarryingData(t *testing.T) {
	const issA, issB, windowA, windowB = 100, 300, 1000, 1000
	steps := []tcp.SegmentStep{{ // A sends 10 octets.
		Seg:    tcp.Segment{SEQ: issA, ACK: issB, Flags: tcp.FlagACK, WND: windowA, DATALEN: 10},
		Action: tcp.StepASends,
		AState: tcp.StateEstablished,
	}}
	for i := range tcp.Size(3) { // B sends data acknowledging SND.UNA: A only acknowledges it.
		steps = append(steps, tcp.SegmentStep{
			Seg:      tcp.Segment{SEQ: tcp.Add(issB, 10*i), ACK: issA, Flags: tcp.FlagACK, WND: windowB, DATALEN: 10},
			Action:   tcp.StepBSends,
			AState:   tcp.StateEstablished,
			APending: &tcp.Segment{SEQ: issA + 10, ACK: tcp.Add(issB, 10*(i+1)), Flags: tcp.FlagACK, WND: windowA},
		})
	}
	test := tcp.ExchangeTest{
		ISSA: issA, ISSB: issB, WindowA: windowA, WindowB: windowB,
		InitStateA: tcp.StateEstablished, InitStateB: tcp.StateEstablished,
		Steps: steps,
	}
	test.RunA(t)
}

// TestExchangeTest_dupACKWindowUpdate: an ACK of SND.UNA opening the window is a window update, not a
// duplicate ACK (RFC 5681 §2), while repeats of a smaller window still count. Previously three window
// updates, as from a receiver draining its buffer, triggered a spurious fast retransmit.
func TestExchangeTest_dupACKWindowUpdate(t *testing.T) {
	const issA, issB, windowA, windowB = 100, 300, 1000, 1000
	steps := []tcp.SegmentStep{{ // A sends 10 octets.
		Seg:    tcp.Segment{SEQ: issA, ACK: issB, Flags: tcp.FlagACK, WND: windowA, DATALEN: 10},
		Action: tcp.StepASends,
		AState: tcp.StateEstablished,
	}}
	for i := range tcp.Size(3) { // B opens its window three times: no retransmit.
		steps = append(steps, tcp.SegmentStep{
			Seg:    tcp.Segment{SEQ: issB, ACK: issA, Flags: tcp.FlagACK, WND: windowB + 1 + i},
			Action: tcp.StepBSends,
			AState: tcp.StateEstablished,
		})
	}
	for i := range 3 { // B repeats a smaller window three times: fast retransmit.
		var want *tcp.Segment
		if i == 2 {
			want = &tcp.Segment{SEQ: issA, ACK: issB, Flags: tcp.FlagACK, WND: windowA}
		}
		steps = append(steps, tcp.SegmentStep{
			Seg:      tcp.Segment{SEQ: issB, ACK: issA, Flags: tcp.FlagACK, WND: 800},
			Action:   tcp.StepBSends,
			AState:   tcp.StateEstablished,
			APending: want,
		})
	}
	test := tcp.ExchangeTest{
		ISSA: issA, ISSB: issB, WindowA: windowA, WindowB: windowB,
		InitStateA: tcp.StateEstablished, InitStateB: tcp.StateEstablished,
		Steps: steps,
	}
	test.RunA(t)
}

/*
	 Recovery from Old Duplicate SYN
		TCP Peer A                                           TCP Peer B

		1.  CLOSED                                               LISTEN

		2.  SYN-SENT    --> <SEQ=100><CTL=SYN>               ...

		3.  (duplicate) ... <SEQ=90><CTL=SYN>               --> SYN-RECEIVED

		4.  SYN-SENT    <-- <SEQ=300><ACK=91><CTL=SYN,ACK>  <-- SYN-RECEIVED

		5.  SYN-SENT    --> <SEQ=91><CTL=RST>               --> LISTEN

		6.              ... <SEQ=100><CTL=SYN>               --> SYN-RECEIVED

		7.  ESTABLISHED <-- <SEQ=400><ACK=101><CTL=SYN,ACK>  <-- SYN-RECEIVED

		8.  ESTABLISHED --> <SEQ=101><ACK=401><CTL=ACK>      --> ESTABLISHED

NOTE: This test is asymmetric. A and B have different views because B receives an
old duplicate SYN that A never sent. Cannot use Run() - must test each perspective separately.
*/
func TestExchangeTest_rfc9293_figure8(t *testing.T) {
	const issA, issB, windowA, windowB = 100, 300, 1000, 1000
	const issAold = 90
	const issBnew = 400

	// Test from A's perspective: A sends SYN, gets wrong SYNACK, sends RST,
	// gets correct SYNACK, sends ACK.
	t.Run("PeerA", func(t *testing.T) {
		var tcbA tcp.ControlBlock
		tcbA.HelperInitState(tcp.StateSynSent, issA, issA, windowA)

		stepsA := []tcp.SegmentStep{
			0: { // A sends SYN (step 2 in figure).
				Seg:    tcp.Segment{SEQ: issA, Flags: tcp.FlagSYN, WND: windowA},
				Action: tcp.StepASends,
				AState: tcp.StateSynSent,
			},
			1: { // A receives SYNACK with wrong ACK (acking old duplicate SYN).
				Seg:      tcp.Segment{SEQ: issB, ACK: issAold + 1, Flags: SYNACK, WND: windowB},
				Action:   tcp.StepBSends,
				AState:   tcp.StateSynSent, // A stays in SYN-SENT because ACK is wrong.
				APending: &tcp.Segment{SEQ: issAold + 1, Flags: tcp.FlagRST, WND: windowA},
			},
			2: { // A sends RST to reject the bad SYNACK.
				Seg:    tcp.Segment{SEQ: issAold + 1, Flags: tcp.FlagRST, WND: windowA},
				Action: tcp.StepASends,
				AState: tcp.StateSynSent,
			},
			3: { // A sends duplicate SYN (retransmit, step 6 arrival at B).
				Seg:    tcp.Segment{SEQ: issA, Flags: tcp.FlagSYN, WND: windowA},
				Action: tcp.StepASends,
				AState: tcp.StateSynSent,
			},
			4: { // A receives correct SYNACK from B with new ISS.
				Seg:      tcp.Segment{SEQ: issBnew, ACK: issA + 1, Flags: SYNACK, WND: windowB},
				Action:   tcp.StepBSends,
				AState:   tcp.StateEstablished,
				APending: &tcp.Segment{SEQ: issA + 1, ACK: issBnew + 1, Flags: tcp.FlagACK, WND: windowA},
			},
			5: { // A sends ACK to complete handshake.
				Seg:    tcp.Segment{SEQ: issA + 1, ACK: issBnew + 1, Flags: tcp.FlagACK, WND: windowA},
				Action: tcp.StepASends,
				AState: tcp.StateEstablished,
			},
		}
		tcbA.HelperSteps(t, stepsA, true)
	})

	// Test from B's perspective: B receives old SYN, sends SYNACK, receives RST,
	// receives real SYN, sends new SYNACK, receives ACK.
	t.Run("PeerB", func(t *testing.T) {
		var tcbB tcp.ControlBlock
		tcbB.HelperInitState(tcp.StateListen, issB, issB, windowB)

		stepsB := []tcp.SegmentStep{
			0: { // B receives old duplicate SYN (step 3).
				Seg:      tcp.Segment{SEQ: issAold, Flags: tcp.FlagSYN, WND: windowA},
				Action:   tcp.StepASends,
				BState:   tcp.StateSynRcvd,
				BPending: &tcp.Segment{SEQ: issB, ACK: issAold + 1, Flags: SYNACK, WND: windowB},
			},
			1: { // B sends SYNACK for old SYN.
				Seg:    tcp.Segment{SEQ: issB, ACK: issAold + 1, Flags: SYNACK, WND: windowB},
				Action: tcp.StepBSends,
				BState: tcp.StateSynRcvd,
			},
			2: { // B receives RST, goes back to LISTEN.
				Seg:    tcp.Segment{SEQ: issAold + 1, Flags: tcp.FlagRST, WND: windowA},
				Action: tcp.StepASends,
				BState: tcp.StateListen,
			},
			3: { // B receives real SYN (step 6).
				Seg:      tcp.Segment{SEQ: issA, Flags: tcp.FlagSYN, WND: windowA},
				Action:   tcp.StepASends,
				BState:   tcp.StateSynRcvd,
				BPending: &tcp.Segment{SEQ: issBnew, ACK: issA + 1, Flags: SYNACK, WND: windowB},
			},
			4: { // B sends new SYNACK.
				Seg:    tcp.Segment{SEQ: issBnew, ACK: issA + 1, Flags: SYNACK, WND: windowB},
				Action: tcp.StepBSends,
				BState: tcp.StateSynRcvd,
			},
			5: { // B receives ACK, connection established.
				Seg:    tcp.Segment{SEQ: issA + 1, ACK: issBnew + 1, Flags: tcp.FlagACK, WND: windowA},
				Action: tcp.StepASends,
				BState: tcp.StateEstablished,
			},
		}
		tcbB.HelperSteps(t, stepsB, false)
	})
}

/*
	 Figure 13: Simultaneous Close Sequence
			TCP Peer A                                           TCP Peer B

		1.  ESTABLISHED                                          ESTABLISHED

		2.  (Close)                                              (Close)
			FIN-WAIT-1  --> <SEQ=100><ACK=300><CTL=FIN,ACK>  ... FIN-WAIT-1
						<-- <SEQ=300><ACK=100><CTL=FIN,ACK>  <--
						... <SEQ=100><ACK=300><CTL=FIN,ACK>  -->

		3.  CLOSING     --> <SEQ=101><ACK=301><CTL=ACK>      ... CLOSING
						<-- <SEQ=301><ACK=101><CTL=ACK>      <--
						... <SEQ=101><ACK=301><CTL=ACK>      -->

		4.  TIME-WAIT                                            TIME-WAIT
			(2 MSL)                                              (2 MSL)
			CLOSED                                               CLOSED
*/
func TestResetEstablished(t *testing.T) {
	var tcb tcp.ControlBlock
	const windowA, windowB = 502, 4096
	const issA, issB = 0x5e722b7d, 0xbe6e4c0f
	tcb.HelperInitState(tcp.StateEstablished, issA, issA, windowA)
	tcb.HelperInitRcv(issB, issB, windowB)

	err := tcb.Recv(tcp.Segment{SEQ: issB, ACK: issA, Flags: tcp.FlagRST, WND: windowB})
	if err == nil {
		t.Fatal("expected error")
	}
	if tcb.State() != tcp.StateClosed {
		t.Error("expected closed state; got ", tcb.State().String())
	}
	checkNoPending(t, &tcb)
}

func TestFinackClose(t *testing.T) {
	var tcb tcp.ControlBlock
	const windowA, windowB = 502, 4096
	const issA, issB = 100, 200
	tcb.HelperInitState(tcp.StateEstablished, issA, issA, windowA)
	tcb.HelperInitRcv(issB, issB, windowB)
	// Start closing process.
	err := tcb.Close()
	if err != nil {
		t.Fatal(err)
	}
	seg, ok := tcb.PendingSegment(0)
	if !ok {
		t.Fatal("expected pending segment")
	}
	if !seg.Flags.HasAll(tcp.FlagFIN | tcp.FlagACK) {
		t.Fatalf("expected FIN|ACK; got %s", seg.Flags.String())
	}
	err = tcb.Send(seg)
	if err != nil {
		t.Fatal(err)
	}
	if tcb.State() != tcp.StateFinWait1 {
		t.Fatalf("expected FinWait1; got %s", tcb.State().String())
	}
	// Special case where we receive FINACK all together, we can streamline and go into TimeWait.
	err = tcb.Recv(tcp.Segment{
		SEQ:   issB,
		ACK:   issA + 1,
		WND:   windowB,
		Flags: FINACK,
	})
	if err != nil {
		t.Fatal(err)
	}
	if tcb.State() != tcp.StateTimeWait {
		t.Fatalf("expected TimeWait after FINACK; got %s", tcb.State().String())
	}
}

func checkNoPending(t *testing.T, tcb *tcp.ControlBlock) bool {
	t.Helper()
	// We extensively test the API for inadvertent state modification in a HasPending or PendingSegment call.
	hasPD := tcb.HasPending()
	pd, ok := tcb.PendingSegment(0)
	hasPD2 := tcb.HasPending()
	if hasPD || ok || hasPD2 {
		t.Errorf("unexpected pending segment: %+v (%v,%v,%v)", pd, hasPD, ok, hasPD2)
		return false
	}
	if hasPD != ok || hasPD != hasPD2 {
		t.Fatalf("inconsistent pending segment: (%v,%v,%v)", hasPD, ok, hasPD2)
	}
	if !ok && pd != (tcp.Segment{}) {
		t.Fatalf("inconsistent pending segment: %+v (%v,%v,%v)", pd, hasPD, ok, hasPD2)
	}
	return true
}

// Full client-server interaction in the sending of "hello world" over TCP in order.
var exchangeHelloWorld = [][]byte{
	// client SYN1
	0: []byte("\x28\xcd\xc1\x05\x4d\xbb\xd8\x5e\xd3\x43\x03\xeb\x08\x00\x45\x00\x00\x3c\x71\xac\x40\x00\x40\x06\x44\x9b\xc0\xa8\x01\x93\xc0\xa8\x01\x91\x84\x96\x04\xd2\x5e\x72\x2b\x7d\x00\x00\x00\x00\xa0\x02\xfa\xf0\x27\x6d\x00\x00\x02\x04\x05\xb4\x04\x02\x08\x0a\x07\x8b\x86\x4a\x00\x00\x00\x00\x01\x03\x03\x07"),
	// server SYNACK
	1: []byte("\xd8\x5e\xd3\x43\x03\xeb\x28\xcd\xc1\x05\x4d\xbb\x08\x00\x45\x00\x00\x34\x00\x00\x40\x00\x40\x06\xb6\x4f\xc0\xa8\x01\x91\xc0\xa8\x01\x93\x04\xd2\x84\x96\xbe\x6e\x4c\x0f\x5e\x72\x2b\x7e\x80\x12\x10\x00\xc0\xbb\x00\x00\x02\x04\x05\xb4\x03\x03\x00\x04\x02\x00\x00\x00"),
	// client ACK1
	2: []byte("\x28\xcd\xc1\x05\x4d\xbb\xd8\x5e\xd3\x43\x03\xeb\x08\x00\x45\x00\x00\x28\x71\xad\x40\x00\x40\x06\x44\xae\xc0\xa8\x01\x93\xc0\xa8\x01\x91\x84\x96\x04\xd2\x5e\x72\x2b\x7e\xbe\x6e\x4c\x10\x50\x10\x01\xf6\x0b\x92\x00\x00"),
	// client PSHACK0
	3: []byte("\x28\xcd\xc1\x05\x4d\xbb\xd8\x5e\xd3\x43\x03\xeb\x08\x00\x45\x00\x00\x34\x71\xae\x40\x00\x40\x06\x44\xa1\xc0\xa8\x01\x93\xc0\xa8\x01\x91\x84\x96\x04\xd2\x5e\x72\x2b\x7e\xbe\x6e\x4c\x10\x50\x18\x01\xf6\x79\xa5\x00\x00\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x0a"),
	// server ACK1
	4: []byte("\xd8\x5e\xd3\x43\x03\xeb\x28\xcd\xc1\x05\x4d\xbb\x08\x00\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\xb6\x5b\xc0\xa8\x01\x91\xc0\xa8\x01\x93\x04\xd2\x84\x96\xbe\x6e\x4c\x10\x5e\x72\x2b\x8a\x50\x10\x0f\xf4\xfd\x87\x00\x00\x00\x00\x00\x00\x00\x00"),
	// server PSHACK1
	5: []byte("\xd8\x5e\xd3\x43\x03\xeb\x28\xcd\xc1\x05\x4d\xbb\x08\x00\x45\x00\x00\x34\x00\x00\x40\x00\x40\x06\xb6\x4f\xc0\xa8\x01\x91\xc0\xa8\x01\x93\x04\xd2\x84\x96\xbe\x6e\x4c\x10\x5e\x72\x2b\x8a\x50\x18\x10\x00\x6b\x8f\x00\x00\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x0a"),
	// client ACK2
	6: []byte("\x28\xcd\xc1\x05\x4d\xbb\xd8\x5e\xd3\x43\x03\xeb\x08\x00\x45\x00\x00\x28\x71\xaf\x40\x00\x40\x06\x44\xac\xc0\xa8\x01\x93\xc0\xa8\x01\x91\x84\x96\x04\xd2\x5e\x72\x2b\x8a\xbe\x6e\x4c\x1c\x50\x10\x01\xf6\x0b\x7a\x00\x00"),
	// client PSHACK1
	7: []byte("\x28\xcd\xc1\x05\x4d\xbb\xd8\x5e\xd3\x43\x03\xeb\x08\x00\x45\x00\x00\x34\x71\xb0\x40\x00\x40\x06\x44\x9f\xc0\xa8\x01\x93\xc0\xa8\x01\x91\x84\x96\x04\xd2\x5e\x72\x2b\x8a\xbe\x6e\x4c\x1c\x50\x18\x01\xf6\x79\x8d\x00\x00\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x0a"),
	// server PSHACK2
	8: []byte("\xd8\x5e\xd3\x43\x03\xeb\x28\xcd\xc1\x05\x4d\xbb\x08\x00\x45\x00\x00\x34\x00\x00\x40\x00\x40\x06\xb6\x4f\xc0\xa8\x01\x91\xc0\xa8\x01\x93\x04\xd2\x84\x96\xbe\x6e\x4c\x1c\x5e\x72\x2b\x96\x50\x18\x10\x00\x6b\x77\x00\x00\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x0a"),
	// client ACK3
	9: []byte("\x28\xcd\xc1\x05\x4d\xbb\xd8\x5e\xd3\x43\x03\xeb\x08\x00\x45\x00\x00\x28\x71\xb1\x40\x00\x40\x06\x44\xaa\xc0\xa8\x01\x93\xc0\xa8\x01\x91\x84\x96\x04\xd2\x5e\x72\x2b\x96\xbe\x6e\x4c\x28\x50\x10\x01\xf6\x0b\x62\x00\x00"),
	// client FINACK
	10: []byte("\x28\xcd\xc1\x05\x4d\xbb\xd8\x5e\xd3\x43\x03\xeb\x08\x00\x45\x00\x00\x28\x71\xb2\x40\x00\x40\x06\x44\xa9\xc0\xa8\x01\x93\xc0\xa8\x01\x91\x84\x96\x04\xd2\x5e\x72\x2b\x96\xbe\x6e\x4c\x28\x50\x11\x01\xf6\x0b\x61\x00\x00"),
	// server ACK
	11: []byte("\xd8\x5e\xd3\x43\x03\xeb\x28\xcd\xc1\x05\x4d\xbb\x08\x00\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\xb6\x5b\xc0\xa8\x01\x91\xc0\xa8\x01\x93\x04\xd2\x84\x96\xbe\x6e\x4c\x28\x5e\x72\x2b\x97\x50\x10\x10\x00\xfd\x56\x00\x00\x00\x00\x00\x00\x00\x00"),
}

// This corresponds to https://github.com/soypat/seqs/issues/19
// The bug consisted of a panic condition encountered when using wget client with a seqs based server.
// Thanks to @knieriem for finding this and the detailed report they submitted.
func TestIssue19(t *testing.T) {
	var tcb tcp.ControlBlock
	assertState := func(state tcp.State) {
		t.Helper()
		if tcb.State() != state {
			t.Fatalf("want state %s; got %s", state.String(), tcb.State().String())
		}
	}
	const httpLen = 1192
	const issA, issB, windowA, windowB = 1, 0, 2000, 2000
	tcb.HelperInitState(tcp.StateEstablished, issA, issA, windowA)
	tcb.HelperInitRcv(issB, issB, windowB)

	// Send out HTTP request and close connection.
	err := tcb.Send(tcp.Segment{SEQ: issA, ACK: issB, Flags: PSHACK, WND: windowA, DATALEN: httpLen})
	if err != nil {
		t.Fatal(err)
	}
	err = tcb.Close()
	if err != nil {
		t.Fatal(err)
	}
	assertState(tcp.StateEstablished)

	pending, ok := tcb.PendingSegment(0)
	if !ok {
		t.Fatal("expected pending segment")
	} else if pending.Flags != FINACK {
		t.Fatalf("expected FINACK; got %s", pending.Flags.String())
	}

	// Receive ACK of HTTP segment.
	err = tcb.Recv(tcp.Segment{SEQ: issB, ACK: issA + httpLen, Flags: tcp.FlagACK, WND: windowB})
	if err != nil {
		t.Fatal(err)
	}
	assertState(tcp.StateEstablished)
	err = tcb.Close()
	if err != nil {
		t.Fatal(err)
	}
	pending, ok = tcb.PendingSegment(0)
	if !ok {
		t.Fatal("expected pending segment")
	} else if pending.Flags != FINACK {
		t.Fatalf("expected FINACK; got %s", pending.Flags.String())
	}

	// Send out FINACK.
	err = tcb.Send(pending)
	if err != nil {
		t.Fatal(err)
	}
	assertState(tcp.StateFinWait1)
	pending, ok = tcb.PendingSegment(0)
	if ok {
		t.Fatal("expected no pending segment after finack")
	}

	// Receive FINACK response from client.
	err = tcb.Recv(tcp.Segment{SEQ: issB, ACK: issA + httpLen, Flags: FINACK, WND: windowB})
	if err != nil {
		t.Fatal(err)
	}
	assertState(tcp.StateClosing)
	pending, ok = tcb.PendingSegment(0)
	if !ok {
		t.Fatal("expected pending segment")
	} else if pending.Flags != tcp.FlagACK {
		t.Fatalf("expected ACK; got %s", pending.Flags.String())
	}

	// Before responding we receive an ACK from client. This is where panic is triggered.
	err = tcb.Recv(tcp.Segment{SEQ: issB + 1, ACK: issA + httpLen + 1, Flags: tcp.FlagACK, WND: windowB})
	if err != nil {
		t.Fatal(err)
	}
	assertState(tcp.StateTimeWait)

	// Check we still need to send an ACK.
	pending, ok = tcb.PendingSegment(0)
	if !ok {
		t.Fatal("expected pending segment")
	} else if pending.Flags != tcp.FlagACK {
		t.Fatalf("expected ACK; got %s", pending.Flags.String())
	}
	// Prepare response to client.
	err = tcb.Send(pending)
	if err != nil {
		t.Fatal(err)
	}
}

// TestPendingSegment_fastRetransmitOutstanding: a fast retransmit resends only data already sent,
// however much is asked for. Previously it took the payload length asked for, sending new data
// past SND.NXT as a retransmission.
func TestPendingSegment_fastRetransmitOutstanding(t *testing.T) {
	const issA, issB, windowA, windowB, inFlight = 100, 300, 1000, 1000, 10
	var tcb tcp.ControlBlock
	tcb.HelperInitState(tcp.StateEstablished, issA, issA, windowA)
	tcb.HelperInitRcv(issB, issB, windowB)
	if err := tcb.Send(tcp.Segment{SEQ: issA, ACK: issB, Flags: tcp.FlagACK, WND: windowA, DATALEN: inFlight}); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := tcb.Recv(tcp.Segment{SEQ: issB, ACK: issA, Flags: tcp.FlagACK, WND: windowB}); err != nil {
			t.Fatal(err)
		}
	}
	seg, ok := tcb.PendingSegment(100)
	want := tcp.Segment{SEQ: issA, ACK: issB, Flags: tcp.FlagACK, WND: windowA, DATALEN: inFlight}
	if !ok || seg != want {
		t.Fatalf("PendingSegment(100)=%+v, %v; want %+v", seg, ok, want)
	}
}

// TestRcvFinWait2 tests rcvFinWait2 behavior per RFC 9293 §3.10.7.4.
// In FIN-WAIT-2, the local side has sent FIN and received its ACK.
// The remote side has NOT closed yet and may still send data or ACKs.
// TestFinWait1_PartialACK_StaysInFinWait1 tests that receiving an ACK in FIN-WAIT-1
// that acknowledges data but NOT the FIN does not transition to FIN-WAIT-2.
// This is a regression test for a bug observed in monitor.log where lneto sent
// data followed by FIN, received a stale ACK covering only the data, and
// incorrectly entered FIN-WAIT-2. Per RFC 9293 §3.10.7.4 step 5, FIN-WAIT-2
// is entered only "if the FIN segment is now acknowledged."
func TestFinWait1_PartialACK_StaysInFinWait1(t *testing.T) {
	const windowA, windowB = 1024, 64240
	const issA, issB = 100, 300
	const dataLen = 192

	var tcb tcp.ControlBlock
	tcb.HelperInitState(tcp.StateEstablished, issA, issA, windowA)
	tcb.HelperInitRcv(issB, issB, windowB)

	// Send data segment (like MQTT publish).
	err := tcb.Send(tcp.Segment{SEQ: issA, ACK: issB, Flags: PSHACK, WND: windowA, DATALEN: dataLen})
	if err != nil {
		t.Fatal(err)
	}

	// Close connection — queues FIN.
	err = tcb.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Send the pending FIN|ACK.
	seg, ok := tcb.PendingSegment(0)
	if !ok {
		t.Fatal("expected pending FIN|ACK")
	}
	if !seg.Flags.HasAll(FINACK) {
		t.Fatalf("expected FIN|ACK; got %s", seg.Flags)
	}
	err = tcb.Send(seg)
	if err != nil {
		t.Fatal(err)
	}
	if tcb.State() != tcp.StateFinWait1 {
		t.Fatalf("expected FIN-WAIT-1; got %s", tcb.State())
	}
	// snd.NXT is now issA + dataLen + 1 (data + FIN).

	// Receive ACK that covers the data but NOT the FIN (seg.ack = issA + dataLen).
	// This is what the remote sends when it received the data but the FIN was lost.
	err = tcb.Recv(tcp.Segment{SEQ: issB, ACK: tcp.Value(issA + dataLen), Flags: tcp.FlagACK, WND: windowB})
	if err != nil {
		t.Fatal(err)
	}

	// Bug: old code transitions to FIN-WAIT-2 here.
	// Correct: must stay in FIN-WAIT-1 because FIN is not yet acknowledged.
	if tcb.State() != tcp.StateFinWait1 {
		t.Fatalf("expected FIN-WAIT-1 (FIN not yet ACKed); got %s", tcb.State())
	}

	// Now receive ACK that covers the FIN (seg.ack = issA + dataLen + 1).
	err = tcb.Recv(tcp.Segment{SEQ: issB, ACK: tcp.Value(issA + dataLen + 1), Flags: tcp.FlagACK, WND: windowB})
	if err != nil {
		t.Fatal(err)
	}
	if tcb.State() != tcp.StateFinWait2 {
		t.Fatalf("expected FIN-WAIT-2 (FIN now ACKed); got %s", tcb.State())
	}
}

// TestClose_PartialACKDoesNotAdvance verifies RFC 9293 §3.10.7.4: in LAST-ACK
// and CLOSING an ACK that covers earlier data but not our FIN must not advance
// the connection. Only an ACK of the FIN (seg.ACK == snd.NXT) closes LAST-ACK or
// moves CLOSING to TIME-WAIT.
func TestClose_PartialACKDoesNotAdvance(t *testing.T) {
	const issA, issB, windowA, windowB = 1, 127, 2000, 2000
	const dataLen = 1192

	t.Run("LAST-ACK", func(t *testing.T) {
		var tcb tcp.ControlBlock
		tcb.HelperInitState(tcp.StateEstablished, issA, issA, windowA)
		tcb.HelperInitRcv(issB, issB, windowB)
		tcb.HelperExchange(t, []tcp.Exchange{
			0: { // Local sends data.
				Outgoing:  &tcp.Segment{SEQ: issA, ACK: issB, Flags: PSHACK, WND: windowA, DATALEN: dataLen},
				WantState: tcp.StateEstablished,
			},
			1: { // Peer acknowledges the data.
				Incoming:  &tcp.Segment{SEQ: issB, ACK: issA + dataLen, Flags: tcp.FlagACK, WND: windowB},
				WantState: tcp.StateEstablished,
			},
			2: { // Peer sends FIN|ACK. Local enters CLOSE-WAIT.
				Incoming:    &tcp.Segment{SEQ: issB, ACK: issA + dataLen, Flags: FINACK, WND: windowB},
				WantPending: &tcp.Segment{SEQ: issA + dataLen, ACK: issB + 1, Flags: tcp.FlagACK, WND: windowA},
				WantState:   tcp.StateCloseWait,
			},
			3: { // Local closes and sends its FIN|ACK. snd.NXT = issA+dataLen+1.
				Outgoing:  &tcp.Segment{SEQ: issA + dataLen, ACK: issB + 1, Flags: FINACK, WND: windowA},
				WantState: tcp.StateLastAck,
			},
			4: { // Partial ACK acks data but not the FIN: must stay LAST-ACK.
				Incoming:  &tcp.Segment{SEQ: issB + 1, ACK: issA + dataLen, Flags: tcp.FlagACK, WND: windowB},
				WantState: tcp.StateLastAck,
			},
			5: { // ACK of the FIN closes the connection.
				Incoming:  &tcp.Segment{SEQ: issB + 1, ACK: issA + dataLen + 1, Flags: tcp.FlagACK, WND: windowB},
				WantState: tcp.StateClosed,
			},
		})
	})

	t.Run("CLOSING", func(t *testing.T) {
		var tcb tcp.ControlBlock
		tcb.HelperInitState(tcp.StateEstablished, issA, issA, windowA)
		tcb.HelperInitRcv(issB, issB, windowB)
		tcb.HelperExchange(t, []tcp.Exchange{
			0: { // Local sends data.
				Outgoing:  &tcp.Segment{SEQ: issA, ACK: issB, Flags: PSHACK, WND: windowA, DATALEN: dataLen},
				WantState: tcp.StateEstablished,
			},
			1: { // Local closes and sends FIN|ACK. snd.NXT = issA+dataLen+1.
				Outgoing:  &tcp.Segment{SEQ: issA + dataLen, ACK: issB, Flags: FINACK, WND: windowA},
				WantState: tcp.StateFinWait1,
			},
			2: { // Peer's FIN|ACK acks the data but not our FIN: simultaneous close.
				// The ACK owed to the peer is left pending to isolate the
				// receive-side transition being tested here.
				Incoming:    &tcp.Segment{SEQ: issB, ACK: issA + dataLen, Flags: FINACK, WND: windowB},
				WantPending: &tcp.Segment{SEQ: issA + dataLen + 1, ACK: issB + 1, Flags: tcp.FlagACK, WND: windowA},
				WantState:   tcp.StateClosing,
			},
			3: { // Duplicate ACK not covering our FIN: must stay CLOSING.
				Incoming:    &tcp.Segment{SEQ: issB + 1, ACK: issA + dataLen, Flags: tcp.FlagACK, WND: windowB},
				WantPending: &tcp.Segment{SEQ: issA + dataLen + 1, ACK: issB + 1, Flags: tcp.FlagACK, WND: windowA},
				WantState:   tcp.StateClosing,
			},
			4: { // ACK of our FIN moves to TIME-WAIT.
				Incoming:    &tcp.Segment{SEQ: issB + 1, ACK: issA + dataLen + 1, Flags: tcp.FlagACK, WND: windowB},
				WantPending: &tcp.Segment{SEQ: issA + dataLen + 1, ACK: issB + 1, Flags: tcp.FlagACK, WND: windowA},
				WantState:   tcp.StateTimeWait,
			},
		})
	})
}

// Linux probes a zero window with an empty ACK at RCV.NXT-1 (tcp_xmit_probe_skb). Each probe must be
// refused and acknowledged like an RFC probe; they drew challenge ACKs, which stop after maxChallengeRejects.
func TestExchangeTest_LinuxZeroWindowProbe(t *testing.T) {
	const issA, issB, windowB = 100, 300, 1000
	probe := tcp.Segment{SEQ: issB - 1, ACK: issA, Flags: tcp.FlagACK, WND: windowB}
	ack := tcp.Segment{SEQ: issA, ACK: issB, Flags: tcp.FlagACK}
	var steps []tcp.SegmentStep
	for range 20 {
		steps = append(steps,
			tcp.SegmentStep{Seg: probe, Action: tcp.StepBSends, AState: tcp.StateEstablished, APending: &ack, WantErr: tcp.ErrZeroWindow},
			tcp.SegmentStep{Seg: ack, Action: tcp.StepASends, AState: tcp.StateEstablished},
		)
	}
	test := tcp.ExchangeTest{
		ISSA:       issA,
		ISSB:       issB,
		WindowA:    0,
		WindowB:    windowB,
		InitStateA: tcp.StateEstablished,
		InitStateB: tcp.StateEstablished,
		Steps:      steps,
	}
	test.RunA(t)
}

// TestExchangeTest_ZeroWindowProbesDoNotAbort verifies that data at RCV.NXT
// against a zero receive window is refused and acknowledged without counting
// toward the challenge-ACK abort (RFC 9293 §3.10.7.4, RFC 1122 §4.2.2.17).
func TestExchangeTest_ZeroWindowProbesDoNotAbort(t *testing.T) {
	const issA, issB, windowB = 100, 300, 1000
	probe := tcp.Segment{SEQ: issB, ACK: issA, Flags: tcp.FlagACK, WND: windowB, DATALEN: 1}
	ack := tcp.Segment{SEQ: issA, ACK: issB, Flags: tcp.FlagACK}
	var steps []tcp.SegmentStep
	for range 20 {
		steps = append(steps,
			tcp.SegmentStep{Seg: probe, Action: tcp.StepBSends, AState: tcp.StateEstablished, APending: &ack, WantErr: tcp.ErrZeroWindow},
			tcp.SegmentStep{Seg: ack, Action: tcp.StepASends, AState: tcp.StateEstablished},
		)
	}
	test := tcp.ExchangeTest{
		ISSA:       issA,
		ISSB:       issB,
		WindowA:    0,
		WindowB:    windowB,
		InitStateA: tcp.StateEstablished,
		InitStateB: tcp.StateEstablished,
		Steps:      steps,
	}
	test.RunA(t)
}

// TestZeroWindowProbe verifies a one-octet probe is offered only when the peer's
// window is zero, nothing is outstanding and new data may be sent, that Send
// accepts it while rejecting more than one octet, and that it is offered once.
func TestZeroWindowProbe(t *testing.T) {
	const issA, issB, windowA = 100, 300, 1000
	for _, tc := range []struct {
		name      string
		state     tcp.State
		sndWND    tcp.Size
		inFlight  tcp.Size
		wantProbe bool
	}{
		{name: "closed-window", state: tcp.StateEstablished, wantProbe: true},
		{name: "close-wait", state: tcp.StateCloseWait, wantProbe: true},
		{name: "open-window", state: tcp.StateEstablished, sndWND: 10},
		{name: "data-outstanding", state: tcp.StateEstablished, inFlight: 1},
		{name: "fin-sent", state: tcp.StateFinWait1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var tcb tcp.ControlBlock
			tcb.HelperInitState(tc.state, issA, issA+tcp.Value(tc.inFlight), windowA)
			tcb.HelperInitRcv(issB, issB, tc.sndWND)
			probe, ok := tcb.ZeroWindowProbe()
			if ok != tc.wantProbe {
				t.Fatalf("probe offered=%v, want %v", ok, tc.wantProbe)
			} else if !ok {
				return
			}
			want := tcp.Segment{SEQ: issA, ACK: issB, WND: windowA, Flags: tcp.FlagACK, DATALEN: 1}
			if probe != want {
				t.Fatalf("probe=%+v, want %+v", probe, want)
			}
			twoOctets := probe
			twoOctets.DATALEN = 2
			if err := tcb.Send(twoOctets); err == nil {
				t.Fatal("zero window accepted two octets")
			}
			if err := tcb.Send(probe); err != nil {
				t.Fatal("probe rejected:", err)
			}
			if tcb.SendNext() != issA+1 {
				t.Fatalf("SND.NXT=%d, want %d", tcb.SendNext(), issA+1)
			}
			if _, ok := tcb.ZeroWindowProbe(); ok {
				t.Fatal("second probe offered while the first is outstanding")
			}
		})
	}
}

// TestSendRetransmitBounds verifies a segment starting below SND.NXT is sent as
// a retransmission only if it ends at or below SND.NXT. One reaching past it
// would put new data on the wire without advancing SND.NXT.
func TestSendRetransmitBounds(t *testing.T) {
	const issA, issB, windowA, sndWND = 100, 300, 1000, 1000
	const inFlight = 10
	for _, tc := range []struct {
		name    string
		seq     tcp.Value
		datalen tcp.Size
		wantErr bool
	}{
		{name: "all-outstanding", seq: issA, datalen: inFlight},
		{name: "tail-outstanding", seq: issA + 5, datalen: 5},
		{name: "past-snd-nxt", seq: issA + 5, datalen: 10, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var tcb tcp.ControlBlock
			tcb.HelperInitState(tcp.StateEstablished, issA, issA+inFlight, windowA)
			tcb.HelperInitRcv(issB, issB, sndWND)
			seg := tcp.Segment{SEQ: tc.seq, ACK: issB, WND: windowA, Flags: tcp.FlagACK, DATALEN: tc.datalen}
			if err := tcb.Send(seg); (err != nil) != tc.wantErr {
				t.Fatalf("Send(%+v) = %v, want error %v", seg, err, tc.wantErr)
			}
			if tcb.SendNext() != issA+inFlight {
				t.Fatalf("SND.NXT=%d, want %d", tcb.SendNext(), issA+inFlight)
			}
		})
	}
}

func TestRcvFinWait2(t *testing.T) {
	const windowA, windowB = 1000, 1000
	const issA, issB = 100, 300

	// enterFinWait2 returns a ControlBlock in FIN-WAIT-2 with no pending flags.
	// Simulates: A sent FIN|ACK, B acknowledged it, A drained pending ACK.
	enterFinWait2 := func(t *testing.T) tcp.ControlBlock {
		t.Helper()
		var tcb tcp.ControlBlock
		tcb.HelperInitState(tcp.StateEstablished, issA, issA, windowA)
		tcb.HelperInitRcv(issB, issB, windowB)
		if err := tcb.Close(); err != nil {
			t.Fatal(err)
		}
		seg, _ := tcb.PendingSegment(0)
		if err := tcb.Send(seg); err != nil {
			t.Fatal(err)
		}
		if err := tcb.Recv(tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: tcp.FlagACK, WND: windowB}); err != nil {
			t.Fatal(err)
		}
		if tcb.State() != tcp.StateFinWait2 {
			t.Fatalf("setup: want FIN-WAIT-2; got %s", tcb.State())
		}
		// Drain pending ACK left from rcvFinWait1 so subtests start clean.
		if seg, ok := tcb.PendingSegment(0); ok {
			if err := tcb.Send(seg); err != nil {
				t.Fatal(err)
			}
		}
		return tcb
	}

	// Bare ACK: no state change, no pending flags generated.
	t.Run("BareACK", func(t *testing.T) {
		tcb := enterFinWait2(t)
		err := tcb.Recv(tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: tcp.FlagACK, WND: windowB})
		if err != nil {
			t.Fatalf("bare ACK rejected: %v", err)
		}
		if tcb.State() != tcp.StateFinWait2 {
			t.Fatalf("want FIN-WAIT-2; got %s", tcb.State())
		}
		checkNoPending(t, &tcb)
	})

	// In-window data: ACK generated, RCV.NXT advanced by payload length.
	t.Run("InWindowData", func(t *testing.T) {
		tcb := enterFinWait2(t)
		rcvNxtBefore := tcb.RecvNext()
		const dataLen = 50
		err := tcb.Recv(tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: PSHACK, WND: windowB, DATALEN: dataLen})
		if err != nil {
			t.Fatalf("in-window data rejected: %v", err)
		}
		if tcb.State() != tcp.StateFinWait2 {
			t.Fatalf("want FIN-WAIT-2; got %s", tcb.State())
		}
		seg, ok := tcb.PendingSegment(0)
		if !ok {
			t.Fatal("expected ACK pending for received data")
		}
		if !seg.Flags.HasAll(tcp.FlagACK) {
			t.Fatalf("pending flags: want ACK; got %s", seg.Flags)
		}
		if seg.ACK != rcvNxtBefore+dataLen {
			t.Fatalf("pending ACK: want %d; got %d", rcvNxtBefore+dataLen, seg.ACK)
		}
		if tcb.RecvNext() != rcvNxtBefore+dataLen {
			t.Fatalf("RCV.NXT: want %d; got %d", rcvNxtBefore+dataLen, tcb.RecvNext())
		}
	})

	// FIN (without ACK): transition to TIME-WAIT, ACK generated, RCV.NXT advanced by 1.
	t.Run("FIN", func(t *testing.T) {
		tcb := enterFinWait2(t)
		rcvNxtBefore := tcb.RecvNext()
		// Bare FIN without ACK — tests that HasAny(FlagFIN) is used, not HasAll(finack).
		err := tcb.Recv(tcp.Segment{SEQ: issB, Flags: tcp.FlagFIN, WND: windowB})
		if err != nil {
			t.Fatalf("FIN rejected: %v", err)
		}
		if tcb.State() != tcp.StateTimeWait {
			t.Fatalf("want TIME-WAIT; got %s", tcb.State())
		}
		seg, ok := tcb.PendingSegment(0)
		if !ok {
			t.Fatal("expected ACK pending for FIN")
		}
		if !seg.Flags.HasAll(tcp.FlagACK) {
			t.Fatalf("pending flags: want ACK; got %s", seg.Flags)
		}
		if seg.ACK != rcvNxtBefore+1 {
			t.Fatalf("pending ACK: want %d; got %d", rcvNxtBefore+1, seg.ACK)
		}
		if tcb.RecvNext() != rcvNxtBefore+1 {
			t.Fatalf("RCV.NXT: want %d; got %d", rcvNxtBefore+1, tcb.RecvNext())
		}
	})
}

func TestZeroWindowACKProcessing(t *testing.T) {
	const issA, issB, windowB, inFlight = 100, 300, 1000, 10
	ack := tcp.Segment{SEQ: issA + inFlight, ACK: issB, Flags: tcp.FlagACK}
	for _, tc := range []struct {
		name    string
		dataLen tcp.Size
		wantUNA tcp.Value
		wantErr error
		pending *tcp.Segment
	}{
		{name: "acceptable-ACK", wantUNA: issA + inFlight},
		{name: "unacceptable-data-probe", dataLen: 1, wantUNA: issA, wantErr: tcp.ErrZeroWindow, pending: &ack},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var tcb tcp.ControlBlock
			tcb.HelperInitState(tcp.StateEstablished, issA, issA+inFlight, 0)
			tcb.HelperInitRcv(issB, issB, windowB)
			seg := tcp.Segment{SEQ: issB, ACK: issA + inFlight, Flags: tcp.FlagACK, WND: windowB, DATALEN: tc.dataLen}
			if err := tcb.Recv(seg); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Recv() = %v, want %v", err, tc.wantErr)
			}
			if tcb.SendUNA() != tc.wantUNA || tcb.State() != tcp.StateEstablished || tcb.RecvNext() != issB {
				t.Fatalf("UNA=%d state=%s RCV.NXT=%d; want %d ESTABLISHED %d", tcb.SendUNA(), tcb.State(), tcb.RecvNext(), tc.wantUNA, issB)
			}
			pending, ok := tcb.PendingSegment(0)
			if ok != (tc.pending != nil) || (tc.pending != nil && pending != *tc.pending) {
				t.Fatalf("pending=%v present=%v; want %v", pending, ok, tc.pending)
			}
		})
	}
}

func FuzzTCBActions(f *testing.F) {
	const mtu = 2048
	const (
		actionRecv = iota
		actionSend
		actionClose
		actionMax
	)
	f.Add(
		int64(0x2313_2313),
		[]byte{actionSend, actionRecv, actionSend, actionRecv, actionSend, actionRecv},
	)
	f.Add(
		int64(0x2fefe_feefe),
		[]byte{actionSend, actionRecv, actionSend, actionClose, actionSend, actionRecv},
	)
	f.Add(
		int64(0x2fefe_feefe),
		[]byte{actionClose, actionRecv, actionSend, actionClose, actionSend, actionRecv},
	)
	recvsendSize := func(rng *rand.Rand) int {
		return rng.Int() % mtu
	}
	f.Fuzz(func(t *testing.T, seed int64, actions []byte) {
		if len(actions) == 0 || len(actions) > 100 {
			t.SkipNow()
		}
		rng := rand.New(rand.NewSource(seed))
		var clientISS tcp.Value = tcp.Value(rng.Int31())
		var serverISS tcp.Value = tcp.Value(rng.Int31())

		var client tcp.ControlBlock
		client.HelperInitState(tcp.StateEstablished, clientISS, clientISS, mtu)
		client.HelperInitRcv(serverISS, serverISS, mtu)

		var server tcp.ControlBlock
		server.HelperInitState(tcp.StateEstablished, serverISS, serverISS, mtu)
		server.HelperInitRcv(clientISS, clientISS, mtu)
		var closeCalled bool
		// logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		// 	Level: slog.LevelDebug - 2,
		// }))
		// client.SetLogger(logger.WithGroup("client"))
		// server.SetLogger(logger.WithGroup("server"))
		// var exchanges []tcp.Exchange
		// hasPanicked := true
		// defer func() {
		// 	if hasPanicked {
		// 		for _, ex := range exchanges {
		// 			t.Log(ex.RFC9293String(tcp.StateEstablished, tcp.StateEstablished))
		// 		}
		// 	}
		// }()
		for _, action := range actions {
			v := recvsendSize(rng)
			switch action % actionMax {
			case actionSend:
				seg, ok := client.PendingSegment(v % mtu)
				if ok {
					// exchanges = append(exchanges, tcp.Exchange{Outgoing: &seg})
					err := client.Send(seg)
					if err != nil {
						panic(err)
					}
					err = server.Recv(seg)
					if err != nil {
						panic(err)
					}
				}
			case actionRecv:
				seg, ok := server.PendingSegment(v % mtu)
				if ok {
					// exchanges = append(exchanges, tcp.Exchange{Incoming: &seg})
					err := server.Send(seg)
					if err != nil {
						panic(err)
					}
					err = client.Recv(seg)
					if err != nil && !closeCalled {
						panic(err)
					}
				}
			case actionClose:
				err := client.Close()
				if err != nil && !closeCalled {
					panic(err)
				}
				closeCalled = true
				return
			}
		}
		// hasPanicked = false
	})
}

func TestFlagsString(t *testing.T) {
	tests := []struct {
		flags tcp.Flags
		want  string
	}{
		{flags: 0, want: "[]"},
		{flags: tcp.FlagSYN, want: "[SYN]"},
		{flags: tcp.FlagACK, want: "[ACK]"},
		{flags: tcp.FlagFIN, want: "[FIN]"},
		{flags: tcp.FlagRST, want: "[RST]"},
		{flags: tcp.FlagSYN | tcp.FlagACK, want: "[SYN,ACK]"},
		{flags: tcp.FlagFIN | tcp.FlagACK, want: "[FIN,ACK]"},
		{flags: tcp.FlagPSH | tcp.FlagACK, want: "[PSH,ACK]"},
		// Multi-flag combinations.
		{flags: tcp.FlagFIN | tcp.FlagSYN | tcp.FlagACK, want: "[FIN,SYN,ACK]"},
		{flags: tcp.FlagURG | tcp.FlagACK, want: "[ACK,URG]"},
		{flags: tcp.FlagECE | tcp.FlagCWR, want: "[ECE,CWR]"},
		{flags: tcp.FlagNS | tcp.FlagACK, want: "[ACK,NS ]"},
		// All flags set.
		{flags: tcp.FlagFIN | tcp.FlagSYN | tcp.FlagRST | tcp.FlagPSH | tcp.FlagACK | tcp.FlagURG | tcp.FlagECE | tcp.FlagCWR | tcp.FlagNS, want: "[FIN,SYN,RST,PSH,ACK,URG,ECE,CWR,NS ]"},
		// Invalid flags (bits above mask).
		{flags: 0xFFFF, want: "<invalid TCP flags>"},
	}
	for _, tc := range tests {
		got := tc.flags.String()
		if got != tc.want {
			t.Errorf("Flags(%#x).String() = %q; want %q", uint16(tc.flags), got, tc.want)
		}
	}
}

func TestFlagsAppendFormat(t *testing.T) {
	tests := []struct {
		flags tcp.Flags
		want  string
	}{
		{flags: 0, want: ""},
		{flags: tcp.FlagSYN, want: "SYN"},
		{flags: tcp.FlagACK, want: "ACK"},
		{flags: tcp.FlagFIN, want: "FIN"},
		{flags: tcp.FlagRST, want: "RST"},
		{flags: tcp.FlagSYN | tcp.FlagACK, want: "SYN,ACK"},
		{flags: tcp.FlagFIN | tcp.FlagACK, want: "FIN,ACK"},
		{flags: tcp.FlagPSH | tcp.FlagACK, want: "PSH,ACK"},
		{flags: tcp.FlagFIN | tcp.FlagSYN | tcp.FlagACK, want: "FIN,SYN,ACK"},
		{flags: tcp.FlagURG | tcp.FlagACK, want: "ACK,URG"},
		{flags: tcp.FlagECE | tcp.FlagCWR, want: "ECE,CWR"},
		{flags: tcp.FlagNS | tcp.FlagACK, want: "ACK,NS "},
		{flags: tcp.FlagFIN | tcp.FlagSYN | tcp.FlagRST | tcp.FlagPSH | tcp.FlagACK | tcp.FlagURG | tcp.FlagECE | tcp.FlagCWR | tcp.FlagNS, want: "FIN,SYN,RST,PSH,ACK,URG,ECE,CWR,NS "},
		{flags: 0xFFFF, want: "<invalid TCP flags>"},
	}
	for _, tc := range tests {
		got := string(tc.flags.AppendFormat(nil))
		if got != tc.want {
			t.Errorf("Flags(%#x).AppendFormat(nil) = %q; want %q", uint16(tc.flags), got, tc.want)
		}
	}

	// Test that AppendFormat appends to existing data.
	prefix := []byte("flags=")
	got := string(SYNACK.AppendFormat(prefix))
	if want := "flags=SYN,ACK"; got != want {
		t.Errorf("AppendFormat with prefix = %q; want %q", got, want)
	}
}

func TestFlagsStringAppendFormatConsistency(t *testing.T) {
	// Verify String() and AppendFormat() produce consistent results
	// for all single-flag and common multi-flag values.
	allFlags := []tcp.Flags{
		0,
		tcp.FlagFIN, tcp.FlagSYN, tcp.FlagRST, tcp.FlagPSH,
		tcp.FlagACK, tcp.FlagURG, tcp.FlagECE, tcp.FlagCWR, tcp.FlagNS,
		SYNACK, FINACK, PSHACK,
		tcp.FlagFIN | tcp.FlagSYN | tcp.FlagRST | tcp.FlagPSH | tcp.FlagACK | tcp.FlagURG | tcp.FlagECE | tcp.FlagCWR | tcp.FlagNS,
	}
	for _, flags := range allFlags {
		str := flags.String()
		appended := string(flags.AppendFormat(nil))
		// String() wraps in brackets, AppendFormat() does not.
		if flags == 0 {
			if str != "[]" {
				t.Errorf("Flags(0).String() = %q; want %q", str, "[]")
			}
			if appended != "" {
				t.Errorf("Flags(0).AppendFormat() = %q; want empty", appended)
			}
			continue
		}
		wantStr := "[" + appended + "]"
		if str != wantStr {
			t.Errorf("Flags(%#x): String()=%q inconsistent with AppendFormat()=%q (want %q)", uint16(flags), str, appended, wantStr)
		}
	}
}

/*
	 Section 3.5 of RFC 9293: Basic 3-way handshake for connection synchronization.
		TCP Peer A                                           TCP Peer B

		1.  CLOSED                                               LISTEN

		2.  SYN-SENT    --> <SEQ=100><CTL=SYN>               --> SYN-RECEIVED

		3.  ESTABLISHED <-- <SEQ=300><ACK=101><CTL=SYN,ACK>  <-- SYN-RECEIVED

		4.  ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK>       --> ESTABLISHED

		5.  ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK><DATA> --> ESTABLISHED
*/

/*
	 Section 3.5 of RFC 9293: Simultaneous Connection Synchronization (SYN).
		TCP Peer A                                       TCP Peer B

		1.  CLOSED                                           CLOSED

		2.  SYN-SENT     --> <SEQ=100><CTL=SYN>              ...

		3.  SYN-RECEIVED <-- <SEQ=300><CTL=SYN>              <-- SYN-SENT

		4.               ... <SEQ=100><CTL=SYN>              --> SYN-RECEIVED

		5.  SYN-RECEIVED --> <SEQ=100><ACK=301><CTL=SYN,ACK> ...

		6.  ESTABLISHED  <-- <SEQ=300><ACK=101><CTL=SYN,ACK> <-- SYN-RECEIVED

		7.               ... <SEQ=100><ACK=301><CTL=SYN,ACK> --> ESTABLISHED
*/
/*
	 Recovery from Old Duplicate SYN
		TCP Peer A                                           TCP Peer B

		1.  CLOSED                                               LISTEN

		2.  SYN-SENT    --> <SEQ=100><CTL=SYN>               ...

		3.  (duplicate) ... <SEQ=90><CTL=SYN>               --> SYN-RECEIVED

		4.  SYN-SENT    <-- <SEQ=300><ACK=91><CTL=SYN,ACK>  <-- SYN-RECEIVED

		5.  SYN-SENT    --> <SEQ=91><CTL=RST>               --> LISTEN

		6.              ... <SEQ=100><CTL=SYN>               --> SYN-RECEIVED

		7.  ESTABLISHED <-- <SEQ=400><ACK=101><CTL=SYN,ACK>  <-- SYN-RECEIVED

		8.  ESTABLISHED --> <SEQ=101><ACK=401><CTL=ACK>      --> ESTABLISHED
*/
/*
		Figure 12: Normal Close Sequence
	    TCP Peer A                                           TCP Peer B
		1.  ESTABLISHED                                          ESTABLISHED

		2.  (Close)
			FIN-WAIT-1  --> <SEQ=100><ACK=300><CTL=FIN,ACK>  --> CLOSE-WAIT

		3.  FIN-WAIT-2  <-- <SEQ=300><ACK=101><CTL=ACK>      <-- CLOSE-WAIT

		4.                                                       (Close)
			TIME-WAIT   <-- <SEQ=300><ACK=101><CTL=FIN,ACK>  <-- LAST-ACK

		5.  TIME-WAIT   --> <SEQ=101><ACK=301><CTL=ACK>      --> CLOSED

		6.  (2 MSL)
			CLOSED
*/
/*
Figure 12: Normal Close Sequence from Peer B (passive close) perspective.

	TCP Peer A                                           TCP Peer B

	1.  ESTABLISHED                                          ESTABLISHED

	2.  (Close)
	    FIN-WAIT-1  --> <SEQ=100><ACK=300><CTL=FIN,ACK>  --> CLOSE-WAIT

	3.  FIN-WAIT-2  <-- <SEQ=300><ACK=101><CTL=ACK>      <-- CLOSE-WAIT

	4.                                                       (Close)
	    TIME-WAIT   <-- <SEQ=300><ACK=101><CTL=FIN,ACK>  <-- LAST-ACK

	5.  TIME-WAIT   --> <SEQ=101><ACK=301><CTL=ACK>      --> CLOSED

This test validates the passive close (B side) behavior where B receives
a FIN from A, acknowledges it, then later closes and sends its own FIN.
*/
/*
	 Figure 12: Simultaneous Close Sequence
			TCP Peer A                                           TCP Peer B

		1.  ESTABLISHED                                          ESTABLISHED

		2.  (Close)                                              (Close)
			FIN-WAIT-1  --> <SEQ=100><ACK=300><CTL=FIN,ACK>  ... FIN-WAIT-1
						<-- <SEQ=300><ACK=100><CTL=FIN,ACK>  <--
						... <SEQ=100><ACK=300><CTL=FIN,ACK>  -->

		3.  CLOSING     --> <SEQ=101><ACK=301><CTL=ACK>      ... CLOSING
						<-- <SEQ=301><ACK=101><CTL=ACK>      <--
						... <SEQ=101><ACK=301><CTL=ACK>      -->

		4.  TIME-WAIT                                            TIME-WAIT
			(2 MSL)                                              (2 MSL)
			CLOSED                                               CLOSED
*/
// Check no duplicate ack is sent during establishment.
func TestExchange_noDupAckDuringEstablished(t *testing.T) {
	var tcbA tcp.ControlBlock
	const issA, issB, windowA, windowB = 300, 334222749, 256, 64240
	synseg := tcp.ClientSynSegment(issA, windowA)

	// err := tcbA.Open(issA, issA, tcp.StateSynSent)
	tcbA.SetRecvWindow(windowA)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	establishA := []tcp.Exchange{
		0: { // A sends SYN to B.
			Outgoing:  &synseg,
			WantState: tcp.StateSynSent,
		},
		1: { // B sends SYN to A.
			Incoming:    &tcp.Segment{SEQ: issB, ACK: 0, WND: windowB, Flags: tcp.FlagSYN},
			WantPending: &tcp.Segment{SEQ: issA, ACK: issB + 1, WND: windowA, Flags: SYNACK},
			WantState:   tcp.StateSynRcvd,
		},
		2: { // Send SYNACK to B.
			Outgoing:  &tcp.Segment{SEQ: issA, ACK: issB + 1, WND: windowA, Flags: SYNACK},
			WantState: tcp.StateSynRcvd,
		},
		3: { // B ACKs SYNACK, thus establishing the connection on both sides.
			Incoming:  &tcp.Segment{SEQ: issB + 1, ACK: issA + 1, WND: windowB, Flags: tcp.FlagACK},
			WantState: tcp.StateEstablished,
		},
	}
	tcbA.HelperExchange(t, establishA)
	if tcbA.State() != tcp.StateEstablished {
		t.Fatal("expected established state")
	}
	checkNoPending(t, &tcbA)
	const datasize = 5
	dataExA := []tcp.Exchange{
		0: { // B sends PSH|ACK to A with data.
			Incoming:    &tcp.Segment{SEQ: issB + 1, ACK: issA + 1, WND: windowB, Flags: PSHACK, DATALEN: datasize},
			WantPending: &tcp.Segment{SEQ: issA + 1, ACK: issB + 1 + datasize, WND: windowA, Flags: tcp.FlagACK},
			WantState:   tcp.StateEstablished,
		},
		1: { // A ACKs B's data.
			Outgoing:  &tcp.Segment{SEQ: issA + 1, ACK: issB + 1 + datasize, WND: windowA, Flags: tcp.FlagACK},
			WantState: tcp.StateEstablished,
		},
		2: { // A sends PSH|ACK to B with data, same amount, as if echoing.
			Outgoing:  &tcp.Segment{SEQ: issA + 1, ACK: issB + 1 + datasize, WND: windowA, Flags: PSHACK, DATALEN: datasize},
			WantState: tcp.StateEstablished,
		},
		// 3: { // B ACKs A's data.
		// 	Incoming:    &tcp.Segment{SEQ: issB + 1 + datasize, ACK: issA + 1 + datasize, WND: windowB, Flags: tcp.FlagACK},
		// 	WantPending: nil,
		// 	WantState:   tcp.StateEstablished,
		// },
	}
	tcbA.HelperExchange(t, dataExA)
	checkNoPending(t, &tcbA)
	tcbA.Recv(tcp.Segment{SEQ: issB + 1 + datasize, ACK: issA + 1 + datasize, WND: windowB, Flags: tcp.FlagACK})
	checkNoPending(t, &tcbA)
}

// This test reenacts a full client-server interaction in the sending and receiving
// of the 12 byte message "hello world\n" over TCP.
func TestExchange_helloworld(t *testing.T) {
	// Client Transmission Control Block.
	var tcbA tcp.ControlBlock
	const windowA, windowB = 502, 4096
	const issA, issB = 0x5e722b7d, 0xbe6e4c0f
	const datalen = 12

	exchangeA := []tcp.Exchange{
		0: { // A sends SYN to B.
			Outgoing:      &tcp.Segment{SEQ: issA, Flags: tcp.FlagSYN, WND: windowA},
			WantState:     tcp.StateSynSent,
			WantPeerState: tcp.StateSynRcvd,
		},
		1: { // A receives SYNACK from B.
			Incoming:      &tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: SYNACK, WND: windowB},
			WantState:     tcp.StateEstablished,
			WantPending:   &tcp.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: tcp.FlagACK, WND: windowA},
			WantPeerState: tcp.StateSynRcvd,
		},
		2: { // A sends ACK to B thus establishing connection.
			Outgoing:      &tcp.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: tcp.FlagACK, WND: windowA},
			WantState:     tcp.StateEstablished,
			WantPeerState: tcp.StateEstablished,
		},
		3: { // A sends PSH|ACK to B with 12 byte message: "hello world\n"
			Outgoing:      &tcp.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: PSHACK, WND: windowA, DATALEN: datalen},
			WantState:     tcp.StateEstablished,
			WantPeerState: tcp.StateEstablished,
		},
		4: { // A receives ACK from B of last message.
			Incoming:      &tcp.Segment{SEQ: issB + 1, ACK: issA + 1 + datalen, Flags: tcp.FlagACK, WND: windowB},
			WantState:     tcp.StateEstablished,
			WantPeerState: tcp.StateEstablished,
		},
		5: { // A receives PSH|ACK from B with echoed 12 byte message: "hello world\n"
			Incoming:      &tcp.Segment{SEQ: issB + 1, ACK: issA + 1 + datalen, Flags: PSHACK, WND: windowB, DATALEN: datalen},
			WantState:     tcp.StateEstablished,
			WantPending:   &tcp.Segment{SEQ: issA + 1 + datalen, ACK: issB + 1 + datalen, Flags: tcp.FlagACK, WND: windowA},
			WantPeerState: tcp.StateEstablished,
		},
		6: { // A ACKs B's message.
			Outgoing:      &tcp.Segment{SEQ: issA + 1 + datalen, ACK: issB + 1 + datalen, Flags: tcp.FlagACK, WND: windowA},
			WantState:     tcp.StateEstablished,
			WantPeerState: tcp.StateEstablished,
		},
		7: { // A sends PSH|ACK to B with SECOND 12 byte message.
			Outgoing:      &tcp.Segment{SEQ: issA + 1 + datalen, ACK: issB + 1 + datalen, Flags: PSHACK, WND: windowA, DATALEN: datalen},
			WantState:     tcp.StateEstablished,
			WantPeerState: tcp.StateEstablished,
		},
		8: { // A receives PSH|ACK that acks last message and contains echoed of SECOND 12 byte message.
			Incoming:      &tcp.Segment{SEQ: issB + 1 + datalen, ACK: issA + 1 + 2*datalen, Flags: PSHACK, WND: windowB, DATALEN: datalen},
			WantState:     tcp.StateEstablished,
			WantPending:   &tcp.Segment{SEQ: issA + 1 + 2*datalen, ACK: issB + 1 + 2*datalen, Flags: tcp.FlagACK, WND: windowA},
			WantPeerState: tcp.StateEstablished,
		},
		9: { // A ACKs B's SECOND message.
			Outgoing:      &tcp.Segment{SEQ: issA + 1 + 2*datalen, ACK: issB + 1 + 2*datalen, Flags: tcp.FlagACK, WND: windowA},
			WantState:     tcp.StateEstablished,
			WantPeerState: tcp.StateEstablished,
		},
		10: { // A sends FIN|ACK to B to close connection.
			Outgoing:      &tcp.Segment{SEQ: issA + 1 + 2*datalen, ACK: issB + 1 + 2*datalen, Flags: FINACK, WND: windowA},
			WantState:     tcp.StateFinWait1,
			WantPeerState: tcp.StateCloseWait,
		},
		11: { // A receives B's ACK of FIN.
			Incoming:      &tcp.Segment{SEQ: issB + 1 + 2*datalen, ACK: issA + 2 + 2*datalen, Flags: tcp.FlagACK, WND: windowB},
			WantState:     tcp.StateFinWait2,
			WantPending:   nil, // Bare ACK must not elicit ACK (same as Figure 12 fix).
			WantPeerState: tcp.StateCloseWait,
		},
	}
	// The client starts in the SYN_SENT state with a random sequence number.
	gotServerSeg, _ := parseSegment(t, exchangeHelloWorld[0])
	tcbA.HelperInitState(tcp.StateSynSent, gotServerSeg.SEQ, gotServerSeg.SEQ, windowB)
	tcbA.HelperExchange(t, exchangeA)
}

func parseSegment(t *testing.T, b []byte) (tcp.Segment, []byte) {
	var vld lneto.Validator
	t.Helper()
	efrm, err := ethernet.NewFrame(b)
	if err != nil {
		t.Fatal(err)
	}
	if efrm.EtherTypeOrSize() != ethernet.TypeIPv4 {
		t.Fatalf("not IPv4")
	}
	efrm.ValidateSize(&vld)
	if err := vld.ErrPop(); err != nil {
		t.Fatal(vld.ErrPop())
	}
	ifrm, err := ipv4.NewFrame(efrm.Payload())
	if err != nil {
		t.Fatal(err)
	}
	if ifrm.Protocol() != 6 {
		t.Fatalf("not TCP")
	}
	v, _ := ifrm.VersionAndIHL()
	if v != 4 {
		t.Fatal("invalid IP version", v)
	}
	ifrm.ValidateSize(&vld)
	if err := vld.ErrPop(); err != nil {
		t.Fatal(vld.ErrPop())
	}

	ipl := ifrm.Payload()
	tfrm, err := tcp.NewFrame(ipl)
	if err != nil {
		t.Fatal(err)
	}
	tfrm.ValidateSize(&vld)
	if err := vld.ErrPop(); err != nil {
		t.Fatal(err)
	}
	_ = tfrm.String()
	payload := tfrm.Payload()
	return tfrm.Segment(len(payload)), payload
}

func TestUnexpectedStateClosing(t *testing.T) {
	// TCB is a server which returns an HTTP response and receives a FINACK.
	var tcb tcp.ControlBlock
	const httpLen = 1192
	const issA, issB, windowA, windowB = 1, 127, 2000, 2000
	tcb.HelperInitState(tcp.StateEstablished, issA, issA, windowA)
	tcb.HelperInitRcv(issB, issB, windowB)

	ex := []tcp.Exchange{
		0: { // Server sends HTTP response.
			Outgoing:  &tcp.Segment{SEQ: issA, ACK: issB, Flags: PSHACK, WND: windowA, DATALEN: httpLen},
			WantState: tcp.StateEstablished,
		},
		1: { // Client sends an ACK to server.
			Incoming:  &tcp.Segment{SEQ: issB, ACK: issA + httpLen, Flags: tcp.FlagACK, WND: windowB},
			WantState: tcp.StateEstablished,
		},
		2: { //  Client sends FIN|ACK to server.
			Incoming:    &tcp.Segment{SEQ: issB, ACK: issA + httpLen, Flags: FINACK, WND: windowB},
			WantPending: &tcp.Segment{SEQ: issA + httpLen, ACK: issB + 1, Flags: tcp.FlagACK, WND: windowA},
			WantState:   tcp.StateCloseWait,
		},
		3: { // Server sends out FINACK.
			Outgoing:  &tcp.Segment{SEQ: issA + httpLen, ACK: issB + 1, Flags: FINACK, WND: windowA},
			WantState: tcp.StateLastAck,
		},
		4: { // Client sends back ACK.
			Incoming:  &tcp.Segment{SEQ: issB + 1, ACK: issA + httpLen + 1, Flags: tcp.FlagACK, WND: windowB},
			WantState: tcp.StateClosed,
		},
	}
	tcb.HelperExchange(t, ex[:])
}

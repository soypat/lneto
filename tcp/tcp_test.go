package tcp_test

import (
	"math/rand"
	"testing"

	"github.com/soypat/lneto/tcp"
)

const (
	SYNACK = tcp.FlagSYN | tcp.FlagACK
	FINACK = tcp.FlagFIN | tcp.FlagACK
	PSHACK = tcp.FlagPSH | tcp.FlagACK
)

// TestExchangeTest_PassiveClose_FINACKRegression is a regression test for the bug where
// Close() in CLOSE-WAIT state set pending = [FlagFIN, FlagACK] (separate slots) instead
// of pending = [FlagFIN|FlagACK, 0]. This caused PendingSegment() to return only FIN
// without ACK since it only reads pending[0].
func TestExchangeTest_PassiveClose_FINACKRegression(t *testing.T) {
	const issA, issB, windowA, windowB = 100, 300, 1000, 1000
	test := tcp.ExchangeTest{
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
			1: { // B sends ACK to A. Auto-queues FIN|ACK in CLOSE-WAIT.
				Seg:      tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: tcp.FlagACK, WND: windowB},
				Action:   tcp.StepBSends,
				AState:   tcp.StateFinWait2,
				BState:   tcp.StateCloseWait,
				BPending: &tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: FINACK, WND: windowB},
			},
			2: { // B calls Close(). Goes to LAST-ACK. Pending must be FIN|ACK combined.
				// This is the regression check: Close() must NOT overwrite the auto-queued
				// FIN|ACK with [FlagFIN, FlagACK] in separate pending slots.
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
	}
	test.RunB(t) // Only run B's perspective since that's where Close() is called.
}

// TestExchangeTest_figure12 demonstrates ExchangeTest which defines both peers' states
// symmetrically and runs tests from both perspectives with a single definition.
func TestExchangeTest_figure12(t *testing.T) {
	const issA, issB, windowA, windowB = 100, 300, 1000, 1000
	test := tcp.ExchangeTest{
		ISSA:       issA,
		ISSB:       issB,
		WindowA:    windowA,
		WindowB:    windowB,
		InitStateA: tcp.StateEstablished,
		InitStateB: tcp.StateEstablished,
		Steps: []tcp.SegmentStep{
			0: { // A sends FIN|ACK to B.
				Seg:      tcp.Segment{SEQ: issA, ACK: issB, Flags: FINACK, WND: windowA},
				Action:   tcp.StepASends,
				AState:   tcp.StateFinWait1,
				BState:   tcp.StateCloseWait,
				APending: nil,
				BPending: &tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: tcp.FlagACK, WND: windowB},
			},
			1: { // B sends ACK to A. (Auto-queues FIN|ACK in CLOSE-WAIT)
				Seg:      tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: tcp.FlagACK, WND: windowB},
				Action:   tcp.StepBSends,
				AState:   tcp.StateFinWait2,
				BState:   tcp.StateCloseWait,
				APending: &tcp.Segment{SEQ: issA + 1, ACK: issB, Flags: tcp.FlagACK, WND: windowA}, // TODO: should be nil?
				BPending: &tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: FINACK, WND: windowB},
			},
			2: { // B sends FIN|ACK to A.
				Seg:      tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: FINACK, WND: windowB},
				Action:   tcp.StepBSends,
				AState:   tcp.StateTimeWait,
				BState:   tcp.StateLastAck,
				APending: &tcp.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: tcp.FlagACK, WND: windowA},
				BPending: nil,
			},
			3: { // A sends final ACK to B.
				Seg:      tcp.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: tcp.FlagACK, WND: windowA},
				Action:   tcp.StepASends,
				AState:   tcp.StateTimeWait,
				BState:   tcp.StateClosed,
				APending: nil,
				BPending: nil,
			},
		},
	}
	test.Run(t) // Runs both PeerA and PeerB subtests.
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
func TestExchangeTest_rfc9293_figure6(t *testing.T) {
	const issA, issB, windowA, windowB = 100, 300, 1000, 1000
	test := tcp.ExchangeTest{
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
	}
	test.Run(t)
}

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
func TestExchangeTest_rfc9293_figure7(t *testing.T) {
	const issA, issB, windowA, windowB = 100, 300, 1000, 1000
	// NOTE: Simultaneous SYN can only be tested from one perspective because
	// the "simultaneous" nature means segments cross in flight. In a sequential
	// test, when B receives A's SYN first, B goes to SYN-RECEIVED, not SYN-SENT.
	test := tcp.ExchangeTest{
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
	}
	test.RunA(t) // Only A's perspective - B's is fundamentally different in sequential test.
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
func TestExchangeTest_rfc9293_figure13(t *testing.T) {
	const issA, issB, windowA, windowB = 100, 300, 1000, 1000
	// NOTE: Simultaneous close can only be tested from one perspective because
	// the "simultaneous" nature means FINs cross in flight. In a sequential test,
	// when B receives A's FIN first, B goes to CLOSE-WAIT, not CLOSING.
	test := tcp.ExchangeTest{
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
			2: { // A sends ACK to B.
				Seg:    tcp.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: tcp.FlagACK, WND: windowA},
				Action: tcp.StepASends,
				AState: tcp.StateTimeWait,
			},
		},
	}
	test.RunA(t) // Only A's perspective - B's is fundamentally different in sequential test.
}

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

// TestRcvFinWait2_BareACK reproduces the bug where rcvFinWait2 rejects any segment
// without both FIN and ACK flags. Per RFC 9293 §3.10.7.4, FIN-WAIT-2 should:
//   - Silently accept bare ACKs (duplicate ACKs, window updates)
//   - Accept incoming data (remote hasn't sent FIN yet)
//   - Transition to TIME-WAIT only when FIN is received
//
// The overly strict check causes connections to get stuck in FIN-WAIT-2 until timeout,
// exhausting the connection pool when multiple clients are affected.
func TestRcvFinWait2_BareACK(t *testing.T) {
	var tcb tcp.ControlBlock
	const windowA, windowB = 1000, 1000
	const issA, issB = 100, 300
	tcb.HelperInitState(tcp.StateEstablished, issA, issA, windowA)
	tcb.HelperInitRcv(issB, issB, windowB)
	assertState := func(want tcp.State) {
		t.Helper()
		if tcb.State() != want {
			t.Fatalf("want state %s; got %s", want, tcb.State())
		}
	}

	// A initiates close → sends FIN|ACK.
	err := tcb.Close()
	if err != nil {
		t.Fatal(err)
	}
	seg, ok := tcb.PendingSegment(0)
	if !ok || !seg.Flags.HasAll(FINACK) {
		t.Fatalf("expected FIN|ACK pending; got %+v (ok=%v)", seg, ok)
	}
	err = tcb.Send(seg)
	if err != nil {
		t.Fatal(err)
	}
	assertState(tcp.StateFinWait1)

	// A receives ACK for its FIN → FIN-WAIT-2.
	err = tcb.Recv(tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: tcp.FlagACK, WND: windowB})
	if err != nil {
		t.Fatal(err)
	}
	assertState(tcp.StateFinWait2)

	// A receives bare ACK (duplicate/window update) in FIN-WAIT-2.
	// RFC 9293: this should be silently accepted, NOT rejected.
	err = tcb.Recv(tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: tcp.FlagACK, WND: windowB})
	if err != nil {
		t.Fatalf("bare ACK in FIN-WAIT-2 rejected: %v", err)
	}
	assertState(tcp.StateFinWait2)

	// A receives FIN|ACK → TIME-WAIT.
	err = tcb.Recv(tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: FINACK, WND: windowB})
	if err != nil {
		t.Fatal(err)
	}
	assertState(tcp.StateTimeWait)
}

// TestRcvFinWait2_DataFromRemote tests that data segments are accepted in FIN-WAIT-2.
// The remote side has not sent FIN yet and may still send data per RFC 9293 §3.10.7.4.
func TestRcvFinWait2_DataFromRemote(t *testing.T) {
	var tcb tcp.ControlBlock
	const windowA, windowB = 1000, 1000
	const issA, issB = 100, 300
	tcb.HelperInitState(tcp.StateEstablished, issA, issA, windowA)
	tcb.HelperInitRcv(issB, issB, windowB)

	// A sends FIN|ACK → FIN-WAIT-1.
	err := tcb.Close()
	if err != nil {
		t.Fatal(err)
	}
	seg, _ := tcb.PendingSegment(0)
	err = tcb.Send(seg)
	if err != nil {
		t.Fatal(err)
	}

	// A receives ACK → FIN-WAIT-2.
	err = tcb.Recv(tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: tcp.FlagACK, WND: windowB})
	if err != nil {
		t.Fatal(err)
	}
	if tcb.State() != tcp.StateFinWait2 {
		t.Fatalf("want FIN-WAIT-2; got %s", tcb.State())
	}

	// A receives data from remote (remote hasn't closed yet).
	const dataLen = 50
	err = tcb.Recv(tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: PSHACK, WND: windowB, DATALEN: dataLen})
	if err != nil {
		t.Fatalf("data in FIN-WAIT-2 rejected: %v", err)
	}
	if tcb.State() != tcp.StateFinWait2 {
		t.Fatalf("want FIN-WAIT-2 after data; got %s", tcb.State())
	}

	// A receives FIN|ACK → TIME-WAIT.
	err = tcb.Recv(tcp.Segment{SEQ: issB + dataLen, ACK: issA + 1, Flags: FINACK, WND: windowB})
	if err != nil {
		t.Fatal(err)
	}
	if tcb.State() != tcp.StateTimeWait {
		t.Fatalf("want TIME-WAIT; got %s", tcb.State())
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

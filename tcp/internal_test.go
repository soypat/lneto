package tcp

import (
	"errors"
	"fmt"
	"testing"
)

// Here we define internal testing helpers that may be used in any *_test.go file
// but are not exported.

// Exchange represents a single exchange of segments.
// TODO: replace [Exchange] tests with [ExchageTest].
type Exchange struct {
	Outgoing      *Segment
	Incoming      *Segment
	WantPending   *Segment // Expected pending segment. If nil not checked.
	WantState     State    // Expected end state.
	WantPeerState State    // Expected end state of peer. Not necessary when calling HelperExchange but can aid with logging information.
}

// ExchangeTest defines a complete TCP exchange scenario with initial state for both peers.
// Use Run() to execute the test from both perspectives, or RunA()/RunB() individually.
type ExchangeTest struct {
	ISSA       Value // Initial Send Sequence for peer A.
	ISSB       Value // Initial Send Sequence for peer B.
	WindowA    Size  // A's receive window size.
	WindowB    Size  // B's receive window size.
	InitStateA State // A's state before exchanges.
	InitStateB State // B's state before exchanges.
	Steps      []SegmentStep
}
type StepAction uint8

const (
	_ StepAction = iota
	StepASends
	StepBSends
	StepACloses
	StepBCloses
)

// SegmentStep defines a single segment exchange with resulting states for both peers.
type SegmentStep struct {
	Seg    Segment // The segment being exchanged.
	Action StepAction

	// States after the segment is processed.
	AState State
	BState State

	// Pending segments after the step (nil if none expected).
	APending *Segment
	BPending *Segment
}

// Run executes the test from both peers' perspectives as subtests.
func (et ExchangeTest) Run(t *testing.T) {
	t.Helper()
	t.Run("PeerA", func(t *testing.T) {
		t.Helper()
		et.RunA(t)
	})
	t.Run("PeerB", func(t *testing.T) {
		t.Helper()
		et.RunB(t)
	})
}

// RunA executes the test from peer A's perspective.
func (et ExchangeTest) RunA(t *testing.T) {
	t.Helper()
	var tcb ControlBlock
	tcb.HelperInitState(et.InitStateA, et.ISSA, et.ISSA, et.WindowA)
	if et.InitStateA.hasIRS() {
		tcb.HelperInitRcv(et.ISSB, et.ISSB, et.WindowB)
	}
	tcb.HelperSteps(t, et.Steps, true)
}

// RunB executes the test from peer B's perspective.
func (et ExchangeTest) RunB(t *testing.T) {
	t.Helper()
	var tcb ControlBlock
	tcb.HelperInitState(et.InitStateB, et.ISSB, et.ISSB, et.WindowB)
	if et.InitStateB.hasIRS() {
		tcb.HelperInitRcv(et.ISSA, et.ISSA, et.WindowA)
	}
	tcb.HelperSteps(t, et.Steps, false)
}

func (tcb *ControlBlock) HelperExchange(t *testing.T, exchange []Exchange) {
	t.Helper()
	var i int
	var ex Exchange
	defer func() {
		if t.Failed() {
			t.Errorf("exchange failed:\nwant: %s\ngot:  %s",
				ex.RFC9293String(ex.WantState, ex.WantPeerState),
				ex.RFC9293String(tcb._state, ex.WantPeerState),
			)
		}
	}()
	const pfx = "exchange"
	t.Log(tcb._state, "Exchange start")
	for i, ex = range exchange {
		if ex.Outgoing != nil && ex.Incoming != nil {
			t.Fatalf(pfx+"[%d] cannot send and receive in the same exchange, please split into two exchanges.", i)
		} else if ex.Outgoing == nil && ex.Incoming == nil {
			t.Fatalf(pfx+"[%d] must send or receive a segment.", i)
		}
		if ex.Outgoing != nil {
			prevInflight := tcb.snd.inFlight()
			err := tcb.Send(*ex.Outgoing)
			gotSent := tcb.snd.inFlight() - prevInflight
			if err != nil {
				t.Fatalf(pfx+"[%d] snd: %s\nseg=%+v\nrcv=%+v\nsnd=%+v", i, err, *ex.Outgoing, tcb.rcv, tcb.snd)
			} else if gotSent != ex.Outgoing.LEN() {
				t.Fatalf(pfx+"[%d] snd: expected %d data sent, calculated inflight %d", i, ex.Outgoing.LEN(), gotSent)
			}
		}
		if ex.Incoming != nil {
			err := tcb.Recv(*ex.Incoming)
			if err != nil {
				msg := fmt.Sprintf(pfx+"[%d] rcv: %s\nseg=%+v\nrcv=%+v\nsnd=%+v", i, err, *ex.Incoming, tcb.rcv, tcb.snd)
				if IsDroppedErr(err) {
					t.Log(msg)
				} else {
					t.Fatal(msg)
				}
			}
		}

		t.Log(ex.RFC9293String(tcb._state, ex.WantPeerState))

		state := tcb.State()
		if state != ex.WantState {
			t.Errorf(pfx+"[%d] unexpected state:\n got=%s\nwant=%s", i, state, ex.WantState)
		}
		pending, ok := tcb.PendingSegment(0)
		if !ok && ex.WantPending != nil {
			t.Fatalf(pfx+"[%d] pending:got none, want=%+v", i, *ex.WantPending)
		} else if ex.WantPending != nil && pending != *ex.WantPending {
			t.Fatalf(pfx+"[%d] pending:\n got=%+v\nwant=%+v", i, pending, *ex.WantPending)
		} else if ok && ex.WantPending == nil {
			t.Fatalf(pfx+"[%d] pending:\n got=%+v\nwant=none", i, pending)
		}
	}
}

// HelperSteps processes segment steps from a specific peer's perspective, calling Close() when indicated.
func (tcb *ControlBlock) HelperSteps(t *testing.T, steps []SegmentStep, isPeerA bool) {
	t.Helper()
	var i int
	var st SegmentStep
	defer func() {
		if t.Failed() {
			peer := "B"
			if isPeerA {
				peer = "A"
			}
			t.Errorf("step[%d] failed (peer %s)", i, peer)
		}
	}()
	const pfx = "step"
	t.Log(tcb._state, "Steps start, isPeerA:", isPeerA)
	for i, st = range steps {
		// Determine if this peer should close before this step.
		nop := isPeerA && st.Action == StepBCloses || !isPeerA && st.Action == StepACloses
		if nop {
			continue
		}
		switch st.Action {
		default:
			panic("unknown action")
		case StepACloses, StepBCloses:
			err := tcb.Close()
			if err != nil {
				t.Fatalf(pfx+"[%d] Close: %s", i, err)
			}
		case StepASends, StepBSends:
			// Determine if this peer sends or receives.
			isSender := isPeerA && st.Action == StepASends || !isPeerA && st.Action == StepBSends
			seg := st.Seg
			if isSender {
				prevInflight := tcb.snd.inFlight()
				err := tcb.Send(seg)
				gotSent := tcb.snd.inFlight() - prevInflight
				if err != nil {
					t.Fatalf(pfx+"[%d] snd: %s\nseg=%+v\nrcv=%+v\nsnd=%+v", i, err, seg, tcb.rcv, tcb.snd)
				} else if gotSent != seg.LEN() {
					t.Fatalf(pfx+"[%d] snd: expected %d data sent, calculated inflight %d", i, seg.LEN(), gotSent)
				}
			} else if tcb._state != StateTimeWait { // TODO: should we support receiving in TimeWait?
				err := tcb.Recv(seg)
				if err != nil {
					msg := fmt.Sprintf(pfx+"[%d] rcv: %s\nseg=%+v\nrcv=%+v\nsnd=%+v", i, err, seg, tcb.rcv, tcb.snd)
					if IsDroppedErr(err) {
						t.Log(msg)
					} else {
						t.Fatal(msg)
					}
				}
			}
		}
		// Select expected state and pending based on which peer we are.
		var wantState State
		var wantPending *Segment
		if isPeerA {
			wantState = st.AState
			wantPending = st.APending
		} else {
			wantState = st.BState
			wantPending = st.BPending
		}

		t.Logf(pfx+"[%d] state=%s (want=%s)", i, tcb._state, wantState)

		state := tcb.State()
		if state != wantState {
			t.Errorf(pfx+"[%d] unexpected state:\n got=%s\nwant=%s", i, state, wantState)
		}
		pending, ok := tcb.PendingSegment(0)
		if !ok && wantPending != nil {
			t.Fatalf(pfx+"[%d] pending:got none, want=%+v", i, *wantPending)
		} else if wantPending != nil && pending != *wantPending {
			t.Fatalf(pfx+"[%d] pending:\n got=%+v\nwant=%+v", i, pending, *wantPending)
		} else if ok && wantPending == nil {
			t.Fatalf(pfx+"[%d] pending:\n got=%+v\nwant=none", i, pending)
		}
	}
}

func (tcb *ControlBlock) HelperInitState(state State, localISS, localNXT Value, localWindow Size) {
	tcb._state = state
	tcb.snd = sendSpace{
		ISS: localISS,
		UNA: localISS,
		NXT: localNXT,
		WND: 1, // 1 byte window, so we can test the SEQ field.
		// UP, WL1, WL2 defaults to zero values.
	}
	tcb.rcv = recvSpace{
		WND: localWindow,
	}
}

func (tcb *ControlBlock) HelperInitRcv(irs, nxt Value, remoteWindow Size) {
	tcb.rcv.IRS = irs
	tcb.rcv.NXT = nxt
	tcb.snd.WND = remoteWindow
}

func (tcb *ControlBlock) RelativeSendSpace() sendSpace {
	snd := tcb.snd
	snd.NXT -= snd.ISS
	snd.UNA -= snd.ISS
	snd.ISS = 0
	return snd
}

func (tcb *ControlBlock) RelativeRecvSpace() recvSpace {
	rcv := tcb.rcv
	rcv.NXT -= rcv.IRS
	rcv.IRS = 0
	return rcv
}

func (tcb *ControlBlock) RelativeRecvSegment(seg Segment) Segment {
	seg.SEQ -= tcb.rcv.IRS
	seg.ACK -= tcb.snd.ISS
	return seg
}

func (tcb *ControlBlock) RelativeSendSegment(seg Segment) Segment {
	seg.SEQ -= tcb.snd.ISS
	seg.ACK -= tcb.rcv.IRS
	return seg
}

func (tcb *ControlBlock) RelativeAutoSegment(seg Segment) Segment {
	rcv := tcb.RelativeRecvSegment(seg)
	snd := tcb.RelativeSendSegment(seg)
	if rcv.SEQ > snd.SEQ {
		return snd
	}
	return rcv
}

func (tcb *ControlBlock) HelperPrintSegment(t *testing.T, isReceive bool, seg Segment) {
	const fmtmsg = "\nSeg=%+v\nRcvSpace=%s\nSndSpace=%s"
	rcv := tcb.RelativeRecvSpace()
	rcvStr := rcv.RelativeGoString()
	snd := tcb.RelativeSendSpace()
	sndStr := snd.RelativeGoString()
	t.Helper()
	if isReceive {
		t.Logf("RECV:"+fmtmsg, seg.RelativeGoString(tcb.rcv.IRS, tcb.snd.ISS), rcvStr, sndStr)
	} else {
		t.Logf("SEND:"+fmtmsg, seg.RelativeGoString(tcb.snd.ISS, tcb.rcv.IRS), rcvStr, sndStr)
	}
}

func (rcv recvSpace) RelativeGoString() string {
	return fmt.Sprintf("{NXT:%d} ", rcv.NXT-rcv.IRS)
}

func (rcv sendSpace) RelativeGoString() string {
	nxt := rcv.NXT - rcv.ISS
	una := rcv.UNA - rcv.ISS
	unaLen := Sizeof(una, nxt)
	if unaLen != 0 {
		return fmt.Sprintf("{NXT:%d UNA:%d} (%d unacked)", nxt, una, unaLen)
	}
	return fmt.Sprintf("{NXT:%d UNA:%d}", nxt, una)
}

func (seg Segment) RelativeGoString(iseq, iack Value) string {
	seglen := seg.LEN()
	if seglen != seg.DATALEN {
		// If SYN/FIN is set print out the length of the segment.
		return fmt.Sprintf("{SEQ:%d ACK:%d DATALEN:%d Flags:%s} (LEN:%d)", seg.SEQ-iseq, seg.ACK-iack, seg.DATALEN, seg.Flags, seglen)
	}
	return fmt.Sprintf("{SEQ:%d ACK:%d DATALEN:%d Flags:%s} ", seg.SEQ-iseq, seg.ACK-iack, seg.DATALEN, seg.Flags)
}

// https://datatracker.ietf.org/doc/html/rfc9293#section-3.8.6.2.1
func (tcb *ControlBlock) UsableWindow() Size {
	return Sizeof(tcb.snd.NXT, tcb.snd.UNA) + tcb.snd.WND
}

func IsDroppedErr(err error) bool {
	return err != nil && errors.Is(err, errDropSegment)
}

func (ex *Exchange) RFC9293String(A, B State) string {
	var seg Segment
	sentByA := ex.Outgoing != nil
	if sentByA {
		seg = *ex.Outgoing
	} else if ex.Incoming != nil {
		seg = *ex.Incoming
	} else {
		return ""
	}
	return StringExchange(seg, A, B, !sentByA)
}

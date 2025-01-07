package tcp

import (
	"errors"
	"fmt"
	"testing"
)

// Here we define internal testing helpers that may be used in any *_test.go file
// but are not exported.

// Exchange represents a single exchange of segments.
type Exchange struct {
	Outgoing      *Segment
	Incoming      *Segment
	WantPending   *Segment // Expected pending segment. If nil not checked.
	WantState     State    // Expected end state.
	WantPeerState State    // Expected end state of peer. Not necessary when calling HelperExchange but can aid with logging information.
}

func (tcb *ControlBlock) HelperExchange(t *testing.T, exchange []Exchange) {
	t.Helper()
	var i int
	var ex Exchange
	defer func() {
		if t.Failed() {
			t.Errorf("exchange failed:\nwant: %s\ngot:  %s",
				ex.RFC9293String(ex.WantState, ex.WantPeerState),
				ex.RFC9293String(tcb.state, ex.WantPeerState),
			)
		}
	}()
	const pfx = "exchange"
	t.Log(tcb.state, "Exchange start")
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

		t.Log(ex.RFC9293String(tcb.state, ex.WantPeerState))

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

func (tcb *ControlBlock) HelperInitState(state State, localISS, localNXT Value, localWindow Size) {
	tcb.state = state
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

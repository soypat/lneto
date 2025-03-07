package tcp_test

import (
	"math/rand"
	"strconv"
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

/*
	 Section 3.5 of RFC 9293: Basic 3-way handshake for connection synchronization.
		TCP Peer A                                           TCP Peer B

		1.  CLOSED                                               LISTEN

		2.  SYN-SENT    --> <SEQ=100><CTL=SYN>               --> SYN-RECEIVED

		3.  ESTABLISHED <-- <SEQ=300><ACK=101><CTL=SYN,ACK>  <-- SYN-RECEIVED

		4.  ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK>       --> ESTABLISHED

		5.  ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK><DATA> --> ESTABLISHED
*/
func TestExchange_rfc9293_figure6(t *testing.T) {
	const issA, issB, windowA, windowB = 100, 300, 1000, 1000
	exchangeA := []tcp.Exchange{
		{ // A sends SYN to B.
			Outgoing:      &tcp.Segment{SEQ: issA, Flags: tcp.FlagSYN, WND: windowA},
			WantState:     tcp.StateSynSent,
			WantPeerState: tcp.StateSynRcvd,
		},
		{ // A receives SYNACK from B thus establishing the connection on A's side.
			Incoming:      &tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: SYNACK, WND: windowB},
			WantState:     tcp.StateEstablished,
			WantPending:   &tcp.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: tcp.FlagACK, WND: windowA},
			WantPeerState: tcp.StateSynRcvd,
		},
		{ // A sends ACK to B, which leaves connection established on their side. Three way handshake complete by now.
			Outgoing:      &tcp.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: tcp.FlagACK, WND: windowA},
			WantState:     tcp.StateEstablished,
			WantPeerState: tcp.StateEstablished,
		},
	}
	var tcbA tcp.ControlBlock
	tcbA.HelperInitState(tcp.StateSynSent, issA, issA, windowA)
	tcbA.HelperExchange(t, exchangeA)
	segA, ok := tcbA.PendingSegment(0)
	if ok {
		t.Error("unexpected Client pending segment after establishment: ", segA)
	}
	exchangeB := reverseExchange(exchangeA)

	var tcbB tcp.ControlBlock
	tcbB.HelperInitState(tcp.StateListen, issB, issB, windowB)
	tcbB.HelperExchange(t, exchangeB) // TODO remove [:3] after snd.UNA bugfix
	segB, ok := tcbB.PendingSegment(0)
	if ok {
		t.Error("unexpected Listener pending segment after establishment: ", segB)
	}
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
func TestExchange_rfc9293_figure7(t *testing.T) {
	const issA, issB, windowA, windowB = 100, 300, 1000, 1000
	exchangeA := []tcp.Exchange{
		0: { // A sends SYN to B.
			Outgoing:  &tcp.Segment{SEQ: issA, Flags: tcp.FlagSYN, WND: windowA},
			WantState: tcp.StateSynSent,
		},
		1: { // A receives a SYN with no ACK from B.
			Incoming:    &tcp.Segment{SEQ: issB, Flags: tcp.FlagSYN, WND: windowB},
			WantState:   tcp.StateSynRcvd,
			WantPending: &tcp.Segment{SEQ: issA, ACK: issB + 1, Flags: SYNACK, WND: windowA},
		},
		2: { // A sends SYNACK to B.
			Outgoing:  &tcp.Segment{SEQ: issA, ACK: issB + 1, Flags: SYNACK, WND: windowA},
			WantState: tcp.StateSynRcvd,
		},
		3: { // A receives ACK from B.
			Incoming:  &tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: SYNACK, WND: windowA},
			WantState: tcp.StateEstablished,
		},
	}
	var tcbA tcp.ControlBlock
	tcbA.HelperInitState(tcp.StateSynSent, issA, issA, windowA)
	tcbA.HelperExchange(t, exchangeA)
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
*/
func TestExchange_rfc9293_figure8(t *testing.T) {
	const issA, issB, windowA, windowB = 100, 300, 1000, 1000
	const issAold = 90
	const issBNew = issB + 100
	exchangeA := []tcp.Exchange{
		0: { // A sends new SYN to B (which is not received).
			Outgoing:      &tcp.Segment{SEQ: issA, Flags: tcp.FlagSYN, WND: windowA},
			WantState:     tcp.StateSynSent,
			WantPeerState: tcp.StateSynRcvd,
		},
		1: { // Receive SYN from B acking an old "duplicate" SYN.
			Incoming:      &tcp.Segment{SEQ: issB, ACK: issAold + 1, Flags: SYNACK, WND: windowB},
			WantState:     tcp.StateSynSent,
			WantPending:   &tcp.Segment{SEQ: issAold + 1, Flags: tcp.FlagRST, WND: windowA},
			WantPeerState: tcp.StateSynRcvd,
		},
		2: { // A sends RST to B and makes segment believable by using the old SEQ.
			Outgoing:      &tcp.Segment{SEQ: issAold + 1, Flags: tcp.FlagRST, WND: windowA},
			WantState:     tcp.StateSynSent,
			WantPeerState: tcp.StateListen,
		},
		3: { // A sends a duplicate SYN to B.
			Outgoing:      &tcp.Segment{SEQ: issA, Flags: tcp.FlagSYN, WND: windowA},
			WantState:     tcp.StateSynSent,
			WantPeerState: tcp.StateSynRcvd,
		},
		4: { // B SYNACKs new SYN.
			Incoming:      &tcp.Segment{SEQ: issBNew, ACK: issA + 1, Flags: SYNACK, WND: windowB},
			WantState:     tcp.StateEstablished,
			WantPending:   &tcp.Segment{SEQ: issA + 1, ACK: issBNew + 1, Flags: tcp.FlagACK, WND: windowA},
			WantPeerState: tcp.StateSynRcvd,
		},
		5: { // B receives ACK from A.
			Outgoing:      &tcp.Segment{SEQ: issA + 1, ACK: issBNew + 1, Flags: tcp.FlagACK, WND: windowA},
			WantState:     tcp.StateEstablished,
			WantPeerState: tcp.StateEstablished,
		},
	}
	var tcbA tcp.ControlBlock
	tcbA.HelperInitState(tcp.StateSynSent, issA, issA, windowA)
	tcbA.HelperExchange(t, exchangeA)

	exchangeB := []tcp.Exchange{
		0: { // B receives old SYN from A.
			Incoming:    &tcp.Segment{SEQ: issAold, Flags: tcp.FlagSYN, WND: windowA},
			WantState:   tcp.StateSynRcvd,
			WantPending: &tcp.Segment{SEQ: issB, ACK: issAold + 1, Flags: SYNACK, WND: windowB},
		},
		1: { // B SYNACKs old SYN.
			Outgoing:  &tcp.Segment{SEQ: issB, ACK: issAold + 1, Flags: SYNACK, WND: windowB},
			WantState: tcp.StateSynRcvd,
		},
		2: { // B receives RST from A.
			Incoming:  &tcp.Segment{SEQ: issAold + 1, Flags: tcp.FlagRST, WND: windowA},
			WantState: tcp.StateListen,
		},
		3: { // B receives new SYN from A.
			Incoming:    &tcp.Segment{SEQ: issA, Flags: tcp.FlagSYN, WND: windowA},
			WantState:   tcp.StateSynRcvd,
			WantPending: &tcp.Segment{SEQ: issBNew, ACK: issA + 1, Flags: SYNACK, WND: windowB},
		},
		4: { // B SYNACKs new SYN.
			Outgoing:  &tcp.Segment{SEQ: issBNew, ACK: issA + 1, Flags: SYNACK, WND: windowB},
			WantState: tcp.StateSynRcvd,
		},
		5: { // B receives ACK from A.
			Incoming:  &tcp.Segment{SEQ: issA + 1, ACK: issBNew + 1, Flags: tcp.FlagACK, WND: windowA},
			WantState: tcp.StateEstablished,
		},
	}
	var tcbB tcp.ControlBlock
	tcbB.HelperInitState(tcp.StateListen, issB, issB, windowB)
	tcbB.HelperExchange(t, exchangeB)
}

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
func TestExchange_rfc9293_figure12(t *testing.T) {
	const issA, issB, windowA, windowB = 100, 300, 1000, 1000
	exchangeA := []tcp.Exchange{
		0: { // A sends FIN|ACK to B to begin closing connection.
			Outgoing:      &tcp.Segment{SEQ: issA, ACK: issB, Flags: FINACK, WND: windowA},
			WantState:     tcp.StateFinWait1,
			WantPeerState: tcp.StateCloseWait,
		},
		1: { // A receives ACK from B.
			Incoming:      &tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: tcp.FlagACK, WND: windowB},
			WantState:     tcp.StateFinWait2,
			WantPeerState: tcp.StateCloseWait,
			//	 TODO(soypat): WantPending should be nil here? Perhaps fix test by modifying rcvFinWait1 pending result.
			WantPending: &tcp.Segment{SEQ: issA + 1, ACK: issB, Flags: tcp.FlagACK, WND: windowA},
		},
		2: { // A receives FIN|ACK from B.
			Incoming:      &tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: FINACK, WND: windowB},
			WantState:     tcp.StateTimeWait,
			WantPending:   &tcp.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: tcp.FlagACK, WND: windowA},
			WantPeerState: tcp.StateLastAck,
		},
		3: { // A sends ACK to B.
			Outgoing:      &tcp.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: tcp.FlagACK, WND: windowA},
			WantState:     tcp.StateTimeWait, // Technically we should be in TimeWait here.
			WantPeerState: tcp.StateClosed,
		},
	}
	var tcbA tcp.ControlBlock
	tcbA.HelperInitState(tcp.StateEstablished, issA, issA, windowA)
	tcbA.HelperInitRcv(issB, issB, windowB)
	tcbA.HelperExchange(t, exchangeA)
	// tcbA.HelperExchange(t, exchangeA[:1])
	// tcbA.HelperExchange(t, exchangeA[1:2])
	// tcbA.HelperExchange(t, exchangeA[2:])

	return
	exchangeB := reverseExchange(exchangeA)
	exchangeB[1].WantPending = &tcp.Segment{SEQ: issB, ACK: issA + 1, Flags: FINACK, WND: windowB}
	var tcbB tcp.ControlBlock
	tcbB.HelperInitState(tcp.StateEstablished, issB, issB, windowB)
	tcbB.HelperInitRcv(issA, issA, windowA)
	tcbB.HelperExchange(t, exchangeB)
}

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
func TestExchange_rfc9293_figure13(t *testing.T) {
	const issA, issB, windowA, windowB = 100, 300, 1000, 1000
	exchangeA := []tcp.Exchange{
		0: { // A sends FIN|ACK to B to begin closing connection.
			Outgoing:  &tcp.Segment{SEQ: issA, ACK: issB, Flags: FINACK, WND: windowA},
			WantState: tcp.StateFinWait1,
		},
		1: { // A receives FIN|ACK from B, who sent packet before receiving A's FINACK.
			Incoming:    &tcp.Segment{SEQ: issB, ACK: issA, Flags: FINACK, WND: windowB},
			WantState:   tcp.StateClosing,
			WantPending: &tcp.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: tcp.FlagACK, WND: windowA},
		},
		2: { // A sends ACK to B.
			Outgoing:  &tcp.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: tcp.FlagACK, WND: windowA},
			WantState: tcp.StateTimeWait,
		},
	}
	var tcbA tcp.ControlBlock
	tcbA.HelperInitState(tcp.StateEstablished, issA, issA, windowA)
	tcbA.HelperInitRcv(issB, issB, windowB)
	tcbA.HelperExchange(t, exchangeA)

	// No need to test B since exchange is completely symmetric.
}

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
			WantPending:   &tcp.Segment{SEQ: issA + 2 + 2*datalen, ACK: issB + 1 + 2*datalen, Flags: tcp.FlagACK, WND: windowA},
			WantPeerState: tcp.StateCloseWait,
		},
	}
	// The client starts in the SYN_SENT state with a random sequence number.
	gotServerSeg, _ := parseSegment(t, exchangeHelloWorld[0])
	tcbA.HelperInitState(tcp.StateSynSent, gotServerSeg.SEQ, gotServerSeg.SEQ, windowB)
	tcbA.HelperExchange(t, exchangeA)

	// TODO(soypat): fix exchange reversal.
	return
	exchangeB := reverseExchange(exchangeA)

	exchangeB[7].WantPending = nil // Is an unpredicable action.
	var tcbB tcp.ControlBlock
	tcbB.HelperInitState(tcp.StateListen, issB, issB, windowB)
	tcbB.HelperInitRcv(issA, issA, windowA)
	tcbB.HelperExchange(t, exchangeB)
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

func TestExchange_helloworld_client(t *testing.T) {
	return
	// Client Transmission Control Block.
	var tcb tcp.ControlBlock
	// The client starts in the SYN_SENT state with a random sequence number.
	gotClientSeg, _ := parseSegment(t, exchangeHelloWorld[0])

	// We add the SYN state to the client.
	tcb.HelperInitState(tcp.StateSynSent, gotClientSeg.SEQ, gotClientSeg.SEQ, gotClientSeg.WND)
	err := tcb.Send(gotClientSeg)
	if err != nil {

		t.Fatal(err)
	}
	tcb.HelperPrintSegment(t, false, gotClientSeg)

	segString := func(seg tcp.Segment) string {
		return tcb.RelativeAutoSegment(seg).RelativeGoString(0, 0)
	}
	for i, packet := range exchangeHelloWorld {
		if i == 0 {
			continue // we already processed first packet.
		}
		seg, payload := parseSegment(t, packet)
		if seg.DATALEN > 0 {
			t.Logf("seg[%d] <%s> payload: %q", i, tcb.State(), string(payload))
		} else {
			t.Logf("seg[%d] <%s>", i, tcb.State())
		}
		isClient := packet[0] == 0x28
		if isClient {
			isPSH := seg.Flags&tcp.FlagPSH != 0
			gotClientSeg.Flags |= seg.Flags & (tcp.FlagPSH | tcp.FlagFIN) // Can't predict when client will send FIN.
			if isPSH {
				gotClientSeg.DATALEN = seg.DATALEN
			}

			gotClientSeg.WND = seg.WND // Ignore window field, not a core part of control flow.
			if gotClientSeg != seg {
				t.Fatalf("client:\n got=%+v\nwant=%+v", segString(gotClientSeg), segString(seg))
			}
			err := tcb.Send(gotClientSeg)
			if err != nil {
				t.Fatalf("incoming %s:\nseg[%d]=%s\nrcv=%+v\nsnd=%+v", err, i, segString(gotClientSeg), tcb.RelativeRecvSpace(), tcb.RelativeSendSpace())
			}
			tcb.HelperPrintSegment(t, false, gotClientSeg)
			continue // we only pass server packets to the client.
		}
		err = tcb.Recv(seg)
		if err != nil {
			t.Fatalf("%s:\nseg[%d]=%s\nrcv=%+v\nsnd=%+v", err, i, segString(seg), tcb.RelativeRecvSpace(), tcb.RelativeSendSpace())
		}
		tcb.HelperPrintSegment(t, true, seg)
		var ok bool
		gotClientSeg, ok = tcb.PendingSegment(0)
		if !ok {
			t.Fatalf("[%d]: got no segment state=%s", i, tcb.State())
		}
	}
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
	if err := vld.Err(); err != nil {
		t.Fatal(vld.Err())
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
	if err := vld.Err(); err != nil {
		t.Fatal(vld.Err())
	}

	ipl := ifrm.Payload()
	tfrm, err := tcp.NewFrame(ipl)
	if err != nil {
		t.Fatal(err)
	}
	tfrm.ValidateSize(&vld)
	if err := vld.Err(); err != nil {
		t.Fatal(err)
	}
	_ = tfrm.String()
	payload := tfrm.Payload()
	return tfrm.Segment(len(payload)), payload
}

func reverseExchange(exchange []tcp.Exchange) []tcp.Exchange {
	if len(exchange) == 0 {
		panic("len(exchange) != len(states) or empty exchange: " + strconv.Itoa(len(exchange)))
	}
	firstIsIn := exchange[0].Incoming != nil
	if firstIsIn {
		panic("please start with an outgoing segment to reverse exchange for best test results")
	}
	out := make([]tcp.Exchange, len(exchange))
	for i := range exchange {
		isLast := i == len(exchange)-1
		isOut := exchange[i].Outgoing != nil
		out[i].WantState, out[i].WantPeerState = exchange[i].WantPeerState, exchange[i].WantState
		if isOut {
			out[i].Incoming = exchange[i].Outgoing
			if !isLast {
				out[i].WantPending = exchange[i+1].Incoming
			}
		} else {
			out[i].Outgoing = exchange[i].Incoming
		}
	}
	return out
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

func FuzzTCBActions(f *testing.F) {
	const mtu = 2048
	const (
		actionRecv = iota
		actionSend
		actionClose
		actionMax
	)
	f.Add(
		0x2313_2313,
		[]byte{actionSend, actionRecv, actionSend, actionRecv, actionSend, actionRecv},
	)
	f.Add(
		0x2fefe_feefe,
		[]byte{actionSend, actionRecv, actionSend, actionClose, actionSend, actionRecv},
	)
	f.Add(
		0x2fefe_feefe,
		[]byte{actionClose, actionRecv, actionSend, actionClose, actionSend, actionRecv},
	)
	recvsendSize := func(rng *rand.Rand) int {
		return rng.Int() % mtu
	}
	f.Fuzz(func(t *testing.T, seed int, actions []byte) {
		if len(actions) == 0 || len(actions) > 100 {
			t.SkipNow()
		}
		rng := rand.New(rand.NewSource(int64(seed)))
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

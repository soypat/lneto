package tcp

import (
	"errors"
	"fmt"
	"math/bits"
	"strconv"
	"unsafe"

	"github.com/soypat/lneto"
)

//go:generate stringer -type=State,OptionKind -linecomment -output stringers.go .

var (
	errDropSegment    error = lneto.ErrPacketDrop
	errWindowTooLarge       = errors.New("invalid window size > 2**16")

	errBufferTooSmall        error = lneto.ErrShortBuffer
	errNeedClosedTCBToOpen         = errors.New("need closed TCB to call open")
	errInvalidState                = errors.New("invalid state")
	errConnNotExist                = errors.New("connection does not exist")
	errConnectionClosing           = errors.New("connection closing")
	errExpectedSYN                 = errors.New("seqs:expected SYN")
	errBadSegack                   = errors.New("seqs:bad segack")
	errFinwaitExpectedACK          = errors.New("seqs:finwait1 expected ACK")

	errWindowOverflow    = newRejectErr("wnd > 2**16")
	errSeqNotInWindow    = newRejectErr("seq not in snd/rcv.wnd")
	errZeroWindow        = newRejectErr("zero window")
	errLastNotInWindow   = newRejectErr("last not in snd/rcv.wnd")
	errRequireSequential = newRejectErr("seq != rcv.nxt (require sequential segments)")
	errAckNotNext        = newRejectErr("ack != snd.nxt")
)

func newRejectErr(err string) *RejectError { return &RejectError{err: "reject in/out seg: " + err} }

// RejectError represents an error that arises during admission of a segment into the
// Transmission Control Block logic in which the packet cannot be processed by the TCB.
type RejectError struct {
	err string
}

func (e *RejectError) Error() string { return e.err }

// Segment represents an incoming/outgoing TCP segment in the sequence space.
type Segment struct {
	SEQ     Value // sequence number of first octet of segment. If SYN is set it is the initial sequence number (ISN) and the first data octet is ISN+1.
	ACK     Value // acknowledgment number. If ACK is set it is sequence number of first octet the sender of the segment is expecting to receive next.
	DATALEN Size  // The number of octets occupied by the data (payload) not counting SYN and FIN.
	WND     Size  // segment window
	Flags   Flags // TCP flags.
}

// LEN returns the length of the segment in octets including SYN and FIN flags.
func (seg *Segment) LEN() Size {
	add := Size(seg.Flags>>0) & 1 // Add FIN bit.
	add += Size(seg.Flags>>1) & 1 // Add SYN bit.
	return seg.DATALEN + add
}

// End returns the sequence number of the last octet of the segment.
func (seg *Segment) Last() Value {
	seglen := seg.LEN()
	if seglen == 0 {
		return seg.SEQ
	}
	return Add(seg.SEQ, seglen) - 1
}

func (seg Segment) isFirstSYN() bool {
	return seg.Flags == FlagSYN && seg.ACK == 0 && seg.DATALEN == 0 && seg.WND > 0
}

func (seg Segment) String() string {
	if seg.DATALEN == 0 {
		return fmt.Sprintf("SEG %s ACK=%d SEQ=%d WND=%d", seg.Flags, seg.ACK, seg.SEQ, seg.WND)
	}
	return fmt.Sprintf("SEG %s ACK=%d SEQ=%d WND=%d DATALEN=%d", seg.Flags, seg.ACK, seg.SEQ, seg.WND, seg.DATALEN)
}

// ClientSynSegment is a the first packet sent over a TCP connection to a server. Typically the client
// will call ClientSynSegment to generate a new SYN packet to send over to the server to initiate communications:
//
//	synseg := ClientSynSegment(100, 256)
//	err := clientTCB.Send(synseg) // By now the client's TCB is in StateSynSent and is attempting to open a connection.
func ClientSynSegment(clientISS Value, clientWND Size) Segment {
	return Segment{
		SEQ:     clientISS,
		WND:     clientWND,
		Flags:   FlagSYN,
		ACK:     0,
		DATALEN: 0,
	}
}

// StringExchange returns a string representation of a segment exchange over
// a network in RFC9293 styled visualization. invertDir inverts the arrow directions.
// i.e:
//
//	SynSent --> <SEQ=300><ACK=91>[SYN,ACK]  --> SynRcvd
func StringExchange(seg Segment, A, B State, invertDir bool) string {
	b := make([]byte, 0, 64)
	b = appendStringExchange(b, seg, A, B, invertDir)
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// appendStringExchange appends a RFC9293 styled visualization of exchange to buf.
// i.e:
//
//	SynSent --> <SEQ=300><ACK=91>[SYN,ACK]  --> SynRcvd
func appendStringExchange(buf []byte, seg Segment, A, B State, invertDir bool) []byte {
	const emptySpaces = "                    "
	const spacelen = len(emptySpaces)
	const fill = len(emptySpaces) - 1
	appendVal := func(buf []byte, name string, i Value) []byte {
		buf = append(buf, '<')
		buf = append(buf, name...)
		buf = append(buf, '=')
		buf = strconv.AppendInt(buf, int64(i), 10)
		buf = append(buf, '>')
		return buf
	}
	startLen := len(buf)
	dirSep := []byte(" --> ")
	if invertDir {
		dirSep = []byte(" <-- ")
	}
	astr := A.String()
	buf = append(buf, astr...)
	if len(astr) < fill {
		// Space padding.
		buf = append(buf, emptySpaces[:fill-len(astr)]...)
	}
	buf = append(buf, dirSep...)
	buf = appendVal(buf, "SEQ", seg.SEQ)
	buf = appendVal(buf, "ACK", seg.ACK)
	if seg.DATALEN > 0 {
		buf = appendVal(buf, "DATA", Value(seg.DATALEN))
	}
	buf = append(buf, '[')
	buf = seg.Flags.AppendFormat(buf)
	buf = append(buf, ']')
	if len(buf)-startLen < 48 {
		// More space padding.
		buf = append(buf, emptySpaces[:48-len(buf)]...)
	}
	buf = append(buf, dirSep...)
	buf = append(buf, B.String()...)
	return buf
}

// Flags is a TCP flags bit-masked implementation i.e: SYN, FIN, ACK.
type Flags uint16

const (
	FlagFIN Flags = 1 << iota // FlagFIN - No more data from sender.
	FlagSYN                   // FlagSYN - Synchronize sequence numbers.
	FlagRST                   // FlagRST - Reset the connection.
	FlagPSH                   // FlagPSH - Push function.
	FlagACK                   // FlagACK - Acknowledgment field significant.
	FlagURG                   // FlagURG - Urgent pointer field significant.
	FlagECE                   // FlagECE - ECN-Echo has a nonce-sum in the SYN/ACK.
	FlagCWR                   // FlagCWR - Congestion Window Reduced.
	FlagNS                    // FlagNS  - Nonce Sum flag (see RFC 3540).
)

const flagMask = 0x01ff

// The union of SYN|FIN|PSH and ACK flags is commonly found throughout the specification, so we define unexported shorthands.
const (
	synack = FlagSYN | FlagACK
	finack = FlagFIN | FlagACK
	pshack = FlagPSH | FlagACK
)

// HasAll checks if mask bits are all set in the receiver flags.
func (flags Flags) HasAll(mask Flags) bool { return flags&mask == mask }

// HasAny checks if one or more mask bits are set in receiver flags.
func (flags Flags) HasAny(mask Flags) bool { return flags&mask != 0 }

// Mask returns the flags with non-flag bits unset.
func (flags Flags) Mask() Flags { return flags & flagMask }

func (flags Flags) Invalid() bool { return flags&flagMask != flags }

// StringFlags returns human readable flag string. i.e:
//
//	"[SYN,ACK]"
//
// Flags are printed in order from LSB (FIN) to MSB (NS).
// All flags are printed with length of 3, so a NS flag will
// end with a space i.e. [ACK,NS ]
func (flags Flags) String() string {
	// Cover most common cases without heap allocating.
	switch flags {
	case 0:
		return "[]"
	case synack:
		return "[SYN,ACK]"
	case finack:
		return "[FIN,ACK]"
	case pshack:
		return "[PSH,ACK]"
	case FlagFIN | FlagPSH | FlagACK:
		return "[FIN,PSH,ACK]"
	case FlagACK:
		return "[ACK]"
	case FlagSYN:
		return "[SYN]"
	case FlagFIN:
		return "[FIN]"
	case FlagRST:
		return "[RST]"
	}
	if flags.Invalid() {
		return strInvalidTCPFlags
	}
	// Since Go 1.26 this should not allocate if returned string does not escape and is smaller than 32 bytes.
	// https://go.dev/blog/allocation-optimizations
	var buf [2 + 4*9]byte
	buf[0] = '['
	n := flags.format((*[36]byte)(buf[1:]))
	buf[1+n] = ']'
	return string(buf[:2+n])
}

// AppendFormat appends a human readable flag string to b returning the extended buffer.
func (flags Flags) AppendFormat(b []byte) []byte {
	var buf [36]byte
	n := flags.format(&buf)
	return append(b, buf[:n]...)
}

const strInvalidTCPFlags = "<invalid TCP flags>"

func (flags Flags) format(buf *[4 * 9]byte) (n int) {
	if flags == 0 {
		return 0
	} else if flags.Invalid() {
		return copy(buf[:], strInvalidTCPFlags)
	}
	const flaglen = 3
	const strflags = "FINSYNRSTPSHACKURGECECWRNS "
	var addcommas bool
	for flags != 0 { // written by Github Copilot- looks OK.
		i := bits.TrailingZeros16(uint16(flags))
		if addcommas {
			buf[n] = ','
			n++
		} else {
			addcommas = true
		}
		n += copy(buf[n:], strflags[i*flaglen:i*flaglen+flaglen])
		flags &= ^(1 << i)
	}
	return n
}

// State enumerates states a TCP connection progresses through during its lifetime as per RFC9293.
type State uint8

const (
	// CLOSED - represents no connection state at all. Is not a valid state of the TCP state machine but rather a pseudo-state pre-initialization.
	StateClosed State = iota // CLOSED
	// LISTEN - represents waiting for a connection request from any remote TCP and port.
	StateListen // LISTEN
	// SYN-RECEIVED - represents waiting for a confirming connection request acknowledgment
	// after having both received and sent a connection request.
	StateSynRcvd // SYN-RECEIVED
	// SYN-SENT - represents waiting for a matching connection request after having sent a connection request.
	StateSynSent // SYN-SENT
	// ESTABLISHED - represents an open connection, data received can be delivered
	// to the user.  The normal state for the data transfer phase of the connection.
	StateEstablished // ESTABLISHED
	// FIN-WAIT-1 - represents waiting for a connection termination request
	// from the remote TCP, or an acknowledgment of the connection
	// termination request previously sent.
	StateFinWait1 // FIN-WAIT-1
	// FIN-WAIT-2 - represents waiting for a connection termination request
	// from the remote TCP.
	StateFinWait2 // FIN-WAIT-2
	// CLOSING - represents waiting for a connection termination request
	// acknowledgment from the remote TCP.
	StateClosing // CLOSING
	// TIME-WAIT - represents waiting for enough time to pass to be sure the remote
	// TCP received the acknowledgment of its connection termination request.
	StateTimeWait // TIME-WAIT
	// CLOSE-WAIT - represents waiting for a connection termination request
	// from the local user.
	StateCloseWait // CLOSE-WAIT
	// LAST-ACK - represents waiting for an acknowledgment of the
	// connection termination request previously sent to the remote TCP
	// (which includes an acknowledgment of its connection termination request).
	StateLastAck // LAST-ACK
)

// IsPreestablished returns true if the connection is in a state preceding the established state.
// Returns false for Closed pseudo state.
func (s State) IsPreestablished() bool {
	return s == StateSynRcvd || s == StateSynSent || s == StateListen
}

// IsClosing returns true if the connection is in a closing state but not yet terminated (relieved of remote connection state).
// Returns false for Closed pseudo state.
func (s State) IsClosing() bool {
	return s == StateFinWait1 || s == StateFinWait2 || s == StateClosing || s == StateLastAck || s == StateCloseWait
}

// IsClosed returns true if the connection closed and can possibly relieved of
// all state related to the remote connection. It returns true if Closed or in TimeWait.
func (s State) IsClosed() bool {
	return s == StateClosed || s == StateTimeWait
}

// IsSynchronized returns true if the connection has gone through the Established state.
func (s State) IsSynchronized() bool {
	return s >= StateEstablished && !s.IsClosed()
}

// TxDataOpen returns true if the state allows for outgoing data segments to be sent.
// Combine with [State.IsPreestablished] to know whether there is no more data to be sent over the network.
func (s State) TxDataOpen() bool {
	// In CloseWait state the remote endpoint has closed
	// our receive hald of the connection but we can still transmit indefinitely.
	return s == StateEstablished || s == StateCloseWait
}

// RxDataOpen returns true if the state allows the receiving of incoming data segments.
// Combine with [State.IsPreestablished] to know whether there is no more data to be received over the network.
func (s State) RxDataOpen() bool {
	return s == StateEstablished || s == StateFinWait1 || s == StateFinWait2
}

// IsDataOpen returns true if the connection allows sending and receiving of data.
func (s State) isOpen() bool {
	return !s.IsClosed()
}

// hasIRS checks if the ControlBlock has received a valid initial sequence number (IRS).
func (s State) hasIRS() bool {
	return s.isOpen() && s != StateSynSent && s != StateListen
}

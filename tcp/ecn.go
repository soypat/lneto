package tcp

import "github.com/soypat/lneto/internal"

// ECN codepoints of RFC 3168 §5, carried in the IP header rather than in TCP.
const (
	// ECNNotECT marks a packet whose endpoints do not use ECN, so a congested
	// router drops it rather than marking it.
	ECNNotECT = internal.ECNNotECT
	// ECNECT0 marks a packet as ECN-capable: a congested router may mark it
	// instead of discarding it. This is what a negotiated connection sends.
	ECNECT0 = internal.ECNECT0
	// ECNECT1 is the second ECN-capable codepoint, unused here.
	ECNECT1 = internal.ECNECT1
	// ECNCE is Congestion Experienced: a router has signalled congestion by
	// marking this packet instead of dropping it.
	ECNCE = internal.ECNCE
)

// Explicit Congestion Notification, RFC 3168.
//
// ECN lets a congested router say so by marking a packet rather than discarding it,
// which is a strictly better signal: it arrives a round trip sooner than the loss it
// replaces and costs no retransmission. TCP carries the signal back to the sender in
// two header flags — the receiver echoes ECE for every marked packet it sees, and the
// sender answers with CWR once it has reacted.
//
// # Why this lives in the core
//
// Reducing the congestion window on the signal is a policy's decision, but setting
// ECE and CWR on outgoing segments is not something the policy seam can express:
// [TxDirective] steers what is sent, not which flags it carries, and adding flag
// control there would let any policy forge a FIN or an RST.
//
// It does not need to. ECE arrives as an ordinary TCP flag, so a policy already sees
// it in [RxEvent.Segment] with no new hook, and answering it is bookkeeping the state
// machine can do alone. So the negotiation and the echo stay here and the reaction
// stays in the policy, which is the division the two halves already have.
//
// # What the core does not do
//
// The congestion window is untouched here. A connection with ECN enabled and no
// policy negotiates ECN, echoes ECE and sets CWR correctly and never slows down,
// exactly as a connection with no policy never retransmits.
type ecnState struct {
	// requested reports that this side wants ECN, set by configuration. Nothing
	// below happens unless it is set, so the default is a connection that neither
	// offers ECN nor claims to.
	requested bool
	// peerOffered reports that the peer's SYN carried the ECN-setup flags.
	peerOffered bool
	// enabled reports that both sides agreed. Only then are marks acted on: acting
	// on a mark from a peer that never agreed means reacting to whatever the IP
	// header happened to contain.
	enabled bool
	// offered reports that this side put the ECN-setup flags on a transmitted SYN
	// or SYN-ACK, so a peer's answer can be interpreted.
	offered bool
	// echoCE reports that a marked packet has arrived and has not yet been
	// acknowledged by the peer. RFC 3168 §6.1.3 requires ECE on every
	// acknowledgement until the peer answers with CWR, not merely on the next one,
	// so that losing an acknowledgement does not lose the congestion signal.
	echoCE bool
	// sendCWR reports that this side has been told of congestion and owes the peer
	// a CWR to say it has reacted (§6.1.2).
	sendCWR bool
}

// EnableECN configures whether this connection offers Explicit Congestion
// Notification on its next handshake. It must be set before the connection opens.
//
// Enabling it asks routers to mark packets instead of dropping them. Whether that
// makes the connection slow down is up to the installed [Policy], which sees the
// echoed signal as [FlagECE] on a received segment.
func (tcb *ControlBlock) EnableECN(enable bool) { tcb.ecn.requested = enable }

// ECNEnabled reports whether ECN was successfully negotiated with the peer.
func (tcb *ControlBlock) ECNEnabled() bool { return tcb.ecn.enabled }

// ECNCodepoint returns the codepoint the IP layer should mark outgoing packets with:
// ECT(0) once ECN is negotiated so that routers mark rather than drop, and Not-ECT
// otherwise.
//
// RFC 3168 §6.1.5 keeps pure acknowledgements, retransmissions and window probes
// Not-ECT. They are not distinguished here, which costs nothing in correctness: a
// mark on one is still a true report of congestion and is still echoed. It does mean
// a marked retransmission signals congestion twice for one event.
func (tcb *ControlBlock) ECNCodepoint() uint8 {
	if tcb.ecn.enabled {
		return ECNECT0
	}
	return ECNNotECT
}

// observeECN records the codepoint of a received packet's IP header. A Congestion
// Experienced mark starts echoing ECE back to the peer.
func (tcb *ControlBlock) observeECN(codepoint uint8) {
	if tcb.ecn.enabled && codepoint == ECNCE {
		tcb.ecn.echoCE = true
	}
}

// ecnRecvFlags applies the ECN flags of a received segment: the handshake
// negotiation, the peer's CWR answering our echo, and the peer's ECE telling us to
// react.
func (tcb *ControlBlock) ecnRecvFlags(seg Segment) {
	flags := seg.Flags
	isSyn := flags.HasAny(FlagSYN)
	switch {
	case isSyn && !flags.HasAny(FlagACK):
		// An ECN-setup SYN carries both ECE and CWR (§6.1.1). A SYN with only one
		// of them is not an offer, which is how the flags are distinguished from a
		// SYN that happens to carry congestion signalling.
		tcb.ecn.peerOffered = flags.HasAll(FlagECE | FlagCWR)
	case isSyn:
		// An ECN-setup SYN-ACK carries ECE and not CWR (§6.1.1). Both set would be
		// a peer echoing our own SYN's flags back rather than agreeing.
		if tcb.ecn.requested && tcb.ecn.offered &&
			flags.HasAny(FlagECE) && !flags.HasAny(FlagCWR) {
			tcb.ecn.enabled = true
		}
	default:
		if !tcb.ecn.enabled {
			return
		}
		if flags.HasAny(FlagCWR) {
			// The peer has reacted to the congestion we reported, so stop echoing
			// (§6.1.3).
			tcb.ecn.echoCE = false
		}
		if flags.HasAny(FlagECE) {
			// The peer is reporting congestion on our data. Owe it a CWR saying we
			// have reacted; reacting itself is the policy's business, and it sees
			// this same flag on the segment.
			tcb.ecn.sendCWR = true
		}
	}
}

// ecnSendFlags returns the ECN flags to add to an outgoing segment, and is where the
// echo and the CWR answer are actually put on the wire.
func (tcb *ControlBlock) ecnSendFlags(seg Segment) Flags {
	if !tcb.ecn.requested {
		return 0
	}
	isSyn := seg.Flags.HasAny(FlagSYN)
	switch {
	case isSyn && !seg.Flags.HasAny(FlagACK):
		return FlagECE | FlagCWR // ECN-setup SYN (§6.1.1).
	case isSyn:
		if tcb.ecn.peerOffered {
			return FlagECE // ECN-setup SYN-ACK (§6.1.1).
		}
		return 0
	}
	if !tcb.ecn.enabled {
		return 0
	}
	var flags Flags
	if tcb.ecn.echoCE {
		flags |= FlagECE
	}
	if tcb.ecn.sendCWR && seg.DATALEN > 0 {
		// CWR goes on a data segment (§6.1.2): it says the sending rate has been
		// reduced, which a pure acknowledgement makes no claim about.
		flags |= FlagCWR
	}
	return flags
}

// ecnSent commits the ECN state of a segment that has been transmitted: the offer,
// and the discharge of an owed CWR.
//
// Recorded after transmission rather than where the flags are chosen, for the reason
// the window scale offer is: a segment can be built and then not sent, and a
// connection that believed it had answered a congestion report would never answer it.
func (tcb *ControlBlock) ecnSent(seg Segment) {
	if !tcb.ecn.requested {
		return
	}
	if seg.Flags.HasAny(FlagSYN) {
		tcb.ecn.offered = true
		if seg.Flags.HasAny(FlagACK) && tcb.ecn.peerOffered {
			// A transmitted ECN-setup SYN-ACK completes the negotiation: the option
			// has now been both received and sent.
			tcb.ecn.enabled = seg.Flags.HasAny(FlagECE)
		}
		return
	}
	if seg.Flags.HasAny(FlagCWR) && seg.DATALEN > 0 {
		tcb.ecn.sendCWR = false
	}
}

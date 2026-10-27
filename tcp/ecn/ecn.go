// Package ecn implements Explicit Congestion Notification (RFC 3168) as a
// [tcp.ECNPolicy]: it negotiates ECN in the handshake, sends new data
// ECN-capable so a congested router can mark it instead of dropping it,
// echoes such marks to the peer with ECE until it answers with CWR, and
// answers the peer's ECE with CWR. Reducing the window is up to the congestion
// controller, which sees ECE on the peer's ACKs, as tcp/congestion's CUBIC
// does. With a controller that does not, ECN only hides congestion.
//
// The codepoints are in the IP header, which a [tcp.Conn] reads and writes for
// the Policy.
package ecn

import (
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/tcp"
)

// ECN codepoints of the IP header (RFC 3168 §5).
const (
	NotECT = internal.ECNNotECT
	ECT1   = internal.ECNECT1
	ECT0   = internal.ECNECT0
	CE     = internal.ECNCE // Congestion Experienced.
)

// Policy implements ECN. It echoes marks once the peer answered an offer of
// ours, or we answered the peer's, in the handshake, and sends new data
// ECN-capable unless a SYN of either side went without the offer (RFC 3168
// §6.1.1). The zero value is ready to use.
type Policy struct {
	// Handshake.
	synSent     bool // A SYN was sent; retransmissions do not offer ECN (§6.1.1.1).
	offered     bool // Our latest SYN offered ECN.
	offeredAny  bool // A SYN of ours offered ECN.
	synRcvd     bool // A SYN was received.
	peerOffered bool // Every SYN received offered ECN.

	echoes bool // Echo CE marks and take CWR.
	ect    bool // Send new data ECT(0) and answer ECE with CWR.

	ce   bool // The packet being received is marked CE.
	echo bool // Set ECE until the peer sends CWR (§6.1.3).
	cwr  bool // Set CWR on the next segment of new data (§6.1.2).
	// cwrSent holds until the peer acknowledges cwrEnd, the end of the segment
	// sent with CWR. ECE meanwhile echoes the mark CWR answered.
	cwrSent bool
	cwrEnd  tcp.Value

	// State before the segment being sent, saved in PreTx.
	nxt     tcp.Value
	probing bool // The peer's window is closed.

	codepoint uint8 // Of the segment just sent.
}

var _ tcp.ECNPolicy = (*Policy)(nil)

// Reset implements [tcp.Policy].
func (p *Policy) Reset() { *p = Policy{} }

// Enabled reports whether both sides agreed to use ECN in both directions.
func (p *Policy) Enabled() bool { return p.echoes && p.ect }

// RecvECN implements [tcp.ECNPolicy].
func (p *Policy) RecvECN(codepoint uint8) { p.ce = codepoint == CE }

// SendECN returns ECT(0) for a segment of new data once ECN is enabled, else
// Not-ECT, which SYNs, pure ACKs, resends and window probes keep (RFC 3168
// §6.1.1, §6.1.5, §6.1.6). It implements [tcp.ECNPolicy].
func (p *Policy) SendECN() uint8 { return p.codepoint }

// PreRx takes the offer of the peer's SYN, also of one the connection drops
// as a retransmission, stops the echo on the peer's CWR and starts it on a
// packet marked CE, also for a segment held out of order. It implements
// [tcp.Policy].
func (p *Policy) PreRx(h *tcp.Handler, incoming tcp.Frame) bool {
	_, flags := incoming.OffsetAndFlags()
	if flags.HasAny(tcp.FlagSYN) && !flags.HasAny(tcp.FlagACK) {
		offer := flags.HasAll(tcp.FlagECE | tcp.FlagCWR)
		p.peerOffered = offer && (p.peerOffered || !p.synRcvd)
		p.synRcvd = true
		if !offer { // The peer fell back.
			p.echoes, p.ect = false, false
		}
	}
	if flags.HasAny(tcp.FlagCWR) {
		p.echo = false
	}
	p.echo = p.echo || p.echoes && p.ce
	p.ce = false
	return true
}

// PostRx takes the peer's answer to our offer from its SYN-ACK, and owes CWR
// on its ECE once it got our last CWR. It implements [tcp.Policy].
func (p *Policy) PostRx(h *tcp.Handler, _ tcp.State, accepted tcp.Frame) {
	_, flags := accepted.OffsetAndFlags()
	switch {
	case flags.HasAll(tcp.FlagSYN | tcp.FlagACK):
		// A SYN-ACK with CWR too reflects our offer instead of answering it.
		answer := flags.HasAny(tcp.FlagECE) && !flags.HasAny(tcp.FlagCWR)
		p.echoes, p.ect = p.offeredAny && answer, p.offered && answer
	case flags.HasAny(tcp.FlagSYN):
	default:
		if p.cwrSent && !accepted.Ack().LessThan(p.cwrEnd) {
			p.cwrSent = false
		}
		p.cwr = p.cwr || p.ect && !p.cwrSent && flags.HasAny(tcp.FlagECE)
	}
}

// PreTx records the send state. It implements [tcp.Policy].
func (p *Policy) PreTx(h *tcp.Handler, outgoingOpts tcp.Frame) (tcp.Size, tcp.Value, bool) {
	cb := h.ControlBlock()
	p.nxt, p.probing = cb.SendNext(), cb.MaxInFlightData() == 0
	return tcp.TransmitUnlimited, 0, false
}

// PostTx sets the ECN flags of the sent segment and chooses its codepoint. It
// implements [tcp.Policy].
func (p *Policy) PostTx(h *tcp.Handler, outgoing tcp.Frame) {
	seg := outgoing.Segment(len(outgoing.Payload()))
	offset, flags := outgoing.OffsetAndFlags()
	p.codepoint = NotECT
	switch {
	case flags.HasAny(tcp.FlagSYN) && !flags.HasAny(tcp.FlagACK):
		p.offered, p.synSent = !p.synSent, true
		p.offeredAny = p.offeredAny || p.offered
		if p.offered {
			flags |= tcp.FlagECE | tcp.FlagCWR // ECN-setup SYN.
		}
	case flags.HasAny(tcp.FlagSYN):
		p.echoes, p.ect = p.peerOffered, p.peerOffered
		if p.peerOffered {
			flags |= tcp.FlagECE // ECN-setup SYN-ACK.
		}
	case !flags.HasAny(tcp.FlagRST):
		if p.echoes && p.echo {
			flags |= tcp.FlagECE
		}
		if p.ect && seg.DATALEN > 0 && !seg.SEQ.LessThan(p.nxt) && !p.probing {
			p.codepoint = ECT0
			if p.cwr {
				flags |= tcp.FlagCWR
				p.cwr, p.cwrSent, p.cwrEnd = false, true, tcp.Add(seg.SEQ, seg.DATALEN)
			}
		}
	}
	outgoing.SetOffsetAndFlags(offset, flags)
}

// Package sack implements RFC 2018 selective acknowledgement as a [tcp.Policy]
// living outside the core tcp package.
//
// Selective acknowledgement has two halves that are usually described together but
// are entirely separate pieces of code, and this package implements both:
//
//   - as a receiver, it advertises the out-of-order ranges the connection is
//     holding, so the peer learns which of its segments arrived and which did not;
//   - as a sender, it reads those advertisements from the peer and asks for the
//     missing ranges to be resent, one at a time, instead of resending everything
//     from the first hole onward.
//
// Without it a single lost segment costs a sender everything sent after it, because
// a cumulative acknowledgement cannot distinguish "the rest never arrived" from
// "only this one is missing".
//
// The package uses only exported tcp API. Both halves are reached through the
// policy seam: [tcp.TxPlan.Reassembly] reports what the receiver holds, and
// [tcp.TxDirective] carries the resend request.
package sack

import "github.com/soypat/lneto/tcp"

const (
	// maxBlocks is the number of SACK blocks that fit in a TCP header. The option
	// area is 40 octets; four blocks plus the option's own kind and length come to
	// 34, which leaves room for the timestamp option (10) only if one block is
	// dropped. RFC 2018 §3 caps it at four and notes exactly this interaction.
	maxBlocks = 4
	// blockLen is the wire length of one block: two 32-bit sequence numbers.
	blockLen = 8
	// sizeOptionPermitted is the wire length of the SACK-Permitted option.
	sizeOptionPermitted = 2
)

// Block is a range of sequence space the receiver has, expressed as the half-open
// interval [Left, Right). RFC 2018 calls these the left and right edges.
type Block struct {
	Left  tcp.Value
	Right tcp.Value
}

// Len reports the number of octets the block covers.
func (b Block) Len() tcp.Size { return tcp.Sizeof(b.Left, b.Right) }

// Contains reports whether seq falls inside the block.
func (b Block) Contains(seq tcp.Value) bool {
	return !seq.LessThan(b.Left) && seq.LessThan(b.Right)
}

// SACK implements RFC 2018 selective acknowledgement.
//
// The zero value is ready to use and offers the option on the next handshake. It
// carries no retransmission timer of its own: selective acknowledgement decides
// which range to resend, not when, so it is composed with an [rto.Timer] and a
// congestion controller through a [tcp.Composite].
//
// [rto.Timer]: https://pkg.go.dev/github.com/soypat/lneto/tcp/rto#Timer
type SACK struct {
	codec tcp.OptionCodec

	// enabled reports whether both sides agreed to use the option. Only then may
	// blocks be sent or acted on (RFC 2018 §4).
	enabled bool
	// offered reports whether SACK-Permitted was put on a SYN or SYN-ACK that was
	// actually transmitted.
	offered bool
	// peerPermitted reports that the peer's SYN carried SACK-Permitted.
	peerPermitted bool
	// wrotePermitted stages that SACK-Permitted was written into the segment being
	// built. Negotiation is committed in PostTx, because a segment that is built is
	// not yet a segment the peer has seen.
	wrotePermitted bool
}

var _ tcp.Policy = (*SACK)(nil)

// Reset returns the policy to its initial per-connection state. It implements
// [tcp.Policy].
func (s *SACK) Reset() { *s = SACK{} }

// Enabled reports whether the option was successfully negotiated with the peer.
func (s *SACK) Enabled() bool { return s.enabled }

// NextDeadline reports no deadline: selective acknowledgement decides what to
// resend, never when. It implements [tcp.Policy].
func (s *SACK) NextDeadline() int64 { return 0 }

// PreRx notes the peer's SACK-Permitted option during the handshake and keeps every
// segment. It implements [tcp.Policy].
//
// Only the handshake is handled here. Blocks carried by a segment are read in
// [SACK.PostRx], because a block from a segment the connection refused describes a
// send sequence this side may not share.
func (s *SACK) PreRx(rx tcp.RxMeta) tcp.RxDirective {
	if rx.Segment.Flags.HasAny(tcp.FlagSYN) && s.hasPermitted(rx.Options) {
		s.peerPermitted = true
		if rx.Segment.Flags.HasAny(tcp.FlagACK) {
			// A SYN-ACK answering our offer completes the negotiation.
			s.enabled = s.offered
		}
	}
	return tcp.RxDirective{Keep: true}
}

// WriteOptions offers SACK-Permitted during the handshake. It implements
// [tcp.Policy].
//
// It records nothing about the negotiation: the segment may never be sent, and
// treating the option as agreed on the strength of having written it would have this
// side act on blocks a peer never agreed to send. The agreement is committed in
// [SACK.PostTx].
func (s *SACK) WriteOptions(plan tcp.TxPlan, opts []byte) uint8 {
	s.wrotePermitted = false
	switch plan.Kind {
	case tcp.TxKindSYN:
		// §2: offer the option. Nothing has been received to acknowledge yet.
	case tcp.TxKindSYNACK:
		if !s.peerPermitted {
			return 0 // Only answer a peer that offered.
		}
	default:
		return 0 // Blocks are written by a later slice of this work.
	}
	if len(opts) < sizeOptionPermitted {
		return 0
	}
	n, err := s.codec.PutOption(opts, tcp.OptSACKPermitted)
	if err != nil || n < 0 {
		return 0
	}
	s.wrotePermitted = true
	return uint8(n)
}

// PostTx commits the negotiation for an option that has actually been transmitted.
// It implements [tcp.Policy].
func (s *SACK) PostTx(outgoing tcp.Segment, now int64) {
	if !s.wrotePermitted {
		return
	}
	s.wrotePermitted = false
	if !outgoing.Flags.HasAny(tcp.FlagSYN) {
		return
	}
	s.offered = true
	if outgoing.Flags.HasAny(tcp.FlagACK) {
		// A transmitted SYN-ACK means the option has been both received and sent.
		s.enabled = s.peerPermitted
	}
}

// PostRx does nothing yet. It implements [tcp.Policy].
func (s *SACK) PostRx(event tcp.RxEvent) {}

// PreTx requests nothing yet. It implements [tcp.Policy].
func (s *SACK) PreTx(intent tcp.TxIntent) tcp.TxDirective { return tcp.TxDirective{} }

// hasPermitted reports whether the option area carries SACK-Permitted.
func (s *SACK) hasPermitted(opts []byte) (found bool) {
	if len(opts) == 0 {
		return false
	}
	s.codec.ForEachOption(opts, func(kind tcp.OptionKind, _ []byte) error {
		if kind == tcp.OptSACKPermitted {
			found = true
		}
		return nil
	})
	return found
}

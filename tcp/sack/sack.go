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

	// acked is the scoreboard: the ranges the peer has reported holding, above the
	// cumulative acknowledgement. RFC 6675 §2 calls this the scoreboard and derives
	// what to retransmit from it. It is a fixed array so the sender allocates
	// nothing, holding as many ranges as a peer can report in one segment.
	acked  [maxBlocks]Block
	nAcked int
	// una is the cumulative acknowledgement the scoreboard is relative to. Ranges
	// below it are acknowledged outright and are dropped.
	una     tcp.Value
	haveUNA bool
	// resendFrom names the hole to ask for on the next transmit, valid while
	// resendPending. One hole is requested per transmit, because a segment carries
	// one range; the next transmit asks for the next.
	resendFrom    tcp.Value
	resendPending bool
}

var _ tcp.Policy = (*SACK)(nil)

// Reset returns the policy to its initial per-connection state, including the
// scoreboard. It implements [tcp.Policy].
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
		// Post-handshake: report the ranges held out of order, so the peer learns
		// which of its segments arrived. RFC 2018 §3 forbids the option on a SYN.
		return s.writeBlocks(plan, opts)
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

// writeBlocks advertises the out-of-order data the connection is holding.
//
// The blocks are read here, while the outgoing segment is being built, rather than
// when the data arrived: what matters is what is still held at the moment the peer
// is told about it. A block recorded on receipt could have been delivered in the
// meantime, and reporting it would tell the peer a hole had been filled when the
// receiver has already moved past it.
func (s *SACK) writeBlocks(plan tcp.TxPlan, opts []byte) uint8 {
	if !s.enabled {
		return 0
	}
	held := plan.Reassembly.Len()
	if held == 0 {
		return 0 // Nothing out of order: the cumulative acknowledgement says it all.
	}
	// Fit as many blocks as the option area allows, highest sequence first, so the
	// blocks most likely to be dropped for want of room are the oldest.
	//
	// RFC 2018 §4 asks for the first block to be the one containing the segment that
	// triggered this acknowledgement. Highest-sequence-first is that block whenever
	// the arriving segment extended the furthest range, which is the ordinary case
	// of a single hole with data accumulating past it. It can differ when a segment
	// fills a lower gap while higher data is also held; the blocks reported are the
	// same, only their order differs, and no sender depends on that order for
	// correctness — it decides which range to report first when they do not all fit.
	room := blocksThatFit(len(opts))
	if room == 0 {
		return 0
	}
	// Walk the held ranges from the highest sequence down, merging ones that touch.
	// The receive path holds a range per arriving segment, so data accumulating
	// behind a hole is many adjacent ranges describing one gap-free region. Reported
	// separately they would spend the whole option area restating that region and
	// crowd out the genuinely separate holes a sender needs to know about.
	var blocks [maxBlocks]Block
	n := 0
	for i := held - 1; i >= 0 && n < room; i-- {
		left, right := plan.Reassembly.Block(i)
		if n > 0 && blocks[n-1].Left == right {
			blocks[n-1].Left = left // Contiguous with the block already recorded.
			continue
		}
		blocks[n] = Block{Left: left, Right: right}
		n++
	}
	return s.putBlocks(opts, blocks[:n])
}

// blocksThatFit reports how many blocks the option area can hold, capped at the
// number a TCP header has room for.
func blocksThatFit(space int) int {
	n := (space - 2) / blockLen // Less the option's own kind and length octets.
	if n < 0 {
		return 0
	}
	return min(n, maxBlocks)
}

// putBlocks serializes blocks into the option area, writing nothing if they do not
// fit. It is separate from collecting them so the space arithmetic can be exercised
// without a connection holding real out-of-order data.
func (s *SACK) putBlocks(opts []byte, blocks []Block) uint8 {
	if len(blocks) == 0 || len(blocks) > blocksThatFit(len(opts)) {
		return 0
	}
	var data [maxBlocks * blockLen]byte
	for i, b := range blocks {
		put32(data[i*blockLen:], uint32(b.Left))
		put32(data[i*blockLen+4:], uint32(b.Right))
	}
	written, err := s.codec.PutOption(opts, tcp.OptSACK, data[:len(blocks)*blockLen]...)
	if err != nil || written < 0 {
		return 0
	}
	return uint8(written)
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

// PostRx records the ranges the peer reports holding and works out which hole to ask
// for. It implements [tcp.Policy].
//
// Blocks are read here rather than in PreRx because a block describes this side's send
// sequence, and a segment the connection refused carries no claim about it worth
// acting on: retransmitting on the strength of a rejected segment's option is doing
// work an attacker or a stale duplicate asked for.
func (s *SACK) PostRx(event tcp.RxEvent) {
	if !s.enabled || !event.Accepted || !event.Segment.Flags.HasAny(tcp.FlagACK) {
		return
	}
	ack := event.Segment.ACK
	if s.haveUNA && ack.LessThan(s.una) {
		return // Older than what is already known acknowledged.
	}
	s.una, s.haveUNA = ack, true
	s.parseBlocks(event.Options, ack)
	s.planResend()
}

// PreTx asks for the hole the scoreboard has identified. It implements [tcp.Policy].
//
// One hole is requested per transmit. A segment carries one range, so there is nothing
// to gain from naming more, and asking again on the next transmit keeps the request
// answering the newest scoreboard rather than a plan made before the last
// acknowledgement arrived.
func (s *SACK) PreTx(intent tcp.TxIntent) tcp.TxDirective {
	if !s.enabled || !s.resendPending {
		return tcp.TxDirective{}
	}
	from := s.resendFrom
	if from.LessThan(intent.UNA) {
		// The hole has been acknowledged since it was identified.
		s.resendPending = false
		return tcp.TxDirective{}
	}
	if !from.LessThan(intent.NXT) {
		s.resendPending = false
		return tcp.TxDirective{} // Nothing sent from there to resend.
	}
	s.resendPending = false
	return tcp.TxDirective{Retransmit: true, RetransmitFrom: from}
}

// parseBlocks refreshes the scoreboard from a segment's option area, discarding
// ranges the cumulative acknowledgement has overtaken.
func (s *SACK) parseBlocks(opts []byte, ack tcp.Value) {
	s.nAcked = 0
	if len(opts) == 0 {
		return
	}
	s.codec.ForEachOption(opts, func(kind tcp.OptionKind, data []byte) error {
		if kind != tcp.OptSACK || len(data)%blockLen != 0 {
			return nil
		}
		for off := 0; off+blockLen <= len(data) && s.nAcked < len(s.acked); off += blockLen {
			b := Block{
				Left:  tcp.Value(get32(data[off:])),
				Right: tcp.Value(get32(data[off+4:])),
			}
			if !b.Left.LessThan(b.Right) || b.Right.LessThanEq(ack) {
				// Empty, reversed, or already covered by the cumulative
				// acknowledgement. A peer is not trusted to report either.
				continue
			}
			if b.Left.LessThan(ack) {
				b.Left = ack // Clamp to the part still outstanding.
			}
			s.acked[s.nAcked] = b
			s.nAcked++
		}
		return nil
	})
}

// planResend picks the first hole below the reported ranges: the octet at the
// cumulative acknowledgement, when the peer has reported holding anything above it.
//
// That the peer holds data above the acknowledgement is itself the loss signal, and a
// stronger one than a duplicate acknowledgement: it says not merely that something is
// missing but that later data arrived, so what is missing is the range starting where
// the stream stalled.
func (s *SACK) planResend() {
	if s.nAcked == 0 {
		s.resendPending = false
		return
	}
	// Only ask for the hole if there is one, meaning a reported range starts above
	// the cumulative acknowledgement rather than at it.
	lowest := s.acked[0]
	for _, b := range s.acked[1:s.nAcked] {
		if b.Left.LessThan(lowest.Left) {
			lowest = b
		}
	}
	if !s.una.LessThan(lowest.Left) {
		s.resendPending = false // The peer's ranges start at the acknowledgement.
		return
	}
	s.resendFrom, s.resendPending = s.una, true
}

// Acked returns the ranges the peer has reported holding above the cumulative
// acknowledgement, in the order reported. The slice is only valid until the next
// received segment and must not be retained.
func (s *SACK) Acked() []Block { return s.acked[:s.nAcked] }

// Holes reports whether the peer has told us something is missing: it holds data
// above the cumulative acknowledgement, so the range starting there was lost.
func (s *SACK) Holes() bool { return s.resendPending }

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

func put32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
}

func get32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

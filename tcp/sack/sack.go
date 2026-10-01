// Package sack implements TCP selective acknowledgement (RFC 2018) as a
// [tcp.Policy]: as a receiver it reports held out-of-order ranges, and as a
// sender it resends the holes the peer reports (RFC 6675). It decides what to
// resend, not when, so it is meant to run beside a retransmission timer such as
// rto.Timer in [tcp.Policies].
package sack

import "github.com/soypat/lneto/tcp"

const (
	// maxBlocks is the number of SACK blocks that fit the 40-octet option area
	// together with the two leading no-operation octets (RFC 2018 §3).
	maxBlocks = 4
	blockLen  = 8
	// maxScoreboard bounds the disjoint ranges remembered as received by the peer.
	maxScoreboard = 8
	// dupThresh is the loss threshold of RFC 6675 §2, in segments.
	dupThresh = 3
	// defaultSMSS is assumed until a data segment has been sent (RFC 9293 §3.7.1).
	defaultSMSS = 536
	maxOptions  = 40
)

// Block is the half-open sequence range [Left, Right).
type Block struct {
	Left, Right tcp.Value
}

// Policy implements selective acknowledgement. Blocks are sent and acted on
// only once both sides offered SACK-Permitted in the handshake (RFC 2018 §2).
// The zero value is ready to use.
type Policy struct {
	codec tcp.OptionCodec

	// Handshake.
	offered        bool // SACK-Permitted sent on our SYN or SYN-ACK.
	peerPermitted  bool // SACK-Permitted received on the peer's SYN.
	wrotePermitted bool // Written in PreTx, committed in PostTx once sent.
	enabled        bool

	// Receiver: start of the latest out-of-order arrival, reported first.
	lastRecv     tcp.Value
	haveLastRecv bool

	// Sender (RFC 6675 §2): ranges the peer reported, ascending and above UNA.
	scoreboard [maxScoreboard]Block
	nblocks    int
	smss       tcp.Size
	sndMax     tcp.Value // End of the highest data sent, to tell resends apart.
	haveSndMax bool
	recovering bool
	recoverAt  tcp.Value // RFC 6675 RecoveryPoint.
	highRxt    tcp.Value // RFC 6675 HighRxt: resent up to here this recovery.
	// requested is the hole asked for by the last PreTx, valid while
	// haveRequested.
	requested     tcp.Value
	haveRequested bool
}

var _ tcp.Policy = (*Policy)(nil)

// Reset implements [tcp.Policy].
func (p *Policy) Reset() { *p = Policy{} }

// Enabled reports whether both sides agreed to selective acknowledgement.
func (p *Policy) Enabled() bool { return p.enabled }

// Scoreboard returns the ranges the peer reported holding above SND.UNA, in
// ascending order. The slice is valid until the next received segment.
func (p *Policy) Scoreboard() []Block { return p.scoreboard[:p.nblocks] }

// PreRx notes SACK-Permitted on the peer's SYN and where out-of-order data
// arrives. It keeps every segment. It implements [tcp.Policy].
func (p *Policy) PreRx(h *tcp.Handler, incoming tcp.Frame) bool {
	seg := incoming.Segment(len(incoming.Payload()))
	if seg.Flags.HasAny(tcp.FlagSYN) && p.hasPermitted(incoming.Options()) {
		p.peerPermitted = true
		if seg.Flags.HasAny(tcp.FlagACK) {
			p.enabled = p.offered // SYN-ACK answering our offer.
		}
	}
	if p.enabled && seg.DATALEN > 0 && seg.SEQ != h.ControlBlock().RecvNext() {
		p.lastRecv, p.haveLastRecv = seg.SEQ, true
	}
	return true
}

// PostRx records the blocks of an accepted acknowledgement and enters or leaves
// loss recovery. Blocks of refused segments are ignored. It implements
// [tcp.Policy].
func (p *Policy) PostRx(h *tcp.Handler, _ tcp.State, accepted tcp.Frame) {
	seg := accepted.Segment(len(accepted.Payload()))
	if !p.enabled || !seg.Flags.HasAny(tcp.FlagACK) {
		return
	}
	una, nxt := h.ControlBlock().SendUNA(), h.ControlBlock().SendNext()
	p.prune(una)
	p.codec.ForEachOption(accepted.Options(), func(kind tcp.OptionKind, data []byte) error {
		if kind != tcp.OptSACK {
			return nil
		}
		for ; len(data) >= blockLen; data = data[blockLen:] {
			b := Block{Left: tcp.Value(get32(data)), Right: tcp.Value(get32(data[4:]))}
			// Ignore empty, reversed, unsent and fully acknowledged blocks; a
			// block below UNA is a D-SACK (RFC 2883) and reports nothing new.
			if !b.Left.LessThan(b.Right) || nxt.LessThan(b.Right) || b.Right.LessThanEq(una) {
				continue
			}
			if b.Left.LessThan(una) {
				b.Left = una
			}
			p.insert(b)
		}
		return nil
	})
	if p.recovering && !una.LessThan(p.recoverAt) {
		p.recovering = false // RFC 6675 §5 step (B): recovery complete.
	}
	if !p.recovering && p.isLost(una) {
		p.recovering, p.recoverAt, p.highRxt = true, nxt, una // RFC 6675 §5 step (4).
	}
}

// PreTx offers SACK-Permitted on handshake segments, writes the receiver's
// blocks and, during loss recovery, asks for the next lost hole. It implements
// [tcp.Policy].
func (p *Policy) PreTx(h *tcp.Handler, outgoingOpts tcp.Frame) (tcp.Size, tcp.Value, bool) {
	p.wrotePermitted, p.haveRequested = false, false
	if syn, ack := h.NextSegmentSYN(); syn {
		if !ack || p.peerPermitted {
			p.wrotePermitted = p.writeOption(outgoingOpts, 0, tcp.OptSACKPermitted, nil)
		}
		return tcp.TransmitUnlimited, 0, false
	}
	if !p.enabled {
		return tcp.TransmitUnlimited, 0, false
	}
	p.writeBlocks(h.Reassembly(), outgoingOpts)
	if !p.recovering {
		return tcp.TransmitUnlimited, 0, false
	}
	hole, ok := p.nextHole(h.ControlBlock().SendUNA(), h.BufferedUnsent() == 0)
	p.requested, p.haveRequested = hole, ok
	return tcp.TransmitUnlimited, hole, ok
}

// PostTx commits the SACK-Permitted offer once sent and advances HighRxt past
// resent data. It implements [tcp.Policy].
func (p *Policy) PostTx(h *tcp.Handler, outgoing tcp.Frame) {
	seg := outgoing.Segment(len(outgoing.Payload()))
	if p.wrotePermitted && seg.Flags.HasAny(tcp.FlagSYN) {
		p.offered = true
		if seg.Flags.HasAny(tcp.FlagACK) {
			p.enabled = p.peerPermitted // SYN-ACK answering the peer's offer.
		}
	}
	p.wrotePermitted = false
	if seg.DATALEN == 0 {
		return
	}
	p.smss = max(p.smss, seg.DATALEN)
	end := tcp.Add(seg.SEQ, seg.DATALEN)
	if !p.haveSndMax || p.sndMax.LessThan(end) {
		p.sndMax, p.haveSndMax = end, true
		return // New data.
	}
	if !p.recovering {
		return
	}
	if p.highRxt.LessThan(end) {
		p.highRxt = end
	}
	if p.haveRequested && !p.requested.LessThan(end) {
		// The requested hole starts mid-packet and only the packet's head fit,
		// so asking again would resend the same head forever. Leave the rest of
		// this hole to the retransmission timer.
		p.highRxt = p.holeEnd(p.requested)
	}
	p.haveRequested = false
}

// holeEnd returns the left edge of the lowest SACKed range above seq, or the
// end of sent data when there is none.
func (p *Policy) holeEnd(seq tcp.Value) tcp.Value {
	for _, b := range p.scoreboard[:p.nblocks] {
		if seq.LessThan(b.Left) {
			return b.Left
		}
	}
	return p.sndMax
}

// nextHole returns the start of the lowest unacknowledged range at or above
// HighRxt and below the highest SACKed octet that IsLost deems lost (RFC 6675
// NextSeg rule 1), or any such range when there is no new data to send instead
// (rule 3).
func (p *Policy) nextHole(una tcp.Value, noNewData bool) (tcp.Value, bool) {
	cursor := p.highRxt
	if cursor.LessThan(una) {
		cursor = una
	}
	for _, b := range p.scoreboard[:p.nblocks] {
		if cursor.LessThan(b.Left) {
			// Higher holes have less data SACKed above them, so none is lost if
			// this one is not.
			return cursor, noNewData || p.isLost(cursor)
		}
		if cursor.LessThan(b.Right) {
			cursor = b.Right
		}
	}
	return 0, false // No hole below the highest SACKed octet.
}

// isLost reports whether more than (DupThresh-1)*SMSS octets above seq were
// SACKed (RFC 6675 §4 IsLost).
func (p *Policy) isLost(seq tcp.Value) bool {
	smss := p.smss
	if smss == 0 {
		smss = defaultSMSS
	}
	var above tcp.Size
	for _, b := range p.scoreboard[:p.nblocks] {
		switch {
		case !seq.LessThan(b.Right):
		case seq.LessThan(b.Left):
			above += tcp.Sizeof(b.Left, b.Right)
		default:
			above += tcp.Sizeof(seq, b.Right)
		}
	}
	return above > (dupThresh-1)*smss
}

// insert merges b into the ascending, disjoint scoreboard. When full, the
// highest range is dropped: holes are repaired from the lowest up.
func (p *Policy) insert(b Block) {
	sb := &p.scoreboard
	i := 0
	for i < p.nblocks && sb[i].Right.LessThan(b.Left) {
		i++
	}
	j := i
	for ; j < p.nblocks && !b.Right.LessThan(sb[j].Left); j++ {
		if sb[j].Left.LessThan(b.Left) {
			b.Left = sb[j].Left
		}
		if b.Right.LessThan(sb[j].Right) {
			b.Right = sb[j].Right
		}
	}
	if i == j && p.nblocks == maxScoreboard {
		if i == maxScoreboard {
			return // Above every range held: drop it.
		}
		p.nblocks--
	}
	n := copy(sb[i+1:], sb[j:p.nblocks])
	sb[i] = b
	p.nblocks = i + 1 + n
}

// prune drops what the cumulative acknowledgement una now covers.
func (p *Policy) prune(una tcp.Value) {
	n := 0
	for _, b := range p.scoreboard[:p.nblocks] {
		if !una.LessThan(b.Right) {
			continue
		}
		if b.Left.LessThan(una) {
			b.Left = una
		}
		p.scoreboard[n] = b
		n++
	}
	p.nblocks = n
}

// writeBlocks reports the held out-of-order ranges, merging adjacent ones. The
// block holding the latest arrival goes first (RFC 2018 §4), the rest highest
// first.
func (p *Policy) writeBlocks(held tcp.ReassemblyView, frm tcp.Frame) {
	if held.Len() == 0 {
		return
	}
	offset, _ := frm.OffsetAndFlags()
	used := int(offset)*4 - 20
	room := min(maxBlocks, (maxOptions-used-4)/blockLen)
	if room <= 0 {
		return
	}
	var blocks [maxScoreboard]Block
	n := 0
	for i := held.Len() - 1; i >= 0; i-- {
		left, right := held.Block(i)
		if n > 0 && blocks[n-1].Left == right {
			blocks[n-1].Left = left
			continue
		} else if n == len(blocks) {
			break
		}
		blocks[n] = Block{Left: left, Right: right}
		n++
	}
	for i := 1; i < n && p.haveLastRecv; i++ {
		if b := blocks[i]; !p.lastRecv.LessThan(b.Left) && p.lastRecv.LessThan(b.Right) {
			copy(blocks[1:i+1], blocks[:i])
			blocks[0] = b
			break
		}
	}
	n = min(n, room)
	var data [maxBlocks * blockLen]byte
	for i, b := range blocks[:n] {
		put32(data[i*blockLen:], uint32(b.Left))
		put32(data[i*blockLen+4:], uint32(b.Right))
	}
	p.writeOption(frm, 2, tcp.OptSACK, data[:n*blockLen])
}

// writeOption appends nops leading no-operation octets and the option after
// the options already in frm, padding to a word, and raises the data offset.
func (p *Policy) writeOption(frm tcp.Frame, nops int, kind tcp.OptionKind, data []byte) bool {
	offset, flags := frm.OffsetAndFlags()
	used := int(offset)*4 - 20
	size := nops + 2 + len(data)
	words := (size + 3) / 4
	if used+words*4 > maxOptions {
		return false
	}
	frm.SetOffsetAndFlags(offset+uint8(words), flags)
	opts := frm.Options()[used:]
	for i := range opts {
		opts[i] = byte(tcp.OptNop)
	}
	_, err := p.codec.PutOption(opts[nops:], kind, data...)
	return err == nil
}

func (p *Policy) hasPermitted(opts []byte) (found bool) {
	p.codec.ForEachOption(opts, func(kind tcp.OptionKind, _ []byte) error {
		found = found || kind == tcp.OptSACKPermitted
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

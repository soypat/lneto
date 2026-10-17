// Package timestamps implements the TCP Timestamps option (RFC 7323) as a
// [tcp.Policy]: it negotiates the option, stamps and echoes timestamps,
// rejects old duplicates with PAWS and measures the round-trip time from the
// echo of every acknowledgment of new data, which it can feed to an
// [rto.Timer] running beside it in [tcp.Policies].
package timestamps

import (
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/tcp/rto"
)

const (
	optDataLen = 8 // TSval and TSecr.
	maxOptions = 40
	// tick is the timestamp clock period, within the 1 ms to 1 s that RFC 7323
	// §5.4 allows.
	tick = time.Millisecond
	// pawsIdle is how long TS.Recent stays valid without being updated (RFC
	// 7323 §5.5).
	pawsIdle = 24 * 24 * time.Hour
	// defaultSMSS is assumed until a data segment has been sent (RFC 9293 §3.7.1).
	defaultSMSS = 536
)

// Config configures a [Policy].
type Config struct {
	// Nanotime returns monotonic time in nanoseconds. It drives the timestamp
	// clock. Required.
	Nanotime func() int64
	// PAWS rejects segments whose timestamp is older than TS.Recent (RFC 7323
	// §5).
	PAWS bool
	// Timer, if set, receives the round-trip samples and then takes none of its
	// own. The Timer is not driven by this Policy and must be installed beside
	// it.
	Timer *rto.Timer
}

// Policy implements the Timestamps option. Timestamps are sent and acted on
// only once both sides sent the option in the handshake (RFC 7323 §3.2).
// Configure it before use.
type Policy struct {
	codec    tcp.OptionCodec
	nanotime func() int64
	paws     bool
	timer    *rto.Timer

	// Handshake.
	peerOffered bool // Option received on the peer's SYN.
	offered     bool // Option sent on our SYN or SYN-ACK.
	wrote       bool // Written in PreTx, committed in PostTx once sent.
	enabled     bool

	epoch     int64  // Clock value TSval counts from.
	offset    uint32 // TSval at epoch: the ISS, random per connection.
	haveEpoch bool

	// TS.Recent, the peer's timestamp to echo, and when it was last updated.
	recent     uint32
	recentAt   int64
	haveRecent bool

	lastACK     tcp.Value // Last.ACK.sent (RFC 7323 §4.3).
	haveLastACK bool

	una     tcp.Value // SND.UNA before the segment being received.
	smss    tcp.Size  // Largest payload sent.
	lastRTT time.Duration
	haveRTT bool
}

var _ tcp.Policy = (*Policy)(nil)

// Configure applies cfg and resets the Policy.
func (p *Policy) Configure(cfg Config) error {
	if cfg.Nanotime == nil {
		return lneto.ErrMissingHALConfig
	}
	*p = Policy{nanotime: cfg.Nanotime, paws: cfg.PAWS, timer: cfg.Timer}
	return nil
}

// Reset clears the per-connection state, keeping the configuration. It
// implements [tcp.Policy].
func (p *Policy) Reset() {
	*p = Policy{nanotime: p.nanotime, paws: p.paws, timer: p.timer}
}

// Enabled reports whether both sides agreed to send timestamps.
func (p *Policy) Enabled() bool { return p.enabled }

// Recent returns TS.Recent, the peer timestamp echoed in outgoing segments.
func (p *Policy) Recent() (tsval uint32, ok bool) { return p.recent, p.haveRecent }

// LastRTT returns the latest round-trip time measured from an echo.
func (p *Policy) LastRTT() (rtt time.Duration, ok bool) { return p.lastRTT, p.haveRTT }

// PreRx drops, once timestamps are in use, a segment without the option or,
// with PAWS, with one older than TS.Recent. A segment dropped by PAWS is
// answered with an ACK. A RST, and a SYN before the connection is synchronized,
// are never dropped. It implements [tcp.Policy].
func (p *Policy) PreRx(h *tcp.Handler, incoming tcp.Frame) bool {
	seg := incoming.Segment(len(incoming.Payload()))
	if !p.enabled || seg.Flags.HasAny(tcp.FlagRST) ||
		(seg.Flags.HasAny(tcp.FlagSYN) && !h.State().IsSynchronized()) {
		return true
	}
	tsval, _, present := p.parse(incoming.Options())
	if !present {
		return false // RFC 7323 §3.2.
	}
	if p.paws && p.recentValid() && lessThan(tsval, p.recent) {
		h.ControlBlock().QueueACK() // RFC 7323 §5.3 R1.
		return false
	}
	p.una = h.ControlBlock().SendUNA()
	return true
}

// PostRx records the option on the peer's SYN accepted during the handshake,
// updates TS.Recent from an accepted segment (RFC 7323 §4.3) and takes a
// round-trip sample when it acknowledges new data (§4.1). It implements
// [tcp.Policy].
func (p *Policy) PostRx(h *tcp.Handler, prevState tcp.State, accepted tcp.Frame) {
	seg := accepted.Segment(len(accepted.Payload()))
	tsval, tsecr, present := p.parse(accepted.Options())
	if seg.Flags.HasAny(tcp.FlagSYN) {
		if present && !prevState.IsSynchronized() {
			p.peerOffered = true
			p.setRecent(tsval)
			if seg.Flags.HasAny(tcp.FlagACK) {
				p.enabled = p.offered // SYN-ACK answering our offer.
			}
		}
		return
	}
	if !p.enabled || !present {
		return
	}
	// A segment above Last.ACK.sent, as one following another before an ACK
	// went out, must not move the echo forward. An outdated TS.Recent is
	// replaced (RFC 7323 §5.5).
	if (!p.recentValid() || !lessThan(tsval, p.recent)) && p.haveLastACK && seg.SEQ.LessThanEq(p.lastACK) {
		p.setRecent(tsval)
	}
	una := h.ControlBlock().SendUNA()
	if !seg.Flags.HasAny(tcp.FlagACK) || !p.una.LessThan(una) {
		return
	}
	elapsed := int32(p.tsval() - tsecr)
	if elapsed < 0 || lessThan(tsecr, p.offset) {
		return // Echo of a timestamp not sent on this connection.
	}
	rtt := time.Duration(elapsed) * tick
	p.lastRTT, p.haveRTT = rtt, true
	if p.timer != nil {
		// RFC 7323 Appendix G: ExpectedSamples = ceil(FlightSize / (2*SMSS)).
		smss := p.smss
		if smss == 0 {
			smss = defaultSMSS
		}
		flight := tcp.Sizeof(p.una, h.ControlBlock().SendNext())
		p.timer.ObserveRTTPerFlight(rtt, int((flight+2*smss-1)/(2*smss)))
	}
}

// PreTx offers the option on a SYN, answers a peer's offer on the SYN-ACK and
// stamps every later segment once timestamps are in use. It implements
// [tcp.Policy].
func (p *Policy) PreTx(h *tcp.Handler, outgoingOpts tcp.Frame) (tcp.Size, tcp.Value, bool) {
	p.wrote = false
	syn, ack := h.NextSegmentSYN()
	if (syn && ack && !p.peerOffered) || (!syn && !p.enabled) {
		return tcp.TransmitUnlimited, 0, false
	}
	if !p.haveEpoch {
		p.epoch, p.offset, p.haveEpoch = p.nanotime(), uint32(h.ISS()), true
	}
	var data [optDataLen]byte
	put32(data[:4], p.tsval())
	if p.haveRecent {
		put32(data[4:], p.recent) // TSecr is zero on our SYN (RFC 7323 §3.2).
	}
	p.wrote = p.writeOption(outgoingOpts, data[:])
	return tcp.TransmitUnlimited, 0, false
}

// PostTx commits the handshake offer once sent and records Last.ACK.sent and
// the largest payload sent. It implements [tcp.Policy].
func (p *Policy) PostTx(h *tcp.Handler, outgoing tcp.Frame) {
	seg := outgoing.Segment(len(outgoing.Payload()))
	if p.wrote && seg.Flags.HasAny(tcp.FlagSYN) {
		p.offered = true
		if seg.Flags.HasAny(tcp.FlagACK) {
			p.enabled = p.peerOffered // SYN-ACK answering the peer's offer.
		}
	}
	p.wrote = false
	if seg.Flags.HasAny(tcp.FlagACK) {
		p.lastACK, p.haveLastACK = seg.ACK, true
	}
	p.smss = max(p.smss, seg.DATALEN)
}

func (p *Policy) setRecent(tsval uint32) {
	p.recent, p.recentAt, p.haveRecent = tsval, p.nanotime(), true
}

// recentValid reports whether TS.Recent is set and was updated within the
// last 24 days (RFC 7323 §5.5).
func (p *Policy) recentValid() bool {
	return p.haveRecent && p.nanotime()-p.recentAt <= int64(pawsIdle)
}

// tsval returns the current timestamp clock value. It starts at the ISS, so
// it does not reveal the host's uptime (RFC 7323 §7.1).
func (p *Policy) tsval() uint32 {
	return p.offset + uint32((p.nanotime()-p.epoch)/int64(tick))
}

// writeOption appends two no-operation octets and the option after the
// options already in frm, the layout of RFC 7323 Appendix A, and raises the
// data offset.
func (p *Policy) writeOption(frm tcp.Frame, data []byte) bool {
	const size = 2 + 2 + optDataLen
	offset, flags := frm.OffsetAndFlags()
	used := int(offset)*4 - 20
	if used+size > maxOptions {
		return false
	}
	frm.SetOffsetAndFlags(offset+size/4, flags)
	opts := frm.Options()[used:]
	opts[0], opts[1] = byte(tcp.OptNop), byte(tcp.OptNop)
	_, err := p.codec.PutOption(opts[2:], tcp.OptTimestamps, data...)
	return err == nil
}

func (p *Policy) parse(opts []byte) (tsval, tsecr uint32, present bool) {
	p.codec.ForEachOption(opts, func(kind tcp.OptionKind, data []byte) error {
		if kind == tcp.OptTimestamps && len(data) == optDataLen {
			tsval, tsecr, present = get32(data), get32(data[4:]), true
		}
		return nil
	})
	return tsval, tsecr, present
}

// lessThan compares timestamps modulo 2^32 (RFC 7323 §5.2).
func lessThan(a, b uint32) bool { return int32(a-b) < 0 }

func put32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
}

func get32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

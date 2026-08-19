// Package timestamps implements the RFC 7323 TCP Timestamps option as a
// [tcp.Policy] policy living outside the core tcp package.
//
// It negotiates the option during the handshake, echoes the peer's TSval per
// RFC 7323 §4.3, measures the round-trip time from the echo it gets back, and
// optionally rejects segments whose timestamp is older than the one recorded
// (PAWS, §5).
//
// The package uses only exported tcp API. It is the counterpart to
// tcp/congestion for the option-bearing half of the seam: where a congestion
// controller only needs send-state metadata, an option-negotiating extension
// needs to read incoming options and write outgoing ones, which the seam
// provides through [tcp.RxMeta.Options] and [tcp.Policy.WriteOptions].
package timestamps

import (
	"time"

	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/tcp/rto"
)

const (
	// optLen is the length of the Timestamps option: kind, length, TSval, TSecr.
	optLen = 10
	// optDataLen is the length of the option's payload.
	optDataLen = 8
	// nanosPerMilli converts the connection clock to the millisecond granularity
	// this implementation ticks TSval at. RFC 7323 §5.4 requires a tick between
	// 1 ms and 1 s.
	nanosPerMilli = 1_000_000
	// maxPlausibleRTTMillis bounds an RTT derived from an echoed timestamp. A
	// larger value means the echo is stale, forged or from a clock that does not
	// match ours, so the sample is discarded rather than poisoning the estimator.
	maxPlausibleRTTMillis = 120_000
)

// Timestamps implements RFC 7323 timestamp negotiation, echoing and RTT
// measurement as a [tcp.Policy].
//
// It composes a [rto.Timer] so that installing it also installs RFC 6298
// retransmission timing; round-trip samples taken from echoed timestamps are
// handed to that timer, which is the point of the option for a sender.
//
// The zero value is ready to use and offers the option on the next handshake.
type Timestamps struct {
	// timer provides retransmission timing. Timestamp-derived samples are fed to
	// it in addition to the samples it takes from acknowledgments. Used only when
	// no shared timer is set.
	timer rto.Timer
	// shared is a timer owned and driven by someone else, set by
	// [Timestamps.SetTimer]. When set this policy feeds samples to it and reads it
	// but does not drive it, since a timer driven twice observes every segment twice.
	shared *rto.Timer
	// codec serializes and walks the option area.
	codec tcp.OptionCodec

	// enabled reports whether both sides agreed to use timestamps. It is only
	// set once the handshake exchanged the option in both directions.
	enabled bool
	// offered reports whether this side put the option in a SYN or SYN-ACK that
	// was actually transmitted, so a peer echo can be interpreted.
	offered bool
	// wrote reports that the option was written into the segment currently being
	// built. It is staging for PostTx, not negotiation state: WriteOptions may be
	// called for a segment that is never sent, so what it wrote is only known to
	// have reached the peer once the transmit path reports the segment. Cleared at
	// the start of every WriteOptions so an abandoned attempt cannot be committed
	// by a later one.
	wrote bool

	// recent is TS.Recent: the most recent timestamp value received that is
	// eligible to be echoed back (§4.3).
	recent uint32
	// haveRecent guards recent before the first timestamp arrives.
	haveRecent bool

	// epoch is the clock value the connection's TSval counts from, so timestamps
	// start near zero rather than at an arbitrary uptime.
	epoch     int64
	haveEpoch bool

	// paws enables Protection Against Wrapped Sequences (§5).
	paws bool

	// lastRTT is the most recent round-trip sample derived from an echo, in
	// nanoseconds. haveRTT guards it because a sub-millisecond round trip is a
	// legitimate sample of zero.
	lastRTT int64
	haveRTT bool
}

var _ tcp.Policy = (*Timestamps)(nil)

// Config configures a [Timestamps] policy.
type Config struct {
	// PAWS enables rejecting in-window segments carrying a timestamp older than
	// TS.Recent (RFC 7323 §5). It defends long-lived, high-bandwidth connections
	// against a wrapped sequence number.
	PAWS bool
}

// Configure applies cfg and resets the policy.
func (ts *Timestamps) Configure(cfg Config) {
	paws := cfg.PAWS
	ts.Reset()
	ts.paws = paws
}

// Reset returns the policy and its retransmission timer to the initial
// per-connection state. It implements [tcp.Policy].
func (ts *Timestamps) Reset() {
	paws, shared := ts.paws, ts.shared
	*ts = Timestamps{paws: paws, shared: shared} // Installed configuration, not per-connection state.
	if shared == nil {
		ts.timer.Reset() // A shared timer is reset by whoever drives it.
	}
}

// SetTimer makes this policy feed its round-trip samples to t and read timing from
// it, instead of from a timer of its own, without driving it. It is how the
// timestamp extension is combined with a congestion controller: both need the same
// retransmission timer, and two timers would retransmit on whichever estimate is
// more pessimistic while each took the result as its own.
//
// Sharing is the point of the option here rather than an optimisation. A timestamp
// echo dates an acknowledgement even when it acknowledges a retransmission, which
// the timer's own sampling has to discard (Karn), so the samples this policy
// contributes are ones the timer cannot take for itself — and they are only worth
// contributing to the timer that actually decides when to retransmit.
//
// The shared timer must itself be driven, which means adding it to the same
// [tcp.Composite] as a policy in its own right. Passing nil returns the policy to
// using its own timer. Call before the connection is opened.
func (ts *Timestamps) SetTimer(t *rto.Timer) { ts.shared = t }

// tmr returns the timer in effect, shared or own.
func (ts *Timestamps) tmr() *rto.Timer {
	if ts.shared != nil {
		return ts.shared
	}
	return &ts.timer
}

// Enabled reports whether the option was successfully negotiated with the peer.
func (ts *Timestamps) Enabled() bool { return ts.enabled }

// Recent returns TS.Recent, the peer timestamp currently being echoed.
func (ts *Timestamps) Recent() (uint32, bool) { return ts.recent, ts.haveRecent }

// LastRTT returns the most recent round-trip time measured from an echoed
// timestamp, in nanoseconds, and whether one has been taken.
func (ts *Timestamps) LastRTT() (int64, bool) { return ts.lastRTT, ts.haveRTT }

// SmoothedRTT returns the smoothed round-trip time of the timer in effect, in
// nanoseconds.
func (ts *Timestamps) SmoothedRTT() int64 { return int64(ts.tmr().SmoothedRTT()) }

// NextDeadline returns the retransmission deadline of the timer this policy drives,
// or 0 when the timer is shared and reports its own. It implements [tcp.Policy].
func (ts *Timestamps) NextDeadline() int64 {
	if ts.shared != nil {
		return 0
	}
	return ts.timer.NextDeadline()
}

// PostTx commits the negotiation state for an option that has actually been
// transmitted and forwards the emitted segment to the retransmission timer. It
// implements [tcp.Policy].
//
// This is where an offer becomes real, rather than in WriteOptions: the outgoing
// segment is reported here only once the transmit path has committed to it, so a
// segment that was built and then abandoned cannot leave this side believing an
// agreement the peer never received.
func (ts *Timestamps) PostTx(outgoing tcp.Segment, now int64) {
	if ts.wrote {
		ts.wrote = false
		isSyn := outgoing.Flags.HasAny(tcp.FlagSYN)
		switch {
		case isSyn && outgoing.Flags.HasAny(tcp.FlagACK):
			// A SYN-ACK carrying the option answers a peer that offered it, so the
			// option has now been both received and sent and is in use.
			ts.offered, ts.enabled = true, true
		case isSyn:
			ts.offered = true
		}
	}
	if ts.shared == nil {
		ts.timer.PostTx(outgoing, now)
	}
}

// PreTx forwards to the retransmission timer, or returns no directive when the
// timer is shared and reports its own. It implements [tcp.Policy].
func (ts *Timestamps) PreTx(intent tcp.TxIntent) tcp.TxDirective {
	if ts.shared != nil {
		return tcp.TxDirective{}
	}
	return ts.timer.PreTx(intent)
}

// tsval returns the timestamp clock value to place in an outgoing segment.
func (ts *Timestamps) tsval(now int64) uint32 {
	if !ts.haveEpoch {
		ts.haveEpoch = true
		ts.epoch = now
	}
	return uint32((now - ts.epoch) / nanosPerMilli)
}

// WriteOptions offers the Timestamps option during the handshake and, once
// negotiated, stamps every outgoing segment with the current TSval and the
// peer's TS.Recent. It implements [tcp.Policy].
//
// It records nothing about the negotiation itself. The segment it is writing into
// may never be transmitted, and treating the option as agreed on the strength of
// having written it would make this side drop every subsequent segment from a peer
// that never saw the offer (RFC 7323 §3.2). The agreement is committed in
// [Timestamps.PostTx], once the segment is known to have gone out.
func (ts *Timestamps) WriteOptions(plan tcp.TxPlan, opts []byte) uint8 {
	ts.wrote = false // Discard an earlier attempt that was abandoned unsent.
	switch plan.Kind {
	case tcp.TxKindSYN:
		// §2: offer the option; nothing has been received to echo yet.
	case tcp.TxKindSYNACK:
		// Only answer a peer that offered, which is recorded when their SYN
		// arrived.
		if !ts.haveRecent {
			return 0
		}
	default:
		if !ts.enabled {
			return 0
		}
	}
	// Space is checked before any negotiation state is recorded: claiming the
	// option is in use while omitting it from the wire would make this side drop
	// every subsequent segment from a peer that never agreed to send it.
	if len(opts) < optLen {
		return 0
	}
	var data [optDataLen]byte
	put32(data[0:4], ts.tsval(plan.Now))
	put32(data[4:8], ts.recent) // Zero until a peer timestamp is recorded.
	n, err := ts.codec.PutOption(opts, tcp.OptTimestamps, data[:]...)
	if err != nil || n < 0 {
		return 0
	}
	ts.wrote = true
	return uint8(n)
}

// PreRx parses the peer's Timestamps option, completes negotiation, maintains
// TS.Recent, measures the round-trip time from the echo and, with PAWS enabled,
// drops segments whose timestamp has gone backwards. It implements
// [tcp.Policy].
func (ts *Timestamps) PreRx(rx tcp.RxMeta) tcp.RxDirective {
	tsval, _, present := ts.parse(rx.Options)
	isSyn := rx.Segment.Flags.HasAny(tcp.FlagSYN)
	switch {
	case isSyn:
		// A SYN or SYN-ACK carrying the option means the peer supports it. The
		// option is only in use once both sides sent it.
		if present {
			ts.recent, ts.haveRecent = tsval, true
			if rx.Segment.Flags.HasAny(tcp.FlagACK) {
				// SYN-ACK answering our offer completes negotiation.
				ts.enabled = ts.offered
			}
		}
	case ts.enabled && !present:
		// §3.2: once negotiated, a segment without the option should be dropped,
		// except a RST which must still be honored.
		if !rx.Segment.Flags.HasAny(tcp.FlagRST) {
			return tcp.RxDirective{Keep: false}
		}
	case ts.enabled && present:
		if ts.paws && ts.haveRecent && lessThan32(tsval, ts.recent) {
			// §5: the timestamp went backwards, so the sequence number may have
			// wrapped. Drop the segment before it is processed.
			return tcp.RxDirective{Keep: false}
		}
		// Recording the timestamp and taking the sample wait for PostRx: §4.3 ties
		// both to a segment being acceptable, which is not known yet.
	}
	if ts.shared != nil {
		return tcp.RxDirective{Keep: true}
	}
	// Let the retransmission timer see every segment the state machine will.
	return ts.timer.PreRx(rx)
}

// PostRx records the peer's timestamp and takes a round-trip sample from a segment
// the connection accepted, then forwards the event to the retransmission timer. It
// implements [tcp.Policy].
//
// RFC 7323 §4.3 advances TS.Recent only for an acceptable segment, so a refused one
// must not move it. Letting it would echo a timestamp from a segment that never
// counted and corrupt the peer's round-trip estimate.
func (ts *Timestamps) PostRx(event tcp.RxEvent) {
	if ts.shared == nil {
		defer ts.timer.PostRx(event)
	}
	if !event.Accepted || !ts.enabled || event.Segment.Flags.HasAny(tcp.FlagSYN) {
		return
	}
	tsval, tsecr, present := ts.parse(event.Options)
	if !present {
		return
	}
	ts.updateRecent(tsval, event.Segment.SEQ, event.RcvNXT)
	ts.sample(tsecr, event.Now)
}

// updateRecent applies the RFC 7323 §4.3 rule for advancing TS.Recent: the
// segment's timestamp must not be older than the stored one and the segment must
// be at or below the left edge of what has been acknowledged, so a reordered
// segment cannot pull the echo backwards.
func (ts *Timestamps) updateRecent(tsval uint32, seq, rcvNXT tcp.Value) {
	if ts.haveRecent && lessThan32(tsval, ts.recent) {
		return
	}
	if !seq.LessThanEq(rcvNXT) {
		return // Ahead of what has been acknowledged: not eligible.
	}
	ts.recent, ts.haveRecent = tsval, true
}

// sample derives a round-trip time from an echoed timestamp. Implausible values
// are discarded rather than fed to the estimator.
func (ts *Timestamps) sample(tsecr uint32, now int64) {
	if tsecr == 0 || !ts.haveEpoch {
		return // Nothing of ours echoed back yet.
	}
	elapsed := int32(ts.tsval(now) - tsecr)
	if elapsed < 0 || elapsed > maxPlausibleRTTMillis {
		return
	}
	ts.lastRTT, ts.haveRTT = int64(elapsed)*nanosPerMilli, true
	// Hand the sample to the retransmission timer. This is the point of the option
	// for a sender: the echo dates the acknowledgement even when it arrives for a
	// retransmitted segment, which the timer's own sampling must discard.
	ts.tmr().ObserveRTT(time.Duration(ts.lastRTT))
}

// parse walks the option area looking for the Timestamps option.
func (ts *Timestamps) parse(opts []byte) (tsval, tsecr uint32, present bool) {
	if len(opts) == 0 {
		return 0, 0, false
	}
	ts.codec.ForEachOption(opts, func(kind tcp.OptionKind, data []byte) error {
		if kind == tcp.OptTimestamps && len(data) == optDataLen {
			tsval = get32(data[0:4])
			tsecr = get32(data[4:8])
			present = true
		}
		return nil
	})
	return tsval, tsecr, present
}

func put32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
}

func get32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// lessThan32 compares timestamps modulo 2^32, as RFC 7323 §5.2 requires, so the
// comparison stays correct across a wrap of the timestamp clock.
func lessThan32(a, b uint32) bool { return int32(a-b) < 0 }

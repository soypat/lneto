package tcp

import "errors"

// MaxComposedPolicies bounds how many policies a [Composite] can drive. The
// storage is a fixed array so composing allocates nothing, which is what lets a
// composite be used on a system with no heap.
const MaxComposedPolicies = 4

var errTooManyPolicies = errors.New("tcp: too many composed policies")

// Composite drives several [Policy] implementations as one, so that independent
// concerns can be combined instead of one implementation having to subsume the
// others. A congestion controller, a timestamp extension and a selective
// acknowledgement extension are separate algorithms that happen to need the same
// hooks; without a composite the only way to run two of them is for one to embed
// the other and forward every call by hand.
//
// The zero value is an empty composite that does nothing. Add policies before the
// connection is opened.
//
// # Merge rules
//
// Every hook is offered to every policy, in the order they were added. Where a
// hook returns something, the results are combined as follows.
//
//   - [Policy.NextDeadline]: the earliest non-zero deadline. A policy with no
//     deadline reports 0 and does not hold the connection back; the connection is
//     serviced when the first policy needs it.
//   - [Policy.PreRx]: the segment is kept only if every policy keeps it. A single
//     policy rejecting a segment, as PAWS does, is enough to drop it. Every policy
//     is still asked, so none is left with a gap in what it observed.
//   - [Policy.PreTx]: Retransmit and HoldNew are the logical or of the directives,
//     so any policy can ask for a retransmission and any policy can hold new data
//     back. RetransmitFrom is the lowest sequence number requested by a policy
//     that asked to retransmit, compared in sequence space, so the retransmission
//     covers what every requester wanted.
//   - [Policy.WriteOptions]: each policy is offered the space its predecessors did
//     not use and the lengths are summed.
//
// The or rules make the composite conservative: combining policies can only ever
// retransmit more, hold more back and drop more than the policies would alone. A
// composite therefore cannot send something none of its members would have sent,
// which is the property that matters when the members were written independently.
//
// # What a composite cannot reconcile
//
// Policies must be independent. Two policies that each maintain their own
// retransmission timer will both drive retransmission from their own estimate,
// and no merge rule recovers a single correct timer from that: the earliest
// deadline wins, so the connection retransmits on whichever estimate is more
// pessimistic, and both then observe the result as though it were their own
// decision. Compose policies that own different state, and give policies that
// need retransmission timing a shared timer instead of one each.
type Composite struct {
	policies [MaxComposedPolicies]Policy
	n        int
}

var _ Policy = (*Composite)(nil)

// Add appends a policy to be driven by c. It returns an error if c already holds
// [MaxComposedPolicies] policies or if p is nil.
func (c *Composite) Add(p Policy) error {
	if p == nil {
		return errors.New("tcp: nil composed policy")
	}
	if c.n >= len(c.policies) {
		return errTooManyPolicies
	}
	c.policies[c.n] = p
	c.n++
	return nil
}

// Len reports how many policies c drives.
func (c *Composite) Len() int { return c.n }

// Reset resets every composed policy. It implements [Policy].
func (c *Composite) Reset() {
	for _, p := range c.policies[:c.n] {
		p.Reset()
	}
}

// NextDeadline returns the earliest non-zero deadline of the composed policies,
// or 0 if none has one. It implements [Policy].
func (c *Composite) NextDeadline() int64 {
	var earliest int64
	for _, p := range c.policies[:c.n] {
		d := p.NextDeadline()
		if d == 0 {
			continue // No deadline of its own.
		}
		if earliest == 0 || d < earliest {
			earliest = d
		}
	}
	return earliest
}

// PreRx offers the segment to every composed policy and keeps it only if all of
// them do. It implements [Policy].
func (c *Composite) PreRx(rx RxMeta) RxDirective {
	keep := true
	for _, p := range c.policies[:c.n] {
		// Every policy is asked even once one has rejected the segment, so that a
		// policy's view of the traffic does not depend on the order it was added in.
		if !p.PreRx(rx).Keep {
			keep = false
		}
	}
	return RxDirective{Keep: keep}
}

// PostRx reports the outcome to every composed policy. It implements [Policy].
func (c *Composite) PostRx(event RxEvent) {
	for _, p := range c.policies[:c.n] {
		p.PostRx(event)
	}
}

// PreTx merges the transmit directives of the composed policies. It implements
// [Policy].
func (c *Composite) PreTx(intent TxIntent) TxDirective {
	var merged TxDirective
	for _, p := range c.policies[:c.n] {
		dir := p.PreTx(intent)
		if dir.HoldNew {
			merged.HoldNew = true
		}
		if !dir.Retransmit {
			continue
		}
		if !merged.Retransmit || dir.RetransmitFrom.LessThan(merged.RetransmitFrom) {
			// The lowest requested sequence number wins, so a policy asking to
			// resend from further back is not silently narrowed by another.
			merged.RetransmitFrom = dir.RetransmitFrom
		}
		merged.Retransmit = true
	}
	return merged
}

// WriteOptions offers each composed policy the option space its predecessors left
// and returns the total written. It implements [Policy].
func (c *Composite) WriteOptions(plan TxPlan, opts []byte) uint8 {
	var total int
	for _, p := range c.policies[:c.n] {
		n := int(p.WriteOptions(plan, opts[total:]))
		if total+n > len(opts) {
			// A policy overran the space it was lent. Stop rather than report a
			// length the header cannot hold; the core rejects an overrun itself, but
			// a composite must not turn one policy's fault into a corrupt total.
			return uint8(total)
		}
		total += n
	}
	return uint8(total)
}

// PostTx reports the emitted segment to every composed policy. It implements
// [Policy].
func (c *Composite) PostTx(outgoing Segment, now int64) {
	for _, p := range c.policies[:c.n] {
		p.PostTx(outgoing, now)
	}
}

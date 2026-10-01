package tcp

import "errors"

// MaxComposedPolicies bounds how many policies a [Composite] drives. The storage
// is a fixed array so composing allocates nothing.
const MaxComposedPolicies = 4

var (
	errTooManyPolicies = errors.New("tcp: too many composed policies")
	errNilPolicy       = errors.New("tcp: nil composed policy")
)

// Composite drives several [Policy] implementations as one, so independent
// concerns such as a retransmission timer and selective acknowledgement can be
// combined without one embedding the other. Every hook is offered to every
// member in the order they were added. Results are merged as follows:
//
//   - PreRx keeps the segment only if every member keeps it. Every member is
//     still asked.
//   - PreTx returns the smallest new-data limit, and requests a retransmission
//     if any member does, from the lowest sequence requested, so the resend
//     covers what every requester wanted.
//
// Members writing options in PreTx must append after the options already
// present, which end at the frame's data offset, and raise the offset to cover
// their own.
//
// Members should own separate state: two members each running a retransmission
// timer both drive retransmission, and no merge rule recovers one correct timer.
//
// The zero value is empty and does nothing. Add members before the connection
// is opened.
type Composite struct {
	policies [MaxComposedPolicies]Policy
	n        int
}

var _ Policy = (*Composite)(nil)

// Add appends p to the policies c drives. It fails if p is nil or c already
// holds [MaxComposedPolicies] policies.
func (c *Composite) Add(p Policy) error {
	if p == nil {
		return errNilPolicy
	} else if c.n == len(c.policies) {
		return errTooManyPolicies
	}
	c.policies[c.n] = p
	c.n++
	return nil
}

// Reset resets every member. It implements [Policy].
func (c *Composite) Reset() {
	for _, p := range c.policies[:c.n] {
		p.Reset()
	}
}

// PreTx merges the members' transmit requests. It implements [Policy].
func (c *Composite) PreTx(h *Handler, outgoingOpts Frame) (newTransmitLimit Size, retransmitFrom Value, retransmit bool) {
	newTransmitLimit = TransmitUnlimited
	for _, p := range c.policies[:c.n] {
		limit, from, rtx := p.PreTx(h, outgoingOpts)
		newTransmitLimit = min(newTransmitLimit, limit)
		if rtx && (!retransmit || from.LessThan(retransmitFrom)) {
			retransmitFrom, retransmit = from, true
		}
	}
	return newTransmitLimit, retransmitFrom, retransmit
}

// PostTx reports the emitted frame to every member. It implements [Policy].
func (c *Composite) PostTx(h *Handler, outgoing Frame) {
	for _, p := range c.policies[:c.n] {
		p.PostTx(h, outgoing)
	}
}

// PreRx keeps the segment only if every member keeps it. It implements [Policy].
func (c *Composite) PreRx(h *Handler, incoming Frame) (keep bool) {
	keep = true
	for _, p := range c.policies[:c.n] {
		keep = p.PreRx(h, incoming) && keep
	}
	return keep
}

// PostRx reports the accepted frame to every member. It implements [Policy].
func (c *Composite) PostRx(h *Handler, prevState State, accepted Frame) {
	for _, p := range c.policies[:c.n] {
		p.PostRx(h, prevState, accepted)
	}
}

// NextDeadline returns the earliest non-zero deadline among members that have a
// NextDeadline method, such as rto.Timer, or 0 if none has one.
func (c *Composite) NextDeadline() (earliest int64) {
	for _, p := range c.policies[:c.n] {
		dp, ok := p.(interface{ NextDeadline() int64 })
		if !ok {
			continue
		}
		if d := dp.NextDeadline(); d != 0 && (earliest == 0 || d < earliest) {
			earliest = d
		}
	}
	return earliest
}

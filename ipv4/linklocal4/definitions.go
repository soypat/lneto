// Package linklocal4 implements dynamic configuration of IPv4 link-local addresses
// (a.k.a. APIPA, "self-assigned" 169.254.x.x addresses) as specified in [RFC3927].
//
// The [Handler] is a heapless state machine that claims and defends a link-local
// address using ARP probes and announcements. It performs no allocations during
// steady-state operation and holds no buffers of its own; the caller provides the
// scratch buffer on each call. This makes it suitable for memory constrained and
// bare-metal targets.
//
// [RFC3927]: https://datatracker.ietf.org/doc/html/rfc3927
package linklocal4

import "time"

// Protocol constants as defined in [RFC3927] section 9.
//
// [RFC3927]: https://datatracker.ietf.org/doc/html/rfc3927#section-9
const (
	// probeWait is the initial random delay before sending the first probe.
	probeWait = 1 * time.Second
	// probeNum is the number of ARP probes to send.
	probeNum = 3
	// probeMin and probeMax bound the random spacing between probes.
	probeMin = 1 * time.Second
	probeMax = 2 * time.Second
	// announceWait is the delay after the last probe before announcing.
	announceWait = 2 * time.Second
	// announceNum is the number of ARP announcements to send.
	announceNum = 2
	// announceInterval is the spacing between announcements.
	announceInterval = 2 * time.Second
	// maxConflicts is the number of conflicts after which probing is rate limited.
	maxConflicts = 10
	// rateLimitInterval bounds the rate of address claiming once maxConflicts is exceeded.
	rateLimitInterval = 60 * time.Second
	// defendInterval is the minimum spacing between defensive announcements before
	// the address is abandoned to break an endless defense loop.
	defendInterval = 10 * time.Second
)

// arpIPv4Size is the size of an ARP-over-Ethernet IPv4 packet (RFC826):
// 8 byte fixed header + 2*(6 byte hardware addr + 4 byte protocol addr).
const arpIPv4Size = 28

// State represents the stage of the link-local address autoconfiguration
// state machine. The transition order during a successful claim is:
//
//	StateWaiting -> StateProbing -> StateAnnouncing -> StateBound
type State uint8

const (
	// StateInvalid is the zero value; the handler has not been configured.
	StateInvalid State = iota
	// StateWaiting is the initial random delay before the first probe is sent.
	StateWaiting
	// StateProbing sends ARP probes to detect whether the candidate is in use.
	StateProbing
	// StateAnnouncing has claimed the candidate and is broadcasting announcements.
	StateAnnouncing
	// StateBound owns the address and defends it against conflicts.
	StateBound
	// StateRateLimited is waiting out rateLimitInterval after too many conflicts.
	StateRateLimited
)

// IsBound reports whether the state machine has successfully claimed an address.
func (s State) IsBound() bool { return s == StateBound }

func (s State) String() string {
	switch s {
	case StateInvalid:
		return "invalid"
	case StateWaiting:
		return "waiting"
	case StateProbing:
		return "probing"
	case StateAnnouncing:
		return "announcing"
	case StateBound:
		return "bound"
	case StateRateLimited:
		return "rate-limited"
	default:
		return "linklocal4.State(?)"
	}
}

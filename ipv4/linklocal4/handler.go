package linklocal4

import (
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/arp"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/ipv4"
)

// Handler implements the [RFC3927] IPv4 link-local address autoconfiguration
// state machine. It is a [lneto.StackNode] over the ARP EtherType: it produces
// ARP probes and announcements on [Handler.Encapsulate] and inspects incoming
// ARP traffic for conflicts on [Handler.Demux].
//
// Handler is heapless and performs zero allocations after [Handler.Reset];
// the only allocation is the one-time capture of the clock function. It holds
// no internal buffers and operates entirely on the caller-supplied scratch
// buffer, making it suitable for memory constrained targets.
//
// A Handler claims and defends a single address. Normal "who-has" ARP
// resolution of the claimed address is the responsibility of the ARP layer
// (see [arp.Handler]); this Handler only manages the claim-and-defend protocol.
//
// [RFC3927]: https://datatracker.ietf.org/doc/html/rfc3927
type Handler struct {
	connID uint64
	now    func() time.Time

	// nextActionAt is the time at which the next probe/announcement is due.
	nextActionAt time.Time
	// lastDefend is the time the most recent defensive announcement was sent.
	lastDefend time.Time

	prng           uint32
	candidate      [4]byte
	firstCandidate [4]byte
	hw             [6]byte

	state        State
	probesSent   uint8
	announceSent uint8
	conflicts    uint8

	haveFirst   bool
	defendDue   bool
	defendValid bool
	vld         lneto.Validator
}

var _ lneto.StackNode = (*Handler)(nil)

// linkLocalNet is the RFC3927 IPv4 link-local prefix (169.254.0.0/16). The first
// and last /24 within it (169.254.0.x and 169.254.255.x) are reserved per
// section 2.1, so the usable host range is 169.254.1.0-169.254.254.255.
var linkLocalNet = ipv4.PrefixFrom([4]byte{169, 254, 0, 0}, 16)

// Config configures a [Handler] for link-local address acquisition.
type Config struct {
	// HardwareAddr is the interface MAC address used as the ARP sender hardware address.
	HardwareAddr [6]byte
	// Now is the monotonic clock source used to schedule probes and announcements.
	// It is required.
	Now func() time.Time
	// Seed seeds the pseudo-random address generator. It is required and must be
	// non-zero. Per RFC3927 section 2.1 it SHOULD be derived from a persistent
	// per-host value such as the MAC address so that different hosts pick different
	// sequences and a host tends to reuse the same address across reboots.
	Seed uint64
	// FirstCandidate, if within 169.254.1.0-169.254.254.255, is tried before any
	// random address. Use it to retry a previously recorded address.
	FirstCandidate [4]byte
}

// Reset configures the handler and begins link-local address acquisition,
// transitioning to [StateWaiting]. It increments the connection ID, invalidating
// any prior registration.
func (h *Handler) Reset(cfg Config) error {
	if cfg.Now == nil || internal.IsZeroed(cfg.HardwareAddr[:]...) || cfg.Seed == 0 {
		return lneto.ErrInvalidConfig
	}
	first := cfg.FirstCandidate
	haveFirst := linkLocalNet.Contains(first) && first[2] >= 1 && first[2] <= 254
	*h = Handler{
		connID:         h.connID + 1,
		now:            cfg.Now,
		prng:           uint32(cfg.Seed) ^ uint32(cfg.Seed>>32),
		hw:             cfg.HardwareAddr,
		firstCandidate: first,
		haveFirst:      haveFirst,
	}
	if h.prng == 0 {
		h.prng = 1 // Fold of a non-zero seed can still be zero; xorshift cannot escape the zero state.
	}
	h.beginProbing(cfg.Now(), randDelay(h.prand(), probeWait))
	return nil
}

// LocalPort implements [lneto.StackNode]. It always returns 0.
func (h *Handler) LocalPort() uint16 { return 0 }

// Protocol implements [lneto.StackNode], returning the ARP EtherType.
func (h *Handler) Protocol() uint64 { return uint64(ethernet.TypeARP) }

// ConnectionID implements [lneto.StackNode].
func (h *Handler) ConnectionID() *uint64 { return &h.connID }

// State returns the current autoconfiguration state.
func (h *Handler) State() State { return h.state }

// Addr returns the claimed link-local address. ok is true only once the address
// has been successfully claimed (state [StateBound]).
func (h *Handler) Addr() (addr [4]byte, ok bool) {
	return h.candidate, h.state == StateBound
}

// Candidate returns the address currently being probed, announced or defended.
func (h *Handler) Candidate() [4]byte { return h.candidate }

// Conflicts returns the number of address conflicts encountered so far.
func (h *Handler) Conflicts() int { return int(h.conflicts) }

// Encapsulate implements [lneto.StackNode]. It writes the next ARP probe or
// announcement into carrierData at offsetToFrame when one is due, returning the
// number of bytes written, or 0 when no action is pending. The Ethernet
// destination, if present before offsetToFrame, is set to broadcast.
func (h *Handler) Encapsulate(carrierData []byte, _, offsetToFrame int) (int, error) {
	if offsetToFrame < 0 || len(carrierData)-offsetToFrame < arpIPv4Size {
		return 0, lneto.ErrShortBuffer
	}
	now := h.now()
	b := carrierData[offsetToFrame:]
	var senderProto [4]byte // zero = ARP probe; candidate = ARP announcement.
	switch h.state {
	case StateWaiting, StateProbing:
		if now.Before(h.nextActionAt) {
			return 0, nil
		}
		if h.probesSent < probeNum {
			h.state = StateProbing
			h.probesSent++
			if h.probesSent < probeNum {
				h.nextActionAt = now.Add(randInterval(h.prand(), probeMin, probeMax))
			} else {
				h.nextActionAt = now.Add(announceWait)
			}
			// senderProto stays zero: this is a probe.
		} else {
			// announceWait elapsed with no conflict: claim the address.
			h.state = StateAnnouncing
			h.announceSent = 1
			h.nextActionAt = now.Add(announceInterval)
			senderProto = h.candidate
		}

	case StateAnnouncing:
		if now.Before(h.nextActionAt) {
			return 0, nil
		}
		h.announceSent++
		senderProto = h.candidate
		if h.announceSent >= announceNum {
			h.state = StateBound
		} else {
			h.nextActionAt = now.Add(announceInterval)
		}

	case StateBound:
		if !h.defendDue {
			return 0, nil
		}
		h.defendDue = false
		senderProto = h.candidate

	case StateRateLimited:
		if now.Before(h.nextActionAt) {
			return 0, nil
		}
		// onConflict already selected a fresh candidate; resume probing it.
		h.beginProbing(now, randDelay(h.prand(), probeWait))
		return 0, nil

	default:
		return 0, nil
	}

	h.putARP(b, senderProto)
	if offsetToFrame >= 14 {
		// TODO: Support VLAN-tagged Ethernet headers when setting the broadcast destination.
		broadcast := ethernet.BroadcastAddr()
		copy(carrierData[offsetToFrame-14:offsetToFrame-8], broadcast[:])
	}
	return arpIPv4Size, nil
}

// Demux implements [lneto.StackNode]. It inspects an incoming ARP frame for
// address conflicts per RFC3927 sections 2.2.1 and 2.5, updating the state
// machine to reconfigure or defend as required.
func (h *Handler) Demux(carrierData []byte, frameOffset int) error {
	if h.state == StateInvalid {
		return nil
	}
	afrm, err := arp.NewFrame(carrierData[frameOffset:])
	if err != nil {
		return err
	}
	h.vld.ResetErr()
	afrm.ValidateSize(&h.vld)
	if h.vld.HasError() {
		return h.vld.ErrPop()
	}
	ptype, plen := afrm.Protocol()
	if ptype != ethernet.TypeIPv4 || plen != 4 {
		return nil // Not IPv4 ARP; irrelevant to link-local conflict detection.
	}
	senderHW, senderProto := afrm.Sender4()
	_, targetProto := afrm.Target4()
	now := h.now()

	switch h.state {
	case StateWaiting, StateProbing:
		// Conflict if anyone else uses the candidate as a sender address, or
		// is probing for the same candidate from a different hardware address.
		conflict := *senderProto == h.candidate ||
			(afrm.Operation() == arp.OpRequest && internal.IsZeroed(senderProto[:]...) &&
				*targetProto == h.candidate && *senderHW != h.hw)
		if conflict {
			h.onConflict(now)
		}

	case StateAnnouncing, StateBound:
		// We own the address; a conflicting sender hardware address means another
		// host claims it too.
		if *senderProto == h.candidate && *senderHW != h.hw {
			h.onDefend(now)
		}
	}
	return nil
}

// onConflict handles a conflict detected while probing: pick a new candidate and
// restart, rate limiting once maxConflicts is exceeded.
func (h *Handler) onConflict(now time.Time) {
	if h.conflicts < 255 {
		h.conflicts++
	}
	h.selectCandidate()
	if h.conflicts > maxConflicts {
		h.state = StateRateLimited
		h.nextActionAt = now.Add(rateLimitInterval)
		return
	}
	h.beginProbing(now, randDelay(h.prand(), probeWait))
}

// onDefend handles a conflict on an address we own per RFC3927 section 2.5(b):
// defend once with a single announcement, but abandon the address if conflicts
// recur within defendInterval to avoid an endless defense loop.
func (h *Handler) onDefend(now time.Time) {
	if !h.defendValid || now.Sub(h.lastDefend) >= defendInterval {
		h.lastDefend = now
		h.defendValid = true
		h.defendDue = true
		return
	}
	// Second conflict within defendInterval: give up and reconfigure.
	h.onConflict(now)
}

// beginProbing resets probe/announce counters and schedules the first probe after delay.
func (h *Handler) beginProbing(now time.Time, delay time.Duration) {
	if internal.IsZeroed(h.candidate[:]...) {
		h.selectCandidate()
	}
	h.state = StateWaiting
	h.probesSent = 0
	h.announceSent = 0
	h.defendDue = false
	h.defendValid = false
	h.nextActionAt = now.Add(delay)
}

// selectCandidate picks the next address to try. It uses FirstCandidate once if
// provided, otherwise a uniform pseudo-random address in 169.254.1.0-169.254.254.255
// per RFC3927 section 2.1 (the first and last /24 are reserved).
func (h *Handler) selectCandidate() {
	if h.haveFirst {
		h.haveFirst = false
		h.candidate = h.firstCandidate
		return
	}
	// 254*256 = 65024 usable addresses; offset by one /24 to skip 169.254.0.x.
	low := 256 + h.prand()%65024
	h.candidate = [4]byte{169, 254, byte(low >> 8), byte(low)}
}

// putARP marshals an ARP request (probe or announcement) into dst. A probe has
// an all-zero sender protocol address; an announcement repeats the candidate.
func (h *Handler) putARP(dst []byte, senderProto [4]byte) {
	f, _ := arp.NewFrame(dst)
	f.SetHardware(1, 6)
	f.SetProtocol(ethernet.TypeIPv4, 4)
	f.SetOperation(arp.OpRequest)
	shw, sproto := f.Sender4()
	*shw = h.hw
	*sproto = senderProto
	thw, tproto := f.Target4()
	*thw = [6]byte{} // Target hardware address ignored; set to zero per RFC3927 section 2.2.1.
	*tproto = h.candidate
}

func (h *Handler) prand() uint32 {
	h.prng = internal.Prand32(h.prng)
	return h.prng
}

// randDelay returns a duration uniformly in [0, max] derived from r.
func randDelay(r uint32, max time.Duration) time.Duration {
	return time.Duration(uint64(r) % uint64(max+1))
}

// randInterval returns a duration uniformly in [min, max] derived from r.
func randInterval(r uint32, min, max time.Duration) time.Duration {
	span := max - min
	if span <= 0 {
		return min
	}
	return min + time.Duration(uint64(r)%uint64(span+1))
}

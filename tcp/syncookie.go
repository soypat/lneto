package tcp

import (
	"encoding/binary"
	"io"

	"github.com/soypat/lneto"
)

// Embed low 5 bits of counter into cookie for efficient validation.
// Lower bits of cookie are counter bits.
const (
	cookiebits  = 32
	counterbits = 5
	hashbits    = cookiebits - counterbits
	countermsk  = (1 << counterbits) - 1
)

// SYNCookieJar implements SYN cookie generation and validation for TCP SYN flood protection.
// SYN cookies allow a server to avoid allocating state for half-open connections by
// encoding connection parameters into the Initial Sequence Number (ISS) of the SYN-ACK response.
//
// The cookie encodes:
//   - A hash of the connection tuple (src IP, dst IP, src port, dst port)
//   - A timestamp counter for cookie expiration
//   - MSS index (optional, for preserving Maximum Segment Size negotiation)
//
// See RFC 4987 for background on SYN flood attacks and cookie-based mitigations.
type SYNCookieJar struct {
	// counter is incremented periodically or under pressure to expire old cookies.
	// Cookies generated with a counter more than maxCounterDelta behind current are rejected.
	counter uint32
	// maxCounterDelta defines how many counter increments a cookie remains valid.
	// A value of 2 means cookies from counter, counter-1, and counter-2 are accepted.
	maxCounterDelta uint32
	// secret is the key used for cookie generation. Should be random and kept private.
	secret [16]byte
}

// SYNCookieConfig contains configuration for SYN cookie initialization.
type SYNCookieConfig struct {
	// Rand is used for entropy generation of cookies.
	Rand io.Reader
	// MaxCounterDelta defines cookie validity window in counter increments.
	// Recommended value is 1-2. Zero defaults to 1.
	MaxCounterDelta uint32
}

var errInvalidCookie error = lneto.ErrMismatch

// Reset initializes or reinitializes the SYNCookie with the given configuration.
// The counter is preserved across resets to maintain cookie validity during secret rotation.
func (sc *SYNCookieJar) Reset(config SYNCookieConfig) error {
	if config.Rand == nil {
		return lneto.ErrInvalidConfig
	}
	_, err := io.ReadFull(config.Rand, sc.secret[:])
	if err != nil {
		return err
	}
	maxDelta := config.MaxCounterDelta
	if maxDelta == 0 {
		maxDelta = 1
	}
	sc.maxCounterDelta = maxDelta
	// counter is intentionally NOT reset to preserve validity of recent cookies
	return nil
}

// IncrementCounter advances the counter, which will eventually expire old cookies.
// Call this periodically (e.g., every few seconds) or when under SYN flood pressure.
func (sc *SYNCookieJar) IncrementCounter() {
	sc.counter++
}

// Counter returns the current counter value.
func (sc *SYNCookieJar) Counter() uint32 {
	return sc.counter
}

// MakeSYNCookie creates a SYN cookie value to be used as the ISS in a SYN-ACK response.
// The cookie encodes the connection tuple and current counter for later validation.
//
// Parameters:
//   - srcAddr: source IP address (4 bytes for IPv4, 16 for IPv6)
//   - dstAddr: destination IP address
//   - srcPort: source TCP port
//   - dstPort: destination TCP port
//   - clientISN: the client's Initial Sequence Number from the SYN packet
func (sc *SYNCookieJar) MakeSYNCookie(srcAddr, dstAddr []byte, srcPort, dstPort uint16, clientISN Value) Value {
	return sc.generateWithCounter(srcAddr, dstAddr, srcPort, dstPort, clientISN, sc.counter)
}

// generateWithCounter creates a cookie using a specific counter value.
func (sc *SYNCookieJar) generateWithCounter(srcAddr, dstAddr []byte, srcPort, dstPort uint16, clientISN Value, counter uint32) Value {
	// Cookie structure (32 bits):
	//   [5 bits: counter low bits][27 bits: hash of tuple+secret+counter]
	//
	// The counter bits allow validation to check multiple counter values efficiently.
	// The hash provides cryptographic binding to the connection tuple.

	hash := sc.hashTuple(srcAddr, dstAddr, srcPort, dstPort, clientISN, counter)
	hash = hash << counterbits
	return Value(hash | counter&countermsk)
}

// ValidateSYNCookie checks if an ACK number from a client completing the handshake contains
// a valid cookie. Returns the original cookie value if valid.
//
// Parameters:
//   - srcAddr, dstAddr: IP addresses (must match original SYN)
//   - srcPort, dstPort: TCP ports (must match original SYN)
//   - clientISN: client's ISN from original SYN (can be derived from ack-1 of final ACK)
//   - ackNum: the ACK number from the client's ACK packet (should be cookie+1)
//
// Returns the cookie value and nil error if valid, or zero and error if invalid.
func (sc *SYNCookieJar) ValidateSYNCookie(srcAddr, dstAddr []byte, srcPort, dstPort uint16, clientISN Value, ackNum Value) (Value, error) {
	// Client ACKs cookie+1, so the cookie is ackNum-1
	cookie := ackNum - 1

	// Extract counter bits from cookie
	cookieCounterBits := uint32(cookie) & countermsk

	// Try validation with current counter and allowed previous values
	for delta := uint32(0); delta <= sc.maxCounterDelta; delta++ {
		tryCounter := sc.counter - delta
		tryCounterBits := tryCounter & countermsk
		if tryCounterBits != cookieCounterBits {
			continue
		}

		// Counter bits match, verify full hash
		expected := sc.generateWithCounter(srcAddr, dstAddr, srcPort, dstPort, clientISN, tryCounter)
		if expected == cookie {
			return cookie, nil
		}
	}

	return 0, errInvalidCookie
}

// hashTuple computes a hash of the connection tuple mixed with secret and counter.
// Uses a simple but effective mixing function suitable for embedded systems.
func (sc *SYNCookieJar) hashTuple(srcAddr, dstAddr []byte, srcPort, dstPort uint16, clientISN Value, counter uint32) uint32 {
	// Initialize with secret words
	h0 := binary.LittleEndian.Uint32(sc.secret[0:4])
	h1 := binary.LittleEndian.Uint32(sc.secret[4:8])
	h2 := binary.LittleEndian.Uint32(sc.secret[8:12])
	h3 := binary.LittleEndian.Uint32(sc.secret[12:16])

	// Mix in connection tuple
	h0 ^= uint32(srcPort) | (uint32(dstPort) << 16)
	h1 ^= uint32(clientISN)
	h2 ^= counter

	// Mix in addresses (handle both IPv4 and IPv6)
	for i := 0; i+3 < len(srcAddr); i += 4 {
		h3 ^= binary.LittleEndian.Uint32(srcAddr[i:])
		h0, h1, h2, h3 = mixRound(h0, h1, h2, h3)
	}
	// Handle remaining bytes of srcAddr
	if rem := len(srcAddr) % 4; rem != 0 {
		var last uint32
		for i := 0; i < rem; i++ {
			last |= uint32(srcAddr[len(srcAddr)-rem+i]) << (i * 8)
		}
		h3 ^= last
	}

	for i := 0; i+3 < len(dstAddr); i += 4 {
		h0 ^= binary.LittleEndian.Uint32(dstAddr[i:])
		h0, h1, h2, h3 = mixRound(h0, h1, h2, h3)
	}
	// Handle remaining bytes of dstAddr
	if rem := len(dstAddr) % 4; rem != 0 {
		var last uint32
		for i := 0; i < rem; i++ {
			last |= uint32(dstAddr[len(dstAddr)-rem+i]) << (i * 8)
		}
		h0 ^= last
	}

	// Final mixing rounds
	h0, h1, h2, h3 = mixRound(h0, h1, h2, h3)
	h0, h1, h2, h3 = mixRound(h0, h1, h2, h3)

	return h0 ^ h1 ^ h2 ^ h3
}

// mixRound performs one round of mixing, similar to SipHash quarter-round.
func mixRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a += b
	d ^= a
	d = rotl32(d, 16)

	c += d
	b ^= c
	b = rotl32(b, 12)

	a += b
	d ^= a
	d = rotl32(d, 8)

	c += d
	b ^= c
	b = rotl32(b, 7)

	return a, b, c, d
}

// rotl32 performs a 32-bit left rotation.
func rotl32(x uint32, n int) uint32 {
	return (x << n) | (x >> (32 - n))
}

// encodeMSSIndex encodes an MSS value into a 2-bit index for embedding in cookies.
// Common MSS values are mapped to indices 0-3. Returns the closest match.
func encodeMSSIndex(mss uint16) uint8 {
	// Common MSS values: 536 (minimum), 1460 (Ethernet), 1440 (PPPoE), 8960 (jumbo)
	switch {
	case mss <= 536:
		return 0
	case mss <= 1220:
		return 1
	case mss <= 1460:
		return 2
	default:
		return 3
	}
}

// decodeMSSIndex converts a 2-bit index back to an MSS value.
func decodeMSSIndex(idx uint8) uint16 {
	switch idx & 0x3 {
	case 0:
		return 536
	case 1:
		return 1220
	case 2:
		return 1460
	default:
		return 8960
	}
}

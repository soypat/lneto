package ipv4

const (
	sizeHeader = 20
)

// ToS represents the Traffic Class (a.k.a Type of Service). It is 8 bits long. 6 MSB are Differentiated Services; 2 LSB are Explicit Congenstion Notification.
type ToS uint8

// DS returns the top 6 bits of the IPv4 ToS holding the Differentiated Services field
// which is used to classify packets.
func (tos ToS) DS() uint8 { return uint8(tos) >> 2 }

// ECN is the Explicit Congestion Notification which provides congestion control and non-congestion control traffic.
func (tos ToS) ECN() uint8 { return uint8(tos & 0b11) }

// Flags holds fragmentation field data of an IPv4 header. It is 16 bits long.
type Flags uint16

// IsEvil returns true if evil bit set as per [RFC3514].
//
// [RFC3514]: https://datatracker.ietf.org/doc/html/rfc3514
func (f Flags) IsEvil() bool { return f&2000 != 0 }

// DontFragment specifies whether the datagram can not be fragmented.
// This can be used when sending packets to a host that does not have resources to perform reassembly of fragments.
// If the DontFragment(DF) flag is set, and fragmentation is required to route the packet, then the packet is dropped.
func (f Flags) DontFragment() bool { return f&0x4000 != 0 }

// MoreFragments is cleared for unfragmented packets.
// For fragmented packets, all fragments except the last have the MF flag set.
// The last fragment has a non-zero Fragment Offset field, so it can still be differentiated from an unfragmented packet.
func (f Flags) MoreFragments() bool { return f&0x8000 != 0 }

// FragmentOffset specifies the offset of a particular fragment relative to the beginning of the original unfragmented IP datagram.
// Fragments are specified in units of 8 bytes, which is why fragment lengths are always a multiple of 8; except the last, which may be smaller.
// The fragmentation offset value for the first fragment is always 0.
func (f Flags) FragmentOffset() uint16 { return uint16(f) & 0x1fff }

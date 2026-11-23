package vxlan

// Flags represents the VXLAN flags field. See [RFC7348].
// The only currently defined flag in [RFC7348] is the Valid VNI flag (I flag).
//
// [RFC7348]: https://tools.ietf.org/html/rfc7348
type Flags uint8

const (
	FlagValidVNI = Flags(1 << 3)
)

// ValidVNI returns true if the Valid VNI flag is set. See [Flags].
// This flag should be set on all valid VXLAN frames.
func (f Flags) ValidVNI() bool {
	return f&FlagValidVNI != 0
}

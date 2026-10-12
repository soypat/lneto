package dns

import (
	"math"
	"strings"

	"github.com/soypat/lneto/internal"
)

// Name is a wire representation of a DNS name.
type Name struct {
	data []byte
}

// EqualString checks if the name receiver matches the strname string (non-wire formatted) name.
func (n Name) EqualString(strname string) bool {
	data := n.data
	for len(data) > 0 {
		labelLen := int(data[0])
		if labelLen == 0 {
			return strname == "" || strname == "."
		}
		if len(data) < 1+labelLen {
			return false
		}
		label := data[1 : 1+labelLen]
		var seg string
		before, after, ok := strings.Cut(strname, ".")
		if !ok {
			seg, strname = strname, ""
		} else {
			seg, strname = before, after
		}
		if len(seg) != len(label) || seg != string(label) {
			return false
		}
		data = data[1+labelLen:]
	}
	return false
}

// NamesEqual reports whether two DNS names are equal by comparing
// their wire-format representations directly. This is case-sensitive;
// for case-insensitive comparison use [NamesEqualFold].
func NamesEqual(a, b Name) bool {
	return internal.BytesEqual(a.data, b.data)
}

// NamesEqualFold reports whether two DNS names are equal under ASCII case
// folding, which is how DNS labels compare per RFC 1035 section 2.3.3.
func NamesEqualFold(a, b Name) bool {
	return internal.BytesEqualFoldASCII(a.data, b.data)
}

func skipName(msg []byte, off uint16) (uint16, error) {
	return visitAllLabels(msg, off, func(b []byte) {}, allowCompression)
}

// MustNewName parses domain into a new Name and panics on error. See [Name.Parse].
func MustNewName(domain string) Name {
	var name Name
	err := name.Parse(domain)
	if err != nil {
		panic(err)
	}
	return name
}

var rootDomain = []byte{0}

// Parse resets n and parses the dotted domain name into it, reusing n's buffer.
// A lone "." parses as the root domain. On error n is left empty.
func (n *Name) Parse(domain string) error {
	n.Reset()
	if domain == "" {
		return errEmptyDomainName
	}
	if len(domain) == 1 && domain[0] == '.' {
		n.data = append(n.data, rootDomain...)
		return nil
	}
	for len(domain) > 0 {
		idx := strings.IndexByte(domain, '.')
		done := idx < 0 || idx+1 > len(domain)
		if done {
			idx = len(domain)
		}
		if !n.CanAddLabel(domain[:idx]) {
			n.Reset()
			return errCantAddLabel
		}
		n.AddLabel(domain[:idx])
		if done {
			break
		}
		domain = domain[idx+1:]
	}
	return nil
}

// TrimLabels returns a Name sharing the same backing data with the first n labels removed.
// For example, trimming 1 label from "My Web._http._tcp.local" yields "_http._tcp.local".
// Returns an empty Name if n exceeds the number of labels.
func (n Name) TrimLabels(skip int) Name {
	off := 0
	for range skip {
		if off >= len(n.data) {
			return Name{}
		}
		off += 1 + int(n.data[off])
	}
	return Name{data: n.data[off:]}
}

// Len returns the length over-the-wire of the encoded Name.
func (n *Name) Len() uint16 {
	if len(n.data) > math.MaxUint16 {
		panic("size of DNS name data overflows 16bits")
	}
	return uint16(len(n.data))
}

func (n *Name) CopyFrom(ex Name) {
	n.data = append(n.data[:0], ex.data...)
}

// AppendTo appends the Name to b in wire format and returns the resulting slice.
func (n *Name) AppendTo(b []byte) ([]byte, error) {
	if len(n.data) == 0 {
		return b, errInvalidName
	}
	return append(b, n.data...), nil
}

// String returns a string representation of the name in dotted format.
func (n *Name) String() string {
	b := make([]byte, 0, len(n.data)+3)
	return string(n.AppendDottedTo(b))
}

// AppendDottedTo appends the Name to b in dotted format and returns the resulting slice.
func (n *Name) AppendDottedTo(b []byte) []byte {
	n.VisitLabels(func(label []byte) {
		b = append(b, label...)
		b = append(b, '.')
	})
	return b
}

// Decode resets internal Name buffer and reads raw wire data from buffer, returning any error encountered.
func (n *Name) Decode(b []byte, off uint16) (uint16, error) {
	n.Reset()
	off, err := visitAllLabels(b, off, n.vistAddLabel, allowCompression)
	if err != nil {
		n.Reset()
		return off, err
	}
	n.data = append(n.data, 0) // Add terminator, off counts the terminator already in visitAllLabels.
	return off, nil
}

// Reset resets the Name labels to be empty andatad reuses buffer.
func (n *Name) Reset() { n.data = n.data[:0] }

// CanAddLabel reports whether the label can be added to the name.
func (n *Name) CanAddLabel(label string) bool {
	return len(label) != 0 && len(label) <= 63 && len(label)+len(n.data)+2 <= 255 && // Include len+terminator+label.
		label[len(label)-1] != 0 && // We do not support implicitly zero-terminated labels.
		strings.IndexByte(label, '.') < 0 // See issue golang/go#56246
}

// AddLabel adds a label to the name. If n.CanAddLabel(label) returns false, it panics.
func (n *Name) AddLabel(label string) {
	if !n.CanAddLabel(label) {
		panic(errCantAddLabel.Error())
	}
	if n.isTerminated() {
		n.data = n.data[:len(n.data)-1] // Remove terminator if present to add another label.
	}
	n.data = append(n.data, byte(len(label)))
	n.data = append(n.data, label...)
	n.data = append(n.data, 0)
}

func (n *Name) vistAddLabel(label []byte) {
	n.data = append(n.data, byte(len(label)))
	n.data = append(n.data, label...)
}

func (n *Name) isTerminated() bool {
	return len(n.data) > 0 && n.data[len(n.data)-1] == 0
}

func (n *Name) VisitLabels(fn func(label []byte)) error {
	_, err := n.visitLabels(fn)
	return err
}

// visitLabels visits the labels of n and returns the offset past its terminator.
// Pointers are rejected: n is detached from the message they would point into.
func (n *Name) visitLabels(fn func(label []byte)) (uint16, error) {
	if len(n.data) > 255 {
		return 0, errNameTooLong
	}
	return visitAllLabels(n.data, 0, fn, !allowCompression)
}

func visitAllLabels(msg []byte, off uint16, fn func(b []byte), allowCompression bool) (uint16, error) {
	if len(msg) > math.MaxUint16 {
		return off, errResTooLong
	}
	// ptr is the number of pointers followed.
	var ptr uint8
	// newOff is the offset where the next record will start. Pointers lead
	// to data that belongs to other names and thus doesn't count towards to
	// the usage of this name.
	var newOff = off

	for {
		start, end, isPtr, err := NextLabel(msg[off:])
		if err != nil {
			return off, err
		} else if start == end {
			if ptr == 0 {
				newOff = off + 1 // advance past the null terminator byte
			}
			break
		} else if isPtr {
			if !allowCompression {
				return newOff, errCompressedSRV
			}
			if ptr == 0 {
				newOff = off + 2 // next record follows the 2-byte pointer
			}
			off = start
			if int(off) >= len(msg) {
				return newOff, errInvalidPtr
			} else if ptr++; ptr > 10 {
				return newOff, errTooManyPtr
			}
		} else {
			// Is normal label; start/end are relative to msg[off:].
			fn(msg[off+start : off+end])
			off += end
		}
	}
	return newOff, nil
}

// validate checks n is a single terminated, uncompressed name with no trailing data.
func (n *Name) validate() error {
	end, err := n.visitLabels(func([]byte) {})
	if err != nil {
		return err
	} else if int(end) != len(n.data) {
		return errInvalidName
	}
	return nil
}

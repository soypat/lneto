package tls

import (
	"encoding/binary"

	"github.com/soypat/lneto"
)

// Iterators in this package have the signature of an [iter.Seq2] instead of
// returning one, so they are ranged over as a method value without a call:
//
//	for off, ext := range list.All {
//		for off, ks := range ext.KeyShares {
//		}
//	}
//
// A method value bound to a receiver stays on the caller's stack, while a
// closure returned from a method escapes to the heap. The int key is always the
// item's offset within the enclosing message body, and nested iterators inherit
// that base, so a decoder never has to add up prefix widths.
//
// Every length prefix was checked when the message was parsed, so no iterator
// can fail and none returns an error.

// ExtensionFrame provides access to a single hello extension (RFC 8446 4.2):
//
//	struct {
//	    ExtensionType extension_type; // 2 bytes
//	    opaque extension_data<0..2^16-1>;
//	} Extension;
//
// The lists nested inside an extension are reached with the iterators below,
// each of which walks only its own extension type.
type ExtensionFrame struct {
	buf []byte
	// base is where buf starts within the enclosing message body.
	base int
	// server records that this came from a server hello. The server forms of
	// key_share and supported_versions carry a single value, not a list.
	server bool
}

// NewExtensionFrame wraps buf as an [ExtensionFrame]. It checks the extension's
// own framing but not the structure nested inside extension_data; prefer
// [ParseClientExtensions] or [ParseServerExtensions], which check both.
func NewExtensionFrame(buf []byte) (ExtensionFrame, error) {
	return newExtensionFrame(buf, 0, false)
}

func newExtensionFrame(buf []byte, base int, server bool) (ExtensionFrame, error) {
	if len(buf) < 4 {
		return ExtensionFrame{}, lneto.ErrTruncatedFrame
	}
	n := int(binary.BigEndian.Uint16(buf[2:4]))
	if 4+n > len(buf) {
		return ExtensionFrame{}, lneto.ErrTruncatedFrame
	}
	return ExtensionFrame{buf: buf[:4+n], base: base, server: server}, nil
}

// Type returns the extension type.
func (ef ExtensionFrame) Type() ExtensionType {
	return ExtensionType(binary.BigEndian.Uint16(ef.buf[0:2]))
}

// Length returns the declared extension_data length.
func (ef ExtensionFrame) Length() uint16 {
	return binary.BigEndian.Uint16(ef.buf[2:4])
}

// Data returns the extension_data bytes.
func (ef ExtensionFrame) Data() []byte { return ef.buf[4:] }

// RawData returns the extension bytes, type and length included.
func (ef ExtensionFrame) RawData() []byte { return ef.buf }

// DataOffset is where Data starts within the enclosing message body.
func (ef ExtensionFrame) DataOffset() int { return ef.base + 4 }

// ExtensionList is an extensions block whose framing has been checked, down to
// the lists inside the extensions this package recognizes.
type ExtensionList struct {
	buf    []byte
	base   int
	server bool
}

// ParseClientExtensions validates a ClientHello extensions block. exts is the
// block contents with the outer two-byte length already stripped, and base is
// where exts starts within the enclosing message body.
//
// Unknown extension types, GREASE among them, are accepted and left unchecked.
// A repeated known type is rejected with [lneto.ErrInvalidField]: RFC 8446 4.2
// forbids duplicates, and tolerating them lets this parser and a middlebox act
// on different copies.
func ParseClientExtensions(exts []byte, base int) (ExtensionList, error) {
	return parseExtensions(exts, base, false)
}

// ParseServerExtensions validates a ServerHello extensions block. It differs
// from [ParseClientExtensions] in the key_share and supported_versions forms.
func ParseServerExtensions(exts []byte, base int) (ExtensionList, error) {
	return parseExtensions(exts, base, true)
}

func parseExtensions(exts []byte, base int, server bool) (ExtensionList, error) {
	var seen extSeen
	for off := 0; off < len(exts); {
		ef, err := newExtensionFrame(exts[off:], base+off, server)
		if err != nil {
			return ExtensionList{}, err
		}
		if seen.mark(ef.Type()) {
			return ExtensionList{}, lneto.ErrInvalidField
		}
		err = ef.validate()
		if err != nil {
			return ExtensionList{}, err
		}
		off += len(ef.RawData())
	}
	return ExtensionList{buf: exts, base: base, server: server}, nil
}

// All iterates the extensions in wire order, keyed by the offset of each
// extension's data within the enclosing message body.
func (l ExtensionList) All(yield func(off int, ext ExtensionFrame) bool) {
	for off := 0; off < len(l.buf); {
		ef, err := newExtensionFrame(l.buf[off:], l.base+off, l.server)
		if err != nil {
			return // Framing was checked at parse.
		}
		if !yield(ef.DataOffset(), ef) {
			return
		}
		off += len(ef.RawData())
	}
}

// Bytes returns the block contents.
func (l ExtensionList) Bytes() []byte { return l.buf }

// validate checks the structure nested inside extension_data for the types this
// package walks. The switch mirrors the iterators below: an extension with no
// iterator has no shape to check here.
func (ef ExtensionFrame) validate() error {
	data := ef.Data()
	switch ef.Type() {
	case ExtServerName:
		return validateServerNames(data)
	case ExtALPN:
		return validateALPN(data)
	case ExtSupportedGroups, ExtSignatureAlgorithms, ExtSignatureAlgorithmsCert:
		body, err := vectorU16(data)
		if err != nil {
			return err
		}
		return validateU16List(body)
	case ExtSupportedVersions:
		if ef.server {
			return validateU16List(data) // Bare uint16.
		}
		body, err := vectorU8(data)
		if err != nil {
			return err
		}
		return validateU16List(body)
	case ExtKeyShare:
		return ef.validateKeyShare()
	}
	return nil
}

func validateU16List(b []byte) error {
	if len(b)%2 != 0 {
		return lneto.ErrInvalidLengthField
	}
	return nil
}

func validateServerNames(data []byte) error {
	body, err := vectorU16(data)
	if err != nil {
		return err
	}
	for off := 0; off < len(body); {
		if len(body)-off < 3 {
			return lneto.ErrTruncatedFrame
		}
		n := int(binary.BigEndian.Uint16(body[off+1 : off+3]))
		off += 3
		if n > len(body)-off {
			return lneto.ErrTruncatedFrame
		}
		off += n
	}
	return nil
}

func validateALPN(data []byte) error {
	body, err := vectorU16(data)
	if err != nil {
		return err
	}
	for off := 0; off < len(body); {
		n := int(body[off])
		off++
		if n == 0 {
			// A zero-length name would make a walk unable to advance.
			return lneto.ErrInvalidLengthField
		} else if n > len(body)-off {
			return lneto.ErrTruncatedFrame
		}
		off += n
	}
	return nil
}

func (ef ExtensionFrame) validateKeyShare() error {
	data := ef.Data()
	if ef.server {
		// A ServerHello names one group and its key; a HelloRetryRequest names
		// only the group.
		if len(data) == 2 {
			return nil
		}
		return validateKeyShareEntries(data)
	}
	body, err := vectorU16(data)
	if err != nil {
		return err
	}
	return validateKeyShareEntries(body)
}

func validateKeyShareEntries(b []byte) error {
	for off := 0; off < len(b); {
		if len(b)-off < 4 {
			return lneto.ErrTruncatedFrame
		}
		n := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		off += 4
		if n > len(b)-off {
			return lneto.ErrTruncatedFrame
		}
		off += n
	}
	return nil
}

// KeyShare is one KeyShareEntry of a key_share extension:
//
//	struct {
//	    NamedGroup group;
//	    opaque key_exchange<1..2^16-1>;
//	} KeyShareEntry;
//
// A HelloRetryRequest names a group with no key, so Key may be empty. GREASE
// key shares carry a deliberately absurd key, commonly one byte, so no length
// constraint is placed on Key beyond fitting inside the extension.
type KeyShare struct {
	Group NamedGroup
	Key   []byte
}

// ServerName is one entry of an SNI server_name_list. Type 0 is host_name, the
// only type ever defined.
type ServerName struct {
	Type uint8
	Name []byte
}

// KeyShares iterates the key shares of a key_share extension, in the client or
// server form as the enclosing hello requires, keyed by the offset of the
// key_exchange bytes. Yields nothing for any other extension type.
func (ef ExtensionFrame) KeyShares(yield func(off int, ks KeyShare) bool) {
	if ef.Type() != ExtKeyShare {
		return
	}
	body, base := ef.Data(), ef.DataOffset()
	if ef.server {
		if len(body) == 2 { // HelloRetryRequest: selected_group only.
			yield(base, KeyShare{Group: NamedGroup(binary.BigEndian.Uint16(body))})
			return
		}
	} else {
		b, err := vectorU16(body)
		if err != nil {
			return
		}
		body, base = b, base+2
	}
	for off := 0; off+4 <= len(body); {
		group := NamedGroup(binary.BigEndian.Uint16(body[off : off+2]))
		n := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		off += 4
		if n > len(body)-off {
			return
		}
		if !yield(base+off, KeyShare{Group: group, Key: body[off : off+n]}) {
			return
		}
		off += n
	}
}

// ServerNames iterates the server_name_list of an SNI extension, keyed by the
// offset of the name. Yields nothing for any other extension type.
func (ef ExtensionFrame) ServerNames(yield func(off int, name ServerName) bool) {
	if ef.Type() != ExtServerName {
		return
	}
	body, err := vectorU16(ef.Data())
	if err != nil {
		return
	}
	base := ef.DataOffset() + 2
	for off := 0; off+3 <= len(body); {
		nameType := body[off]
		n := int(binary.BigEndian.Uint16(body[off+1 : off+3]))
		off += 3
		if n > len(body)-off {
			return
		}
		if !yield(base+off, ServerName{Type: nameType, Name: body[off : off+n]}) {
			return
		}
		off += n
	}
}

// ALPNProtos iterates the protocol names of an ALPN extension, keyed by the
// offset of the name. Chrome includes a GREASE entry here, so callers must match
// against their own offer list rather than assuming the first name is
// meaningful. Yields nothing for any other extension type.
func (ef ExtensionFrame) ALPNProtos(yield func(off int, proto []byte) bool) {
	if ef.Type() != ExtALPN {
		return
	}
	body, err := vectorU16(ef.Data())
	if err != nil {
		return
	}
	base := ef.DataOffset() + 2
	for off := 0; off < len(body); {
		n := int(body[off])
		off++
		if n == 0 || n > len(body)-off {
			return
		}
		if !yield(base+off, body[off:off+n]) {
			return
		}
		off += n
	}
}

// SupportedVersions iterates a supported_versions extension. The ClientHello
// form is a list behind a one-byte prefix, unlike every other hello list; the
// ServerHello form is a bare uint16, which yields a single value. Yields nothing
// for any other extension type.
func (ef ExtensionFrame) SupportedVersions(yield func(off int, version uint16) bool) {
	if ef.Type() != ExtSupportedVersions {
		return
	}
	body, base := ef.Data(), ef.DataOffset()
	if !ef.server {
		b, err := vectorU8(body)
		if err != nil {
			return
		}
		body, base = b, base+1
	}
	for off := 0; off+2 <= len(body); off += 2 {
		if !yield(base+off, binary.BigEndian.Uint16(body[off:off+2])) {
			return
		}
	}
}

// SupportedGroups iterates a supported_groups extension, keyed by the group's
// offset. Yields nothing for any other extension type.
func (ef ExtensionFrame) SupportedGroups(yield func(off int, group NamedGroup) bool) {
	body, base, ok := ef.u16Vector(ExtSupportedGroups)
	if !ok {
		return
	}
	for off := 0; off+2 <= len(body); off += 2 {
		if !yield(base+off, NamedGroup(binary.BigEndian.Uint16(body[off:off+2]))) {
			return
		}
	}
}

// SignatureSchemes iterates a signature_algorithms or signature_algorithms_cert
// extension, keyed by the scheme's offset. Yields nothing for any other type.
func (ef ExtensionFrame) SignatureSchemes(yield func(off int, scheme SignatureScheme) bool) {
	want := ef.Type()
	if want != ExtSignatureAlgorithms && want != ExtSignatureAlgorithmsCert {
		return
	}
	body, base, ok := ef.u16Vector(want)
	if !ok {
		return
	}
	for off := 0; off+2 <= len(body); off += 2 {
		if !yield(base+off, SignatureScheme(binary.BigEndian.Uint16(body[off:off+2]))) {
			return
		}
	}
}

// u16Vector returns the contents of a two-byte-prefixed vector and where it
// starts within the message body, or ok false for another extension type.
func (ef ExtensionFrame) u16Vector(want ExtensionType) (body []byte, base int, ok bool) {
	if ef.Type() != want {
		return nil, 0, false
	}
	body, err := vectorU16(ef.Data())
	if err != nil {
		return nil, 0, false
	}
	return body, ef.DataOffset() + 2, true
}

// vectorU16 strips a two-byte length prefix and returns the vector contents.
// It requires the prefix to describe the buffer exactly: trailing bytes mean
// the sender and this parser disagree on the structure, which is precisely the
// ambiguity parser-differential attacks exploit.
func vectorU16(b []byte) ([]byte, error) {
	if len(b) < 2 {
		return nil, lneto.ErrTruncatedFrame
	}
	n := int(binary.BigEndian.Uint16(b[0:2]))
	if n != len(b)-2 {
		if n > len(b)-2 {
			return nil, lneto.ErrTruncatedFrame
		}
		return nil, errTrailingBytes
	}
	return b[2:], nil
}

// vectorU8 strips a one-byte length prefix. See [vectorU16] for why trailing
// bytes are rejected.
func vectorU8(b []byte) ([]byte, error) {
	if len(b) < 1 {
		return nil, lneto.ErrTruncatedFrame
	}
	n := int(b[0])
	if n != len(b)-1 {
		if n > len(b)-1 {
			return nil, lneto.ErrTruncatedFrame
		}
		return nil, errTrailingBytes
	}
	return b[1:], nil
}

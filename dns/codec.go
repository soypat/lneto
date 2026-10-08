package dns

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math"
	"strconv"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

// Global parameters.
const (
	// SizeHeader is the length (in bytes) of a DNS header.
	// A header is comprised of 6 uint16s and no padding.
	SizeHeader = 6 * 2
	// The Internet supports name server access using TCP [RFC-9293] on server
	// port 53 (decimal) as well as datagram access using UDP [RFC-768] on UDP port 53 (decimal).
	ServerPort = 53
	ClientPort = 53
	// Messages carried by UDP are restricted to 512 bytes (not counting the IP
	// or UDP headers).  Longer messages are truncated and the TC bit is set in the header.
	MaxSizeUDP = 512
)

type Question struct {
	Name  Name
	Type  Type
	Class Class
}

type Resource struct {
	header ResourceHeader
	data   []byte
}

// A ResourceHeader is the header of a DNS resource record. There are
// many types of DNS resource records, but they all share the same header.
type ResourceHeader struct {
	Name   Name
	Type   Type
	Class  Class
	TTL    uint32
	Length uint16
}

// NextLabel parses the first control byte of data and returns the position and extent of next DNS label.
//
// For a normal string label (RFC 1035 §3.1), isPointer==false and start/end are
// byte indices into data: data[start:end] holds the raw label bytes.
// A null terminator (c==0) signals the end of the name: start==end==1, err==nil.
//
// For a compression pointer (RFC 1035 §4.1.4), isPointer==true:
//   - start is the absolute target offset within the full DNS message to jump to.
//   - end==0 (sentinel; not a data range).
//
// Returns [lneto.ErrTruncatedFrame] if data is too short to read the full label or pointer.
// Returns errReserved for the 0x40 and 0x80 reserved prefix classes.
func NextLabel(data []byte) (start_RelOrAbs, endRel uint16, isAbsPointer bool, err error) {
	// Default invalid values
	start_RelOrAbs, endRel = 0, 0
	if len(data) == 0 {
		return start_RelOrAbs, endRel, false, lneto.ErrTruncatedFrame
	}
	c := uint16(data[0])
	switch c & 0xc0 {
	case 0:
		start_RelOrAbs = 1
		// String label segment.
		if c == 0 {
			return start_RelOrAbs, start_RelOrAbs, false, nil // Null terminator. String ended.
		}
		endRel = start_RelOrAbs + c
		if int(endRel) > len(data) {
			return start_RelOrAbs, endRel, false, lneto.ErrTruncatedFrame
		}
		// Reject names containing dots. See issue golang/go#56246
		if bytes.IndexByte(data[start_RelOrAbs:endRel], '.') >= 0 {
			return start_RelOrAbs, endRel, false, errInvalidName
		}
		// Correct label!
	case 0xc0:
		// Pointer. Start is absolute index in DNS message.
		isAbsPointer = true
		if len(data) < 2 {
			return start_RelOrAbs, endRel, isAbsPointer, lneto.ErrTruncatedFrame // Need more data to fully read pointer.
		}
		c1 := uint16(data[1])
		start_RelOrAbs = (c^0xC0)<<8 | c1
	default:
		err = errReserved
	}
	return start_RelOrAbs, endRel, isAbsPointer, err
}

// PutMessage writes DNS message to dst in wire format and returns length written. Nil sections encoded as empty.
func PutMessage(dst []byte, txid uint16, flags HeaderFlags, questions []Question, answers, authorities, additionals []Resource) (n int, err error) {
	toWrite := SizeHeader + lenSections(questions, answers, authorities, additionals)
	if len(dst) < toWrite {
		return 0, lneto.ErrShortBuffer
	}
	dst = dst[:0]
	// Set the buffer directly with header fields.
	f, err := NewFrame(dst[len(dst) : len(dst)+SizeHeader])
	if err != nil {
		return 0, err
	}
	f.SetTxID(txid)
	f.SetFlags(flags)
	f.SetQDCount(uint16(len(questions)))
	f.SetANCount(uint16(len(answers)))
	f.SetNSCount(uint16(len(authorities)))
	f.SetARCount(uint16(len(additionals)))
	dst = dst[:len(dst)+SizeHeader]
	for i := range questions {
		dst, err = questions[i].appendTo(dst)
		if err != nil {
			return len(dst), err
		}
	}
	for _, rs := range [...][]Resource{answers, authorities, additionals} {
		for i := range rs {
			dst, err = rs[i].appendTo(dst)
			if err != nil {
				return len(dst), err
			}
		}
	}
	if len(dst) != toWrite {
		panic("dns: toWrite!=n")
	}
	return len(dst), nil
}

// DecodeMessage decodes the DNS message into question, answer, authority and additional resources.
// It returns the number of bytes
// consumed from b (0 if no bytes were consumed) and any error encountered.
// If the message was not completely parsed due to LimitResourceDecoding,
// incompleteButOK is true and an error is returned, though the message is still usable.
//
// The slice memory is overwritten and capacity used as the limit of encoding.
// If the argument slice is nil it is skipped for decoding but does not prevent further decoding
// of other answers, authorities or additionals from being decoded.
func DecodeMessage(q *[]Question, answers, authorities, additionals *[]Resource, msg []byte) (_ uint16, incompleteButOK bool, err error) {
	hdr, err := NewFrame(msg)
	if err != nil {
		return 0, false, err
	}
	qd := hdr.QDCount()
	nq := int(qd)
	off := uint16(SizeHeader)
	// Return tooManyErr if found to flag to the caller that the message was
	// decoded but contained too many resources to decode completely.
	var tooManyErr error
	switch {
	case nq > caporzero(q):
		tooManyErr = errTooManyQuestions
	case int(hdr.ANCount()) > caporzero(answers):
		tooManyErr = errTooManyAnswers
	case int(hdr.NSCount()) > caporzero(authorities):
		tooManyErr = errTooManyAuthorities
	case int(hdr.ARCount()) > caporzero(additionals):
		tooManyErr = errTooManyAdditionals
	}
	if q != nil {
		if nq > cap(*q) {
			nq = cap(*q)
		}
		*q = (*q)[:nq]
		for i := 0; i < nq; i++ {
			off, err = (*q)[i].Decode(msg, off)
			if err != nil {
				*q = (*q)[:i] // Trim non-decoded/failed questions.
				return off, false, err
			}
		}
	} else {
		nq = 0 // No question slice provided, skip all questions below.
	}
	// Skip undecoded questions.
	for i := 0; i < int(qd)-nq; i++ {
		off, err = skipQuestion(msg, off)
		if err != nil {
			return off, false, err
		}
	}
	off, err = decodeToCapResources(answers, msg, hdr.ANCount(), off)
	if err != nil {
		return off, false, err
	}
	off, err = decodeToCapResources(authorities, msg, hdr.NSCount(), off)
	if err != nil {
		return off, false, err
	}
	off, err = decodeToCapResources(additionals, msg, hdr.ARCount(), off)
	if err != nil {
		return off, false, err
	}
	return off, tooManyErr != nil, tooManyErr
}

func decodeToCapResources(dst *[]Resource, msg []byte, nrec, off uint16) (_ uint16, err error) {
	originalRec := nrec
	if dst == nil {
		nrec = 0 // No resource slice provided, skip all resources below.
	} else {
		if nrec > uint16(cap(*dst)) {
			nrec = uint16(cap(*dst)) // Decode up to cap. Caller will return an error flag.
		}
		*dst = (*dst)[:nrec]
		for i := uint16(0); i < nrec; i++ {
			off, err = (*dst)[i].Decode(msg, off)
			if err != nil {
				*dst = (*dst)[:i] // Trim non-decoded/failed resources.
				return off, err
			}
		}
	}
	// Parse undecoded resources, effectively skipping them.
	for i := uint16(0); i < originalRec-nrec; i++ {
		off, err = skipResource(msg, off)
		if err != nil {
			return off, err
		}
	}
	return off, nil
}

func skipQuestion(msg []byte, off uint16) (_ uint16, err error) {
	off, err = skipName(msg, off)
	if err != nil {
		return off, err
	}
	if int(off)+4 > len(msg) {
		return off, lneto.ErrTruncatedFrame
	}
	return off + 4, nil
}

func skipResource(msg []byte, off uint16) (_ uint16, err error) {
	off, err = skipName(msg, off)
	if err != nil {
		return off, err
	}
	// | Name... | Type16 | Class16 | TTL32 | Length16 | Data... |
	if int(off)+10 > len(msg) {
		return off, lneto.ErrTruncatedFrame
	}
	end := int(off) + 10 + int(binary.BigEndian.Uint16(msg[off+8:]))
	if end > len(msg) {
		return off, lneto.ErrTruncatedFrame
	}
	return uint16(end), nil
}

// validateSections checks the sections can be encoded by [EncodeMessage] into a well-formed DNS message.
func validateSections(vld *lneto.Validator, questions []Question, answers, authorities, additionals []Resource) {
	if SizeHeader+lenSections(questions, answers, authorities, additionals) > math.MaxUint16 {
		vld.AddError(errResTooLong)
		return
	}
	for i := range questions {
		if err := questions[i].Name.validate(); err != nil {
			vld.AddError(err)
		}
	}
	validateResources(vld, answers, false)
	validateResources(vld, authorities, false)
	validateResources(vld, additionals, true)
}

// lenSections returns the wire length of all sections. It is an int so
// [validateSections] can detect messages that overflow the uint16 [Message.Len].
// Each record is summed as an int too: [Resource.Len] wraps for RDLENGTH near 65535.
func lenSections(questions []Question, answers, authorities, additionals []Resource) (l int) {
	for i := range questions {
		l += len(questions[i].Name.data) + 4
	}
	for _, rs := range [...][]Resource{answers, authorities, additionals} {
		for i := range rs {
			l += rs[i].wireLen()
		}
	}
	return l
}

func caporzero[T any](v *[]T) int {
	if v == nil {
		return 0
	}
	return cap(*v)
}

func (r *ResourceHeader) Reset() {
	r.Name.Reset()
	*r = ResourceHeader{Name: r.Name} // Reuse Name's buffer.
}

// ownedBy reports whether the record's owner name is name.
func (h *ResourceHeader) ownedBy(name Name) bool {
	// Fold: the server chooses the case of both the CNAME target and the owner
	// name of the records it aliases, and may randomize it (DNS 0x20).
	return NamesEqualFold(h.Name, name)
}

// String returns a string representation of the header.
func (h *ResourceHeader) String() string {
	b, _ := h.AppendText(make([]byte, 0, 64))
	return string(b)
}

func (dst *ResourceHeader) CopyFrom(rh ResourceHeader) {
	dst.Name.CopyFrom(rh.Name)
	dst.Type = rh.Type
	dst.Class = rh.Class
	dst.TTL = rh.TTL
	dst.Length = rh.Length
}

// AppendText appends a human readable representation of the header to b and
// returns the resulting slice. It implements [encoding.TextAppender].
func (h *ResourceHeader) AppendText(b []byte) ([]byte, error) {
	b = h.Name.AppendDottedTo(b)
	b = append(b, ' ')
	b = append(b, h.Type.String()...)
	b = append(b, ' ')
	b = append(b, h.Class.String()...)
	b = append(b, " ttl="...)
	b = strconv.AppendUint(b, uint64(h.TTL), 10)
	b = append(b, " len="...)
	b = strconv.AppendUint(b, uint64(h.Length), 10)
	return b, nil
}

func (rhdr *ResourceHeader) Decode(msg []byte, off uint16) (uint16, error) {
	off, err := rhdr.Name.Decode(msg, off)
	if err != nil {
		return off, err
	}
	if off+10 > uint16(len(msg)) {
		return off, errResourceLen
	}
	rhdr.Type = Type(binary.BigEndian.Uint16(msg[off:]))     // 2
	rhdr.Class = Class(binary.BigEndian.Uint16(msg[off+2:])) // 4
	rhdr.TTL = binary.BigEndian.Uint32(msg[off+4:])          // 8
	rhdr.Length = binary.BigEndian.Uint16(msg[off+8:])       // 10
	return off + 10, nil
}

func (rhdr *ResourceHeader) appendTo(buf []byte) (_ []byte, err error) {
	buf, err = rhdr.Name.AppendTo(buf)
	if err != nil {
		return buf, err
	}
	buf = append16(buf, uint16(rhdr.Type))
	buf = append16(buf, uint16(rhdr.Class))
	buf = append32(buf, rhdr.TTL)
	buf = append16(buf, rhdr.Length)
	return buf, nil
}

func NewResource(name Name, typ Type, class Class, ttl uint32, data []byte) Resource {
	return Resource{
		header: ResourceHeader{
			Name:   name,
			Type:   typ,
			Class:  class,
			TTL:    ttl,
			Length: uint16(len(data)),
		},
		data: data,
	}
}

// String returns a string representation of the Resource: its header followed by
// the record's data.
func (r *Resource) String() string {
	b, _ := r.AppendText(make([]byte, 0, 96))
	return string(b)
}
func (r *Resource) Header() ResourceHeader { return r.header }

// Len returns the length over-the-wire of the encoded Resource.
// It wraps if the resource does not fit in a DNS message, see [Message.Validate].
func (r *Resource) Len() uint16 { return uint16(r.wireLen()) }

// wireLen returns the length over-the-wire of the encoded Resource without wrapping.
func (r *Resource) wireLen() int { return len(r.header.Name.data) + 10 + len(r.data) }

func (r *Resource) RawSet(hdr ResourceHeader, data []byte) { r.header, r.data = hdr, data }

func (r *Resource) RawData() []byte { return r.data }

func (r *Resource) Reset() {
	r.header.Reset()
	r.data = r.data[:0]
}

// CNAMEView returns the canonical name held by a CNAME record, aliasing the
// Resource's buffer. It returns a zero Name for any other record type.
func (r *Resource) CNAMEView() Name {
	if r.header.Type != TypeCNAME {
		return Name{}
	}
	return Name{data: r.RawData()}
}

func (r *Resource) Decode(b []byte, off uint16) (uint16, error) {
	off, err := r.header.Decode(b, off)
	if err != nil {
		return off, err
	}
	if r.header.Length > uint16(len(b[off:])) {
		return off, errResourceLen
	}
	end := off + r.header.Length
	if r.header.Type == TypeCNAME {
		// CNAME data is a name which may use message compression. Expand it now
		// since r.data is detached from b, leaving pointers unresolvable later.
		cname := Name{data: r.data[:0]}
		if _, derr := cname.Decode(b, off); derr == nil {
			r.data = cname.data
			r.header.Length = uint16(len(r.data))
			return end, nil
		}
	}
	r.data = append(r.data[:0], b[off:end]...)
	return end, nil
}

// SetA sets an A (IPv4 address) resource record, reusing internal buffers.
func (r *Resource) SetA(name Name, class Class, ttl uint32, addr []byte) {
	r.copyHeader(name, TypeA, class, ttl)
	r.data = append(r.data[:0], addr...)
	r.header.Length = uint16(len(r.data))
}

// SetPTR sets a PTR (pointer) resource record, reusing internal buffers.
func (r *Resource) SetPTR(name Name, class Class, ttl uint32, target Name) {
	r.copyHeader(name, TypePTR, class, ttl)
	r.data, _ = target.AppendTo(r.data[:0])
	r.header.Length = uint16(len(r.data))
}

// SetSRV sets a SRV (service locator) resource record, reusing internal buffers.
func (r *Resource) SetSRV(name Name, class Class, ttl uint32, priority, weight, port uint16, target Name) {
	r.copyHeader(name, TypeSRV, class, ttl)
	r.data = binary.BigEndian.AppendUint16(r.data[:0], priority)
	r.data = binary.BigEndian.AppendUint16(r.data, weight)
	r.data = binary.BigEndian.AppendUint16(r.data, port)
	r.data, _ = target.AppendTo(r.data)
	r.header.Length = uint16(len(r.data))
}

// SetTXT sets a TXT resource record, reusing internal buffers.
func (r *Resource) SetTXT(name Name, class Class, ttl uint32, txt []byte) {
	r.copyHeader(name, TypeTXT, class, ttl)
	if len(txt) == 0 {
		r.data = append(r.data[:0], 0)
	} else {
		r.data = append(r.data[:0], txt...)
	}
	r.header.Length = uint16(len(r.data))
}

func (r *Resource) copyHeader(name Name, typ Type, class Class, ttl uint32) {
	r.header.Name.CopyFrom(name)
	r.header.Type = typ
	r.header.Class = class
	r.header.TTL = ttl
}

func (dst *Resource) CopyFrom(r Resource) {
	dst.header.CopyFrom(r.header)
	dst.data = append(dst.data[:0], r.data...)
}

// AppendText appends a human readable representation of the Resource to b: the
// header followed by the record's data, in dotted format for CNAME records and
// hexadecimal otherwise. It implements [encoding.TextAppender].
func (r *Resource) AppendText(b []byte) (_ []byte, err error) {
	b, err = r.header.AppendText(b)
	if err != nil {
		return b, err
	}
	b = append(b, " data="...)
	if r.header.Type == TypeCNAME {
		cname := r.CNAMEView()
		return cname.AppendDottedTo(b), nil
	}
	return hex.AppendEncode(b, r.RawData()), nil
}

func (r *Resource) appendTo(buf []byte) (_ []byte, err error) {
	buf, err = r.header.appendTo(buf)
	if err != nil {
		return buf, err
	}
	buf = append(buf, r.data...)
	return buf, nil
}

func (r *Resource) validate() error {
	if err := r.header.Name.validate(); err != nil {
		return err
	} else if int(r.header.Length) != len(r.data) {
		return lneto.ErrInvalidLengthField // appendTo writes both as they are.
	}
	switch r.header.Type {
	case TypeA:
		if len(r.data) != 4 {
			return lneto.ErrInvalidAddr
		}
	case TypeAAAA:
		if len(r.data) != 16 {
			return lneto.ErrInvalidAddr
		}
	case TypeCNAME:
		cname := r.CNAMEView()
		return cname.validate()
	case TypeOPT:
		if !NamesEqual(r.header.Name, Name{data: rootDomain}) {
			return errInvalidName
		}
		// TODO: TXT, SRV, MX checks. Parsers yet unimplemented.
	}
	return nil
}

func (q *Question) Reset() {
	q.Name.Reset()
	*q = Question{Name: q.Name} // Reuse Name's buffer.
}

// Len returns Question's length over-the-wire.
func (q *Question) Len() uint16 { return q.Name.Len() + 4 }

// String returns a string representation of the Question with the Name in dotted format.
func (q *Question) String() string {
	b, _ := q.AppendText(make([]byte, 0, 32))
	return string(b)
}

// AppendText appends a human readable representation of the Question to b with
// the Name in dotted format. It implements [encoding.TextAppender].
func (q *Question) AppendText(b []byte) ([]byte, error) {
	b = q.Name.AppendDottedTo(b)
	b = append(b, ' ')
	b = append(b, q.Type.String()...)
	b = append(b, ' ')
	b = append(b, q.Class.String()...)
	return b, nil
}

func (q *Question) Decode(msg []byte, off uint16) (uint16, error) {
	off, err := q.Name.Decode(msg, off)
	if err != nil {
		return off, err
	}
	if off+4 > uint16(len(msg)) {
		return off, errResourceLen
	}
	q.Type = Type(binary.BigEndian.Uint16(msg[off:]))
	q.Class = Class(binary.BigEndian.Uint16(msg[off+2:]))
	return off + 4, nil
}

func (q *Question) appendTo(buf []byte) (_ []byte, err error) {
	buf, err = q.Name.AppendTo(buf)
	if err != nil {
		return buf, err
	}
	buf = append16(buf, uint16(q.Type))
	buf = append16(buf, uint16(q.Class))
	return buf, nil
}

func (dst *Question) CopyFrom(q Question) {
	dst.Name.CopyFrom(q.Name)
	dst.Class = q.Class
	dst.Type = q.Type
}

func append16(b []byte, v uint16) []byte {
	binary.BigEndian.PutUint16(b[len(b):len(b)+2], v)
	return b[:len(b)+2]
}

// equalWireFold reports whether the uncompressed question at msg[off:] equals q and returns
// the offset past it. Names compare under ASCII case folding since servers may echo the
// question with randomized case (DNS 0x20). Label lengths are never letters so fold safely.
func (q *Question) equalWireFold(msg []byte, off uint16) (next uint16, ok bool) {
	nameEnd := int(off) + len(q.Name.data)
	end := nameEnd + 4
	if end > len(msg) || !internal.BytesEqualFoldASCII(q.Name.data, msg[off:nameEnd]) ||
		binary.BigEndian.Uint16(msg[nameEnd:]) != uint16(q.Type) ||
		binary.BigEndian.Uint16(msg[nameEnd+2:]) != uint16(q.Class) {
		return off, false
	}
	return uint16(end), true
}

func append32(b []byte, v uint32) []byte {
	binary.BigEndian.PutUint32(b[len(b):len(b)+4], v)
	return b[:len(b)+4]
}

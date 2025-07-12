package dns

import (
	"bytes"
	"encoding/binary"
	"math"
	"slices"
	"strconv"
	"strings"
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

type Message struct {
	Questions   []Question
	Answers     []Resource
	Authorities []Resource
	Additionals []Resource
}

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

type Name struct {
	data []byte
}

type ZFlags uint16

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

func (r *Resource) SetEDNS0(UDPlength uint16, rcode RCode, zflags ZFlags, data []byte) {
	if len(data) > math.MaxUint16-2 || len(data)+8+2*SizeHeader > int(UDPlength) {
		panic("too large data")
	}
	r.header = ResourceHeader{
		Name:   Name{data: rootDomain},
		Type:   TypeOPT,
		Class:  Class(UDPlength),
		TTL:    uint32(rcode)<<24 | 0<<16 | uint32(zflags),
		Length: uint16(len(data)),
	}
	r.data = append(r.data[:0], data...)
}

// Decode decodes the DNS message in b into m. It returns the number of bytes
// consumed from b (0 if no bytes were consumed) and any error encountered.
// If the message was not completely parsed due to LimitResourceDecoding,
// incompleteButOK is true and an error is returned, though the message is still usable.
func (m *Message) Decode(msg []byte) (_ uint16, incompleteButOK bool, err error) {
	if len(msg) < SizeHeader {
		return 0, false, errBaseLen
	} else if len(msg) > math.MaxUint16 {
		return 0, false, errResTooLong
	}
	m.Reset()
	hdr, err := NewFrame(msg)
	if err != nil {
		return 0, false, err
	}
	nq := int(hdr.QDCount())
	off := uint16(SizeHeader)
	// Return tooManyErr if found to flag to the caller that the message was
	// decoded but contained too many resources to decode completely.

	var tooManyErr error
	switch {
	case nq > cap(m.Questions):
		tooManyErr = errTooManyQuestions
	case hdr.ANCount() > uint16(cap(m.Answers)):
		tooManyErr = errTooManyAnswers
	case hdr.NSCount() > uint16(cap(m.Authorities)):
		tooManyErr = errTooManyAuthorities
	case hdr.ARCount() > uint16(cap(m.Additionals)):
		tooManyErr = errTooManyAdditionals
	}
	if nq > cap(m.Questions) {
		nq = cap(m.Questions)
	}
	m.Questions = m.Questions[:nq]
	for i := 0; i < nq; i++ {
		off, err = m.Questions[i].Decode(msg, off)
		if err != nil {
			m.Questions = m.Questions[:i] // Trim non-decoded/failed questions.
			return off, false, err
		}
	}
	// Skip undecoded questions.
	qd := hdr.QDCount()
	for i := 0; i < int(qd)-nq; i++ {
		off, err = skipQuestion(msg, off)
		if err != nil {
			return off, false, err
		}
	}

	off, err = decodeToCapResources(&m.Answers, msg, hdr.ANCount(), off)
	if err != nil {
		return off, false, err
	}
	off, err = decodeToCapResources(&m.Authorities, msg, hdr.NSCount(), off)
	if err != nil {
		return off, false, err
	}
	off, err = decodeToCapResources(&m.Additionals, msg, hdr.ARCount(), off)
	if err != nil {
		return off, false, err
	}
	return off, tooManyErr != nil, tooManyErr
}

func decodeToCapResources(dst *[]Resource, msg []byte, nrec, off uint16) (_ uint16, err error) {
	originalRec := nrec
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
	if off+4 > uint16(len(msg)) {
		return off, errBaseLen
	}
	return off + 4, nil
}

func skipResource(msg []byte, off uint16) (_ uint16, err error) {
	off, err = skipName(msg, off)
	if err != nil {
		return off, err
	}
	// | Name... | Type16 | Class16 | TTL32 | Length16 | Data... |
	datalen := binary.BigEndian.Uint16(msg[off+8:])
	off += datalen + 10
	if off > uint16(len(msg)) {
		return off, errBaseLen
	}
	return off, nil
}

func skipName(msg []byte, off uint16) (uint16, error) {
	return visitAllLabels(msg, off, func(b []byte) {}, allowCompression)
}

func (m *Message) AppendTo(buf []byte, txid uint16, flags HeaderFlags) (_ []byte, err error) {
	nq := uint16(len(m.Questions))
	nans := uint16(len(m.Answers))
	nauth := uint16(len(m.Authorities))
	nadd := uint16(len(m.Additionals))
	var hdr [SizeHeader]byte
	f, err := NewFrame(hdr[:])
	if err != nil {
		return buf, err
	}
	f.SetTxID(txid)
	f.SetFlags(flags)
	f.SetQDCount(nq)
	f.SetANCount(nans)
	f.SetNSCount(nauth)
	f.SetARCount(nadd)

	buf = slices.Grow(buf, int(m.Len()))
	buf = append(buf, hdr[:]...)
	for _, q := range m.Questions {
		buf, err = q.appendTo(buf)
		if err != nil {
			return buf, err
		}
	}
	for _, r := range m.Answers {
		buf, err = r.appendTo(buf)
		if err != nil {
			return buf, err
		}
	}
	for _, r := range m.Authorities {
		buf, err = r.appendTo(buf)
		if err != nil {
			return buf, err
		}
	}
	for _, r := range m.Additionals {
		buf, err = r.appendTo(buf)
		if err != nil {
			return buf, err
		}
	}
	return buf, nil
}

func (m *Message) Len() uint16 {
	return SizeHeader + m.lenResources()
}

func (m *Message) lenResources() (l uint16) {
	for i := range m.Questions {
		l += m.Questions[i].Len()
	}
	for i := range m.Answers {
		l += m.Answers[i].Len()
	}
	for i := range m.Authorities {
		l += m.Authorities[i].Len()
	}
	for i := range m.Additionals {
		l += m.Additionals[i].Len()
	}
	return l
}

func (m *Message) AddQuestions(questions []Question) {
	// This question slice handling here is done in spirit of DNSClient being owner of its own buffer.
	// If this is not done we risk the Questions being edited by user and interfering with the DNS request.
	qoff := len(m.Questions)
	m.Questions = slices.Grow(m.Questions, len(questions))
	m.Questions = m.Questions[:qoff+len(questions)]
	for i := range questions {
		m.Questions[qoff+i].CopyFrom(questions[i])
	}
}

func (m *Message) AddAdditionals(rsc []Resource) {
	aoff := len(m.Additionals)
	m.Additionals = slices.Grow(m.Additionals, len(rsc))
	m.Additionals = m.Additionals[:aoff+len(rsc)]
	for i := range rsc {
		m.Additionals[aoff+i].CopyFrom(rsc[i])
	}
}

func (m *Message) LimitResourceDecoding(maxQ, maxAns, maxAuth, maxAdd uint16) {
	m.Questions = slices.Grow(m.Questions, int(maxQ))
	m.Answers = slices.Grow(m.Answers, int(maxQ))
	m.Authorities = slices.Grow(m.Authorities, int(maxQ))
	m.Additionals = slices.Grow(m.Additionals, int(maxQ))
}

func (m *Message) Reset() {
	m.Questions = m.Questions[:0]
	m.Answers = m.Answers[:0]
	m.Authorities = m.Authorities[:0]
	m.Additionals = m.Additionals[:0]
}

// String returns a string representation of the header.
func (h *ResourceHeader) String() string {
	return h.Name.String() + " " + h.Type.String() + " " + h.Class.String() +
		" ttl=" + strconv.FormatUint(uint64(h.TTL), 10) + " len=" + strconv.FormatUint(uint64(h.Length), 10)
}

func (r *Resource) Reset() {
	r.header.Reset()
	r.data = r.data[:0]
}

func (r *Resource) RawData() []byte {
	length := r.header.Length
	if int(length) > len(r.data) {
		length = uint16(len(r.data))
	}
	return r.data[:length]
}

func (q *Question) Reset() {
	q.Name.Reset()
	*q = Question{Name: q.Name} // Reuse Name's buffer.
}

// Len returns Question's length over-the-wire.
func (q *Question) Len() uint16 { return q.Name.Len() + 4 }

func (r *ResourceHeader) Reset() {
	r.Name.Reset()
	*r = ResourceHeader{Name: r.Name} // Reuse Name's buffer.
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

// String returns a string representation of the Question with the Name in dotted format.
func (q *Question) String() string {
	return q.Name.String() + " " + q.Type.String() + " " + q.Class.String()
}

func (r *Resource) Decode(b []byte, off uint16) (uint16, error) {
	off, err := r.header.Decode(b, off)
	if err != nil {
		return off, err
	}
	if r.header.Length > uint16(len(b[off:])) {
		return off, errResourceLen
	}
	r.data = append(r.data[:0], b[off:off+r.header.Length]...)
	return off + r.header.Length, nil
}

func (r *Resource) appendTo(buf []byte) (_ []byte, err error) {
	buf, err = r.header.appendTo(buf)
	if err != nil {
		return buf, err
	}
	buf = append(buf, r.data...)
	return buf, nil
}

func (r *Resource) Len() uint16 {
	return r.header.Name.Len() + 10 + uint16(len(r.data))
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

func MustNewName(s string) Name {
	name, err := NewName(s)
	if err != nil {
		panic(err)
	}
	return name
}

var rootDomain = []byte{0}

// NewName parses a domain name and returns a new Name.
func NewName(domain string) (Name, error) {
	if domain == "" {
		return Name{}, errEmptyDomainName
	}
	if len(domain) == 1 && domain[0] == '.' {
		return Name{data: append([]byte{}, rootDomain...)}, nil
	}
	var name Name
	for len(domain) > 0 {
		idx := strings.IndexByte(domain, '.')
		done := idx < 0 || idx+1 > len(domain)
		if done {
			idx = len(domain)
		}
		if !name.CanAddLabel(domain[:idx]) {
			return Name{}, errCantAddLabel
		}
		name.AddLabel(domain[:idx])
		if done {
			break
		}
		domain = domain[idx+1:]
	}
	return name, nil
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
	if len(n.data) > 255 {
		return errNameTooLong
	}
	_, err := visitAllLabels(n.data, 0, fn, allowCompression)
	return err
}

func append16(b []byte, v uint16) []byte {
	binary.BigEndian.PutUint16(b[len(b):len(b)+2], v)
	return b[:len(b)+2]
}

func append32(b []byte, v uint32) []byte {
	binary.BigEndian.PutUint32(b[len(b):len(b)+4], v)
	return b[:len(b)+4]
}

func visitAllLabels(msg []byte, off uint16, fn func(b []byte), allowCompression bool) (uint16, error) {
	// currOff is the current working offset.
	currOff := off
	if len(msg) > math.MaxUint16 {
		return off, errResTooLong
	}
	// ptr is the number of pointers followed.
	var ptr uint8
	// newOff is the offset where the next record will start. Pointers lead
	// to data that belongs to other names and thus doesn't count towards to
	// the usage of this name.
	var newOff = off

LOOP:
	for {
		if currOff >= uint16(len(msg)) {
			return off, errBaseLen
		}
		c := uint16(msg[currOff])
		currOff++
		switch c & 0xc0 {
		case 0x00: // String label (segment).
			if c == 0x00 {
				break LOOP // Nominal end of name, always ends with null terminator.
			}
			endOff := currOff + c
			if endOff > uint16(len(msg)) {
				return off, errCalcLen
			}

			// Reject names containing dots. See issue golang/go#56246
			if bytes.IndexByte(msg[currOff:endOff], '.') >= 0 {
				return off, errInvalidName
			}

			fn(msg[currOff:endOff])
			currOff = endOff

		case 0xc0: // Pointer.
			// https://cs.opensource.google/go/x/net/+/refs/tags/v0.19.0:dns/dnsmessage/message.go;l=2078
			if !allowCompression {
				return off, errCompressedSRV
			}
			if currOff >= uint16(len(msg)) {
				return off, errInvalidPtr
			}
			c1 := msg[currOff]
			currOff++
			if ptr == 0 {
				newOff = currOff
			}
			// Don't follow too many pointers, maybe there's a loop.
			if ptr++; ptr > 10 {
				return off, errTooManyPtr
			}
			currOff = (c^0xC0)<<8 | uint16(c1)
		default:
			// Prefixes 0x80 and 0x40 are reserved.
			return off, errReserved
		}
	}
	if ptr == 0 {
		newOff = currOff
	}
	return newOff, nil
}

func (dst *Message) CopyFrom(m Message) {
	reuseGrowSlice(&dst.Questions, len(m.Questions))
	reuseGrowSlice(&dst.Answers, len(m.Answers))
	reuseGrowSlice(&dst.Authorities, len(m.Authorities))
	reuseGrowSlice(&dst.Additionals, len(m.Additionals))
	for i := range dst.Questions {
		dst.Questions[i].CopyFrom(m.Questions[i])
	}
	for i := range dst.Answers {
		dst.Answers[i].CopyFrom(m.Answers[i])
	}
	for i := range dst.Authorities {
		dst.Authorities[i].CopyFrom(m.Authorities[i])
	}
	for i := range dst.Additionals {
		dst.Additionals[i].CopyFrom(m.Additionals[i])
	}
}

func (dst *Question) CopyFrom(q Question) {
	dst.Name.CopyFrom(q.Name)
	dst.Class = q.Class
	dst.Type = q.Type
}

func (dst *Resource) CopyFrom(r Resource) {
	dst.header.CopyFrom(r.header)
	dst.data = append(dst.data[:0], r.data...)
}

func (dst *ResourceHeader) CopyFrom(rh ResourceHeader) {
	dst.Name.CopyFrom(rh.Name)
	dst.Type = rh.Type
	dst.Class = rh.Class
	dst.TTL = rh.TTL
	dst.Length = rh.Length
}

func reuseGrowSlice[T any](dst *[]T, n int) {
	if n == 0 {
		return
	}
	*dst = slices.Grow(*dst, n)[:n]
}

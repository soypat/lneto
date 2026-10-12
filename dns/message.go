package dns

import (
	"math"
	"net/netip"
	"slices"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

// Message is a convenience type for decoding DNS messages and storing results in a single object.
// Message is designed for ease of memory reuse. All internal buffers in a Message are reused in methods:
// - [Message.Decode]: Limited in decode size by [Message.LimitResourceDecoding] which must be called beforehand.
// - [Message.CopyFrom]
// - [Message.AddQuestions]
type Message struct {
	Questions   []Question
	Answers     []Resource
	Authorities []Resource
	Additionals []Resource
}

func (m *Message) Len() uint16 {
	return uint16(SizeHeader + m.lenResources())
}

// Decode decodes the DNS message in b into m. It is a convenience wrapper for [DecodeMessage].
func (m *Message) Decode(msg []byte) (_ uint16, incompleteButOK bool, err error) {
	return DecodeMessage(&m.Questions, &m.Answers, &m.Authorities, &m.Additionals, msg)
}

func (m *Message) AppendTo(buf []byte, txid uint16, flags HeaderFlags) (_ []byte, err error) {
	nq := uint16(len(m.Questions))
	nans := uint16(len(m.Answers))
	nauth := uint16(len(m.Authorities))
	nadd := uint16(len(m.Additionals))
	buf = slices.Grow(buf, int(m.Len()))
	// Set the buffer directly with header fields.
	f, err := NewFrame(buf[len(buf) : len(buf)+SizeHeader])
	if err != nil {
		return buf, err
	}
	f.SetTxID(txid)
	f.SetFlags(flags)
	f.SetQDCount(nq)
	f.SetANCount(nans)
	f.SetNSCount(nauth)
	f.SetARCount(nadd)
	buf = buf[:len(buf)+SizeHeader]
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

// WriteAnswers writes the addresses answering host into dst, following the
// CNAME chain rooted at host. It returns the number of addresses written.
func (m *Message) WriteAnswers(dst []netip.Addr, host Name) (n uint16, err error) {
	// Each round resolves one CNAME, which consumes an answer. Bounding the
	// walk by the answer count is thus enough to reach the addresses, and
	// terminates on cyclic chains.
	alias := host // Name reached so far by following CNAMEs.
	for range m.Answers {
		var next Name
		for i := range m.Answers {
			ans := &m.Answers[i]
			if !ans.header.ownedBy(alias) {
				continue
			}
			switch {
			case ans.header.Type.IsIPAddr():
				if int(n) >= len(dst) {
					return n, lneto.ErrExhausted
				}
				addr, ok := netip.AddrFromSlice(ans.RawData())
				if !ok {
					err = lneto.ErrInvalidAddr
					continue
				}
				dst[n] = addr
				n++
			case ans.header.Type == TypeCNAME:
				if cname := ans.CNAMEView(); cname.Len() != 0 {
					next = cname
				}
			}
		}
		if n > 0 || next.Len() == 0 {
			break
		}
		alias = next
	}
	return n, err
}

func (dst *Message) CopyFrom(m Message) {
	internal.SliceReuse(&dst.Questions, len(m.Questions))
	internal.SliceReuse(&dst.Answers, len(m.Answers))
	internal.SliceReuse(&dst.Authorities, len(m.Authorities))
	internal.SliceReuse(&dst.Additionals, len(m.Additionals))
	dst.Questions = dst.Questions[:len(m.Questions)]
	dst.Answers = dst.Answers[:len(m.Answers)]
	dst.Authorities = dst.Authorities[:len(m.Authorities)]
	dst.Additionals = dst.Additionals[:len(m.Additionals)]
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

// LimitResourceDecoding sets the maximum number of resources that can be decoded
// by a subsequent call to [Message.Decode]. This is useful for limiting memory
// usage when decoding untrusted DNS messages.
//
// After calling LimitResourceDecoding, a call to Decode will:
//   - Decode at most maxQ questions
//   - Decode at most maxAns answers
//   - Decode at most maxAuth authority records
//   - Decode at most maxAdd additional records
//
// If the message contains more resources than the limits, Decode returns
// incompleteButOK=true along with an error indicating which resource type
// exceeded the limit. The message is still usable with the decoded resources.
//
// Call this method before Decode to set up the limits. The limits are based on
// slice capacity, which is set exactly to the specified values.
func (m *Message) LimitResourceDecoding(maxQ, maxAns, maxAuth, maxAdd uint16) {
	internal.SliceReuse(&m.Questions, int(maxQ))
	internal.SliceReuse(&m.Answers, int(maxAns))
	internal.SliceReuse(&m.Authorities, int(maxAuth))
	internal.SliceReuse(&m.Additionals, int(maxAdd))
}

func (m *Message) Reset() {
	m.Questions = m.Questions[:0]
	m.Answers = m.Answers[:0]
	m.Authorities = m.Authorities[:0]
	m.Additionals = m.Additionals[:0]
}

// AppendText appends a human readable representation of the Message's resources
// to b and returns the resulting slice. It implements [encoding.TextAppender].
func (m *Message) AppendText(b []byte) (_ []byte, err error) {
	if len(m.Questions) > 0 {
		b = append(b, "-- Questions\n"...)
		for i := range m.Questions {
			b, err = m.Questions[i].AppendText(b)
			if err != nil {
				return b, err
			}
			b = append(b, '\n')
		}
	}
	b, err = appendResourcesText(b, "-- Answers\n", m.Answers)
	if err != nil {
		return b, err
	}
	b, err = appendResourcesText(b, "-- Authorities\n", m.Authorities)
	if err != nil {
		return b, err
	}
	return appendResourcesText(b, "-- Additionals\n", m.Additionals)
}

func appendResourcesText(b []byte, title string, resources []Resource) (_ []byte, err error) {
	if len(resources) == 0 {
		return b, nil
	}
	b = append(b, title...)
	for i := range resources {
		b, err = resources[i].AppendText(b)
		if err != nil {
			return b, err
		}
		b = append(b, '\n')
	}
	return b, nil
}

// Validate checks m can be encoded by [Message.AppendTo] into a well-formed DNS message.
func (m *Message) Validate(vld *lneto.Validator) {
	if SizeHeader+m.lenResources() > math.MaxUint16 {
		vld.AddError(errResTooLong)
		return
	}
	for i := range m.Questions {
		if err := m.Questions[i].Name.validate(); err != nil {
			vld.AddError(err)
		}
	}
	validateResources(vld, m.Answers, false)
	validateResources(vld, m.Authorities, false)
	validateResources(vld, m.Additionals, true)
}

// validateResources validates each resource. OPT records are only valid
// in the additional section, at most once (RFC 6891 section 6.1.1).
func validateResources(vld *lneto.Validator, rs []Resource, isAdditional bool) {
	seenOPT := false
	for i := range rs {
		r := &rs[i]
		if err := r.validate(); err != nil {
			vld.AddError(err)
		}
		if r.header.Type == TypeOPT {
			if !isAdditional || seenOPT {
				vld.AddError(lneto.ErrInvalidField)
			}
			seenOPT = true
		}
	}
}

// CanonicalName returns end of CNAME chain rooted at host, aliasing m.
// Returns zero Name if host has no CNAME.
func (m *Message) CanonicalName(host Name) (cname Name) {
	alias := host
	// Constrain outer for loop, never more than num answer CNAMEs.
	for range m.Answers {
		var next Name
		for i := range m.Answers {
			ans := &m.Answers[i]
			if ans.header.Type == TypeCNAME && ans.header.ownedBy(alias) {
				next = ans.CNAMEView()
				break
			}
		}
		if next.Len() == 0 {
			break
		}
		cname, alias = next, next
	}
	return cname
}

// lenResources returns the wire length of all sections. It is an int so
// [Message.Validate] can detect messages that overflow the uint16 [Message.Len].
// Each record is summed as an int too: [Resource.Len] wraps for RDLENGTH near 65535.
func (m *Message) lenResources() (l int) {
	for i := range m.Questions {
		l += len(m.Questions[i].Name.data) + 4
	}
	for _, rs := range [...][]Resource{m.Answers, m.Authorities, m.Additionals} {
		for i := range rs {
			l += rs[i].wireLen()
		}
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

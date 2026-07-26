package httpraw

import (
	"bytes"
	"io"
)

// Multipart splits a "multipart/form-data" body into its parts. Such bodies
// frame their fields with a delimiter instead of escaping them, so a part's
// value has no length: it ends where the next delimiter begins.
//
// Multipart stores none of the body, leaving the caller to decide what to keep,
// what to skip and when a part has grown too large:
//
//	m := httpraw.Multipart{Boundary: httpraw.MultipartBoundary(contentType)}
//	var hdr httpraw.MultipartHeader
//	for {
//		rest, err := m.NextHeader(&hdr, buf)
//		if err != nil {
//			break // io.EOF, or ErrNeedMoreData: read more into buf and retry.
//		}
//		for {
//			body, next, done := m.NextBody(rest)
//			// Consume body for hdr.Name, then compact next to the front of buf
//			// and read more.
//			rest = next
//			if done {
//				break
//			}
//		}
//	}
type Multipart struct {
	// Boundary is the delimiter parameter of the body's Content-Type field,
	// without the leading "--" the delimiter carries on the wire.
	Boundary []byte
}

// MultipartHeader is a part's header block and the Content-Disposition
// parameters that identify it. All fields alias the buffer they were parsed
// from and stay valid as long as it does.
type MultipartHeader struct {
	// PartView is the part's raw header block, ending in its final CRLF.
	PartView []byte
	// Name is the name parameter of a part's Content-Disposition field,
	// i.e: "photo" for `form-data; name="photo"; filename="beach.png"`.
	Name []byte
	// Filename is the filename parameter of a part's Content-Disposition
	// field, nil when the part is not a file upload.
	Filename []byte
}

// SetContentType sets [Multipart.Boundary] from the boundary parameter of a
// Content-Type field value, i.e: "abc123" for
// "multipart/form-data; boundary=abc123". The leading "--" the delimiter carries
// on the wire is not included. Fails when the parameter is absent or is not
// 1 to 70 characters long, RFC 2046 5.1.1; a zero length boundary would match
// every "--" in the body.
func (m *Multipart) SetContentType(contentType []byte) error {
	m.Boundary = ContentParam(contentType, "boundary")
	if len(m.Boundary) == 0 || len(m.Boundary) > 70 {
		return errNoBoundary // RFC 2046 5.1.1: 1..70 characters, required.
	}
	return nil
}

// NextHeader splits the leading part's header block off a multipart body into
// dst, returning the body bytes that follow it. Returns [ErrNeedMoreData] while
// data holds no complete delimiter and header block, and [io.EOF] once the
// closing delimiter is reached. dst is left zeroed on error.
func (m *Multipart) NextHeader(dst *MultipartHeader, data []byte) (rest []byte, err error) {
	*dst = MultipartHeader{}
	if len(m.Boundary) == 0 {
		return nil, errNoBoundary
	}
	idx := m.indexDelimiter(data)
	if idx < 0 {
		return nil, ErrNeedMoreData
	}
	after := idx + len("--") + len(m.Boundary)
	if after+2 > len(data) {
		return nil, ErrNeedMoreData // Cannot tell a closing delimiter yet.
	} else if data[after] == '-' && data[after+1] == '-' {
		return nil, io.EOF
	}
	// Delimiter is followed by CRLF, then the part's header block.
	if data[after] == '\r' {
		after++
	}
	if after >= len(data) {
		return nil, ErrNeedMoreData
	} else if data[after] != '\n' {
		return nil, errBadDelimiter
	}
	after++
	end := bytes.Index(data[after:], []byte("\r\n\r\n"))
	if end < 0 {
		return nil, ErrNeedMoreData
	}
	dst.PartView = data[after : after+end+2]
	disposition := partField(dst.PartView)
	dst.Name = append(dst.Name[:0], ContentParam(disposition, "name")...)
	dst.Filename = append(dst.Filename[:0], ContentParam(disposition, "filename")...)
	return data[after+end+4:], nil
}

func (m *Multipart) NextHeaderInt(dst *MultipartHeader, data []byte) (parsedLen int, err error) {
	*dst = MultipartHeader{}
	if len(m.Boundary) == 0 {
		return 0, errNoBoundary
	}
	idx := m.indexDelimiter(data)
	if idx < 0 {
		return 0, nil
	}
	after := idx + len("--") + len(m.Boundary)
	if after+2 > len(data) {
		return 0, nil // Cannot tell a closing delimiter yet.
	} else if data[after] == '-' && data[after+1] == '-' {
		return 0, io.EOF
	}
	// Delimiter is followed by CRLF, then the part's header block.
	if data[after] == '\r' {
		after++
	}
	if after >= len(data) {
		return 0, nil
	} else if data[after] != '\n' {
		return 0, errBadDelimiter
	}
	after++
	end := bytes.Index(data[after:], []byte("\r\n\r\n"))
	if end < 0 {
		return 0, nil
	}
	dst.PartView = data[after : after+end+2]
	disposition := partField(dst.PartView)
	dst.Name = append(dst.Name[:0], ContentParam(disposition, "name")...)
	dst.Filename = append(dst.Filename[:0], ContentParam(disposition, "filename")...)
	return after + end + 4, nil
}

func (m *Multipart) NextBodyInt(data []byte) (bodyLen int, done bool) {
	idx := m.indexPartEnd(data)
	if idx >= 0 {
		return idx, true
		// return data[:idx], data[idx+len("\r\n"):], true
	}
	// Longest prefix of "\r\n--"+boundary that could still be completed.
	hold := len("\r\n--") + len(m.Boundary) - 1
	if hold > len(data) {
		hold = len(data)
	}
	return len(data) - hold, false
}

// NextBody returns the part bytes available in data, holding back any tail
// that could be the start of a delimiter. done reports the part ended, in which
// case rest begins the next part's delimiter; otherwise rest is the held back
// tail, which the caller compacts before reading more data into the buffer.
func (m *Multipart) NextBody(data []byte) (body, rest []byte, done bool) {
	idx := m.indexPartEnd(data)
	if idx >= 0 {
		return data[:idx], data[idx+len("\r\n"):], true
	}
	// Longest prefix of "\r\n--"+boundary that could still be completed.
	hold := len("\r\n--") + len(m.Boundary) - 1
	if hold > len(data) {
		hold = len(data)
	}
	return data[:len(data)-hold], data[len(data)-hold:], false
}

// indexDelimiter returns the offset of the leading "--"+Boundary in data.
func (m *Multipart) indexDelimiter(data []byte) int {
	for i := 0; i+len("--")+len(m.Boundary) <= len(data); i++ {
		dash := bytes.IndexByte(data[i:], '-')
		if dash < 0 {
			return -1
		}
		i += dash
		if i+len("--")+len(m.Boundary) > len(data) {
			return -1
		}
		if data[i+1] == '-' && b2s(data[i+2:i+2+len(m.Boundary)]) == b2s(m.Boundary) {
			return i
		}
	}
	return -1
}

// indexPartEnd returns the offset of the CRLF that closes a part, that is the
// CRLF preceding the next delimiter.
func (m *Multipart) indexPartEnd(data []byte) int {
	for i := 0; i+len("\r\n--")+len(m.Boundary) <= len(data); i++ {
		cr := bytes.IndexByte(data[i:], '\r')
		if cr < 0 {
			return -1
		}
		i += cr
		if i+len("\r\n--")+len(m.Boundary) > len(data) {
			return -1
		}
		if data[i+1] == '\n' && data[i+2] == '-' && data[i+3] == '-' &&
			b2s(data[i+4:i+4+len(m.Boundary)]) == b2s(m.Boundary) {
			return i
		}
	}
	return -1
}

// MediaTypeIs reports whether a Content-Type field value carries the given
// media type, ignoring case and any parameters that follow it, i.e: true for
// "text/plain; charset=utf-8" and media type "text/plain". mediaType must be
// ASCII lowercase. RFC 9110 8.3.1.
func MediaTypeIs(value []byte, mediaType string) bool {
	if semi := bytes.IndexByte(value, ';'); semi >= 0 {
		value = value[:semi]
	}
	return equalFold(trimOWS(value), mediaType)
}

// ContentParam returns the value of a parameter of a header field value, i.e:
// "utf-8" for key "charset" of "text/plain; charset=utf-8". Quoted values are
// returned without their quotes and with escapes left as they appear on the
// wire. Key matching is case insensitive, RFC 9110 5.6.6.
func ContentParam(value []byte, key string) []byte {
	for len(value) > 0 {
		semi := bytes.IndexByte(value, ';')
		if semi < 0 {
			return nil // No parameters left.
		}
		value = trimOWS(value[semi+1:])
		eq := bytes.IndexByte(value, '=')
		if eq < 0 {
			return nil
		}
		gotKey := trimOWS(value[:eq])
		value = value[eq+1:]
		param := value
		if len(param) > 0 && param[0] == '"' {
			end := bytes.IndexByte(param[1:], '"')
			if end < 0 {
				return nil // Unterminated quoted string.
			}
			param, value = param[1:end+1], param[end+2:]
		} else {
			end := bytes.IndexByte(param, ';')
			if end >= 0 {
				param, value = param[:end], param[end:]
			} else {
				value = nil
			}
			param = trimOWS(param)
		}
		if equalFold(gotKey, key) {
			return param
		}
	}
	return nil
}

// partField returns the Content-Disposition field value of a part header block.
func partField(partHdr []byte) []byte {
	const key = "content-disposition"
	for len(partHdr) > 0 {
		eol := bytes.IndexByte(partHdr, '\n')
		line := partHdr
		if eol >= 0 {
			line, partHdr = partHdr[:eol], partHdr[eol+1:]
		} else {
			partHdr = nil
		}
		colon := bytes.IndexByte(line, ':')
		if colon > 0 && equalFold(line[:colon], key) {
			return line[colon+1:]
		}
	}
	return nil
}

// trimOWS trims optional whitespace off both ends of b, RFC 9110 5.6.3.
func trimOWS(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t') {
		b = b[1:]
	}
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\t') {
		b = b[:len(b)-1]
	}
	return b
}

// equalFold compares b to the ASCII lowercase key, case insensitively.
func equalFold(b []byte, key string) bool {
	if len(b) != len(key) {
		return false
	}
	const asciiCapDiff = 'a' - 'A'
	for i := range b {
		c := b[i]
		if c >= 'A' && c <= 'Z' {
			c += asciiCapDiff
		}
		if c != key[i] {
			return false
		}
	}
	return true
}

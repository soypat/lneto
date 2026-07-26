package httpraw

// Multipart bodies frame their fields with a delimiter instead of escaping them,
// so a part's value has no length: it ends where the next delimiter begins. The
// functions below split a body without storing any of it, leaving the caller to
// decide what to keep, what to skip and when a part has grown too large:
//
//	boundary := httpraw.MultipartBoundary(contentType)
//	for {
//		hdr, rest, err := httpraw.NextPartHeader(buf, boundary)
//		if err != nil {
//			break // ErrEndOfParts, or ErrNeedMoreData: read more into buf and retry.
//		}
//		name := httpraw.PartName(hdr)
//		for {
//			body, next, done := httpraw.NextPartBody(rest, boundary)
//			// Consume body, then compact next to the front of buf and read more.
//			rest = next
//			if done {
//				break
//			}
//		}
//	}

type Multipart struct {
	Boundary []byte
}

func ()

// MultipartBoundary returns the boundary parameter of a Content-Type field value,
// i.e: "abc123" for "multipart/form-data; boundary=abc123". The leading "--" of
// the wire delimiter is not included. Returns nil if there is no such parameter.
func MultipartBoundary(contentType []byte) []byte { return ContentParam(contentType, "boundary") }

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

// NextPartHeader splits the leading part's header block off a multipart body,
// returning it with its final CRLF and the body bytes that follow it. Returns
// [ErrNeedMoreData] while data holds no complete delimiter and header block, and
// [ErrEndOfParts] once the closing delimiter is reached.
func NextPartHeader(data, boundary []byte) (partHdr, rest []byte, err error) {
	if len(boundary) == 0 {
		return nil, nil, errNoBoundary
	}
	idx := indexDelimiter(data, boundary)
	if idx < 0 {
		return nil, nil, ErrNeedMoreData
	}
	after := idx + len("--") + len(boundary)
	if after+2 > len(data) {
		return nil, nil, ErrNeedMoreData // Cannot tell a closing delimiter yet.
	} else if data[after] == '-' && data[after+1] == '-' {
		return nil, nil, ErrEndOfParts
	}
	// Delimiter is followed by CRLF, then the part's header block.
	if data[after] == '\r' {
		after++
	}
	if after >= len(data) {
		return nil, nil, ErrNeedMoreData
	} else if data[after] != '\n' {
		return nil, nil, errInvalidName // Junk between delimiter and part.
	}
	after++
	end := bytes.Index(data[after:], []byte("\r\n\r\n"))
	if end < 0 {
		return nil, nil, ErrNeedMoreData
	}
	return data[after : after+end+2], data[after+end+4:], nil
}

// NextPartBody returns the part bytes available in data, holding back any tail
// that could be the start of a delimiter. done reports the part ended, in which
// case rest begins the next part's delimiter; otherwise rest is the held back
// tail, which the caller compacts before reading more data into the buffer.
func NextPartBody(data, boundary []byte) (body, rest []byte, done bool) {
	idx := indexPartEnd(data, boundary)
	if idx >= 0 {
		return data[:idx], data[idx+len("\r\n"):], true
	}
	// Longest prefix of "\r\n--"+boundary that could still be completed.
	hold := len("\r\n--") + len(boundary) - 1
	if hold > len(data) {
		hold = len(data)
	}
	return data[:len(data)-hold], data[len(data)-hold:], false
}

// PartName returns the name parameter of a part's Content-Disposition field,
// i.e: "photo" for `form-data; name="photo"; filename="beach.png"`.
func PartName(partHdr []byte) []byte { return ContentParam(partField(partHdr), "name") }

// PartFileName returns the filename parameter of a part's Content-Disposition
// field, nil when the part is not a file upload.
func PartFileName(partHdr []byte) []byte { return ContentParam(partField(partHdr), "filename") }

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

// indexDelimiter returns the offset of the leading "--"+boundary in data.
func indexDelimiter(data, boundary []byte) int {
	for i := 0; i+len("--")+len(boundary) <= len(data); i++ {
		dash := bytes.IndexByte(data[i:], '-')
		if dash < 0 {
			return -1
		}
		i += dash
		if i+len("--")+len(boundary) > len(data) {
			return -1
		}
		if data[i+1] == '-' && b2s(data[i+2:i+2+len(boundary)]) == b2s(boundary) {
			return i
		}
	}
	return -1
}

// indexPartEnd returns the offset of the CRLF that closes a part, that is the
// CRLF preceding the next delimiter.
func indexPartEnd(data, boundary []byte) int {
	for i := 0; i+len("\r\n--")+len(boundary) <= len(data); i++ {
		cr := bytes.IndexByte(data[i:], '\r')
		if cr < 0 {
			return -1
		}
		i += cr
		if i+len("\r\n--")+len(boundary) > len(data) {
			return -1
		}
		if data[i+1] == '\n' && data[i+2] == '-' && data[i+3] == '-' &&
			b2s(data[i+4:i+4+len(boundary)]) == b2s(boundary) {
			return i
		}
	}
	return -1
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

package httpraw

import (
	"bytes"
	"errors"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

var (
	errNoProto = errors.New("missing protocol, HTTP/0.9 unsupported")
	// ErrNeedMoreData signals a parser was handed an incomplete buffer: append
	// more data to it and call again.
	ErrNeedMoreData = errors.New("need more data: cannot find trailing lf/delimiter")
	errNoBoundary   = errors.New("httpraw: multipart boundary not set")
	errUnparsed     = errors.New("need to finish parsing")
	errInvalidName  = errors.New("invalid header name")
	// ErrBufferExhausted signals a buffer with no room left for the data being
	// written and no permission to grow, see [KVBuffer.EnableBufferGrowth].
	// Enlarging the buffer handed to Reset is the only fix; a server answers it
	// on a request header with 431, RFC 6585 5.
	ErrBufferExhausted = errors.New("httpraw: buffer exhausted, increase size")
	// ErrHeaderTooMany signals a header block carrying more fields than
	// the buffer it is parsed into has room for, see [Header.Reset]. A server
	// answers it with 431, RFC 6585 5: no larger buffer is coming, so reading
	// the rest of the block would only spend memory on a request already lost.
	ErrHeaderTooMany = errors.New("httpraw: more header fields than buffer holds")
	// Header.Set and Header.Add mangles the buffer.
	// Call them after retrieving the Body. Do not call them before parsing the header (why would you even do that?).
	errMangledBuffer    = errors.New("httpraw: mangled buffer")
	errNoCookies        = errors.New("no cookie found")
	errEmptyURI         = errors.New("empty URI")
	errLongStatusCode   = errors.New("long status code")
	errBadStatusCode    = errors.New("invalid status code")
	errAlreadyParsed    = errors.New("TryParse called after header parsed")
	errNeedMethodURI    = errors.New("need method/request URI to create request header")
	errBadStatusCodeTxt = errors.New("invalid status code or text")
	errCookiesParsed    = errors.New("cookies already parsed, reset before parsing again")
	errBufferTooLarge   = errors.New("httpraw: buffer exceeds max size (offsets are uint16)")
	errBadPercentEncode = errors.New("httpraw: invalid percent-encoding in URL")
	errBadDelimiter     = errors.New("httpraw: junk between multipart delimiter and part")
	errNoContentLength  = errors.New("httpraw: no Content-Length field")
	errBadContentLength = errors.New("httpraw: invalid Content-Length value")
)

// maxBufLen bounds the header buffer. Offsets/lengths are stored as uint16
// (tokint); a buffer past this would truncate/overflow those, silently
// returning the wrong bytes or panicking on a wrapped slice bound.
const maxBufLen = 0xffff

func protoIsV1(s string) bool {
	return s[:min(len(strHTTP1), len(s))] == strHTTP1
}

type headerv1Buf struct {
	kv kvBuffer
	// buf[:len] holds entire HTTP header data, which may be normalized by [flags]. buf[off:len] holds data not yet processed during parsing.
	// buf []byte
	// offset into buf for parsing.
	off int
	// args contains key-value store.
	// headers []argsKV
}

// reset sets the buffer data and discards all parsed data. The field table is
// grown to match the new buffer's capacity and never shrinks, so a header
// reused across requests settles on its largest buffer and stops allocating.
func (h *headerv1Buf) reset(buf []byte, numHeaderCapacity int) {
	h.kv.Reset(buf, numHeaderCapacity)
	h.off = 0
}

type scannerState struct {
	err error

	// by checking whether the next line contains a colon or not to tell
	// it's a header entry or a multi line value of current header entry.
	// the side effect of this operation is that we know the index of the
	// next colon and new line, so this can be used during next iteration,
	// instead of find them again.
	nextColon   int
	nextNewLine int

	initialized bool
}

func (h *HeaderV1) parse(asResponse bool) (err error) {
	debuglog("http:firstline:start")
	err = h.parseFirstLine(asResponse)
	if err != nil {
		debuglog("http:firstline:err")
		return err
	}
	debuglog("http:firstline:done")
	err = h.parseNextHeaders(h.Flags())
	debuglog("http:headers:done")
	return err
}

func (h *HeaderV1) parseFirstLine(asResponse bool) (err error) {
	if len(h.hbuf.kv.buf) > maxBufLen {
		return errBufferTooLarge // Offsets would overflow uint16 tokint.
	}
	flags := h.Flags()
	if asResponse {
		h.statusCode, h.statusText, flags, err = h.hbuf.parseFirstLineResponse(flags)
	} else {
		h.method, h.requestTarget, h.proto, flags, err = h.hbuf.parseFirstLineRequest(flags)
	}
	h.hbuf.kv.flags = flags
	return err
}

func (h *HeaderV1) parseNextHeaders(flags Flags) error {
	var ss scannerState
	h.hbuf.parseNextHeaders(&ss, flags)
	if ss.err != nil {
		h.hbuf.kv.flags |= flagConnClose
		return ss.err
	}
	h.hbuf.kv.flags |= flagDoneParsingHeader
	return nil
}

func (hb *headerv1Buf) free() int { return hb.kv.free() }

func (hb *headerv1Buf) parseNextHeaders(ss *scannerState, flags Flags) {
	debuglog("http:nexthdr:loop")
	for kv := hb.next(ss); kv.isValidHeader(); kv = hb.next(ss) {
		if !hb.kv.canAddOneKV() {
			ss.err = ErrHeaderTooMany
			return
		}
		hb.kv.kvs = append(hb.kv.kvs, kv)
	}
	debuglog("http:nexthdr:done")
}

func (hb *headerv1Buf) offBuf() []byte {
	return hb.kv.buf[hb.off:]
}

func (hb *headerv1Buf) skipLeadingCRLF() {
	for hb.off < len(hb.kv.buf) && (hb.kv.buf[hb.off] == '\n' || hb.kv.buf[hb.off] == '\r') {
		hb.off++
	}
}

func (hb *headerv1Buf) scanLine() []byte {
	buf := hb.scanUntilByte('\n')
	if len(buf) > 0 && buf[len(buf)-1] == '\r' {
		buf = buf[:len(buf)-1] // exclude carriage return.
	}
	if hb.off < len(hb.kv.buf) {
		hb.off++ // consume newline.
	}
	return buf
}

func (hb *headerv1Buf) scanUntilByte(c byte) []byte {
	buf := hb.offBuf()
	idx := bytes.IndexByte(buf, c)
	if idx >= 0 {
		buf = buf[:idx]
	}
	hb.off += len(buf)
	return buf
}

func (hb *headerv1Buf) parseFirstLineRequest(initFlags Flags) (method, uri, proto view, flags Flags, err error) {
	debuglog("http:req:scan")
	hb.off = 0 // Parsing first line resets offset.
	hb.skipLeadingCRLF()
	flags = initFlags
	if bytes.IndexByte(hb.offBuf(), '\n') < 0 {
		return method, uri, proto, flags, ErrNeedMoreData // Incomplete line.
	}
	b := hb.scanLine()
	if len(b) < 5 {
		return method, uri, proto, flags, ErrNeedMoreData
	}
	debuglog("http:req:parse")

	methodEnd := max(0, bytes.IndexByte(b, ' '))
	reqURIEnd := bytes.IndexByte(b[methodEnd+1:], ' ')
	if reqURIEnd > 0 {
		reqURIEnd += methodEnd + 1
		uri = hb.kv.view(b[methodEnd+1 : reqURIEnd])
		proto = hb.kv.view(b[reqURIEnd+1:]) // Skip space before protocol.
		protoText := b2s(b[reqURIEnd+1:])
		if !protoIsV1(protoText) {
			// Refused here rather than after the fields: the field loop is nearly
			// all of the parse cost and none of it serves a version this type
			// does not speak. proto is set so the caller can name it, i.e: 505.
			method = hb.kv.view(b[:methodEnd])
			return method, uri, proto, flags | flagNoHTTP11, lneto.ErrUnsupported
		} else if protoText != strHTTP11 {
			flags |= flagNoHTTP11 // HTTP/1.0, which defaults to closing the connection.
		}
	} else if reqURIEnd == 0 {
		return method, uri, proto, flags, errEmptyURI
	} else {
		// No version at all is a HTTP/0.9 simple-request, not a 1.x request-line,
		// RFC 9112 3. proto stays empty, telling it apart from a named version.
		uri = hb.kv.view(b[methodEnd+1:])
		method = hb.kv.view(b[:methodEnd])
		return method, uri, proto, flags | flagNoHTTP11, lneto.ErrUnsupported
	}
	method = hb.kv.view(b[:methodEnd])
	return method, uri, proto, flags, nil
}

func (hb *headerv1Buf) parseFirstLineResponse(initFlags Flags) (statusCode, statusText view, flags Flags, err error) {
	debuglog("http:resp:scan")
	hb.off = 0 // Parsing first line resets offset.
	hb.skipLeadingCRLF()
	flags = initFlags
	if bytes.IndexByte(hb.offBuf(), '\n') < 0 {
		return statusCode, statusText, flags, ErrNeedMoreData // Incomplete line.
	}
	b := hb.scanLine()
	if len(b) < 5 {
		return statusCode, statusText, flags, ErrNeedMoreData
	}
	debuglog("http:resp:parse")

	// Parse protocol (e.g. "HTTP/1.1"), then status code, then status text.
	protoEnd := bytes.IndexByte(b, ' ')
	if protoEnd < 0 {
		return statusCode, statusText, flags, ErrNeedMoreData
	}
	if !protoIsV1(b2s(b[:protoEnd])) {
		// Refused before the fields, as on the request side: a response naming
		// another version is not one this type can read.
		return statusCode, statusText, flags | flagNoHTTP11, lneto.ErrUnsupported
	} else if b2s(b[:protoEnd]) != strHTTP11 {
		flags |= flagNoHTTP11
	}
	b = b[protoEnd+1:] // Advance past protocol and space.

	codeEnd := bytes.IndexByte(b, ' ')
	if codeEnd < 0 {
		codeEnd = len(b) // Status text is optional.
	}
	code := b[:codeEnd]
	if len(code) > 3 {
		return statusCode, statusText, flags, errLongStatusCode
	}
	for i := range code {
		if code[i] > '9' || code[i] < '0' {
			debuglog("http:resp:invalid-code")
			return statusCode, statusText, flags, errBadStatusCode
		}
	}
	statusCode = hb.kv.view(code)
	if codeEnd < len(b) {
		statusText = hb.kv.view(b[codeEnd+1:]) // Skip space before text.
	}
	debuglog("http:resp:done")
	return statusCode, statusText, flags, nil
}

func (hb *headerv1Buf) next(ss *scannerState) pairKV {
	if !ss.initialized {
		ss.nextColon = -1
		ss.nextNewLine = -1
	}
	buf := hb.kv.buf[hb.off:]
	blen := len(buf)
	if blen >= 2 && buf[0] == '\r' && buf[1] == '\n' {
		hb.off += 2
		return hb.kv.noKV() // \r\n\r\n Ends header.
	} else if blen >= 1 && buf[0] == '\n' {
		hb.off += 1
		return hb.kv.noKV() // \n\n Ends header.
	}

	// n is parsing offset. Will start by storing colon index.
	n := 0
	if ss.nextColon >= 0 {
		// Retake from last colon found.
		n = ss.nextColon
		ss.nextColon = -1
	} else {
		n = bytes.IndexByte(buf, ':')
		x := bytes.IndexByte(buf, '\n')
		if x < 0 {
			// A header name should always at some point be followed by a \n
			// even if it's the one that terminates the header block.
			ss.err = ErrNeedMoreData
			return hb.kv.noKV()
		} else if x < n {
			// There was a \n before the colon! This is invalid.
			ss.err = errInvalidName
			return hb.kv.noKV()
		} else if n < 0 {
			// A newline is present (x>=0 reached here) but the line has no
			// colon: malformed, not incomplete. A split arriving before the
			// colon has no newline yet and is caught by the x<0 branch above,
			// so it still returns ErrNeedMoreData.
			ss.err = errInvalidName
			return hb.kv.noKV()
		}
	}
	// n stores colon position by now.
	if bytes.IndexByte(buf[:n], ' ') >= 0 || bytes.IndexByte(buf[:n], '\t') >= 0 {
		// Spaces between the header key and colon are not allowed.
		// See RFC 7230, Section 3.2.4.
		ss.err = errInvalidName
		return hb.kv.noKV()
	}

	// Ready to store key..
	var resultKV pairKV
	resultKV.key = hb.kv.view(buf[:n])
	n++ // consume colon.
	for len(buf) > n && buf[n] == ' ' {
		n++ // Trim leading spaces.
	}
	// n now points to start of value.
	valueStart := n

	// Find end of value. Values may be multiline, in which case we must treat newlines followed by whitespace as part of the value.
	for {
		nl := bytes.IndexByte(buf[n:], '\n')
		if nl < 0 || nl+n+1 == len(buf) {
			// No newline or newline is last character and can't know if is multiline.
			ss.err = ErrNeedMoreData
			return hb.kv.noKV()
		}
		n += nl + 1 // Index of the newly found newline.
		nextChar := buf[n]
		if nextChar != ' ' && nextChar != '\t' {
			break // End of value found.
		}
	}

	valueEnd := n - 1 // Trim newline.
	if valueEnd > valueStart && buf[valueEnd-1] == '\r' {
		valueEnd-- // Trim \r character if present before value.
	}
	resultKV.value = hb.kv.view(buf[valueStart:valueEnd])
	hb.off += n
	return resultKV
}

// ConnectionClose returns true if 'Connection: close' header is set or if a invalid header was found.
func (h *HeaderV1) ConnectionClose() bool {
	flags := h.Flags()
	closed := flags.HasAny(flagConnClose) ||
		h.hasConnectionToken(strClose) ||
		(flags.HasAny(flagNoHTTP11) && !h.hasConnectionToken(strKeepAlive))
	if closed {
		h.hbuf.kv.flags |= flagConnClose
	}
	return closed
}

// hasConnectionToken reports whether the Connection field lists token, which
// must be lowercase. The field name, its comma list and each token all compare
// case insensitively, RFC 9110 5.1 and 7.6.1.
func (h *HeaderV1) hasConnectionToken(token string) bool {
	value := h.GetFold(headerConnection)
	for len(value) > 0 {
		item := value
		if comma := bytes.IndexByte(value, ','); comma >= 0 {
			item, value = value[:comma], value[comma+1:]
		} else {
			value = nil
		}
		if equalFold(trimOWS(item), token) {
			return true
		}
	}
	return false
}

const enableDebug = internal.HeapAllocDebugging

func debuglog(msg string) {
	if enableDebug {
		internal.LogAllocs(msg)
	}
}

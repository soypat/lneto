package httpraw

import (
	"bytes"
	"errors"
	"slices"
	"unsafe"
)

var (
	errNoProto     = errors.New("missing protocol, HTTP/0.9 unsupported")
	errNeedMore    = errors.New("need more data: cannot find trailing lf")
	errUnparsed    = errors.New("need to finish parsing")
	errInvalidName = errors.New("invalid header name")
	errSmallBuffer = errors.New("small read buffer. Increase ReadBufferSize")
	errOOM         = errors.New("httpraw: buffer out of memory")
	// Header.Set and Header.Add mangles the buffer.
	// Call them after retrieving the Body. Do not call them before parsing the header (why would you even do that?).
	errMangledBuffer = errors.New("httpraw: mangled buffer")
	errNoCookies     = errors.New("no cookie found")
)

type headerBuf struct {
	// buf[:len] holds entire HTTP header data, which may be normalized by [flags]. buf[off:len] holds data not yet processed during parsing.
	buf []byte
	// offset into buf for parsing.
	off int
	// args contains key-value store.
	headers []argsKV
}

type tokint = uint16

type headerSlice struct {
	start tokint
	len   tokint
}

type argsKV struct {
	key   headerSlice
	value headerSlice // value start >0 means value is present.
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

func (h *Header) parse(asResponse bool) (err error) {
	err = h.parseFirstLine(asResponse)
	if err != nil {
		return err
	}
	return h.parseNextHeaders()
}

func (h *Header) parseFirstLine(asResponse bool) (err error) {
	if asResponse {
		h.statusCode, h.statusText, h.flags, err = h.hbuf.parseFirstLineResponse(h.flags)
	} else {
		h.method, h.requestURI, h.proto, h.flags, err = h.hbuf.parseFirstLineRequest(h.flags)
	}
	return err
}

func (h *Header) parseNextHeaders() error {
	var ss scannerState
	h.hbuf.parseNextHeaders(&ss)
	if ss.err != nil {
		h.flags |= flagConnClose
		return ss.err
	}
	h.flags |= flagDoneParsingHeader
	return nil
}

func (hb *headerBuf) readFromBytes(b []byte) {
	hb.buf = append(hb.buf, b...)
}

func (hb *headerBuf) free() int { return cap(hb.buf) - len(hb.buf) }

func (hb *headerBuf) parseNextHeaders(ss *scannerState) {
	for kv := hb.next(ss); kv.isValid(); kv = hb.next(ss) {
		hb.headers = append(hb.headers, kv)
	}
}

func (hb *headerBuf) offBuf() []byte {
	return hb.buf[hb.off:]
}

func (hb *headerBuf) skipLeadingCRLF() {
	for hb.off < len(hb.buf) && (hb.buf[hb.off] == '\n' || hb.buf[hb.off] == '\r') {
		hb.off++
	}
}

func (hb *headerBuf) scanLine() []byte {
	buf := hb.scanUntilByte('\n')
	if len(buf) > 0 && buf[len(buf)-1] == '\r' {
		buf = buf[:len(buf)-1] // exclude carriage return.
	}
	if hb.off < len(hb.buf) {
		hb.off++ // consume newline.
	}
	return buf
}

func (hb *headerBuf) scanUntilByte(c byte) []byte {
	buf := hb.offBuf()
	idx := bytes.IndexByte(buf, c)
	if idx >= 0 {
		buf = buf[:idx]
	}
	hb.off += len(buf)
	return buf
}

func (hb *headerBuf) parseFirstLineRequest(initFlags flags) (method, uri, proto headerSlice, flags flags, err error) {
	hb.off = 0 // Parsing first line resets offset.
	var b []byte
	hb.skipLeadingCRLF()
	b = hb.scanLine()
	flags = initFlags
	if len(b) < 5 {
		return method, uri, proto, flags, errNeedMore
	}

	methodEnd := max(0, bytes.IndexByte(b, ' '))
	reqURIEnd := bytes.IndexByte(b[methodEnd+1:], ' ')
	if reqURIEnd > 0 {
		reqURIEnd += methodEnd + 1
		uri = hb.slice(b[methodEnd+1 : reqURIEnd])
		if b2s(b[methodEnd+1:reqURIEnd]) != strHTTP11 {
			flags |= flagNoHTTP11
		}
	} else if reqURIEnd == 0 {
		return method, uri, proto, flags, errors.New("empty URI")
	} else {
		// No version provided.
		reqURIEnd = methodEnd + 1
		flags |= flagNoHTTP11
		uri = hb.slice(b[methodEnd+1 : reqURIEnd])
	}
	proto = hb.slice(b[reqURIEnd:])
	method = hb.slice(b[:methodEnd])
	return method, uri, proto, flags, nil
}

func (hb *headerBuf) parseFirstLineResponse(initFlags flags) (statusCode, statusText headerSlice, flags flags, err error) {
	hb.off = 0 // Parsing first line resets offset.
	var b []byte
	hb.skipLeadingCRLF()
	b = hb.scanLine()
	flags = initFlags
	if len(b) < 5 {
		return statusCode, statusText, flags, errNeedMore
	}

	statusCodeEnd := max(0, bytes.IndexByte(b, ' '))
	if statusCodeEnd < 0 {
		return statusCode, statusText, flags, errors.New("missing status code")
	}
	code := b[:statusCodeEnd]
	text := b[statusCodeEnd:]
	if len(code) > 3 {
		return statusCode, statusText, flags, errors.New("long status code")
	}
	for i := range code {
		if code[i] > '9' || code[i] < '0' {
			return statusCode, statusText, flags, errors.New("invalid status code")
		}
	}
	statusCode = hb.slice(code)
	statusText = hb.slice(text)
	return statusCode, statusText, flags, nil
}

func (kv argsKV) isValid() bool {
	return kv.key.start > 0
}

func (kv *argsKV) invalidate() {
	*kv = argsKV{}
}

func (tb headerBuf) musttoken(slice headerSlice) []byte {
	return tok2bytes(tb.buf, slice)

}

func (tb headerBuf) slice(b []byte) headerSlice {
	return bytes2tok(tb.buf, b)
}

func (kv argsKV) HasValue() bool { return kv.value.start > 0 }

func (h *Header) hasHeaderValue(key, value string) bool {
	kv := h.peekHeader(key)
	return kv.isValid() && b2s(h.hbuf.musttoken(kv.value)) == value
}

// peekHeader returns header key-value for the given key.
//
// The returned value is valid until the request is released,
// either though ReleaseRequest or your request handler returning.
// Do not store references to returned value. Make copies instead.
func (h *Header) peekHeader(key string) argsKV {
	hb := &h.hbuf
	for i := 0; i < len(h.hbuf.headers); i++ {
		if b2s(hb.musttoken(h.hbuf.headers[i].key)) == key {
			return h.hbuf.headers[i]
		}
	}
	return hb.noKV()
}

func (hb *headerBuf) mustAppendSlice(value string) headerSlice {
	L := len(hb.buf)
	if L == 0 {
		L++ // Valid key-values start after 0.
	}
	copy(hb.buf[L:L+len(value)], value)
	hb.buf = hb.buf[:L+len(value)]
	return hb.slice(hb.buf[L : L+len(value)])
}

func (h *Header) reuseOrAppend(tok headerSlice, value string) headerSlice {
	if tok.len > tokint(len(value)) {
		copy(h.hbuf.musttoken(tok), value)
		tok.len = tokint(len(value))
		return tok
	}
	return h.appendSlice(value)
}

func (h *Header) appendSlice(value string) headerSlice {
	free := h.hbuf.free()
	if len(value) > free {
		if h.flags.hasAny(flagNoBufferGrow) {
			h.flags |= flagOOMReached
			return headerSlice{}
		}
		h.hbuf.buf = slices.Grow(h.hbuf.buf, len(value)+1) // Grow 1 beyond due to slice validity.
	}
	h.flags |= flagMangledBuffer
	return h.hbuf.mustAppendSlice(value)
}

func (h *Header) appendHeader(key, value string) {
	hb := &h.hbuf
	free := hb.free()
	buf := h.hbuf.buf

	if len(key)+len(value) > free {
		if h.flags.hasAny(flagNoBufferGrow) {
			panic(errSmallBuffer)
		}
		hb.buf = slices.Grow(buf, len(key)+len(value))
	}
	h.flags |= flagMangledBuffer
	k := hb.mustAppendSlice(key)
	v := hb.mustAppendSlice(value)
	hb.headers = append(hb.headers, argsKV{
		key:   k,
		value: v,
	})
}

func (hb *headerBuf) noKV() argsKV { return argsKV{} }

func (hb *headerBuf) next(ss *scannerState) argsKV {
	if !ss.initialized {
		ss.nextColon = -1
		ss.nextNewLine = -1
	}
	buf := hb.buf[hb.off:]
	blen := len(buf)
	if blen >= 2 && buf[0] == '\r' && buf[1] == '\n' {
		hb.off += 2
		return hb.noKV() // \r\n\r\n Ends header.
	} else if blen >= 1 && buf[0] == '\n' {
		hb.off += 1
		return hb.noKV() // \n\n Ends header.
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
			ss.err = errNeedMore
			return hb.noKV()
		} else if x < n {
			// There was a \n before the colon! This is invalid.
			ss.err = errInvalidName
			return hb.noKV()
		} else if n < 0 {
			// No colon found, probably missing data.
			ss.err = errNeedMore
			return hb.noKV()
		}
	}
	// n stores colon position by now.
	if bytes.IndexByte(buf[:n], ' ') >= 0 || bytes.IndexByte(buf[:n], '\t') >= 0 {
		// Spaces between the header key and colon are not allowed.
		// See RFC 7230, Section 3.2.4.
		ss.err = errInvalidName
		return hb.noKV()
	}

	// Ready to store key..
	var resultKV argsKV
	resultKV.key = hb.slice(buf[:n])
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
			ss.err = errNeedMore
			return hb.noKV()
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
	resultKV.value = hb.slice(buf[valueStart:valueEnd])
	hb.off += n
	return resultKV
}

// reset sets the buffer data and discards all parsed data.
func (h *headerBuf) reset(buf []byte) {
	if buf == nil {
		buf = h.buf[:0] // Reuse buffer but discard raw data on nil input.
	}
	*h = headerBuf{
		buf:     buf,
		headers: h.headers[:0],
	}
}

// ConnectionClose returns true if 'Connection: close' header is set or if a invalid header was found.
func (h *Header) ConnectionClose() bool {
	closed := h.flags.hasAny(flagConnClose) ||
		(h.flags.hasAny(flagNoHTTP11) && !h.hasHeaderValue("Connection", "keep-alive"))
	if closed {
		h.flags |= flagConnClose
	}
	return closed
}

// b2s converts byte slice to a string without memory allocation.
// See https://groups.google.com/forum/#!msg/Golang-Nuts/ENgbUzYvCuU/90yGx7GUAgAJ .
func b2s(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func tok2bytes(buf []byte, slice headerSlice) []byte {
	return buf[slice.start : slice.start+slice.len]
}

func bytes2tok(buf, value []byte) headerSlice {
	base := uintptr(unsafe.Pointer(unsafe.SliceData(buf)))
	off := uintptr(unsafe.Pointer(unsafe.SliceData(value)))
	if off < base || off > base+uintptr(len(buf)) {
		panic("httpx: argument buffer does not alias header buffer")
	}
	return headerSlice{
		start: tokint(off - base),
		len:   tokint(len(value)),
	}
}

package httpx

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"unsafe"
)

var (
	errNeedMore        = errors.New("need more data: cannot find trailing lf")
	errInvalidName     = errors.New("invalid header name")
	errSmallBuffer     = errors.New("small read buffer. Increase ReadBufferSize")
	errNonNumericChars = errors.New("non-numeric chars found")
)

func (hb *headerBuf) readFromBytes(b []byte) {
	hb.buf = append(hb.buf, b...)
}

func (hb *headerBuf) free() int { return cap(hb.buf) - len(hb.buf) }

func (hb *headerBuf) readFrom(r io.Reader) error {
	buf := hb.buf
	free := hb.free()
	if free == 0 {
		return errSmallBuffer
	}
	n, err := r.Read(buf[len(buf):cap(buf)])
	hb.buf = buf[:len(buf)+n]
	return err
}

func (h *header) parse() (err error) {
	hb := &h.hbuf
	hb.off = 0 // start parsing from 0.
	h.method, h.requestURI, h.proto, h.flags, err = hb.parseFirstLine(h.flags)
	if err != nil {
		return err
	}

	var ss scannerState
	err = h.parseHeaders(&ss)
	if err != nil {
		return err
	}
	return nil
}

func (hb *headerBuf) offBuf() []byte {
	return hb.buf[hb.off:]
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

func (hb *headerBuf) parseFirstLine(initFlags flags) (method, uri, proto headerSlice, flags flags, err error) {
	var b []byte
	for len(b) == 0 {
		b = hb.scanLine()
	}
	flags = initFlags
	if len(b) < 5 {
		return method, uri, proto, flags, errors.New("too short first HTTP line")
	}

	methodEnd := max(0, bytes.IndexByte(b, ' '))
	reqURIEnd := bytes.IndexByte(b[methodEnd+1:], ' ')
	switch {
	case reqURIEnd < 0:
		flags |= noHTTP11
		reqURIEnd = methodEnd + 1
	case reqURIEnd == 0:
		return method, uri, proto, flags, errors.New("empty URI")
	case b2s(b[reqURIEnd+1:]) != strHTTP11:
		flags |= noHTTP11
		fallthrough
	default:
		proto = hb.slice(b[reqURIEnd+1:])
	}
	uri = hb.slice(b[methodEnd+1 : reqURIEnd])
	method = hb.slice(b[:methodEnd])
	return method, uri, proto, flags, nil
}

type scannerState struct {
	err error

	// hLen stores header subslice len
	hLen int

	disableNormalizing bool

	// by checking whether the next line contains a colon or not to tell
	// it's a header entry or a multi line value of current header entry.
	// the side effect of this operation is that we know the index of the
	// next colon and new line, so this can be used during next iteration,
	// instead of find them again.
	nextColon   int
	nextNewLine int

	initialized bool
}

func (h *header) parseHeaders(ss *scannerState) (err error) {
	hb := &h.hbuf
	h.contentLength = -2

	for kv := hb.nextKV(ss); kv.isValid(); kv = hb.nextKV(ss) {
		if h.flags.hasAny(disableSpecialHeader) {
			h.hbuf.headers = append(h.hbuf.headers, kv)
			continue
		}
	}
	if ss.err != nil && err == nil {
		err = ss.err
	}
	if err != nil {
		h.flags |= connectionClose
		return err
	}

	// if h.contentLength < 0 {
	// 	h.contentLengthBytes = hb.noKV().value
	// }
	if h.flags.hasAny(noHTTP11) && !h.flags.hasAny(connectionClose) {
		// close connection for non-http/1.1 request unless 'Connection: keep-alive' is set.
		if !h.hasHeaderValue(strConnection, strKeepAlive) {
			h.flags |= connectionClose
		}
	}
	return nil
}

func (h *header) hasHeaderValue(key, value string) bool {
	kv := h.peekHeader(key)
	return kv.isValid() && b2s(h.hbuf.musttoken(kv.value)) == value
}

func (h *header) peekHeaderBytes(key string) []byte {
	kv := h.peekHeader(key)
	if kv.isValid() {
		return h.hbuf.musttoken(kv.value)
	}
	return nil
}

// peekHeader returns header key-value for the given key.
//
// The returned value is valid until the request is released,
// either though ReleaseRequest or your request handler returning.
// Do not store references to returned value. Make copies instead.
func (h *header) peekHeader(key string) argsKV {
	hb := &h.hbuf
	for i := 0; i < len(h.hbuf.headers); i++ {
		if b2s(hb.musttoken(h.hbuf.headers[i].key)) == key {
			return h.hbuf.headers[i]
		}
	}
	return hb.noKV()
}

func (h *header) peekPtrHeader(key string) *argsKV {
	hb := &h.hbuf
	for i := 0; i < len(h.hbuf.headers); i++ {
		if b2s(hb.musttoken(h.hbuf.headers[i].key)) == key {
			return &h.hbuf.headers[i]
		}
	}
	return nil
}

func (hb *headerBuf) mustAppendSlice(value string) headerSlice {
	L := len(hb.buf)
	copy(hb.buf[L:L+len(value)], value)
	hb.buf = hb.buf[:L+len(value)]
	return hb.slice(hb.buf[L : L+len(value)])
}

func (h *header) reuseOrAppend(tok headerSlice, value string) headerSlice {
	if tok.len > tokint(len(value)) {
		copy(h.hbuf.musttoken(tok), value)
		tok.len = tokint(len(value))
		return tok
	}
	return h.appendSlice(value)
}

func (h *header) appendSlice(value string) headerSlice {
	free := h.hbuf.free()
	if len(value) > free {
		if h.flags.hasAny(flagNoBufferGrow) {
			h.flags |= flagOOMReached
			return headerSlice{}
		}
		h.hbuf.buf = slices.Grow(h.hbuf.buf, len(value))
	}
	return h.hbuf.mustAppendSlice(value)
}

func (h *header) appendHeader(key, value string) {
	hb := &h.hbuf
	free := hb.free()
	buf := h.hbuf.buf

	if len(key)+len(value) > free {
		if h.flags.hasAny(flagNoBufferGrow) {
			panic(errSmallBuffer)
		}
		slices.Grow(buf, len(key)+len(value))
	}
	k := hb.mustAppendSlice(key)
	v := hb.mustAppendSlice(value)
	if !h.flags.hasAny(disableNormalizing) {
		// TODO
	}
	hb.headers = append(hb.headers, argsKV{
		key:   k,
		value: v,
	})
}

func readRawHeaders(dst []byte, buf string) ([]byte, int, error) {
	n := strings.IndexByte(buf, nChar)
	if n < 0 {
		return dst[:0], 0, errNeedMore
	}
	if (n == 1 && buf[0] == rChar) || n == 0 {
		// empty headers
		return dst, n + 1, nil
	}

	n++
	b := buf
	m := n
	for {
		b = b[m:]
		m = strings.IndexByte(b, nChar)
		if m < 0 {
			return dst, 0, errNeedMore
		}
		m++
		n += m
		if (m == 2 && b[0] == rChar) || m == 1 {
			dst = append(dst, buf[:n]...)
			return dst, n, nil
		}
	}
}
func (hb *headerBuf) noKV() argsKV { return argsKV{} }

func (hb *headerBuf) nextKV(ss *scannerState) argsKV {
	if !ss.initialized {
		ss.nextColon = -1
		ss.nextNewLine = -1
		ss.initialized = true
	}
	buf := hb.buf[hb.off:]
	bLen := len(buf)
	if bLen >= 2 && buf[0] == rChar && buf[1] == nChar {
		hb.off += 2
		return hb.noKV() // \r\n\r\n Ends header.
	}
	if bLen >= 1 && buf[0] == nChar {
		hb.off++
		return hb.noKV() // \n\n: Ends header.
	}

	var n int
	if ss.nextColon >= 0 {
		n = ss.nextColon
		ss.nextColon = -1
	} else {
		n = bytes.IndexByte(buf, ':')

		// There can't be a \n inside the header name, check for this.
		x := bytes.IndexByte(buf, nChar)
		if x < 0 {
			// A header name should always at some point be followed by a \n
			// even if it's the one that terminates the header block.
			ss.err = errNeedMore
			return hb.noKV()
		}
		if x < n {
			// There was a \n before the :
			ss.err = errInvalidName
			return hb.noKV()
		}
	}
	if n < 0 {
		ss.err = errNeedMore
		return hb.noKV()
	}

	if bytes.IndexByte(buf[:n], ' ') >= 0 || bytes.IndexByte(buf[:n], '\t') >= 0 {
		// Spaces between the header key and colon are not allowed.
		// See RFC 7230, Section 3.2.4.
		ss.err = errInvalidName
		return hb.noKV()
	}

	var resultKV argsKV
	resultKV.key = hb.slice(buf[:n])
	normalizeHeaderKey(buf[:n], ss.disableNormalizing)
	n++
	for len(buf) > n && buf[n] == ' ' {
		n++
		// the newline index is a relative index, and lines below trimmed `s.b` by `n`,
		// so the relative newline index also shifted forward. it's safe to decrease
		// to a minus value, it means it's invalid, and will find the newline again.
		ss.nextNewLine--
	}
	ss.hLen += n
	buf = buf[n:]
	if ss.nextNewLine >= 0 {
		n = ss.nextNewLine
		ss.nextNewLine = -1
	} else {
		n = bytes.IndexByte(buf, nChar)
	}
	if n < 0 {
		ss.err = errNeedMore
		return hb.noKV()
	}
	isMultiLineValue := false
	for {
		if n+1 >= len(buf) {
			break
		}
		if buf[n+1] != ' ' && buf[n+1] != '\t' {
			break
		}
		d := bytes.IndexByte(buf[n+1:], nChar)
		if d <= 0 {
			break
		} else if d == 1 && buf[n+1] == rChar {
			break
		}
		e := n + d + 1
		if c := bytes.IndexByte(buf[n+1:e], ':'); c >= 0 {
			ss.nextColon = c
			ss.nextNewLine = d - c - 1
			break
		}
		isMultiLineValue = true
		n = e
	}
	if n >= len(buf) {
		ss.err = errNeedMore
		return hb.noKV()
	}
	oldB := buf
	value := buf[:n]
	ss.hLen += n + 1
	buf = buf[n+1:]

	if n > 0 && value[n-1] == rChar {
		n--
	}
	for n > 0 && value[n-1] == ' ' {
		n--
	}
	value = value[:n]
	if isMultiLineValue {
		value, buf, ss.hLen = normalizeHeaderValue(value, oldB, ss.hLen)
	}
	resultKV.value = hb.slice(value)
	return resultKV
}

func normalizeHeaderKey(b []byte, disableNormalizing bool) {
	if disableNormalizing {
		return
	}

	n := len(b)
	if n == 0 {
		return
	}

	b[0] = toUpperTable[b[0]]
	for i := 1; i < n; i++ {
		p := &b[i]
		if *p == '-' {
			i++
			if i < n {
				b[i] = toUpperTable[b[i]]
			}
			continue
		}
		*p = toLowerTable[*p]
	}
}

func normalizeHeaderValue(ov, ob []byte, headerLength int) (nv, nb []byte, nhl int) {
	nv = ov
	length := len(ov)
	if length <= 0 {
		return
	}
	write := 0
	shrunk := 0
	lineStart := false
	for read := 0; read < length; read++ {
		c := ov[read]
		switch {
		case c == rChar || c == nChar:
			shrunk++
			if c == nChar {
				lineStart = true
			}
			continue
		case lineStart && c == '\t':
			c = ' '
		default:
			lineStart = false
		}
		nv[write] = c
		write++
	}

	nv = nv[:write]
	copy(ob[write:], ob[write+shrunk:])

	// Check if we need to skip \r\n or just \n
	skip := 0
	if ob[write] == rChar {
		if ob[write+1] == nChar {
			skip += 2
		} else {
			skip++
		}
	} else if ob[write] == nChar {
		skip++
	}

	nb = ob[write+skip : len(ob)-shrunk]
	nhl = headerLength - shrunk
	return
}

func parseContentLength(b string) (int, error) {
	v, n, err := parseUintBuf(b)
	if err != nil {
		return -1, fmt.Errorf("cannot parse Content-Length: %w", err)
	}
	if n != len(b) {
		return -1, fmt.Errorf("cannot parse Content-Length: %w", errNonNumericChars)
	}
	return v, nil
}

func nextLine(b []byte) ([]byte, []byte, error) {
	nNext := bytes.IndexByte(b, nChar)
	if nNext < 0 {
		return nil, nil, errNeedMore
	}
	n := nNext
	if n > 0 && b[n-1] == rChar {
		n--
	}
	return b[:n], b[nNext+1:], nil
}

func stripSpace(b string) string {
	for len(b) > 0 && b[0] == ' ' {
		b = b[1:]
	}
	for len(b) > 0 && b[len(b)-1] == ' ' {
		b = b[:len(b)-1]
	}
	return b
}

var (
	errEmptyInt               = errors.New("empty integer")
	errUnexpectedFirstChar    = errors.New("unexpected first char found. Expecting 0-9")
	errUnexpectedTrailingChar = errors.New("unexpected trailing char found. Expecting 0-9")
	errTooLongInt             = errors.New("too long int")
)

func parseUintBuf(b string) (int, int, error) {
	n := len(b)
	if n == 0 {
		return -1, 0, errEmptyInt
	}
	v := 0
	for i := 0; i < n; i++ {
		c := b[i]
		k := c - '0'
		if k > 9 {
			if i == 0 {
				return -1, i, errUnexpectedFirstChar
			}
			return v, i, nil
		}
		vNew := 10*v + int(k)
		// Test for overflow.
		if vNew < v {
			return -1, i, errTooLongInt
		}
		v = vNew
	}
	return v, n, nil
}

/*

Request Parsing

*/

// Read reads request header from r.
//
// io.EOF is returned if r is closed before reading the first header byte.
func (h *header) Read(r *bufio.Reader) error {
	return h.readLoop(r, true)
}

// readLoop reads request header from r optionally loops until it has enough data.
//
// io.EOF is returned if r is closed before reading the first header byte.
func (h *header) readLoop(r *bufio.Reader, waitForMore bool) error {
	n := 1
	for {
		err := h.tryRead(r, n)
		if err == nil {
			return nil
		}
		if !waitForMore || err != errNeedMore {
			h.resetSkipNormalize()
			return err
		}
		n = r.Buffered() + 1
	}
}

func (h *header) tryRead(r *bufio.Reader, n int) error {
	h.resetSkipNormalize()
	b, err := r.Peek(n)

	if len(b) == 0 {
		if err == io.EOF {
			return err
		}

		if err == nil {
			panic("bufio.Reader.Peek() returned nil, nil")
		}

		// This is for go 1.6 bug. See https://github.com/golang/go/issues/14121 .
		if err == bufio.ErrBufferFull {
			return &ErrSmallBuffer{
				error: fmt.Errorf("error when reading request headers: %w (n=%d, r.Buffered()=%d)", errSmallBuffer, n, r.Buffered()),
			}
		}

		// n == 1 on the first read for the request.
		if n == 1 {
			// We didn't read a single byte.
			return ErrNothingRead{err}
		}

		return fmt.Errorf("error when reading request headers: %w", err)
	}
	b = mustPeekBuffered(r)
	errParse := h.parse()
	if errParse != nil {
		return headerError("request", err, errParse, b, false)
	}
	// mustDiscard(r, headersLen)
	return nil
}

func (h *headerBuf) reset() {
	*h = headerBuf{
		buf:     h.buf[:0],
		headers: h.headers[:0],
		cookies: h.cookies[:0],
	}
}

func (h *header) resetSkipNormalize() {
	h.hbuf.reset()
	*h = header{
		hbuf:   h.hbuf,
		logger: h.logger,
	}
}

func headerError(typ string, err, errParse error, b []byte, secureErrorLogMessage bool) error {
	if errParse != errNeedMore {
		return headerErrorMsg(typ, errParse, b, secureErrorLogMessage)
	}
	if err == nil {
		return errNeedMore
	}

	// Buggy servers may leave trailing CRLFs after http body.
	// Treat this case as EOF.
	if isOnlyCRLF(b) {
		return io.EOF
	}

	if err != bufio.ErrBufferFull {
		return headerErrorMsg(typ, err, b, secureErrorLogMessage)
	}
	return &ErrSmallBuffer{
		error: headerErrorMsg(typ, errSmallBuffer, b, secureErrorLogMessage),
	}
}

func isOnlyCRLF(b []byte) bool {
	for _, ch := range b {
		if ch != rChar && ch != nChar {
			return false
		}
	}
	return true
}

func headerErrorMsg(typ string, err error, b []byte, secureErrorLogMessage bool) error {
	return fmt.Errorf("error when reading %s headers: %w. Buffer size=%d", typ, err, len(b))
}

// ErrNothingRead is returned when a keep-alive connection is closed,
// either because the remote closed it or because of a read timeout.
type ErrNothingRead struct {
	error
}

// ErrSmallBuffer is returned when the provided buffer size is too small
// for reading request and/or response headers.
//
// ReadBufferSize value from Server or clients should reduce the number
// of such errors.
type ErrSmallBuffer struct {
	error
}

func mustPeekBuffered(r *bufio.Reader) []byte {
	buf, err := r.Peek(r.Buffered())
	if len(buf) == 0 || err != nil {
		panic(fmt.Sprintf("bufio.Reader.Peek() returned unexpected data (%q, %v)", buf, err))
	}
	return buf
}

func mustDiscard(r *bufio.Reader, n int) {
	if _, err := r.Discard(n); err != nil {
		panic(fmt.Sprintf("bufio.Reader.Discard(%d) failed: %v", n, err))
	}
}

// Host returns Host header value.
func (h *header) Host() []byte {
	return h.peekHeaderBytes(HeaderHost)
}

// ConnectionClose returns true if 'Connection: close' header is set.
func (h *header) ConnectionClose() bool {
	return h.flags.hasAny(connectionClose)
}

// UserAgent returns User-Agent header value.
func (h *header) UserAgent() []byte {
	return h.peekHeaderBytes(HeaderUserAgent)
}

// b2s converts byte slice to a string without memory allocation.
// See https://groups.google.com/forum/#!msg/Golang-Nuts/ENgbUzYvCuU/90yGx7GUAgAJ .
func b2s(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// s2b converts string to a byte slice without memory allocation.
func s2b(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

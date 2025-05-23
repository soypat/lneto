package httpx

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"unsafe"
)

var (
	errNeedMore        = errors.New("need more data: cannot find trailing lf")
	errInvalidName     = errors.New("invalid header name")
	errSmallBuffer     = errors.New("small read buffer. Increase ReadBufferSize")
	errNonNumericChars = errors.New("non-numeric chars found")
)

type headerScanner struct {
	b     []byte
	key   []byte
	value []byte
	err   error

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

type headerValueScanner struct {
	b     string
	value string
}

func (h *header) parse(buf []byte) (int, error) {
	m, err := h.parseFirstLine(buf)
	if err != nil {
		return 0, err
	}

	h.rawHeaders, _, err = readRawHeaders(h.rawHeaders[:0], b2s(buf[m:]))
	if err != nil {
		return 0, err
	}
	var n int
	n, err = h.parseHeaders(buf[m:])
	if err != nil {
		return 0, err
	}
	return m + n, nil
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

func (hb *headerBuf) parseFirstLine() (method, uri, proto headerSlice, flags flags, err error) {
	var b []byte
	for len(b) == 0 {
		b = hb.scanLine()
	}
	if len(b) < 5 {
		return method, uri, proto, 0, errors.New("too short first HTTP line")
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

func (h *header) parseHeaders(buf []byte) (int, error) {
	h.contentLength = -2
	h.scanner = headerScanner{}
	s := &h.scanner
	s.b = buf
	s.disableNormalizing = h.disableNormalizing
	var err error
	for s.next() {
		key := b2s(s.key)
		value := b2s(s.value)
		if len(key) > 0 {
			// Spaces between the header key and colon are not allowed.
			// See RFC 7230, Section 3.2.4.

			if strings.IndexByte(key, ' ') != -1 || strings.IndexByte(key, '\t') != -1 {
				err = fmt.Errorf("invalid header key %q", s.key)
				continue
			}

			if h.disableSpecialHeader {
				h.h = appendArg(h.h, key, value, argsHasValue)
				continue
			}

			switch s.key[0] | 0x20 {
			case 'h':
				if caseInsensitiveCompare(key, strHost) {
					h.host = append(h.host[:0], value...)
					continue
				}
			case 'u':
				if caseInsensitiveCompare(key, strUserAgent) {
					h.userAgent = append(h.userAgent[:0], value...)
					continue
				}
			case 'c':
				if caseInsensitiveCompare(key, strContentType) {
					h.contentType = append(h.contentType[:0], value...)
					continue
				}
				if caseInsensitiveCompare(key, strContentLength) {
					if h.contentLength != -1 {
						var nerr error
						if h.contentLength, nerr = parseContentLength(b2s(s.value)); nerr != nil {
							if err == nil {
								err = nerr
							}
							h.contentLength = -2
						} else {
							h.contentLengthBytes = append(h.contentLengthBytes[:0], value...)
						}
					}
					continue
				}
				if caseInsensitiveCompare(key, strConnection) {
					if b2s(s.value) == strClose {
						h.connectionClose = true
					} else {
						h.connectionClose = false
						h.h = appendArg(h.h, key, value, argsHasValue)
					}
					continue
				}
			case 't':
				if caseInsensitiveCompare(key, strTransferEncoding) {
					if value != strIdentity {
						h.contentLength = -1
						h.h = setArg(h.h, strTransferEncoding, strChunked, argsHasValue)
					}
					continue
				}
				if caseInsensitiveCompare(key, strTrailer) {
					if nerr := h.SetTrailer(value); nerr != nil {
						if err == nil {
							err = nerr
						}
					}
					continue
				}
			}
		}
		h.h = appendArg(h.h, key, value, argsHasValue)
	}
	if s.err != nil && err == nil {
		err = s.err
	}
	if err != nil {
		h.connectionClose = true
		return 0, err
	}

	if h.contentLength < 0 {
		h.contentLengthBytes = h.contentLengthBytes[:0]
	}
	if h.noHTTP11 && !h.connectionClose {
		// close connection for non-http/1.1 request unless 'Connection: keep-alive' is set.
		v := peekArgStr(h.h, strConnection)
		h.connectionClose = !hasHeaderValue(b2s(v), strKeepAlive)
	}
	return s.hLen, nil
}

func (s *headerScanner) next() bool {
	if !s.initialized {
		s.nextColon = -1
		s.nextNewLine = -1
		s.initialized = true
	}
	bLen := len(s.b)
	if bLen >= 2 && s.b[0] == rChar && s.b[1] == nChar {
		s.b = s.b[2:]
		s.hLen += 2
		return false
	}
	if bLen >= 1 && s.b[0] == nChar {
		s.b = s.b[1:]
		s.hLen++
		return false
	}

	var n int
	if s.nextColon >= 0 {
		n = s.nextColon
		s.nextColon = -1
	} else {
		n = bytes.IndexByte(s.b, ':')

		// There can't be a \n inside the header name, check for this.
		x := bytes.IndexByte(s.b, nChar)
		if x < 0 {
			// A header name should always at some point be followed by a \n
			// even if it's the one that terminates the header block.
			s.err = errNeedMore
			return false
		}
		if x < n {
			// There was a \n before the :
			s.err = errInvalidName
			return false
		}
	}
	if n < 0 {
		s.err = errNeedMore
		return false
	}
	s.key = s.b[:n]
	normalizeHeaderKey(s.key, s.disableNormalizing)
	n++
	for len(s.b) > n && s.b[n] == ' ' {
		n++
		// the newline index is a relative index, and lines below trimmed `s.b` by `n`,
		// so the relative newline index also shifted forward. it's safe to decrease
		// to a minus value, it means it's invalid, and will find the newline again.
		s.nextNewLine--
	}
	s.hLen += n
	s.b = s.b[n:]
	if s.nextNewLine >= 0 {
		n = s.nextNewLine
		s.nextNewLine = -1
	} else {
		n = bytes.IndexByte(s.b, nChar)
	}
	if n < 0 {
		s.err = errNeedMore
		return false
	}
	isMultiLineValue := false
	for {
		if n+1 >= len(s.b) {
			break
		}
		if s.b[n+1] != ' ' && s.b[n+1] != '\t' {
			break
		}
		d := bytes.IndexByte(s.b[n+1:], nChar)
		if d <= 0 {
			break
		} else if d == 1 && s.b[n+1] == rChar {
			break
		}
		e := n + d + 1
		if c := bytes.IndexByte(s.b[n+1:e], ':'); c >= 0 {
			s.nextColon = c
			s.nextNewLine = d - c - 1
			break
		}
		isMultiLineValue = true
		n = e
	}
	if n >= len(s.b) {
		s.err = errNeedMore
		return false
	}
	oldB := s.b
	s.value = s.b[:n]
	s.hLen += n + 1
	s.b = s.b[n+1:]

	if n > 0 && s.value[n-1] == rChar {
		n--
	}
	for n > 0 && s.value[n-1] == ' ' {
		n--
	}
	s.value = s.value[:n]
	if isMultiLineValue {
		s.value, s.b, s.hLen = normalizeHeaderValue(s.value, oldB, s.hLen)
	}
	return true
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

func hasHeaderValue(s, value string) bool {
	var vs headerValueScanner
	vs.b = s
	for vs.next() {
		if caseInsensitiveCompare(vs.value, value) {
			return true
		}
	}
	return false
}

func (s *headerValueScanner) next() bool {
	b := s.b
	if len(b) == 0 {
		return false
	}
	n := strings.IndexByte(b, ',')
	if n < 0 {
		s.value = stripSpace(b)
		s.b = b[len(b):]
		return true
	}
	s.value = stripSpace(b[:n])
	s.b = b[n+1:]
	return true
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
	headersLen, errParse := h.parse(b)
	if errParse != nil {
		return headerError("request", err, errParse, b, false)
	}
	mustDiscard(r, headersLen)
	return nil
}

func (h *header) resetSkipNormalize() {
	h.noHTTP11 = false
	h.connectionClose = false

	h.contentLength = 0
	h.contentLengthBytes = h.contentLengthBytes[:0]

	h.method = h.method[:0]
	h.proto = h.proto[:0]
	h.requestURI = h.requestURI[:0]
	h.host = h.host[:0]
	h.contentType = h.contentType[:0]
	h.userAgent = h.userAgent[:0]
	h.trailer = h.trailer[:0]
	h.mulHeader = h.mulHeader[:0]

	h.h = h.h[:0]
	h.cookies = h.cookies[:0]
	h.cookiesCollected = false

	h.rawHeaders = h.rawHeaders[:0]
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

// Peek returns header value for the given key.
//
// The returned value is valid until the request is released,
// either though ReleaseRequest or your request handler returning.
// Do not store references to returned value. Make copies instead.
func (h *header) Peek(key string) []byte {
	k := getHeaderKeyBytes(&h.bufKV, key, h.disableNormalizing)
	return h.peek(b2s(k))
}

// Host returns Host header value.
func (h *header) Host() []byte {
	if h.disableSpecialHeader {
		return peekArg(h.h, HeaderHost)
	}
	return h.host
}

func getHeaderKeyBytes(kv *argsKV, key string, disableNormalizing bool) []byte {
	kv.key = append(kv.key[:0], key...)
	normalizeHeaderKey(kv.key, disableNormalizing)
	return kv.key
}

func peekArg(h []argsKV, k string) []byte {
	for i, n := 0, len(h); i < n; i++ {
		kv := &h[i]
		if b2s(kv.key) == k {
			return kv.value
		}
	}
	return nil
}

func (h *header) peek(key string) []byte {
	switch key {
	case HeaderHost:
		return h.Host()
	case HeaderContentType:
		return h.ContentType()
	case HeaderUserAgent:
		return h.UserAgent()
	case HeaderConnection:
		if h.ConnectionClose() {
			return []byte(strClose)
		}
		return peekArg(h.h, key)
	case HeaderContentLength:
		return h.contentLengthBytes
	case HeaderCookie:
		if h.cookiesCollected {
			return appendRequestCookieBytes(nil, h.cookies)
		}
		return peekArg(h.h, key)
	case HeaderTrailer:
		return appendArgsKey(nil, h.trailer, strCommaSpace)
	default:
		return peekArg(h.h, key)
	}
}

// ConnectionClose returns true if 'Connection: close' header is set.
func (h *header) ConnectionClose() bool {
	return h.connectionClose
}

// UserAgent returns User-Agent header value.
func (h *header) UserAgent() []byte {
	if h.disableSpecialHeader {
		return peekArg(h.h, HeaderUserAgent)
	}
	return h.userAgent
}

func appendArgsKey(dst []byte, args []argsKV, sep string) []byte {
	for i, n := 0, len(args); i < n; i++ {
		kv := &args[i]
		dst = append(dst, kv.key...)
		if i+1 < n {
			dst = append(dst, sep...)
		}
	}
	return dst
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

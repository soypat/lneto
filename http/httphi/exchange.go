package httphi

import (
	"io"
	"net"
	"slices"
	"strconv"
	"sync/atomic"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/http/httpraw"
	"github.com/soypat/lneto/internal"
)

// maxStatusLine bounds the response status line: "HTTP/1.1 " + 3 digit code +
// " " + longest [StatusText] + CRLF.
const maxStatusLine = len("HTTP/1.1 ") + 3 + 1 + len("Network Authentication Required") + 2

// Exchange is a single request-response cycle over a connection, playing the
// part of both http.Request and http.ResponseWriter: Request* methods read the
// request, [Exchange.StageHeader] and [Exchange.WriteBody] produce the response.
// A [Router] owns a fixed pool of them, which is what bounds its memory.
//
// Request and response share one buffer, the response header being written over
// the bytes that follow the parsed request header. Read the request body with
// [Exchange.ReadBody] before setting response headers.
type Exchange struct {
	acquired       atomic.Bool
	gen            atomic.Uint32
	respTopBuf     [maxStatusLine]byte
	respTopWritten uint8

	rawbuf        []byte
	respHeaderOff uint16
	respHeaderLen uint16
	reqHdr        httpraw.Header

	hijacked bool
	rw       conn

	matchedPattern string

	respRemains   int
	respErr       error // Sticky: response is unrecoverable once a write fails.
	headerWritten bool
	normalizeKeys bool
	nextFree      *Exchange
	readErr       error
}

type ExchangeConfig struct {
	RawBuf                []byte
	RequestBufferLim      int
	NumHeaderKVCap        int
	NormalizeOutgoingKeys bool
	NoRequestBufferGrowth bool
}

// HijackRaw is a low-level implementation of http.Hijacker interface.
// A Hijack method is not exposed due to heap allocation implications and correctness concerns.
// Below is what an actual implementation may look like:
//
//	func (exch *Exchange) Hijack() (net.Conn, *bufio.ReadWriter, error) {
//		conn, ok := exch.rw.(net.Conn)
//		if !ok {
//			return nil, nil, errors.New("net.Conn not implemented")
//		}
//		_, data, err := exch.HijackRaw(nil)
//		if err != nil {
//			return nil, nil, err
//		}
//		var rd *bufio.ReadWriter
//		if len(data) > 0 {
//			rd = &bufio.ReadWriter{Reader: bufio.NewReader(bytes.NewReader(data))}
//		}
//		return conn, rd, nil
//	}
func (exch *Exchange) HijackRaw(dstBody []byte) (conn, []byte, error) {
	data, err := exch.remainingSurplusBody()
	if err != nil {
		return nil, nil, err
	}
	exch.hijacked = true
	dstBody = append(dstBody, data...)
	return exch.rw, dstBody, nil
}

// Configure sets the memory the exchange works with for the rest of its life:
// rawbuf holds the request header, the response header and any surplus body,
// of which the first requestLim bytes are reserved for the request header.
// Panics if requestLim exceeds the buffer. Set normalizeKeys to normalize
// outgoing header keys, i.e: "content-type" to "Content-Type".
func (exch *Exchange) Configure(cfg ExchangeConfig) {
	respSize := len(cfg.RawBuf) - cfg.RequestBufferLim
	if respSize < 0 {
		panic("request lim larger than buffer")
	}
	exch.rawbuf = cfg.RawBuf
	exch.reqHdr.Reset(cfg.RawBuf[:0:cfg.RequestBufferLim], cfg.NumHeaderKVCap)
	exch.reqHdr.ConfigBufferGrowth(!cfg.NoRequestBufferGrowth)
	exch.normalizeKeys = cfg.NormalizeOutgoingKeys
}

// Acquire claims the exchange for conn and resets it to serve a new request,
// reusing the buffer set by [Exchange.Configure]. Returns false if the exchange
// is already serving, in which case conn is untouched.
func (exch *Exchange) Acquire(conn conn) bool {
	if !exch.acquired.CompareAndSwap(false, true) {
		return false
	}
	exch.matchedPattern = ""
	exch.gen.Add(1)
	exch.readErr = nil
	exch.respErr = nil
	exch.hijacked = false
	exch.respTopWritten = 0
	exch.respHeaderOff = 0
	exch.respHeaderLen = 0
	exch.respRemains = 0
	exch.rw = conn
	exch.headerWritten = false
	exch.nextFree = nil
	exch.reqHdr.Reset(nil, 0)
	return true
}

// Release closes the exchange's connection and frees the exchange for a future
// [Exchange.Acquire]. The connection is left open if the handler took ownership
// of it with [Exchange.HijackRaw].
func (exch *Exchange) Release() {
	if !exch.hijacked {
		exch.rw.Close()
	}
	exch.rw = nil
	exch.gen.Add(1)
	exch.acquired.Store(false)
}

// UnsafeRawBuffer returns the contiguous buffer owned by [Exchange] being used for the request and response.
//
// Writing to it will mangle the entire request header+body and/or any staged response headers.
// Does not return the buffer used for the response first line so can be safely
// written to and used without modifying the staged response first line.
//
// Staging headers will write to this buffer so use mindfully.
// To access only the request header buffer portion use [httpraw.Header.BufferRaw] limited
// to [httpraw.Header.BufferParsed] as returned by [Exchange.RequestHeaderRaw].
// Writing to this section will not change the contents read by [Exchange.ReadBody].
//
// In [Router] context, the size of this buffer is influenced directly by [RouterConfig] HeaderBufferSize fields.
func (exch *Exchange) UnsafeRawBuffer() []byte { return exch.rawbuf }

// StageHeader stages a response header field, written on the first
// [Exchange.FlushHeader], [Exchange.WriteHeader] or [Exchange.WriteBody].
// Returns false and drops the field if the response buffer cannot fit it.
// Has no effect once the header has been written.
func (exch *Exchange) StageHeader(key, value string) (enoughMemory bool) {
	if exch.headerWritten {
		return false
	}
	off := int(exch.respHeaderOff) + int(exch.respHeaderLen)
	free := len(exch.rawbuf) - off
	// Field costs key+':'+value+CRLF, plus the CRLF [Exchange.FlushHeader]
	// appends past the last field to close the header block.
	if len(key)+len(value)+len(":\r\n")+len("\r\n") > free {
		exch.respErr = lneto.ErrBufferFull // Omit writing header back to prevent incomplete response.
		return false
	}
	n := copy(exch.rawbuf[off:], key)
	if exch.normalizeKeys {
		httpraw.NormalizeHeaderKey(exch.rawbuf[off : off+n])
	}
	exch.rawbuf[off+n] = ':'
	n++
	n += copy(exch.rawbuf[off+n:], value)
	exch.rawbuf[off+n] = '\r'
	exch.rawbuf[off+n+1] = '\n'
	n += 2
	exch.respHeaderLen += uint16(n)
	return true
}

// StageHeaderInt is [Exchange.StageHeader] with an integer value, i.e: Content-Length.
// It formats the value directly into the response buffer without allocating.
// base must be in the range 10..36; lower bases are dropped, no HTTP header
// field value is written below base 10.
func (exch *Exchange) StageHeaderInt(key string, value int64, base int) (enoughMemory bool) {
	if exch.headerWritten || base < 10 || base > 36 {
		return false
	}
	off := int(exch.respHeaderOff) + int(exch.respHeaderLen)
	free := len(exch.rawbuf) - off
	if len(key)+internal.IntLen(value, base)+len(":\r\n")+len("\r\n") > free {
		exch.respErr = lneto.ErrBufferFull // Omit writing header back to prevent incomplete response.
		return false
	}
	n := copy(exch.rawbuf[off:], key)
	if exch.normalizeKeys {
		httpraw.NormalizeHeaderKey(exch.rawbuf[off : off+n])
	}
	exch.rawbuf[off+n] = ':'
	n++
	n += len(strconv.AppendInt(exch.rawbuf[off+n:off+n], value, base))
	exch.rawbuf[off+n] = '\r'
	exch.rawbuf[off+n+1] = '\n'
	n += 2
	exch.respHeaderLen += uint16(n)
	return true
}

// StageStatus prepares the status line for the given code without writing
// it, i.e: "HTTP/1.1 404 Not Found". Codes with no [StatusText] get an empty
// reason phrase. Has no effect once the header has been written.
func (exch *Exchange) StageStatus(code int) {
	if code >= 1000 || exch.headerWritten {
		return
	} else if code == 200 {
		// Common case.
		exch.respTopWritten = uint8(copy(exch.respTopBuf[:], "HTTP/1.1 200 OK\r\n"))
		return
	}
	n := copy(exch.respTopBuf[:], "HTTP/1.1 ")
	n += len(strconv.AppendInt(exch.respTopBuf[n:n], int64(code), 10))
	text := StatusText(code)
	exch.respTopBuf[n] = ' '
	n++
	n += copy(exch.respTopBuf[n:], text)
	exch.respTopBuf[n] = '\r'
	exch.respTopBuf[n+1] = '\n'
	exch.respTopWritten = uint8(n + 2)
}

// WriteHeader sends the status line for code along with the staged header
// fields. Only the first call reaches the wire, as in http.ResponseWriter.
func (exch *Exchange) WriteHeader(code int) {
	if !exch.headerWritten {
		exch.StageStatus(code)
		exch.FlushHeader()
	}
}

// FlushHeader writes the status line and staged header fields to the connection
// and returns the bytes written, defaulting to a 200 status if none was staged.
// Does nothing if the header was already written.
func (exch *Exchange) FlushHeader() (int, error) {
	if exch.respErr != nil {
		return 0, exch.respErr
	} else if exch.headerWritten {
		return 0, nil
	}
	if exch.respTopWritten == 0 {
		exch.StageStatus(200)
	}
	exch.headerWritten = true
	ng, err := exch.rw.Write(exch.respTopBuf[:exch.respTopWritten])
	if err != nil {
		exch.respErr = err
		return ng, err
	}
	off := int(exch.respHeaderOff)
	headers := exch.rawbuf[off : off+int(exch.respHeaderLen)+2]
	headers[len(headers)-1] = '\n'
	headers[len(headers)-2] = '\r'
	ng2, err := exch.rw.Write(headers)
	exch.respErr = err
	return ng + ng2, err
}

// ExchangeRW is an [io.ReadWriteCloser] view of an [Exchange] wrapping
// [Exchange.ReadBody] and [Exchange.WriteBody] methods.
//
// Exchanges are pooled and reused, so a handle records the exchange generation
// it was taken at and refuses to touch the connection once that exchange moves
// on to another request. Obtain one with [Exchange.ReadWriter].
type ExchangeRW struct {
	gen  uint32
	exch *Exchange
}

// IsValid returns true while the handle still refers to the request it was
// taken from, i.e: false once the exchange was released.
func (rw *ExchangeRW) IsValid() bool {
	return rw.gen == rw.exch.gen.Load() && rw.exch.acquired.Load()
}

func (rw *ExchangeRW) validate() error {
	if !rw.IsValid() {
		return net.ErrClosed
	}
	return nil
}

// Write writes response body bytes. See [Exchange.WriteBody].
// Fails with [net.ErrClosed] once the handle is no longer valid.
func (rw *ExchangeRW) Write(buf []byte) (int, error) {
	if err := rw.validate(); err != nil {
		return 0, err
	}
	return rw.exch.WriteBody(buf)
}

// Read reads request body bytes. See [Exchange.ReadBody].
// Fails with [net.ErrClosed] once the handle is no longer valid.
func (rw *ExchangeRW) Read(buf []byte) (int, error) {
	if err := rw.validate(); err != nil {
		return 0, err
	}
	return rw.exch.ReadBody(buf)
}

// Close invalidates this handle so later reads and writes fail. It does not
// close the connection nor end the exchange, both of which the [Router] owns.
func (rw *ExchangeRW) Close() error {
	if err := rw.validate(); err != nil {
		return err
	}
	rw.gen--
	return nil
}

// ReadWriter fills dst with a stream view of the exchange, valid until the
// exchange is released. The caller owns dst, so a handler may keep one and
// refill it every request without allocating.
func (exch *Exchange) ReadWriter(dst *ExchangeRW) {
	dst.gen = exch.gen.Load()
	dst.exch = exch
}

// Write writes response body bytes, flushing the header first if the handler
// has not written it yet. Once a write to the connection fails the response is
// unrecoverable and every later write returns that same error, so a body never
// reaches the wire without its header.
func (exch *Exchange) WriteBody(buf []byte) (int, error) {
	if exch.respErr != nil {
		return 0, exch.respErr
	} else if !exch.headerWritten {
		_, err := exch.FlushHeader()
		if err != nil {
			return 0, err // Body must not reach the wire without its header.
		}
	}
	if len(buf) == 0 {
		return 0, nil
	}
	n, err := exch.rw.Write(buf)
	exch.respErr = err
	return n, err
}

// ReadBody reads the request body into dst, starting with the bytes that
// arrived in the same read as the header and continuing from the connection.
// The exchange does not know the body's length: use Content-Length or the
// transfer encoding to know when to stop reading.
func (exch *Exchange) ReadBody(dst []byte) (n int, _ error) {
	if exch.respRemains > 0 {
		toRead, err := exch.remainingSurplusBody()
		if err != nil {
			return 0, err
		}
		n = copy(dst, toRead)
		exch.respRemains -= n
		// hand over what already arrived since conn might have
		// exhausted data and could block indefinetely.
		return n, nil
	}
	return exch.rw.Read(dst)
}

func (exch *Exchange) remainingSurplusBody() ([]byte, error) {
	_, err := exch.reqHdr.Body()
	if err != nil {
		return nil, err // Returns mangled buffer error if request header has been misused.
	}
	surplus := exch.rawbuf[exch.reqHdr.BufferParsed():exch.reqHdr.BufferReceived()]
	toRead := surplus[len(surplus)-exch.respRemains:]
	return toRead, nil
}

// MuxPattern returns the pattern [Mux] matched to the request.
func (exch *Exchange) MuxPattern() string {
	return exch.matchedPattern
}

// RequestHeaderRaw returns the parsed request header for access beyond the
// Request* methods, such as [httpraw.Header.ForEach]. Valid until the exchange
// is released, and writing to it corrupts the response.
func (exch *Exchange) RequestHeaderRaw() *httpraw.Header {
	return &exch.reqHdr
}

// RequestParseCookie parses the request's key header field into dst, i.e:
// "Cookie". The caller owns dst and its buffer, so it may be reused between
// requests.
func (exch *Exchange) RequestParseCookie(dst *httpraw.Cookie, key string) error {
	value := exch.RequestHeader(key)
	return dst.ParseBytes(value)
}

// RequestContentType returns the request's Content-Type field value as it
// appears on the wire, parameters included, nil if absent. Test it with
// [httpraw.MediaTypeIs] and pick parameters out with [httpraw.ContentParam].
func (exch *Exchange) RequestContentType() []byte {
	return exch.RequestHeader("Content-Type")
}

// RequestContentLength returns the body length declared by the request's
// Content-Length field. An absent field is signalled with present=false and no error.
// See [httpraw.Header.ContentLength].
func (exch *Exchange) RequestContentLength() (_ int64, present bool, _ error) {
	return exch.RequestHeaderRaw().ContentLength()
}

// RequestParseForm reads the request body into buf and parses it as
// "application/x-www-form-urlencoded" into dst. buf is the only storage used and
// the only limit: a body longer than buf is refused with [lneto.ErrBufferFull]
// before a single byte is read, leaving the caller free to answer 413. Pairs are
// left as they arrived, call [httpraw.Form.Decode] to decode them in place.
//
// Unlike http.Request.ParseForm the query string is not folded in, reach it with
// [Exchange.RequestQuery] or [Exchange.AppendQuery]. The body is consumed, so
// call this before [Exchange.ReadBody].
//
// A request with no Content-Length has no body, RFC 9112 6.3, and yields an
// empty form. Use [Exchange.RequestContentLength] to tell that apart from a body
// that arrived empty.
func (exch *Exchange) RequestParseForm(dst *httpraw.Form, buf []byte) error {
	if !httpraw.MediaTypeIs(exch.RequestContentType(), "application/x-www-form-urlencoded") {
		return errNotFormEncoded
	} else if exch.RequestHeader("Transfer-Encoding") != nil {
		// Chunked bodies are framed, so reading Content-Length bytes off the
		// wire would parse chunk sizes as form data. httpraw does not decode them.
		return errUnsupportedTransferCoding
	}

	length, present, err := exch.RequestContentLength()
	if !present {
		dst.Reset(nil, 0)
		return nil // No length is no body, RFC 9112 6.3.
	} else if err != nil {
		return err
	} else if length > int64(len(buf)) {
		return lneto.ErrShortBuffer // Refuse before reading, caller may answer 413.
	}
	buf = buf[:length]
	for read := 0; read < len(buf); {
		n, err := exch.ReadBody(buf[read:])
		read += n
		if n == 0 {
			if err == nil {
				err = io.ErrNoProgress
			} else if err == io.EOF {
				break
			}
			return err
		}
	}
	dst.Reset(buf, 0)
	return dst.Parse()
}

// RequestMultipart returns a parser prepared from the boundary parameter of the
// request's Content-Type field. It reads no body: multipart parts declare no
// length, so the caller drives the loop with a buffer it owns and decides per
// part what to keep and when a part has grown too large. See
// [Exchange.ReadMultiparts] for that loop already written.
func (exch *Exchange) RequestMultipart() (mp httpraw.Multipart, err error) {
	contentType := exch.RequestContentType()
	if !httpraw.MediaTypeIs(contentType, "multipart/form-data") {
		return mp, errNotMultipart
	}
	return mp, mp.SetContentType(contentType)
}

// MultipartSink is a part of a multipart body together with the writer its
// content was streamed to, as appended by [Exchange.ReadMultiparts].
type MultipartSink struct {
	// Header identifies the part. Name and Filename are copies, so they
	// outlive the read buffer; PartView does not, see [httpraw.MultipartHeader].
	Header httpraw.MultipartHeader
	// Sink received the part's content and was closed when the part ended,
	// nil for a part newSink chose to discard.
	Sink io.WriteCloser
}

// ReadMultiparts streams the request's "multipart/form-data" body, writing each
// part to a sink newSink returns for it and appending the pair to dst. buf is the
// only storage used and content is never held whole, so a part of any length
// streams through a buffer the caller sized. dst is appended to and returned, so
// a handler may hand back the slice of a previous request to reuse its parts.
//
// newSink is called once per part, before any of its content is read, and picks
// what to do with it from hdr.Name and hdr.Filename: return a writer to keep the
// part, or nil to discard its content and keep only the header. Each sink is
// closed as soon as its part ends, so Close reports the part arrived whole; on
// error the sink of the part being read is left open for the caller to deal with.
//
// A part header that does not fit buf is refused with [lneto.ErrShortBuffer],
// since reading more can never complete it, leaving the caller free to answer
// 413. The body is consumed, so call this before [Exchange.ReadBody].
func (exch *Exchange) ReadMultiparts(dst []MultipartSink, buf []byte, newSink func(hdr *httpraw.MultipartHeader) io.WriteCloser) (_ []MultipartSink, _ error) {
	mp, err := exch.RequestMultipart()
	if err != nil {
		return dst, err
	} else if newSink == nil || len(buf) <= len("\r\n--")+len(mp.Boundary) {
		// A buffer that cannot outgrow a delimiter never makes progress.
		return dst, lneto.ErrInvalidConfig
	}
	buflen := 0
	for {
		// Slot for the next part, given back when the body turns out to be
		// over, so its Name and Filename buffers stay available for reuse.
		part := internal.SliceReclaim(&dst)
		var parsed int
		for {
			parsed, err = mp.NextHeader(&part.Header, buf[:buflen])
			if err != nil {
				dst = dst[:len(dst)-1]
				if err == io.EOF {
					err = nil // Closing delimiter, body done.
				}
				return dst, err
			} else if parsed > 0 {
				break // Delimiter and header block complete.
			} else if buflen == len(buf) {
				dst = dst[:len(dst)-1]
				return dst, lneto.ErrShortBuffer // Header longer than buf.
			}
			// A read that both delivers and fails, as the last of the body
			// followed by a hangup does, may still hold what the parser is
			// waiting for: take the data and let the error surface on the
			// next read.
			n, readErr := exch.ReadBody(buf[buflen:])
			buflen += n
			if n == 0 && readErr != nil {
				dst = dst[:len(dst)-1]
				return dst, readErr
			}
		}
		part.Sink = newSink(&part.Header)
		buflen = copy(buf, buf[parsed:buflen])
		for {
			bodyLen, restOff, done := mp.NextBody(buf[:buflen])
			if bodyLen > 0 && part.Sink != nil {
				_, err = part.Sink.Write(buf[:bodyLen])
				if err != nil {
					return dst, err
				}
			}
			buflen = copy(buf, buf[restOff:buflen])
			if done {
				break // Buffer now starts at the next part's delimiter.
			}
			n, readErr := exch.ReadBody(buf[buflen:])
			buflen += n
			if n == 0 && readErr != nil {
				return dst, readErr // Body ended mid part.
			}
		}
		if part.Sink != nil {
			if err = part.Sink.Close(); err != nil {
				return dst, err
			}
		}
	}
}

// RequestHeader returns the value of the first request header field matching
// key, or nil if absent. Key matching is case sensitive.
func (exch *Exchange) RequestHeader(key string) []byte {
	header := exch.RequestHeaderRaw()
	return header.Get(key)
}

// RequestTarget returns the request-target (URI) of the request line, i.e:
// "/search?q=go". See [httpraw.Header.RequestTarget].
func (exch *Exchange) RequestTarget() []byte {
	return exch.RequestHeaderRaw().RequestTarget()
}

// RequestPath returns the request-target (URI) up to the query string. This is
// what the [Mux] matches on, i.e: "/search" for a request to "/search?q=go".
func (exch *Exchange) RequestPath() []byte {
	return exch.RequestHeaderRaw().RequestPath()
}

// RequestQuery returns the request's query string as it appears on the wire.
// Iterate it with [httpraw.NextQueryPair]. See [httpraw.Header.RequestQuery].
func (exch *Exchange) RequestQuery() []byte {
	return exch.RequestHeaderRaw().RequestQuery()
}

// AppendQuery appends the value of the first query parameter matching key to
// dst and reports whether the parameter was present. A parameter with no value
// ("?debug") and one with an empty value ("?debug=") are both present with
// nothing appended.
//
// Keys are matched decoded, so key "a b" finds "a%20b" and "a+b". Values are
// appended raw unless decoded is set, in which case percent escapes and '+' are
// decoded. A parameter whose value fails to decode is reported absent, and a
// parameter whose key fails to decode is skipped.
//
// dst doubles as scratch space for decoding candidate keys, so AppendQuery only
// allocates when dst lacks the capacity to hold the longest key it inspects.
func (exch *Exchange) AppendQuery(dst []byte, key string, decoded bool) (valueAppended []byte, present bool) {
	const plusAsSpace = true // Query strings are form encoded, unlike paths.
	base := len(dst)
	rawkey, rawval, rest := httpraw.NextQueryPair(exch.RequestQuery())
	for ; rawkey != nil; rawkey, rawval, rest = httpraw.NextQueryPair(rest) {
		if b2s(rawkey) != key {
			// Key may be encoded: decode it over dst's free space and compare.
			// A decoded key cannot appear raw, so this cannot alias a real key.
			dst = slices.Grow(dst, len(rawkey))
			scratch := dst[base : base+len(rawkey)]
			n, err := httpraw.CopyDecodedPercentURL(scratch, rawkey, plusAsSpace)
			if err != nil || b2s(scratch[:n]) != key {
				continue // Malformed or different key, keep looking.
			}
		}
		if len(rawval) == 0 {
			return dst[:base], true // Flag or empty value, nothing to append.
		}
		dst = slices.Grow(dst, len(rawval))
		if !decoded {
			return append(dst[:base], rawval...), true
		}
		n, err := httpraw.CopyDecodedPercentURL(dst[base:base+len(rawval)], rawval, plusAsSpace)
		if err != nil {
			return dst[:base], false // Do not hand back half a decode.
		}
		return dst[:base+n], true
	}
	return dst[:base], false
}

// RequestMethod returns the request line's method, i.e: "GET". See
// [MethodFromBytes] to compare it against a [Method].
func (exch *Exchange) RequestMethod() []byte {
	return exch.RequestHeaderRaw().Method()
}

// RequestConnectionClose returns true if the client asked for the connection to
// be closed after this exchange with a "Connection: close" header field.
func (exch *Exchange) RequestConnectionClose() bool {
	return exch.RequestHeaderRaw().ConnectionClose()
}

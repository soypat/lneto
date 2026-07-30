package httphi

import (
	"io"
	"net"
	"slices"
	"strconv"
	"sync/atomic"
	"unsafe"

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
	pathValues    []PathValue
	// bodyRW is the reader handed to [httpraw.Form.ReadLimited], kept here so
	// boxing it into an io.Reader allocates nothing per request.
	bodyRW ExchangeRW

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

// ExchangeConfig is the memory an [Exchange] is fixed to for the rest of its
// life by [Exchange.Configure]. A [Router] derives one per exchange from its
// [RouterConfig], which is what bounds the router's memory.
//
// Fields open with Required, Conditional or Optional and the constraint in
// brackets, as in [RouterConfig].
type ExchangeConfig struct {
	// Required [non-empty] single buffer holding the request header, the response
	// header and any surplus body. See [Exchange.UnsafeRawBuffer].
	RawBuf []byte
	// Required [<=len(RawBuf)] bytes of RawBuf reserved for the request header,
	// the rest being the response. Configure panics if it exceeds RawBuf.
	RequestBufferLim int
	// Required [>0] request header fields that may be parsed. A request carrying
	// more is answered 431, see [httpraw.ErrHeaderTooMany].
	NumHeaderKVCap int
	// Optional [any] normalization of staged response header keys as they are
	// written, i.e: "content-type" becomes "Content-Type".
	NormalizeOutgoingKeys bool
	// Optional [any] cap holding the request header to RequestBufferLim rather than
	// growing it. A header outgrowing it is answered 431, see [httpraw.ErrBufferExhausted].
	NoRequestBufferGrowth bool
	// Conditional [>=the most wildcards any one registered pattern binds] number of
	// path values bindable, read back with [Exchange.PathValue]. A pattern binding
	// more never matches, see [SetPathValues]. Zero suits a mux of literal patterns.
	MaxPathValues int
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
	internal.SliceReuse(&exch.pathValues, cfg.MaxPathValues)
	exch.pathValues = exch.pathValues[:cfg.MaxPathValues]
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
	clear(exch.pathValues)
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

// StageHeaderBytes is [Exchange.StageHeader] with a byte slice value, i.e: a
// field copied out of the request. The value is not retained.
func (exch *Exchange) StageHeaderBytes(key string, value []byte) (enoughMemory bool) {
	return exch.StageHeader(key, b2s(value))
}

// StageHeaderInt is [Exchange.StageHeaderIntBase] in base 10, which is the base
// every HTTP field value carrying a number uses, i.e: Content-Length.
func (exch *Exchange) StageHeaderInt(key string, value int64) (enoughMemory bool) {
	return exch.StageHeaderIntBase(key, value, 10)
}

// StageHeaderIntBase is [Exchange.StageHeader] with an integer value, i.e: Content-Length.
// It formats the value directly into the response buffer without allocating.
// base must be in the range 10..36; lower bases are dropped, no HTTP header
// field value is written below base 10.
func (exch *Exchange) StageHeaderIntBase(key string, value int64, base int) (enoughMemory bool) {
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
func (exch *Exchange) WriteHeader(code int) (n int, err error) {
	if !exch.headerWritten {
		exch.StageStatus(code)
		n, err = exch.FlushHeader()
	}
	return n, err
}

// Respond writes a complete response in one call: Content-Type, a Content-Length
// taken from len(body), the status line and the body. An empty contentType
// stages no Content-Type field, for a code that carries no entity.
//
// It also stages "Connection: close", the router serving one exchange per
// connection, so a peer never waits on a response that is not coming.
//
// Returns [Exchange.ResponseError]: staged fields that did not fit and failed
// writes are both reported there, so a truncated response cannot pass silently.
func (exch *Exchange) Respond(code int, contentType string, body []byte) error {
	exch.stageResponse(code, contentType, len(body))
	exch.WriteBody(body) // Reports through respErr, checked below.
	return exch.respErr
}

// RespondString is [Exchange.Respond] with a string body, saving the conversion.
func (exch *Exchange) RespondString(code int, contentType, body string) error {
	exch.stageResponse(code, contentType, len(body))
	exch.WriteBodyString(body) // Reports through respErr, checked below.
	return exch.respErr
}

// stageResponse stages the fields and status line a complete response needs.
// Drops are recorded on respErr by the Stage* calls, so [Exchange.WriteBody]
// declines to write a partial header afterwards.
func (exch *Exchange) stageResponse(code int, contentType string, bodyLen int) {
	if contentType != "" {
		exch.StageHeader("Content-Type", contentType)
	}
	exch.StageHeaderInt("Content-Length", int64(bodyLen))
	// One exchange per connection today, so the peer is told not to wait for a
	// second response on it. Revisit once the router loops exchanges.
	exch.StageHeader("Connection", "close")
	exch.StageStatus(code)
}

// ResponseError returns any error encountered during staging of headers or during writing of response.
// Provides an ergonomic way of checking if one ran out of buffer space after staging all headers with [Exchange.StageHeader].
func (exch *Exchange) ResponseError() error {
	return exch.respErr
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

// WriteString wraps [Exchange.WriteBodyString]. Fails if handle no longer valid.
func (rw *ExchangeRW) WriteString(s string) (int, error) {
	if err := rw.validate(); err != nil {
		return 0, err
	}
	return rw.exch.WriteBodyString(s)
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

// WriteBodyString implements [io.StringWriter] by unsafe conversion.
// Most underlying [io.Writer] implementations are TCP transport and not modify/own the underlying buffer.
func (exch *Exchange) WriteBodyString(buf string) (int, error) {
	return exch.WriteBody(unsafe.Slice(unsafe.StringData(buf), len(buf)))
}

// WriteBody writes response body bytes, flushing the header first if the handler
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
	// Folded: field names are case insensitive and HTTP/2 mandates lowercase, so
	// a proxy translating h2 to h1 sends "content-type", RFC 9110 5.1.
	return exch.RequestHeaderRaw().GetFold("Content-Type")
}

// RequestContentLength returns the body length declared by the request's
// Content-Length field. An absent field is signalled with present=false and no error.
// See [httpraw.Header.ContentLength].
func (exch *Exchange) RequestContentLength() (_ int64, present bool, _ error) {
	return exch.RequestHeaderRaw().ContentLength()
}

// RequestParseForm parses "application/x-www-form-urlencoded" pairs into dst
// from the request body and, when parseURL is set, from the query string as
// well. Pairs are stored as they arrived, call [httpraw.Form.Decode] to decode
// them in place.
//
// dst owns the memory: both sources are read into its buffer and parsed together
// once. Hand it a preallocated buffer with [httpraw.Form.Reset] and turn growth
// off with [httpraw.Form.EnableBufferGrowth] to bound it, which then reports
// [httpraw.ErrBufferExhausted] instead of allocating. It grows by default.
//
// prioritizeURL reads the query ahead of the body, so a key carried by both
// resolves to the query's value: [httpraw.Form.Get] answers with the first pair
// holding a key. Both stay readable in wire order through [httpraw.Form.Pair].
// The body is consumed, so call this before [Exchange.ReadBody].
//
// A request with no Content-Length has no body, RFC 9112 6.3, and one with no
// Content-Type declares no encoding to parse, RFC 9110 8.3. Neither is an error,
// a bodiless POST being legal, and the query is still parsed when asked for. A
// Content-Type that is present and not form encoded is [errNotFormEncoded].
func (exch *Exchange) RequestParseForm(dst *httpraw.Form, parseURL, prioritizeURL bool) error {
	dst.Reset(nil, 0) // Reuse whatever buffer dst holds, discarding old pairs.
	if parseURL && prioritizeURL {
		if err := exch.readQueryForm(dst); err != nil {
			return err
		}
	}
	if err := exch.readBodyForm(dst); err != nil {
		return err
	}
	if parseURL && !prioritizeURL {
		if err := exch.readQueryForm(dst); err != nil {
			return err
		}
	}
	return dst.Parse()
}

// formSeparator joins two sources inside one form buffer. Shared so appending it
// converts no literal per call.
var formSeparator = []byte{'&'}

// readQueryForm appends the request's query string to dst's buffer.
func (exch *Exchange) readQueryForm(dst *httpraw.Form) error {
	query := exch.RequestQuery()
	if len(query) == 0 {
		return nil
	} else if err := separateForm(dst); err != nil {
		return err
	}
	return dst.ReadFromBytes(query)
}

// readBodyForm appends the request body to dst's buffer, reading until
// Content-Length bytes have arrived.
func (exch *Exchange) readBodyForm(dst *httpraw.Form) error {
	contentType := exch.RequestContentType()
	if contentType == nil {
		return nil // No declared encoding is no form, RFC 9110 8.3.
	} else if !httpraw.MediaTypeIs(contentType, "application/x-www-form-urlencoded") {
		return errNotFormEncoded
	} else if exch.RequestHeaderRaw().GetFold("Transfer-Encoding") != nil {
		// Chunked bodies are framed, so reading Content-Length bytes off the
		// wire would parse chunk sizes as form data. httpraw does not decode them.
		return errUnsupportedTransferCoding
	}
	length, present, err := exch.RequestContentLength()
	if err != nil {
		return err
	} else if !present || length == 0 {
		return nil // No length is no body, RFC 9112 6.3.
	}
	if err = separateForm(dst); err != nil {
		return err
	}
	// Reuse the exchange's own handle: a local would escape when boxed into the
	// io.Reader [httpraw.Form.ReadLimited] takes, costing an allocation a request.
	exch.ReadWriter(&exch.bodyRW)
	// A single read may fall short of the limit, the body arriving a TCP segment
	// at a time, so read until the declared length is in hand.
	for read := 0; read < int(length); {
		n, err := dst.ReadLimited(&exch.bodyRW, int(length)-read)
		read += n
		if n == 0 {
			if err == nil {
				err = io.ErrNoProgress
			} else if err == io.EOF {
				break // Peer sent less than it declared.
			}
			return err
		} else if err != nil && err != io.EOF {
			return err
		}
	}
	return nil
}

// separateForm appends the '&' keeping two sources from merging into one pair,
// doing nothing while dst holds no bytes yet.
func separateForm(dst *httpraw.Form) error {
	if dst.BufferUsed() == 0 {
		return nil
	}
	return dst.ReadFromBytes(formSeparator)
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

// RequestQueryValue returns an undecoded view of the first query parameter
// matching key and reports whether it was present. Keys are matched decoded, so
// key "a b" finds "a%20b" and "a+b"; a parameter whose key is a malformed
// escape is skipped. A parameter with no value ("?debug") and one with an empty
// value ("?debug=") are both present with a zero length view.
//
// The view aliases the request buffer, so copy it to outlive the handler or use
// [Exchange.RequestQueryAppend] to decode it out.
func (exch *Exchange) RequestQueryValue(key string) (rawValue []byte, present bool) {
	const plusAsSpace = true // Query strings are form encoded, unlike paths.
	rawkey, rawval, rest := httpraw.NextQueryPair(exch.RequestQuery())
	for ; rawkey != nil; rawkey, rawval, rest = httpraw.NextQueryPair(rest) {
		// Compare raw first: a key needing no decoding is the common case, and
		// the decoding compare walks the key an escape at a time.
		if b2s(rawkey) == key || httpraw.EqualDecodedPercentURL(rawkey, key, plusAsSpace) {
			return rawval, true
		}
	}
	return nil, false
}

// RequestQueryAppend appends the value of the first query parameter matching key to
// dst and reports whether the parameter was present, matching keys as
// [Exchange.RequestQueryValue] does. A parameter with no value ("?debug") and
// one with an empty value ("?debug=") are both present with nothing appended.
//
// Values are appended raw unless decoded is set, in which case percent escapes
// and '+' are decoded. A parameter whose value fails to decode is reported
// absent, dst being left as it was rather than holding half a decode.
func (exch *Exchange) RequestQueryAppend(dst []byte, key string, decoded bool) (valueAppended []byte, present bool) {
	const plusAsSpace = true // Query strings are form encoded, unlike paths.
	rawval, present := exch.RequestQueryValue(key)
	if !present || len(rawval) == 0 {
		return dst, present
	}
	if !decoded {
		return append(dst, rawval...), true
	}
	base := len(dst)
	dst = slices.Grow(dst, len(rawval))
	n, err := httpraw.CopyDecodedPercentURL(dst[base:base+len(rawval)], rawval, plusAsSpace)
	if err != nil {
		return dst[:base], false // Do not hand back half a decode.
	}
	return dst[:base+n], true
}

// PathValue returns the segment the request path bound to the wildcard named
// key, or nil if the matched pattern has no such wildcard. It plays the part of
// http.Request.PathValue. See [SetPathValues] for the pattern syntax and for
// which segments a wildcard binds.
//
//	sm.Handle("GET /users/{id}", func(exch *httphi.Exchange) {
//		id := exch.PathValue("id") // "42" on a GET /users/42.
//	})
func (exch *Exchange) PathValue(key string) []byte {
	for i := range exch.pathValues {
		if exch.pathValues[i].Key == key {
			return exch.pathValues[i].Value
		} else if exch.pathValues[i].Key == "" {
			break // No more keys set.
		}
	}
	return nil
}

// PathValueAppend acceses the result of [Exchange.PathValue] and appends it to dst.
// If decoded is set to true the result will be URL-percent decoded. An error is returned if URL-percent decoding fails.
func (exch *Exchange) PathValueAppend(dst []byte, key string, decoded bool) ([]byte, error) {
	const plusAsSpace = true
	rawValue := exch.PathValue(key)
	if !decoded || len(rawValue) == 0 {
		return append(dst, rawValue...), nil
	}
	base := len(dst)
	dst = slices.Grow(dst, len(rawValue))
	n, err := httpraw.CopyDecodedPercentURL(dst[base:base+len(rawValue)], rawValue, plusAsSpace)
	if err != nil {
		return dst[:base], err // Do not hand back half a decode.
	}
	return dst[:base+n], nil
}

// RequestMethod returns the request's [Method] enum.
func (exch *Exchange) RequestMethod() Method {
	return MethodFromBytes(exch.RequestMethodRaw())
}

// RequestMethod returns the request line's method as a []byte view, i.e: "GET".
func (exch *Exchange) RequestMethodRaw() []byte {
	return exch.RequestHeaderRaw().Method()
}

// RequestConnectionClose returns true if the client asked for the connection to
// be closed after this exchange with a "Connection: close" header field.
func (exch *Exchange) RequestConnectionClose() bool {
	return exch.RequestHeaderRaw().ConnectionClose()
}

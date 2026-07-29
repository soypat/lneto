package httpraw

import (
	"bytes"
	"io"
	"strconv"
)

const (
	methodGet           = "GET"
	strHTTP11           = "HTTP/1.1"
	strCRLF             = "\r\n"
	headerCookie        = "Cookie"
	headerConnection    = "Connection"
	headerContentLength = "Content-Length"
	strClose            = "close"
)

// Flags is a bitset of signals gathered while parsing or building a header,
// such as a status code having been set or the peer requesting connection
// close. See [Header.Flags].
type Flags uint16

const (
	flagNoBufferGrow Flags = 1 << iota
	flagDoneParsingHeader
	flagOOMReached
	flagConnClose
	flagNoHTTP11
	flagMangledBuffer // set when header fields appended to buffer via Add,Set calls
	flagKVAppended    // set after KV appended to buffer outside Read methods.
	flagReaderEOF
	// set if [Header.SetStatus] or [Header.SetStatusInt] has been called.
	FlagStatusSet
)

// HasAny returns true if any of the argument flags are set.
func (f Flags) HasAny(checkThese Flags) bool {
	return f&checkThese != 0
}

// Header implements "raw" HTTP header key-value parsing, validation and marshalling.
//
// It does NOT implement:
//   - Normalization.
//   - Cookies (see [Cookie]).
//   - Special header optimizations.
//   - Content-Length validation and other special header field value validation.
type Header struct {
	hbuf headerBuf

	// Request fields.
	method        headerSlice
	requestTarget headerSlice
	proto         headerSlice

	// Response fields.
	statusCode headerSlice
	statusText headerSlice
	_          noCopy
}

// Flags returns [Flags] to signal status code has been set, Connection:Close or other useful signals provided by flags.
func (h *Header) Flags() Flags { return h.hbuf.kv.flags }

// ConfigBufferGrowth configures the memory the header may use. Setting
// outlives [Header.Reset]. Call before parsing/reading.
//
// enableBufferGrowth enables growing both the header buffer and the header key/value pair slice.
func (h *Header) ConfigBufferGrowth(enableBufferGrowth bool) {
	h.hbuf.kv.EnableBufferGrowth(enableBufferGrowth)
}

// ParseBytes copies the bytes into buffer and parses the HTTP header. It fails if HTTP header data is incomplete.
func (h *Header) ParseBytes(asResponse bool, b []byte) error {
	h.Reset(nil, 0)
	err := h.hbuf.kv.ReadFromBytes(b)
	if err != nil {
		return err
	}
	return h.parse(asResponse)
}

// Parse parses accumulated data in-place with no copying. One can set HTTP header data buffer with [Header.Reset].
// It fails if HTTP data is incomplete.
func (h *Header) Parse(asResponse bool) error {
	debuglog("http:parse:reset")
	h.Reset(h.hbuf.kv.buf, 0)
	debuglog("http:parse:start")
	return h.parse(asResponse)
}

// TryParse begins parsing or resumes parsing from a failed previous attempt from any of the Parse* methods.
// As long as needMoreData returns true future calls to TryParse may succeed and the header is not done parsing.
// Users may call [Header.ForEach] in-between TryParse calls so as to validate values before header is completely parsed.
//
//	needMoreData := true
//	var err error
//	for needMoreData {
//		_, err = h.ReadFrom(r, 1024)
//		if err != nil {
//			break
//		}
//		needMoreData, err = h.TryParse(asResponse)
//	}
//	if err != nil {
//		return err
//	}
func (h *Header) TryParse(asResponse bool) (needMoreData bool, err error) {
	flags := h.Flags()
	if flags.HasAny(flagDoneParsingHeader) {
		return false, errAlreadyParsed
	} else if flags.HasAny(flagMangledBuffer) {
		return false, errMangledBuffer
	}
	if asResponse && h.statusCode.len == 0 || !asResponse && h.requestTarget.start == 0 {
		err = h.parseFirstLine(asResponse)
		if err != nil {
			return err == ErrNeedMoreData, err
		}
	}
	err = h.parseNextHeaders(flags)
	return err == ErrNeedMoreData, err
}

// ParsingSuccess returns true if TryParse was successful, that is to say it returned needMoreData==false and err==nil.
func (h *Header) ParsingSuccess() bool {
	return h.Flags().HasAny(flagDoneParsingHeader)
}

// ReadFromLimited reads at most maxBytesToRead from reader and appends them to underlying buffer.
// Used to accumulate HTTP header for later parsing with [Header.TryParse].
// If read is successful (read length>0) and reader returns [io.EOF] then ReadFromLimited will return a nil error.
func (h *Header) ReadFromLimited(r io.Reader, maxBytesToRead int) (int, error) {
	return h.hbuf.kv.ReadLimited(r, maxBytesToRead)
}

// ReadFromBytes appends argument buffer to underlying buffer.
// Used to accumulate HTTP header for later parsing with [Header.TryParse].
func (h *Header) ReadFromBytes(b []byte) error {
	return h.hbuf.kv.ReadFromBytes(b)
}

// BufferReceived returns the amoung of bytes read during calls to Read* methods.
// Returns 0 if buffer is invalid/mangled.
func (h *Header) BufferReceived() int {
	if h.Flags().HasAny(flagMangledBuffer | flagOOMReached) {
		return 0
	}
	return len(h.hbuf.kv.BufferRaw())
}

// BufferParsed returns the amount of bytes parsed during a call to Parse* methods.
// If the Parse* method completed without error then BufferParsed returns the header's length including the final "\r\n\r\n" text.
// BufferParsed returns 0 if the buffer is invalid/mangled or if no header data has been parsed succesfully.
func (h *Header) BufferParsed() int {
	if h.Flags().HasAny(flagMangledBuffer | flagOOMReached) {
		return 0
	}
	return h.hbuf.off
}

// BufferRaw returns the undeerlying buffer as stored currently in memory.
// The length of the returned buffer is the used portion. Capacity of returned slice is [Header.BufferCapacity].
func (h *Header) BufferRaw() []byte { return h.hbuf.kv.BufferRaw() }

// BufferUsed returns the raw memory used.
//
//	BufferUsed + BufferFree == BufferCapacity
func (h *Header) BufferUsed() int {
	return len(h.hbuf.kv.BufferRaw())
}

// BufferFree returns amount of bytes free in underlying buffer.
//
//	BufferUsed + BufferFree == BufferCapacity
func (h *Header) BufferFree() int {
	return h.hbuf.free()
}

// BufferCapacity returns the total capacity of the underlying buffer.
//
//	BufferUsed + BufferFree == BufferCapacity
func (h *Header) BufferCapacity() int {
	return cap(h.hbuf.kv.BufferRaw())
}

// ForEach iterates over header key-value field tuples.
func (h *Header) ForEach(cb func(key, value []byte) bool) {
	h.hbuf.kv.ForEach(cb)
}

// Reset discards all parsed data and sets the buffer data to buf. This method
// can be used to avoid copying and growing buffers. Call [Header.Parse] after setting buffer
// data with Reset to parse data in-place.
// If buf is nil then the current buffer is reused. There are 3 ways to use Reset:
//
//	h.Reset(prealloc[:0], 16); h.ParseBytes(httpHeader) // Tell header to use a pre-allocated buffer capacity.
//	h.Reset(httpHeader, 16); h.Parse() // Parse bytes in place with no copying.
//	h.Reset(nil) // Reuse buffer previously set in a call to Reset.
func (h *Header) Reset(buf []byte, numHeaderCapacity int) {
	const persistentFlags = flagNoBufferGrow
	debuglog("http:reset:hbuf")
	h.hbuf.reset(buf, numHeaderCapacity)
	if h.Flags().HasAny(flagNoBufferGrow) && h.BufferCapacity() < 32 {
		panic("small buffer and flagNoBufferGrow set")
	}
	*h = Header{hbuf: h.hbuf}
	debuglog("http:reset:done")
}

// Body returns the surplus data following headers. It is only valid as long as Parse* or Reset methods are not called.
func (h *Header) Body() ([]byte, error) {
	debuglog("http:body")
	flags := h.Flags()
	if flags.HasAny(flagMangledBuffer) {
		return nil, errMangledBuffer
	} else if flags.HasAny(flagDoneParsingHeader) {
		return h.BufferRaw()[h.hbuf.off:], nil
	}
	return nil, errUnparsed
}

// SetBytes is equivalent to [Header.Set] but with a []byte value. Does not keep reference to value slice.
// Calling SetBytes Mangles the buffer.
func (h *Header) SetBytes(key string, value []byte) {
	h.Set(key, b2s(value))
}

// SetInt is equivalent to [Header.Set] but with an integer value i.e: Content-Length header key.
// base must be in the range 2..36 (as accepted by [strconv.AppendInt]); other bases are dropped.
// SetInt formats the value directly into the header buffer without heap allocation.
func (h *Header) SetInt(key string, value int64, base int) {
	if base < 2 || base > 36 {
		return // strconv.AppendInt only supports base 2..36.
	}
	h.hbuf.kv.SetInt(key, value, base)
}

// Set sets a key-value pair in the HTTP header.
// Calling Set mangles the buffer.
func (h *Header) Set(key, value string) (enoughSpace bool) {
	return h.hbuf.kv.Set(key, value)

	// useKv := h.takeReusableSlot(key)
	// if useKv == nil {
	// 	h.hbuf.kv.appendPair(key, value)
	// } else {
	// 	useKv.value = h.hbuf.kv.reuseOrAppend(useKv.value, value)
	// }
}

// takeReusableSlot returns the valid key-value entry for key with the largest
// value buffer (best candidate for in-place reuse) and invalidates any other
// entries sharing the key. Returns nil if the key is not present.
func (h *Header) takeReusableSlot(key string) *argsKV {
	// hb := &h.hbuf
	var useKv *argsKV
	// for i := 0; i < len(hb.headers); i++ {
	// 	// Search for key-value with largest buffer for value to store value reusing buffer.
	// 	gotkv := &hb.headers[i]
	// 	if gotkv.isValidHeader() && b2s(hb.musttoken(gotkv.key)) == key {
	// 		if useKv == nil {
	// 			useKv = gotkv
	// 		} else if gotkv.value.len > useKv.value.len {
	// 			useKv.invalidate()
	// 			useKv = gotkv
	// 		} else {
	// 			gotkv.invalidate()
	// 		}
	// 	}
	// }
	return useKv
}

// Get gets the first exact-match value of a key found in the headers. Use [Header.ForEach] to find multiple values corresponding to same key.
func (h *Header) Get(key string) []byte {
	return h.hbuf.kv.Get(key)
	// debuglog("http:get:start")
	// kv := h.peekHeader(key)
	// if kv.isValidHeader() {
	// 	debuglog("http:get:found")
	// 	return h.hbuf.musttoken(kv.value)
	// }
	// debuglog("http:get:notfound")
	// return nil
}

// GetFold gets the first value whose key matches key under ASCII case-insensitive
// comparison, i.e: "content-length" matches "Content-Length".
// Use [Header.Get] for exact match and [Header.ForEach] to find multiple values
// corresponding to same key.
func (h *Header) GetFold(key string) []byte {
	nh := h.hbuf.kv.Len()
	for i := range nh {
		if asciiEqualFold(key, b2s(h.hbuf.kv.AtKey(i))) {
			return h.hbuf.kv.AtValue(i)
		}
	}
	return nil
}

// asciiEqualFold reports whether a and b are equal under ASCII case folding.
// Unlike strings.EqualFold it does not fold non-ASCII runes, so no multi-byte
// rune such as U+212A KELVIN SIGN can alias a header key.
func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	const asciiCapDiff = 'a' - 'A'
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += asciiCapDiff
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += asciiCapDiff
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// NormalizeKeys normalizes all header keys. i.e: CONTENT-type -> Content-Type
func (h *Header) NormalizeKeys() {
	for i, kv := range h.hbuf.kv.kvs {
		if kv.isValidHeader() {
			NormalizeHeaderKey(h.hbuf.kv.AtKey(i))
		}
	}
}

// ContentLength returns the body length declared by the Content-Length field.
// If the field is not present then the returned bool is false. Will return error for invalid or non-integer value.
func (h *Header) ContentLength() (_ int64, present bool, _ error) {
	value := h.GetFold(headerContentLength)
	if value == nil {
		return 0, false, nil
	}
	value = trimOWS(value)
	// Unsigned parse of 63 bits rejects a sign and anything past int64's range.
	n, err := strconv.ParseInt(b2s(value), 10, 64)
	if err != nil || n < 0 {
		return n, true, errBadContentLength // strconv's error allocates and is not comparable.
	}
	return n, true, nil
}

// Add adds a new key-value pair to the HTTP header. Calling Add mangles the buffer.
func (h *Header) Add(key, value string) {
	h.hbuf.kv.appendPair(key, value)
}

// Method returns HTTP request method.
func (h *Header) Method() []byte {
	return h.getNonEmptyValue(h.method)
}

// SetMethod sets the request header's method.
func (h *Header) SetMethod(method string) {
	h.method = h.hbuf.kv.reuseOrAppend(h.method, method)
}

// SetRequestTarget sets request-target (URI) for the first HTTP request line.
func (h *Header) SetRequestTarget(requestTarget string) {
	h.requestTarget = h.hbuf.kv.reuseOrAppend(h.requestTarget, requestTarget)
}

// RequestTarget returns a view of the request-target (URI) of the first HTTP request line.
// Called Request-URI in the obsolete RFC 2616, renamed request-target by RFC 9112.
func (h *Header) RequestTarget() []byte {
	return h.getNonEmptyValue(h.requestTarget)
}

// RequestPath returns the request-target (URI) up to the query string, i.e: "/search"
// for "/search?q=go". Returns the whole target if it contains no query string.
func (h *Header) RequestPath() []byte {
	target := h.RequestTarget()
	before, _, ok := bytes.Cut(target, []byte{'?'})
	if !ok {
		return target
	}
	return before
}

// RequestQuery returns the request-target (URI) query string as it appears on the
// wire, percent-encoded and with '+' undecoded, i.e: "q=go" for "/search?q=go".
// Returns nil if the target has no query string. Iterate it with [NextQueryPair].
func (h *Header) RequestQuery() []byte {
	target := h.RequestTarget()
	_, after, ok := bytes.Cut(target, []byte{'?'})
	if !ok {
		return nil
	}
	return after
}

// NextQueryPair splits the leading key-value pair off a query string and returns
// what remains of it. Loop until rawkey is nil:
//
//	rawkey, rawval, rest := httpraw.NextQueryPair(h.RequestQuery())
//	for rawkey != nil {
//		// use rawkey, rawval.
//		rawkey, rawval, rest = httpraw.NextQueryPair(rest)
//	}
//
// A pair with no '=' yields a nil rawval, i.e: "debug" in "?debug&q=go", which
// distinguishes it from "?debug=" where the value is present and empty. Empty
// sequences are skipped, so "?&&q=go&" yields a single pair. Only '&' separates
// pairs and only the first '=' splits a pair.
func NextQueryPair(query []byte) (rawkey, rawval, rest []byte) {
	for len(query) > 0 {
		pair := query
		amp := bytes.IndexByte(query, '&')
		if amp >= 0 {
			pair, query = query[:amp], query[amp+1:]
		} else {
			query = nil
		}
		if len(pair) == 0 {
			continue // Empty sequence, see WHATWG URL urlencoded parsing.
		}
		if before, after, ok := bytes.Cut(pair, []byte{'='}); ok {
			return before, after, query
		}
		return pair, nil, query
	}
	return nil, nil, nil
}

// Protocol returns the request header's HTTP protocol. Usually "HTTP/1.1".
func (h *Header) Protocol() []byte {
	return h.getNonEmptyValue(h.proto)
}

// SetProtocol sets the request header's protocol. Usually "HTTP/1.1".
func (h *Header) SetProtocol(protocol string) {
	h.proto = h.hbuf.kv.reuseOrAppend(h.proto, protocol)
}

// Status returns the response header's status code and status text. i.e: "200" "OK".
func (h *Header) Status() (code, statusText []byte) {
	if h.statusCode.len == 0 {
		return nil, nil
	}
	return h.hbuf.kv.musttoken(h.statusCode), h.hbuf.kv.musttoken(h.statusText)
}

// SetStatus sets the response header's status code and status text. i.e: "200" "OK".
func (h *Header) SetStatus(code, statusText string) {
	h.hbuf.kv.flags |= FlagStatusSet
	h.statusCode = h.hbuf.kv.reuseOrAppend(h.statusCode, code)
	h.statusText = h.hbuf.kv.reuseOrAppend(h.statusText, statusText)
}

// SetStatusInt is identical to [Header.SetStatus] but performs integer to text conversion for status code.
func (h *Header) SetStatusInt(code int64, statusText string) {
	h.hbuf.kv.flags |= FlagStatusSet
	h.statusCode = h.hbuf.kv.reuseOrAppendInt(h.statusCode, code, 10)
	h.statusText = h.hbuf.kv.reuseOrAppend(h.statusText, statusText)
}

func (h *Header) getNonEmptyValue(s headerSlice) []byte {
	if s.len == 0 {
		return nil // If empty then value is invalid, return nil.
	}
	return h.hbuf.kv.musttoken(s)
}

// AppendRequest appends the request header representation to the buffer and returns the result.
func (h *Header) AppendRequest(dst []byte) ([]byte, error) {
	proto := h.Protocol()
	if h.hbuf.kv.flags.HasAny(flagOOMReached) {
		return dst, ErrBufferExhausted
	} else if h.requestTarget.len == 0 || h.method.len == 0 {
		return dst, errNeedMethodURI
	} else if len(proto) == 0 {
		return dst, errNoProto
	}

	method := h.Method()
	if len(method) == 0 {
		dst = append(dst, methodGet...)
	} else {
		dst = append(dst, method...)
	}
	uri := h.RequestTarget()

	dst = append(dst, ' ')
	dst = append(dst, uri...)
	dst = append(dst, ' ')
	dst = append(dst, proto...)
	dst = append(dst, strCRLF...)

	dst = h.AppendHeaders(dst)

	return append(dst, strCRLF...), nil
}

// AppendResponse appends the response header representation to the buffer and returns the result.
func (h *Header) AppendResponse(dst []byte) ([]byte, error) {
	dst, err := h.AppendResponseNoHeaders(dst)
	if err != nil {
		return dst, err
	}
	dst = h.AppendHeaders(dst)
	return append(dst, strCRLF...), nil
}

// AppendResponseNoHeaders appends the first line of the response containing protocol and status code/text: i.e: "HTTP/1.1 200 OK\r\n"
func (h *Header) AppendResponseNoHeaders(dst []byte) ([]byte, error) {
	proto := h.Protocol()
	if h.hbuf.kv.flags.HasAny(flagOOMReached) {
		return dst, ErrBufferExhausted
	} else if h.statusCode.len == 0 || h.statusText.len == 0 {
		return dst, errBadStatusCodeTxt
	} else if len(proto) == 0 {
		return dst, errNoProto
	}
	code, text := h.Status()

	dst = append(dst, proto...)
	dst = append(dst, ' ')
	dst = append(dst, code...)
	dst = append(dst, ' ')
	dst = append(dst, text...)
	dst = append(dst, strCRLF...)
	return dst, nil
}

// AppendHeaders appends headers to buffer. Use AppendRequest and AppendResponse over this.
// Does not append extra \r\n to end. Appends nothing if contains no headers.
func (h *Header) AppendHeaders(dst []byte) []byte {
	for i, kv := range h.hbuf.kv.kvs {
		if kv.isValidHeader() {
			k, v := h.hbuf.kv.At(i)
			dst = appendHeaderLine(dst, b2s(k), b2s(v))
		}
	}
	return dst
}

// String returns the header's wire representation, as a request if it has a
// request line and as a response otherwise. Returns the error text if neither
// can be built. Allocates, so it is meant for debugging and logging only.
func (h *Header) String() string {
	buf, err := h.AppendRequest(nil)
	if err != nil {
		buf, err = h.AppendResponse(nil)
		if err != nil {
			return err.Error()
		}
	}
	return b2s(buf)
}

func appendHeaderLine(dst []byte, key, value string) []byte {
	dst = append(dst, key...)
	dst = append(dst, ':', ' ')
	dst = append(dst, value...)
	return append(dst, strCRLF...)
}

// Embed this type into a struct, which mustn't be copied,
// so `go vet` gives a warning if this struct is copied.
//
// See https://github.com/golang/go/issues/8005#issuecomment-190753527 for details.
// and also: https://stackoverflow.com/questions/52494458/nocopy-minimal-example
type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

// NormalizeKey normalizes a HTTP header key in-place. Returns true if buffer modified.
// Examples of normalization:
//   - CONTENT -> Content
//   - content-length -> Content-Length
//   - cOnTeNt-LenGtH -> Content-Length
func NormalizeHeaderKey(b []byte) (modified bool) {
	if len(b) == 0 {
		return false
	}
	const asciiCapDiff = 'a' - 'A'
	for i := -1; i < len(b); i++ {
		nextToUpper := i == -1 || (b[i] == '-' && i < len(b)-1)
		if nextToUpper {
			i++
			isLower := b[i] >= 'a' && b[i] <= 'z'
			if isLower {
				modified = true
				b[i] -= asciiCapDiff
			}
		} else {
			isUpper := b[i] >= 'A' && b[i] <= 'Z'
			if isUpper {
				modified = true
				b[i] += asciiCapDiff
			}
		}
	}
	return modified
}

// CopyNormalizedHeaderValue copies the header value in the value buffer to dst.
// The result may be shrunk. The target and source buffers can only alias if the
// destination buffer 0 address is equal to value's 0 address.
// Header value normalization implies the replacement of \r\n\t with a single space.
func CopyNormalizedHeaderValue(dst []byte, value []byte) (n int, modified bool) {
	if len(dst) < len(value) {
		panic("httpraw.CopyNormalizedHeaderValue: dst buffer shorter than length")
	}
	write := 0
	read := 0
	for {
		rmStart := bytes.IndexByte(value[read:], '\n')
		if rmStart < 0 {
			write += copy(dst[write:], value[read:])
			break
		}
		omit := 1
		rmStart += read
		if rmStart+1 < len(value) && value[rmStart+1] == '\t' {
			omit++
		}
		if rmStart > 0 && value[rmStart-1] == '\r' {
			rmStart--
			omit++
		}
		modified = true
		n := copy(dst[write:], value[read:rmStart])
		dst[write+n] = ' '
		read += omit + n
		write += n + 1
	}
	return write, modified
}

// CopyDecodedPercentURL decodes percent-escapes in value into dst and returns bytes written.
// n < len(value) implies percent-escapes were decoded; the converse does not hold since
// '+' substitution preserves length. If plusAsSpace is set '+' decodes to ' ',
// which is correct for query and form-encoded data but NOT for path segments.
// On malformed escape returns n bytes written before the fault and a non-nil error.
// dst and value may only alias if &dst[0] == &value[0].
func CopyDecodedPercentURL(dst, value []byte, plusAsSpace bool) (n int, err error) {
	if len(dst) < len(value) {
		panic("httpraw.CopyDecodedPercentURL: dst buffer shorter than value")
	}
	read := 0
	for {
		escape := bytes.IndexByte(value[read:], '%')
		if escape < 0 {
			n += copyPlusDecoded(dst[n:], value[read:], plusAsSpace)
			return n, nil
		}
		escape += read
		n += copyPlusDecoded(dst[n:], value[read:escape], plusAsSpace)
		if escape+2 >= len(value) {
			return n, errBadPercentEncode // Truncated escape at end of value.
		}
		hi, okhi := unhexdigit(value[escape+1])
		lo, oklo := unhexdigit(value[escape+2])
		if !okhi || !oklo {
			return n, errBadPercentEncode
		}
		// Write index n is always <= escape since decoding shrinks 3 bytes to 1,
		// so writing here never clobbers an unread byte when dst aliases value.
		dst[n] = hi<<4 | lo
		n++
		read = escape + 3
	}
}

// copyPlusDecoded copies src to dst replacing '+' with ' ' if plusAsSpace set.
func copyPlusDecoded(dst, src []byte, plusAsSpace bool) int {
	n := copy(dst, src)
	if plusAsSpace {
		for i := range n {
			if dst[i] == '+' {
				dst[i] = ' '
			}
		}
	}
	return n
}

func unhexdigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

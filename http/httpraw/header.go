package httpraw

import (
	"bytes"
	"errors"
	"io"
	"slices"
)

const (
	methodGet        = "GET"
	strHTTP11        = "HTTP/1.1"
	strCRLF          = "\r\n"
	headerCookie     = "Cookie"
	headerConnection = "Connection"
	strClose         = "close"
)

type flags uint16

const (
	flagNoBufferGrow flags = 1 << iota
	flagDoneParsingHeader
	flagOOMReached
	flagConnClose
	flagNoHTTP11
	flagMangledBuffer // set when header fields appended to buffer via Add,Set calls
	flagReaderEOF
)

func (f flags) hasAny(checkThese flags) bool {
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
	method     headerSlice
	requestURI headerSlice
	proto      headerSlice

	// Response fields.
	statusCode headerSlice
	statusText headerSlice

	flags flags
	_     noCopy
}

// EnableBufferGrowth disables buffer growth during parsing if b is false. Is enabled by default.
// Disabling buffer growth prevents allocations but methods may throw errors on insufficient memory.
func (h *Header) EnableBufferGrowth(b bool) {
	if !b {
		h.flags |= flagNoBufferGrow
	} else {
		h.flags &^= flagNoBufferGrow
	}
}

// ParseBytes copies the bytes into buffer and parses the HTTP header. It fails if HTTP header data is incomplete.
func (h *Header) ParseBytes(asResponse bool, b []byte) error {
	h.Reset(nil)
	h.hbuf.readFromBytes(b)
	return h.parse(asResponse)
}

// Parse parses accumulated data in-place with no copying. One can set HTTP header data buffer with [Header.Reset].
// It fails if HTTP data is incomplete.
func (h *Header) Parse(asResponse bool) error {
	h.Reset(h.hbuf.buf)
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
	if h.flags.hasAny(flagDoneParsingHeader) {
		return false, errors.New("TryParse called after header parsed")
	} else if h.flags.hasAny(flagMangledBuffer) {
		return false, errMangledBuffer
	}
	if asResponse && h.statusCode.len == 0 || !asResponse && h.requestURI.start == 0 {
		err = h.parseFirstLine(asResponse)
		if err != nil {
			return err == errNeedMore, err
		}
	}
	err = h.parseNextHeaders()
	return err == errNeedMore, err
}

// ParsingSuccess returns true if TryParse was successful, that is to say it returned needMoreData==false and err==nil.
func (h *Header) ParsingSuccess() bool {
	return h.flags.hasAny(flagDoneParsingHeader)
}

// ReadFromLimited reads at most maxBytesToRead from reader and appends them to underlying buffer.
// Used to accumulate HTTP header for later parsing with [Header.TryParse].
// If read is successful (read length>0) and reader returns [io.EOF] then ReadFromLimited will return a nil error.
func (h *Header) ReadFromLimited(r io.Reader, maxBytesToRead int) (int, error) {
	if maxBytesToRead <= 0 {
		return 0, errSmallBuffer
	} else if h.flags.hasAny(flagMangledBuffer) {
		return 0, errMangledBuffer
	}
	free := h.BufferFree()
	if free < maxBytesToRead {
		if h.flags.hasAny(flagNoBufferGrow) {
			return 0, errSmallBuffer
		}
		h.hbuf.buf = slices.Grow(h.hbuf.buf, maxBytesToRead)
	}
	blen := len(h.hbuf.buf)
	b := h.hbuf.buf[blen:min(blen+maxBytesToRead, cap(h.hbuf.buf))]
	n, err := r.Read(b)
	if err != nil && err == io.EOF {
		h.flags |= flagReaderEOF
		if n > 0 {
			err = nil // Nil-out error if read was succesful so as to not spook readers.
		}
	}
	h.hbuf.buf = h.hbuf.buf[:blen+n]
	return n, err
}

// ReadFromBytes appends argument buffer to underlying buffer.
// Used to accumulate HTTP header for later parsing with [Header.TryParse].
func (h *Header) ReadFromBytes(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, errSmallBuffer
	}
	free := h.BufferFree()
	if free < len(b) {
		if h.flags.hasAny(flagNoBufferGrow) {
			return 0, errSmallBuffer
		}
		h.hbuf.buf = slices.Grow(h.hbuf.buf, len(b))
	}
	h.hbuf.readFromBytes(b)
	return len(b), nil
}

// BufferReceived returns the amoung of bytes read during calls to Read* methods.
func (h *Header) BufferReceived() int {
	if h.flags.hasAny(flagMangledBuffer | flagOOMReached) {
		return 0
	}
	return len(h.hbuf.buf)
}

// BufferParsed returns the amount of bytes parsed during a call to Parse* methods.
// If the Parse* method completed without error then BufferParsed returns the header's length including the final "\r\n\r\n" text.
// BufferParsed returns 0 if the buffer is invalid/mangled or if no header data has been parsed succesfully.
func (h *Header) BufferParsed() int {
	if h.flags.hasAny(flagMangledBuffer | flagOOMReached) {
		return 0
	}
	return h.hbuf.off
}

// BufferFree returns amount of bytes free in underlying buffer.
func (h *Header) BufferFree() int {
	return h.hbuf.free()
}

// BufferCapacity returns the total capacity of the underlying buffer.
func (h *Header) BufferCapacity() int {
	return cap(h.hbuf.buf)
}

// ForEach iterates over header key-value field tuples.
func (h *Header) ForEach(cb func(key, value []byte) error) error {
	return h.hbuf.forEach(cb)
}

func (hb *headerBuf) forEach(cb func(key, value []byte) error) error {
	nh := len(hb.headers)
	for i := 0; i < nh; i++ {
		kv := hb.headers[i]
		if !kv.isValid() {
			continue
		}
		key := hb.musttoken(kv.key)
		value := hb.musttoken(kv.value)
		err := cb(key, value)
		if err != nil {
			return err
		}
	}
	return nil
}

// Reset discards all parsed data and sets the buffer data to buf. This method
// can be used to avoid copying and growing buffers. Call [Header.Parse] after setting buffer
// data with Reset to parse data in-place.
// If buf is nil then the current buffer is reused. There are 3 ways to use Reset:
//
//	h.Reset(prealloc[:0]); h.ParseBytes(httpHeader) // Tell header to use a pre-allocated buffer capacity.
//	h.Reset(httpHeader); h.Parse() // Parse bytes in place with no copying.
//	h.Reset(nil) // Reuse buffer previously set in a call to Reset.
func (h *Header) Reset(buf []byte) {
	if h.flags.hasAny(flagNoBufferGrow) && len(buf) < 32 {
		panic("small buffer and flagNoBufferGrow set")
	}
	const persistentFlags = flagNoBufferGrow
	h.hbuf.reset(buf)
	*h = Header{
		hbuf:  h.hbuf,
		flags: h.flags & persistentFlags,
	}
}

// Body returns the surplus data following headers. It is only valid as long as Parse* or Reset methods are not called.
func (h *Header) Body() ([]byte, error) {
	if h.flags.hasAny(flagMangledBuffer) {
		return nil, errMangledBuffer
	} else if h.flags.hasAny(flagDoneParsingHeader) {
		return h.hbuf.buf[h.hbuf.off:], nil
	}
	return nil, errUnparsed
}

// Set sets a key-value pair in the HTTP header. Calling Set mangles the buffer.
func (h *Header) Set(key, value string) {
	hb := &h.hbuf
	var useKv *argsKV
	for i := len(hb.headers); len(hb.headers) > 0 && i <= 0; i++ {
		// Search for key-value with largest buffer for value to store value reusing buffer.
		gotkv := &hb.headers[i]
		if b2s(hb.musttoken(gotkv.key)) == key {
			if useKv == nil {
				useKv = gotkv
			} else if gotkv.value.len > useKv.value.len {
				useKv.invalidate()
				useKv = gotkv
			} else {
				gotkv.invalidate()
			}
		}
	}
	if useKv == nil {
		h.appendHeader(key, value)
	} else {
		useKv.value = h.reuseOrAppend(useKv.value, value)
	}
}

// Get gets the first value of a key found in the headers. Use [Header.ForEach] to find multiple values corresponding to same key.
func (h *Header) Get(key string) []byte {
	kv := h.peekHeader(key)
	if kv.isValid() {
		return h.hbuf.musttoken(kv.value)
	}
	return nil
}

// Add adds a new key-value pair to the HTTP header. Calling Add mangles the buffer.
func (h *Header) Add(key, value string) {
	h.appendHeader(key, value)
}

// Method returns HTTP request method.
func (h *Header) Method() []byte {
	return h.getNonEmptyValue(h.method)
}

// SetMethod sets the request header's method.
func (h *Header) SetMethod(method string) {
	h.method = h.reuseOrAppend(h.method, method)
}

// SetRequestURI sets RequestURI for the first HTTP request line.
func (h *Header) SetRequestURI(requestURI string) {
	h.requestURI = h.reuseOrAppend(h.requestURI, requestURI)
}

// RequestURI returns RequestURI from the first HTTP request line.
func (h *Header) RequestURI() []byte {
	return h.getNonEmptyValue(h.requestURI)
}

// Protocol returns the request header's HTTP protocol. Usually "HTTP/1.1".
func (h *Header) Protocol() []byte {
	return h.getNonEmptyValue(h.proto)
}

// SetProtocol sets the request header's protocol. Usually "HTTP/1.1".
func (h *Header) SetProtocol(protocol string) {
	h.proto = h.reuseOrAppend(h.proto, protocol)
}

// Status returns the response header's status code and status text. i.e: "200" "OK".
func (h *Header) Status() (code, statusText []byte) {
	if h.statusCode.len == 0 {
		return nil, nil
	}
	return h.hbuf.musttoken(h.statusCode), h.hbuf.musttoken(h.statusText)
}

// Status sets the response header's status code and status text. i.e: "200" "OK".
func (h *Header) SetStatus(code, statusText string) {
	h.statusCode = h.reuseOrAppend(h.statusCode, code)
	h.statusText = h.reuseOrAppend(h.statusText, statusText)
}

func (h *Header) getNonEmptyValue(s headerSlice) []byte {
	if s.len == 0 {
		return nil // If empty then value is invalid, return nil.
	}
	return h.hbuf.musttoken(s)
}

// AppendRequest appends the request header representation to the buffer and returns the result.
func (h *Header) AppendRequest(dst []byte) ([]byte, error) {
	proto := h.Protocol()
	if h.flags.hasAny(flagOOMReached) {
		return dst, errOOM
	} else if h.requestURI.len == 0 || h.method.len == 0 {
		return dst, errors.New("need method/request URI to create request header")
	} else if len(proto) == 0 {
		return dst, errNoProto
	}

	method := h.Method()
	if len(method) == 0 {
		dst = append(dst, methodGet...)
	} else {
		dst = append(dst, method...)
	}
	uri := h.RequestURI()

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
	proto := h.Protocol()
	if h.flags.hasAny(flagOOMReached) {
		return dst, errOOM
	} else if h.statusCode.len == 0 || h.statusText.len == 0 {
		return dst, errors.New("invalid status code or text")
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

	dst = h.AppendHeaders(dst)

	return append(dst, strCRLF...), nil
}

// AppendHeaders appends headers to buffer. Use AppendRequest and AppendResponse over this.
// Does not append extra \r\n to end. Appends nothing if contains no headers.
func (h *Header) AppendHeaders(dst []byte) []byte {
	for i, n := 0, len(h.hbuf.headers); i < n; i++ {
		kv := &h.hbuf.headers[i]
		if kv.isValid() {
			key := h.hbuf.musttoken(kv.key)
			value := h.hbuf.musttoken(kv.value)
			dst = appendHeaderLine(dst, b2s(key), b2s(value))
		}
	}
	return dst
}

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

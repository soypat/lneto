package httpx

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"unsafe"

	"github.com/soypat/lneto/internal"
)

type headerBuf struct {
	buf []byte
	off int // offset into buf for parsing.
	// args contains key-value store.
	args []argsKV
}

type tokint = uint16

type headerSlice struct {
	start tokint
	len   tokint
}

type argSlice struct {
	start tokint
	len   tokint
}

type argsKV struct {
	key   headerSlice
	value headerSlice // value start >0 means value is present.
}

func (tb headerBuf) musttoken(slice headerSlice) []byte {
	return tb.buf[slice.start : slice.start+slice.len]
}
func (tb headerBuf) mustargs(slice argSlice) []argsKV {
	return tb.args[slice.start : slice.start+slice.len]
}

func (tb headerBuf) visitArgs(args argSlice, f func(k, v []byte)) {
	a := tb.mustargs(args)
	for _, arg := range a {
		k := tb.musttoken(arg.key)
		v := tb.musttoken(arg.value)
		f(k, v)
	}
}

func (tb headerBuf) visitArgsKey(args argSlice, f func(k []byte)) {
	a := tb.mustargs(args)
	for _, arg := range a {
		f(tb.musttoken(arg.key))
	}
}

func (tb headerBuf) slice(b []byte) headerSlice {
	base := uintptr(unsafe.Pointer(&tb.buf[0]))
	off := uintptr(unsafe.Pointer(&b[0]))
	if off < base || off > base+uintptr(len(tb.buf)) {
		panic("httpx: argument buffer does not alias header buffer")
	}
	return headerSlice{
		start: tokint(off - base),
		len:   tokint(len(b)),
	}
}

func (kv argsKV) HasValue() bool { return kv.value.start > 0 }

type flags uint8

const (
	disableNormalizing flags = 1 << iota
	disableSpecialHeader
	noDefaultContentType
	connectionClose
	noHTTP11
	cookiesCollected
)

func (f flags) hasAll(checkThese flags) bool {
	return f&checkThese == checkThese
}

type header struct {
	buf           headerBuf
	contentLength int
	h             argSlice
	cookies       argSlice
	trailer       argSlice

	host               headerSlice
	contentLengthBytes headerSlice
	contentType        headerSlice
	userAgent          headerSlice
	method             headerSlice
	proto              headerSlice
	requestURI         headerSlice
	rawHeaders         headerSlice
	mulHeader          headerSlice

	flags  flags
	logger *slog.Logger
}

func (h *header) Set(key, value string) {
	h.bufKV.key = append(h.bufKV.key[:0], key...)
	normalizeHeaderKey(h.bufKV.key, h.disableNormalizing)
	h.SetCanonical(b2s(h.bufKV.key), value)
}

func (h *header) Add(key, value string) {
	if h.setSpecialHeader(key, value) {
		return
	}
	k := getHeaderKeyBytes(&h.bufKV, key, h.disableNormalizing)
	h.h = appendArg(h.h, b2s(k), value, argsHasValue)
}

// ContentEncoding returns Content-Encoding header value.
func (h *header) ContentEncoding() []byte {
	return peekArg(h.h, strContentEncoding)
}

// SetContentEncoding sets Content-Encoding header value.
func (h *header) SetContentEncoding(contentEncoding string) {
	h.Set(strContentEncoding, contentEncoding)
}

// SetContentType sets Content-Type header value.
func (h *header) SetContentType(contentType string) {
	h.contentType = append(h.contentType[:0], contentType...)
}

// ContentType returns Content-Type header value.
func (h *header) ContentType() []byte {
	contentType := h.contentType
	if !h.noDefaultContentType && len(h.contentType) == 0 {
		contentType = append(contentType, defaultContentType...)
	}
	return contentType
}

// SetCanonical sets the given 'key: value' header assuming that
// key is in canonical form.
//
// If the header is set as a Trailer (forbidden trailers will not be set, see SetTrailer for more details),
// it will be sent after the chunked request body.
func (h *header) SetCanonical(key, value string) {
	if h.setSpecialHeader(key, value) {
		return
	}
	h.setNonSpecial(key, value)
}

// setSpecialHeader handles special headers and return true when a header is processed.
func (h *header) setSpecialHeader(key, value string) bool {
	if len(key) == 0 || h.disableSpecialHeader {
		return false
	}
	h.trace("setSpecialHeader", slog.String("key", key), slog.String("value", value))
	switch key[0] | 0x20 {
	case 'c':
		switch {
		case caseInsensitiveCompare(strContentType, key):
			h.SetContentType(value)
			return true
		case caseInsensitiveCompare(strContentLength, key):
			if contentLength, err := parseContentLength(value); err == nil {
				h.contentLength = contentLength
				h.contentLengthBytes = append(h.contentLengthBytes[:0], value...)
			}
			return true
		case caseInsensitiveCompare(strConnection, key):
			if strClose == value {
				h.SetConnectionClose()
			} else {
				h.ResetConnectionClose()
				h.setNonSpecial(key, value)
			}
			return true
		case caseInsensitiveCompare(strCookie, key):
			h.collectCookies()
			h.cookies = parseRequestCookies(h.cookies, value)
			return true
		}
	case 't': // OK
		if caseInsensitiveCompare(strTransferEncoding, key) {
			// Transfer-Encoding is managed automatically.
			return true
		} else if caseInsensitiveCompare(strTrailer, key) {
			_ = h.SetTrailer(value)
			return true
		}
	case 'h':
		if caseInsensitiveCompare(strHost, key) {
			h.SetHost(value)
			return true
		}
	case 'u':
		if caseInsensitiveCompare(strUserAgent, key) {
			h.SetUserAgent(value)
			return true
		}
	}

	return false
}

// SetHost sets Host header value.
func (h *header) SetHost(host string) {
	h.host = append(h.host[:0], host...)
}

// SetUserAgent sets User-Agent header value.
func (h *header) SetUserAgent(userAgent string) {
	h.userAgent = append(h.userAgent[:0], userAgent...)
}

// SetConnectionClose sets 'Connection: close' header.
func (h *header) SetConnectionClose() {
	h.connectionClose = true
}

// ResetConnectionClose clears 'Connection: close' header if it exists.
func (h *header) ResetConnectionClose() {
	if h.connectionClose {
		h.connectionClose = false
		h.h = delAllArgs(h.h, strConnection)
	}
}

func (h *header) SetContentRange(startPos, endPos, contentLength int) {
	b := h.bufKV.value[:0]
	b = append(b, strBytes...)
	b = append(b, ' ')
	b = appendUint(b, startPos)
	b = append(b, '-')
	b = appendUint(b, endPos)
	b = append(b, '/')
	b = appendUint(b, contentLength)
	h.bufKV.value = b

	h.setNonSpecial(strContentRange, b2s(h.bufKV.value))
}

// setNonSpecial directly put into map i.e. not a basic header.
func (h *header) setNonSpecial(key string, value string) {
	h.trace("httpx:setNonSpecial", slog.String("key", key), slog.String("value", value))
	h.h = setArg(h.h, key, value, argsHasValue)
}

func appendUint(b []byte, v int) []byte {
	if v < 0 {
		panic("negative uint")
	}
	return strconv.AppendUint(b, uint64(v), 10)
}

// ContentLength returns Content-Length header value.
//
// It may be negative:
// -1 means Transfer-Encoding: chunked.
// -2 means Transfer-Encoding: identity.
func (h *header) ContentLength() int {
	return h.contentLength
}

// SetContentLength sets Content-Length header value.
//
// Content-Length may be negative:
// -1 means Transfer-Encoding: chunked.
// -2 means Transfer-Encoding: identity.
func (h *header) SetContentLength(contentLength int) {
	h.contentLength = contentLength
	if contentLength >= 0 {
		h.contentLengthBytes = appendUint(h.contentLengthBytes[:0], contentLength)
		h.h = delAllArgs(h.h, strTransferEncoding)
	} else {
		h.contentLengthBytes = h.contentLengthBytes[:0]
		h.h = setArg(h.h, strTransferEncoding, strChunked, argsHasValue)
	}
}

var ErrBadTrailer = errors.New("contain forbidden trailer")

// SetTrailer sets Trailer header value for chunked request
// to indicate which headers will be sent after the body.
//
// Use Set to set the trailer header later.
//
// Trailers are only supported with chunked transfer.
// Trailers allow the sender to include additional headers at the end of chunked messages.
//
// The following trailers are forbidden:
// 1. necessary for message framing (e.g., Transfer-Encoding and Content-Length),
// 2. routing (e.g., Host),
// 3. request modifiers (e.g., controls and conditionals in Section 5 of [RFC7231]),
// 4. authentication (e.g., see [RFC7235] and [RFC6265]),
// 5. response control data (e.g., see Section 7.1 of [RFC7231]),
// 6. determining how to process the payload (e.g., Content-Encoding, Content-Type, Content-Range, and Trailer)
//
// Return ErrBadTrailer if contain any forbidden trailers.
func (h *header) SetTrailer(trailer string) error {
	h.trailer = h.trailer[:0]
	return h.AddTrailer(trailer)
}

// AddTrailerBytes add Trailer header value for chunked response
// to indicate which headers will be sent after the body.
//
// Use Set to set the trailer header later.
//
// Trailers are only supported with chunked transfer.
// Trailers allow the sender to include additional headers at the end of chunked messages.
//
// The following trailers are forbidden:
// 1. necessary for message framing (e.g., Transfer-Encoding and Content-Length),
// 2. routing (e.g., Host),
// 3. request modifiers (e.g., controls and conditionals in Section 5 of [RFC7231]),
// 4. authentication (e.g., see [RFC7235] and [RFC6265]),
// 5. response control data (e.g., see Section 7.1 of [RFC7231]),
// 6. determining how to process the payload (e.g., Content-Encoding, Content-Type, Content-Range, and Trailer)
//
// Return ErrBadTrailer if contain any forbidden trailers.
func (h *header) AddTrailer(trailer string) error {
	h.trace("httpx:AddTrailer", slog.String("trailer", trailer))
	var err error
	for i := -1; i+1 < len(trailer); {
		trailer = trailer[i+1:]
		i = strings.IndexByte(trailer, ',')
		if i < 0 {
			i = len(trailer)
		}
		key := stripSpace(trailer[:i])
		// Forbidden by RFC 7230, section 4.1.2
		if isBadTrailer(key) {
			err = ErrBadTrailer
			continue
		}
		h.bufKV.key = append(h.bufKV.key[:0], key...)
		normalizeHeaderKey(h.bufKV.key, h.disableNormalizing)
		h.trailer = appendArg(h.trailer, b2s(h.bufKV.key), "", argsNoValue)
	}

	return err
}

func isBadTrailer(key string) bool {
	if len(key) == 0 {
		return true
	}

	switch key[0] | 0x20 {
	case 'a':
		return caseInsensitiveCompare(key, strAuthorization)
	case 'c':
		if len(key) > len(HeaderContentType) && caseInsensitiveCompare(key[:8], strContentType[:8]) {
			// skip compare prefix 'Content-'
			return caseInsensitiveCompare(key[8:], strContentEncoding[8:]) ||
				caseInsensitiveCompare(key[8:], strContentLength[8:]) ||
				caseInsensitiveCompare(key[8:], strContentType[8:]) ||
				caseInsensitiveCompare(key[8:], strContentRange[8:])
		}
		return caseInsensitiveCompare(key, strConnection)
	case 'e':
		return caseInsensitiveCompare(key, strExpect)
	case 'h':
		return caseInsensitiveCompare(key, strHost)
	case 'k':
		return caseInsensitiveCompare(key, strKeepAlive)
	case 'm':
		return caseInsensitiveCompare(key, strMaxForwards)
	case 'p':
		if len(key) > len(HeaderProxyConnection) && caseInsensitiveCompare(key[:6], strProxyConnection[:6]) {
			// skip compare prefix 'Proxy-'
			return caseInsensitiveCompare(key[6:], strProxyConnection[6:]) ||
				caseInsensitiveCompare(key[6:], strProxyAuthenticate[6:]) ||
				caseInsensitiveCompare(key[6:], strProxyAuthorization[6:])
		}
	case 'r':
		return caseInsensitiveCompare(key, strRange)
	case 't':
		return caseInsensitiveCompare(key, strTE) ||
			caseInsensitiveCompare(key, strTrailer) ||
			caseInsensitiveCompare(key, strTransferEncoding)
	case 'w':
		return caseInsensitiveCompare(key, strWWWAuthenticate)
	}
	return false
}

// RawHeaders returns raw header key/value bytes.
//
// Depending on server configuration, header keys may be normalized to
// capital-case in place.
//
// This copy is set aside during parsing, so empty slice is returned for all
// cases where parsing did not happen. Similarly, request line is not stored
// during parsing and can not be returned.
//
// The slice is not safe to use after the handler returns.
func (h *header) RawHeaders() []byte {
	return h.rawHeaders
}

// DisableNormalizing disables header names' normalization.
//
// By default all the header names are normalized by uppercasing
// the first letter and all the first letters following dashes,
// while lowercasing all the other letters.
// Examples:
//
//   - CONNECTION -> Connection
//   - conteNT-tYPE -> Content-Type
//   - foo-bar-baz -> Foo-Bar-Baz
//
// Disable header names' normalization only if know what are you doing.
func (h *header) DisableNormalizing() {
	h.disableNormalizing = true
}

// DisableSpecialHeader disables special header processing.
// fasthttp will not set any special headers for you, such as Host, Content-Type, User-Agent, etc.
// You must set everything yourself.
// If RequestHeader.Read() is called, special headers will be ignored.
// This can be used to control case and order of special headers.
// This is generally not recommended.
func (h *header) DisableSpecialHeader() {
	h.disableSpecialHeader = true
}

// Method returns HTTP request method.
func (h *header) Method() []byte {
	if len(h.method) == 0 {
		h.method = append(h.method, http.MethodGet...)
	}
	return h.method
}

func (h *header) SetMethod(method string) {
	h.method = append(h.method[:0], method...)
}

// SetRequestURI sets RequestURI for the first HTTP request line.
func (h *header) SetRequestURI(requestURI string) {
	h.requestURI = append(h.requestURI[:0], requestURI...)
}

// RequestURI returns RequestURI from the first HTTP request line.
func (h *header) RequestURI() []byte {
	requestURI := h.requestURI
	if len(requestURI) == 0 {
		requestURI = append(requestURI, '/')
	}
	return requestURI
}

// Protocol returns HTTP protocol.
func (h *header) Protocol() []byte {
	if len(h.proto) == 0 {
		h.proto = append(h.proto, strHTTP11...)
	}
	return h.proto
}

func (h *header) SetProtocol(protocol string) {
	h.proto = append(h.proto[:0], protocol...)
}

// AppendReqRespCommon appends request/response common header representation to dst and returns the extended buffer.
func (h *header) AppendReqRespCommon(dst []byte) []byte {
	for i, n := 0, len(h.h); i < n; i++ {
		kv := &h.h[i]
		// Exclude trailer from header
		exclude := false
		for _, t := range h.trailer {
			if b2s(kv.key) == b2s(t.key) {
				exclude = true
				break
			}
		}
		if !exclude {
			dst = appendHeaderLine(dst, b2s(kv.key), b2s(kv.value))
		}
	}

	if len(h.trailer) > 0 {
		aux := appendArgsKey(nil, h.trailer, strCommaSpace)
		dst = appendHeaderLine(dst, strTrailer, b2s(aux))
	}

	// there is no need in h.collectCookies() here, since if cookies aren't collected yet,
	// they all are located in h.h.
	n := len(h.cookies)
	if n > 0 && !h.disableSpecialHeader {
		dst = append(dst, strCookie...)
		dst = append(dst, strColonSpace...)
		dst = appendRequestCookieBytes(dst, h.cookies)
		dst = append(dst, strCRLF...)
	}

	if h.ConnectionClose() && !h.disableSpecialHeader {
		dst = appendHeaderLine(dst, strConnection, strClose)
	}

	return append(dst, strCRLF...)
}

func appendHeaderLine(dst []byte, key, value string) []byte {
	dst = append(dst, key...)
	dst = append(dst, strColonSpace...)
	dst = append(dst, value...)
	return append(dst, strCRLF...)
}

func (h *header) ignoreBody() bool {
	return h.IsGet() || h.IsHead()
}

func (h *header) collectCookies() {
	if h.cookiesCollected {
		return
	}

	for i, n := 0, len(h.h); i < n; i++ {
		kv := &h.h[i]
		if caseInsensitiveCompare(b2s(kv.key), strCookie) {
			h.cookies = parseRequestCookies(h.cookies, b2s(kv.value))
			tmp := *kv
			copy(h.h[i:], h.h[i+1:])
			n--
			i--
			h.h[n] = tmp
			h.h = h.h[:n]
		}
	}
	h.cookiesCollected = true
}

func (h *header) MethodIs(method string) bool {
	return b2s(h.method) == method
}

// IsGet returns true if request method is GET.
func (h *header) IsGet() bool { return len(h.method) == 0 || h.MethodIs(http.MethodGet) }

// IsHead returns true if request method is HEAD.
func (h *header) IsHead() bool { return h.MethodIs(http.MethodHead) }

// IsPost returns true if request method is POST.
func (h *header) IsPost() bool { return h.MethodIs(http.MethodPost) }

// IsPut returns true if request method is PUT.
func (h *header) IsPut() bool { return h.MethodIs(http.MethodPut) }

// IsDelete returns true if request method is DELETE.
func (h *header) IsDelete() bool { return h.MethodIs(http.MethodDelete) }

// IsConnect returns true if request method is CONNECT.
func (h *header) IsConnect() bool { return h.MethodIs(http.MethodConnect) }

// IsOptions returns true if request method is OPTIONS.
func (h *header) IsOptions() bool { return h.MethodIs(http.MethodOptions) }

// IsTrace returns true if request method is TRACE.
func (h *header) IsTrace() bool { return h.MethodIs(http.MethodTrace) }

// IsPatch returns true if request method is PATCH.
func (h *header) IsPatch() bool { return h.MethodIs(http.MethodPatch) }

// IsHTTP11 returns true if the request is HTTP/1.1.
func (h *header) IsHTTP11() bool { return !h.noHTTP11 }

// Embed this type into a struct, which mustn't be copied,
// so `go vet` gives a warning if this struct is copied.
//
// See https://github.com/golang/go/issues/8005#issuecomment-190753527 for details.
// and also: https://stackoverflow.com/questions/52494458/nocopy-minimal-example
type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

func (h *header) trace(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(h.logger, internal.LevelTrace, msg, attrs...)
}
func (h *header) debug(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(h.logger, slog.LevelDebug, msg, attrs...)
}
func (h *header) info(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(h.logger, slog.LevelInfo, msg, attrs...)
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

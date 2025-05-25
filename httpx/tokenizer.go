package httpx

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"unsafe"

	"github.com/soypat/lneto/internal"
)

type headerBuf struct {
	// buf[:len] holds entire HTTP header data, which may be normalized by [flags]. buf[off:len] holds data not yet processed during parsing.
	buf []byte
	// offset into buf for parsing.
	off int
	// args contains key-value store.
	headers []argsKV
	cookies []argsKV
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

func (kv argsKV) isValid() bool {
	return kv.key.start > 0
}

func (kv *argsKV) invalidate() {
	*kv = argsKV{}
}

func (tb headerBuf) musttoken(slice headerSlice) []byte {
	return tb.buf[slice.start : slice.start+slice.len]
}

func (tb headerBuf) slice(b []byte) headerSlice {
	base := uintptr(unsafe.Pointer(unsafe.SliceData(tb.buf)))
	off := uintptr(unsafe.Pointer(unsafe.SliceData(b)))
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
	flagNoBufferGrow
	flagOOMReached
)

func (f flags) hasAny(checkThese flags) bool {
	return f&checkThese != 0
}

type header struct {
	hbuf          headerBuf
	logger        *slog.Logger
	contentLength int

	method     headerSlice
	requestURI headerSlice
	proto      headerSlice

	flags flags
}

func (h *header) ParseBytes(b []byte) error {
	h.resetSkipNormalize()
	h.hbuf.readFromBytes(b)
	return h.parse()
}

func (h *header) Set(key, value string) {
	h.SetCanonical(key, value) //TODO: implement non-canonical.
}

func (h *header) Add(key, value string) {
	h.appendHeader(key, value)
}

// ContentType returns Content-Type header value.
func (h *header) ContentType() []byte {
	return h.peekHeaderBytes(HeaderContentType)
}

// SetCanonical sets the given 'key: value' header assuming that
// key is in canonical form.
//
// If the header is set as a Trailer (forbidden trailers will not be set, see SetTrailer for more details),
// it will be sent after the chunked request body.
func (h *header) SetCanonical(key, value string) {
	kv := h.peekPtrHeader(key)
	if kv != nil {
		kv.invalidate()
	}
	h.appendHeader(key, value)
}

// SetHost sets Host header value.
func (h *header) SetHost(host string) {
	h.Set(HeaderHost, host)
}

// SetUserAgent sets User-Agent header value.
func (h *header) SetUserAgent(userAgent string) {
	h.Set(HeaderUserAgent, userAgent)
}

// SetConnectionClose sets 'Connection: close' header.
func (h *header) SetConnectionClose() {
	h.flags |= connectionClose
}

// ResetConnectionClose clears 'Connection: close' header if it exists.
func (h *header) ResetConnectionClose() {
	if h.flags.hasAny(connectionClose) {
		h.flags &^= connectionClose
		// h.h = delAllArgs(h.h, strConnection) // TODO
	}
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

var ErrBadTrailer = errors.New("contain forbidden trailer")

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
	h.flags |= disableNormalizing
}

// Method returns HTTP request method.
func (h *header) Method() []byte {
	return h.hbuf.musttoken(h.method)
}

func (h *header) SetMethod(method string) {
	h.method = h.reuseOrAppend(h.method, method)
}

// SetRequestURI sets RequestURI for the first HTTP request line.
func (h *header) SetRequestURI(requestURI string) {
	h.requestURI = h.reuseOrAppend(h.requestURI, requestURI)
}

// RequestURI returns RequestURI from the first HTTP request line.
func (h *header) RequestURI() []byte {
	if h.requestURI.start == 0 {
		return nil
	} else if h.requestURI.len == 0 {
		h.requestURI = h.appendSlice("/")
	}
	return h.hbuf.musttoken(h.requestURI)
}

// Protocol returns HTTP protocol.
func (h *header) Protocol() []byte {
	if h.proto.len == 0 {
		h.proto = h.appendSlice(strHTTP11)
	}
	return h.hbuf.musttoken(h.proto)
}

func (h *header) SetProtocol(protocol string) {
	h.proto = h.reuseOrAppend(h.proto, protocol)
}

// AppendReqRespCommon appends request/response common header representation to dst and returns the extended buffer.
func (h *header) AppendReqRespCommon(dst []byte) []byte {
	for i, n := 0, len(h.hbuf.headers); i < n; i++ {
		kv := &h.hbuf.headers[i]
		if kv.isValid() {
			key := h.hbuf.musttoken(kv.key)
			value := h.hbuf.musttoken(kv.value)
			dst = appendHeaderLine(dst, b2s(key), b2s(value))
		}
	}

	// if len(h.trailer) > 0 {
	// 	aux := appendArgsKey(nil, h.trailer, strCommaSpace)
	// 	dst = appendHeaderLine(dst, strTrailer, b2s(aux))
	// }

	// there is no need in h.collectCookies() here, since if cookies aren't collected yet,
	// they all are located in h.h.
	n := len(h.hbuf.cookies)
	if n > 0 && !h.flags.hasAny(disableSpecialHeader) {
		dst = append(dst, strCookie...)
		dst = append(dst, strColonSpace...)
		h.hbuf.appendRequestCookieBytes(dst)
		dst = append(dst, strCRLF...)
	}

	if h.ConnectionClose() && !h.flags.hasAny(disableSpecialHeader) {
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
	if h.flags.hasAny(cookiesCollected) {
		return
	}
	n := len(h.hbuf.headers)
	for i := 0; i < n; i++ {
		kv := h.hbuf.headers[i]
		if kv.isValid() && caseInsensitiveCompare(b2s(h.hbuf.musttoken(kv.key)), HeaderCookie) {
			cookie := h.hbuf.musttoken(kv.value)
			for len(cookie) > 0 {
				key, value, n := parseCookie(cookie)
				h.hbuf.cookies = append(h.hbuf.cookies, argsKV{
					key:   h.hbuf.slice(key),
					value: h.hbuf.slice(value),
				})
				cookie = cookie[n:]
			}
		}
	}
	h.flags |= cookiesCollected
}

func (h *header) parseReqCookie(value []byte) {

}

func (h *header) MethodIs(method string) bool {
	return b2s(h.Method()) == method
}

// IsGet returns true if request method is GET.
func (h *header) IsGet() bool { return h.method.len == 0 || h.MethodIs(http.MethodGet) }

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
func (h *header) IsHTTP11() bool { return !h.flags.hasAny(noHTTP11) }

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

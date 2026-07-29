package httpraw

import (
	"bytes"
)

// Cookie implements cookie key-value parsing. Methods function similarly to eponymous [Header] methods.
// Cookie represents a single-line Cookie header value in a HTTP header, much like the standard library Cookie.
type Cookie struct {
	kv KVBuffer
}

// EnableBufferGrowth allows the cookie's buffer to grow past what [Cookie.Reset] was
// handed. See [KVBuffer.EnableBufferGrowth].
func (c *Cookie) EnableBufferGrowth(enableBufferGrowth bool) {
	c.kv.EnableBufferGrowth(enableBufferGrowth)
}

// Reset functions very similarly to [Header.Reset]. Can be used for in-place cookie parsing.
func (c *Cookie) Reset(buf []byte, capKV int) { c.kv.Reset(buf, capKV) }

func (c *Cookie) valid() bool {
	return len(c.kv.kvs) > 0 && c.kv.kvs[0].key.len > 0
}

// Name returns the first cookie key which is commonly referred to as the cookie's name. Returns nil if not found.
func (c *Cookie) Name() []byte {
	if !c.valid() {
		return nil
	}
	return c.kv.AtKey(0)
}

// Value returns the first cookie value associated with the name. Returns nil if not found.
func (c *Cookie) Value() []byte {
	if !c.valid() {
		return nil
	}
	return c.kv.AtValue(0)
}

// ParseBytes copies the argument bytes to the Cookie's underlying buffer and parses the cookie.
func (c *Cookie) ParseBytes(cookie []byte) error {
	c.Reset(nil, 0)
	c.kv.buf = append(c.kv.buf[:0], cookie...)
	return c.Parse()
}

// CopyFrom makes a copy of the argument cookie to the receiver dst argument. No memory is shared between cookies.
func (dst *Cookie) CopyFrom(c Cookie) { dst.kv.CopyFrom(&c.kv) }

// Parse parses the cookie's buffer in place.
func (c *Cookie) Parse() error {
	if c.kv.Len() > 0 {
		return errCookiesParsed
	}
	off := 0
	for {
		k, v, n := parseCookie(c.kv.buf[off:])
		if n == 0 {
			break
		}
		if !c.kv.setInternal(k, v) {
			return ErrBufferExhausted
		}

		off += n
	}
	if c.kv.Len() == 0 {
		return errNoCookies
	}
	return nil
}

// ForEach iterates over the cookie's key-value pairs, stopping on the first
// error returned by cb and returning it.
func (c *Cookie) ForEach(cb func(key, value []byte) bool) {
	c.kv.ForEach(cb)
}

// Get gets a cookie's value from its key. Use HasValueOrKey to check if a key or single-valued cookie is present in the cookie.
func (c *Cookie) Get(key string) []byte { return c.kv.Get(key) }

// HasKeyOrSingleValue returns true if the cookie contains a pair with the given
// key or a valueless attribute with the given text, i.e: "Secure" or "HttpOnly".
// It cannot defer to [KVBuffer.Present]: parseCookie stores a valueless
// attribute with an empty key and the text as the value, so a key-only lookup
// would never match one.
func (c *Cookie) HasKeyOrSingleValue(keyOrSingleValue string) bool {
	for i, nc := 0, c.kv.Len(); i < nc; i++ {
		k, v := c.kv.At(i)
		if (len(k) == 0 && b2s(v) == keyOrSingleValue) || b2s(k) == keyOrSingleValue {
			return true
		}
	}
	return false
}

// parseCookie parses a cookie inside cookie buffer and adds it to cookie buffer..
//
//	Cookie: <cookie>\r\n
func parseCookie(cookie []byte) (key, value []byte, cookieEnd int) {
	if len(cookie) == 0 {
		return nil, nil, 0
	}
	valueEnd := bytes.IndexByte(cookie, ';')
	if valueEnd < 0 { // Ouch this `if` looks like it kills CPU pipepline.
		valueEnd = len(cookie)
		cookieEnd = len(cookie)
	} else {
		cookieEnd = valueEnd + 1
	}
	eqIdx := bytes.IndexByte(cookie[:valueEnd], '=')
	key = cookie[:0]
	if eqIdx > 0 {
		key = trimCookie(cookie[:eqIdx], false)
	}
	value = trimCookie(cookie[eqIdx+1:valueEnd], true)
	return key, value, cookieEnd
}

func trimCookie(src []byte, trimQuotes bool) []byte {
	for len(src) > 0 && src[0] == ' ' {
		src = src[1:] // skip leading whitespace.
	}
	for len(src) > 0 && src[len(src)-1] == ' ' {
		src = src[:len(src)-1] // skip trailing whitespace
	}
	if trimQuotes {
		if len(src) > 1 && src[0] == '"' && src[len(src)-1] == '"' {
			src = src[1 : len(src)-1] // Trim leading+trailing quotes.
		}
	}
	return src
}

// String returns the string representation of the cookie value, much like the standard library http.Cookie.String method.
func (c *Cookie) String() string {
	buf := c.AppendKeyValues(nil)
	return b2s(buf)
}

// AppendKeyValues appends the HTTP header value of the cookie expected after the "Cookie:" string. Does not include trailing \r\n's.
func (c *Cookie) AppendKeyValues(dst []byte) []byte {
	nc := c.kv.Len()
	for i := range nc {
		k, v := c.kv.At(i)
		if len(k) != 0 {
			dst = append(dst, k...)
			dst = append(dst, '=')
		}
		dst = append(dst, v...)
		if i+1 < nc {
			dst = append(dst, ';', ' ')
		}
	}
	return dst
}

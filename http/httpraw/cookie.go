package httpraw

import (
	"bytes"
	"errors"
)

// Cookie implements cookie key-value parsing. Methods function similarly to eponymous [Header] methods.
type Cookie struct {
	buf []byte
	kvs []argsKV // first key-value pair is the data Key/Value pair.
}

// Reset functions very similarly to [Header.Reset]. Can be used for in-place cookie parsing.
func (c *Cookie) Reset(buf []byte) {
	if buf == nil {
		buf = c.buf[:0]
	}
	*c = Cookie{
		buf: buf,
		kvs: c.kvs[:0],
	}
}

func (c *Cookie) Key() []byte {
	if len(c.kvs) == 0 || c.kvs[0].key.len == 0 {
		return nil
	}
	return tok2bytes(c.buf, c.kvs[0].key)
}

func (c *Cookie) Value() []byte {
	if len(c.kvs) == 0 || c.kvs[0].value.len == 0 {
		return nil
	}
	return tok2bytes(c.buf, c.kvs[0].value)
}

func (c *Cookie) ParseBytes(cookie []byte) error {
	c.Reset(nil)
	c.buf = append(c.buf[:0], cookie...)
	return c.Parse()
}

func (c *Cookie) CopyTo(dst *Cookie) {
	dst.buf = append(dst.buf[:0], c.buf...)
	dst.kvs = append(dst.kvs[:0], c.kvs...)
}

func (c *Cookie) Parse() error {
	if len(c.kvs) > 0 {
		return errors.New("cookies already parsed, reset before parsing again")
	}
	off := 0
	for {
		k, v, n := parseCookie(c.buf[off:])
		if n == 0 {
			break
		}
		c.kvs = append(c.kvs, argsKV{
			key:   bytes2tok(c.buf, k),
			value: bytes2tok(c.buf, v),
		})
		off += n
	}
	return nil
}

func (c *Cookie) ForEach(cb func(key, value []byte) error) error {
	nc := len(c.kvs)
	for i := 0; i < nc; i++ {
		kv := c.kvs[i]
		key := tok2bytes(c.buf, kv.key)
		value := tok2bytes(c.buf, kv.value)
		err := cb(key, value)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Cookie) Get(key string) []byte {
	nc := len(c.kvs)
	for i := 0; i < nc; i++ {
		kv := c.kvs[i]
		if b2s(tok2bytes(c.buf, kv.key)) == key {
			return tok2bytes(c.buf, kv.value)
		}
	}
	return nil
}

func (c *Cookie) HasValueOrKey(keyOrSingleValue string) bool {
	nc := len(c.kvs)
	for i := 0; i < nc; i++ {
		kv := c.kvs[i]
		if kv.key.len == 0 && b2s(tok2bytes(c.buf, kv.value)) == keyOrSingleValue ||
			b2s(tok2bytes(c.buf, kv.key)) == keyOrSingleValue {
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

func (c *Cookie) String() string {
	buf := c.AppendKeyValues(nil)
	return b2s(buf)
}

func (c *Cookie) AppendKeyValues(dst []byte) []byte {
	nc := len(c.kvs)
	for i := 0; i < nc; i++ {
		kv := c.kvs[i]
		key := tok2bytes(c.buf, kv.key)
		value := tok2bytes(c.buf, kv.value)
		if len(key) != 0 {
			dst = append(dst, key...)
			dst = append(dst, '=')
		}
		dst = append(dst, value...)
		if i+1 < nc {
			dst = append(dst, ';', ' ')
		}
	}
	return dst
}

package httpraw

import (
	"bytes"
	"io"
)

// Form holds "application/x-www-form-urlencoded" key-value pairs, the encoding
// HTML forms use for POST bodies and query strings alike. Methods function
// similarly to eponymous [Cookie] methods.
//
// Pairs are stored as they appear on the wire, percent-encoded and with '+'
// undecoded, until [Form.Decode] rewrites them in place. The caller bounds the
// data: Form parses the buffer it is handed and reads nothing more.
type Form struct {
	kv kvBuffer
}

// EnableBufferGrowth allows the form's buffer to grow past what [Form.Reset] was
// handed. See [kvBuffer.EnableBufferGrowth].
func (f *Form) EnableBufferGrowth(enableGrowth bool) { f.kv.EnableBufferGrowth(enableGrowth) }

// Reset discards parsed pairs and sets the buffer to parse in place.
// If buf is nil the current buffer is reused.
//
// capKV sizes the pair table. With growth disabled it is a hard limit, so a
// capKV of 0 leaves no room for a single pair and [Form.Parse] answers
// [ErrBufferExhausted]; size it to the pairs expected.
func (f *Form) Reset(buf []byte, capKV int) {
	f.kv.Reset(buf, capKV)
}

// ReadFromBytes appends buf to the underlying buffer, accumulating data to parse. Returns ErrBufferExhausted when buf does not fit and growth is disabled.
func (f *Form) ReadFromBytes(b []byte) error { return f.kv.ReadFromBytes(b) }

// BufferUsed returns bytes accumulated by the Read* methods and awaiting a
// [Form.Parse]. See [kvBuffer.BufferUsed].
func (f *Form) BufferUsed() int { return f.kv.BufferUsed() }

// ReadLimited appends at most limit bytes read from r to the underlying buffer. A read returning data alongside io.EOF reports a nil error, later ones io.EOF.
func (f *Form) ReadLimited(r io.Reader, limit int) (int, error) { return f.kv.ReadLimited(r, limit) }

// ParseBytes copies the argument bytes to the Form's underlying buffer and parses them.
func (f *Form) ParseBytes(b []byte) error {
	f.Reset(nil, 0)
	if len(b) == 0 {
		return nil // An empty body is an empty form, not a failure to read one.
	}
	err := f.kv.ReadFromBytes(b)
	if err != nil {
		return err
	}
	return f.Parse()
}

// Parse parses the form's buffer in place.
func (f *Form) Parse() error {
	f.kv.discardKVs()
	key, value, rest := NextQueryPair(f.kv.buf)
	for key != nil {
		if !f.kv.setInternal(key, value) {
			return ErrBufferExhausted
		}
		key, value, rest = NextQueryPair(rest)
	}
	return nil
}

// Decode rewrites every key and value in place, replacing percent escapes and
// '+' with the bytes they encode. Decoding only shrinks, so no memory is added.
func (f *Form) Decode() error {
	const plusAsSpace = true // Form encoded data, unlike a path.
	nkvs := f.kv.Len()
	for i := range nkvs {
		k, v := f.kv.At(i)
		nk, err := CopyDecodedPercentURL(k, k, plusAsSpace)
		if err != nil {
			return err
		} else if len(v) == 0 {
			if nk != len(k) {
				f.kv.setAt(i, k[:nk], v) // k[:nk]: the decoded key is shorter.
			}
			continue
		}
		nv, err := CopyDecodedPercentURL(v, v, plusAsSpace)
		if err != nil {
			return err
		}
		if nk != len(k) || nv != len(v) {
			f.kv.setAt(i, k[:nk], v[:nv])
		}
	}
	return nil
}

// Len returns the amount of key-value pairs parsed.
func (f *Form) Len() int { return f.kv.Len() }

// Pair returns the i'th key-value pair in wire order. The value is nil for a
// pair with no '=', i.e: "ok" in "ok&q=go", which distinguishes it from "ok="
// where the value is present and empty.
func (f *Form) Pair(i int) (key, value []byte) {
	return f.kv.At(i)
}

// Get returns the value of the first pair matching key, nil if absent or if the
// pair has no value. Bytes are compared as stored, so call [Form.Decode] first
// when keys may be encoded.
func (f *Form) Get(key string) []byte { return f.kv.Get(key) }

// Has returns true if key is present, with or without a value.
func (f *Form) Has(key string) bool { return f.kv.Present(key) }

// AppendKeyValues appends the form's wire representation to dst and returns it.
func (f *Form) AppendKeyValues(dst []byte) []byte {
	nkv := f.kv.Len()
	for i := range nkv {
		key, value := f.Pair(i)
		if i > 0 {
			dst = append(dst, '&')
		}
		dst = append(dst, key...)
		if value != nil {
			dst = append(dst, '=')
			dst = append(dst, value...)
		}
	}
	return dst
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

package httpraw

// Form holds "application/x-www-form-urlencoded" key-value pairs, the encoding
// HTML forms use for POST bodies and query strings alike. Methods function
// similarly to eponymous [Cookie] methods.
//
// Pairs are stored as they appear on the wire, percent-encoded and with '+'
// undecoded, until [Form.Decode] rewrites them in place. The caller bounds the
// data: Form parses the buffer it is handed and reads nothing more.
type Form struct {
	buf []byte
	kvs []argsKV
}

// Reset discards parsed pairs and sets the buffer to parse in place.
// If buf is nil the current buffer is reused.
func (f *Form) Reset(buf []byte) {
	if buf == nil {
		buf = f.buf[:0]
	}
	*f = Form{
		buf: buf,
		kvs: f.kvs[:0],
	}
}

// ParseBytes copies the argument bytes to the Form's underlying buffer and parses them.
func (f *Form) ParseBytes(b []byte) error {
	f.Reset(nil)
	f.buf = append(f.buf[:0], b...)
	return f.Parse()
}

// Parse parses the form's buffer in place.
func (f *Form) Parse() error {
	f.kvs = f.kvs[:0]
	key, value, rest := NextQueryPair(f.buf)
	for key != nil {
		kv := argsKV{key: bytes2tok(f.buf, key)}
		if value != nil {
			kv.value = bytes2tok(f.buf, value)
		}
		f.kvs = append(f.kvs, kv)
		key, value, rest = NextQueryPair(rest)
	}
	return nil
}

// Decode rewrites every key and value in place, replacing percent escapes and
// '+' with the bytes they encode. Decoding only shrinks, so no memory is added.
func (f *Form) Decode() error {
	const plusAsSpace = true // Form encoded data, unlike a path.
	for i := range f.kvs {
		kv := &f.kvs[i]
		n, err := CopyDecodedPercentURL(tok2bytes(f.buf, kv.key), tok2bytes(f.buf, kv.key), plusAsSpace)
		if err != nil {
			return err
		}
		kv.key.len = tokint(n)
		if !kv.HasValue() {
			continue
		}
		n, err = CopyDecodedPercentURL(tok2bytes(f.buf, kv.value), tok2bytes(f.buf, kv.value), plusAsSpace)
		if err != nil {
			return err
		}
		kv.value.len = tokint(n)
	}
	return nil
}

// Len returns the amount of key-value pairs parsed.
func (f *Form) Len() int { return len(f.kvs) }

// Pair returns the i'th key-value pair in wire order. The value is nil for a
// pair with no '=', i.e: "ok" in "ok&q=go", which distinguishes it from "ok="
// where the value is present and empty.
func (f *Form) Pair(i int) (key, value []byte) {
	kv := f.kvs[i]
	key = tok2bytes(f.buf, kv.key)
	if kv.HasValue() {
		value = tok2bytes(f.buf, kv.value)
	}
	return key, value
}

// Get returns the value of the first pair matching key, nil if absent or if the
// pair has no value. Bytes are compared as stored, so call [Form.Decode] first
// when keys may be encoded.
func (f *Form) Get(key string) []byte {
	for i := range f.kvs {
		gotKey, value := f.Pair(i)
		if b2s(gotKey) == key {
			return value
		}
	}
	return nil
}

// Has returns true if key is present, with or without a value.
func (f *Form) Has(key string) bool {
	for i := range f.kvs {
		if b2s(tok2bytes(f.buf, f.kvs[i].key)) == key {
			return true
		}
	}
	return false
}

// AppendKeyValues appends the form's wire representation to dst and returns it.
func (f *Form) AppendKeyValues(dst []byte) []byte {
	for i := range f.kvs {
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

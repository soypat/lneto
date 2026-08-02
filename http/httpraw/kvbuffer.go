package httpraw

import (
	"io"
	"slices"
	"strconv"
	"unsafe"

	"github.com/soypat/lneto/internal"
)

// kvBuffer is a common key-value store engine for Cookie, Form, Header and other HTTP abstractions that need
// a key-value store with underlying buffer memory.
type kvBuffer struct {
	buf   []byte
	kvs   []pairKV
	flags Flags
}

func (kvb *kvBuffer) free() int { return cap(kvb.buf) - len(kvb.buf) }

// BufferRaw returns the underlying buffer, its length being the portion in use.
// Stored pairs alias it, so writing to it mangles them.
func (kvb *kvBuffer) BufferRaw() []byte { return kvb.buf }

// BufferUsed returns the raw memory used, which is what a caller appending from
// several sources checks to know whether a separator is needed. Counts buffered
// bytes and not parsed pairs, so it is set before a Parse and unchanged by one.
func (kvb *kvBuffer) BufferUsed() int { return len(kvb.buf) }

// EnableBufferGrowth allows the buffer to grow past the memory [kvBuffer.Reset]
// was handed. The setting outlives Reset; with growth off callers get [ErrBufferExhausted].
func (kvb *kvBuffer) EnableBufferGrowth(enableGrowth bool) {
	if enableGrowth {
		kvb.flags &^= flagNoBufferGrow
	} else {
		kvb.flags |= flagNoBufferGrow
	}
}

func (kvb *kvBuffer) discardKVs() { kvb.kvs = kvb.kvs[:0] }

// BufferGrowthEnabled reports whether the buffer may grow, see [kvBuffer.EnableBufferGrowth].
func (kvb *kvBuffer) BufferGrowthEnabled() bool { return !kvb.flags.HasAny(flagNoBufferGrow) }

// ReadFromBytes appends buf to the underlying buffer, accumulating data to parse.
// Returns [ErrBufferExhausted] when buf does not fit and growth is disabled.
func (kvb *kvBuffer) ReadFromBytes(buf []byte) error {
	if len(buf) == 0 {
		return io.ErrNoProgress // Nothing handed over, not a buffer problem.
	} else if kvb.flags.HasAny(flagMangledBuffer) {
		return errMangledBuffer
	} else if len(buf)+cap(kvb.buf) > maxBufLen {
		return ErrBufferExhausted
	}
	free := kvb.free()
	if len(buf) > free && !kvb.BufferGrowthEnabled() {
		return ErrBufferExhausted
	}
	kvb.buf = append(kvb.buf, buf...)
	return nil
}

// ReadLimited appends at most limit bytes read from r to the underlying buffer.
// A read returning data alongside [io.EOF] reports a nil error, later ones io.EOF.
func (kvb *kvBuffer) ReadLimited(r io.Reader, limit int) (int, error) {
	free := kvb.free()
	growthEnabled := kvb.BufferGrowthEnabled()
	if !growthEnabled && (free == 0 || free < limit) || len(kvb.buf) >= maxBufLen {
		return 0, ErrBufferExhausted
	} else if kvb.flags.HasAny(flagMangledBuffer) {
		return 0, errMangledBuffer
	} else if kvb.flags.HasAny(flagReaderEOF) {
		return 0, io.EOF
	} else if limit <= 0 {
		return 0, io.ErrNoProgress
	}
	kvb.buf = slices.Grow(kvb.buf, limit)
	n, err := r.Read(kvb.buf[len(kvb.buf):min(len(kvb.buf)+limit, maxBufLen)])
	kvb.buf = kvb.buf[:len(kvb.buf)+n]
	if err != nil {
		if n > 0 && err == io.EOF {
			kvb.flags |= flagReaderEOF
			err = nil // Nil out EOF to not scare off readers.
		}
	}
	return n, err
}

// Reset discards all pairs and takes buf as the buffer to parse in place, nil
// reusing the current one. kvCap sizes the pair table. Only the growth setting survives.
func (kvb *kvBuffer) Reset(buf []byte, kvCap int) {
	if buf == nil {
		kvb.buf = kvb.buf[:0]
	} else {
		kvb.buf = buf
	}
	internal.SliceReuse(&kvb.kvs, kvCap)
	kvb.flags = kvb.flags & flagNoBufferGrow // Only flag persisted is buffer grow config.
}

// CopyFrom replaces the receiver's contents with a copy of src, sharing no
// memory with it afterwards.
func (kvb *kvBuffer) CopyFrom(src *kvBuffer) {
	kvb.buf = append(kvb.buf[:0], src.buf...)
	kvb.kvs = append(kvb.kvs[:0], src.kvs...)
}

// Get returns the value of the first pair matching key.
// Bytes are compared as stored, so if using a Form call [Form.Decode] first when keys may be encoded.
// Returns nil for an absent key and for a valueless pair alike, so use
// [kvBuffer.Present] to tell the two apart.
func (kvb *kvBuffer) Get(key string) []byte {
	i := kvb.getIdx(key)
	if i < 0 {
		return nil
	}
	return kvb.AtValue(i)
}

// GetFold returns the value of the first key that matches ascii-case-insensitive.
func (kvb *kvBuffer) GetFold(key string) []byte {
	i := kvb.getFoldIdx(key)
	if i < 0 {
		return nil
	}
	return kvb.AtValue(i)
}

// ForEach iterates over the cookie's key-value pairs as stored until cb returns false.
func (kvb *kvBuffer) ForEach(cb func(key, value []byte) bool) {
	nc := len(kvb.kvs)
	for i := range nc {
		if !kvb.kvs[i].isValid() {
			continue
		} else if !cb(kvb.At(i)) {
			break
		}
	}
}

// Has returns true if key is present, with or without a value.
func (kvb *kvBuffer) Present(key string) bool { // TODO: rename to Has.
	return kvb.getIdx(key) >= 0
}

// Has returns true if key is present, with or without a value.
func (kvb *kvBuffer) HasKeyValue(key, value string) bool {
	idx := kvb.getIdx(key)
	if idx >= 0 {
		return b2s(kvb.musttoken(kvb.kvs[idx].value)) == value
	}
	return false
}

// Add appends a pair, keeping any already sharing the key: use [kvBuffer.Set]
// to replace instead. Reports false if the buffer could not hold it.
func (kvb *kvBuffer) Add(key, value string) (enoughSpace bool) {
	kvb.appendPair(key, value)
	return kvb.getIdx(key) >= 0
}

// Set replaces key's value and invalidates every other pair sharing the key, so
// a following [kvBuffer.Get] sees exactly one value.
//
// It rewrites in place when it can: of the pairs it would invalidate it keeps
// the smallest whose key and value regions both still hold the new pair,
// leaving the roomier regions for a later Set. When none fits the pair is
// appended with [kvBuffer.Add] and the invalidated regions are stranded, since
// nothing here compacts the buffer.
func (kvb *kvBuffer) Set(key, value string) (enoughSpace bool) {
	reuse := kvb.takeReusableSlot(key, len(key), len(value))
	if reuse < 0 {
		return kvb.Add(key, value)
	}
	kvb.overwriteAt(reuse, key, value)
	return true
}

// SetInt is [kvBuffer.Set]'s integer counterpart. It formats value straight into
// the slot it reuses, so overwriting a pair never allocates.
func (kvb *kvBuffer) SetInt(key string, value int64, base int) (enoughSpace bool) {
	reuse := kvb.takeReusableSlot(key, len(key), internal.IntLen(value, base))
	if reuse < 0 {
		return kvb.appendPairInt(key, value, base)
	}
	kvb.flags |= flagMangledBuffer
	kv := &kvb.kvs[reuse]
	copy(kvb.buf[kv.key.start:], key)
	kv.key.len = tokint(len(key))
	// The slot was picked to hold keyLen/valueLen, so AppendInt writes inside
	// buf and never grows a new backing array.
	v := strconv.AppendInt(kvb.buf[kv.value.start:kv.value.start], value, base)
	kv.value.len = tokint(len(v))
	return true
}

// takeReusableSlot invalidates every pair matching key except the smallest one
// whose key and value regions hold keyLen and valueLen bytes, whose index it
// returns. It returns -1 when no surviving slot fits, meaning the caller must
// append instead.
func (kvb *kvBuffer) takeReusableSlot(key string, keyLen, valueLen int) int {
	reuse := -1
	for i := range kvb.kvs {
		kv := &kvb.kvs[i]
		if !kv.isValid() || b2s(kvb.musttoken(kv.key)) != key {
			continue
		}
		// A valueless pair holds no value region, so reusing one would write the
		// value over byte 0. Let it fall through to the caller's append, which
		// gives the pair a real region and keeps "ok" distinct from "ok=".
		fits := kv.HasValue() && int(kv.key.len) >= keyLen && int(kv.value.len) >= valueLen
		if fits && (reuse < 0 || kv.size() < kvb.kvs[reuse].size()) {
			if reuse >= 0 {
				kvb.kvs[reuse].invalidate() // Superseded by a tighter fit.
			}
			reuse = i
			continue
		}
		kv.invalidate()
	}
	return reuse
}

// overwriteAt writes key and value over the regions pair i already owns. The
// caller must have checked both fit; the bytes freed by a shorter pair are
// stranded, not reclaimed.
func (kvb *kvBuffer) overwriteAt(i int, key, value string) {
	kvb.flags |= flagMangledBuffer
	kv := &kvb.kvs[i]
	copy(kvb.buf[kv.key.start:], key)
	kv.key.len = tokint(len(key))
	copy(kvb.buf[kv.value.start:], value)
	kv.value.len = tokint(len(value))
}

func (kvb *kvBuffer) setInternal(key, value []byte) (enoughSpace bool) {
	if !kvb.canAddOneKV() {
		return false
	}
	kvb.flags |= flagKVAppended
	kvb.kvs = append(kvb.kvs, pairKV{
		key:   kvb.view(key),
		value: kvb.view(value),
	})
	return true
}

// Len returns the number of slots stored, counting those [kvBuffer.Set] invalidated.
func (kvb *kvBuffer) Len() int { return len(kvb.kvs) }

// At returns the i'th pair in wire order. value is nil for a pair holding none,
// which is what tells a form's "ok" from "ok=".
func (kvb *kvBuffer) At(i int) (key, value []byte) {
	kv := kvb.kvs[i]
	if !kv.HasValue() {
		return kvb.musttoken(kv.key), nil
	}
	return kvb.musttoken(kv.key), kvb.musttoken(kv.value)
}
func (kvb *kvBuffer) setAt(i int, k, v []byte) {
	kvb.flags |= flagMangledBuffer
	// Route through slice, not bytes2tok: a nil v is a pair with no '=' and must
	// stay absent rather than trip the alias check on a nil pointer.
	kvb.kvs[i] = pairKV{
		key:   kvb.view(k),
		value: kvb.view(v),
	}
}

// AtKey is [kvBuffer.At] limited to the i'th key.
func (kvb *kvBuffer) AtKey(i int) (key []byte) { return kvb.musttoken(kvb.kvs[i].key) }

// AtValue is [kvBuffer.At] limited to the i'th value, nil when the pair holds none.
func (kvb *kvBuffer) AtValue(i int) (key []byte) {
	if !kvb.kvs[i].HasValue() {
		return nil
	}
	return kvb.musttoken(kvb.kvs[i].value)
}

func (kvb *kvBuffer) getIdx(key string) int {
	for i, pair := range kvb.kvs {
		if pair.isValid() && b2s(kvb.musttoken(pair.key)) == key {
			return i
		}
	}
	return -1
}

func (kvb *kvBuffer) getFoldIdx(key string) int {
	for i, pair := range kvb.kvs {
		if pair.isValid() && EqualFoldASCII(key, b2s(kvb.AtKey(i))) {
			return i
		}
	}
	return -1
}

// EqualFoldASCII reports whether a and b are equal under ASCII case folding.
// Unlike strings.EqualFold it does not fold non-ASCII runes, so no multi-byte
// rune such as U+212A KELVIN SIGN can alias a header key.
func EqualFoldASCII(a, b string) bool {
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

// reserve ensures need free bytes are available in the buffer, growing it when
// permitted. It accounts for the byte-0 reservation on an empty buffer (see
// mustAppendSlice). It returns false and sets flagOOMReached when the space
// cannot be guaranteed: a tokint offset overflow, or a full buffer with
// flagNoBufferGrow set.
func (kvb *kvBuffer) reserve(need int) (enoughSpace bool) {
	if len(kvb.buf) == 0 {
		need++ // mustAppend* reserves byte 0 on an empty buffer.
	}
	if len(kvb.buf)+need > maxBufLen {
		kvb.flags |= flagOOMReached // Offsets would overflow uint16 tokint.
		return false
	}
	if need > kvb.free() {
		if kvb.flags.HasAny(flagNoBufferGrow) {
			kvb.flags |= flagOOMReached
			return false
		}
		kvb.buf = slices.Grow(kvb.buf, need)
	}
	return true
}

func (kvb *kvBuffer) appendPair(key, value string) bool {
	if !kvb.canAddOneKV() || !kvb.reserve(len(key)+len(value)) {
		return false
	}
	kvb.flags |= flagKVAppended
	kvb.kvs = append(kvb.kvs, pairKV{
		key:   kvb.mustAppendSlice(key),
		value: kvb.mustAppendSlice(value),
	})
	return true
}

func (kvb *kvBuffer) appendPairInt(key string, value int64, base int) bool {
	vlen := internal.IntLen(value, base)
	if !kvb.canAddOneKV() || !kvb.reserve(len(key)+vlen) {
		return false
	}
	kvb.flags |= flagKVAppended
	kvb.kvs = append(kvb.kvs, pairKV{
		key:   kvb.mustAppendSlice(key),
		value: kvb.mustAppendInt(value, base),
	})
	return true
}

func (kvb *kvBuffer) canAddOneKV() (enoughSpace bool) {
	return len(kvb.kvs) < cap(kvb.kvs) || kvb.flags&flagNoBufferGrow == 0
}

func (kvb *kvBuffer) mustAppendSlice(value string) view {
	L := len(kvb.buf)
	if L == 0 {
		L++ // Valid key-values start after 0.
	}
	copy(kvb.buf[L:L+len(value)], value)
	kvb.buf = kvb.buf[:L+len(value)]
	return kvb.view(kvb.buf[L : L+len(value)])
}

func (kvb *kvBuffer) mustAppendInt(value int64, base int) view {
	L := len(kvb.buf)
	if L == 0 {
		L++ // Valid key-values start after byte 0.
	}
	v := strconv.AppendInt(kvb.buf[L:L], value, base)
	kvb.buf = kvb.buf[:L+len(v)]
	return kvb.view(kvb.buf[L : L+len(v)])
}

// reuseOrAppend writes value over tok's slot when it fits there, avoiding any
// buffer growth; otherwise it appends a fresh slot.
func (kvb *kvBuffer) reuseOrAppend(tok view, value string) view {
	if tok.len > tokint(len(value)) {
		copy(kvb.musttoken(tok), value)
		tok.len = tokint(len(value))
		return tok
	}
	return kvb.appendSlice(value)
}

// appendSlice reserves space (growing or flagging OOM) and appends value as a
// new slot.
func (kvb *kvBuffer) appendSlice(value string) view {
	debuglog("http:appendslice:start")
	if !kvb.reserve(len(value)) {
		return view{} // Drop and flag OOM; never panic.
	}
	kvb.flags |= flagMangledBuffer
	return kvb.mustAppendSlice(value)
}

// reuseOrAppendInt is [kvBuffer.reuseOrAppend]'s integer counterpart.
func (kvb *kvBuffer) reuseOrAppendInt(tok view, value int64, base int) view {
	n := internal.IntLen(value, base)
	if int(tok.len) >= n {
		// Reuse: format directly over the existing slot. No free space needed
		// since n <= tok.len and the slot already lives inside buf.
		v := strconv.AppendInt(kvb.buf[tok.start:tok.start], value, base)
		tok.len = tokint(len(v))
		kvb.flags |= flagMangledBuffer
		return tok
	}
	return kvb.appendInt(value, base, n)
}

// appendInt reserves space (growing or flagging OOM) and appends value as a new slot.
func (kvb *kvBuffer) appendInt(value int64, base, n int) view {
	if !kvb.reserve(n) {
		return view{} // Drop and flag OOM; never panic.
	}
	kvb.flags |= flagMangledBuffer
	return kvb.mustAppendInt(value, base)
}

func (kvb *kvBuffer) view(value []byte) view {
	if value == nil {
		return view{}
	}
	return bytes2tok(kvb.buf, value)
}

func (kvb kvBuffer) musttoken(slice view) []byte {
	return tok2bytes(kvb.buf, slice)
}
func (kvb *kvBuffer) noKV() pairKV { return pairKV{} }

type tokint = uint16

// view is a smaller `string`-like representation of a section in [kvBuffer]'s buffer.
type view struct {
	start tokint
	len   tokint
}

type pairKV struct {
	key   view
	value view // value start >0 means value is present.
}

// SizeKV is the heap cost of a single key/value field slot, as reserved by the
// numHeaderCapacity argument to [HeaderV1.Reset] and by [Form.Reset]. Callers
// budgeting a fixed memory pool up front, such as a Router sizing its
// exchanges, multiply it by the pair capacity to account the field table.
const SizeKV = int(unsafe.Sizeof(pairKV{}))

// isValid is for stores parsed in place, where offset 0 is the first key so
// only length can signal presence. Empty keys are valid: see valueless cookies.
func (pair pairKV) isValid() bool {
	return pair.key.len > 0 || pair.value.len > 0
}

// isValidHeader is for the append-built [HeaderV1] store, where mustAppendSlice
// burns byte 0 so a zero offset means absent. Drops offset-0 pairs otherwise.
func (pair pairKV) isValidHeader() bool { return pair.key.start > 0 }

func (pair *pairKV) invalidate() {
	*pair = pairKV{}
}

// size is the buffer a pair occupies, used to pick the tightest slot to reuse.
func (pair pairKV) size() int { return int(pair.key.len) + int(pair.value.len) }

func (pair pairKV) HasValue() bool { return pair.value.start > 0 }

// b2s converts byte slice to a string without memory allocation.
// See https://groups.google.com/forum/#!msg/Golang-Nuts/ENgbUzYvCuU/90yGx7GUAgAJ .
func b2s(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func tok2bytes(buf []byte, slice view) []byte {
	return buf[slice.start : slice.start+slice.len]
}

func bytes2tok(buf, value []byte) view {
	base := uintptr(unsafe.Pointer(unsafe.SliceData(buf)))
	off := uintptr(unsafe.Pointer(unsafe.SliceData(value)))
	if off < base || off > base+uintptr(len(buf)) {
		panic("httpx: argument buffer does not alias header buffer")
	}
	return view{
		start: tokint(off - base),
		len:   tokint(len(value)),
	}
}

package httpraw

import (
	"io"
	"slices"
	"strconv"

	"github.com/soypat/lneto/internal"
)

// kvBuffer is a common key-value store engine for Cookie, Form, Header and other HTTP abstractions that need
// a key-value store with underlying buffer memory.
type kvBuffer struct {
	buf   []byte
	kvs   []argsKV
	flags Flags
}

func (mb *kvBuffer) free() int { return cap(mb.buf) - len(mb.buf) }

// BufferRaw returns the underlying buffer, its length being the portion in use.
// Stored pairs alias it, so writing to it mangles them.
func (mb *kvBuffer) BufferRaw() []byte { return mb.buf }

// EnableBufferGrowth allows the buffer to grow past the memory [kvBuffer.Reset]
// was handed. The setting outlives Reset; with growth off callers get [ErrBufferExhausted].
func (mb *kvBuffer) EnableBufferGrowth(enableGrowth bool) {
	if enableGrowth {
		mb.flags &^= flagNoBufferGrow
	} else {
		mb.flags |= flagNoBufferGrow
	}
}

func (mb *kvBuffer) discardKVs() { mb.kvs = mb.kvs[:0] }

// BufferGrowthEnabled reports whether the buffer may grow, see [kvBuffer.EnableBufferGrowth].
func (mb *kvBuffer) BufferGrowthEnabled() bool { return !mb.flags.HasAny(flagNoBufferGrow) }

// ReadFromBytes appends buf to the underlying buffer, accumulating data to parse.
// Returns [ErrBufferExhausted] when buf does not fit and growth is disabled.
func (mb *kvBuffer) ReadFromBytes(buf []byte) error {
	if len(buf) == 0 {
		return io.ErrNoProgress // Nothing handed over, not a buffer problem.
	} else if mb.flags.HasAny(flagMangledBuffer) {
		return errMangledBuffer
	} else if len(buf)+cap(mb.buf) > maxBufLen {
		return ErrBufferExhausted
	}
	free := mb.free()
	if len(buf) > free && !mb.BufferGrowthEnabled() {
		return ErrBufferExhausted
	}
	mb.buf = append(mb.buf, buf...)
	return nil
}

// ReadLimited appends at most limit bytes read from r to the underlying buffer.
// A read returning data alongside [io.EOF] reports a nil error, later ones io.EOF.
func (mb *kvBuffer) ReadLimited(r io.Reader, limit int) (int, error) {
	free := mb.free()
	growthEnabled := mb.BufferGrowthEnabled()
	if !growthEnabled && (free == 0 || free < limit) || len(mb.buf) >= maxBufLen {
		return 0, ErrBufferExhausted
	} else if mb.flags.HasAny(flagMangledBuffer) {
		return 0, errMangledBuffer
	} else if mb.flags.HasAny(flagReaderEOF) {
		return 0, io.EOF
	} else if limit <= 0 {
		return 0, io.ErrNoProgress
	}
	mb.buf = slices.Grow(mb.buf, limit)
	n, err := r.Read(mb.buf[len(mb.buf):min(len(mb.buf)+limit, maxBufLen)])
	mb.buf = mb.buf[:len(mb.buf)+n]
	if err != nil {
		if n > 0 && err == io.EOF {
			mb.flags |= flagReaderEOF
			err = nil // Nil out EOF to not scare off readers.
		}
	}
	return n, err
}

// Reset discards all pairs and takes buf as the buffer to parse in place, nil
// reusing the current one. kvCap sizes the pair table. Only the growth setting survives.
func (mb *kvBuffer) Reset(buf []byte, kvCap int) {
	if buf == nil {
		mb.buf = mb.buf[:0]
	} else {
		mb.buf = buf
	}
	internal.SliceReuse(&mb.kvs, kvCap)
	mb.flags = mb.flags & flagNoBufferGrow // Only flag persisted is buffer grow config.
}

// CopyFrom replaces the receiver's contents with a copy of src, sharing no
// memory with it afterwards.
func (mb *kvBuffer) CopyFrom(src *kvBuffer) {
	mb.buf = append(mb.buf[:0], src.buf...)
	mb.kvs = append(mb.kvs[:0], src.kvs...)
}

// Get returns the value of the first pair matching key.
// Bytes are compared as stored, so if using a Form call [Form.Decode] first when keys may be encoded.
// Returns nil for an absent key and for a valueless pair alike, so use
// [kvBuffer.Present] to tell the two apart.
func (mb *kvBuffer) Get(key string) []byte {
	i := mb.getIdx(key)
	if i < 0 {
		return nil
	}
	return mb.AtValue(i)
}

// ForEach iterates over the cookie's key-value pairs as stored until cb returns false.
func (c *kvBuffer) ForEach(cb func(key, value []byte) bool) {
	nc := len(c.kvs)
	for i := range nc {
		if !c.kvs[i].isValid() {
			continue
		} else if !cb(c.At(i)) {
			break
		}
	}
}

// Has returns true if key is present, with or without a value.
func (mb *kvBuffer) Present(key string) bool { // TODO: rename to Has.
	return mb.getIdx(key) >= 0
}

// Has returns true if key is present, with or without a value.
func (mb *kvBuffer) HasKeyValue(key, value string) bool {
	idx := mb.getIdx(key)
	if idx >= 0 {
		return b2s(mb.musttoken(mb.kvs[idx].value)) == value
	}
	return false
}

// Add appends a pair, keeping any already sharing the key: use [kvBuffer.Set]
// to replace instead. Reports false if the buffer could not hold it.
func (mb *kvBuffer) Add(key, value string) (enoughSpace bool) {
	mb.appendPair(key, value)
	return mb.getIdx(key) >= 0
}

// Set replaces key's value and invalidates every other pair sharing the key, so
// a following [kvBuffer.Get] sees exactly one value.
//
// It rewrites in place when it can: of the pairs it would invalidate it keeps
// the smallest whose key and value regions both still hold the new pair,
// leaving the roomier regions for a later Set. When none fits the pair is
// appended with [kvBuffer.Add] and the invalidated regions are stranded, since
// nothing here compacts the buffer.
func (mb *kvBuffer) Set(key, value string) (enoughSpace bool) {
	reuse := mb.takeReusableSlot(key, len(key), len(value))
	if reuse < 0 {
		return mb.Add(key, value)
	}
	mb.overwriteAt(reuse, key, value)
	return true
}

// SetInt is [kvBuffer.Set]'s integer counterpart. It formats value straight into
// the slot it reuses, so overwriting a pair never allocates.
func (mb *kvBuffer) SetInt(key string, value int64, base int) (enoughSpace bool) {
	reuse := mb.takeReusableSlot(key, len(key), internal.IntLen(value, base))
	if reuse < 0 {
		return mb.appendPairInt(key, value, base)
	}
	mb.flags |= flagMangledBuffer
	kv := &mb.kvs[reuse]
	copy(mb.buf[kv.key.start:], key)
	kv.key.len = tokint(len(key))
	// The slot was picked to hold keyLen/valueLen, so AppendInt writes inside
	// buf and never grows a new backing array.
	v := strconv.AppendInt(mb.buf[kv.value.start:kv.value.start], value, base)
	kv.value.len = tokint(len(v))
	return true
}

// takeReusableSlot invalidates every pair matching key except the smallest one
// whose key and value regions hold keyLen and valueLen bytes, whose index it
// returns. It returns -1 when no surviving slot fits, meaning the caller must
// append instead.
func (mb *kvBuffer) takeReusableSlot(key string, keyLen, valueLen int) int {
	reuse := -1
	for i := range mb.kvs {
		kv := &mb.kvs[i]
		if !kv.isValid() || b2s(mb.musttoken(kv.key)) != key {
			continue
		}
		// A valueless pair holds no value region, so reusing one would write the
		// value over byte 0. Let it fall through to the caller's append, which
		// gives the pair a real region and keeps "ok" distinct from "ok=".
		fits := kv.HasValue() && int(kv.key.len) >= keyLen && int(kv.value.len) >= valueLen
		if fits && (reuse < 0 || kv.size() < mb.kvs[reuse].size()) {
			if reuse >= 0 {
				mb.kvs[reuse].invalidate() // Superseded by a tighter fit.
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
func (mb *kvBuffer) overwriteAt(i int, key, value string) {
	mb.flags |= flagMangledBuffer
	kv := &mb.kvs[i]
	copy(mb.buf[kv.key.start:], key)
	kv.key.len = tokint(len(key))
	copy(mb.buf[kv.value.start:], value)
	kv.value.len = tokint(len(value))
}

func (mb *kvBuffer) setInternal(key, value []byte) (enoughSpace bool) {
	if !mb.canAddOneKV() {
		return false
	}
	mb.flags |= flagKVAppended
	mb.kvs = append(mb.kvs, argsKV{
		key:   mb.slice(key),
		value: mb.slice(value),
	})
	return true
}

// Len returns the number of slots stored, counting those [kvBuffer.Set] invalidated.
func (mb *kvBuffer) Len() int { return len(mb.kvs) }

// At returns the i'th pair in wire order. value is nil for a pair holding none,
// which is what tells a form's "ok" from "ok=".
func (mb *kvBuffer) At(i int) (key, value []byte) {
	kv := mb.kvs[i]
	if !kv.HasValue() {
		return mb.musttoken(kv.key), nil
	}
	return mb.musttoken(kv.key), mb.musttoken(kv.value)
}
func (mb *kvBuffer) setAt(i int, k, v []byte) {
	mb.flags |= flagMangledBuffer
	// Route through slice, not bytes2tok: a nil v is a pair with no '=' and must
	// stay absent rather than trip the alias check on a nil pointer.
	mb.kvs[i] = argsKV{
		key:   mb.slice(k),
		value: mb.slice(v),
	}
}

// AtKey is [kvBuffer.At] limited to the i'th key.
func (mb *kvBuffer) AtKey(i int) (key []byte) { return mb.musttoken(mb.kvs[i].key) }

// AtValue is [kvBuffer.At] limited to the i'th value, nil when the pair holds none.
func (mb *kvBuffer) AtValue(i int) (key []byte) {
	if !mb.kvs[i].HasValue() {
		return nil
	}
	return mb.musttoken(mb.kvs[i].value)
}

func (mb *kvBuffer) getIdx(key string) int {
	for i, kv := range mb.kvs {
		if kv.isValid() && b2s(mb.musttoken(kv.key)) == key {
			return i
		}
	}
	return -1
}

// reserve ensures need free bytes are available in the buffer, growing it when
// permitted. It accounts for the byte-0 reservation on an empty buffer (see
// mustAppendSlice). It returns false and sets flagOOMReached when the space
// cannot be guaranteed: a tokint offset overflow, or a full buffer with
// flagNoBufferGrow set.
func (mb *kvBuffer) reserve(need int) (enoughSpace bool) {
	if len(mb.buf) == 0 {
		need++ // mustAppend* reserves byte 0 on an empty buffer.
	}
	if len(mb.buf)+need > maxBufLen {
		mb.flags |= flagOOMReached // Offsets would overflow uint16 tokint.
		return false
	}
	if need > mb.free() {
		if mb.flags.HasAny(flagNoBufferGrow) {
			mb.flags |= flagOOMReached
			return false
		}
		mb.buf = slices.Grow(mb.buf, need)
	}
	return true
}

func (mb *kvBuffer) appendPair(key, value string) bool {
	if !mb.canAddOneKV() || !mb.reserve(len(key)+len(value)) {
		return false
	}
	mb.flags |= flagKVAppended
	mb.kvs = append(mb.kvs, argsKV{
		key:   mb.mustAppendSlice(key),
		value: mb.mustAppendSlice(value),
	})
	return true
}

func (mb *kvBuffer) appendPairInt(key string, value int64, base int) bool {
	vlen := internal.IntLen(value, base)
	if !mb.canAddOneKV() || !mb.reserve(len(key)+vlen) {
		return false
	}
	mb.flags |= flagKVAppended
	mb.kvs = append(mb.kvs, argsKV{
		key:   mb.mustAppendSlice(key),
		value: mb.mustAppendInt(value, base),
	})
	return true
}

func (mb *kvBuffer) canAddOneKV() (enoughSpace bool) {
	return len(mb.kvs) < cap(mb.kvs) || mb.flags&flagNoBufferGrow == 0
}

func (mb *kvBuffer) mustAppendSlice(value string) headerSlice {
	L := len(mb.buf)
	if L == 0 {
		L++ // Valid key-values start after 0.
	}
	copy(mb.buf[L:L+len(value)], value)
	mb.buf = mb.buf[:L+len(value)]
	return mb.slice(mb.buf[L : L+len(value)])
}

func (hb *kvBuffer) mustAppendInt(value int64, base int) headerSlice {
	L := len(hb.buf)
	if L == 0 {
		L++ // Valid key-values start after byte 0.
	}
	v := strconv.AppendInt(hb.buf[L:L], value, base)
	hb.buf = hb.buf[:L+len(v)]
	return hb.slice(hb.buf[L : L+len(v)])
}

// reuseOrAppend writes value over tok's slot when it fits there, avoiding any
// buffer growth; otherwise it appends a fresh slot.
func (mb *kvBuffer) reuseOrAppend(tok headerSlice, value string) headerSlice {
	if tok.len > tokint(len(value)) {
		copy(mb.musttoken(tok), value)
		tok.len = tokint(len(value))
		return tok
	}
	return mb.appendSlice(value)
}

// appendSlice reserves space (growing or flagging OOM) and appends value as a
// new slot.
func (mb *kvBuffer) appendSlice(value string) headerSlice {
	debuglog("http:appendslice:start")
	if !mb.reserve(len(value)) {
		return headerSlice{} // Drop and flag OOM; never panic.
	}
	mb.flags |= flagMangledBuffer
	return mb.mustAppendSlice(value)
}

// reuseOrAppendInt is [kvBuffer.reuseOrAppend]'s integer counterpart.
func (mb *kvBuffer) reuseOrAppendInt(tok headerSlice, value int64, base int) headerSlice {
	n := internal.IntLen(value, base)
	if int(tok.len) >= n {
		// Reuse: format directly over the existing slot. No free space needed
		// since n <= tok.len and the slot already lives inside buf.
		v := strconv.AppendInt(mb.buf[tok.start:tok.start], value, base)
		tok.len = tokint(len(v))
		mb.flags |= flagMangledBuffer
		return tok
	}
	return mb.appendInt(value, base, n)
}

// appendInt reserves space (growing or flagging OOM) and appends value as a new slot.
func (mb *kvBuffer) appendInt(value int64, base, n int) headerSlice {
	if !mb.reserve(n) {
		return headerSlice{} // Drop and flag OOM; never panic.
	}
	mb.flags |= flagMangledBuffer
	return mb.mustAppendInt(value, base)
}

func (mb *kvBuffer) slice(value []byte) headerSlice {
	if value == nil {
		return headerSlice{}
	}
	return bytes2tok(mb.buf, value)
}

func (mb kvBuffer) musttoken(slice headerSlice) []byte {
	return tok2bytes(mb.buf, slice)
}
func (mb *kvBuffer) noKV() argsKV { return argsKV{} }

type tokint = uint16

type headerSlice struct {
	start tokint
	len   tokint
}

type argsKV struct {
	key   headerSlice
	value headerSlice // value start >0 means value is present.
}

// isValid is for stores parsed in place, where offset 0 is the first key so
// only length can signal presence. Empty keys are valid: see valueless cookies.
func (kv argsKV) isValid() bool {
	return kv.key.len > 0 || kv.value.len > 0
}

// isValidHeader is for the append-built [Header] store, where mustAppendSlice
// burns byte 0 so a zero offset means absent. Drops offset-0 pairs otherwise.
func (kv argsKV) isValidHeader() bool { return kv.key.start > 0 }

func (kv *argsKV) invalidate() {
	*kv = argsKV{}
}

// size is the buffer a pair occupies, used to pick the tightest slot to reuse.
func (kv argsKV) size() int { return int(kv.key.len) + int(kv.value.len) }

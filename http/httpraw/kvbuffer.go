package httpraw

import (
	"io"
	"slices"
	"strconv"

	"github.com/soypat/lneto/internal"
)

// KVBuffer is a common key-value store engine for Cookie, Form, and other HTTP abstractions that need
// a key-value store with underlying buffer memory.
type KVBuffer struct {
	buf   []byte
	kvs   []argsKV
	flags Flags
}

func (mb *KVBuffer) free() int { return cap(mb.buf) - len(mb.buf) }

func (mb *KVBuffer) BufferRaw() []byte { return mb.buf }

func (mb *KVBuffer) EnableBufferGrowth(enableGrowth bool) {
	if enableGrowth {
		mb.flags &^= flagNoBufferGrow
	} else {
		mb.flags |= flagNoBufferGrow
	}
}

func (mb *KVBuffer) discardKVs() { mb.kvs = mb.kvs[:0] }

func (mb *KVBuffer) BufferGrowthEnabled() bool { return !mb.flags.HasAny(flagNoBufferGrow) }

func (mb *KVBuffer) ReadFromBytes(buf []byte) error {
	if mb.flags.HasAny(flagMangledBuffer) {
		return errMangledBuffer
	} else if len(buf)+cap(mb.buf) > maxBufLen {
		return errOOM
	}
	free := mb.free()
	if len(buf) > free && !mb.BufferGrowthEnabled() {
		return errOOM
	}
	mb.buf = append(mb.buf, buf...)
	return nil
}

func (mb *KVBuffer) ReadLimited(r io.Reader, limit int) (int, error) {
	if mb.flags.HasAny(flagMangledBuffer) {
		return 0, errMangledBuffer
	} else if mb.flags.HasAny(flagReaderEOF) {
		return 0, io.EOF
	} else if limit <= 0 {
		return 0, io.ErrNoProgress
	} else if len(mb.buf) >= maxBufLen {
		return 0, errOOM
	}
	free := mb.free()
	if limit > free {
		if !mb.BufferGrowthEnabled() {
			return 0, errOOM
		}
		mb.buf = slices.Grow(mb.buf, limit)
	}
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

func (mb *KVBuffer) Reset(buf []byte, kvCap int) {
	if buf == nil {
		mb.buf = mb.buf[:0]
	} else {
		mb.buf = buf
	}
	internal.SliceReuse(&mb.kvs, kvCap)
	mb.flags = mb.flags & flagNoBufferGrow // Only flag persisted is buffer grow config.
}

func (mb *KVBuffer) CopyFrom(src *KVBuffer) {
	mb.buf = append(mb.buf[:0], src.buf...)
	mb.kvs = append(mb.kvs[:0], src.kvs...)
}

// Get returns the value of the first pair matching key.
// Bytes are compared as stored, so if using a Form call [Form.Decode] first when keys may be encoded.
// Returns nil for an absent key and for a valueless pair alike, so use
// [KVBuffer.Present] to tell the two apart.
func (mb *KVBuffer) Get(key string) []byte {
	i := mb.getIdx(key)
	if i < 0 {
		return nil
	}
	return mb.AtValue(i)
}

// ForEach iterates over the cookie's key-value pairs as stored until cb returns false.
func (c *KVBuffer) ForEach(cb func(key, value []byte) bool) {
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
func (mb *KVBuffer) Present(key string) bool { // TODO: rename to Has.
	return mb.getIdx(key) >= 0
}

// Has returns true if key is present, with or without a value.
func (mb *KVBuffer) HasKeyValue(key, value string) bool {
	idx := mb.getIdx(key)
	if idx >= 0 {
		return b2s(mb.musttoken(mb.kvs[idx].value)) == value
	}
	return false
}
func (mb *KVBuffer) Add(key, value string) (enoughSpace bool) {
	mb.appendPair(key, value)
	return mb.getIdx(key) >= 0
}

// Set replaces key's value and invalidates every other pair sharing the key, so
// a following [KVBuffer.Get] sees exactly one value.
//
// It rewrites in place when it can: of the pairs it would invalidate it keeps
// the smallest whose key and value regions both still hold the new pair,
// leaving the roomier regions for a later Set. When none fits the pair is
// appended with [KVBuffer.Add] and the invalidated regions are stranded, since
// nothing here compacts the buffer.
func (mb *KVBuffer) Set(key, value string) (enoughSpace bool) {
	reuse := -1
	for i := range mb.kvs {
		kv := &mb.kvs[i]
		if !kv.isValid() || b2s(mb.musttoken(kv.key)) != key {
			continue
		}
		// A valueless pair holds no value region, so reusing one would write the
		// value over byte 0. Let it fall through to Add, which gives the pair a
		// real region and keeps "ok" distinct from "ok=".
		fits := kv.HasValue() && int(kv.key.len) >= len(key) && int(kv.value.len) >= len(value)
		if fits && (reuse < 0 || kv.size() < mb.kvs[reuse].size()) {
			if reuse >= 0 {
				mb.kvs[reuse].invalidate() // Superseded by a tighter fit.
			}
			reuse = i
			continue
		}
		kv.invalidate()
	}
	if reuse < 0 {
		return mb.Add(key, value)
	}
	mb.overwriteAt(reuse, key, value)
	return true
}

// overwriteAt writes key and value over the regions pair i already owns. The
// caller must have checked both fit; the bytes freed by a shorter pair are
// stranded, not reclaimed.
func (mb *KVBuffer) overwriteAt(i int, key, value string) {
	mb.flags |= flagMangledBuffer
	kv := &mb.kvs[i]
	copy(mb.buf[kv.key.start:], key)
	kv.key.len = tokint(len(key))
	copy(mb.buf[kv.value.start:], value)
	kv.value.len = tokint(len(value))
}

func (mb *KVBuffer) setInternal(key, value []byte) (enoughSpace bool) {
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

func (mb *KVBuffer) Len() int { return len(mb.kvs) }
func (mb *KVBuffer) At(i int) (key, value []byte) {
	kv := mb.kvs[i]
	if !kv.HasValue() {
		return mb.musttoken(kv.key), nil
	}
	return mb.musttoken(kv.key), mb.musttoken(kv.value)
}
func (mb *KVBuffer) setAt(i int, k, v []byte) {
	mb.flags |= flagMangledBuffer
	mb.kvs[i] = argsKV{
		key:   bytes2tok(mb.buf, k),
		value: bytes2tok(mb.buf, v),
	}
}

func (mb *KVBuffer) AtKey(i int) (key []byte) { return mb.musttoken(mb.kvs[i].key) }
func (mb *KVBuffer) AtValue(i int) (key []byte) {
	if !mb.kvs[i].HasValue() {
		return nil
	}
	return mb.musttoken(mb.kvs[i].value)
}

func (mb *KVBuffer) getIdx(key string) int {
	for i, kv := range mb.kvs {
		if kv.isValid() && b2s(mb.musttoken(kv.key)) == key {
			return i
		}
	}
	return -1
}

func (mb *KVBuffer) getInvalidIdx() int {
	for i, kv := range mb.kvs {
		if !kv.isValid() {
			return i
		}
	}
	return -1
}

func (mb *KVBuffer) getInvalidOrKeyIdx(key string) int {
	for i, kv := range mb.kvs {
		if !kv.isValid() || key == b2s(mb.musttoken(kv.key)) {
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
func (mb *KVBuffer) reserve(need int) (enoughSpace bool) {
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

func (mb *KVBuffer) appendPair(key, value string) bool {
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

func (mb *KVBuffer) appendPairInt(key string, value int64, base int) bool {
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

func (mb *KVBuffer) canAddOneKV() (enoughSpace bool) {
	return len(mb.kvs) < cap(mb.kvs) || mb.flags&flagNoBufferGrow == 0
}

func (mb *KVBuffer) mustAppendSlice(value string) headerSlice {
	L := len(mb.buf)
	if L == 0 {
		L++ // Valid key-values start after 0.
	}
	copy(mb.buf[L:L+len(value)], value)
	mb.buf = mb.buf[:L+len(value)]
	return mb.slice(mb.buf[L : L+len(value)])
}

func (hb *KVBuffer) mustAppendInt(value int64, base int) headerSlice {
	L := len(hb.buf)
	if L == 0 {
		L++ // Valid key-values start after byte 0.
	}
	v := strconv.AppendInt(hb.buf[L:L], value, base)
	hb.buf = hb.buf[:L+len(v)]
	return hb.slice(hb.buf[L : L+len(v)])
}

func (mb *KVBuffer) slice(value []byte) headerSlice {
	if value == nil {
		return headerSlice{}
	}
	return bytes2tok(mb.buf, value)
}

func (mb KVBuffer) musttoken(slice headerSlice) []byte {
	return tok2bytes(mb.buf, slice)
}
func (mb *KVBuffer) noKV() argsKV { return argsKV{} }

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

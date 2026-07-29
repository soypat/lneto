package httpraw

import (
	"slices"

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

func (mb *KVBuffer) Get(key string) []byte {
	v := mb.getIdx(key)
	if v < 0 {
		return nil
	}
	return mb.musttoken(mb.kvs[v].value)
}

func (mb *KVBuffer) Present(key string) bool {
	return mb.getIdx(key) >= 0
}
func (mb *KVBuffer) Add(key, value string) bool {
	mb.appendPair(key, value)
	return mb.getIdx(key) >= 0
}

func (mb *KVBuffer) setInternal(key, value []byte) bool {
	if !mb.canAddOneKV() {
		return false
	}
	mb.kvs = append(mb.kvs, argsKV{
		key:   mb.slice(key),
		value: mb.slice(value),
	})
	return true
}

func (mb *KVBuffer) Len() int { return len(mb.kvs) }
func (mb *KVBuffer) Pair(i int) (key, value []byte) {
	kv := mb.kvs[i]
	return mb.musttoken(kv.key), mb.musttoken(kv.value)
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

// reserve ensures need free bytes are available in the buffer, growing it when
// permitted. It accounts for the byte-0 reservation on an empty buffer (see
// mustAppendSlice). It returns false and sets flagOOMReached when the space
// cannot be guaranteed: a tokint offset overflow, or a full buffer with
// flagNoBufferGrow set.
func (mb *KVBuffer) reserve(need int) bool {
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
	// reserve accounts for the byte-0 reservation mustAppendSlice makes on an
	// empty buffer, and drops (flagging OOM) rather than panicking when growth
	// is disabled and space runs out.

	if !mb.canAddOneKV() || !mb.reserve(len(key)+len(value)) {
		return false
	}
	k := mb.mustAppendSlice(key)
	v := mb.mustAppendSlice(value)
	debuglog("http:appendhdr:grow-hdrs")
	mb.kvs = append(mb.kvs, argsKV{
		key:   k,
		value: v,
	})
	return true
}

func (mb *KVBuffer) canAddOneKV() bool {
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

func (mb *KVBuffer) slice(value []byte) headerSlice {
	return bytes2tok(mb.buf, value)
}

func (mb KVBuffer) musttoken(slice headerSlice) []byte {
	return tok2bytes(mb.buf, slice)
}
func (mb *KVBuffer) noKV() argsKV { return argsKV{} }

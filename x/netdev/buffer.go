package netdev

import (
	"sync/atomic"

	"github.com/soypat/lneto/internal"
)

type bufferSelect struct {
	bufs []struct {
		lenAcquire atomic.Int32
		isRx       atomic.Bool
		buf        []byte
	}
}

func (bs *bufferSelect) reset(bufs [][]byte) {
	internal.SliceReuse(&bs.bufs, len(bufs))
	bs.bufs = bs.bufs[:len(bufs)]
	for i := range bs.bufs {
		bs.bufs[i].buf = bufs[i]
	}
	bs.releaseAll()
}

func (bs *bufferSelect) releaseAll() {
	for i := range bs.bufs {
		bs.bufs[i].lenAcquire.Store(0)
	}
}

func (bs *bufferSelect) forceAcquireTx(len int) (buf []byte, dropped int) {
	for i := range bs.bufs {
		if bs.bufs[i].lenAcquire.CompareAndSwap(0, int32(len)) {
			return bs.bufs[i].buf, 0
		}
	}
	bs.bufs[0].isRx.Store(false)
	prevLen := bs.bufs[0].lenAcquire.Load()
	bs.bufs[0].lenAcquire.Store(int32(len))
	return bs.bufs[0].buf, int(prevLen)
}

func (bs *bufferSelect) numRx() (numRx int) {
	for i := range bs.bufs {
		if bs.bufs[i].isRx.Load() && bs.bufs[i].lenAcquire.Load() > 0 {
			numRx++
		}
	}
	return numRx
}

func (bs *bufferSelect) numFree() (numFree int) {
	for i := range bs.bufs {
		if !bs.bufs[i].isRx.Load() && bs.bufs[i].lenAcquire.Load() == 0 {
			numFree++
		}
	}
	return numFree
}

func (bs *bufferSelect) getRx() []byte {
	for i := range bs.bufs {
		if n := bs.bufs[i].lenAcquire.Load(); bs.bufs[i].isRx.Load() && n > 0 {
			return bs.bufs[i].buf[:n]
		}
	}
	return nil
}

func (bs *bufferSelect) acquireNext(len int, isRx bool) []byte {
	if len == 0 {
		return nil
	}
	for i := range bs.bufs {
		if bs.bufs[i].lenAcquire.CompareAndSwap(0, int32(len)) {
			bs.bufs[i].isRx.Store(isRx)
			return bs.bufs[i].buf[:len]
		}
	}
	return nil
}

func (bs *bufferSelect) release(buf []byte) {
	ptr := &buf[0]
	for i := range bs.bufs {
		if &bs.bufs[i].buf[0] == ptr {
			len := bs.bufs[i].lenAcquire.Load()
			if len != 0 && bs.bufs[i].lenAcquire.CompareAndSwap(len, 0) {
				return
			}
			panic("bs:race to release")
		}
	}
	panic("bs:buffer not exist or bad offset")
}

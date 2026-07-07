package netdev

import (
	"sync/atomic"

	"github.com/soypat/lneto/internal"
)

// TODO(soypat): True Zero Copy (TZC)
// TODO(soypat): TZC acheived on redesigning [DevEthernet] to not own any buffers and ask the networking stack for buffers in the callback path. TZC already acheived for Polling path.
// TODO(soypat): TZC in callback path requires redesign of bufferSelect and [Runner] likely.

// lenClaimed marks a slot claimed by putRx before its frame copy completes.
// The slot is published by storing the frame length, which must be the
// claimant's last write so getRx never observes a partially copied frame.
const lenClaimed = -1

// bufferSelect is a fixed pool of frame buffers shared between the runner
// goroutine and the device's receive handler goroutine. Slot ownership is
// arbitrated exclusively through CAS on lenAcquire:
//   - 0: slot free.
//   - lenClaimed(<0): slot claimed by putRx, frame copy in progress.
//   - n>0: slot owned; if isRx is set the slot holds a published Rx frame.
//
// Only goroPutRx may be called concurrently with the other methods; all other
// methods must be called from a single goroutine (the runner's).
type bufferSelect struct {
	// nextSeq generates arrival-order sequence numbers for Rx frames so getRx
	// yields frames in the order they were received, not in slot order.
	nextSeq       atomic.Uint32
	missedAcquire atomic.Uint32
	bufs          []struct {
		lenAcquire atomic.Int32
		isRx       atomic.Bool
		seq        uint32
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
	bs.nextSeq.Store(0)
	bs.missedAcquire.Store(0)
	for i := range bs.bufs {
		bs.bufs[i].isRx.Store(false)
		bs.bufs[i].lenAcquire.Store(0)
	}
}

// acquire claims a free slot for exclusive use by the caller and returns it
// sized to len. Returns nil if no slot is free or len exceeds slot size.
func (bs *bufferSelect) acquire(len int) []byte {
	if len == 0 {
		bs.missedAcquire.Add(1)
		return nil
	}
	for i := range bs.bufs {
		if len > cap(bs.bufs[i].buf) {
			break // Length too long, would need allocation.
		}
		if bs.bufs[i].lenAcquire.CompareAndSwap(0, int32(len)) {
			return bs.bufs[i].buf[:len]
		}
	}
	bs.missedAcquire.Add(1)
	return nil
}

// goroPutRx copies an incoming frame into a free slot and publishes it for getRx.
// It is the only method safe to call concurrently with the runner goroutine.
// Returns false if the frame is empty, oversize or no slot is free.
func (bs *bufferSelect) goroPutRx(frame []byte) bool {
	n := len(frame)
	if n == 0 {
		return false
	}
	for i := range bs.bufs {
		if n > cap(bs.bufs[i].buf) {
			return false
		}
		if bs.bufs[i].lenAcquire.CompareAndSwap(0, lenClaimed) {
			bs.bufs[i].isRx.Store(true)
			bs.bufs[i].seq = bs.nextSeq.Add(1)
			copy(bs.bufs[i].buf, frame)
			bs.bufs[i].lenAcquire.Store(int32(n)) // publish: must be last write.
			return true
		}
	}
	return false
}

func (bs *bufferSelect) numFree() (numFree int) {
	for i := range bs.bufs {
		if bs.bufs[i].lenAcquire.Load() == 0 {
			numFree++
		}
	}
	return numFree
}

// getRx returns the oldest published Rx frame, or nil if none is pending.
func (bs *bufferSelect) getRx() []byte {
	oldest := -1
	var oldestSeq uint32
	for i := range bs.bufs {
		n := bs.bufs[i].lenAcquire.Load()
		if n > 0 && bs.bufs[i].isRx.Load() &&
			(oldest < 0 || lessThan(bs.bufs[i].seq, oldestSeq)) {
			oldest = i
			oldestSeq = bs.bufs[i].seq
		}
	}
	if oldest < 0 {
		return nil
	}
	return bs.bufs[oldest].buf[:bs.bufs[oldest].lenAcquire.Load()]
}

func (bs *bufferSelect) release(buf []byte) {
	ptr := &buf[0]
	for i := range bs.bufs {
		if &bs.bufs[i].buf[0] == ptr {
			// Clear isRx while still owning the slot so the next claimant
			// never inherits a stale Rx mark.
			bs.bufs[i].isRx.Store(false)
			len := bs.bufs[i].lenAcquire.Load()
			if len > 0 && bs.bufs[i].lenAcquire.CompareAndSwap(len, 0) {
				return
			}
			panic("bs:race to release")
		}
	}
	panic("bs:buffer not exist or bad offset")
}

func lessThan(aIsLessThan, b uint32) bool {
	return int32(aIsLessThan-b) < 0
}

package tcp

import (
	"errors"

	"github.com/soypat/lneto/internal"
)

const (
	// this must be at least 2 for buffer to work.
	minBufferSize = 2
)

// ringTx is a ring buffer with retransmission queue functionality added.
//
//	|   acked(free)  |          sent         |          unsent          |             free       |
//	0       freeEnd=first.off       last.end==unsent.off        freeStart=unsent.end         Size()
type ringTx struct {
	// rawbuf contains the ring buffer of ordered bytes. It should be the size of the window.
	rawbuf []byte
	// packets contains
	packets []ringidx
	// unsentOff is the offset of start of unsent data in rawbuf.
	unsentoff int
	// unsentend is the offset of end of unsent data in rawbuf. If zero then unsent buffer is empty.
	unsentend int
	// sentoff is the offset of start of sent data in rawbuf.
	sentoff int
	// sentend is the offset of end of sent data in rawbuf. If zero then sent buffer is empty.
	sentend int
	seq     Value
	// always empty ring.
	emptyRing ringidx
}

// ringidx represents packet data inside RingTx
type ringidx struct {
	// off is data start offset of packet data inside buf. Follows [internal.Ring] semantics.
	off int
	// end is the ringed data end offset, non-inclusive. Follows [internal.Ring] semantics.
	end int
	// seq is the sequence number of the packet.
	seq Value
	// time is a measure of the instant of time message was sent at.
}

// Reset resets the RingTx's internal state to use buf as the main ring buffer and creates or reuses
// the packet ring buffer.
func (rx *ringTx) Reset(buf []byte, maxqueuedPackets int, seq Value) error {
	if maxqueuedPackets <= 0 {
		return errors.New("queued packets <=0")
	} else if len(buf) < minBufferSize || len(buf) < maxqueuedPackets {
		return errors.New("invalid buffer size")
	}
	if cap(rx.packets) < maxqueuedPackets {
		rx.packets = make([]ringidx, maxqueuedPackets)
	}
	*rx = ringTx{
		rawbuf:  buf,
		packets: rx.packets[:maxqueuedPackets],
		seq:     seq,
	}
	for i := range rx.packets {
		rx.packets[i].markRcvd()
	}
	return nil
}

// ResetOrReuse is identical to a call to [ringTx.Reset] with the additional detail that
// the zero value of buf (nil) and maxQueuedPackets (0) will selectively reuse existing data buffer and/or packet index buffer.
func (rx *ringTx) ResetOrReuse(buf []byte, maxQueuedPackets int, ack Value) error {
	if buf == nil {
		buf = rx.rawbuf
	}
	if maxQueuedPackets == 0 {
		maxQueuedPackets = len(rx.packets)
	}
	return rx.Reset(buf, maxQueuedPackets, ack)
}

// Size returns the total storage space of the transmission buffer.
func (tx *ringTx) Size() int { return len(tx.rawbuf) }

// Free returns the total available space for Write calls.
func (tx *ringTx) Free() int {
	r := tx.sentAndUnsentBuffer()
	return r.Free()
}

// Buffered returns the amount of unsent bytes.
func (tx *ringTx) Buffered() int {
	r, _ := tx.unsentRing()
	return r.Buffered()
}

// BufferedSent returns the total amount of bytes sent but not acked.
func (tx *ringTx) BufferedSent() int {
	r, _ := tx.sentRing()
	return r.Buffered()
}

// Write writes data to the underlying unsent data ring buffer.
func (tx *ringTx) Write(b []byte) (n int, err error) {
	r, lim := tx.unsentRing()
	n, err = r.WriteLimited(b, lim)
	if err != nil {
		return 0, err
	}
	tx.unsentend = tx.addEnd(tx.unsentend, n)
	return n, err
}

// MakePacket reads from the unsent data ring buffer and generates a new packet segment.
// It fails if the sent packet queue is full.
func (tx *ringTx) MakePacket(b []byte) (int, Value, error) {
	nxtpkt := tx.nextPkt()
	if tx.nextPkt() < 0 {
		return 0, 0, errors.New("queue full")
	}
	r, _ := tx.unsentRing()
	start := r.Off
	n, err := r.Read(b)
	if err != nil {
		return n, 0, err
	}
	pkt := &tx.packets[nxtpkt]

	off := tx.addEnd(tx.unsentoff, n)
	tx.unsentoff = off
	tx.sentend = off
	if off == tx.unsentend {
		tx.unsentend = 0 // Mark unsent as being empty.
	}
	pkt.off = start
	pkt.end = off

	// Sequence number updates.
	oldseq := tx.seq
	newseq := Add(oldseq, Size(n))
	tx.seq = newseq
	pkt.seq = newseq
	return n, oldseq, nil
}

// RecvSegment processes an incoming segment and updates the sent packet queue
func (tx *ringTx) RecvACK(ack Value) error {
	if ack.LessThan(tx.seq) {
		return errors.New("old packet")
	}
	first := tx.firstPkt()
	if first < 0 {
		return errors.New("no packets to ack")
	}
	hiSeq := tx.pkt(first).seq
	for i := 0; i < len(tx.packets); i++ {
		pkt := &tx.packets[i]
		if pkt.sent() && pkt.seq.LessThanEq(ack) {
			if hiSeq.LessThan(pkt.seq) {
				tx.sentoff = pkt.end
				hiSeq = pkt.seq
			}
			pkt.markRcvd()
		}
	}
	firstAcked := !tx.pkt(first).sent()
	if firstAcked && tx.sentoff == tx.sentend {
		// All data acked.
		tx.sentend = 0
	}
	return nil
}

func (tx *ringTx) sentAndUnsentBuffer() internal.Ring {
	end := tx.unsentend
	if end == 0 {
		end = tx.sentend
	}
	return internal.Ring{Buf: tx.rawbuf, Off: tx.sentoff, End: end}
}

func (tx *ringTx) unsentRing() (internal.Ring, int) {
	return tx.ring(tx.unsentoff, tx.unsentend), tx.sentoff
}

func (tx *ringTx) sentRing() (internal.Ring, int) {
	return tx.ring(tx.sentoff, tx.sentend), tx.unsentoff // unsentoff should match with sentend, so no writes can be performed to sentring.
}

func (tx *ringTx) ring(off, end int) internal.Ring {
	return internal.Ring{Buf: tx.rawbuf, Off: off, End: end}
}

// addEnd adds two integers together and wraps the value around the ring's buffer size.
// Result of addEnd will never be 0 unless arguments are (0,0).
func (tx *ringTx) addEnd(a, b int) int {
	result := a + b
	if result > len(tx.rawbuf) {
		result -= len(tx.rawbuf)
	}
	return result
}

func (tx *ringTx) addOff(a, b int) int {
	result := a + b
	if result >= len(tx.rawbuf) {
		result -= len(tx.rawbuf)
	}
	return result
}

func (tx *ringTx) pkt(i int) *ringidx {
	if i == -1 {
		return &tx.emptyRing
	} else if i < 0 || i >= len(tx.packets) {
		panic("invalid packet index")
	}
	return &tx.packets[i]
}

func (tx *ringTx) firstPkt() int {
	var seq Value
	idx := -1
	for i := 0; i < len(tx.packets); i++ {
		pkt := &tx.packets[i]
		if pkt.sent() && (idx == -1 || seq.LessThan(pkt.seq)) {
			seq = pkt.seq
			idx = i
		}
	}
	return idx
}

func (tx *ringTx) lastPkt() int {
	var seq Value
	idx := -1
	for i := 0; i < len(tx.packets); i++ {
		pkt := &tx.packets[i]
		if pkt.sent() && (idx == -1 || pkt.seq.LessThan(seq)) {
			seq = pkt.seq
			idx = i
		}
	}
	return idx
}

func (tx *ringTx) nextPkt() int {
	idx := -1
	for i := 0; i < len(tx.packets); i++ {
		pkt := &tx.packets[i]
		if !pkt.sent() {
			idx = i
			break
		}
	}
	return idx
}

// lims returns the limits of free|sent|unsent buffers.
// Example:
//
//	|   acked(free)  |          sent         |          unsent          |             free       |
//	0       freeEnd=first.off       last.end==unsent.off        freeStart=unsent.end         Size()
func (tx *ringTx) lims() (freeStart, freeEnd, sentEndorUnsentStart int) {
	freeStart = tx.unsentend
	if freeStart == 0 {
		freeStart = tx.unsentoff
	}
	first := tx.pkt(tx.firstPkt())
	if first.sent() {
		freeEnd = first.off
		sentEndorUnsentStart = tx.unsentoff
	} else if tx.unsentend != 0 {
		// sent section empty and unsent not empty.
		freeEnd = tx.unsentoff
		sentEndorUnsentStart = tx.unsentoff
	} else {
		freeEnd = tx.unsentoff
		sentEndorUnsentStart = tx.unsentoff
	}
	return freeStart, freeEnd, sentEndorUnsentStart
}

func (pkt *ringidx) sent() bool {
	return pkt.end != 0 || pkt.off != 0
}

func (pkt *ringidx) markRcvd() {
	*pkt = ringidx{}
	// pkt.end = 0
	// pkt.off = 0
}

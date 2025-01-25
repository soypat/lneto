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
type ringTx struct {
	// rawbuf contains the ring buffer of ordered bytes. It should be the size of the window.
	rawbuf []byte
	// packets contains
	packets []ringidx
	// unsentOff is the offset of start of unsent data into rawbuf.
	unsentoff int
	// unsentend is the offset of end of unsent data in rawbuf.
	unsentend int
	seq       Value
	// always empty ring.
	emptyRing ringidx
}

// ringidx represents packet data inside RingTx
type ringidx struct {
	// off is data start offset of packet data inside buf.
	off int
	// end is the ringed data end offset, non-inclusive.
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

// Buffered returns the amount of unsent bytes.
func (tx *ringTx) Buffered() int {
	r := tx.unsentRing()
	return r.Buffered()
}

// BufferedSent returns the total amount of bytes sent but not acked.
func (tx *ringTx) BufferedSent() int {
	r := tx.sentRing()
	return r.Buffered()
}

// Write writes data to the underlying unsent data ring buffer.
func (tx *ringTx) Write(b []byte) (n int, err error) {
	first := tx.pkt(tx.firstPkt())
	r := tx.unsentRing()
	if !first.sent() {
		// No packets in queue case.
		n, err = r.Write(b)
	} else {
		n, err = r.WriteLimited(b, first.off)
	}
	if err != nil {
		return 0, err
	}
	tx.unsentend = tx.addOff(tx.unsentend, n)
	return n, err
}

// MakePacket reads from the unsent data ring buffer and generates a new packet segment.
// It fails if the sent packet queue is full.
func (tx *ringTx) MakePacket(b []byte) (int, Value, error) {
	nxtpkt := tx.nextPkt()
	if tx.nextPkt() < 0 {
		return 0, 0, errors.New("queue full")
	}
	r := tx.unsentRing()
	start := r.Off
	n, err := r.Read(b)
	if err != nil {
		return n, 0, err
	}
	plen := Value(n)
	seq := tx.seq
	tx.packets[nxtpkt].off = start
	tx.packets[nxtpkt].end = tx.addOff(start, n)
	tx.packets[nxtpkt].seq = seq + plen

	tx.unsentoff = tx.addOff(tx.unsentoff, n)
	tx.seq += plen
	return n, seq, nil
}

// RecvSegment processes an incoming segment and updates the sent packet queue
func (tx *ringTx) RecvACK(ack Value) error {
	for i := range tx.packets {
		pkt := &tx.packets[i]
		if pkt.sent() && pkt.seq.LessThanEq(ack) {
			pkt.markRcvd()
		}
	}
	return nil
}

func (tx *ringTx) unsentRing() internal.Ring {
	off := tx.unsentoff
	if off == tx.unsentend && off != 0 {
		off--
	}
	return tx.ring(off, tx.unsentend)
}

func (tx *ringTx) sentRing() internal.Ring {
	first := tx.pkt(tx.firstPkt())
	if !first.sent() {
		return internal.Ring{}
	}
	last := tx.pkt(tx.lastPkt())
	return tx.ring(first.off, last.end)
}

func (tx *ringTx) ring(off, end int) internal.Ring {
	return internal.Ring{Buf: tx.rawbuf, Off: off, End: end}
}

// addOff adds two integers together and wraps the value around the ring's buffer size.
func (tx *ringTx) addOff(a, b int) int {
	off := a + b
	if off >= len(tx.rawbuf) {
		off -= len(tx.rawbuf)
	}
	return off
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
	seq := tx.packets[0].seq
	idx := -1
	for i := 0; i < len(tx.packets); i++ {
		pkt := &tx.packets[i]
		if pkt.sent() && seq.LessThanEq(pkt.seq) {
			seq = pkt.seq
			idx = i
		}
	}
	return idx
}

func (tx *ringTx) lastPkt() int {
	seq := tx.packets[0].seq
	idx := -1
	for i := 0; i < len(tx.packets); i++ {
		pkt := &tx.packets[i]
		if pkt.sent() && pkt.seq.LessThanEq(seq) {
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

func (pkt *ringidx) sent() bool {
	return pkt.end != 0 || pkt.off != 0
}

func (pkt *ringidx) markRcvd() {
	*pkt = ringidx{}
	// pkt.end = 0
	// pkt.off = 0
}

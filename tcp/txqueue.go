package tcp

import (
	"errors"
	"time"

	"github.com/soypat/lneto/internal"
)

func newRingTx(buf []byte, maxQueuedPackets int) *ringTx {
	if maxQueuedPackets <= 0 || len(buf) < 2 || len(buf) < maxQueuedPackets {
		panic("invalid argument to NewRingTx")
	}
	return &ringTx{
		rawbuf:  buf,
		packets: make([]ringidx, maxQueuedPackets),
	}
}

// ringTx is a ring buffer with retransmission queue functionality added.
type ringTx struct {
	// rawbuf contains the ring buffer of ordered bytes. It should be the size of the window.
	rawbuf []byte
	// packets contains
	packets []ringidx
	// _firstPkt is the index of the oldest packet in the packets field.
	_firstPkt int
	_lastPkt  int
	// unsentOff is the offset of start of unsent data into rawbuf.
	unsentoff int
	// unsentend is the offset of end of unsent data in rawbuf.
	unsentend int
}

// ringidx represents packet data inside RingTx
type ringidx struct {
	// off is data start offset of packet data inside buf.
	off int
	// end is the ringed data end offset, non-inclusive.
	end int
	// seq is the sequence number of the packet.
	seq Value
	t   time.Time
	// acked flags if this packet has been acknowledged. Useful for SACK (selective acknowledgement)
	// acked bool
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
	first := tx.packets[tx._firstPkt]
	r := tx.unsentRing()
	if first.off < 0 {
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
func (tx *ringTx) MakePacket(b []byte) (int, error) {
	nxtpkt := (tx._lastPkt + 1) % len(tx.packets)
	if tx._firstPkt == nxtpkt {
		return 0, errors.New("packet queue full")
	}

	r := tx.unsentRing()
	start := r.Off
	n, err := r.Read(b)
	if err != nil {
		return n, err
	}
	last := &tx.packets[tx._lastPkt]
	rlast := tx.packetRing(tx._lastPkt)
	tx.packets[nxtpkt].off = start
	tx.packets[nxtpkt].end = tx.addOff(start, n)
	tx.packets[nxtpkt].seq = last.seq + Value(rlast.Buffered())
	tx._lastPkt = nxtpkt
	tx.unsentoff = tx.addOff(tx.unsentoff, n)
	return n, nil
}

// IsQueueFull returns true if the sent packet queue is full in which
// case a call to ReadPacket is guaranteed to fail.
func (tx *ringTx) IsQueueFull() bool {
	return tx._firstPkt == (tx._lastPkt+1)%len(tx.packets)
}

func (tx *ringTx) packetRing(i int) internal.Ring {
	pkt := tx.packets[i]
	if pkt.off < 0 {
		return internal.Ring{}
	}
	return tx.ring(pkt.off, pkt.end)
}

// RecvSegment processes an incoming segment and updates the sent packet queue
func (tx *ringTx) RecvACK(ack Value) error {
	i := tx._firstPkt
	for {
		pkt := &tx.packets[i]
		if ack >= pkt.seq {
			// Packet was received by remote. Mark it as acked.
			pkt.off = -1
			tx._firstPkt++
			continue
		}
		if i == tx._lastPkt {
			break
		}
		i = (i + 1) % len(tx.packets)
	}
	return nil
}

func (tx *ringTx) unsentRing() internal.Ring {
	return tx.ring(tx.unsentoff, tx.unsentend)
}

func (tx *ringTx) freeRing() (internal.Ring, int) {
	return tx.ring(tx.unsentoff, tx.unsentend), 0
}

func (tx *ringTx) a() {

}

func (tx *ringTx) sentRing() internal.Ring {
	first := tx.packets[tx._firstPkt]
	if first.off < 0 {
		return tx.ring(0, 0)
	}
	last := tx.packets[tx._lastPkt]
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

func (tx *ringTx) firstPkt() int {
	seq := tx.packets[0].seq
	idx := -1
	for i := 0; i < len(tx.packets); i++ {
		pkt := &tx.packets[i]
		if (pkt.end != 0 || pkt.off != 0) && seq.LessThanEq(pkt.seq) {
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
		if (pkt.end != 0 || pkt.off != 0) && pkt.seq.LessThanEq(seq) {
			seq = pkt.seq
			idx = i
		}
	}
	return idx
}

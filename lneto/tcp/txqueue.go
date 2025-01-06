package tcp

import (
	"errors"
	"time"

	"github.com/soypat/tseq/internal"
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
	// firstPkt is the index of the oldest packet in the packets field.
	firstPkt int
	lastPkt  int
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
func (tx *ringTx) Write(b []byte) (int, error) {
	first := tx.packets[tx.firstPkt]
	r := tx.unsentRing()
	if first.off < 0 {
		// No packets in queue case.
		return r.Write(b)
	}
	return r.WriteLimited(b, first.off)
}

// ReadPacket reads from the unsent data ring buffer and generates a new packet segment.
// It fails if the sent packet queue is full.
func (tx *ringTx) NewPacketAndRead(b []byte) (int, error) {
	nxtpkt := (tx.lastPkt + 1) % len(tx.packets)
	if tx.firstPkt == nxtpkt {
		return 0, errors.New("packet queue full")
	}

	r := tx.unsentRing()
	start := r.Off
	n, err := r.Read(b)
	if err != nil {
		return n, err
	}
	last := &tx.packets[tx.lastPkt]
	rlast := tx.packetRing(tx.lastPkt)
	tx.packets[nxtpkt].off = start
	tx.packets[nxtpkt].end = r.Off
	tx.packets[nxtpkt].seq = last.seq + Value(rlast.Buffered())
	tx.lastPkt = nxtpkt
	tx.unsentoff = r.Off
	return n, nil
}

// IsQueueFull returns true if the sent packet queue is full in which
// case a call to ReadPacket is guaranteed to fail.
func (tx *ringTx) IsQueueFull() bool {
	return tx.firstPkt == (tx.lastPkt+1)%len(tx.packets)
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
	i := tx.firstPkt
	for {
		pkt := &tx.packets[i]
		if ack >= pkt.seq {
			// Packet was received by remote. Mark it as acked.
			pkt.off = -1
			tx.firstPkt++
			continue
		}
		if i == tx.lastPkt {
			break
		}
		i = (i + 1) % len(tx.packets)
	}
	return nil
}

func (tx *ringTx) unsentRing() internal.Ring {
	return tx.ring(tx.unsentoff, tx.unsentend)
}

func (tx *ringTx) sentRing() internal.Ring {
	first := tx.packets[tx.firstPkt]
	if first.off < 0 {
		return tx.ring(0, 0)
	}
	last := tx.packets[tx.lastPkt]
	return tx.ring(first.off, last.end)
}

func (tx *ringTx) ring(off, end int) internal.Ring {
	return internal.Ring{Buf: tx.rawbuf, Off: off, End: end}
}

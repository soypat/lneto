package tcp

import (
	"log/slog"

	"github.com/soypat/lneto"
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
	// unsentOff is the offset of start of unsent data in rawbuf.
	unsentoff int
	// unsentend is the offset of end of unsent data in rawbuf. If zero then unsent buffer is empty.
	unsentend int
	// sentoff is the offset of start of sent data in rawbuf.
	sentoff int
	// sentend is the offset of end of sent data in rawbuf. If zero then sent buffer is empty.
	sentend int
	slist   sentlist
	// seq     Value
	// always empty ring.
	emptyRing ringidx
	iss       Value
}

// ringidx represents packet data inside RingTx
type ringidx struct {
	// off is data start offset of packet data inside buf. Follows [internal.Ring] semantics.
	off int
	// end is the ringed data end offset, non-inclusive. Follows [internal.Ring] semantics.
	end int
	// seq is the sequence number of the first byte in the packet.
	seq Value
	// size is the size of the packet in bytes.
	size Size
	// time is a measure of the instant of time message was sent at.
}

// Reset resets the RingTx's internal state to use buf as the main ring buffer and creates or reuses
// the packet ring buffer.
func (rtx *ringTx) Reset(buf []byte, maxqueuedPackets int, iss Value) error {
	buf = buf[:len(buf):len(buf)] // safely omit capacity section.
	if maxqueuedPackets <= 0 {
		return lneto.ErrInvalidConfig
	} else if len(buf) < minBufferSize || len(buf) < maxqueuedPackets {
		return lneto.ErrShortBuffer
	}

	*rtx = ringTx{
		rawbuf: buf,
		slist:  rtx.slist,
	}
	rtx.slist.Reset(maxqueuedPackets, iss)
	rtx.iss = iss
	return nil
}

// ResetOrReuse is identical to a call to [ringTx.Reset] with the additional detail that
// the zero value of buf (nil) and maxQueuedPackets (0) will selectively reuse existing data buffer and/or packet index buffer.
func (rtx *ringTx) ResetOrReuse(buf []byte, maxQueuedPackets int, ack Value) error {
	if buf == nil {
		buf = rtx.rawbuf
	}
	if maxQueuedPackets == 0 {
		maxQueuedPackets = cap(rtx.slist.pkts)
	}
	return rtx.Reset(buf, maxQueuedPackets, ack)
}

// Size returns the total storage space of the transmission buffer.
func (rtx *ringTx) Size() int { return len(rtx.rawbuf) }

// Free returns the total available space for Write calls.
func (rtx *ringTx) Free() int {
	r := rtx.sentAndUnsentBuffer()
	return r.Free()
}

// BufferedUnsent returns the amount of written but unsent bytes.
func (rtx *ringTx) BufferedUnsent() int {
	r, _ := rtx.unsentRing()
	return r.Buffered()
}

// BufferedSent returns the total amount of bytes sent but not acked.
func (rtx *ringTx) BufferedSent() int {
	r, _ := rtx.sentRing()
	return r.Buffered()
}

// Write writes data to the underlying unsent data ring buffer.
func (rtx *ringTx) Write(b []byte) (n int, err error) {
	unsent, lim := rtx.unsentRing()
	if rtx.sentend == 0 {
		n, err = unsent.Write(b) // catches case where limit matches with end when both buffers empty
	} else {
		n, err = unsent.WriteLimited(b, lim)
	}
	if err != nil {
		return 0, err
	}
	rtx.unsentend = unsent.End
	return n, err
}

// MakePacket reads from the unsent data ring buffer and generates a new packet segment.
// It fails if the sent packet queue is full.
func (rtx *ringTx) MakePacket(b []byte, currentSeq Value) (int, error) {
	free := rtx.slist.Free()
	if free == 0 {
		return 0, lneto.ErrBufferFull
	}
	endSeq, ok := rtx.sentEndSeq()
	if ok && currentSeq.LessThan(endSeq) {
		internal.LogAttrs(nil, slog.LevelError, "txqueue:seq<endseq", slog.Uint64("seq", uint64(currentSeq)), slog.Uint64("endseq", uint64(endSeq)))
		return 0, lneto.ErrBug
	}
	// Reading unsent ring consumes unsent and converts it to "sent".
	unsent, _ := rtx.unsentRing()
	oldUnsentOff := unsent.Off
	n, err := unsent.Read(b)
	if err != nil {
		return 0, err
	}
	// unsentOff increases, sentEnd matches this value.
	// Start of buffer will be SENT, end of buffer will be UNSENT(or empty).
	// Packet generated has offset at old unsentOff.
	size := rtx.Size()
	pkt := rtx.slist.AddPacket(n, oldUnsentOff, size, currentSeq)
	if pkt.off != oldUnsentOff || pkt.end != addEnd(pkt.off, n, size) {
		panic("invalid generated packet")
	}
	if rtx.sentend == 0 {
		// Sent was previously empty, offset is reset from start of this packet
		rtx.sentoff = pkt.off
	}
	if unsent.End == 0 {
		// Fully read unsent buffer so offset is reset, need to recalculate.
		rtx.unsentoff = pkt.end
	} else {
		rtx.unsentoff = unsent.Off
	}
	rtx.sentend = pkt.end
	rtx.unsentend = unsent.End
	return n, nil
}

// RecvSegment processes an incoming segment and updates the sent packet queue
func (rtx *ringTx) RecvACK(ack Value) error {
	size := rtx.Size()
	err := rtx.slist.RecvAck(ack, size)
	if err != nil {
		return err
	}
	oldest := rtx.slist.Oldest()
	newest := rtx.slist.Newest()
	if oldest == nil {
		// All sent data received, discard.
		rtx.sentend = 0
	} else {
		rtx.sentoff = oldest.off
		rtx.sentend = newest.end
	}
	rtx.consolidateBufs()
	return nil
}

func (rtx *ringTx) sentAndUnsentBuffer() internal.Ring {
	off := rtx.sentoff
	end := rtx.unsentend
	if end == 0 {
		end = rtx.sentend
	} else if rtx.sentend == 0 {
		off = rtx.unsentoff
	}
	return internal.Ring{Buf: rtx.rawbuf, Off: off, End: end}
}

func (rtx *ringTx) unsentRing() (internal.Ring, int) {
	return rtx.ring(rtx.unsentoff, rtx.unsentend), rtx.sentoff
}

func (rtx *ringTx) sentRing() (internal.Ring, int) {
	return rtx.ring(rtx.sentoff, rtx.sentend), rtx.unsentoff // unsentoff should match with sentend, so no writes can be performed to sentring.
}

func (rtx *ringTx) ring(off, end int) internal.Ring {
	return internal.Ring{Buf: rtx.rawbuf, Off: off, End: end}
}

// addEnd adds two integers together and wraps the value around the ring's buffer size.
// Result of addEnd will never be 0 unless arguments are (0,0).
func (rtx *ringTx) addEnd(a, b int) int { return addEnd(a, b, len(rtx.rawbuf)) }

func (rtx *ringTx) consolidateBufs() {
	unsentEmpty := rtx.unsentend == 0
	sentEmpty := rtx.sentend == 0
	if unsentEmpty && sentEmpty {
		// reset start of buffers.
		rtx.sentoff = 0
		rtx.unsentoff = 0
	}
}

func (rtx *ringTx) sentEndSeq() (Value, bool) {
	newest := rtx.slist.Newest()
	if newest == nil {
		return 0, false
	}
	return newest.endSeq(), true
}

// lims returns the limits of free|sent|unsent buffers.
// Example:
//
//	|   acked(free)  |          sent         |          unsent          |             free       |
//	0       freeEnd=first.off       last.end==unsent.off        freeStart=unsent.end         Size()
func (tx *ringTx) lims() (unsentStart, unsentEnd, sentStart, sentEnd int) {
	return tx.unsentoff, tx.unsentend, tx.sentoff, tx.sentend
}

func (pkt *ringidx) sent() bool {
	return pkt.end != 0 || pkt.off != 0
}

func (pkt *ringidx) markRcvd() {
	*pkt = ringidx{}
	// pkt.end = 0
	// pkt.off = 0
}

func (pkt *ringidx) isRecvd() bool {
	return pkt.size == 0
}

func (pkt *ringidx) endSeq() Value {
	return Add(pkt.seq, pkt.size)
}

// sentlist stores information about sent TCP packets
type sentlist struct {
	// ssn is an auxiliary sequence counter.
	// If there are no packets then ssn is reset to be the end sequence number of the last acked packet such that
	// the next packet added has their
	ssn Value
	// pkts is an ordered list of packets. First packet is 'oldest' packet, last packet is the most recently sent.
	pkts []ringidx
}

// Reset clears the sent packet list and prepares it for reuse.
// The packet queue capacity is set to exactly pktQueueSize.
// The initial sequence number is set to iss.
func (sl *sentlist) Reset(pktQueueSize int, iss Value) {
	internal.SliceReuse(&sl.pkts, pktQueueSize)
	sl.ssn = iss
}

func (sl sentlist) Newest() *ringidx {
	if len(sl.pkts) == 0 {
		return nil
	}
	return &sl.pkts[len(sl.pkts)-1]
}

func (sl sentlist) Oldest() *ringidx {
	if len(sl.pkts) == 0 {
		return nil
	}
	return &sl.pkts[0]
}

func (sl *sentlist) EndSeq() Value {
	seq := sl.ssn
	lastPkt := sl.Newest()
	if lastPkt != nil {
		seq = lastPkt.endSeq()
	}
	return seq
}

func (sl *sentlist) Free() int {
	return cap(sl.pkts) - len(sl.pkts)
}

func (sl *sentlist) AddPacket(datalen, off, bufsize int, seq Value) *ringidx {
	free := sl.Free()
	if free == 0 {
		panic("pkt buffer full")
	}
	lastPkt := sl.Newest()
	if lastPkt != nil && ((off != 0 && off != lastPkt.end) || (off == 0 && lastPkt.end != bufsize)) {
		panic("new sent packet offset must match last sent packet end")
	}
	sl.pkts = append(sl.pkts, ringidx{
		off:  off,
		end:  addEnd(off, datalen, bufsize),
		seq:  seq,
		size: Size(datalen),
	})
	return &sl.pkts[len(sl.pkts)-1]
}

func (sl *sentlist) RecvAck(ack Value, bufsize int) error {
	newest := sl.Newest()
	if newest == nil {
		return lneto.ErrPacketDrop
	}
	endseq := newest.endSeq()
	if endseq.LessThan(ack) {
		return lneto.ErrPacketDrop
	}
	// Mark fully acked.
	for i := 0; i < len(sl.pkts); i++ {
		pkt := &sl.pkts[i]
		endseq := pkt.endSeq()
		isFullyAcked := endseq.LessThanEq(ack)
		if isFullyAcked {
			sl.ssn = endseq
			pkt.markRcvd()
		} else {
			break
		}
	}
	sl.removeRecvd()
	maybePartial := sl.Oldest()
	if maybePartial == nil {
		return nil // No more packets, all acked.
	}
	totalAcked := int32(ack - maybePartial.seq)
	isPartial := totalAcked > 0
	if !isPartial {
		return nil // Not a partial packet ack.
	}
	maybePartial.off = addOff(maybePartial.off, int(totalAcked), bufsize)
	maybePartial.size -= Size(totalAcked)
	maybePartial.seq += Value(totalAcked)
	return nil
}

func (sl *sentlist) removeRecvd() {
	if !sl.Oldest().isRecvd() {
		return // No packets to remove.
	}
	off := 0
	for i := 0; i < len(sl.pkts); i++ {
		if sl.pkts[i].isRecvd() {
			continue
		} else {
			sl.pkts[off] = sl.pkts[i]
			off++
		}
	}
	sl.pkts = sl.pkts[:off]
}

// addEnd adds two integers together and wraps the value around the ring's buffer size.
// Result of addEnd will never be 0 unless arguments are (0,0).
func addEnd(a, b int, size int) int {
	result := a + b
	if result > size {
		result -= size
	}
	return result
}

func addOff(a, b int, size int) int {
	result := a + b
	if result >= size {
		result -= size
	}
	return result
}

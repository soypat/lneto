package tcp

import (
	"errors"
	"fmt"

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
		return errors.New("queued packets <=0")
	} else if len(buf) < minBufferSize || len(buf) < maxqueuedPackets {
		return errors.New("invalid buffer size")
	}
	if cap(rtx.packets) < maxqueuedPackets {
		rtx.packets = make([]ringidx, maxqueuedPackets)
	}
	*rtx = ringTx{
		rawbuf:  buf,
		packets: rtx.packets[:maxqueuedPackets],
	}
	for i := range rtx.packets {
		rtx.packets[i].markRcvd()
	}
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
		maxQueuedPackets = len(rtx.packets)
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

// Buffered returns the amount of written but unsent bytes.
func (rtx *ringTx) Buffered() int {
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
	r, lim := rtx.unsentRing()
	n, err = r.WriteLimited(b, lim)
	if err != nil {
		return 0, err
	}
	rtx.unsentend = rtx.addEnd(rtx.unsentend, n)
	return n, err
}

// MakePacket reads from the unsent data ring buffer and generates a new packet segment.
// It fails if the sent packet queue is full.
func (rtx *ringTx) MakePacket(b []byte, currentSeq Value) (int, error) {
	nxtpkt := rtx.nextPkt()
	if nxtpkt < 0 {
		return 0, errors.New("queue full")
	}
	endSeq, ok := rtx.endSeq()
	if ok && currentSeq.LessThan(endSeq) {
		return 0, errors.New("sequence number less than last sequence number")
	}
	r, _ := rtx.unsentRing()
	start := r.Off
	n, err := r.Read(b)
	if err != nil {
		return n, err
	}
	pkt := &rtx.packets[nxtpkt]

	off := rtx.addEnd(rtx.unsentoff, n)
	rtx.unsentoff = off
	rtx.sentend = off
	if off == rtx.unsentend {
		rtx.unsentend = 0 // Mark unsent as being empty.
	}
	*pkt = ringidx{
		off:  start,
		end:  off,
		seq:  currentSeq,
		size: Size(n),
	}
	return n, nil
}

// RecvSegment processes an incoming segment and updates the sent packet queue
func (rtx *ringTx) RecvACK(ack Value) error {
	first := rtx.firstPkt()
	if first < 0 {
		return errors.New("no packets to ack")
	}
	pkt0 := rtx.pkt(first)
	if ack.LessThanEq(pkt0.seq) {
		return fmt.Errorf("incoming ack %d older than first packet seq %d", ack, pkt0.seq)
	}
	// lastAckedPkt stores last fully acked packet.
	var lastAckedPkt *ringidx
	var partialPkt *ringidx
	for i := 0; i < len(rtx.packets); i++ {
		pkt := &rtx.packets[i]
		if !pkt.sent() || ack.LessThanEq(pkt.seq) {
			continue
		}
		endseq := pkt.endSeq()
		isFullyAcked := endseq.LessThanEq(ack)
		isPartialAcked := ack.InRange(pkt.seq, endseq)
		isLast := lastAckedPkt == nil || lastAckedPkt.seq.LessThanEq(pkt.seq)
		isBeforeLast := lastAckedPkt != nil && !isLast
		if isFullyAcked == isPartialAcked { // is either or.
			panic("unreachable")
		}
		if isLast && isFullyAcked {
			if lastAckedPkt != nil {
				lastAckedPkt.markRcvd()
			}
			lastAckedPkt = pkt
		} else if isBeforeLast {
			if isPartialAcked {
				panic("unreachable")
			}
			pkt.markRcvd()
		} else if !isPartialAcked {
			panic("unreachable")
		} else {
			// Is partial acked.
			if partialPkt != nil {
				panic("unreachable") // can't have two partially acked packets.
			}
			acked := int(ack - pkt.seq)
			pring := rtx.ring(pkt.off, pkt.end)
			buffered := pring.Buffered()
			if acked > buffered {
				panic("unreachable")
			}
			off := rtx.addOff(pkt.off, acked)
			pkt.off = off
			pkt.seq = ack
			pkt.size = pkt.size - Size(acked)
			rtx.sentoff = off
			partialPkt = pkt
		}
	}
	if partialPkt != nil {
		return nil
	}
	if lastAckedPkt != nil {
		rtx.sentoff = lastAckedPkt.end
		lastAckedPkt.markRcvd()
		if rtx.sentoff == rtx.sentend {
			// All data acked.
			rtx.sentend = 0
			rtx.consolidateBufs()
		}
	}
	return nil
}

func (rtx *ringTx) sentAndUnsentBuffer() internal.Ring {
	end := rtx.unsentend
	if end == 0 {
		end = rtx.sentend
	}
	return internal.Ring{Buf: rtx.rawbuf, Off: rtx.sentoff, End: end}
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

func (rtx *ringTx) addOff(a, b int) int { return addOff(a, b, len(rtx.rawbuf)) }

func (rtx *ringTx) pkt(i int) *ringidx {
	if i == -1 {
		return &rtx.emptyRing
	} else if i < 0 || i >= len(rtx.packets) {
		panic("invalid packet index")
	}
	return &rtx.packets[i]
}

func (rtx *ringTx) firstPkt() int {
	var seq Value
	idx := -1
	for i := 0; i < len(rtx.packets); i++ {
		pkt := &rtx.packets[i]
		if pkt.sent() && (idx == -1 || pkt.seq.LessThan(seq)) {
			seq = pkt.seq
			idx = i
		}
	}
	return idx
}

func (rtx *ringTx) lastPkt() int {
	var seq Value
	idx := -1
	for i := 0; i < len(rtx.packets); i++ {
		pkt := &rtx.packets[i]
		if pkt.sent() && (idx == -1 || seq.LessThan(pkt.seq)) {
			seq = pkt.seq
			idx = i
		}
	}
	return idx
}

func (rtx *ringTx) nextPkt() int {
	idx := -1
	for i := 0; i < len(rtx.packets); i++ {
		pkt := &rtx.packets[i]
		if !pkt.sent() {
			idx = i
			break
		}
	}
	return idx
}

func (rtx *ringTx) consolidateBufs() {
	unsentEmpty := rtx.unsentend == 0
	sentEmpty := rtx.sentend == 0
	if unsentEmpty && sentEmpty {
		// reset start of buffers.
		rtx.sentoff = 0
		rtx.unsentoff = 0
	}
}

func (rtx *ringTx) endSeq() (Value, bool) {
	pkt := rtx.lastPkt()
	if pkt < 0 {
		return 0, false
	}
	last := rtx.pkt(pkt)
	return last.endSeq(), true
}
func (rtx *ringTx) lastSeq() (Value, bool) {
	pkt := rtx.lastPkt()
	if pkt < 0 {
		return 0, false
	}
	return rtx.pkt(pkt).seq, true
}
func (rtx *ringTx) firstSeq() (Value, bool) {
	pkt := rtx.firstPkt()
	if pkt < 0 {
		return 0, false
	}
	return rtx.pkt(pkt).seq, true
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
	// pkts is an ordered list of packets. First packet is 'oldest' packet, last packet is the most recently sent.
	iss  Value
	pkts []ringidx
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
	seq := sl.iss
	lastPkt := sl.Newest()
	if lastPkt != nil {
		seq = lastPkt.endSeq()
	}
	return seq
}

func (sl *sentlist) AddPacket(datalen int, bufsize int) {
	free := cap(sl.pkts) - len(sl.pkts)
	if free == 0 {
		panic("pkt buffer full")
	}
	lastPkt := sl.Newest()
	lastEnd := 0
	if lastPkt != nil {
		lastEnd = lastPkt.end
	}
	pkt := ringidx{
		off:  lastEnd,
		end:  addEnd(lastEnd, datalen, bufsize),
		seq:  sl.EndSeq(),
		size: Size(datalen),
	}
	sl.pkts = append(sl.pkts, pkt)
}

func (sl *sentlist) RecvAck(ack Value, bufsize int) {
	// Mark fully acked.
	for i := 0; i < len(sl.pkts); i++ {
		pkt := &sl.pkts[i]
		endseq := pkt.endSeq()
		isFullyAcked := endseq.LessThanEq(ack)
		if isFullyAcked {
			sl.iss = endseq
			pkt.markRcvd()
		} else {
			break
		}
	}
	sl.removeRecvd()
	maybePartial := sl.Oldest()
	if maybePartial == nil {
		return // No more packets, all acked.
	}
	totalAcked := int32(ack - maybePartial.seq)
	isPartial := totalAcked > 0
	if !isPartial {
		return // Not a partial packet ack.
	}
	maybePartial.off = addOff(maybePartial.off, int(totalAcked), bufsize)
	maybePartial.size -= Size(totalAcked)
	maybePartial.seq += Value(totalAcked)
}

func (sl *sentlist) removeRecvd() {
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

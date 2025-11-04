package tcp

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/soypat/lneto/internal"
)

var (
	errPacketQueueFull = errors.New("packet queue full")
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
	slist  sentlist
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

	*rtx = ringTx{
		rawbuf: buf,
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
	free := rtx.slist.Free()
	if free == 0 {
		return 0, errPacketQueueFull
	}
	endSeq, ok := rtx.endSeq()
	if ok && currentSeq.LessThan(endSeq) {
		return 0, errors.New("sequence number less than last sequence number")
	}
	// Reading unsent ring consumes unsent and converts it to "sent".
	r, _ := rtx.unsentRing()
	oldSentOff := r.Off
	n, err := r.Read(b)
	if err != nil {
		return n, err
	}
	// unsentOff increases, sentEnd matches this value.
	// Start of buffer will be SENT, end of buffer will be UNSENT(or empty).
	// Packet generated has offset at old unsentOff.
	newUnsentOff := rtx.addEnd(rtx.unsentoff, n)
	pkt := rtx.slist.AddPacket(n, oldSentOff, rtx.Size())
	if pkt.off != oldSentOff || pkt.end != addEnd(pkt.off, n, rtx.Size()) {
		panic("invalid generated packet")
	}
	rtx.unsentoff = newUnsentOff
	rtx.sentend = newUnsentOff
	if newUnsentOff == rtx.unsentend {
		rtx.unsentend = 0 // Mark unsent as being empty.
	}
	return n, nil
}

// RecvSegment processes an incoming segment and updates the sent packet queue
func (rtx *ringTx) RecvACK(ack Value) error {
	err := rtx.slist.RecvAck(ack, rtx.Size())
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

func (sl *sentlist) Reset(pktQueueSize int, iss Value) {
	sl.pkts = slices.Grow(sl.pkts[:0], pktQueueSize)
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

func (sl *sentlist) AddPacket(datalen, off, bufsize int) *ringidx {
	free := sl.Free()
	if free == 0 {
		panic("pkt buffer full")
	}
	lastPkt := sl.Newest()
	if lastPkt != nil && off != lastPkt.end {
		panic("new sent packet offset must match last sent packet end")
	}
	sl.pkts = append(sl.pkts, ringidx{
		off:  off,
		end:  addEnd(off, datalen, bufsize),
		seq:  sl.EndSeq(),
		size: Size(datalen),
	})
	return &sl.pkts[len(sl.pkts)-1]
}

func (sl *sentlist) RecvAck(ack Value, bufsize int) error {
	newest := sl.Newest()
	if newest == nil {
		return errors.New("no packet to ack")
	} else if newest.endSeq().LessThan(ack) {
		return errors.New("ack of unsent packet")
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

// prints out buffer zones with indices:
//
// 0              32             42            47
// |---free(32)---|---usnt(10)---|---free(5)---|
func (rtx *ringTx) appendString(b []byte) []byte {
	size := rtx.Size()
	type zone struct {
		name       string
		start, end int
	}
	zcontains := func(off int, z *zone) bool {
		if z.end == 0 {
			return false // Empty
		} else if z.end < z.start {
			// zone wraps.
		}
		return off >= z.start && off < z.end
	}

	zs := zone{name: "sent", start: rtx.sentoff, end: rtx.sentend}
	zu := zone{name: "usnt", start: rtx.unsentoff, end: rtx.unsentend}
	bufStart := zs.start
	if bufStart == 0 {
		bufStart = zu.start
	}
	bufEnd := zu.end
	if bufEnd == 0 {
		bufEnd = zs.end
	}
	zf := zone{name: "free", start: bufEnd, end: bufStart}
	getZone := func(off int) *zone {
		if zcontains(0, &zs) {
			return &zs
		} else if zcontains(0, &zu) {
			return &zu
		} else {
			return &zf
		}
	}

	zones := []*zone{getZone(0)}
	for i := 1; i < size; i++ {
		z := getZone(i)
		if z != zones[len(zones)-1] {
			zones = append(zones, z)
		}
	}

	var wrapZone *zone
	for i := range zones {
		wraps := zones[i].end != 0 && zones[i].end < zones[i].start
		if wraps {
			if wrapZone != nil {
				panic("illegal to have more than one wrap zone")
			}
			wrapZone = zones[i]
		}
	}
	// ---- your simple approach starts here ----
	var currentZone *zone
	if wrapZone != nil {
		currentZone = wrapZone
	} else {
		currentZone = zones[0]
	}

	var lastPrintedZone *zone
	var l1, l2 bytes.Buffer
	changes := 0
	zoneLen := func(z *zone, sz int) int {
		if z.end == 0 {
			return 0
		}
		if z.end < z.start {
			return (sz - z.start) + z.end
		}
		return z.end - z.start
	}
	for ib := 0; ib < size; ib++ {
		// see if current zone still contains this index
		currentContainsIdx := currentZone != nil && zcontains(ib, currentZone)
		if !currentContainsIdx {
			// find which zone contains this index
			for _, z := range zones {
				if zcontains(ib, z) {
					currentZone = z
					currentContainsIdx = true
					break
				}
			}
		}
		// if still same zone, keep going
		if currentZone == lastPrintedZone {
			continue
		}

		// zone changed
		changes++
		if changes > 4 {
			panic("found too many zone changes")
		}
		lastPrintedZone = currentZone

		// build the bottom line segment
		seg := "|---" + currentZone.name + "(" + strconv.Itoa(zoneLen(currentZone, size)) + ")---"
		l2.WriteString(seg)

		// write the start index aligned to seg width
		n, _ := fmt.Fprintf(&l1, "%d", currentZone.start)
		for i := 0; i < len(seg)-n; i++ {
			l1.WriteByte(' ')
		}
	}

	// close last zone: print its end index and closing bar
	l2.WriteByte('|')

	// if the last zone "ends" at 0 because of wrap, use sz
	endIdx := lastPrintedZone.end
	if endIdx == 0 {
		endIdx = size
	}
	fmt.Fprintf(&l1, "%d\n", endIdx)

	// write second line under the first
	l2.WriteTo(&l1)
	l1.WriteByte('\n')

	b = append(b, l1.Bytes()...)
	return b
}

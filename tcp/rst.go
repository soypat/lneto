package tcp

import "github.com/soypat/lneto/internal"

// RSTQueue is a small fixed-size queue of pending stateless RST responses.
// It is not safe for concurrent use; callers must synchronize access.
type RSTQueue struct {
	buf [4]rstEntry
	len uint8
}

type rstEntry struct {
	remoteAddr [4]byte
	remotePort uint16
	localPort  uint16
	seq        Value
	ack        Value
	flags      Flags
}

// Queue enqueues a RST response. Silently drops if srcaddr is not IPv4 or queue is full.
func (q *RSTQueue) Queue(srcaddr []byte, remotePort, localPort uint16, seq, ack Value, flags Flags) {
	if len(srcaddr) == 4 && q.len < uint8(len(q.buf)) {
		entry := &q.buf[q.len]
		copy(entry.remoteAddr[:], srcaddr)
		entry.remotePort = remotePort
		entry.localPort = localPort
		entry.seq = seq
		entry.ack = ack
		entry.flags = flags
		q.len++
	}
}

// Pending returns the number of queued RST entries.
func (q *RSTQueue) Pending() int { return int(q.len) }

// Drain writes one pending RST to the carrier buffer and returns the TCP frame length written.
// Returns (0, nil) if the queue is empty or offsetToIP < 0.
func (q *RSTQueue) Drain(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	if q.len == 0 || offsetToIP < 0 {
		return 0, nil
	}
	q.len--
	entry := &q.buf[q.len]
	tfrm, err := NewFrame(carrierData[offsetToFrame:])
	if err != nil {
		return 0, nil
	}
	tfrm.SetSourcePort(entry.localPort)
	tfrm.SetDestinationPort(entry.remotePort)
	tfrm.SetSegment(Segment{
		SEQ:   entry.seq,
		ACK:   entry.ack,
		Flags: entry.flags,
	}, 5)
	tfrm.SetUrgentPtr(0)
	err = internal.SetIPAddrs(carrierData[offsetToIP:offsetToFrame], 0, nil, entry.remoteAddr[:])
	if err != nil {
		return 0, nil
	}
	return sizeHeaderTCP, nil
}

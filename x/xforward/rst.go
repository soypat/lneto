package xforward

import (
	"github.com/soypat/lneto"
	"github.com/soypat/lneto/tcp"
)

// rstQueue holds stateless RST replies (RFC 9293 §3.10.7.1) for IPv4 and IPv6.
// Unlike [tcp.RSTQueue] it keeps the local address so replies are sourced from it.
// Fixed size; drops when full.
type rstQueue struct {
	buf [8]struct {
		key      flowKey
		seq, ack tcp.Value
		flags    tcp.Flags
	}
	len uint8
}

// queue enqueues a RST for flow k. Silently drops if the queue is full.
func (q *rstQueue) queue(k *flowKey, seq, ack tcp.Value, flags tcp.Flags) {
	if int(q.len) == len(q.buf) {
		return
	}
	e := &q.buf[q.len]
	e.key = *k
	e.seq = seq
	e.ack = ack
	e.flags = flags
	q.len++
}

// drain writes one pending RST as a complete IP packet into pkt and returns its length, 0 when empty.
// pkt must fit an IPv6 header and a TCP header.
func (q *rstQueue) drain(pkt []byte, id uint16) int {
	if q.len == 0 {
		return 0
	}
	q.len--
	e := &q.buf[q.len]
	hl := putIPHeader(pkt, &e.key, lneto.IPProtoTCP, id)
	tfrm, _ := tcp.NewFrame(pkt[hl:])
	tfrm.ClearHeader()
	tfrm.SetSourcePort(e.key.lport)
	tfrm.SetDestinationPort(e.key.rport)
	tfrm.SetSegment(tcp.Segment{SEQ: e.seq, ACK: e.ack, Flags: e.flags}, 5)
	finishIP(pkt, hl, sizeTCPHeader, lneto.IPProtoTCP)
	return hl + sizeTCPHeader
}

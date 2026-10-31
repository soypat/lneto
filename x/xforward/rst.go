package xforward

import "github.com/soypat/lneto/tcp"

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
	panic("unimplemented")
}

// drain writes one pending RST TCP header to tcpFrame and returns its flow
// for IP framing and the length written. n==0 when empty.
func (q *rstQueue) drain(tcpFrame []byte) (key *flowKey, n int) {
	panic("unimplemented")
}

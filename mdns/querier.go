package mdns

import (
	"encoding/binary"
	"net"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dns"
)

// Querier sends mDNS queries and collects multicast responses.
// It implements the [internet.StackNode] interface via Encapsulate/Demux.
type Querier struct {
	connID uint64
	state  querierState
	msg    dns.Message
}

// QueryConfig contains the parameters for starting a mDNS query.
type QueryConfig struct {
	// Questions to ask.
	Questions []dns.Question
	// MaxAnswers limits the number of answer records decoded.
	// Zero means no answers decoded.
	MaxAnswers uint16
}

// StartQuery prepares the querier to send a one-shot multicast query.
// Call Encapsulate to emit the query packet, then Demux to process responses.
func (q *Querier) StartQuery(cfg QueryConfig) error {
	if len(cfg.Questions) == 0 {
		return errNoQuery
	}
	q.reset(querierSendQuery)
	q.msg.LimitResourceDecoding(0, cfg.MaxAnswers, 0, 0)
	q.msg.AddQuestions(cfg.Questions)
	return nil
}

// Encapsulate writes an mDNS query packet into carrierData[offsetToFrame:].
// The mDNS query has txid=0, no recursion desired, and no opcode (RFC 6762 §18.1).
func (q *Querier) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	if q.isClosed() {
		return 0, net.ErrClosed
	} else if q.state != querierSendQuery {
		return 0, nil
	}

	msg := &q.msg
	frame := carrierData[offsetToFrame:]
	msglen := msg.Len()
	if int(msglen) > len(frame) {
		return 0, lneto.ErrShortBuffer
	}
	// mDNS queries use txid=0 and no flags (RFC 6762 §18.1).
	data, err := msg.AppendTo(frame[:0], 0, 0)
	if err != nil {
		return 0, err
	}
	q.state = querierAwaitResponse
	return len(data), nil
}

// Demux processes an incoming mDNS response packet. Answers are accumulated
// into the internal message. Once sufficient answers are collected or a
// timeout occurs the querier transitions to querierDone.
func (q *Querier) Demux(carrierData []byte, frameOffset int) error {
	if q.isClosed() {
		return net.ErrClosed
	} else if q.state != querierAwaitResponse {
		return nil
	}
	frame := carrierData[frameOffset:]
	f, err := dns.NewFrame(frame)
	if err != nil {
		return err
	}
	flags := f.Flags()
	if !flags.IsResponse() {
		return nil // Not a response, ignore.
	}

	// Decode response into our message, collecting answers.
	var resp dns.Message
	resp.LimitResourceDecoding(0, f.ANCount(), 0, 0)
	_, _, err = resp.Decode(frame)
	if err != nil {
		return err
	}

	// Append new answers to our accumulated answers.
	q.msg.Answers = appendResources(q.msg.Answers, resp.Answers, cap(q.msg.Answers))
	return nil
}

// Done reports whether the querier has finished collecting answers.
func (q *Querier) Done() bool { return q.state == querierDone }

// Finish transitions the querier to the done state. Call this after the
// desired timeout has elapsed to signal that no more responses are expected.
func (q *Querier) Finish() {
	if q.state == querierAwaitResponse {
		q.state = querierDone
	}
}

// Answers returns collected answer resource records.
// Only valid after the querier has received responses.
func (q *Querier) Answers() []dns.Resource { return q.msg.Answers }

// Reset clears all state for reuse while preserving allocated buffers.
func (q *Querier) Reset() { q.reset(querierIdle) }

// Protocol returns the IP protocol number (UDP).
func (q *Querier) Protocol() uint64 { return uint64(lneto.IPProtoUDP) }

// LocalPort returns the mDNS port 5353.
func (q *Querier) LocalPort() uint16 { return Port }

// ConnectionID returns a pointer to the connection ID for stack invalidation.
func (q *Querier) ConnectionID() *uint64 { return &q.connID }

func (q *Querier) isClosed() bool {
	return q.state == querierIdle
}

func (q *Querier) reset(state querierState) {
	q.connID++
	q.state = state
	q.msg.Reset()
}

// appendResources appends src resources to dst up to maxCap capacity.
func appendResources(dst, src []dns.Resource, maxCap int) []dns.Resource {
	for i := range src {
		if len(dst) >= maxCap {
			break
		}
		var r dns.Resource
		r.CopyFrom(src[i])
		dst = append(dst, r)
	}
	return dst
}

// encodeSRVData encodes SRV record data (priority, weight, port, target) into dst.
// Returns bytes written. dst must be at least 6+target.Len() bytes.
func encodeSRVData(dst []byte, priority, weight, port uint16, target dns.Name) (int, error) {
	tlen := target.Len()
	need := 6 + int(tlen)
	if len(dst) < need {
		return 0, lneto.ErrShortBuffer
	}
	binary.BigEndian.PutUint16(dst[0:2], priority)
	binary.BigEndian.PutUint16(dst[2:4], weight)
	binary.BigEndian.PutUint16(dst[4:6], port)
	b, err := target.AppendTo(dst[:6])
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

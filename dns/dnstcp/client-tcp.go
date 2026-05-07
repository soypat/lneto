package dnstcp

import (
	"encoding/binary"
	"net"
	"slices"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/tcp"
)

var _ lneto.StackNode = (*Client)(nil)

// ClientTCPConfig configures a [Client].
type ClientTCPConfig struct {
	// TxBuf and RxBuf are TCP-level transmit and receive ring buffers.
	TxBuf      []byte
	RxBuf      []byte
	// TCPPackets is the number of TCP packets the TX ring buffer can hold.
	TCPPackets int
	// QueryBuf is scratch space for serializing outgoing DNS queries (2-byte prefix + message body).
	// Must be at least 2+dns.SizeHeader bytes and large enough for the largest query to be sent.
	QueryBuf []byte
	// StreamBuf is the buffer for reassembling the incoming TCP byte stream.
	// Must hold at least 2+dns.SizeHeader bytes and ideally at least one complete DNS response.
	StreamBuf []byte
	// PipelineLimit is the maximum number of in-flight queries (RFC 7766 §6.2.1.1).
	PipelineLimit int
	// AnswerLimit caps the number of answer records decoded per response. Zero defaults to 16.
	AnswerLimit uint16
	// LocalPort and RemotePort are the TCP port numbers.
	LocalPort  uint16
	RemotePort uint16
	// InitSeq is the initial TCP sequence number.
	InitSeq tcp.Value
}

// Client is a DNS-over-TCP client per RFC 7766.
// It supports connection reuse and query pipelining (RFC 7766 §6.2.1.1).
type Client struct {
	connid    uint64
	h         tcp.Handler
	responses []struct {
		txid            uint16
		msglen          uint16 // DNS message length from the 2-byte TCP-DNS prefix
		state           dns.StateClientQuery
		enableRecursion bool
		msg             dns.Message
	}
	buf         []byte // TCP stream reassembly buffer
	buflen      int    // valid bytes in buf
	qbuf        []byte // scratch buffer for outgoing query serialization
	answerLimit uint16
	lport       uint16
}

func (c *Client) Configure(cfg ClientTCPConfig) error {
	if cfg.PipelineLimit <= 0 || len(cfg.QueryBuf) < 2+dns.SizeHeader || len(cfg.StreamBuf) < 2+dns.SizeHeader {
		return lneto.ErrInvalidConfig
	}
	if err := c.h.SetBuffers(cfg.TxBuf, cfg.RxBuf, cfg.TCPPackets); err != nil {
		return err
	}
	if err := c.h.OpenActive(cfg.LocalPort, cfg.RemotePort, cfg.InitSeq); err != nil {
		return err
	}
	internal.SliceReuse(&c.responses, cfg.PipelineLimit)
	c.buf = cfg.StreamBuf
	c.buflen = 0
	c.qbuf = cfg.QueryBuf
	c.answerLimit = cfg.AnswerLimit
	if c.answerLimit == 0 {
		c.answerLimit = 16
	}
	c.lport = cfg.LocalPort
	c.connid++
	return nil
}

func (c *Client) Protocol() uint64      { return uint64(lneto.IPProtoTCP) }
func (c *Client) LocalPort() uint16     { return c.lport }
func (c *Client) ConnectionID() *uint64 { return &c.connid }

func (c *Client) Reset() {
	c.responses = c.responses[:0]
	c.buflen = 0
}

func (c *Client) Abort() {
	c.h.Abort()
	c.Reset()
	c.connid++
}

// StartResolve stages a DNS query to be written on the next [Client.Encapsulate] call.
func (c *Client) StartResolve(txid uint16, cfg dns.ResolveConfig) error {
	if len(c.responses) >= cap(c.responses) {
		return lneto.ErrExhausted
	}
	nd := len(cfg.Questions)
	v := internal.SliceReclaim(&c.responses)
	v.txid = txid
	v.state = dns.CQueryPending
	v.enableRecursion = cfg.EnableRecursion
	v.msg.Reset()
	v.msg.LimitResourceDecoding(uint16(nd), uint16(nd), 0, 0)
	v.msg.AddQuestions(cfg.Questions)
	v.msg.AddAdditionals(cfg.Additional)
	return nil
}

// Encapsulate writes a TCP segment into carrierData[offsetToFrame:].
// If a DNS query is staged via [Client.StartResolve] and the connection is established,
// it is written to the TCP send buffer before the segment is emitted.
func (c *Client) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	if c.h.State().TxDataOpen() {
		for i := range c.responses {
			r := &c.responses[i]
			if r.state != dns.CQueryPending {
				continue
			}
			msgLen := r.msg.Len()
			if int(msgLen)+2 > len(c.qbuf) {
				return 0, lneto.ErrShortBuffer
			}
			// Serialize: 2-byte big-endian length prefix (RFC 7766 §8) followed by DNS message.
			binary.BigEndian.PutUint16(c.qbuf[:2], msgLen)
			data, err := r.msg.AppendTo(c.qbuf[2:2], r.txid, dns.NewClientHeaderFlags(dns.OpCodeQuery, r.enableRecursion))
			if err != nil {
				return 0, err
			}
			n, err := c.h.Write(c.qbuf[:2+len(data)])
			if err != nil {
				return 0, err
			} else if n != 2+len(data) {
				return 0, lneto.ErrBufferFull
			}
			r.msglen = msgLen
			r.state = dns.CQueryOutstanding
			r.msg.Reset() // release query data; response will reuse the capacity
			break          // one query per Encapsulate call
		}
	}
	return c.h.Send(carrierData[offsetToFrame:])
}

// Demux receives an incoming TCP segment and parses any complete DNS responses from the stream.
func (c *Client) Demux(carrierData []byte, frameOffset int) error {
	if err := c.h.Recv(carrierData[frameOffset:]); err != nil {
		if err == net.ErrClosed {
			c.connid++
		}
		return err
	}
	// Drain TCP receive buffer into stream reassembly buffer.
	n, _ := c.h.Read(c.buf[c.buflen:])
	c.buflen += n
	// Parse complete 2-byte-prefixed DNS messages (RFC 7766 §8).
	for c.buflen >= 2 {
		msglen := int(binary.BigEndian.Uint16(c.buf[:2]))
		if c.buflen < 2+msglen {
			break
		}
		c.demuxMessage(c.buf[2 : 2+msglen])
		c.slideStream(2 + msglen)
	}
	return nil
}

func (c *Client) demuxMessage(msgdata []byte) {
	frm, err := dns.NewFrame(msgdata)
	if err != nil {
		return
	}
	flags := frm.Flags()
	if !flags.IsResponse() || flags.OpCode() != dns.OpCodeQuery {
		// Drop server-initiated messages (including RFC 8490 DSO) and non-standard opcodes.
		return
	}
	txid := frm.TxID()
	for i := range c.responses {
		r := &c.responses[i]
		if r.txid == txid && r.state == dns.CQueryOutstanding {
			r.msglen = uint16(len(msgdata))
			r.msg.LimitResourceDecoding(1, c.answerLimit, 0, 0)
			r.msg.Decode(msgdata) //nolint:errcheck — incompleteButOK is not an error
			r.state = dns.CQueryDone
			return
		}
	}
}

func (c *Client) slideStream(n int) {
	copy(c.buf, c.buf[n:c.buflen])
	c.buflen -= n
}

// PopAnswerTo copies the decoded response for txid into dst and removes it from the pipeline queue.
// Returns false if the response has not yet been received.
func (c *Client) PopAnswerTo(txid uint16, dst *dns.Message) bool {
	for i := range c.responses {
		if c.responses[i].txid == txid && c.responses[i].state == dns.CQueryDone {
			dst.CopyFrom(c.responses[i].msg)
			c.responses = slices.Delete(c.responses, i, i+1)
			return true
		}
	}
	return false
}

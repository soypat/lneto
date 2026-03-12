package mdns

import (
	"math"
	"net"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dns"
)

const (
	// Port is the mDNS UDP port (RFC 6762 §1).
	Port = 5353

	// Default TTL for mDNS records (RFC 6762 §11).
	DefaultTTL uint32 = 120
	// classCacheFlush is bit 15 of the Class field, indicating the record
	// is from a unique source and should replace cached entries (RFC 6762 §10.2).
	classCacheFlush uint16 = 1 << 15
	mdnsTxID               = 0
	mdnsFlags              = 0
)

type querierState uint8

const (
	querierIdle          querierState = iota
	querierSendQuery                  // Query ready to be sent.
	querierAwaitResponse              // Waiting for answers.
	querierFailed                     // failed query
	querierDone                       // Answers collected.
)

// Client provides both querying and service multicast DNS funcionality
// once configured and attached to MDNS port 5353.
//
// Clients are attached to MDNS ports and function until manual deattachment
// due to their dual design: they double as a queryier and service discovery.
type Client struct {
	connID uint64

	lport uint16
	// Query State:
	qstate querierState
	qcode  dns.RCode
	qerr   error
	// qmsg is used for queries to marshal/unmarshal our
	// outgoing queries and responses to our queries.
	qmsg dns.Message

	// Response state:
	// TODO.
}

type ClientConfig struct {
	LocalPort uint16
}

func (c *Client) Configure(cfg ClientConfig) error {
	if cfg.LocalPort == 0 {
		return lneto.ErrZeroSource
	}
	c.reset(cfg.LocalPort)
	return nil
}

func (c *Client) Protocol() uint64 { return uint64(lneto.IPProtoUDP) }

func (c *Client) LocalPort() uint16 { return c.lport }

func (c *Client) ConnectionID() *uint64 { return &c.connID }

type ResolveConfig struct {
	Questions  []dns.Question
	MaxAnswers uint16
}

func (c *Client) StartResolve(cfg ResolveConfig) error {
	nq := len(cfg.Questions)
	if nq > math.MaxUint16 || nq == 0 || cfg.MaxAnswers == 0 {
		return lneto.ErrInvalidConfig
	}
	c.qreset(querierSendQuery)
	c.qmsg.LimitResourceDecoding(uint16(nq), cfg.MaxAnswers, 0, 0)
	c.qmsg.AddQuestions(cfg.Questions)
	return nil
}

func (c *Client) reset(localport uint16) {
	*c = Client{
		connID: c.connID + 1,
		lport:  localport,
		qmsg:   c.qmsg, // Ensure memory not lost.
	}
}

// qreset resets the current query state. It is only a partial reset of a Client.
func (c *Client) qreset(state querierState) {
	c.qstate = state
	c.qmsg.Reset()
}

// Encapsulate writes an mDNS query packet into carrierData[offsetToFrame:].
// The mDNS query has txid=0, no recursion desired, and no opcode (RFC 6762 §18.1).
func (q *Client) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	if q.isClosed() {
		return 0, net.ErrClosed
	}
	if q.qstate == querierSendQuery {
		// User requested a query.
		return q.encapsQuery(carrierData[offsetToFrame:])
	}
	return 0, nil
}

// Demux processes an incoming mDNS response packet. Answers are accumulated
// into the internal message. Once sufficient answers are collected or a
// timeout occurs the querier transitions to querierDone.
func (q *Client) Demux(carrierData []byte, frameOffset int) error {
	if q.isClosed() {
		return net.ErrClosed
	}
	frame := carrierData[frameOffset:]
	f, err := dns.NewFrame(frame)
	if err != nil {
		return err
	} else if f.TxID() != 0 {
		return lneto.ErrPacketDrop
	}
	flags := f.Flags()
	if flags.IsResponse() && q.qstate == querierAwaitResponse {
		q.qcode = flags.ResponseCode()
		// Decode response into our message, collecting answers.
		_, _, q.qerr = q.qmsg.Decode(frame)
		if q.qerr != nil {
			q.qstate = querierFailed
			return q.qerr
		}
		q.qstate = querierDone
		return nil // success.
	}
	// Is a request
	// TODO: support requests.
	return nil
}

func (q *Client) encapsQuery(frame []byte) (int, error) {
	msg := &q.qmsg
	msglen := msg.Len()
	if int(msglen) > len(frame) {
		q.qerr = lneto.ErrShortBuffer
		q.qstate = querierFailed
		return 0, q.qerr
	}
	// mDNS queries use txid=0 and no flags (RFC 6762 §18.1).
	data, err := msg.AppendTo(frame[:0], mdnsTxID, mdnsFlags)
	if err != nil {
		q.qerr = err
		q.qstate = querierFailed
		return 0, err
	} else if len(data) != int(msglen) {
		panic("bad dns length calculation") // panic since this is a big bug in lneto.
	}
	q.qstate = querierAwaitResponse
	return len(data), nil
}

func (c *Client) isClosed() bool {
	return false
}

func (c *Client) MessageCopyTo(dst *dns.Message) (done bool, err error) {
	if c.qstate == querierFailed {
		return false, c.qerr
	} else if c.qstate != querierDone {
		return false, nil
	}
	dst.CopyFrom(c.qmsg)
	rcode := c.qcode
	if rcode != 0 {
		return true, rcode
	}
	return true, nil
}

package mdns

import (
	"math"
	"net"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/internal"
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

// Client provides both querying and service multicast DNS functionality
// once configured and attached to MDNS port 5353.
//
// Clients are attached to MDNS ports and function until manual detachment
// due to their dual design: they double as a querier and service discovery.
type Client struct {
	connID uint64
	closed bool
	lport  uint16
	ip     []byte
	// Query State:
	qstate querierState
	qcode  dns.RCode
	qerr   error
	// qmsg is used for queries to marshal/unmarshal our
	// outgoing queries and responses to our queries.
	qans []dns.Resource
	qqst []dns.Question
	// Response state:
	services []Service // Stores services we'd broadcast.
	rans     []dns.Resource
	rqst     []dns.Question
}

type ClientConfig struct {
	LocalPort     uint16
	Services      []Service
	MulticastAddr []byte
}

func (c *Client) Configure(cfg ClientConfig) error {
	if cfg.LocalPort == 0 {
		return lneto.ErrZeroSource
	}
	c.reset(cfg.LocalPort)
	c.services = append(c.services[:0], cfg.Services...)
	c.ip = append(c.ip[:0], cfg.MulticastAddr...)
	internal.SliceReuse(&c.rqst, len(cfg.Services))
	// Each service can produce up to 4 answer records (PTR+SRV+TXT+A).
	nrans := 2 * len(cfg.Services)
	if nrans > 0 {
		nrans = max(4, nrans)
	}
	internal.SliceReuse(&c.rans, nrans)
	return nil
}

func (c *Client) Protocol() uint64 { return uint64(lneto.IPProtoUDP) }

func (c *Client) LocalPort() uint16 { return c.lport }

func (c *Client) ConnectionID() *uint64 { return &c.connID }

type ResolveConfig struct {
	Questions          []dns.Question
	MaxResponseAnswers uint16
}

func (c *Client) StartResolve(cfg ResolveConfig) error {
	nq := len(cfg.Questions)
	if nq > math.MaxUint16 || nq == 0 || cfg.MaxResponseAnswers == 0 {
		return lneto.ErrInvalidConfig
	}
	c.qreset(querierSendQuery)
	internal.SliceReuse(&c.qans, int(cfg.MaxResponseAnswers))
	internal.SliceReuse(&c.qqst, nq)
	c.qqst = c.qqst[:nq]
	for i := range c.qqst {
		c.qqst[i].CopyFrom(cfg.Questions[i])
	}
	return nil
}

func (c *Client) reset(localport uint16) {
	*c = Client{
		connID: c.connID + 1,
		lport:  localport,
		// Ensure memory reused:
		qqst:     c.qqst[:0],
		qans:     c.qans[:0],
		services: c.services[:0],
		rans:     c.rans[:0],
		ip:       c.ip[:0],
	}
}

// qreset resets the current query state. It is only a partial reset of a Client.
func (c *Client) qreset(state querierState) {
	c.qstate = state
}

// Encapsulate writes a pending mDNS packet into carrierData[offsetToFrame:].
// Pending responses take priority over outgoing queries.
func (c *Client) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (n int, err error) {
	if c.isClosed() {
		return 0, net.ErrClosed
	}
	if len(c.rans) > 0 {
		// Pending response to an incoming query.
		n, err = c.encapsResponse(carrierData[offsetToFrame:])
	} else if c.qstate == querierSendQuery {
		n, err = c.encapsQuery(carrierData[offsetToFrame:])
	}
	if n > 0 && offsetToIP >= 0 {
		// Set Multicast IP destination and Ethernet MAC.
		internal.SetMulticast(carrierData, offsetToIP, c.ip)
	}
	return n, err
}

// Demux processes an incoming mDNS response packet. Answers are accumulated
// into the internal message. Once sufficient answers are collected or a
// timeout occurs the querier transitions to querierDone.
func (c *Client) Demux(carrierData []byte, frameOffset int) error {
	if c.isClosed() {
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
	isresponse := flags.IsResponse()
	if isresponse && c.qstate == querierAwaitResponse {
		c.qcode = flags.ResponseCode()
		// Decode response into our message, collecting answers.
		_, _, c.qerr = dns.DecodeMessage(nil, &c.qans, nil, nil, frame)
		if c.qerr != nil {
			c.qstate = querierFailed
			return c.qerr
		}
		c.qstate = querierDone
		return nil // success.
	}
	freeAns := cap(c.rans) - len(c.rans)
	if !isresponse && len(c.services) > 0 && freeAns > 0 {
		// Incoming query — match against our services.
		var query dns.Message
		query.LimitResourceDecoding(f.QDCount(), 0, 0, 0)
		_, _, err = query.Decode(frame)
		if err != nil {
			return err
		}
		for i := range query.Questions {
			q := &query.Questions[i]
			for j := range c.services {
				if matchQuestion(q, &c.services[j]) {
					addServiceAnswers(&c.rans, q, &c.services[j])
					break
				}
			}
		}
	}
	return nil
}

func (c *Client) encapsQuery(frame []byte) (int, error) {
	msg := dns.Message{
		Questions: c.qqst,
	}
	msglen := msg.Len()
	if int(msglen) > len(frame) {
		c.qerr = lneto.ErrShortBuffer
		c.qstate = querierFailed
		return 0, c.qerr
	}
	// mDNS queries use txid=0 and no flags (RFC 6762 §18.1).
	data, err := msg.AppendTo(frame[:0], mdnsTxID, mdnsFlags)
	if err != nil {
		c.qerr = err
		c.qstate = querierFailed
		return 0, err
	} else if len(data) != int(msglen) {
		panic("bad dns length calculation") // panic since this is a big bug in lneto.
	}
	c.qstate = querierAwaitResponse
	return len(data), nil
}

func (c *Client) encapsResponse(frame []byte) (int, error) {
	var msg dns.Message
	msg.Answers = c.rans
	msglen := msg.Len()
	if int(msglen) > len(frame) {
		return 0, lneto.ErrShortBuffer
	}
	// mDNS responses: txid=0, QR=1, AA=1 (RFC 6762 §18.4, §6).
	flags := dns.HeaderFlags(1<<15 | 1<<10)
	data, err := msg.AppendTo(frame[:0], 0, flags)
	if err != nil {
		return 0, err
	}
	return len(data), nil
}

// Abort closes the client, causing all subsequent Encapsulate/Demux calls to return [net.ErrClosed].
func (c *Client) Abort() {
	c.closed = true
}

func (c *Client) isClosed() bool {
	return c.closed
}

// AnswersCopyTo checks if [Client.StartResolve] ended succesfully before
// doing a deep copy of answers received to the argument buffer using [dns.Resource.CopyFrom].
func (c *Client) AnswersCopyTo(dst []dns.Resource) (n int, done bool, err error) {
	if len(dst) == 0 {
		return 0, false, lneto.ErrShortBuffer
	} else if c.qstate == querierIdle {
		return 0, false, net.ErrClosed
	} else if c.qstate == querierFailed {
		return 0, false, c.qerr
	} else if c.qstate != querierDone {
		return 0, false, nil
	}
	for i := range min(len(dst), len(c.qans)) {
		dst[i].CopyFrom(c.qans[i])
		n++
	}
	rcode := c.qcode
	if rcode != 0 {
		return n, true, rcode
	}
	return n, true, nil
}

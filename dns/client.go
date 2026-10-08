package dns

import (
	"math"
	"net/netip"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

var _ lneto.StackNode = (*Client)(nil) // Compile-time guarantee of interface implementation.

// Client provides parallel DNS lookups via Lookup* methods. Currently only supports UDP.
type Client struct {
	connID uint64
	// rawlookups holds lookup slots. Its length is fixed by [ClientConfig.MaxLookups] and
	// slots never move so the *Message returned by [Client.LookupResponse] stays valid.
	rawlookups []lookup
	// lidxs is a permutation of looksies indices: lidxs[:len] index active lookups
	// and lidxs[len:len(looksies)] index free slots, which keep their buffers for reuse.
	lidxs []uint16
	vld   lneto.Validator
	lport uint16
}

// lookup stores a single lookup state with restart ability for canonical name resolution.
type lookup struct {
	questions       []Question
	additional      []Resource
	resp            Message
	txid            uint16
	respFlags       HeaderFlags
	state           StateClientQuery
	enableRecursion bool
}

type ClientConfig struct {
	LocalPort uint16
	// MaxLookups is the maximum number of lookups that may be active at once.
	MaxLookups int
}

type LookupConfig struct {
	Questions       []Question
	Additional      []Resource
	EnableRecursion bool
	// MaxResponseAnswers hard-limits how many answer records decoded from response.
	MaxResponseAnswers uint16
}

// Configure discards ongoing/pending/active lookups and configures client. Also increments connection ID.
func (c *Client) Configure(cfg ClientConfig) error {
	if cfg.MaxLookups <= 0 || cfg.MaxLookups > math.MaxUint16 {
		return lneto.ErrInvalidConfig
	}
	c.connID++
	c.lport = cfg.LocalPort
	n := cfg.MaxLookups
	if cap(c.rawlookups) < n {
		grown := make([]lookup, n)
		copy(grown, c.rawlookups[:cap(c.rawlookups)]) // Keep slot buffers.
		c.rawlookups = grown
	} else {
		c.rawlookups = c.rawlookups[:n]
	}
	internal.SliceReuse(&c.lidxs, n)
	for i := range n {
		c.lidxs = append(c.lidxs, uint16(i))
	}
	c.lidxs = c.lidxs[:0]
	return nil
}

func (c *Client) Protocol() uint64 { return uint64(lneto.IPProtoUDP) }

func (c *Client) LocalPort() uint16 { return c.lport }

func (c *Client) ConnectionID() *uint64 { return &c.connID }

// NumLookups returns the number of active lookups, sent or not, completed or not.
func (c *Client) NumLookups() int { return len(c.lidxs) }

// MaxLookups returns the maximum number of lookups that may be active at once.
func (c *Client) MaxLookups() int { return len(c.rawlookups) }

// LookupStart starts a lookup identified by txid which must be unique.
func (c *Client) LookupStart(txid uint16, cfg LookupConfig) error {
	nd := len(cfg.Questions)
	if nd > math.MaxUint16 || nd == 0 || txid == 0 {
		return lneto.ErrInvalidConfig
	} else if c.lidx(txid) >= 0 {
		return lneto.ErrAlreadyRegistered
	} else if len(c.lidxs) == len(c.rawlookups) {
		return lneto.ErrExhausted
	}
	validateSections(&c.vld, cfg.Questions, nil, nil, cfg.Additional)
	if err := c.vld.ErrPop(); err != nil {
		return err
	}
	c.lidxs = c.lidxs[:len(c.lidxs)+1] // Claim first free slot.
	c.lAt(len(c.lidxs)-1).reset(txid, cfg)
	return nil
}

// reset sets the lookup up as a pending lookup txid with cfg's sections. cfg must be validated.
func (lk *lookup) reset(txid uint16, cfg LookupConfig) {
	nd := uint16(len(cfg.Questions))
	maxAns := cfg.MaxResponseAnswers
	if maxAns == 0 {
		maxAns = nd
	}
	lk.enableRecursion = cfg.EnableRecursion
	// Copy sections: the caller may modify its slices while the lookup is active.
	internal.SliceCopyFrom(&lk.questions, cfg.Questions)
	internal.SliceCopyFrom(&lk.additional, cfg.Additional)
	lk.restart(txid)
	lk.resp.LimitResourceDecoding(nd, maxAns, 0, 0)
}

// restart makes the lookup pending as txid, discarding its response.
func (lk *lookup) restart(txid uint16) {
	lk.resp.Reset()
	lk.txid = txid
	lk.respFlags = 0
	lk.state = CQueryPending
}

// LookupPeek reports whether the lookup txid has completed. ok is false if no such lookup is active.
func (c *Client) LookupPeek(txid uint16) (state StateClientQuery, ok bool) {
	idx := c.lidx(txid)
	if idx < 0 {
		return 0, false
	}
	return c.lAt(idx).state, true
}

// LookupPop removes the lookup by txid. completed=true if the lookup already completed.
func (c *Client) LookupPop(txid uint16) (state StateClientQuery, ok bool) {
	idx := c.lidx(txid)
	if idx < 0 {
		return 0, false
	}
	state = c.lAt(idx).state
	c.lidxRemove(idx)
	return state, true
}

// LookupResponse returns the decoded response corresponding to the lookup identied by txid. See [HeaderFlags.ResponseCode] to check if lookup succesful.
// resp is owned by Client and valid until txid removed with [Client.LookupPop], [Client.Reset], [Client.Abort] or [Client.Configure],
// or restarted with [Client.LookupCanonicalRestart]. Starting, completing or removing other lookups does not affect resp.
func (c *Client) LookupResponse(txid uint16) (resp *Message, flags HeaderFlags, ok bool) {
	idx := c.lidx(txid)
	if idx < 0 || c.lAt(idx).state != CQueryDone {
		return nil, 0, false
	}
	lk := c.lAt(idx)
	return &lk.resp, lk.respFlags, true
}

// LookupIPAnswers writes response answer addresses of lookup txid into dst and returns number of addresses written.
// If response holds CNAME but no address [ErrUnresolvedCNAME] is returned and can be restarted with [Client.LookupCanonicalRestart].
func (c *Client) LookupIPAnswers(txid uint16, dst []netip.Addr) (n int, state StateClientQuery, err error) {
	idx := c.lidx(txid)
	if idx < 0 {
		return 0, 0, lneto.ErrNoSuchResource
	}
	lk := c.lAt(idx)
	state = lk.state
	if lk.state != CQueryDone {
		return 0, state, nil
	} else if rcode := lk.respFlags.ResponseCode(); rcode != 0 {
		return 0, state, rcode
	} else if len(lk.resp.Questions) == 0 {
		return 0, state, ErrNoAnswer
	}
	// The response echoes the question, which after following a CNAME holds the canonical name.
	host := lk.resp.Questions[0].Name
	nans, err := lk.resp.WriteAnswers(dst, host)
	if nans == 0 && err == nil {
		err = ErrNoAnswer
		if lk.resp.CanonicalName(host).Len() != 0 {
			err = ErrUnresolvedCNAME
		}
	}
	return int(nans), state, err
}

// LookupCanonicalRestart restarts a completed lookup txid as newTxid, querying the canonical name its response holds.
// Use when [Message.WriteAnswers] outputs no addresses and [Message.CanonicalName] output is non-zero lengthed.
func (c *Client) LookupCanonicalRestart(txid, newTxid uint16) error {
	idx := c.lidx(txid)
	if idx < 0 || c.lAt(idx).state != CQueryDone {
		return errNoResponse
	} else if newTxid == 0 {
		return lneto.ErrInvalidConfig
	} else if c.lidx(newTxid) >= 0 {
		return lneto.ErrAlreadyRegistered
	}
	lk := c.lAt(idx)
	if rcode := lk.respFlags.ResponseCode(); rcode != 0 {
		return rcode
	} else if len(lk.questions) != 1 {
		return lneto.ErrUnsupported
	}
	cname := lk.resp.CanonicalName(lk.questions[0].Name)
	if cname.Len() == 0 {
		return errNoCNAME
	} else if err := cname.validate(); err != nil {
		return err
	}
	lk.questions[0].Name.CopyFrom(cname) // cname aliases lk.resp, never the question.
	lk.restart(newTxid)
	return nil
}

// Reset removes all lookups.
func (c *Client) Reset() {
	c.lidxs = c.lidxs[:0]
}

// Abort removes all lookups and invalidates the client's registration on a stack.
func (c *Client) Abort() {
	c.Reset()
	c.connID++
}

// Encapsulate writes the query of the first lookup not yet sent. Returns 0 and nil error if there is none.
func (c *Client) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	idx := c.lidxPending()
	if idx < 0 {
		return 0, nil
	}
	lk := c.lAt(idx)
	frame := carrierData[offsetToFrame:]
	msglen := uint16(SizeHeader + lenSections(lk.questions, nil, nil, lk.additional))
	if msglen > uint16(len(frame)) {
		return 0, errCalcLen
	}
	flags := NewClientHeaderFlags(OpCodeQuery, lk.enableRecursion)
	n, err := PutMessage(frame, lk.txid, flags, lk.questions, nil, nil, lk.additional)
	if err != nil {
		return 0, err
	}
	lk.state = CQueryOutstanding
	// Unset don't frag since DNS requests go through LOTS of nodes.
	// if frameOffset >= 28 {
	// 	version := carrierData[0] >> 4
	// 	if version == 4 {
	// 		carrierData[6], carrierData[7] = 0, 0 // unset IP Flags.
	// 	}
	// }
	return n, nil
}

// Demux decodes a response to a sent lookup query, matched by txid, opcode and question section.
// Frames that answer no lookup are ignored.
func (c *Client) Demux(carrierData []byte, frameOffset int) error {
	frame := carrierData[frameOffset:]
	f, err := NewFrame(frame)
	if err != nil {
		return err
	}
	idx := c.lidx(f.TxID())
	if idx < 0 || c.lAt(idx).state != CQueryOutstanding || !c.lAt(idx).isResponse(f) {
		return nil // Not meant for our client.
	}
	lk := c.lAt(idx)
	lk.respFlags = f.Flags()
	lk.state = CQueryDone
	_, incompleteButOK, err := lk.resp.Decode(frame)
	if err != nil && !incompleteButOK {
		return err
	}
	return nil
}

// isResponse reports whether frame responds to the lookup: response flag set,
// same opcode and same question section. txid is checked by the caller.
func (lk *lookup) isResponse(f Frame) bool {
	flags := f.Flags()
	if !flags.IsResponse() || flags.OpCode() != OpCodeQuery || int(f.QDCount()) != len(lk.questions) {
		return false
	}
	off := uint16(SizeHeader)
	for i := range lk.questions {
		var ok bool
		off, ok = lk.questions[i].equalWireFold(f.buf, off)
		if !ok {
			return false
		}
	}
	return true
}

// lAt returns the active lAt at position idx of lidxs.
func (c *Client) lAt(idx int) *lookup {
	return &c.rawlookups[c.lidxs[idx]]
}

// lidxPending gets lidxs position of next pending lookup.
func (c *Client) lidxPending() int {
	idx := -1
	for i := range c.lidxs {
		if c.lAt(i).state == CQueryPending {
			idx = i
			break
		}
	}
	return idx
}

// lidx returns lidxs position of active lookup matching transaction ID.
func (c *Client) lidx(txid uint16) int {
	for i := range c.lidxs {
		if c.lAt(i).txid == txid {
			return i
		}
	}
	return -1
}

// lidxRemove frees the lookup at lidxs position idx by swapping its slot index past the end.
// The lookup itself stays in place, keeping its buffers for reuse.
func (c *Client) lidxRemove(idx int) {
	last := len(c.lidxs) - 1
	c.lidxs[idx], c.lidxs[last] = c.lidxs[last], c.lidxs[idx]
	c.lidxs = c.lidxs[:last]
}

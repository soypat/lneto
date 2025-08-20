package dhcpv4

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"net"
	"net/netip"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ipv4"
)

type Client struct {
	connID      uint64
	reqHostname string
	clientID    []byte
	hostname    []byte
	dns         []netip.Addr
	ntps        []netip.Addr

	svIPtos    ipv4.ToS
	tRenew     uint32
	tRebind    uint32
	tIPLease   uint32
	currentXID uint32
	state      ClientState
	clientMAC  [6]byte
	offer      addr4
	svip       addr4 // OptServerIdentification.
	siip       addr4 // SIAddr.
	reqIP      addr4
	router     addr4
	subnet     addr4
	broadcast  addr4
	gateway    addr4

	auxbuf [64]byte
}

type addr4 struct {
	addr  [4]byte
	valid bool
}

func (a *addr4) unpack() ([4]byte, bool) {
	return a.addr, a.valid
}

func (a *addr4) setmaybe(data []byte) {
	if len(data) == 4 {
		a.set4([4]byte(data[:]))
	} else {
		a.valid = false
	}
}

func (a *addr4) set4(addr [4]byte) {
	a.valid = true
	a.addr = addr
}

type RequestConfig struct {
	RequestedAddr      [4]byte
	ClientHardwareAddr [6]byte
	// Optional hostname to request.
	Hostname string
	ClientID string
}

// Reset clears all DHCP state and disconnects from Stack (increments ConnectionID).
func (c *Client) Reset() {
	c.reset(0)
}

func (c *Client) BeginRequest(xid uint32, cfg RequestConfig) error {
	if len(cfg.Hostname) > 36 {
		return errors.New("requested hostname too long")
	} else if c.state != StateInit && c.state != 0 {
		return errors.New("dhcp client must be closed/Init before new request")
	} else if xid == 0 {
		return errors.New("zero xid")
	} else if len(cfg.ClientID) > 32 {
		return errors.New("client ID too long")
	}
	c.reset(xid)
	c.state = StateInit
	c.currentXID = xid
	c.reqHostname = cfg.Hostname
	c.reqIP = addr4{addr: cfg.RequestedAddr, valid: true}
	c.clientMAC = cfg.ClientHardwareAddr
	if cfg.ClientID != "" {
		c.clientID = append(c.clientID[:0], cfg.ClientID...)
	} else {
		c.clientID = append(c.clientID[:0], c.clientMAC[:]...)
	}
	return nil
}

func (c *Client) Protocol() uint64      { return uint64(lneto.IPProtoUDP) }
func (c *Client) LocalPort() uint16     { return DefaultClientPort }
func (c *Client) ConnectionID() *uint64 { return &c.connID }

func (c *Client) setIP(b []byte, frameOffset int) {
	if frameOffset < 28 {
		return // Not an IP/UDP frame.
	}
	ifrm, _ := ipv4.NewFrame(b)
	ifrm.SetID((uint16(c.currentXID) ^ uint16(c.currentXID>>16)) + uint16(c.state))
	if c.state > StateInit {
		// Match server ToS since some routers drop DHCP requests if no ToS set apparently?
		ifrm.SetToS(c.svIPtos)
	}
	src := ifrm.SourceAddr()
	for i := range src {
		src[i] = 0
	}
	dst := ifrm.DestinationAddr()[:]
	for i := range dst {
		dst[i] = 255
	}
}

func (c *Client) Encapsulate(carrierFrame []byte, frameOffset int) (int, error) {
	if c.isClosed() {
		return 0, net.ErrClosed
	} else if c.state == StateSelecting && !c.offer.valid {
		return 0, nil // No offer received yet.
	} else if c.state == StateBound {
		return 0, nil // Done!
	} else if c.state == StateRequesting {
		return 0, nil // Currently awaiting ACK.
	}
	dst := carrierFrame[frameOffset:]
	frm, err := NewFrame(dst)
	if err != nil {
		return 0, err
	}
	opts := frm.OptionsPayload()
	if len(opts) < 255 {
		return 0, errors.New("too short packet for options")
	}

	var nextState ClientState
	var numOpts int
	switch c.state {
	case StateInit:
		// Send out discover.
		n, _ := EncodeOption(opts[numOpts:], OptMessageType, byte(MsgDiscover))
		numOpts += n
		n, _ = EncodeOption(opts[numOpts:], OptParameterRequestList, defaultParamReqList...)
		numOpts += n
		maxlen := len(dst)
		if maxlen > math.MaxUint16 {
			maxlen = math.MaxUint16
		}
		n, _ = EncodeOption16(opts[numOpts:], OptMaximumMessageSize, uint16(maxlen))
		numOpts += n
		if !c.reqIP.valid {
			n, _ = EncodeOption(opts[numOpts:], OptRequestedIPaddress, c.reqIP.addr[:]...)
			numOpts += n
		}
		nextState = StateSelecting

	case StateSelecting:
		if !c.offer.valid {
			return 0, nil // Offer not yet received.
		}
		// Send out request, we know we've received an offer by now.
		n, _ := EncodeOption(opts[numOpts:], OptMessageType, byte(MsgRequest))
		numOpts += n
		n, _ = EncodeOption(opts[numOpts:], OptRequestedIPaddress, c.offer.addr[:]...)
		numOpts += n
		n, _ = EncodeOption(opts[numOpts:], OptServerIdentification, c.svip.addr[:]...)
		numOpts += n
		nextState = StateRequesting

	default:
		return 0, errors.New("unhandled state" + c.state.String())
	}
	n, _ := EncodeOption(opts[numOpts:], OptClientIdentifier, c.clientID...)
	numOpts += n
	if len(c.reqHostname) > 0 {
		n, err := EncodeOptionString(opts[numOpts:], OptHostName, c.reqHostname)
		numOpts += n
		if err != nil {
			return 0, err
		}
	}

	opts[numOpts] = byte(OptEnd)
	numOpts++
	c.setHeader(frm)
	c.setIP(carrierFrame, frameOffset)
	c.state = nextState
	return OptionsOffset + numOpts, nil
}

func (c *Client) Demux(carrierData []byte, frameOffset int) error {
	if c.isClosed() {
		return net.ErrClosed
	}
	pkt := carrierData[frameOffset:]
	frm, err := NewFrame(pkt)
	if err != nil {
		return err
	} else if frm.XID() != c.currentXID {
		return errors.New("dhcpv4 unexpected transaction ID")
	} else if frm.MagicCookie() != MagicCookie {
		return errors.New("dhcpv4 bad magic cookie")
	}
	msgType := c.getMessageType(frm)
	if msgType == MsgNack {
		return errors.New("dhcp nack received")
	}

	msgOK := msgType == MsgOffer || msgType == MsgAck
	if !msgOK {
		return fmt.Errorf("invalid DHCP message received or none got=%d", msgType)
	}
	err = c.setOptions(frm)
	if err != nil {
		return err
	}

	switch c.state {
	case StateSelecting:
		if msgType == MsgOffer && !c.offer.valid {
			// Lock in on this offer.
			c.gateway.set4(*frm.GIAddr())
			c.offer.set4(*frm.YIAddr())
			c.siip.set4(*frm.SIAddr())
		}

	case StateRequesting:
		if msgType == MsgAck {
			c.state = StateBound
		}
	default:
		return fmt.Errorf("dcpv4 unexpected state in recv %s", c.state.String())
	}
	if frameOffset > 28 && c.svIPtos == 0 {
		ifrm, _ := ipv4.NewFrame(carrierData)
		c.svIPtos = ifrm.ToS()
	}
	return nil
}

func (c *Client) getMessageType(frm Frame) MessageType {
	c.auxbuf[0] = 255
	ptrMsgType := &c.auxbuf[0]
	frm.ForEachOption(func(_ int, opt OptNum, data []byte) error {
		if len(data) == 1 {
			*ptrMsgType = data[0]
			return io.EOF
		}
		return nil
	})
	return MessageType(*ptrMsgType)
}

func (c *Client) setOptions(frm Frame) error {
	err := frm.ForEachOption(func(_ int, opt OptNum, data []byte) error {
		switch opt {
		case OptRenewTimeValue:
			c.tRenew = maybeU32(data)
		case OptIPAddressLeaseTime:
			c.tIPLease = maybeU32(data)
		case OptRebindingTimeValue:
			c.tRebind = maybeU32(data)
		case OptServerIdentification:
			c.svip.setmaybe(data)
		case OptRouter:
			c.router.setmaybe(data)
		case OptBroadcastAddress:
			c.broadcast.setmaybe(data)
		case OptSubnetMask:
			c.subnet.setmaybe(data)

		case OptHostName:
			if len(data) < maxHostSize {
				c.hostname = append(c.hostname[:0], data...)
			}
		case OptDNSServers:
			if len(c.dns) > 0 || len(data)%4 != 0 {
				return nil // No DNS parsing if already got in previous exchange.
			}
			for i := 0; i < len(data); i += 4 {
				c.dns = append(c.dns, netip.AddrFrom4([4]byte(data[i:i+4])))
			}
		case OptNTPServersAddresses:
			if len(c.ntps) > 0 || len(data)%4 != 0 {
				return nil
			}
			for i := 0; i < len(data); i += 4 {
				c.ntps = append(c.ntps, netip.AddrFrom4([4]byte(data[i:i+4])))
			}
		}
		return nil
	})
	return err
}

func (c *Client) isClosed() bool { return c.state == 0 || c.currentXID == 0 }

func (c *Client) setHeader(frm Frame) {
	frm.ClearHeader()
	frm.SetOp(OpRequest)
	frm.SetXID(c.currentXID)
	frm.SetHardware(1, 6, 0)
	frm.SetSecs(1)
	if c.state.HasIP() {
		*frm.CIAddr() = c.offer.addr
	}
	if c.state == StateInit {
		siaddr := frm.SIAddr()[:]
		for i := range siaddr {
			siaddr[i] = 255
		}
	} else {
		if !c.siip.valid {
			*frm.SIAddr() = c.svip.addr
		} else {
			*frm.SIAddr() = c.siip.addr
		}
	}
	*frm.YIAddr() = c.offer.addr
	copy(frm.CHAddrAs6()[:], c.clientMAC[:])
	frm.SetMagicCookie(MagicCookie)
}

func (c *Client) reset(xid uint32) {
	*c = Client{
		connID:      c.connID + 1,
		reqHostname: c.reqHostname,
		currentXID:  xid,
		reqIP:       c.reqIP,
		clientMAC:   c.clientMAC,
		clientID:    c.clientID,
	}
}

func (d *Client) State() ClientState { return d.state }

func (d *Client) BroadcastAddr() ([4]byte, bool)                 { return d.broadcast.unpack() }
func (d *Client) AssignedAddr() ([4]byte, bool)                  { return d.offer.unpack() }
func (d *Client) ServerAddr() ([4]byte, bool)                    { return d.svip.unpack() }
func (d *Client) RouterAddr() ([4]byte, bool)                    { return d.router.unpack() }
func (d *Client) GatewayAddr() ([4]byte, bool)                   { return d.gateway.unpack() }
func (d *Client) Subnet() ([4]byte, bool)                        { return d.subnet.unpack() }
func (d *Client) RebindingSeconds() uint32                       { return d.tRebind }
func (d *Client) RenewalSeconds() uint32                         { return d.tRenew }
func (d *Client) IPLeaseSeconds() uint32                         { return d.tIPLease }
func (d *Client) AppendDNSServers(dst []netip.Addr) []netip.Addr { return append(dst, d.dns...) }
func (d *Client) NumDNSServers() int                             { return len(d.dns) }
func (d *Client) DNSServerFirst() netip.Addr {
	if len(d.dns) < 1 {
		return netip.Addr{}
	}
	return d.dns[0]
}

func (d *Client) SubnetPrefix() netip.Prefix {
	if !d.offer.valid {
		return netip.Prefix{}
	}
	m, _ := netip.AddrFrom4(d.offer.addr).Prefix(int(d.SubnetCIDRBits()))
	return m
}

func (d *Client) SubnetCIDRBits() uint8 {
	if !d.subnet.valid {
		return 0
	}
	v := binary.BigEndian.Uint32(d.subnet.addr[:])
	return 32 - uint8(bits.TrailingZeros32(v))
}

var defaultParamReqList = []byte{
	byte(OptSubnetMask),
	byte(OptTimeOffset),
	byte(OptRouter),
	byte(OptInterfaceMTUSize),
	byte(OptBroadcastAddress),
	byte(OptDNSServers),
	byte(OptDomainName),
	byte(OptNTPServersAddresses),
}

func maybeU32(b []byte) uint32 {
	if len(b) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

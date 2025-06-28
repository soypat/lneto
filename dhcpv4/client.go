package dhcpv4

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"net"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ipv4"
)

type Client struct {
	connID      uint64
	reqHostname string
	hostname    []byte
	dns         [][4]byte

	tRenew     uint32
	tRebind    uint32
	tIPLease   uint32
	currentXID uint32
	state      ClientState
	offer      [4]byte
	svip       [4]byte
	reqIP      [4]byte
	router     [4]byte
	subnet     [4]byte
	broadcast  [4]byte
	gateway    [4]byte
	clientMAC  [6]byte

	auxbuf [64]byte
}

type RequestConfig struct {
	RequestedAddr      [4]byte
	ClientHardwareAddr [6]byte
	// Optional hostname to request.
	Hostname string
}

func (c *Client) BeginRequest(xid uint32, cfg RequestConfig) error {
	if len(cfg.Hostname) > 36 {
		return errors.New("requested hostname too long")
	} else if c.state != StateInit && c.state != 0 {
		return errors.New("dhcp client must be closed/done before new request")
	} else if xid == 0 {
		return errors.New("zero xid")
	}
	c.reset(xid)
	c.state = StateInit
	c.currentXID = xid
	c.reqHostname = cfg.Hostname
	c.reqIP = cfg.RequestedAddr
	c.clientMAC = cfg.ClientHardwareAddr
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
		// TODO(soypat): Document why disabling ToS used by DHCP server may cause Request to fail.
		// Apparently server sets ToS=192. Uncommenting this line causes DHCP to fail on my setup.
		// If left fixed at 192, DHCP does not work.
		// If left fixed at 0, DHCP does not work.
		// Apparently ToS is a function of which state of DHCP one is in. Not sure why code below works.
		// Note: Not exactly needed for all servers.
		const ecnmask = 0b1100_0000
		ifrm.SetToS(ecnmask)
	}
}

func (c *Client) Encapsulate(carrierFrame []byte, frameOffset int) (int, error) {
	if c.isClosed() {
		return 0, net.ErrClosed
	} else if c.state == StateSelecting && c.offer == [4]byte{} {
		return 0, nil // No offer received yet.
	} else if c.state == StateBound {
		return 0, nil // Done!
	}
	dst := carrierFrame[frameOffset:]
	frm, err := NewFrame(dst)
	if err != nil {
		return 0, err
	}

	// var options []Option
	// var nextState ClientState
	optBuf := c.auxbuf[:0]
	var nextState ClientState
	switch c.state {
	case StateInit:
		// Send out discover.
		optBuf = AppendOption(optBuf, OptMessageType, byte(MsgDiscover))
		optBuf = AppendOption(optBuf, OptParameterRequestList, defaultParamReqList...)
		optBuf = AppendOption(optBuf, OptClientIdentifier, c.clientMAC[:]...)
		maxlen := len(dst)
		if maxlen > math.MaxUint16 {
			maxlen = math.MaxUint16
		}
		optBuf = AppendOption(optBuf, OptMaximumMessageSize, byte(maxlen>>8), byte(maxlen))
		if c.reqIP != [4]byte{} {
			optBuf = AppendOption(optBuf, OptRequestedIPaddress, c.reqIP[:]...)
		}
		nextState = StateSelecting

	case StateSelecting:
		if c.offer == ([4]byte{}) {
			return 0, nil // Offer not yet received.
		}
		// Send out request, we know we've received an offer by now.
		optBuf = AppendOption(optBuf, OptMessageType, byte(MsgRequest))
		optBuf = AppendOption(optBuf, OptRequestedIPaddress, c.offer[:]...)
		optBuf = AppendOption(optBuf, OptServerIdentification, c.svip[:]...)
		nextState = StateRequesting

	default:
		return 0, errors.New("unhandled state")
	}
	if len(c.reqHostname) > 0 {
		optBuf = AppendOptionString(optBuf, OptHostName, c.reqHostname)
	}
	optBuf = append(optBuf, 0xff) // End mark.
	options := frm.OptionsPayload()
	if len(optBuf) > len(options) {
		return 0, errors.New("DHCPv4 short buffer for options")
	}
	c.setHeader(frm)
	n := copy(options, optBuf)
	c.setIP(carrierFrame, frameOffset)
	c.state = nextState
	return optionsOffset + n, nil
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
		if msgType == MsgOffer && c.offer == [4]byte{} {
			// Lock in on this offer.
			c.gateway = *frm.GIAddr()
			c.offer = *frm.YIAddr()
			c.svip = *frm.SIAddr()
		}

	case StateRequesting:
		if msgType == MsgAck {
			c.state = StateBound
		}
	default:
		return fmt.Errorf("dcpv4 unexpected state in recv %s", c.state.String())
	}
	return nil
}

func (c *Client) getMessageType(frm Frame) MessageType {
	c.auxbuf[0] = 255
	ptrMsgType := &c.auxbuf[0]
	frm.ForEachOption(func(opt OptNum, data []byte) error {
		if len(data) == 1 {
			*ptrMsgType = data[0]
			return io.EOF
		}
		return nil
	})
	return MessageType(*ptrMsgType)
}

func (c *Client) setOptions(frm Frame) error {
	return frm.ForEachOption(func(opt OptNum, data []byte) error {
		switch opt {
		case OptRenewTimeValue:
			c.tRenew = maybeU32(data)
		case OptIPAddressLeaseTime:
			c.tIPLease = maybeU32(data)
		case OptRebindingTimeValue:
			c.tRebind = maybeU32(data)

		case OptServerIdentification:
			c.svip = maybe4byte(data)
		case OptRouter:
			c.router = maybe4byte(data)
		case OptBroadcastAddress:
			c.broadcast = maybe4byte(data)
		case OptSubnetMask:
			c.subnet = maybe4byte(data)

		case OptHostName:
			if len(data) < maxHostSize {
				c.hostname = append(c.hostname[:0], data...)
			}
		case OptDNSServers:
			if len(c.dns) > 0 || len(data)%4 != 0 {
				return nil // No DNS parsing if already got in previous exchange.
			}
			for i := 0; i < len(data); i += 4 {
				c.dns = append(c.dns, [4]byte(data[i:i+4]))
			}
		}
		return nil
	})
}

func (c *Client) isClosed() bool { return c.state == 0 || c.currentXID == 0 }

func (c *Client) setHeader(frm Frame) {
	frm.ClearHeader()
	frm.SetOp(OpRequest)
	frm.SetXID(c.currentXID)
	frm.SetHardware(1, 6, 0)
	frm.SetSecs(1)
	if c.state == StateRequesting || c.state == StateSelecting || c.state == StateBound || c.state == StateRenewing {
		copy(frm.CIAddr()[:], c.offer[:])
	}
	copy(frm.SIAddr()[:], c.svip[:])
	copy(frm.YIAddr()[:], c.offer[:])
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
	}
}

func (d *Client) State() ClientState { return d.state }

func (d *Client) BroadcastAddr() [4]byte                   { return d.broadcast }
func (d *Client) AssignedAddr() [4]byte                    { return d.offer }
func (d *Client) ServerAddr() [4]byte                      { return d.svip }
func (d *Client) RouterAddr() [4]byte                      { return d.router }
func (d *Client) GatewayAddr() [4]byte                     { return d.gateway }
func (d *Client) RebindingSeconds() uint32                 { return d.tRebind }
func (d *Client) RenewalSeconds() uint32                   { return d.tRenew }
func (d *Client) IPLeaseSeconds() uint32                   { return d.tIPLease }
func (d *Client) AppendDNSServers(dst [][4]byte) [][4]byte { return append(dst, d.dns...) }

func (d *Client) CIDRBits() uint8 {
	if d.subnet == [4]byte{} {
		return 0
	}
	v := binary.BigEndian.Uint32(d.subnet[:])
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

func maybe4byte(b []byte) [4]byte {
	if len(b) != 4 {
		return [4]byte{}
	}
	return [4]byte(b)
}

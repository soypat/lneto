package dhcpv4

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

type Server struct {
	connID   uint64
	nextAddr netip.Addr
	prefix   netip.Prefix
	hosts    map[[36]byte]serverEntry
	vld      lneto.Validator
	pending  int
	port     uint16
	siaddr   [4]byte
	gwaddr   [4]byte
}

type serverEntry struct {
	hostname    string
	xid         uint32
	port        uint16
	addr        [4]byte
	requestlist [10]byte
	hwaddr      [6]byte
	clientIdlen uint8
	// Possible states:
	//  - 0: No entry/uninitialized
	//  - Init: Server received discover, pending Offer sent out.
	//  - Selecting: Server sent out offer, request not received.
	//  - Requesting: Request received, pending Ack sent out.
	//  - Bound: Request sent out, no more pending data to be sent.
	state ClientState
}

func (sv *Server) Reset(serverAddr [4]byte, port uint16) {
	*sv = Server{
		connID:   sv.connID + 1,
		siaddr:   serverAddr,
		port:     port,
		hosts:    sv.hosts,
		nextAddr: netip.AddrFrom4(serverAddr),
	}
	if sv.hosts == nil {
		sv.hosts = make(map[[36]byte]serverEntry)
	} else {
		for k := range sv.hosts {
			delete(sv.hosts, k)
		}
	}
}

func (sv *Server) ConnectionID() *uint64 { return &sv.connID }
func (sv *Server) Protocol() uint64      { return uint64(lneto.IPProtoUDP) }
func (sv *Server) Port() uint16          { return sv.port }

func (sv *Server) Demux(carrierData []byte, frameOffset int) error {
	isIPLayer := frameOffset >= 28
	dhcpData := carrierData[frameOffset:]
	dfrm, err := NewFrame(dhcpData)
	if err != nil {
		return err
	}
	dfrm.ValidateSize(&sv.vld)
	if sv.vld.HasError() {
		return sv.vld.ErrPop()
	}

	var msgType MessageType
	var clientID []byte
	var reqlist []byte
	var reqAddr []byte
	var hostname []byte
	err = dfrm.ForEachOption(func(off int, op OptNum, data []byte) error {
		switch op {
		case OptMessageType:
			if len(data) == 1 {
				msgType = MessageType(data[0])
			}
		case OptHostName:
			if len(data) <= 36 {
				hostname = data
			}
		case OptClientIdentifier:
			if len(data) <= 36 {
				clientID = data
			}
		case OptParameterRequestList:
			if len(data) > 36 {
				return errors.New("too many request options")
			}
			reqlist = data
		case OptRequestedIPaddress:
			if len(data) == 4 {
				reqAddr = data
			}
		}
		return nil
	})
	var clientIDRaw [36]byte
	var client serverEntry
	var clientExists bool
	if len(clientID) == 0 {
		client, clientIDRaw, clientExists = sv.getClientByIP(*dfrm.CIAddr())
	} else {
		copy(clientIDRaw[:], clientID)
		client, clientExists = sv.getClient(clientIDRaw)
	}

	switch msgType {
	case MsgDiscover:
		if clientExists {
			err = errors.New("DHCP Discover on initialized client")
			break
		}
		if len(reqAddr) == 4 {
			println("requested", reqAddr[0], reqAddr[1], reqAddr[2], reqAddr[3])
		}
		sv.nextAddr = sv.nextAddr.Next()
		copy(client.requestlist[:], reqlist)
		client.addr = sv.nextAddr.As4()
		client.state = StateInit
		client.hostname = string(hostname)
		client.xid = dfrm.XID()
		client.hwaddr = *dfrm.CHAddrAs6()
		if isIPLayer {
			_, client.port, _ = getSrcIPPort(carrierData)
		}
		client.clientIdlen = uint8(len(clientID))
		sv.pending++

	case MsgRequest:
		if !clientExists {
			err = errors.New("request for non existing client?")
		} else if dfrm.XID() != client.xid {
			err = errors.New("unexpected XID for client")
		} else if client.state != StateSelecting && client.state != StateRequesting {
			err = errors.New("DHCP request unexpected state")
		}
		if err != nil {
			break
		}
		client.state = StateRequesting
		sv.pending++

	default:
		err = errors.New("unhandled message type")
	}
	if err != nil {
		return fmt.Errorf("msgtype=%s client=%+v: %w", msgType.String(), client, err)
	}
	sv.hosts[clientIDRaw] = client
	return nil
}

func (sv *Server) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	carrierIsIP := offsetToIP >= 0
	dfrm, err := NewFrame(carrierData[offsetToFrame:])
	optBuf := dfrm.OptionsPayload()[:]
	if err != nil {
		return 0, err
	} else if len(optBuf) < 255 {
		return 0, errOptionNotFit
	}
	if sv.pending == 0 {
		return 0, nil // No pending outgoing frames.a
	}

	var client serverEntry
	var clientID [36]byte
	for k, v := range sv.hosts {
		pending := v.state == StateInit || v.state == StateRequesting
		if pending {
			client = v
			clientID = k
			break
		}
	}
	if client.state == 0 {
		return 0, nil // Nothing to do.
	}
	futureState := ClientState(0)
	var nopt int
	switch client.state {
	case StateInit:
		futureState = StateSelecting
		nopt, err = EncodeOption(optBuf[nopt:], OptMessageType, byte(MsgOffer))
	case StateRequesting:
		futureState = StateBound
		nopt, err = EncodeOption(optBuf[nopt:], OptMessageType, byte(MsgAck))
		*dfrm.CIAddr() = client.addr
	}
	if err != nil {
		return 0, err
	}
	n, _ := EncodeOption(optBuf[nopt:], OptServerIdentification, sv.siaddr[:]...)
	nopt += n
	if sv.gwaddr != [4]byte{} {
		n, _ = EncodeOption(optBuf[nopt:], OptRouter, sv.gwaddr[:]...)
		nopt += n
	}
	optBuf[nopt] = byte(OptEnd)
	nopt++

	dfrm.ClearHeader()
	dfrm.SetOp(OpReply)
	dfrm.SetHardware(1, 6, 0)
	dfrm.SetXID(client.xid)
	dfrm.SetSecs(0)
	dfrm.SetFlags(0)
	*dfrm.YIAddr() = client.addr // Offer here.
	*dfrm.SIAddr() = sv.siaddr
	*dfrm.GIAddr() = sv.gwaddr
	copy(dfrm.CHAddrAs6()[:], client.hwaddr[:])
	dfrm.SetMagicCookie(MagicCookie)
	if carrierIsIP {
		err = internal.SetIPAddrs(carrierData[offsetToIP:], 0, sv.siaddr[:], client.addr[:])
		if err != nil {
			return 0, err
		}
	}

	client.state = futureState

	// Set server state.
	sv.hosts[clientID] = client
	sv.pending--
	return OptionsOffset + nopt, nil
}

func (sv *Server) getClient(clientID [36]byte) (serverEntry, bool) {
	entry, ok := sv.hosts[clientID]
	return entry, ok
}

func (sv *Server) getClientByIP(ip [4]byte) (serverEntry, [36]byte, bool) {
	for k, v := range sv.hosts {
		if v.addr == ip {
			return v, k, true
		}
	}
	return serverEntry{}, [36]byte{}, false
}

func getSrcIPPort(ipCarrier []byte) (srcaddr []byte, port uint16, err error) {
	srcaddr, _, _, off, err := internal.GetIPAddr(ipCarrier)
	if err != nil {
		return srcaddr, port, err
	} else if len(ipCarrier[off:]) < 2 {
		return srcaddr, port, errors.New("getSrcIPPort got only IP layer")
	}
	port = binary.BigEndian.Uint16(ipCarrier[off:]) // TCP and UDP share same port offsets.
	return srcaddr, port, nil
}

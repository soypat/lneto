package dhcpv4

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

var errOptionNotFit = errors.New("DHCPv4: options dont fit")

type Server struct {
	connID       uint64
	nextAddr     netip.Addr
	prefix       netip.Prefix
	hosts        map[[36]byte]serverEntry
	vld          lneto.Validator
	pending      int
	leaseSeconds uint32
	port         uint16
	siaddr       [4]byte
	gwaddr       [4]byte
	dns          [4]byte
}

// ServerConfig contains configuration parameters for [Server.Configure].
type ServerConfig struct {
	// ServerAddr is the DHCP server's own IPv4 address.
	ServerAddr [4]byte
	// Gateway advertised to clients as default router. Zero value omits the option.
	Gateway [4]byte
	// DNS server address advertised to clients. Zero value omits the option.
	DNS [4]byte
	// Subnet defines the network prefix for address allocation and subnet mask responses.
	Subnet netip.Prefix
	// LeaseSeconds is the lease duration. Zero defaults to 3600.
	LeaseSeconds uint32
	// Port is the server listening port. Zero defaults to DefaultServerPort.
	Port uint16
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
	//  - Bound: Ack sent out, no more pending data to be sent.
	state ClientState
}

// Configure resets and configures the server with the given configuration.
// The connection ID is incremented on each call to invalidate existing connections.
// The hosts map is reused across calls to avoid reallocation.
func (sv *Server) Configure(cfg ServerConfig) error {
	svAddr := netip.AddrFrom4(cfg.ServerAddr)
	if !cfg.Subnet.IsValid() {
		return errors.New("dhcpv4 server: invalid subnet")
	} else if !cfg.Subnet.Contains(svAddr) {
		return errors.New("dhcpv4 server: server address outside subnet")
	}
	port := cfg.Port
	if port == 0 {
		port = DefaultServerPort
	}
	lease := cfg.LeaseSeconds
	if lease == 0 {
		lease = 3600
	}
	hosts := sv.hosts
	if hosts == nil {
		hosts = make(map[[36]byte]serverEntry)
	} else {
		for k := range hosts {
			delete(hosts, k)
		}
	}
	*sv = Server{
		connID:       sv.connID + 1,
		siaddr:       cfg.ServerAddr,
		gwaddr:       cfg.Gateway,
		dns:          cfg.DNS,
		prefix:       cfg.Subnet,
		port:         port,
		leaseSeconds: lease,
		nextAddr:     svAddr,
		hosts:        hosts,
	}
	return nil
}

func (sv *Server) ConnectionID() *uint64 { return &sv.connID }
func (sv *Server) Protocol() uint64      { return uint64(lneto.IPProtoUDP) }
func (sv *Server) LocalPort() uint16     { return sv.port }

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
	if err != nil {
		return err
	}
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
		if clientExists && (client.state == StateInit || client.state == StateRequesting) {
			sv.pending-- // Cancel unfulfilled pending response.
		}
		if !clientExists {
			addr, ok := sv.allocAddr(reqAddr)
			if !ok {
				return errors.New("dhcpv4 server: address pool exhausted")
			}
			client.addr = addr
		}
		copy(client.requestlist[:], reqlist)
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
			err = errors.New("request for non existing client")
		} else if dfrm.XID() != client.xid {
			err = errors.New("unexpected XID for client")
		} else if client.state != StateSelecting && client.state != StateRequesting {
			err = errors.New("DHCP request unexpected state")
		}
		if err != nil {
			break
		}
		if client.state == StateSelecting {
			client.state = StateRequesting
			sv.pending++
		}

	case MsgRelease:
		if clientExists {
			if client.state == StateInit || client.state == StateRequesting {
				sv.pending--
			}
			delete(sv.hosts, clientIDRaw)
			return nil
		}

	default:
		err = fmt.Errorf("unhandled message type %s", msgType.String())
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
		return 0, nil // No pending outgoing frames.
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
	if sv.prefix.IsValid() {
		bits := uint(sv.prefix.Bits())
		mask := ^uint32(0) << (32 - bits)
		var maskBuf [4]byte
		binary.BigEndian.PutUint32(maskBuf[:], mask)
		n, _ = EncodeOption(optBuf[nopt:], OptSubnetMask, maskBuf[:]...)
		nopt += n
	}
	if sv.dns != [4]byte{} {
		n, _ = EncodeOption(optBuf[nopt:], OptDNSServers, sv.dns[:]...)
		nopt += n
	}
	if sv.leaseSeconds > 0 {
		n, _ = EncodeOption32(optBuf[nopt:], OptIPAddressLeaseTime, sv.leaseSeconds)
		nopt += n
		n, _ = EncodeOption32(optBuf[nopt:], OptRenewTimeValue, sv.leaseSeconds/2)
		nopt += n
		n, _ = EncodeOption32(optBuf[nopt:], OptRebindingTimeValue, sv.leaseSeconds*7/8)
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

// allocAddr allocates the next available address from the pool.
// If reqAddr is a valid 4-byte address within the subnet and not already assigned,
// it is preferred. Returns false if the pool is exhausted.
func (sv *Server) allocAddr(reqAddr []byte) ([4]byte, bool) {
	if len(reqAddr) == 4 {
		candidate := netip.AddrFrom4([4]byte(reqAddr))
		if sv.prefix.Contains(candidate) && candidate.As4() != sv.siaddr && !sv.isAddrAssigned(candidate) {
			return candidate.As4(), true
		}
	}
	sv.nextAddr = sv.nextAddr.Next()
	if !sv.prefix.Contains(sv.nextAddr) {
		return [4]byte{}, false
	}
	// Reject broadcast address (all host bits set).
	a := sv.nextAddr.As4()
	hostBits := uint(32 - sv.prefix.Bits())
	hostMask := ^uint32(0) >> (32 - hostBits)
	if binary.BigEndian.Uint32(a[:])&hostMask == hostMask {
		return [4]byte{}, false
	}
	return a, true
}

func (sv *Server) isAddrAssigned(addr netip.Addr) bool {
	a4 := addr.As4()
	for _, v := range sv.hosts {
		if v.addr == a4 {
			return true
		}
	}
	return false
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

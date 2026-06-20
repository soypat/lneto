package dhcpv4

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dhcp"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/ipv4"
)

var errOptionNotFit = errors.New("DHCPv4: options dont fit")

const defaultMaxPending = 8

// Server implements the DHCPv4 server state machine (RFC 2131). It drives the
// DISCOVER->OFFER->REQUEST->ACK exchange and delegates address assignment,
// lease lifetime and per-client option customization to a [dhcp.Allocator].
//
// The Server itself holds no lease database: it keeps only a bounded table of
// in-flight transactions. The persistent client-to-address bindings live in the
// allocator, which may be supplied through [ServerConfig.Allocator] or, when
// omitted, defaults to a [MapAllocator] built from the configuration.
type Server struct {
	connID     uint64
	subnet     ipv4.Prefix
	alloc      dhcp.Allocator
	txns       []txn
	vld        lneto.Validator
	maxPending int
	port       uint16
	siaddr     [4]byte
	gwaddr     [4]byte
	dns        [4]byte
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
	Subnet ipv4.Prefix
	// LeaseSeconds is the lease duration. Zero defaults to 3600. Only used when
	// building the default allocator (Allocator is nil).
	LeaseSeconds uint32
	// Port is the server listening port. Zero defaults to DefaultServerPort.
	Port uint16
	// Allocator delegates address assignment and lease management. When nil a
	// [MapAllocator] is built from ServerAddr, Subnet, LeaseSeconds and Now.
	Allocator dhcp.Allocator
	// MaxPending bounds the number of simultaneous in-flight transactions the
	// server tracks. Zero defaults to a small built-in value.
	MaxPending int
	// Now, when non-nil, is passed to the default allocator to enable lease
	// expiration. Ignored when Allocator is non-nil.
	Now func() time.Time
}

// txn is an in-flight DORA transaction awaiting a response or a follow-up
// request. The committed lease lives in the allocator; txn only carries what
// the server needs to emit OFFER/ACK frames.
type txn struct {
	binding   dhcp.Binding
	clientID  [36]byte
	xid       uint32
	port      uint16
	offered   [4]byte
	hwaddr    [6]byte
	clientLen uint8
	state     ClientState // StateSelecting (offer pending/sent) or StateRequesting (ack pending).
	respond   MessageType // MsgOffer, MsgAck, or 0 when nothing is queued to send.
}

// Configure resets and configures the server with the given configuration.
// The connection ID is incremented on each call to invalidate existing connections.
func (sv *Server) Configure(cfg ServerConfig) error {
	alloc := cfg.Allocator
	if alloc == nil {
		if !cfg.Subnet.IsValid() {
			return errors.New("dhcpv4 server: invalid subnet")
		} else if !cfg.Subnet.Contains(cfg.ServerAddr) {
			return errors.New("dhcpv4 server: server address outside subnet")
		}
		a, err := NewMapAllocator(AllocatorConfig{
			ServerAddr:   cfg.ServerAddr,
			Subnet:       cfg.Subnet,
			LeaseSeconds: cfg.LeaseSeconds,
			Now:          cfg.Now,
		})
		if err != nil {
			return err
		}
		alloc = a
	}
	port := cfg.Port
	if port == 0 {
		port = DefaultServerPort
	}
	maxPending := cfg.MaxPending
	if maxPending <= 0 {
		maxPending = defaultMaxPending
	}
	txns := sv.txns
	if cap(txns) < maxPending {
		txns = make([]txn, 0, maxPending)
	} else {
		txns = txns[:0]
	}
	*sv = Server{
		connID:     sv.connID + 1,
		siaddr:     cfg.ServerAddr,
		gwaddr:     cfg.Gateway,
		dns:        cfg.DNS,
		subnet:     cfg.Subnet,
		port:       port,
		alloc:      alloc,
		txns:       txns,
		maxPending: maxPending,
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

	// Resolve client identity: the client identifier option when present,
	// otherwise the hardware address.
	if len(clientID) == 0 {
		clientID = dfrm.CHAddrAs6()[:]
	}

	req := dhcp.Request{
		ClientID:     clientID,
		Hostname:     hostname,
		ParamReqList: reqlist,
	}
	if sv.subnet.IsValid() {
		req.Subnet = sv.subnet.NetipPrefix()
	}
	if len(reqAddr) == 4 {
		req.Requested = netip.AddrFrom4([4]byte(reqAddr))
	}

	switch msgType {
	case MsgDiscover:
		binding, err := sv.alloc.Offer(req)
		if err != nil {
			return fmt.Errorf("dhcpv4 server offer: %w", err)
		}
		offered, ok := binding.Addr()
		if !ok || !offered.Is4() {
			return errors.New("dhcpv4 server: allocator returned no IPv4 address")
		}
		t := sv.upsertTxn(clientID)
		if t == nil {
			return errors.New("dhcpv4 server: too many pending transactions")
		}
		t.binding = binding
		t.offered = offered.As4()
		t.xid = dfrm.XID()
		t.hwaddr = *dfrm.CHAddrAs6()
		if isIPLayer {
			_, t.port, _ = getSrcIPPort(carrierData)
		}
		t.state = StateSelecting
		t.respond = MsgOffer

	case MsgRequest:
		t := sv.findTxn(clientID)
		if t == nil {
			return errors.New("request for non existing client")
		} else if dfrm.XID() != t.xid {
			return errors.New("unexpected XID for client")
		} else if t.state != StateSelecting && t.state != StateRequesting {
			return errors.New("DHCP request unexpected state")
		}
		binding, err := sv.alloc.Commit(req)
		if err != nil {
			return fmt.Errorf("dhcpv4 server commit: %w", err)
		}
		offered, ok := binding.Addr()
		if !ok || !offered.Is4() {
			return errors.New("dhcpv4 server: allocator returned no IPv4 address")
		}
		t.binding = binding
		t.offered = offered.As4()
		t.state = StateRequesting
		t.respond = MsgAck

	case MsgRelease:
		err = sv.alloc.Release(clientID)
		sv.dropTxn(clientID)
		if err != nil {
			return fmt.Errorf("dhcpv4 server release: %w", err)
		}

	case MsgDecline:
		err = sv.alloc.Decline(req)
		sv.dropTxn(clientID)
		if err != nil {
			return fmt.Errorf("dhcpv4 server decline: %w", err)
		}

	default:
		return fmt.Errorf("unhandled message type %s", msgType.String())
	}
	return nil
}

func (sv *Server) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	carrierIsIP := offsetToIP >= 0
	dfrm, err := NewFrame(carrierData[offsetToFrame:])
	if err != nil {
		return 0, err
	}
	optBuf := dfrm.OptionsPayload()
	if len(optBuf) < 255 {
		return 0, errOptionNotFit
	}

	t := sv.nextPending()
	if t == nil {
		return 0, nil // No pending outgoing frames.
	}

	var nopt int
	n, err := EncodeOption(optBuf[nopt:], OptMessageType, byte(t.respond))
	if err != nil {
		return 0, err
	}
	nopt += n
	n, _ = EncodeOption(optBuf[nopt:], OptServerIdentification, sv.siaddr[:]...)
	nopt += n
	if sv.gwaddr != [4]byte{} {
		n, _ = EncodeOption(optBuf[nopt:], OptRouter, sv.gwaddr[:]...)
		nopt += n
	}
	if sv.subnet.IsValid() {
		bits := uint(sv.subnet.Bits())
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
	if lease, ok := leaseOf(t.binding); ok && lease.Valid > 0 {
		n, _ = EncodeOption32(optBuf[nopt:], OptIPAddressLeaseTime, lease.Valid)
		nopt += n
		n, _ = EncodeOption32(optBuf[nopt:], OptT1Renewal, t.binding.T1)
		nopt += n
		n, _ = EncodeOption32(optBuf[nopt:], OptT2Rebinding, t.binding.T2)
		nopt += n
	}

	// Let the allocator append or rewrite options. dst already holds the
	// server-derived options for this client and binding.
	optBuf, err = sv.alloc.AppendOptions(optBuf[:nopt], t.clientID[:t.clientLen], t.binding)
	if err != nil {
		return 0, err
	}
	nopt = len(optBuf)
	optBuf = dfrm.OptionsPayload()
	if nopt >= len(optBuf) {
		return 0, errOptionNotFit
	}
	optBuf[nopt] = byte(OptEnd)
	nopt++

	dfrm.ClearHeader()
	dfrm.SetOp(OpReply)
	dfrm.SetHardware(1, 6, 0)
	dfrm.SetXID(t.xid)
	dfrm.SetSecs(0)
	dfrm.SetFlags(0)
	*dfrm.YIAddr() = t.offered
	if t.respond == MsgAck {
		*dfrm.CIAddr() = t.offered
	}
	*dfrm.SIAddr() = sv.siaddr
	*dfrm.GIAddr() = sv.gwaddr
	copy(dfrm.CHAddrAs6()[:], t.hwaddr[:])
	dfrm.SetMagicCookie(MagicCookie)
	if carrierIsIP {
		err = internal.SetIPAddrs(carrierData[offsetToIP:], 0, sv.siaddr[:], t.offered[:])
		if err != nil {
			return 0, err
		}
	}

	if t.respond == MsgAck {
		// Transaction complete; the lease now lives in the allocator.
		sv.dropTxnAt(t)
	} else {
		t.respond = 0 // Offer sent, await the client's REQUEST.
	}
	return OptionsOffset + nopt, nil
}

// leaseOf returns the first lease of a binding.
func leaseOf(b dhcp.Binding) (dhcp.Lease, bool) {
	if len(b.Leases) == 0 {
		return dhcp.Lease{}, false
	}
	return b.Leases[0], true
}

// findTxn returns the in-flight transaction for clientID, or nil.
func (sv *Server) findTxn(clientID []byte) *txn {
	for i := range sv.txns {
		if sv.txns[i].matches(clientID) {
			return &sv.txns[i]
		}
	}
	return nil
}

// upsertTxn returns the existing transaction for clientID, reusing its slot, or
// appends a new one. It returns nil if the table is full.
func (sv *Server) upsertTxn(clientID []byte) *txn {
	if t := sv.findTxn(clientID); t != nil {
		t.binding = dhcp.Binding{}
		t.respond = 0
		return t
	}
	if len(sv.txns) >= sv.maxPending {
		return nil
	}
	var t txn
	t.clientLen = uint8(copy(t.clientID[:], clientID))
	sv.txns = append(sv.txns, t)
	return &sv.txns[len(sv.txns)-1]
}

// nextPending returns the next transaction with a queued response, or nil.
func (sv *Server) nextPending() *txn {
	for i := range sv.txns {
		if sv.txns[i].respond != 0 {
			return &sv.txns[i]
		}
	}
	return nil
}

// dropTxn removes the transaction for clientID if present.
func (sv *Server) dropTxn(clientID []byte) {
	for i := range sv.txns {
		if sv.txns[i].matches(clientID) {
			sv.removeAt(i)
			return
		}
	}
}

// dropTxnAt removes the transaction pointed to by t.
func (sv *Server) dropTxnAt(t *txn) {
	for i := range sv.txns {
		if &sv.txns[i] == t {
			sv.removeAt(i)
			return
		}
	}
}

func (sv *Server) removeAt(i int) {
	last := len(sv.txns) - 1
	sv.txns[i] = sv.txns[last]
	sv.txns[last] = txn{}
	sv.txns = sv.txns[:last]
}

func (t *txn) matches(clientID []byte) bool {
	if int(t.clientLen) != len(clientID) {
		return false
	}
	return string(t.clientID[:t.clientLen]) == string(clientID)
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

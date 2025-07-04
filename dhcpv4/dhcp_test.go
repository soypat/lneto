package dhcpv4

import (
	"testing"
)

func TestClientServer(t *testing.T) {
	svAddr := [4]byte{192, 168, 1, 1}
	clAddr := svAddr
	clAddr[3]++
	var sv Server
	var cl Client
	err := cl.BeginRequest(123, RequestConfig{
		RequestedAddr:      clAddr,
		ClientHardwareAddr: [6]byte{1, 2, 3, 4, 5, 6},
		Hostname:           "lneto",
	})
	if err != nil {
		t.Fatal(err)
	}
	assertClState := func(state ClientState) {
		t.Helper()
		if state != cl.State() {
			t.Errorf("want client state %s, got %s", state.String(), cl.State().String())
		}
	}
	sv.Reset(svAddr, DefaultServerPort)
	// CLIENT DISCOVER.
	assertClState(StateInit)
	var buf [1024]byte
	n, err := cl.Encapsulate(buf[:], 0)
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		t.Fatal("no client discover")
	}
	assertClState(StateSelecting)
	err = sv.Demux(buf[:n], 0)
	if err != nil {
		t.Fatal(err)
	}
	// SERVER REPLY OFFER
	n, err = sv.Encapsulate(buf[:], 0)
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		t.Fatal("no server offer")
	}
	err = cl.Demux(buf[:n], 0)
	if err != nil {
		t.Fatal(err)
	}
	assertClState(StateSelecting)

	// CLIENT SEND OUT REQUEST.
	n, err = cl.Encapsulate(buf[:], 0)
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		t.Fatal("no client request")
	}
	assertClState(StateRequesting)
	err = sv.Demux(buf[:n], 0)
	if err != nil {
		t.Fatal(err)
	}

	// SERVER REPLIES WITH ACK.
	n, err = sv.Encapsulate(buf[:], 0)
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		t.Fatal("no server reply")
	}
	err = cl.Demux(buf[:n], 0)
	if err != nil {
		t.Fatal(err)
	}
	assertClState(StateBound)
}

func TestExample(t *testing.T) {
	const (
		xid        = 1
		offerLease = 9001
	)
	var cl Client
	clientHwaddr := [6]byte{0, 0, 0, 0, 0, 1}
	clientReqAddr := [4]byte{192, 168, 1, 2}
	clientHostname := "client"
	serverIP := [4]byte{192, 168, 1, 1}
	subnetMask := [4]byte{255, 255, 255, 0}
	routerAddr := [4]byte{192, 168, 1, 0}
	dnsAddr := [4]byte{192, 168, 1, 255}
	cl.BeginRequest(xid, RequestConfig{
		RequestedAddr:      clientReqAddr,
		ClientHardwareAddr: clientHwaddr,
		Hostname:           clientHostname,
	})
	buf := make([]byte, 2048)
	n, err := cl.Encapsulate(buf, 0)
	if err != nil {
		t.Fatal(err)
	} else if n <= 0 {
		t.Fatal("no data sent out by client after starting request")
	}

	dfrm, _ := NewFrame(buf)
	dfrm.ClearHeader()
	dfrm.SetOp(OpReply)
	dfrm.SetHardware(1, 6, 0)
	dfrm.SetFlags(0)
	dfrm.SetXID(xid)
	dfrm.SetSecs(1)
	*dfrm.YIAddr() = clientReqAddr
	copy(dfrm.CHAddr()[:], clientHwaddr[:])
	dfrm.SetMagicCookie(MagicCookie)
	ntot := 0
	nopt, _ := EncodeOption(buf[optionsOffset+ntot:], OptMessageType, byte(MsgOffer))
	ntot += nopt
	nopt, _ = EncodeOption(buf[optionsOffset+ntot:], OptServerIdentification, serverIP[:]...)
	ntot += nopt
	nopt, _ = EncodeOption32(buf[optionsOffset+ntot:], OptServerIdentification, offerLease)
	ntot += nopt
	nopt, _ = EncodeOption(buf[optionsOffset+ntot:], OptSubnetMask, subnetMask[:]...)
	ntot += nopt
	nopt, _ = EncodeOption(buf[optionsOffset+ntot:], OptRouter, routerAddr[:]...)
	ntot += nopt
	nopt, _ = EncodeOption(buf[optionsOffset+ntot:], OptDNSServers, dnsAddr[:]...)
	ntot += nopt
	nopt, _ = EncodeOption(buf[optionsOffset+ntot:], OptEnd, dnsAddr[:]...)
	ntot += nopt

	err = cl.Demux(buf[:optionsOffset+ntot], 0)
	if err != nil {
		t.Fatal(err)
	}
	// frame := buf[:optionsOffset]
	// frame = AppendOption(frame, OptMessageType, byte(MsgOffer))
	// frame = AppendOption(frame, OptServerIdentification, serverIP[:]...)
	// frame = AppendOption(frame, OptIPAddressLeaseTime, serverIP[:]...)
}

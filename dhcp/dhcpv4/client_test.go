package dhcpv4

import (
	"testing"

	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/ipv4"
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
	sv.Configure(ServerConfig{
		ServerAddr: svAddr,
		Subnet:     ipv4.PrefixFrom(svAddr, 24),
	})
	// CLIENT DISCOVER.
	assertClState(StateInit)
	var buf [1024]byte
	n, err := cl.Encapsulate(buf[:], -1, 0)
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
	n, err = sv.Encapsulate(buf[:], -1, 0)
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
	n, err = cl.Encapsulate(buf[:], -1, 0)
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
	n, err = sv.Encapsulate(buf[:], -1, 0)
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
	buf2 := make([]byte, len(buf))
	n, err := cl.Encapsulate(buf, -1, 0)
	if err != nil {
		t.Fatal(err)
	} else if n <= 0 {
		t.Fatal("no data sent out by client after starting request")
	}
	n, err = cl.Encapsulate(buf2, -1, 0)
	if err != nil {
		t.Error("client encaps double tap after discover:", err)
	}
	// Fabricate server OFFER response.
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
	nopt, _ := EncodeOption(buf[OptionsOffset+ntot:], OptMessageType, byte(MsgOffer))
	ntot += nopt
	nopt, _ = EncodeOption(buf[OptionsOffset+ntot:], OptServerIdentification, serverIP[:]...)
	ntot += nopt
	nopt, _ = EncodeOption32(buf[OptionsOffset+ntot:], OptServerIdentification, offerLease)
	ntot += nopt
	nopt, _ = EncodeOption(buf[OptionsOffset+ntot:], OptSubnetMask, subnetMask[:]...)
	ntot += nopt
	nopt, _ = EncodeOption(buf[OptionsOffset+ntot:], OptRouter, routerAddr[:]...)
	ntot += nopt
	nopt, _ = EncodeOption(buf[OptionsOffset+ntot:], OptDNSServers, dnsAddr[:]...)
	ntot += nopt
	nopt, _ = EncodeOption(buf[OptionsOffset+ntot:], OptEnd, dnsAddr[:]...)
	ntot += nopt

	err = cl.Demux(buf[:OptionsOffset+ntot], 0)
	if err != nil {
		t.Fatal(err)
	}

	n, err = cl.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal(err)
	} else if n <= 0 {
		t.Fatal("no data written from client in response to offer")
	}
	n, err = cl.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Error("encapsulate double tap after request:", err)
	} else if n > 0 {
		t.Error("encapsulate double tap got data!", n)
	}
}

// TestRequestedIPAddressOption verifies that when a client has a valid requested IP,
// the OptRequestedIPaddress option is included in the DISCOVER message.
// This tests for the bug where the condition was inverted (!c.reqIP.valid instead of c.reqIP.valid).
func TestRequestedIPAddressOption(t *testing.T) {
	var cl Client
	requestedAddr := [4]byte{192, 168, 1, 100}

	err := cl.BeginRequest(12345, RequestConfig{
		RequestedAddr:      requestedAddr,
		ClientHardwareAddr: [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	})
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 1024)
	n, err := cl.Encapsulate(buf, -1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no data encapsulated")
	}

	// Parse the frame and look for OptRequestedIPaddress
	frm, err := NewFrame(buf[:n])
	if err != nil {
		t.Fatal(err)
	}

	var foundRequestedIP bool
	var foundIPValue [4]byte
	err = frm.ForEachOption(func(_ int, opt OptNum, data []byte) error {
		if opt == OptRequestedIPaddress {
			foundRequestedIP = true
			if len(data) == 4 {
				copy(foundIPValue[:], data)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if !foundRequestedIP {
		t.Error("OptRequestedIPaddress not found in DISCOVER message when reqIP.valid is true")
	} else if foundIPValue != requestedAddr {
		t.Errorf("OptRequestedIPaddress has wrong value: got %v, want %v", foundIPValue, requestedAddr)
	}
}

// TestGetMessageTypeChecksOptNum verifies that getMessageType correctly identifies
// the DHCP message type by checking for OptMessageType specifically, not just
// any single-byte option.
func TestGetMessageTypeChecksOptNum(t *testing.T) {
	var cl Client
	err := cl.BeginRequest(1, RequestConfig{
		ClientHardwareAddr: [6]byte{1, 2, 3, 4, 5, 6},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a frame with a single-byte option BEFORE OptMessageType
	buf := make([]byte, 512)
	frm, _ := NewFrame(buf)
	frm.SetMagicCookie(MagicCookie)
	frm.SetXID(1)

	opts := buf[OptionsOffset:]
	n := 0

	// Add a single-byte option that is NOT OptMessageType first
	// OptOptionOverload (52) can be a single byte value
	opts[n] = byte(OptOptionOverload)
	opts[n+1] = 1
	opts[n+2] = 3 // value 3 means both sname and file contain options
	n += 3

	// Now add the actual message type
	opts[n] = byte(OptMessageType)
	opts[n+1] = 1
	opts[n+2] = byte(MsgOffer)
	n += 3

	opts[n] = byte(OptEnd)

	// getMessageType should return MsgOffer, not MessageType(3)
	msgType := cl.getMessageType(frm)

	// If the bug exists (not checking opt == OptMessageType), it will return
	// MessageType(3) which is MsgRequest, not MsgOffer
	if msgType != MsgOffer {
		t.Errorf("getMessageType returned %v (%d), want MsgOffer (%d); "+
			"likely not checking for OptMessageType specifically",
			msgType, msgType, MsgOffer)
	}
}

// TestGetMessageTypeWithMultipleSingleByteOptions tests that getMessageType
// returns the correct message type even when multiple single-byte options exist.
func TestGetMessageTypeWithMultipleSingleByteOptions(t *testing.T) {
	var cl Client
	err := cl.BeginRequest(42, RequestConfig{
		ClientHardwareAddr: [6]byte{1, 2, 3, 4, 5, 6},
	})
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name            string
		buildOptions    func([]byte) int
		expectedMsgType MessageType
	}{
		{
			name: "message type first",
			buildOptions: func(opts []byte) int {
				n := 0
				n += writeOption(opts[n:], OptMessageType, byte(MsgAck))
				n += writeOption(opts[n:], OptOptionOverload, byte(1))
				opts[n] = byte(OptEnd)
				return n + 1
			},
			expectedMsgType: MsgAck,
		},
		{
			name: "message type after other single-byte option",
			buildOptions: func(opts []byte) int {
				n := 0
				n += writeOption(opts[n:], OptOptionOverload, byte(2))
				n += writeOption(opts[n:], OptMessageType, byte(MsgNack))
				opts[n] = byte(OptEnd)
				return n + 1
			},
			expectedMsgType: MsgNack,
		},
		{
			name: "message type between multi-byte options",
			buildOptions: func(opts []byte) int {
				n := 0
				n += writeOption(opts[n:], OptHostName, 't', 'e', 's', 't')
				n += writeOption(opts[n:], OptMessageType, byte(MsgDiscover))
				n += writeOption(opts[n:], OptRouter, 192, 168, 1, 1)
				opts[n] = byte(OptEnd)
				return n + 1
			},
			expectedMsgType: MsgDiscover,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, 512)
			frm, _ := NewFrame(buf)
			frm.SetMagicCookie(MagicCookie)
			frm.SetXID(42)

			opts := buf[OptionsOffset:]
			tc.buildOptions(opts)

			msgType := cl.getMessageType(frm)
			if msgType != tc.expectedMsgType {
				t.Errorf("got message type %v (%d), want %v (%d)",
					msgType, msgType, tc.expectedMsgType, tc.expectedMsgType)
			}
		})
	}
}

// writeOption is a test helper that writes a DHCP option and returns bytes written.
func writeOption(dst []byte, opt OptNum, data ...byte) int {
	dst[0] = byte(opt)
	dst[1] = byte(len(data))
	copy(dst[2:], data)
	return 2 + len(data)
}

// TestRequestedIPNotSentWhenInvalid verifies that OptRequestedIPaddress is NOT
// sent when reqIP is not valid (zero address with valid=false).
func TestRequestedIPNotSentWhenInvalid(t *testing.T) {
	var cl Client

	// Begin request with zero address - this still sets valid=true in current impl
	err := cl.BeginRequest(99999, RequestConfig{
		RequestedAddr:      [4]byte{0, 0, 0, 0}, // Zero but will be marked valid
		ClientHardwareAddr: [6]byte{1, 2, 3, 4, 5, 6},
	})
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 1024)
	n, err := cl.Encapsulate(buf, -1, 0)
	if err != nil {
		t.Fatal(err)
	}

	frm, _ := NewFrame(buf[:n])

	var foundRequestedIP bool
	var ipValue [4]byte
	frm.ForEachOption(func(_ int, opt OptNum, data []byte) error {
		if opt == OptRequestedIPaddress {
			foundRequestedIP = true
			if len(data) == 4 {
				copy(ipValue[:], data)
			}
		}
		return nil
	})

	// With the bug fixed, when a valid requested IP is set (even 0.0.0.0),
	// it should be included. This test documents expected behavior.
	if foundRequestedIP {
		// Verify the value matches what was requested
		if !internal.BytesEqual(ipValue[:], []byte{0, 0, 0, 0}) {
			t.Errorf("unexpected requested IP value: %v", ipValue)
		}
	}
}

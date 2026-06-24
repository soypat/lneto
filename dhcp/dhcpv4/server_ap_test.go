package dhcpv4

// Tests covering the AP-mode DHCP server fixes:
//   1. Client lookup by chaddr when no ClientID option is present.
//   2. Ciaddr fallback lookup when chaddr lookup finds nothing.
//   3. Ethernet dst is patched to chaddr on Offer/Ack when Encapsulate is
//      called with offsetToIP >= 14.

import (
	"testing"

	"github.com/soypat/lneto/ipv4"
)

// doraNoClientID runs a complete DORA exchange using raw DHCP frames
// (no ClientID option) with the given chaddr. The client uses only chaddr
// as its identity, matching normal AP-mode behaviour where mobile clients
// don't send OptClientIdentifier.
func doraNoClientID(t *testing.T, sv *Server, chaddr [6]byte, xid uint32) (assignedIP [4]byte) {
	t.Helper()
	var cl Client
	err := cl.BeginRequest(xid, RequestConfig{
		ClientHardwareAddr: chaddr,
		// Intentionally no ClientID – forces server to key on chaddr.
	})
	if err != nil {
		t.Fatalf("BeginRequest: %v", err)
	}

	var buf [1024]byte

	// DISCOVER
	n, err := cl.Encapsulate(buf[:], -1, 0)
	if err != nil || n == 0 {
		t.Fatalf("discover encapsulate: n=%d err=%v", n, err)
	}
	if err = sv.Demux(buf[:n], 0); err != nil {
		t.Fatalf("discover demux: %v", err)
	}

	// OFFER
	n, err = sv.Encapsulate(buf[:], -1, 0)
	if err != nil || n == 0 {
		t.Fatalf("offer encapsulate: n=%d err=%v", n, err)
	}
	frm, _ := NewFrame(buf[:n])
	assignedIP = *frm.YIAddr()
	if err = cl.Demux(buf[:n], 0); err != nil {
		t.Fatalf("offer demux: %v", err)
	}

	// REQUEST
	n, err = cl.Encapsulate(buf[:], -1, 0)
	if err != nil || n == 0 {
		t.Fatalf("request encapsulate: n=%d err=%v", n, err)
	}
	if err = sv.Demux(buf[:n], 0); err != nil {
		t.Fatalf("request demux: %v", err)
	}

	// ACK
	n, err = sv.Encapsulate(buf[:], -1, 0)
	if err != nil || n == 0 {
		t.Fatalf("ack encapsulate: n=%d err=%v", n, err)
	}
	if err = cl.Demux(buf[:n], 0); err != nil {
		t.Fatalf("ack demux: %v", err)
	}

	if cl.State() != StateBound {
		t.Errorf("want StateBound, got %s", cl.State())
	}
	return assignedIP
}

// TestServerChaddrLookup_NoClientID verifies the server can complete a full DORA
// cycle when the client sends no OptClientIdentifier option.  Before the fix the
// MsgRequest Demux call would fail with "request for non existing client" because
// the server tried to look up the entry by ciaddr (0.0.0.0) instead of chaddr.
func TestServerChaddrLookup_NoClientID(t *testing.T) {
	svAddr := [4]byte{192, 168, 4, 1}
	var sv Server
	sv.Configure(ServerConfig{
		ServerAddr: svAddr,
		Gateway:    svAddr,
		Subnet:     ipv4.PrefixFrom(svAddr, 24),
	})

	chaddr := [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	ip := doraNoClientID(t, &sv, chaddr, 0x12345678)
	if ip[0] != 192 || ip[1] != 168 || ip[2] != 4 {
		t.Errorf("unexpected subnet in assigned IP %v", ip)
	}
}

// TestServerChaddrLookup_MultipleClientsNoClientID verifies that multiple clients
// without ClientID each get a unique address and successfully reach StateBound.
func TestServerChaddrLookup_MultipleClientsNoClientID(t *testing.T) {
	svAddr := [4]byte{192, 168, 4, 1}
	var sv Server
	sv.Configure(ServerConfig{
		ServerAddr: svAddr,
		Gateway:    svAddr,
		Subnet:     ipv4.PrefixFrom(svAddr, 24),
	})

	addrs := make([][4]byte, 4)
	for i := range addrs {
		chaddr := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, byte(i + 1)}
		addrs[i] = doraNoClientID(t, &sv, chaddr, uint32(i+1))
	}

	for i := range addrs {
		for j := i + 1; j < len(addrs); j++ {
			if addrs[i] == addrs[j] {
				t.Errorf("clients %d and %d got same address %v", i, j, addrs[i])
			}
		}
	}
}

// TestServerCiaddrFallback exercises the ciaddr fallback path in Demux.
// An entry is registered under an explicit non-MAC ClientID.  A subsequent
// RELEASE arrives with no ClientID (so chaddr lookup misses) but with
// ciaddr=assignedIP, which should let the server find and remove the entry.
func TestServerCiaddrFallback(t *testing.T) {
	svAddr := [4]byte{192, 168, 4, 1}
	chaddr := [6]byte{0xca, 0xfe, 0x00, 0x00, 0x01, 0x01}
	const xid = uint32(0xaabbccdd)
	var sv Server
	sv.Configure(ServerConfig{
		ServerAddr: svAddr,
		Subnet:     ipv4.PrefixFrom(svAddr, 24),
	})

	// DORA with an explicit ClientID — server keys the entry by that string.
	var cl Client
	if err := cl.BeginRequest(xid, RequestConfig{
		ClientHardwareAddr: chaddr,
		ClientID:           "device-id",
	}); err != nil {
		t.Fatalf("BeginRequest: %v", err)
	}
	assignedIP := doraWithClient(t, &sv, &cl)

	// RELEASE: no ClientID, ciaddr = assignedIP.
	// chaddr lookup fails (entry is keyed by "device-id"), so server must
	// fall back to getClientByIP.
	var relBuf [512]byte
	rfrm, _ := NewFrame(relBuf[:])
	rfrm.ClearHeader()
	rfrm.SetOp(OpRequest)
	rfrm.SetHardware(1, 6, 0)
	rfrm.SetXID(xid)
	*rfrm.CIAddr() = assignedIP
	copy(rfrm.CHAddrAs6()[:], chaddr[:])
	rfrm.SetMagicCookie(MagicCookie)
	opts := rfrm.OptionsPayload()
	n, _ := EncodeOption(opts, OptMessageType, byte(MsgRelease))
	opts[n] = byte(OptEnd)
	n++
	if err := sv.Demux(relBuf[:OptionsOffset+n], 0); err != nil {
		t.Fatalf("release demux: %v", err)
	}
	if len(sv.hosts) != 0 {
		t.Errorf("expected 0 hosts after release, got %d", len(sv.hosts))
	}
}

// TestServerOfferPatchesEthernetDst verifies that Encapsulate overwrites the
// first 6 bytes of the carrier (Ethernet dst) with the client's chaddr when
// offsetToIP >= 14.
func TestServerOfferPatchesEthernetDst(t *testing.T) {
	svAddr := [4]byte{192, 168, 4, 1}
	clChaddr := [6]byte{0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	var sv Server
	sv.Configure(ServerConfig{
		ServerAddr: svAddr,
		Subnet:     ipv4.PrefixFrom(svAddr, 24),
	})

	var cl Client
	cl.BeginRequest(0x11223344, RequestConfig{ClientHardwareAddr: clChaddr})

	var buf [1024]byte
	n, err := cl.Encapsulate(buf[:], -1, 0)
	if err != nil || n == 0 {
		t.Fatalf("discover encapsulate: n=%d err=%v", n, err)
	}
	if err = sv.Demux(buf[:n], 0); err != nil {
		t.Fatalf("discover demux: %v", err)
	}

	// Carrier: 14 bytes Ethernet header, then a minimal IPv4 header marker.
	var carrier [1024]byte
	carrier[14] = 0x45 // IPv4 version+IHL so SetIPAddrs succeeds.
	offerN, err := sv.Encapsulate(carrier[:], 14, 14+20+8)
	if err != nil || offerN == 0 {
		t.Fatalf("offer encapsulate: n=%d err=%v", offerN, err)
	}

	var got [6]byte
	copy(got[:], carrier[0:6])
	if got != clChaddr {
		t.Errorf("Ethernet dst: got %v, want %v", got, clChaddr)
	}
}

// doraWithClient runs a complete DORA exchange using the given pre-configured
// Client and returns the assigned IP.
func doraWithClient(t *testing.T, sv *Server, cl *Client) (assignedIP [4]byte) {
	t.Helper()
	var buf [1024]byte

	n, err := cl.Encapsulate(buf[:], -1, 0)
	if err != nil || n == 0 {
		t.Fatalf("discover encapsulate: n=%d err=%v", n, err)
	}
	if err = sv.Demux(buf[:n], 0); err != nil {
		t.Fatalf("discover demux: %v", err)
	}

	n, err = sv.Encapsulate(buf[:], -1, 0)
	if err != nil || n == 0 {
		t.Fatalf("offer encapsulate: n=%d err=%v", n, err)
	}
	frm, _ := NewFrame(buf[:n])
	assignedIP = *frm.YIAddr()
	if err = cl.Demux(buf[:n], 0); err != nil {
		t.Fatalf("offer demux: %v", err)
	}

	n, err = cl.Encapsulate(buf[:], -1, 0)
	if err != nil || n == 0 {
		t.Fatalf("request encapsulate: n=%d err=%v", n, err)
	}
	if err = sv.Demux(buf[:n], 0); err != nil {
		t.Fatalf("request demux: %v", err)
	}

	n, err = sv.Encapsulate(buf[:], -1, 0)
	if err != nil || n == 0 {
		t.Fatalf("ack encapsulate: n=%d err=%v", n, err)
	}
	if err = cl.Demux(buf[:n], 0); err != nil {
		t.Fatalf("ack demux: %v", err)
	}
	if cl.State() != StateBound {
		t.Errorf("want StateBound, got %s", cl.State())
	}
	return assignedIP
}

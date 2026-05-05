package dhcpv6

import (
	"encoding/binary"
	"testing"
)

// writeOpt6 encodes a single DHCPv6 option into dst using the 4-byte TLV header
// (2-byte code + 2-byte length) and returns the total bytes written.
// Used by tests to build server frames without depending on the stub EncodeOption.
func writeOpt6(dst []byte, code OptCode, data ...byte) int {
	binary.BigEndian.PutUint16(dst[0:2], uint16(code))
	binary.BigEndian.PutUint16(dst[2:4], uint16(len(data)))
	copy(dst[4:], data)
	return 4 + len(data)
}

// buildServerFrame constructs a minimal DHCPv6 Advertise or Reply frame
// containing OptServerID, and an OptIANA with an embedded OptIAAddr.
func buildServerFrame(msgType MsgType, xid uint32, serverDUID []byte, iaid [4]byte, addr [16]byte) []byte {
	// IAAddr payload: addr(16) + preferred(4) + valid(4)
	iaAddrPayload := make([]byte, 24)
	copy(iaAddrPayload[:16], addr[:])
	binary.BigEndian.PutUint32(iaAddrPayload[16:20], 3600)
	binary.BigEndian.PutUint32(iaAddrPayload[20:24], 7200)

	// Encode IAAddr as an option.
	iaAddrOpt := make([]byte, 4+len(iaAddrPayload))
	writeOpt6(iaAddrOpt, OptIAAddr, iaAddrPayload...)

	// IA_NA payload: IAID(4) + T1(4) + T2(4) + IAAddr option.
	iaNAPayload := make([]byte, 12+len(iaAddrOpt))
	copy(iaNAPayload[:4], iaid[:])
	binary.BigEndian.PutUint32(iaNAPayload[4:8], 1800)
	binary.BigEndian.PutUint32(iaNAPayload[8:12], 3600)
	copy(iaNAPayload[12:], iaAddrOpt)

	buf := make([]byte, 1024)
	buf[0] = byte(msgType)
	buf[1] = byte(xid >> 16)
	buf[2] = byte(xid >> 8)
	buf[3] = byte(xid)
	n := OptionsOffset
	n += writeOpt6(buf[n:], OptServerID, serverDUID...)
	n += writeOpt6(buf[n:], OptIANA, iaNAPayload...)
	return buf[:n]
}

// TestFrameForEachOption verifies that ForEachOption correctly delivers
// the option code and data to the callback for a hand-built frame.
func TestFrameForEachOption(t *testing.T) {
	buf := make([]byte, OptionsOffset+8)
	buf[0] = byte(MsgSolicit)
	buf[3] = 42 // XID low byte

	n := writeOpt6(buf[OptionsOffset:], OptClientID, 'A', 'B')
	frm, err := NewFrame(buf[:OptionsOffset+n])
	if err != nil {
		t.Fatal(err)
	}

	var gotCode OptCode
	var gotData []byte
	err = frm.ForEachOption(func(_ int, code OptCode, data []byte) error {
		gotCode = code
		gotData = append(gotData[:0], data...)
		return nil
	})
	if err != nil {
		t.Fatal("ForEachOption:", err)
	}
	if gotCode != OptClientID {
		t.Errorf("option code: want %d (OptClientID), got %d", OptClientID, gotCode)
	}
	if string(gotData) != "AB" {
		t.Errorf("option data: want %q, got %q", "AB", gotData)
	}
}

// TestFrameValidateSize verifies that ValidateSize returns an error when an option's
// declared length extends past the end of the buffer.
func TestFrameValidateSize(t *testing.T) {
	buf := make([]byte, OptionsOffset+6)
	buf[0] = byte(MsgSolicit)
	// Option code = OptClientID, claimed length = 100, actual data = 2 bytes.
	binary.BigEndian.PutUint16(buf[OptionsOffset:], uint16(OptClientID))
	binary.BigEndian.PutUint16(buf[OptionsOffset+2:], 100)
	buf[OptionsOffset+4] = 'A'
	buf[OptionsOffset+5] = 'B'

	frm, err := NewFrame(buf)
	if err != nil {
		t.Fatal(err)
	}
	if err := frm.ValidateSize(); err == nil {
		t.Error("ValidateSize: want error for truncated option, got nil")
	}
}

// TestClientSolicitRequest exercises the full four-step DHCPv6 exchange:
// Solicit → (fabricated) Advertise → Request → (fabricated) Reply → Bound.
func TestClientSolicitRequest(t *testing.T) {
	const xid = 0x112233
	clientMAC := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	serverDUID := []byte{0, 3, 0, 1, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	assignedAddr := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	iaid := [4]byte{clientMAC[0], clientMAC[1], clientMAC[2], clientMAC[3]}

	var cl Client
	if err := cl.BeginRequest(xid, RequestConfig{ClientHardwareAddr: clientMAC}); err != nil {
		t.Fatal("BeginRequest:", err)
	}
	if cl.State() != StateInit {
		t.Fatalf("initial state: want StateInit, got %v", cl.State())
	}

	buf := make([]byte, 1024)

	// CLIENT: send Solicit.
	n, err := cl.Encapsulate(buf, -1, 0)
	if err != nil {
		t.Fatal("Encapsulate (Solicit):", err)
	}
	if n == 0 {
		t.Fatal("Encapsulate (Solicit): wrote 0 bytes")
	}
	if cl.State() != StateSoliciting {
		t.Fatalf("after Solicit: want StateSoliciting, got %v", cl.State())
	}

	// SERVER: fabricated Advertise.
	advFrame := buildServerFrame(MsgAdvertise, xid, serverDUID, iaid, assignedAddr)
	if err := cl.Demux(advFrame, 0); err != nil {
		t.Fatal("Demux (Advertise):", err)
	}
	if cl.State() != StateRequesting {
		t.Fatalf("after Advertise: want StateRequesting, got %v", cl.State())
	}

	// CLIENT: send Request.
	n, err = cl.Encapsulate(buf, -1, 0)
	if err != nil {
		t.Fatal("Encapsulate (Request):", err)
	}
	if n == 0 {
		t.Fatal("Encapsulate (Request): wrote 0 bytes")
	}

	// SERVER: fabricated Reply.
	replyFrame := buildServerFrame(MsgReply, xid, serverDUID, iaid, assignedAddr)
	if err := cl.Demux(replyFrame, 0); err != nil {
		t.Fatal("Demux (Reply):", err)
	}
	if cl.State() != StateBound {
		t.Fatalf("after Reply: want StateBound, got %v", cl.State())
	}

	addr, valid := cl.AssignedAddr()
	if !valid {
		t.Fatal("AssignedAddr: not valid after bound")
	}
	if addr != assignedAddr {
		t.Errorf("AssignedAddr: got %v, want %v", addr, assignedAddr)
	}
}

// TestClientEncapsulateSolicit verifies that the first Encapsulate call
// writes a Solicit message with at least OptClientID and OptIANA.
func TestClientEncapsulateSolicit(t *testing.T) {
	var cl Client
	if err := cl.BeginRequest(0xABCDEF, RequestConfig{
		ClientHardwareAddr: [6]byte{1, 2, 3, 4, 5, 6},
	}); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 512)
	n, err := cl.Encapsulate(buf, -1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("Encapsulate: wrote 0 bytes")
	}

	frm, err := NewFrame(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if frm.MsgType() != MsgSolicit {
		t.Errorf("MsgType: want MsgSolicit, got %v", frm.MsgType())
	}
	if frm.TransactionID() != 0xABCDEF {
		t.Errorf("TransactionID: want 0xABCDEF, got 0x%X", frm.TransactionID())
	}

	var hasClientID, hasIANA bool
	err = frm.ForEachOption(func(_ int, code OptCode, _ []byte) error {
		switch code {
		case OptClientID:
			hasClientID = true
		case OptIANA:
			hasIANA = true
		}
		return nil
	})
	if err != nil {
		t.Fatal("ForEachOption:", err)
	}
	if !hasClientID {
		t.Error("Solicit: missing OptClientID")
	}
	if !hasIANA {
		t.Error("Solicit: missing OptIANA")
	}
}

// TestClientDoubleTapEncapsulate verifies that calling Encapsulate twice in the
// same state returns 0 bytes on the second call (idempotent, no duplicate messages).
func TestClientDoubleTapEncapsulate(t *testing.T) {
	var cl Client
	if err := cl.BeginRequest(1, RequestConfig{
		ClientHardwareAddr: [6]byte{1, 2, 3, 4, 5, 6},
	}); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 512)
	n, err := cl.Encapsulate(buf, -1, 0)
	if err != nil {
		t.Fatal("first Encapsulate:", err)
	}
	if n == 0 {
		t.Fatal("first Encapsulate: wrote 0 bytes")
	}

	n2, err := cl.Encapsulate(buf, -1, 0)
	if err != nil {
		t.Fatal("second Encapsulate:", err)
	}
	if n2 != 0 {
		t.Errorf("second Encapsulate: want 0 bytes (idempotent), got %d", n2)
	}
}

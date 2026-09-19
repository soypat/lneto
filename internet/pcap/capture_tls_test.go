package pcap

import (
	stdtls "crypto/tls"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/soypat/lneto"
	tls "github.com/soypat/lneto/crypto/tlsraw"
)

// captureClientHelloRecord drives a standard library TLS client far enough to
// emit its first flight and returns the complete handshake record, header
// included. A real client gives realistic extension ordering, a 32-byte
// middlebox compatibility session ID and a post-quantum key share.
func captureClientHelloRecord(t testing.TB, serverName string, protos []string) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		c := stdtls.Client(client, &stdtls.Config{
			ServerName: serverName,
			MinVersion: stdtls.VersionTLS13,
			MaxVersion: stdtls.VersionTLS13,
			NextProtos: protos,
		})
		_ = c.Handshake() // Will fail; only the first flight is needed.
	}()
	server.SetReadDeadline(time.Now().Add(10 * time.Second))
	var buf [4096]byte
	n, err := server.Read(buf[:])
	if err != nil {
		t.Fatalf("reading ClientHello: %v", err)
	}
	if n < tls.SizeHeaderRecord {
		t.Fatalf("short ClientHello read: %d bytes", n)
	}
	recLen := tls.SizeHeaderRecord + int(binary.BigEndian.Uint16(buf[3:5]))
	if n < recLen {
		t.Fatalf("ClientHello record split across reads: have %d want %d", n, recLen)
	}
	return append([]byte{}, buf[:recLen]...)
}

// TestCaptureTLSClientHello breaks down a real ClientHello record and checks
// that the SNI hostname is recovered.
func TestCaptureTLSClientHello(t *testing.T) {
	const serverName = "example.com"
	pkt := captureClientHelloRecord(t, serverName, []string{"h2", "http/1.1"})

	var pbreak PacketBreakdown
	pbreak.SubfieldLimit = 32
	frames, err := pbreak.CaptureTLS(nil, pkt, 0)
	if err != nil {
		t.Fatal(err)
	}
	// TLS record+TLS ClientHello = 2 frames.
	if len(frames) != 2 {
		for i := range frames {
			t.Logf("frame[%d]=%s", i, frames[i].String())
		}
		t.Fatalf("want 2 frames, got %d", len(frames))
	}
	if frames[0].Protocol != "TLS" {
		t.Errorf("frame 0 protocol=%q want TLS", frames[0].Protocol)
	}
	if frames[1].Protocol != "TLS ClientHello" {
		t.Errorf("frame 1 protocol=%q want TLS ClientHello", frames[1].Protocol)
	}
	if len(frames[0].Errors) > 0 || len(frames[1].Errors) > 0 {
		t.Errorf("unexpected errors: %v %v", frames[0].Errors, frames[1].Errors)
	}
	// A handshake record frame describes the record header only; its fragment is
	// broken down by the handshake frame that follows, so that no bytes are
	// claimed by two frames at once.
	if got := frames[0].LenBits() / 8; got != tls.SizeHeaderRecord {
		t.Errorf("TLS record frame len=%d want %d", got, tls.SizeHeaderRecord)
	}
	if got := frames[1].LenBits() / 8; got != len(pkt)-tls.SizeHeaderRecord {
		t.Errorf("handshake frame len=%d want %d", got, len(pkt)-tls.SizeHeaderRecord)
	}

	ctype := fieldByName(frames[0], "handshake")
	if ctype == nil {
		t.Fatal("no handshake content type field")
	}
	if v, _ := frames[0].FieldAsUint(indexOfField(frames[0], "handshake"), pkt); v != uint64(tls.ContentTypeHandshake) {
		t.Errorf("content type=%d want %d", v, tls.ContentTypeHandshake)
	}

	// SNI and ALPN live as subfields of the extensions container.
	exts := fieldByName(frames[1], "extensions")
	if exts == nil {
		t.Fatal("no extensions field in ClientHello")
	}
	// SNI and ALPN are the text subfields, in wire order.
	var text []*FrameField
	for i := range exts.SubFields {
		if exts.SubFields[i].Class == FieldClassText {
			text = append(text, &exts.SubFields[i])
		}
	}
	if len(text) != 2 {
		t.Fatalf("got %d text extension fields want 2 (server_name, ALPN)", len(text))
	}
	got := string(pkt[(frames[1].PacketBitOffset+text[0].FrameBitOffset)/8:][:text[0].BitLength/8])
	if got != serverName {
		t.Errorf("server_name=%q want %q", got, serverName)
	}

	// Formatted output is the point of the exercise: the hostname and the
	// negotiated suites must be readable in one line.
	var f Formatter
	f.SubfieldLimit = 32
	out, err := f.FormatFrames(nil, frames, pkt)
	if err != nil {
		t.Fatal(err)
	}
	str := string(out)
	for _, want := range []string{"TLS", "handshake=", "client_hello=", serverName,
		"TLS_AES_128_GCM_SHA256", "http/1.1"} {
		if !strings.Contains(str, want) {
			t.Errorf("formatted output missing %q:\n%s", want, str)
		}
	}
}

// TestCaptureTLSRecordSequence checks the multi-record path: a server flight
// coalesces ServerHello, the compatibility ChangeCipherSpec and the first
// protected record into a single segment.
func TestCaptureTLSRecordSequence(t *testing.T) {
	var e tls.Encoder
	var buf [512]byte
	e.Reset(buf[:], 0)

	// ServerHello record.
	rec := e.StartRecord(tls.ContentTypeHandshake)
	msg := e.StartMessage(tls.HandshakeTypeServerHello)
	e.Uint16(tls.VersionTLS12) // legacy_version
	for range tls.SizeHelloRandom {
		e.Uint8(0xab) // server_random
	}
	sid := e.Open(1) // legacy_session_id echo
	for range 32 {
		e.Uint8(0xcd)
	}
	e.Close(sid, 1)
	e.Uint16(uint16(tls.SuiteAES128GCMSHA256))
	e.Uint8(0) // legacy_compression_method
	exts := e.Open(2)
	e.Uint16(uint16(tls.ExtSupportedVersions))
	ext := e.Open(2)
	e.Uint16(tls.VersionTLS13)
	e.Close(ext, 2)
	e.Uint16(uint16(tls.ExtKeyShare))
	ext = e.Open(2)
	e.Uint16(uint16(tls.GroupX25519))
	key := e.Open(2)
	for range 32 {
		e.Uint8(0xee)
	}
	e.Close(key, 2)
	e.Close(ext, 2)
	e.Close(exts, 2)
	e.EndMessage(msg)
	e.EndRecord(rec)

	// change_cipher_spec record.
	rec = e.StartRecord(tls.ContentTypeChangeCipherSpec)
	e.Uint8(1)
	e.EndRecord(rec)

	// First protected record: outwardly application_data.
	rec = e.StartRecord(tls.ContentTypeApplicationData)
	for range 24 {
		e.Uint8(0x5a)
	}
	e.EndRecord(rec)
	if e.Err() != nil {
		t.Fatal(e.Err())
	}
	pkt := buf[:e.Len()]

	var pbreak PacketBreakdown
	pbreak.SubfieldLimit = 8
	frames, err := pbreak.CaptureTLS(nil, pkt, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"TLS", "TLS ServerHello", "TLS", "TLS"}
	if len(frames) != len(want) {
		for i := range frames {
			t.Logf("frame[%d]=%s", i, frames[i].String())
		}
		t.Fatalf("got %d frames want %d", len(frames), len(want))
	}
	for i, wantProto := range want {
		if frames[i].Protocol != wantProto {
			t.Errorf("frame[%d] protocol=%q want %q", i, frames[i].Protocol, wantProto)
		}
		if len(frames[i].Errors) > 0 {
			t.Errorf("frame[%d] errors=%v", i, frames[i].Errors)
		}
	}
	if fieldByName(frames[1], tls.SuiteAES128GCMSHA256.String()) == nil {
		t.Error("ServerHello cipher suite field not named after the selected suite")
	}
	i, err := frames[3].FieldByClass(FieldClassPayload)
	if err != nil {
		t.Error("no payload field in application_data record:", err)
	} else if !frames[3].Fields[i].Flags.IsEncrypted() {
		t.Error("application_data fragment not flagged as encrypted")
	}
	// Record frames must start exactly where the previous record ended, and the
	// last one must end at the packet end: no record skipped, none double read.
	off := 0
	for i := range frames {
		if frames[i].Protocol != "TLS" {
			continue
		}
		if frames[i].PacketBitOffset != off*octet {
			t.Errorf("frame[%d] starts at bit %d want %d", i, frames[i].PacketBitOffset, off*octet)
		}
		off += tls.SizeHeaderRecord + int(binary.BigEndian.Uint16(pkt[off+3:]))
	}
	if off != len(pkt) {
		t.Errorf("records cover %d bytes of %d", off, len(pkt))
	}
}

// TestCaptureTLSIncomplete checks the stream cases a stateless breakdown cannot
// reassemble: a record whose fragment continues in the next TCP segment, and a
// handshake message whose body continues in the next record.
func TestCaptureTLSIncomplete(t *testing.T) {
	t.Run("record", func(t *testing.T) {
		pkt := []byte{byte(tls.ContentTypeApplicationData), 0x03, 0x03, 0x04, 0x00, 1, 2, 3}
		var pbreak PacketBreakdown
		frames, err := pbreak.CaptureTLS(nil, pkt, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(frames) != 1 {
			t.Fatalf("got %d frames want 1", len(frames))
		}
		if len(frames[0].Errors) != 1 || frames[0].Errors[0] != lneto.ErrTruncatedFrame {
			t.Errorf("errors=%v want %v", frames[0].Errors, lneto.ErrTruncatedFrame)
		}
		if got := frames[0].LenBits() / 8; got != len(pkt) {
			t.Errorf("frame covers %d bytes want %d", got, len(pkt))
		}
	})
	t.Run("handshake", func(t *testing.T) {
		// A 5-byte record carrying a Certificate message header that declares a
		// 1000-byte body: the rest arrives in later records.
		pkt := []byte{
			byte(tls.ContentTypeHandshake), 0x03, 0x03, 0x00, 0x06,
			byte(tls.HandshakeTypeCertificate), 0x00, 0x03, 0xe8, 0xaa, 0xbb,
		}
		var pbreak PacketBreakdown
		frames, err := pbreak.CaptureTLS(nil, pkt, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(frames) != 2 {
			t.Fatalf("got %d frames want 2", len(frames))
		}
		if frames[1].Protocol != "TLS Handshake" {
			t.Errorf("protocol=%q want TLS Handshake", frames[1].Protocol)
		}
		if len(frames[1].Errors) != 1 || frames[1].Errors[0] != lneto.ErrTruncatedFrame {
			t.Errorf("errors=%v want %v", frames[1].Errors, lneto.ErrTruncatedFrame)
		}
		if got := frames[1].LenBits() / 8; got != 6 {
			t.Errorf("handshake frame covers %d bytes want 6", got)
		}
	})
}

// TestCaptureTLSAlert checks the cleartext alert path, which is the only way a
// TLS 1.3 handshake failure is visible to a capture.
func TestCaptureTLSAlert(t *testing.T) {
	pkt := []byte{
		byte(tls.ContentTypeAlert), 0x03, 0x03, 0x00, 0x02,
		byte(tls.AlertLevelFatal), byte(tls.AlertHandshakeFailure),
	}
	var pbreak PacketBreakdown
	frames, err := pbreak.CaptureTLS(nil, pkt, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 {
		t.Fatalf("got %d frames want 1", len(frames))
	}
	// The alert description is the last field.
	desc := len(frames[0].Fields) - 1
	if v, err := frames[0].FieldAsUint(desc, pkt); err != nil || v != uint64(tls.AlertHandshakeFailure) {
		t.Errorf("alert description=%d err=%v want %d in %s", v, err, tls.AlertHandshakeFailure, frames[0].String())
	}
	var f Formatter
	f.DisableLegacyFilter = true
	out, err := f.FormatFrame(nil, frames[0], pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "type=0x28") {
		t.Errorf("formatted alert missing description: %s", out)
	}
}

// TestCaptureTLSRecordLimit checks that a segment packed with tiny records
// cannot make a single packet produce unbounded frames.
func TestCaptureTLSRecordLimit(t *testing.T) {
	var pkt []byte
	for range maxTLSRecordsPerPacket + 3 {
		pkt = append(pkt, byte(tls.ContentTypeApplicationData), 3, 3, 0, 1, 0x99)
	}
	var pbreak PacketBreakdown
	frames, err := pbreak.CaptureTLS(nil, pkt, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != maxTLSRecordsPerPacket+1 {
		t.Fatalf("got %d frames want %d", len(frames), maxTLSRecordsPerPacket+1)
	}
	last := frames[len(frames)-1]
	if last.Protocol != "TLS records?" {
		t.Errorf("last frame protocol=%q want TLS records?", last.Protocol)
	}
	if end := (last.PacketBitOffset + last.LenBits()) / 8; end != len(pkt) {
		t.Errorf("remaining frame ends at %d want %d", end, len(pkt))
	}
}

func fieldByName(frm Frame, name string) *FrameField {
	i := indexOfField(frm, name)
	if i < 0 {
		return nil
	}
	return &frm.Fields[i]
}

func indexOfField(frm Frame, name string) int {
	for i := range frm.Fields {
		if frm.Fields[i].Name == name {
			return i
		}
	}
	return -1
}

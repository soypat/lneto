package pcap

import (
	stdtls "crypto/tls"
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal/ltesto"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/x/tls"
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
	rec, err := tls.NewRecordFrame(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if !rec.Complete() {
		t.Fatalf("ClientHello record split across reads: have %d want %d", n, rec.RecordLength())
	}
	return append([]byte{}, rec.RawData()...)
}

// TestCaptureTLSClientHello runs a real ClientHello through the full
// Ethernet/IPv4/TCP path to check that TLS is detected by payload content
// rather than by port, and that the SNI hostname is recovered.
func TestCaptureTLSClientHello(t *testing.T) {
	const mtu = ethernet.MaxMTU
	const serverName = "example.com"
	payload := captureClientHelloRecord(t, serverName, []string{"h2", "http/1.1"})

	var buf [mtu]byte
	var gen ltesto.PacketGen
	rng := rand.New(rand.NewSource(1))
	gen.RandomizeAddrs(rng)
	pkt := gen.AppendRandomIPv4TCPPacket(buf[:0], rng, tcp.Segment{
		SEQ:     100,
		ACK:     200,
		DATALEN: tcp.Size(len(payload)),
		WND:     1024,
		Flags:   tcp.FlagPSH | tcp.FlagACK,
	})
	copy(pkt[len(pkt)-len(payload):], payload)

	var pbreak PacketBreakdown
	pbreak.SubfieldLimit = 32
	frames, err := pbreak.CaptureEthernet(nil, pkt, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Ethernet+IPv4+TCP+TLS record+TLS ClientHello = 5 frames.
	if len(frames) != 5 {
		for i := range frames {
			t.Logf("frame[%d]=%s", i, frames[i].String())
		}
		t.Fatalf("want 5 frames, got %d", len(frames))
	}
	if frames[3].Protocol != "TLS" {
		t.Errorf("frame 3 protocol=%q want TLS", frames[3].Protocol)
	}
	if frames[4].Protocol != "TLS ClientHello" {
		t.Errorf("frame 4 protocol=%q want TLS ClientHello", frames[4].Protocol)
	}
	if len(frames[3].Errors) > 0 || len(frames[4].Errors) > 0 {
		t.Errorf("unexpected errors: %v %v", frames[3].Errors, frames[4].Errors)
	}
	// A handshake record frame describes the record header only; its fragment is
	// broken down by the handshake frame that follows, so that no bytes are
	// claimed by two frames at once.
	if got := frames[3].LenBits() / 8; got != tls.SizeHeaderRecord {
		t.Errorf("TLS record frame len=%d want %d", got, tls.SizeHeaderRecord)
	}
	if got := frames[4].LenBits() / 8; got != len(payload)-tls.SizeHeaderRecord {
		t.Errorf("handshake frame len=%d want %d", got, len(payload)-tls.SizeHeaderRecord)
	}

	ctype := fieldByName(frames[3], "handshake")
	if ctype == nil {
		t.Fatal("no handshake content type field")
	}
	if v, _ := frames[3].FieldAsUint(indexOfField(frames[3], "handshake"), pkt); v != uint64(tls.ContentTypeHandshake) {
		t.Errorf("content type=%d want %d", v, tls.ContentTypeHandshake)
	}

	// SNI and ALPN live as subfields of the extensions container.
	exts := fieldByName(frames[4], "extensions")
	if exts == nil {
		t.Fatal("no extensions field in ClientHello")
	}
	var sni, alpn *FrameField
	for i := range exts.SubFields {
		switch exts.SubFields[i].Name {
		case tls.ExtServerName.String():
			sni = &exts.SubFields[i]
		case tls.ExtALPN.String():
			alpn = &exts.SubFields[i]
		}
	}
	if sni == nil {
		t.Fatal("no server_name extension field")
	}
	got := string(pkt[(frames[4].PacketBitOffset+sni.FrameBitOffset)/8:][:sni.BitLength/8])
	if got != serverName {
		t.Errorf("server_name=%q want %q", got, serverName)
	}
	if alpn == nil {
		t.Error("no application_layer_protocol_negotiation extension field")
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
	var b tls.Builder
	var buf [512]byte
	b.Reset(buf[:])

	// ServerHello record.
	b.AddU8(uint8(tls.ContentTypeHandshake))
	b.AddU16(tls.VersionTLS12)
	b.OpenU16()
	b.AddU8(uint8(tls.HandshakeTypeServerHello))
	b.OpenU24()
	b.AddU16(tls.VersionTLS12) // legacy_version
	for range tls.SizeRandom {
		b.AddU8(0xab) // server_random
	}
	b.OpenU8() // legacy_session_id echo
	for range 32 {
		b.AddU8(0xcd)
	}
	b.Close()
	b.AddU16(uint16(tls.SuiteAES128GCMSHA256))
	b.AddU8(0)  // legacy_compression_method
	b.OpenU16() // extensions
	b.AddU16(uint16(tls.ExtSupportedVersions))
	b.OpenU16()
	b.AddU16(tls.VersionTLS13)
	b.Close()
	b.AddU16(uint16(tls.ExtKeyShare))
	b.OpenU16()
	b.AddU16(uint16(tls.GroupX25519))
	b.OpenU16()
	for range 32 {
		b.AddU8(0xee)
	}
	b.Close()
	b.Close()
	b.Close() // extensions
	b.Close() // handshake body
	b.Close() // record fragment

	// change_cipher_spec record.
	b.AddU8(uint8(tls.ContentTypeChangeCipherSpec))
	b.AddU16(tls.VersionTLS12)
	b.OpenU16()
	b.AddU8(1)
	b.Close()

	// First protected record: outwardly application_data.
	b.AddU8(uint8(tls.ContentTypeApplicationData))
	b.AddU16(tls.VersionTLS12)
	b.OpenU16()
	for range 24 {
		b.AddU8(0x5a)
	}
	b.Close()

	pkt, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !payloadIsTLS(pkt) {
		t.Fatal("payloadIsTLS did not recognize a ServerHello record")
	}

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
		rec, err := tls.NewRecordFrame(pkt[off:])
		if err != nil {
			t.Fatal(err)
		}
		off += rec.RecordLength()
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
		if len(frames[0].Errors) != 1 || frames[0].Errors[0] != tls.ErrNeedMore {
			t.Errorf("errors=%v want %v", frames[0].Errors, tls.ErrNeedMore)
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
		if len(frames[1].Errors) != 1 || frames[1].Errors[0] != tls.ErrNeedMore {
			t.Errorf("errors=%v want %v", frames[1].Errors, tls.ErrNeedMore)
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
	if fieldByName(frames[0], tls.AlertHandshakeFailure.String()) == nil {
		t.Errorf("no field named %q in %s", tls.AlertHandshakeFailure.String(), frames[0].String())
	}
	var f Formatter
	f.DisableLegacyFilter = true
	out, err := f.FormatFrame(nil, frames[0], pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "handshake_failure") {
		t.Errorf("formatted alert missing description: %s", out)
	}
}

// TestPayloadIsTLS guards the heuristic that routes a TCP payload to CaptureTLS
// against the HTTP traffic it shares the datapath with.
func TestPayloadIsTLS(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload []byte
		want    bool
	}{
		{"client hello", []byte{22, 3, 1, 0, 10}, true},
		{"app data", []byte{23, 3, 3, 0x40, 0x00}, true},
		{"alert", []byte{21, 3, 3, 0, 2}, true},
		{"http request", []byte("GET / HTTP/1.1\r\n"), false},
		{"http response", []byte("HTTP/1.1 200 OK\r\n"), false},
		{"bad content type", []byte{25, 3, 3, 0, 10}, false},
		{"bad version", []byte{22, 2, 1, 0, 10}, false},
		{"future version", []byte{22, 3, 5, 0, 10}, false},
		{"zero length", []byte{22, 3, 3, 0, 0}, false},
		{"oversize length", []byte{23, 3, 3, 0xff, 0xff}, false},
		{"short", []byte{22, 3, 3}, false},
	} {
		if got := payloadIsTLS(tc.payload); got != tc.want {
			t.Errorf("%s: payloadIsTLS=%v want %v", tc.name, got, tc.want)
		}
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

package pcap

import (
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dhcp/dhcpv4"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/udp"
)

const benchSubfieldLimit = 32
const benchFmtBufLim = 2048

// buildDHCPPacket builds an Ethernet+IPv4+UDP+DHCPv4 Discover packet, exercising
// the option-heavy DHCP path (hostname, client id, requested address, param list).
func buildDHCPPacket(b testing.TB) []byte {
	const (
		ethSize  = 14
		ipv4Size = 20
		udpSize  = 8
	)
	pkt := make([]byte, 600)

	efrm, _ := ethernet.NewFrame(pkt)
	*efrm.DestinationHardwareAddr() = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	*efrm.SourceHardwareAddr() = [6]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe}
	efrm.SetEtherType(ethernet.TypeIPv4)

	ifrm, _ := ipv4.NewFrame(pkt[ethSize:])
	ifrm.SetVersionAndIHL(4, 5)
	ifrm.SetID(0x1234)
	ifrm.SetFlags(0x4000)
	ifrm.SetTTL(64)
	ifrm.SetProtocol(lneto.IPProtoUDP)

	ufrm, _ := udp.NewFrame(pkt[ethSize+ipv4Size:])
	ufrm.SetSourcePort(dhcpv4.DefaultClientPort)
	ufrm.SetDestinationPort(dhcpv4.DefaultServerPort)

	var cl dhcpv4.Client
	err := cl.BeginRequest(0xdeadbeef, dhcpv4.RequestConfig{
		RequestedAddr:      [4]byte{192, 168, 1, 100},
		ClientHardwareAddr: [6]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe},
		Hostname:           "myhost",
		ClientID:           "lneto-test",
	})
	if err != nil {
		b.Fatal("begin request:", err)
	}
	dhcpLen, err := cl.Encapsulate(pkt, ethSize, ethSize+ipv4Size+udpSize)
	if err != nil {
		b.Fatal("encapsulate:", err)
	}
	totalLen := ipv4Size + udpSize + dhcpLen
	ifrm.SetTotalLength(uint16(totalLen))
	ufrm.SetLength(uint16(udpSize + dhcpLen))
	ifrm.SetCRC(ifrm.CalculateHeaderCRC())
	return pkt[:ethSize+totalLen]
}

// buildDNSPacket builds an Ethernet+IPv4+UDP+DNS message with multiple questions
// and answers, exercising name encoding and resource record rendering.
func buildDNSPacket(b testing.TB) []byte {
	const (
		ethSize  = 14
		ipv4Size = 20
		udpSize  = 8
	)
	var msg dns.Message
	msg.Questions = []dns.Question{
		{Name: dns.MustNewName("example.com"), Type: dns.TypeA, Class: dns.ClassINET},
		{Name: dns.MustNewName("temu.com"), Type: dns.TypeAAAA, Class: dns.ClassANY},
	}
	msg.Answers = []dns.Resource{
		dns.NewResource(dns.MustNewName("abc.com"), dns.TypeALL, dns.ClassANY, 64, []byte{10, 0, 11, 1}),
		dns.NewResource(dns.MustNewName("123.com"), dns.TypeA, dns.ClassINET, 64, []byte{20, 0, 22, 2}),
	}
	dnsPayload, err := msg.AppendTo(nil, 0x1234, dns.NewClientHeaderFlags(dns.OpCodeQuery, true))
	if err != nil {
		b.Fatal("dns encode:", err)
	}

	pkt := make([]byte, ethSize+ipv4Size+udpSize+len(dnsPayload))

	efrm, _ := ethernet.NewFrame(pkt)
	*efrm.DestinationHardwareAddr() = [6]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	*efrm.SourceHardwareAddr() = [6]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
	efrm.SetEtherType(ethernet.TypeIPv4)

	ifrm, _ := ipv4.NewFrame(pkt[ethSize:])
	ifrm.SetVersionAndIHL(4, 5)
	ifrm.SetTTL(64)
	ifrm.SetProtocol(lneto.IPProtoUDP)
	ifrm.SetTotalLength(uint16(ipv4Size + udpSize + len(dnsPayload)))
	ifrm.SetCRC(ifrm.CalculateHeaderCRC())

	ufrm, _ := udp.NewFrame(pkt[ethSize+ipv4Size:])
	ufrm.SetSourcePort(58200)
	ufrm.SetDestinationPort(dns.ServerPort)
	ufrm.SetLength(uint16(udpSize + len(dnsPayload)))

	copy(pkt[ethSize+ipv4Size+udpSize:], dnsPayload)
	return pkt
}

// buildTLSRecord returns a real ClientHello record for CaptureTLS, exercising
// the string-heavy TLS path: cipher suite and extension subfields, SNI and ALPN text.
func buildTLSRecord(b testing.TB) []byte {
	return captureClientHelloRecord(b, "example.com", []string{"h2", "http/1.1"})
}

// benchCase is a packet and the entry point that breaks it down.
type benchCase struct {
	name    string
	pkt     []byte
	capture func(pc *PacketBreakdown, dst []Frame, pkt []byte, bitOffset int) ([]Frame, error)
}

func benchCases(b *testing.B) []benchCase {
	eth := (*PacketBreakdown).CaptureEthernet
	return []benchCase{
		{"DHCP", buildDHCPPacket(b), eth},
		{"DNS", buildDNSPacket(b), eth},
		{"TLS", buildTLSRecord(b), (*PacketBreakdown).CaptureTLS},
	}
}

func configureBenchFormatter(f *Formatter) {
	f.SubfieldLimit = benchSubfieldLimit
	f.FrameSep = "\n"
	f.FieldSep = "; "
	f.SubfieldSep = "\n\t"
}

func warmFrames(pb *PacketBreakdown) []Frame {
	return pb.initFrames()
}

// BenchmarkPcap measures the decode, format, and decode+format (roundtrip) phases
// separately for the string-heavy DHCP and DNS frames. Run with -benchmem for
// per-phase allocs/op.
func BenchmarkPcap(b *testing.B) {
	cases := benchCases(b)
	var (
		formt  Formatter
		pb     PacketBreakdown
		frames = warmFrames(&pb)
		fmtbuf = make([]byte, 0, benchFmtBufLim)
		err    error
	)
	pb.SubfieldLimit = benchSubfieldLimit
	configureBenchFormatter(&formt)
	// warm up capture.
	frames, err = pb.CaptureEthernet(frames, buildDNSPacket(b), 0)
	if err != nil {
		b.Fatal(err)
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.Run("decode", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					frames, _ = tc.capture(&pb, frames[:0], tc.pkt, 0)
				}
			})
			b.Run("format", func(b *testing.B) {
				frames, err := tc.capture(&pb, frames[:0], tc.pkt, 0)
				if err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					fmtbuf, _ = formt.FormatFrames(fmtbuf[:0], frames, tc.pkt)
				}
			})
			b.Run("decode+format", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					frames, _ = tc.capture(&pb, frames[:0], tc.pkt, 0)
					fmtbuf, _ = formt.FormatFrames(fmtbuf[:0], frames, tc.pkt)
				}
			})
		})
	}
}

// BenchmarkPcapPhases runs decode+format in a single benchmark loop while
// reporting per-phase wall time via custom metrics (decode-ns/op, format-ns/op).
// decode-ns/op + format-ns/op approximates ns/op minus time.Now overhead.
// Per-phase allocs are not split here (ReadMemStats is STW and skews timing);
// use BenchmarkPcap's decode/format sub-benchmarks with -benchmem for that.
func BenchmarkPcapPhases(b *testing.B) {
	cases := benchCases(b)
	var (
		pb     PacketBreakdown
		formt  Formatter
		frames = warmFrames(&pb)
		fmtbuf = make([]byte, 0, benchFmtBufLim)
	)
	pb.SubfieldLimit = benchSubfieldLimit
	configureBenchFormatter(&formt)
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			var decNs, fmtNs int64
			b.ResetTimer()
			for b.Loop() {
				t0 := time.Now()
				frames, _ = tc.capture(&pb, frames[:0], tc.pkt, 0)
				t1 := time.Now()
				fmtbuf, _ = formt.FormatFrames(fmtbuf[:0], frames, tc.pkt)
				t2 := time.Now()
				decNs += t1.Sub(t0).Nanoseconds()
				fmtNs += t2.Sub(t1).Nanoseconds()
			}
			b.ReportMetric(float64(decNs)/float64(b.N), "decode-ns/op")
			b.ReportMetric(float64(fmtNs)/float64(b.N), "format-ns/op")
		})
	}
}

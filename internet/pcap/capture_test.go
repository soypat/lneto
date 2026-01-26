package pcap

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dhcpv4"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/http/httpraw"
	"github.com/soypat/lneto/internal/ltesto"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/ipv6"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/udp"
)

const httpProtocol = "HTTP/1.1"

func makeHttpPayload(body string) ([]byte, error) {
	var hdr httpraw.Header
	hdr.SetProtocol(httpProtocol)
	hdr.SetStatus("200", "OK")
	hdr.Set("Cookie", "ABC=123")

	payload, err := hdr.AppendResponse(nil)
	if err != nil {
		return nil, err
	}
	return append(payload, body...), nil
}

func TestCap(t *testing.T) {
	const mtu = 1500
	const httpBody = "{200,ok}"
	var buf [mtu]byte
	var gen ltesto.PacketGen

	payload, err := makeHttpPayload(httpBody)
	if err != nil {
		t.Fatal(err)
	}

	rng := rand.New(rand.NewSource(1))
	gen.RandomizeAddrs(rng)
	pkt := gen.AppendRandomIPv4TCPPacket(buf[:0], rng, tcp.Segment{
		SEQ:     100,
		ACK:     200,
		DATALEN: tcp.Size(len(payload)),
		WND:     1024,
		Flags:   tcp.FlagFIN, //tcp.FlagSYN | tcp.FlagACK | tcp.FlagPSH,
	})

	copy(pkt[len(pkt)-len(payload):], payload)
	// padding should not be included in the captured payload
	pkt = append(pkt, "padding"...)

	var pbreak PacketBreakdown
	frames, err := pbreak.CaptureEthernet(nil, pkt, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Ethernet+IPv4+TCP+HTTP = 4 frames
	if len(frames) != 4 {
		t.Errorf("want 4 frames, got %d", len(frames))
	}
	getClass := func(frame Frame, class FieldClass) uint64 {
		idx, err := frame.FieldByClass(class)
		if err != nil {
			return 0xffff_ffff_ffff_ffff
		}
		v, _ := frame.FieldAsUint(idx, pkt)
		return v
	}
	getName := func(frame Frame, name string) uint64 {
		for i := range frame.Fields {
			if frame.Fields[i].Name == name {
				v, _ := frame.FieldAsUint(i, pkt)
				return v
			}
		}
		return math.MaxUint64
	}
	getClassData := func(frame Frame, class FieldClass) []byte {
		idx, err := frame.FieldByClass(class)
		if err != nil {
			return nil
		}
		v, _ := frame.AppendField(nil, idx, pkt)
		return v
	}
	efrm, _ := ethernet.NewFrame(pkt)
	pefrm := frames[0]
	pifrm := frames[1]
	ptfrm := frames[2]
	phfrm := frames[3]
	gotEproto := ethernet.Type(getClass(pefrm, FieldClassProto))
	if gotEproto != efrm.EtherTypeOrSize() {
		t.Errorf("want %s ethernet type, got %s", efrm.EtherTypeOrSize().String(), gotEproto.String())
	}

	ifrm, _ := ipv4.NewFrame(efrm.Payload())
	gotIproto := lneto.IPProto(getClass(pifrm, FieldClassProto))
	if gotIproto != ifrm.Protocol() {
		t.Errorf("want %s IP proto, got %s", ifrm.Protocol().String(), gotIproto.String())
	}
	gotToS := ipv4.ToS(getName(pifrm, "Type of Service"))
	wantToS := ifrm.ToS()
	if gotToS != wantToS {
		t.Errorf("want %x IP ToS, got %x", wantToS, gotToS)
	}
	gotIflags := ipv4.Flags(getClass(pifrm, FieldClassFlags))
	if gotIflags != ifrm.Flags() {
		t.Errorf("want %x IP flags, got %x", ifrm.Flags(), gotIflags)
	}
	gotVersion := getClass(pifrm, FieldClassVersion)
	wantVersion, _ := ifrm.VersionAndIHL()
	if gotVersion != uint64(wantVersion) {
		t.Errorf("want %d IP version, got %d", wantVersion, gotVersion)
	}

	tfrm, _ := tcp.NewFrame(ifrm.Payload())
	gotTCPFlags := tcp.Flags(getClass(ptfrm, FieldClassFlags))
	wantHeaderLen, wantTCPflags := tfrm.OffsetAndFlags()
	if gotTCPFlags != wantTCPflags {
		t.Errorf("want %s TCP flags, got %s", wantTCPflags.String(), gotTCPFlags.String())
	}
	wanDstPort := gen.DstTCP
	wantSrcPort := gen.SrcTCP
	gotSrcPort := uint16(getClass(ptfrm, FieldClassSrc))
	gotDstPort := uint16(getClass(ptfrm, FieldClassDst))
	if wantSrcPort != gotSrcPort {
		t.Errorf("want %d TCP src port, got %d", wantSrcPort, gotSrcPort)
	}
	if wanDstPort != gotDstPort {
		t.Errorf("want %d TCP dst port, got %d", wanDstPort, gotDstPort)
	}
	gotHeaderLen := getClass(ptfrm, FieldClassSize)
	if gotHeaderLen != uint64(wantHeaderLen) {
		t.Errorf("want %d TCP header length, got %d", wantHeaderLen, gotHeaderLen)
	}
	gotHttpHeader := string(getClassData(phfrm, FieldClassText))
	if !strings.HasPrefix(gotHttpHeader, httpProtocol) {
		t.Errorf("want HTTP header starting with %q, got %q", httpProtocol, gotHttpHeader)
	}
	gotBody := getClassData(phfrm, FieldClassPayload)
	if string(gotBody) != httpBody {
		t.Errorf("want %q HTTP body, got %q", httpBody, gotBody)
	}
}

// TestRightAlignedFields tests extraction of fields that span byte boundaries
// with right-aligned output, such as IPv6 Traffic Class and Flow Label.
func TestRightAlignedFields(t *testing.T) {
	// Build a minimal IPv6 packet with known Traffic Class and Flow Label values.
	// IPv6 header: 40 bytes minimum.
	// Byte 0-3: Version (4 bits) + Traffic Class (8 bits) + Flow Label (20 bits)
	const (
		wantVersion      = 6
		wantTrafficClass = 0xAB        // 8 bits at bit offset 4
		wantFlowLabel    = 0x000C_DEF0 // 20 bits at bit offset 12 (we'll use 0xCDEF0 masked to 20 bits = 0xDEF0)
	)
	// Actually flow label is 20 bits, so max is 0xFFFFF. Use 0xDEF01 masked.
	const wantFlow20 = 0xDEF01 & 0xFFFFF // 0xDEF01

	var pkt [14 + 40 + 20]byte // Ethernet + IPv6 header + TCP header
	// Set up Ethernet frame.
	efrm, _ := ethernet.NewFrame(pkt[:])
	efrm.SetEtherType(ethernet.TypeIPv6)

	// Set up IPv6 header manually.
	i6frm, _ := ipv6.NewFrame(efrm.Payload())
	i6frm.SetVersionTrafficAndFlow(wantVersion, ipv6.ToS(wantTrafficClass), wantFlow20)
	i6frm.SetPayloadLength(20) // TCP header size
	i6frm.SetNextHeader(lneto.IPProtoTCP)
	i6frm.SetHopLimit(64)

	// Set up minimal TCP header.
	tfrm, _ := tcp.NewFrame(i6frm.Payload())
	tfrm.SetOffsetAndFlags(5, 0) // 5 words = 20 bytes, no flags

	// Verify our setup is correct.
	gotVer, gotToS, gotFlow := i6frm.VersionTrafficAndFlow()
	if gotVer != wantVersion {
		t.Fatalf("setup: version mismatch: got %d, want %d", gotVer, wantVersion)
	}
	if uint8(gotToS) != wantTrafficClass {
		t.Fatalf("setup: traffic class mismatch: got 0x%02x, want 0x%02x", gotToS, wantTrafficClass)
	}
	if gotFlow != wantFlow20 {
		t.Fatalf("setup: flow label mismatch: got 0x%05x, want 0x%05x", gotFlow, wantFlow20)
	}

	// Capture the packet.
	var pbreak PacketBreakdown
	frames, err := pbreak.CaptureEthernet(nil, pkt[:], 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) < 2 {
		t.Fatalf("expected at least 2 frames (Ethernet + IPv6), got %d", len(frames))
	}

	// Find IPv6 frame.
	var ipv6Frame *Frame
	for i := range frames {
		if frames[i].Protocol == ethernet.TypeIPv6 {
			ipv6Frame = &frames[i]
			break
		}
	}
	if ipv6Frame == nil {
		t.Fatal("IPv6 frame not found")
	}

	// Helper to get field by name.
	getByName := func(name string) (uint64, error) {
		for i, f := range ipv6Frame.Fields {
			if f.Name == name {
				return ipv6Frame.FieldAsUint(i, pkt[:])
			}
		}
		return 0, nil
	}

	// Test Traffic Class (Type of Service) - 8 bits at bit offset 4, right-aligned.
	gotTrafficClass, err := getByName("Type of Service")
	if err != nil {
		t.Fatalf("failed to get Traffic Class: %v", err)
	}
	if uint8(gotTrafficClass) != wantTrafficClass {
		t.Errorf("Traffic Class: got 0x%02x, want 0x%02x", gotTrafficClass, wantTrafficClass)
	}

	// Test Flow Label - 20 bits at bit offset 12, right-aligned.
	gotFlowLabel, err := getByName("Flow Label")
	if err != nil {
		t.Fatalf("failed to get Flow Label: %v", err)
	}
	if uint32(gotFlowLabel) != wantFlow20 {
		t.Errorf("Flow Label: got 0x%05x, want 0x%05x", gotFlowLabel, wantFlow20)
	}

	// Test Version - 4 bits at bit offset 0, not right-aligned.
	gotVersion, err := getByName("")
	if err != nil {
		t.Fatalf("failed to get Version: %v", err)
	}
	if len(ipv6Frame.Fields) > 0 && ipv6Frame.Fields[0].Class == FieldClassVersion {
		gotVersion, _ = ipv6Frame.FieldAsUint(0, pkt[:])
	}
	if uint8(gotVersion) != wantVersion {
		t.Errorf("Version: got %d, want %d", gotVersion, wantVersion)
	}
}

// TestAppendFieldRightAligned directly tests the appendField function
// with right-aligned fields that have trailing bits.
func TestAppendFieldRightAligned(t *testing.T) {
	testCases := []struct {
		name          string
		pkt           []byte
		fieldBitStart int
		bitlen        int
		rightAligned  bool
		wantData      []byte
	}{
		{
			// IPv6 Traffic Class: bits 4-11 (8 bits spanning bytes 0-1)
			name:          "IPv6 Traffic Class 0xAB",
			pkt:           []byte{0x6A, 0xB0, 0x00, 0x00}, // Version=6, TC=0xAB, Flow=0
			fieldBitStart: 4,
			bitlen:        8,
			rightAligned:  true,
			wantData:      []byte{0xAB},
		},
		{
			// IPv6 Traffic Class with different value
			name:          "IPv6 Traffic Class 0xFF",
			pkt:           []byte{0x6F, 0xF0, 0x00, 0x00}, // Version=6, TC=0xFF, Flow=0
			fieldBitStart: 4,
			bitlen:        8,
			rightAligned:  true,
			wantData:      []byte{0xFF},
		},
		{
			// IPv6 Traffic Class at minimum
			name:          "IPv6 Traffic Class 0x00",
			pkt:           []byte{0x60, 0x00, 0x00, 0x00}, // Version=6, TC=0x00, Flow=0
			fieldBitStart: 4,
			bitlen:        8,
			rightAligned:  true,
			wantData:      []byte{0x00},
		},
		{
			// IPv6 Flow Label: bits 12-31 (20 bits spanning bytes 1-3)
			name:          "IPv6 Flow Label 0xDEF01",
			pkt:           []byte{0x60, 0x0D, 0xEF, 0x01}, // Version=6, TC=0, Flow=0xDEF01
			fieldBitStart: 12,
			bitlen:        20,
			rightAligned:  true,
			wantData:      []byte{0x0D, 0xEF, 0x01}, // 20 bits right-aligned in 3 bytes
		},
		{
			// Flow Label max value
			name:          "IPv6 Flow Label 0xFFFFF",
			pkt:           []byte{0x60, 0xFF, 0xFF, 0xFF}, // Version=6, TC=0, Flow=0xFFFFF
			fieldBitStart: 12,
			bitlen:        20,
			rightAligned:  true,
			wantData:      []byte{0x0F, 0xFF, 0xFF}, // 20 bits right-aligned in 3 bytes
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := appendField(nil, tc.pkt, tc.fieldBitStart, tc.bitlen, tc.rightAligned)
			if err != nil {
				t.Fatalf("appendField error: %v", err)
			}
			if len(got) != len(tc.wantData) {
				t.Fatalf("length mismatch: got %d bytes, want %d bytes", len(got), len(tc.wantData))
			}
			for i := range got {
				if got[i] != tc.wantData[i] {
					t.Errorf("byte %d: got 0x%02x, want 0x%02x", i, got[i], tc.wantData[i])
				}
			}
			// Also verify as uint64 for single/double byte cases.
			if len(tc.wantData) <= 8 {
				gotVal, err := fieldAsUint(tc.pkt, tc.fieldBitStart, tc.bitlen, tc.rightAligned)
				if err != nil {
					t.Fatalf("fieldAsUint error: %v", err)
				}
				var wantVal uint64
				for _, b := range tc.wantData {
					wantVal = wantVal<<8 | uint64(b)
				}
				if gotVal != wantVal {
					t.Errorf("as uint: got 0x%x, want 0x%x", gotVal, wantVal)
				}
			}
		})
	}
}

// TestFieldAsUintRightAligned tests fieldAsUint with the same buffer
// used in the appendField fix, ensuring consistency.
func TestFieldAsUintRightAligned(t *testing.T) {
	// Build IPv6 first 4 bytes with known values.
	// Format: VVVV TTTT TTTT FFFF FFFF FFFF FFFF FFFF
	// V=version (4 bits), T=traffic class (8 bits), F=flow label (20 bits)
	var buf [4]byte
	const version = 6
	const trafficClass = 0xAB
	const flowLabel = 0xCDEF0

	// Encode: version in bits 0-3, traffic class in bits 4-11, flow label in bits 12-31
	val := uint32(version)<<28 | uint32(trafficClass)<<20 | flowLabel
	binary.BigEndian.PutUint32(buf[:], val)

	// Verify encoding.
	t.Logf("Encoded bytes: %02x %02x %02x %02x", buf[0], buf[1], buf[2], buf[3])

	// Test version extraction (bits 0-3, 4 bits, left-aligned)
	gotVersion, err := fieldAsUint(buf[:], 0, 4, false)
	if err != nil {
		t.Fatalf("version extraction failed: %v", err)
	}
	if gotVersion != version {
		t.Errorf("version: got %d, want %d", gotVersion, version)
	}

	// Test traffic class extraction (bits 4-11, 8 bits, right-aligned)
	gotTC, err := fieldAsUint(buf[:], 4, 8, true)
	if err != nil {
		t.Fatalf("traffic class extraction failed: %v", err)
	}
	if gotTC != trafficClass {
		t.Errorf("traffic class: got 0x%02x, want 0x%02x", gotTC, trafficClass)
	}

	// Test flow label extraction (bits 12-31, 20 bits, right-aligned)
	gotFlow, err := fieldAsUint(buf[:], 12, 20, true)
	if err != nil {
		t.Fatalf("flow label extraction failed: %v", err)
	}
	if gotFlow != flowLabel {
		t.Errorf("flow label: got 0x%05x, want 0x%05x", gotFlow, flowLabel)
	}
}

func ExampleFormatter_dhcp() {
	// Build an Ethernet + IPv4 + UDP + DHCPv4 packet.
	const (
		ethSize  = 14
		ipv4Size = 20
		udpSize  = 8
	)
	pktSize := ethSize + ipv4Size + udpSize + dhcpv4.OptionsOffset + 32 // room for options
	pkt := make([]byte, pktSize)

	// Ethernet frame.
	efrm, _ := ethernet.NewFrame(pkt)
	*efrm.DestinationHardwareAddr() = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff} // Broadcast
	*efrm.SourceHardwareAddr() = [6]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe}
	efrm.SetEtherType(ethernet.TypeIPv4)

	// IPv4 frame.
	ifrm, _ := ipv4.NewFrame(efrm.Payload())
	ifrm.SetVersionAndIHL(4, 5)
	ifrm.SetTotalLength(uint16(ipv4Size + udpSize + dhcpv4.OptionsOffset + 32))
	ifrm.SetID(0x1234)
	ifrm.SetFlags(0x4000) // Don't Fragment
	ifrm.SetTTL(64)
	ifrm.SetProtocol(lneto.IPProtoUDP)
	*ifrm.SourceAddr() = [4]byte{0, 0, 0, 0}              // 0.0.0.0 (DHCP client)
	*ifrm.DestinationAddr() = [4]byte{255, 255, 255, 255} // Broadcast
	ifrm.SetCRC(ifrm.CalculateHeaderCRC())

	// UDP frame.
	ufrm, _ := udp.NewFrame(ifrm.Payload())
	ufrm.SetSourcePort(dhcpv4.DefaultClientPort)      // 68
	ufrm.SetDestinationPort(dhcpv4.DefaultServerPort) // 67
	ufrm.SetLength(uint16(udpSize + dhcpv4.OptionsOffset + 32))

	// DHCPv4 frame (DHCP Discover).
	dfrm, _ := dhcpv4.NewFrame(ufrm.Payload())
	dfrm.ClearHeader()
	dfrm.SetOp(dhcpv4.OpRequest)
	dfrm.SetHardware(1, 6, 0) // Ethernet, 6 bytes, 0 hops
	dfrm.SetXID(0xdeadbeef)
	*dfrm.CHAddrAs6() = [6]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe}
	dfrm.SetMagicCookie(dhcpv4.MagicCookie)

	// Add DHCP options.
	opts := dfrm.OptionsPayload()
	n := 0
	n += writeOpt(opts[n:], dhcpv4.OptMessageType, byte(dhcpv4.MsgDiscover))
	n += writeOpt(opts[n:], dhcpv4.OptHostName, []byte("myhost")...)
	n += writeOpt(opts[n:], dhcpv4.OptParameterRequestList,
		byte(dhcpv4.OptSubnetMask),
		byte(dhcpv4.OptRouter),
		byte(dhcpv4.OptDNSServers),
	)
	opts[n] = byte(dhcpv4.OptEnd)

	// Capture and format the packet.
	var cap PacketBreakdown
	cap.SubfieldLimit = 10 // Capture up to 10 DHCP options
	frames, err := cap.CaptureEthernet(nil, pkt, 0)
	if err != nil {
		fmt.Println("capture error:", err)
		return
	}

	var fmtr Formatter
	fmtr.SubfieldLimit = cap.SubfieldLimit
	fmtr.FrameSep = "\n"
	fmtr.FieldSep = "; "
	fmtr.SubfieldSep = "\n\t"
	out, err := fmtr.FormatFrames(nil, frames, pkt)
	if err != nil {
		fmt.Println("format error:", err)
		return
	}
	fmt.Println(string(out))
	// Output:
	// Ethernet len=14; destination=ff:ff:ff:ff:ff:ff; source=de:ad:be:ef:ca:fe; protocol=0x0800
	// IPv4 len=20; version=0x04; (Header Length)=5; (Type of Service)=0x00; (Total Length)=300; identification=0x1234; identification=0x1234; flags=0x4000; (Time to live)=0x40; protocol=0x11; checksum=0x278e; source=0.0.0.0; destination=255.255.255.255
	// UDP [RFC768] len=8; (Source port)=68; (Destination port)=67; size=280; checksum=0x0000
	// DHCPv4 len=240; op=1; (Hardware Address Type)=0x01; (Hardware Address Length)=6; Hops=0x00; (Transaction ID)=0xdeadbeef; (Start Time)=0x0000; Flags=0x0000; (Client Address)=0.0.0.0; (Offered Address)=0.0.0.0; (Server Next Address)=0.0.0.0; (Relay Agent Address)=0.0.0.0; (Client Hardware Address)=dead:beef:cafe::; options((DHCP message type.)=1
	// 	(Hostname string)="myhost"
	// 	(Parameter request list)=0x010306)
}
func writeOpt(dst []byte, opt dhcpv4.OptNum, data ...byte) int {
	dst[0] = byte(opt)
	dst[1] = byte(len(data))
	copy(dst[2:], data)
	return 2 + len(data)
}

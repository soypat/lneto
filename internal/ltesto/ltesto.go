package ltesto

import (
	"math"
	"math/rand"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/ipv4/icmpv4"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/udp"
)

const (
	sizeHeaderIPv4      = 20
	sizeHeaderTCP       = 20
	sizeHeaderEthNoVLAN = 14
	sizeHeaderUDP       = 8
	sizeHeaderARPv4     = 28
	sizeHeaderIPv6      = 40
)

type PacketGen struct {
	SrcMAC, DstMAC   [6]byte // hardware address
	SrcIPv4, DstIPv4 [4]byte // address
	SrcTCP, DstTCP   uint16  // ports
	EnableVLAN       bool
}

func (gen *PacketGen) RandomizeAddrs(rng *rand.Rand) {
	rng.Read(gen.SrcMAC[:])
	rng.Read(gen.DstMAC[:])
	rng.Read(gen.SrcIPv4[:])
	rng.Read(gen.DstIPv4[:])
	ports := rng.Uint32()
	gen.SrcTCP = uint16(ports)
	gen.DstTCP = uint16(ports >> 16)
}

func (gen *PacketGen) AppendRandomIPv4TCPPacket(dst []byte, rng *rand.Rand, seg tcp.Segment) []byte {
	if seg.WND > math.MaxUint16 {
		panic("TCP segment window overflow")
	} else if seg.DATALEN > 2048 {
		panic("too long datalen")
	}
	ri := rng.Int()
	var (
		isVLAN    = gen.EnableVLAN && ri&(1<<0) != 0
		hasIPOpt  = ri&(1<<1) != 0
		hasTCPOpt = ri&(1<<2) != 0
	)
	var etherType ethernet.Type = ethernet.TypeIPv4
	var ipOpts []byte
	if hasIPOpt {
		ipOpts = []byte{1, 2, 3, 4}
	}
	ethsize := 14
	if isVLAN {
		ethsize = 18
	}
	var tcpOpts []byte
	if hasTCPOpt {
		tcpOpts = []byte{byte(tcp.OptSACKPermitted), 0, 1, 0}
	}

	ipOptWLen := sizeWord(len(ipOpts))
	tcpOptWlen := sizeWord(len(tcpOpts))
	off := len(dst)
	dst = append(dst, make([]byte, ethsize+sizeHeaderIPv4+4*int(ipOptWLen)+sizeHeaderTCP+4*int(tcpOptWlen)+int(seg.DATALEN))...)
	efrm, err := ethernet.NewFrame(dst[off:])
	if err != nil {
		panic(err)
	}
	*efrm.DestinationHardwareAddr() = gen.DstMAC
	*efrm.SourceHardwareAddr() = gen.SrcMAC

	if isVLAN {
		efrm.SetVLAN(1<<4, ethernet.TypeIPv4)
	} else {
		efrm.SetEtherType(etherType)
	}
	ethernetPayload := efrm.Payload()
	ifrm, err := ipv4.NewFrame(ethernetPayload)
	if err != nil {
		panic(err)
	}
	ifrm.SetVersionAndIHL(4, sizeWord(20+len(ipOpts)))
	ifrm.SetToS(192)
	ifrm.SetTotalLength(uint16(len(ethernetPayload)))
	ifrm.SetID(uint16(rng.Uint32()))
	ifrm.SetFlags(0x4001) // Don't fragment.
	ifrm.SetTTL(64)
	ifrm.SetProtocol(lneto.IPProtoTCP)
	*ifrm.SourceAddr() = gen.SrcIPv4
	*ifrm.DestinationAddr() = gen.DstIPv4
	// Zero the CRC field so its value does not add to the final result.
	ifrm.SetCRC(0)
	crcValue := ifrm.CalculateHeaderCRC()
	ifrm.SetCRC(crcValue)

	ipPayload := ifrm.Payload()
	tfrm, err := tcp.NewFrame(ipPayload)
	if err != nil {
		panic(err)
	}
	tfrm.SetSourcePort(gen.SrcTCP)
	tfrm.SetDestinationPort(gen.DstTCP)
	tfrm.SetSeq(seg.SEQ)
	tfrm.SetAck(seg.ACK)
	wlen := sizeWord(sizeHeaderTCP + len(tcpOpts))
	tfrm.SetOffsetAndFlags(wlen, seg.Flags)
	tfrm.SetWindowSize(uint16(seg.WND))
	urgPtr := uint16(rng.Uint32())
	tfrm.SetUrgentPtr(urgPtr)
	tcpPayload := tfrm.Payload()
	var firstPayloadByte byte
	if len(tcpPayload) > 0 {
		rng.Read(tcpPayload)
		firstPayloadByte = tcpPayload[0]
		if len(tcpPayload) != int(seg.DATALEN) {
			panic("incorrect payload length calculation")
		}
	}
	// Set Variable section of data.
	copy(ifrm.Options(), ipOpts)
	copy(tfrm.Options(), tcpOpts)
	var crc lneto.CRC791
	ifrm.CRCWriteTCPPseudo(&crc)
	// Zero the CRC field so its value does not add to the final result.
	tfrm.SetCRC(0)
	crcValue = crc.PayloadSum16(tfrm.RawData())
	tfrm.SetCRC(crcValue)
	switch {
	case gen.SrcTCP != tfrm.SourcePort():
		panic("IP options overwrite TCP header")
	case !internal.BytesEqual(ifrm.Options(), ipOpts):
		panic("bad ip options written, ensure ip options length is multiple of 4")
	case !internal.BytesEqual(tfrm.Options(), tcpOpts):
		panic("bad tcp options written, ensure tcp options length is multiple of 4")
	case *ifrm.DestinationAddr() != gen.DstIPv4:
		panic("IP options overwrite own header")
	case tfrm.UrgentPtr() != urgPtr:
		panic("TCP options overwrite urgent pointer field?")
	case len(tcpPayload) > 0 && firstPayloadByte != tcpPayload[0]:
		panic("TCP options overwrite payload")
	}
	var vld lneto.Validator
	efrm.ValidateSize(&vld)
	if err = vld.ErrPop(); err != nil {
		panic(err)
	}
	ifrm.ValidateExceptCRC(&vld)
	if err = vld.ErrPop(); err != nil {
		panic(err)
	}
	tfrm.ValidateSize(&vld)
	if err = vld.ErrPop(); err != nil {
		panic(err)
	}
	return dst
}

// ICMPEchoConfig configures an ICMP echo request packet.
type ICMPEchoConfig struct {
	Identifier     uint16
	SequenceNumber uint16
	Payload        []byte
}

// AppendIPv4ICMPEcho builds and appends a complete Ethernet+IPv4+ICMP echo request packet to dst.
// The packet has valid Ethernet, IPv4, and ICMP checksums.
func (gen *PacketGen) AppendIPv4ICMPEcho(dst []byte, cfg ICMPEchoConfig) []byte {
	const icmpHdrLen = 8
	ethsize := sizeHeaderEthNoVLAN
	if gen.EnableVLAN {
		ethsize += 4
	}
	totalPayload := icmpHdrLen + len(cfg.Payload)
	off := len(dst)
	dst = append(dst, make([]byte, ethsize+sizeHeaderIPv4+totalPayload)...)
	pkt := dst[off:]

	// Ethernet header.
	efrm, err := ethernet.NewFrame(pkt)
	if err != nil {
		panic(err)
	}
	*efrm.DestinationHardwareAddr() = gen.DstMAC
	*efrm.SourceHardwareAddr() = gen.SrcMAC
	efrm.SetEtherType(ethernet.TypeIPv4)

	// IPv4 header.
	ethernetPayload := efrm.Payload()
	ifrm, err := ipv4.NewFrame(ethernetPayload)
	if err != nil {
		panic(err)
	}
	ifrm.SetVersionAndIHL(4, 5)
	ifrm.SetTotalLength(uint16(sizeHeaderIPv4 + totalPayload))
	ifrm.SetID(0)
	ifrm.SetFlags(0)
	ifrm.SetTTL(64)
	ifrm.SetProtocol(lneto.IPProtoICMP)
	*ifrm.SourceAddr() = gen.SrcIPv4
	*ifrm.DestinationAddr() = gen.DstIPv4
	ifrm.SetCRC(0)
	ifrm.SetCRC(ifrm.CalculateHeaderCRC())

	// ICMP echo request.
	icmpData := ifrm.Payload()
	icmpFrm, err := icmpv4.NewFrame(icmpData)
	if err != nil {
		panic(err)
	}
	icmpFrm.SetType(icmpv4.TypeEcho)
	icmpFrm.SetCode(0)
	echo := icmpv4.FrameEcho{Frame: icmpFrm}
	echo.SetIdentifier(cfg.Identifier)
	echo.SetSequenceNumber(cfg.SequenceNumber)
	copy(echo.Data(), cfg.Payload)

	// ICMP checksum covers the entire ICMP message (no pseudo header).
	icmpFrm.SetCRC(0)
	var crc lneto.CRC791
	icmpFrm.SetCRC(crc.PayloadSum16(icmpData[:totalPayload]))

	return dst
}

func sizeWord(l int) uint8 {
	return uint8((l + 3) / 4)
}

// PacketMut mutates existing packet bytes in-place for fuzz testing.
// All Mutate methods use bitmapMut to select which fields to mutate:
// each candidate field consumes 1 bit from LSB. Bit=1 means mutate using seed.
// Addresses and ports are never mutated. CRCs are recomputed after mutation.
// Methods return remaining seed and bitmapMut for chaining across layers.
type PacketMut struct{}

// MutateEthernet mutates an Ethernet+IPv4+transport packet top-to-bottom.
// Dispatches to [PacketMut.MutateIPv4] for the IP layer and transport.
func (pm PacketMut) MutateEthernet(pkt []byte, seed, bitmapMut int64) int {
	efrm, err := ethernet.NewFrame(pkt)
	if err != nil {
		return 0
	}
	fields := 0
	seed, bitmapMut = mutate16(seed, bitmapMut, func(v uint16) { efrm.SetEtherType(ethernet.Type(v)) }, uint16(efrm.EtherTypeOrSize()))
	fields++
	n, _, _ := pm.MutateIPv4(efrm.Payload(), seed, bitmapMut)
	return fields + n
}

// MutateIPv4 mutates IPv4 header fields (IHL, ToS, TotalLength, TTL, Protocol)
// and optionally injects IP options, fixes IP CRC, then dispatches to the
// appropriate transport mutator.
func (pm PacketMut) MutateIPv4(ipBuf []byte, seed, bitmapMut int64) (fields int, seedOut, bitmapOut int64) {
	ifrm, err := ipv4.NewFrame(ipBuf)
	if err != nil {
		return 0, seed, bitmapMut
	}
	v, ihl := ifrm.VersionAndIHL()
	if v != 4 || ihl < 5 {
		return 0, seed, bitmapMut
	}

	seed, bitmapMut = mutate8(seed, bitmapMut, func(v uint8) { ifrm.SetVersionAndIHL(4, v&0xf) }, ihl)
	seed, bitmapMut = mutate8(seed, bitmapMut, func(v uint8) { ifrm.SetToS(ipv4.ToS(v)) }, uint8(ifrm.ToS()))
	seed, bitmapMut = mutate16(seed, bitmapMut, ifrm.SetTotalLength, ifrm.TotalLength())
	seed, bitmapMut = mutate8(seed, bitmapMut, ifrm.SetTTL, ifrm.TTL())
	seed, bitmapMut = mutate8(seed, bitmapMut, func(v uint8) { ifrm.SetProtocol(lneto.IPProto(v)) }, uint8(ifrm.Protocol()))
	fields = 5

	// IP option injection: 2 bits consumed (inject + variant selector).
	if bitmapMut&1 != 0 && ifrm.HeaderLength() >= 20 && ifrm.HeaderLength() <= len(ipBuf) {
		opts := ifrm.Options()
		if len(opts) > 0 {
			seed = mutateIPOptions(opts, seed, bitmapMut>>1)
			fields++
			bitmapMut >>= 1 // extra bit for variant
		}
	}
	bitmapMut >>= 1
	fields++

	ifrm.SetCRC(0)
	ifrm.SetCRC(ifrm.CalculateHeaderCRC())

	tl := ifrm.TotalLength()
	if int(tl) > len(ipBuf) {
		tl = uint16(len(ipBuf))
	}
	_, ihl = ifrm.VersionAndIHL()
	hl := uint16(ihl) * 4
	if hl > tl {
		return fields, seed, bitmapMut
	}
	transportBuf := ipBuf[hl:tl]

	var n int
	switch ifrm.Protocol() {
	case lneto.IPProtoTCP:
		n, seed, bitmapMut = pm.MutateTCP(transportBuf, ifrm, seed, bitmapMut)
	case lneto.IPProtoUDP:
		n, seed, bitmapMut = pm.MutateUDP(transportBuf, ifrm, seed, bitmapMut)
	case lneto.IPProtoICMP:
		n, seed, bitmapMut = pm.MutateICMP(transportBuf, seed, bitmapMut)
	}
	return fields + n, seed, bitmapMut
}

// mutateIPOptions writes adversarial IP option bytes into the options region.
// Strategies selected by seed bits:
//   - 0: All NOPs (padding that shouldn't affect parsing but inflates IHL)
//   - 1: Record Route with claimed length exceeding option space
//   - 2: Garbage bytes (random option kinds with random lengths)
//   - 3: Option with length=0 (infinite loop in naive parsers)
//   - 4: Option with length=1 (length includes kind but not length byte itself)
//   - 5: Nested contradictions: valid kind, absurd length crossing into transport
//   - 6: Single option claiming entire IP packet as option data
//   - 7: Fill with End-of-Options (0x00) — parser should stop immediately
func mutateIPOptions(opts []byte, seed int64, variant int64) int64 {
	strategy := variant & 0x7
	switch strategy {
	case 0: // All NOPs.
		for i := range opts {
			opts[i] = 1 // NOP
		}
	case 1: // Record Route (type 7) with oversize length.
		if len(opts) >= 3 {
			opts[0] = 7                    // Record Route
			opts[1] = byte(len(opts)) + 40 // length way past option space
			opts[2] = 4                    // pointer
			for i := 3; i < len(opts); i++ {
				opts[i] = byte(seed >> uint(i%8))
			}
		}
	case 2: // Garbage: random kind + random length pairs.
		for i := 0; i < len(opts); {
			opts[i] = byte(seed)
			seed >>= 3
			if i+1 < len(opts) {
				opts[i+1] = byte(seed) // random length field
				seed >>= 4
			}
			i += 2
		}
	case 3: // Option with length=0 (infinite loop trap).
		if len(opts) >= 2 {
			opts[0] = 68 // Timestamp option kind
			opts[1] = 0  // length=0: parser that loops on length will hang
			for i := 2; i < len(opts); i++ {
				opts[i] = 0
			}
		}
	case 4: // Option with length=1 (only covers kind byte).
		if len(opts) >= 2 {
			opts[0] = 7 // Record Route
			opts[1] = 1 // length=1: doesn't even cover the length byte
			for i := 2; i < len(opts); i++ {
				opts[i] = 1 // NOP fill
			}
		}
	case 5: // Valid kind, length extends into transport header.
		if len(opts) >= 2 {
			opts[0] = 68                   // Timestamp
			opts[1] = byte(len(opts) + 20) // extends 20 bytes into transport
			for i := 2; i < len(opts); i++ {
				opts[i] = byte(seed)
				seed >>= 3
			}
		}
	case 6: // Single option claiming huge data.
		if len(opts) >= 2 {
			opts[0] = 130 // Security option kind
			opts[1] = 255 // max possible length
			for i := 2; i < len(opts); i++ {
				opts[i] = 0xCC
			}
		}
	case 7: // All End-of-Options.
		for i := range opts {
			opts[i] = 0
		}
	}
	return seed
}

// MutateTCP mutates TCP fields: Seq, Ack, Flags, WindowSize, DataOffset and
// optionally injects adversarial TCP options.
// ifrm is needed for pseudo-header CRC recalculation.
func (pm PacketMut) MutateTCP(transportBuf []byte, ifrm ipv4.Frame, seed, bitmapMut int64) (fields int, seedOut, bitmapOut int64) {
	tfrm, err := tcp.NewFrame(transportBuf)
	if err != nil {
		return 0, seed, bitmapMut
	}
	off, flags := tfrm.OffsetAndFlags()

	seed, bitmapMut = mutate32(seed, bitmapMut, func(v uint32) { tfrm.SetSeq(tcp.Value(v)) }, uint32(tfrm.Seq()))
	seed, bitmapMut = mutate32(seed, bitmapMut, func(v uint32) { tfrm.SetAck(tcp.Value(v)) }, uint32(tfrm.Ack()))
	seed, bitmapMut = mutate8(seed, bitmapMut, func(v uint8) { tfrm.SetOffsetAndFlags(off, tcp.Flags(v).Mask()) }, uint8(flags))
	seed, bitmapMut = mutate16(seed, bitmapMut, tfrm.SetWindowSize, tfrm.WindowSize())
	seed, bitmapMut = mutate8(seed, bitmapMut, func(v uint8) { tfrm.SetOffsetAndFlags(v&0xf, flags) }, off)
	fields = 5

	// TCP option injection: 2 bits consumed (inject + variant selector).
	if bitmapMut&1 != 0 && tfrm.HeaderLength() >= 20 && tfrm.HeaderLength() <= len(transportBuf) {
		opts := tfrm.Options()
		if len(opts) > 0 {
			seed = mutateTCPOptions(opts, seed, bitmapMut>>1)
			fields++
			bitmapMut >>= 1
		}
	}
	bitmapMut >>= 1
	fields++

	tfrm.SetCRC(0)
	var crc lneto.CRC791
	ifrm.CRCWriteTCPPseudo(&crc)
	tfrm.SetCRC(crc.PayloadSum16(transportBuf))
	return fields, seed, bitmapMut
}

// mutateTCPOptions writes adversarial TCP option bytes into the options region.
// Strategies selected by seed bits:
//   - 0: MSS with extreme value (1 or 65535)
//   - 1: Window Scale with huge shift (>14, RFC max is 14)
//   - 2: Option with length=0 (infinite loop trap)
//   - 3: Option length exceeds remaining space (truncated option)
//   - 4: SACK blocks with impossible ranges (garbage SACK data)
//   - 5: Duplicate MSS options (which one wins?)
//   - 6: Valid-looking options followed by garbage past End marker
//   - 7: All NOPs (max padding, no real options)
func mutateTCPOptions(opts []byte, seed int64, variant int64) int64 {
	strategy := variant & 0x7
	switch strategy {
	case 0: // MSS extreme values.
		if len(opts) >= 4 {
			opts[0] = byte(tcp.OptMaxSegmentSize) // kind=2
			opts[1] = 4                           // length=4
			if seed&1 != 0 {
				opts[2], opts[3] = 0xFF, 0xFF // MSS=65535
			} else {
				opts[2], opts[3] = 0x00, 0x01 // MSS=1
			}
			seed = internal.Prand64(seed)
			for i := 4; i < len(opts); i++ {
				opts[i] = 0 // End
			}
		}
	case 1: // Window Scale with illegal shift.
		if len(opts) >= 3 {
			opts[0] = byte(tcp.OptWindowScale) // kind=3
			opts[1] = 3                        // length=3
			opts[2] = byte(seed&0x1F) | 0x10   // shift 16-31, RFC max=14
			seed >>= 5
			for i := 3; i < len(opts); i++ {
				opts[i] = 1 // NOP
			}
		}
	case 2: // Option with length=0.
		if len(opts) >= 2 {
			opts[0] = byte(tcp.OptMaxSegmentSize)
			opts[1] = 0 // length=0: naive parser loops forever
			for i := 2; i < len(opts); i++ {
				opts[i] = 0
			}
		}
	case 3: // Option length exceeds remaining space.
		if len(opts) >= 2 {
			opts[0] = byte(tcp.OptSACK)
			opts[1] = byte(len(opts) + 10) // extends past option region
			for i := 2; i < len(opts); i++ {
				opts[i] = byte(seed)
				seed = internal.Prand64(seed)
			}
		}
	case 4: // SACK with garbage block data.
		if len(opts) >= 10 {
			opts[0] = byte(tcp.OptSACK) // kind=5
			sackLen := len(opts)
			if sackLen > 34 {
				sackLen = 34 // max 4 SACK blocks
			}
			opts[1] = byte(sackLen)
			for i := 2; i < sackLen; i++ {
				opts[i] = byte(seed)
				seed = internal.Prand64(seed)
			}
			for i := sackLen; i < len(opts); i++ {
				opts[i] = 0
			}
		}
	case 5: // Duplicate MSS options (parser picks first? last? panics?).
		for i := 0; i+4 <= len(opts); i += 4 {
			opts[i] = byte(tcp.OptMaxSegmentSize)
			opts[i+1] = 4
			mss := uint16(seed & 0xFFFF)
			opts[i+2] = byte(mss >> 8)
			opts[i+3] = byte(mss)
			seed = internal.Prand64(seed)
		}
	case 6: // Valid option then garbage after End marker.
		if len(opts) >= 6 {
			opts[0] = byte(tcp.OptWindowScale)
			opts[1] = 3
			opts[2] = 7 // valid shift
			opts[3] = 0 // End-of-Options
			// Garbage after End — should be ignored but tests parser bounds.
			for i := 4; i < len(opts); i++ {
				opts[i] = byte(seed) | 0x80 // high-bit kinds (undefined)
				seed = internal.Prand64(seed)
			}
		}
	case 7: // All NOPs — maximum padding, option parser iterates through each.
		for i := range opts {
			opts[i] = 1
		}
	}
	return seed
}

// MutateUDP mutates the UDP Length field.
// ifrm is needed for pseudo-header CRC recalculation.
func (pm PacketMut) MutateUDP(transportBuf []byte, ifrm ipv4.Frame, seed, bitmapMut int64) (fields int, seedOut, bitmapOut int64) {
	ufrm, err := udp.NewFrame(transportBuf)
	if err != nil {
		return 0, seed, bitmapMut
	}

	seed, bitmapMut = mutate16(seed, bitmapMut, ufrm.SetLength, ufrm.Length())

	ufrm.SetCRC(0)
	var crc lneto.CRC791
	ifrm.CRCWriteUDPPseudo(&crc, ufrm.Length())
	ufrm.SetCRC(crc.PayloadSum16(transportBuf))
	return 1, seed, bitmapMut
}

// MutateICMP mutates ICMP Type and Code fields.
func (pm PacketMut) MutateICMP(transportBuf []byte, seed, bitmapMut int64) (fields int, seedOut, bitmapOut int64) {
	frm, err := icmpv4.NewFrame(transportBuf)
	if err != nil {
		return 0, seed, bitmapMut
	}

	seed, bitmapMut = mutate8(seed, bitmapMut, func(v uint8) { frm.SetType(icmpv4.Type(v)) }, uint8(frm.Type()))
	seed, bitmapMut = mutate8(seed, bitmapMut, frm.SetCode, frm.Code())

	frm.SetCRC(0)
	var crc lneto.CRC791
	frm.SetCRC(crc.PayloadSum16(transportBuf))
	return 2, seed, bitmapMut
}

func mutate8(seed, bitmapMut int64, set func(uint8), cur uint8) (int64, int64) {
	if bitmapMut&1 != 0 {
		v := uint8(seed) ^ cur
		if v == cur {
			v++
		}
		set(v)
		seed = internal.Prand64(seed)
	}
	return seed, bitmapMut >> 1
}

func mutate16(seed, bitmapMut int64, set func(uint16), cur uint16) (int64, int64) {
	if bitmapMut&1 != 0 {
		v := uint16(seed) ^ cur
		if v == cur {
			v++
		}
		set(v)
		seed = internal.Prand64(seed)

	}
	return seed, bitmapMut >> 1
}

func mutate32(seed, bitmapMut int64, set func(uint32), cur uint32) (int64, int64) {
	if bitmapMut&1 != 0 {
		v := uint32(seed) ^ cur
		if v == cur {
			v++
		}
		set(v)
		seed = internal.Prand64(seed)
	}
	return seed, bitmapMut >> 1
}

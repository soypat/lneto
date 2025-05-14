package ipv4

import (
	"math"
	"math/rand"
	"testing"

	"github.com/soypat/lneto"
)

func TestFrame(t *testing.T) {
	var buf [1024]byte

	ifrm, err := NewFrame(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(1))
	const wantVersion = 4
	v := new(lneto.Validator)
	for i := 0; i < 100; i++ {
		// SET VALUES:
		wantIHL := uint8(5 + rng.Intn(10))
		wantToS := ToS(rng.Intn(4))
		ifrm.SetVersionAndIHL(wantVersion, wantIHL)
		wantPayloadLen := rng.Intn(6)
		ifrm.SetToS(wantToS)
		wantTotalLength := 4*uint16(wantIHL) + uint16(wantPayloadLen)
		ifrm.SetTotalLength(wantTotalLength)
		wantID := uint16(rng.Intn(math.MaxUint16))
		ifrm.SetID(wantID)
		wantFlags := Flags(rng.Intn(16))
		ifrm.SetFlags(wantFlags)
		wantTTL := uint8(rng.Intn(256))
		ifrm.SetTTL(wantTTL)
		wantProtocol := lneto.IPProto(rng.Intn(256))
		ifrm.SetProtocol(wantProtocol)
		wantCRC := uint16(rng.Intn(math.MaxUint16))
		ifrm.SetCRC(wantCRC)
		src := ifrm.SourceAddr()
		rng.Read(src[:])
		wantSrc := *src
		dst := ifrm.DestinationAddr()
		rng.Read(dst[:])
		wantDst := *dst
		ifrm.ValidateExceptCRC(v)
		ifrm.ValidateSize(v)
		if v.Err() != nil {
			t.Error(v.Err())
		}

		// OPTION+PAYLOAD VALIDATION:
		opts := ifrm.Options()
		payload := ifrm.Payload()
		payloadOff := int(wantIHL) * 4
		wantOptions := buf[sizeHeader:payloadOff]
		wantPayload := buf[payloadOff : payloadOff+wantPayloadLen]
		if len(payload) != wantPayloadLen {
			t.Errorf("want payload length %d, got %d", wantPayloadLen, len(payload))
		}
		if len(opts) != len(wantOptions) {
			t.Errorf("want length of options %d, got %d", len(wantOptions), len(opts))
		}
		if len(opts) > 0 && &wantOptions[0] != &opts[0] {
			t.Error("first byte of options unexpected pointer")
		}
		if len(payload) > 0 && &wantPayload[0] != &payload[0] {
			t.Error("first byte of payload unexpected pointer")
		}
		if len(payload) > 0 {
			payload[0] = byte(rng.Int()) // write over start of payload to catch field aliasing.
		}
		if len(opts) > 0 {
			opts[0] = byte(rng.Int()) // Catch field aliasing.
		}

		// FIELD VALIDATION:
		if ver, ihl := ifrm.VersionAndIHL(); ver != wantVersion || ihl != wantIHL {
			t.Errorf("wanted IHL %d, got version,IHL %d,%d ", wantIHL, ver, ihl)
		}
		if tos := ifrm.ToS(); tos != wantToS {
			t.Errorf("wanted ToS %d, got %d", wantToS, tos)
		}
		if tl := ifrm.TotalLength(); tl != wantTotalLength {
			t.Errorf("wanted total length %d, got %d", wantTotalLength, tl)
		}
		if id := ifrm.ID(); id != wantID {
			t.Errorf("want ID %d, got %d", wantID, id)
		}
		if flags := ifrm.Flags(); flags != wantFlags {
			t.Errorf("want flags %d, got %d", wantFlags, flags)
		}
		if ttl := ifrm.TTL(); ttl != wantTTL {
			t.Errorf("want TTL %d, got %d", wantTTL, ttl)
		}
		if proto := ifrm.Protocol(); proto != wantProtocol {
			t.Errorf("want protocol %d, got %d", wantProtocol, proto)
		}
		if crc := ifrm.CRC(); crc != wantCRC {
			t.Errorf("want crc %d, got %d", wantCRC, crc)
		}
		if wantDst != *dst {
			t.Errorf("want dst addr %d, got %d", wantDst, dst)
		}
		if wantSrc != *src {
			t.Errorf("want src addr %d, got %d", wantSrc, src)
		}
	}
}

package tcp

import (
	"math/rand"
	"testing"
)

func TestSYNCookie_ResetValidation(t *testing.T) {
	var sc SYNCookieJar

	// Zero secret should fail
	err := sc.Reset(SYNCookieConfig{})
	if err == nil {
		t.Errorf("expected error, got %v", err)
	}
	rng := rand.New(rand.NewSource(1))
	// Valid secret should succeed
	err = sc.Reset(SYNCookieConfig{Rand: rng})
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestSYNCookie_GenerateValidate(t *testing.T) {
	var sc SYNCookieJar
	rng := rand.New(rand.NewSource(1))
	err := sc.Reset(SYNCookieConfig{Rand: rng, MaxCounterDelta: 2})
	if err != nil {
		t.Fatal(err)
	}

	srcAddr := []byte{192, 168, 1, 100}
	dstAddr := []byte{10, 0, 0, 1}
	srcPort := uint16(54321)
	dstPort := uint16(80)
	clientISN := Value(0x12345678)

	// Generate cookie
	cookie := sc.MakeSYNCookie(srcAddr, dstAddr, srcPort, dstPort, clientISN)

	// Validate with ACK = cookie + 1
	ackNum := cookie + 1
	validatedCookie, err := sc.ValidateSYNCookie(srcAddr, dstAddr, srcPort, dstPort, clientISN, ackNum)
	if err != nil {
		t.Errorf("expected valid cookie, got error: %v", err)
	}
	if validatedCookie != cookie {
		t.Errorf("expected cookie %d, got %d", cookie, validatedCookie)
	}
}

func TestSYNCookie_CounterExpiration(t *testing.T) {
	var sc SYNCookieJar
	rng := rand.New(rand.NewSource(1))
	err := sc.Reset(SYNCookieConfig{Rand: rng, MaxCounterDelta: 1})
	if err != nil {
		t.Fatal(err)
	}

	srcAddr := []byte{192, 168, 1, 100}
	dstAddr := []byte{10, 0, 0, 1}
	srcPort := uint16(54321)
	dstPort := uint16(80)
	clientISN := Value(0x12345678)

	// Generate cookie at counter=0
	cookie := sc.MakeSYNCookie(srcAddr, dstAddr, srcPort, dstPort, clientISN)
	ackNum := cookie + 1

	// Should validate at counter=0
	_, err = sc.ValidateSYNCookie(srcAddr, dstAddr, srcPort, dstPort, clientISN, ackNum)
	if err != nil {
		t.Errorf("expected valid at counter=0, got: %v", err)
	}

	// Increment counter once - should still validate (within delta=1)
	sc.IncrementCounter()
	_, err = sc.ValidateSYNCookie(srcAddr, dstAddr, srcPort, dstPort, clientISN, ackNum)
	if err != nil {
		t.Errorf("expected valid at counter=1, got: %v", err)
	}

	// Increment again - should still validate (counter=2, cookie from 0, delta=1 allows 1 and 2)
	sc.IncrementCounter()
	_, err = sc.ValidateSYNCookie(srcAddr, dstAddr, srcPort, dstPort, clientISN, ackNum)
	if err == nil {
		t.Errorf("expected cookie to be expired at counter=2 with delta=1")
	}
}

func TestSYNCookie_DifferentTuples(t *testing.T) {
	var sc SYNCookieJar
	rng := rand.New(rand.NewSource(1))
	err := sc.Reset(SYNCookieConfig{Rand: rng})
	if err != nil {
		t.Fatal(err)
	}

	srcAddr := []byte{192, 168, 1, 100}
	dstAddr := []byte{10, 0, 0, 1}
	srcPort := uint16(54321)
	dstPort := uint16(80)
	clientISN := Value(0x12345678)

	cookie := sc.MakeSYNCookie(srcAddr, dstAddr, srcPort, dstPort, clientISN)
	ackNum := cookie + 1

	// Different source address should fail
	wrongSrcAddr := []byte{192, 168, 1, 101}
	_, err = sc.ValidateSYNCookie(wrongSrcAddr, dstAddr, srcPort, dstPort, clientISN, ackNum)
	if err == nil {
		t.Error("expected error for wrong source address")
	}

	// Different port should fail
	_, err = sc.ValidateSYNCookie(srcAddr, dstAddr, srcPort+1, dstPort, clientISN, ackNum)
	if err == nil {
		t.Error("expected error for wrong source port")
	}

	// Different clientISN should fail
	_, err = sc.ValidateSYNCookie(srcAddr, dstAddr, srcPort, dstPort, clientISN+1, ackNum)
	if err == nil {
		t.Error("expected error for wrong client ISN")
	}

	// Correct tuple should succeed
	_, err = sc.ValidateSYNCookie(srcAddr, dstAddr, srcPort, dstPort, clientISN, ackNum)
	if err != nil {
		t.Errorf("expected success for correct tuple, got: %v", err)
	}
}

func TestSYNCookie_IPv6(t *testing.T) {
	var sc SYNCookieJar
	rng := rand.New(rand.NewSource(1))

	err := sc.Reset(SYNCookieConfig{Rand: rng})
	if err != nil {
		t.Fatal(err)
	}

	// IPv6 addresses
	srcAddr := []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	dstAddr := []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
	srcPort := uint16(54321)
	dstPort := uint16(443)
	clientISN := Value(0xDEADBEEF)

	cookie := sc.MakeSYNCookie(srcAddr, dstAddr, srcPort, dstPort, clientISN)
	ackNum := cookie + 1

	validatedCookie, err := sc.ValidateSYNCookie(srcAddr, dstAddr, srcPort, dstPort, clientISN, ackNum)
	if err != nil {
		t.Errorf("expected valid IPv6 cookie, got error: %v", err)
	}
	if validatedCookie != cookie {
		t.Errorf("expected cookie %d, got %d", cookie, validatedCookie)
	}
}

func TestSYNCookie_Deterministic(t *testing.T) {
	var sc SYNCookieJar
	rng := rand.New(rand.NewSource(1))
	err := sc.Reset(SYNCookieConfig{Rand: rng})
	if err != nil {
		t.Fatal(err)
	}

	srcAddr := []byte{192, 168, 1, 100}
	dstAddr := []byte{10, 0, 0, 1}
	srcPort := uint16(54321)
	dstPort := uint16(80)
	clientISN := Value(0x12345678)

	// Same inputs should produce same cookie
	cookie1 := sc.MakeSYNCookie(srcAddr, dstAddr, srcPort, dstPort, clientISN)
	cookie2 := sc.MakeSYNCookie(srcAddr, dstAddr, srcPort, dstPort, clientISN)

	if cookie1 != cookie2 {
		t.Errorf("expected deterministic cookies: %d != %d", cookie1, cookie2)
	}
}

func TestMSSIndexEncoding(t *testing.T) {
	tests := []struct {
		mss         uint16
		expectedIdx uint8
	}{
		{200, 0},
		{536, 0},
		{537, 1},
		{1220, 1},
		{1221, 2},
		{1460, 2},
		{1461, 3},
		{8960, 3},
		{9000, 3},
	}

	for _, tc := range tests {
		idx := encodeMSSIndex(tc.mss)
		if idx != tc.expectedIdx {
			t.Errorf("EncodeMSSIndex(%d) = %d, want %d", tc.mss, idx, tc.expectedIdx)
		}
	}

	// Test round-trip for decoded values
	for idx := uint8(0); idx <= 3; idx++ {
		mss := decodeMSSIndex(idx)
		reIdx := encodeMSSIndex(mss)
		if reIdx != idx {
			t.Errorf("MSS index round-trip failed: %d -> %d -> %d", idx, mss, reIdx)
		}
	}
}

func BenchmarkSYNCookie_Generate(b *testing.B) {
	var sc SYNCookieJar
	rng := rand.New(rand.NewSource(1))
	sc.Reset(SYNCookieConfig{Rand: rng})

	srcAddr := []byte{192, 168, 1, 100}
	dstAddr := []byte{10, 0, 0, 1}
	srcPort := uint16(54321)
	dstPort := uint16(80)
	clientISN := Value(0x12345678)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sc.MakeSYNCookie(srcAddr, dstAddr, srcPort, dstPort, clientISN)
	}
}

func BenchmarkSYNCookie_Validate(b *testing.B) {
	var sc SYNCookieJar
	rng := rand.New(rand.NewSource(1))
	sc.Reset(SYNCookieConfig{Rand: rng, MaxCounterDelta: 2})

	srcAddr := []byte{192, 168, 1, 100}
	dstAddr := []byte{10, 0, 0, 1}
	srcPort := uint16(54321)
	dstPort := uint16(80)
	clientISN := Value(0x12345678)

	cookie := sc.MakeSYNCookie(srcAddr, dstAddr, srcPort, dstPort, clientISN)
	ackNum := cookie + 1

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sc.ValidateSYNCookie(srcAddr, dstAddr, srcPort, dstPort, clientISN, ackNum)
	}
}

package ntp

import (
	"testing"
	"time"
)

func TestServer_BasicExchange(t *testing.T) {
	serverTime := BaseTime().Add(100 * time.Second)
	var h Server
	err := h.Reset(ServerConfig{
		Now:       func() time.Time { return serverTime },
		Stratum:   StratumPrimary,
		Precision: -20,
		RefID:     [4]byte{'G', 'P', 'S', 0},
	})
	if err != nil {
		t.Fatal(err)
	}

	reqBuf := make([]byte, SizeHeader)
	frm, _ := NewFrame(reqBuf)
	frm.SetFlags(ModeClient, Version4, LeapNoWarning)
	frm.SetStratum(StratumUnsync)
	clientXmt := TimestampFromUint64(0x12345678_9abcdef0)
	frm.SetTransmitTime(clientXmt)

	if err := h.Demux(reqBuf, 0); err != nil {
		t.Fatal(err)
	}

	respBuf := make([]byte, SizeHeader)
	n, err := h.Encapsulate(respBuf, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != SizeHeader {
		t.Fatalf("expected %d bytes, got %d", SizeHeader, n)
	}

	resp, _ := NewFrame(respBuf)
	mode, version, _ := resp.Flags()
	if mode != ModeServer {
		t.Errorf("response mode = %d; want ModeServer", mode)
	}
	if version != Version4 {
		t.Errorf("response version = %d; want 4", version)
	}
	if resp.Stratum() != StratumPrimary {
		t.Errorf("response stratum = %s; want primary", resp.Stratum())
	}
	if resp.OriginTime() != clientXmt {
		t.Error("response origin time does not echo client transmit time (RFC 5905 §8)")
	}
	if resp.ReferenceID() == nil || *resp.ReferenceID() != [4]byte{'G', 'P', 'S', 0} {
		t.Error("reference ID mismatch")
	}
}

func TestServer_RejectsNonClient(t *testing.T) {
	modes := []struct {
		name string
		mode Mode
	}{
		{name: "server", mode: ModeServer},
		{name: "broadcast", mode: ModeBroadcast},
		{name: "symmetric_active", mode: ModeSymmetricActive},
		{name: "symmetric_passive", mode: ModeSymmetricPassive},
	}
	for _, tc := range modes {
		t.Run(tc.name, func(t *testing.T) {
			var h Server
			h.Reset(ServerConfig{
				Now:     time.Now,
				Stratum: StratumPrimary,
			})
			reqBuf := make([]byte, SizeHeader)
			frm, _ := NewFrame(reqBuf)
			frm.SetFlags(tc.mode, Version4, LeapNoWarning)
			if err := h.Demux(reqBuf, 0); err == nil {
				t.Errorf("Server.Demux(mode=%d) = nil; want error", tc.mode)
			}
		})
	}
}

func TestServer_ExhaustedPending(t *testing.T) {
	var h Server
	h.Reset(ServerConfig{
		Now:        time.Now,
		Stratum:    StratumPrimary,
		MaxPending: 1,
	})

	reqBuf := make([]byte, SizeHeader)
	frm, _ := NewFrame(reqBuf)
	frm.SetFlags(ModeClient, Version4, LeapNoWarning)

	if err := h.Demux(reqBuf, 0); err != nil {
		t.Fatal(err)
	}
	if err := h.Demux(reqBuf, 0); err == nil {
		t.Fatal("expected exhausted error on second request")
	}
}

func TestServer_NoPendingReturnsZero(t *testing.T) {
	var h Server
	h.Reset(ServerConfig{
		Now:     time.Now,
		Stratum: StratumPrimary,
	})

	buf := make([]byte, SizeHeader)
	n, err := h.Encapsulate(buf, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("expected 0 bytes when no pending, got %d", n)
	}
}

func TestServer_ClientServerRoundTrip(t *testing.T) {
	baseTime := BaseTime()
	clientStart := baseTime.Add(10 * time.Second)
	serverOffset := 500 * time.Millisecond
	clockTime := clientStart

	var client Client
	client.Reset(-18, func() time.Time { return clockTime })

	serverTime := clientStart.Add(serverOffset)
	var server Server
	server.Reset(ServerConfig{
		Now:       func() time.Time { return serverTime },
		Stratum:   StratumPrimary,
		Precision: -20,
		RefID:     [4]byte{'G', 'P', 'S', 0},
	})

	for exchange := range 2 {
		reqBuf := make([]byte, SizeHeader)
		n, err := client.Encapsulate(reqBuf, 0, 0)
		if err != nil || n == 0 {
			t.Fatalf("exchange %d: Encapsulate: n=%d err=%v", exchange, n, err)
		}

		if err = server.Demux(reqBuf[:n], 0); err != nil {
			t.Fatalf("exchange %d: server Demux: %v", exchange, err)
		}

		respBuf := make([]byte, SizeHeader)
		n, err = server.Encapsulate(respBuf, 0, 0)
		if err != nil || n == 0 {
			t.Fatalf("exchange %d: server Encapsulate: n=%d err=%v", exchange, n, err)
		}

		clockTime = clockTime.Add(100 * time.Millisecond)
		serverTime = serverTime.Add(100 * time.Millisecond)

		if err = client.Demux(respBuf[:n], 0); err != nil {
			t.Fatalf("exchange %d: client Demux: %v", exchange, err)
		}
	}

	if !client.IsDone() {
		t.Fatal("client should be done after two exchanges")
	}
	if client.RoundTripDelay() < 0 {
		t.Errorf("RTD = %v; want >= 0", client.RoundTripDelay())
	}
}

func FuzzServerDemux(f *testing.F) {
	valid := make([]byte, SizeHeader)
	frm, _ := NewFrame(valid)
	frm.SetFlags(ModeClient, Version4, LeapNoWarning)
	f.Add(valid)
	f.Add(make([]byte, SizeHeader))
	f.Add([]byte{})
	f.Add(make([]byte, 10))
	f.Fuzz(func(t *testing.T, data []byte) {
		var h Server
		h.Reset(ServerConfig{
			Now:     time.Now,
			Stratum: StratumPrimary,
		})
		_ = h.Demux(data, 0)
		buf := make([]byte, SizeHeader)
		h.Encapsulate(buf, 0, 0)
	})
}

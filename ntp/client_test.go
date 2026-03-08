package ntp

import (
	"testing"
	"time"
)

func TestClient_FullExchange(t *testing.T) {
	// Simulate a NTP client-server exchange without network.
	baseTime := BaseTime()
	clientStart := baseTime.Add(10 * time.Second)
	serverOffset := 500 * time.Millisecond // server is 500ms ahead

	clockTime := clientStart
	client := Client{}
	client.Reset(-18, func() time.Time { return clockTime })

	if client.IsDone() {
		t.Fatal("client should not be done before exchange")
	}

	// Step 1: Client encapsulates request.
	reqBuf := make([]byte, SizeHeader)
	n, err := client.Encapsulate(reqBuf, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != SizeHeader {
		t.Fatalf("expected %d bytes, got %d", SizeHeader, n)
	}

	// Verify request frame fields.
	reqFrm, err := NewFrame(reqBuf)
	if err != nil {
		t.Fatal(err)
	}
	mode, version, _ := reqFrm.Flags()
	if mode != ModeClient {
		t.Errorf("request mode = %d; want ModeClient (%d)", mode, ModeClient)
	}
	if version != Version4 {
		t.Errorf("request version = %d; want %d", version, Version4)
	}
	if reqFrm.Stratum() != StratumUnsync {
		t.Errorf("request stratum = %d; want StratumUnsync", reqFrm.Stratum())
	}

	// Step 2: Simulate server response.
	// Server receives at clientStart + serverOffset, sends response at clientStart + serverOffset + 10ms processing.
	serverRecvTime := clientStart.Add(serverOffset)
	serverXmtTime := serverRecvTime.Add(10 * time.Millisecond)

	respBuf := make([]byte, SizeHeader)
	respFrm, _ := NewFrame(respBuf)
	respFrm.SetFlags(ModeServer, Version4, LeapNoWarning)
	respFrm.SetStratum(StratumPrimary)
	respFrm.SetPrecision(-20)

	// Echo client's origin time.
	respFrm.SetOriginTime(reqFrm.OriginTime())

	// Set server timestamps.
	recvTS, err := TimestampFromTime(serverRecvTime)
	if err != nil {
		t.Fatal(err)
	}
	xmtTS, err := TimestampFromTime(serverXmtTime)
	if err != nil {
		t.Fatal(err)
	}
	respFrm.SetReceiveTime(recvTS)
	respFrm.SetTransmitTime(xmtTS)

	// Advance client clock to simulate network delay.
	clockTime = clientStart.Add(100 * time.Millisecond)

	// Step 3: Client demuxes response.
	err = client.Demux(respBuf, 0)
	if err != nil {
		t.Fatal(err)
	}

	if !client.IsDone() {
		t.Fatal("client should be done after exchange")
	}

	// Step 4: Verify results.
	if client.ServerStratum() != StratumPrimary {
		t.Errorf("server stratum = %s; want primary", client.ServerStratum())
	}

	offset := client.Offset()
	if offset == 0 {
		t.Fatal("offset should be non-zero")
	}

	rtd := client.RoundTripDelay()
	if rtd < 0 {
		t.Fatalf("round trip delay should be non-negative, got %s", rtd)
	}

	// Verify Now() returns a reasonable time.
	ntpNow := client.Now()
	if ntpNow.Before(baseTime) {
		t.Errorf("NTP-corrected time %v is before base time %v", ntpNow, baseTime)
	}
}

func TestClient_Reset(t *testing.T) {
	var c Client
	c.Reset(-18, time.Now)
	if c.IsDone() {
		t.Fatal("should not be done after Reset")
	}
	if c.LocalPort() != ClientPort {
		t.Fatalf("expected port %d, got %d", ClientPort, c.LocalPort())
	}
	if c.Protocol() != 0 {
		t.Fatalf("expected protocol 0, got %d", c.Protocol())
	}
	id1 := *c.ConnectionID()

	c.Reset(-18, time.Now)
	id2 := *c.ConnectionID()
	if id2 <= id1 {
		t.Fatal("ConnectionID should increment on Reset")
	}
}

func TestClient_Encapsulate_WhenDone(t *testing.T) {
	var c Client
	// Not reset, state is closed/done.
	buf := make([]byte, SizeHeader)
	n, err := c.Encapsulate(buf, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("expected 0 bytes when done, got %d", n)
	}
}

func TestClient_Demux_WhenDone(t *testing.T) {
	var c Client
	buf := make([]byte, SizeHeader)
	err := c.Demux(buf, 0)
	if err != nil {
		t.Fatal("Demux when done should be no-op")
	}
}

func TestClient_Demux_ShortBuffer(t *testing.T) {
	var c Client
	c.Reset(-18, time.Now)
	// Trigger encapsulate first to move to stateAwait1.
	buf := make([]byte, SizeHeader)
	c.Encapsulate(buf, 0, 0)

	// Short buffer should error.
	err := c.Demux(make([]byte, 10), 0)
	if err == nil {
		t.Fatal("expected error for short buffer")
	}
}

func TestClient_OffsetBeforeDone(t *testing.T) {
	var c Client
	c.Reset(-18, time.Now)
	if c.Offset() != 0 {
		t.Fatal("Offset should be 0 before exchange completes")
	}
	if c.RoundTripDelay() != -1 {
		t.Fatal("RoundTripDelay should be -1 before done")
	}
}

func TestClient_DemuxRejectsBogusResponse(t *testing.T) {
	var c Client
	clockTime := BaseTime().Add(time.Second)
	c.Reset(-18, func() time.Time { return clockTime })

	// Encapsulate to move to stateAwait1.
	buf := make([]byte, SizeHeader)
	c.Encapsulate(buf, 0, 0)

	// Build response with wrong origin time (not echoed correctly).
	resp := make([]byte, SizeHeader)
	frm, _ := NewFrame(resp)
	frm.SetFlags(ModeServer, Version4, LeapNoWarning)
	frm.SetOriginTime(TimestampFromUint64(99999)) // wrong origin
	xmt, _ := TimestampFromTime(clockTime.Add(time.Second))
	frm.SetTransmitTime(xmt)
	frm.SetReceiveTime(xmt)

	err := c.Demux(resp, 0)
	if err == nil {
		t.Fatal("should reject response with mismatched origin time")
	}
	if c.IsDone() {
		t.Fatal("should not be done after rejected response")
	}
}

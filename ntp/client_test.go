package ntp

import (
	"testing"
	"time"
)

// simulateServerResponse builds a server NTP response that echoes the origin from reqBuf,
// and sets T1 (server recv) and T2 (server xmt) using serverRecv and serverXmt.
func simulateServerResponse(t *testing.T, reqBuf []byte, serverRecv, serverXmt time.Time) []byte {
	t.Helper()
	reqFrm, _ := NewFrame(reqBuf)
	respBuf := make([]byte, SizeHeader)
	respFrm, _ := NewFrame(respBuf)
	respFrm.SetFlags(ModeServer, Version4, LeapNoWarning)
	respFrm.SetStratum(StratumPrimary)
	respFrm.SetPrecision(-20)
	respFrm.SetOriginTime(reqFrm.TransmitTime())
	recvTS, err := TimestampFromTime(serverRecv)
	if err != nil {
		t.Fatal(err)
	}
	xmtTS, err := TimestampFromTime(serverXmt)
	if err != nil {
		t.Fatal(err)
	}
	respFrm.SetReceiveTime(recvTS)
	respFrm.SetTransmitTime(xmtTS)
	return respBuf
}

func TestClient_FullExchange(t *testing.T) {
	baseTime := BaseTime()
	clientStart := baseTime.Add(10 * time.Second)
	serverOffset := 500 * time.Millisecond

	clockTime := clientStart
	client := Client{}
	client.Reset(-18, func() time.Time { return clockTime })

	if client.IsDone() {
		t.Fatal("client should not be done before exchange")
	}

	// --- First exchange ---

	reqBuf := make([]byte, SizeHeader)
	n, err := client.Encapsulate(reqBuf, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != SizeHeader {
		t.Fatalf("expected %d bytes, got %d", SizeHeader, n)
	}

	reqFrm, _ := NewFrame(reqBuf)
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

	serverRecv1 := clientStart.Add(serverOffset)
	serverXmt1 := serverRecv1.Add(10 * time.Millisecond)
	resp1Buf := simulateServerResponse(t, reqBuf, serverRecv1, serverXmt1)

	clockTime = clientStart.Add(100 * time.Millisecond)
	if err = client.Demux(resp1Buf, 0); err != nil {
		t.Fatal(err)
	}
	if client.IsDone() {
		t.Fatal("client should not be done after first exchange only")
	}
	if client.ServerStratum() != StratumPrimary {
		t.Errorf("server stratum after first exchange = %s; want primary", client.ServerStratum())
	}

	// --- Second exchange ---

	req2Buf := make([]byte, SizeHeader)
	clockTime = clientStart.Add(200 * time.Millisecond)
	n, err = client.Encapsulate(req2Buf, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != SizeHeader {
		t.Fatalf("second request: expected %d bytes, got %d", SizeHeader, n)
	}

	serverRecv2 := clientStart.Add(serverOffset + 200*time.Millisecond)
	serverXmt2 := serverRecv2.Add(10 * time.Millisecond)
	resp2Buf := simulateServerResponse(t, req2Buf, serverRecv2, serverXmt2)

	clockTime = clientStart.Add(300 * time.Millisecond)
	if err = client.Demux(resp2Buf, 0); err != nil {
		t.Fatal(err)
	}
	if !client.IsDone() {
		t.Fatal("client should be done after second exchange")
	}

	// --- Verify results ---

	offset := client.Offset()
	if offset == 0 {
		t.Fatal("offset should be non-zero")
	}
	rtd := client.RoundTripDelay()
	if rtd < 0 {
		t.Fatalf("round trip delay should be non-negative, got %s", rtd)
	}
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

func TestClient_SecondExchangeRejection(t *testing.T) {
	baseTime := BaseTime()
	clientStart := baseTime.Add(10 * time.Second)
	serverOffset := 500 * time.Millisecond
	clockTime := clientStart

	var client Client
	client.Reset(-18, func() time.Time { return clockTime })

	reqBuf := make([]byte, SizeHeader)
	client.Encapsulate(reqBuf, 0, 0)

	serverRecv1 := clientStart.Add(serverOffset)
	serverXmt1 := serverRecv1.Add(10 * time.Millisecond)
	resp1Buf := simulateServerResponse(t, reqBuf, serverRecv1, serverXmt1)
	clockTime = clientStart.Add(100 * time.Millisecond)
	client.Demux(resp1Buf, 0)

	req2Buf := make([]byte, SizeHeader)
	clockTime = clientStart.Add(200 * time.Millisecond)
	client.Encapsulate(req2Buf, 0, 0)

	bogus := make([]byte, SizeHeader)
	frm, _ := NewFrame(bogus)
	frm.SetFlags(ModeServer, Version4, LeapNoWarning)
	frm.SetOriginTime(TimestampFromUint64(99999))
	xmt, _ := TimestampFromTime(clockTime.Add(time.Second))
	frm.SetTransmitTime(xmt)
	frm.SetReceiveTime(xmt)

	clockTime = clientStart.Add(300 * time.Millisecond)
	err := client.Demux(bogus, 0)
	if err == nil {
		t.Fatal("second exchange should reject mismatched origin")
	}
	if client.IsDone() {
		t.Fatal("should not be done after rejected second response")
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

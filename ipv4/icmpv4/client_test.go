package icmpv4

import (
	"testing"

	"github.com/soypat/lneto/internal"
)

const (
	testHashSeed = 0xdeadbeef
)

func TestClients(t *testing.T) {
	const sizebuffer = 64
	const queuesize = 2
	var sender, responder Client
	err := sender.Configure(ClientConfig{
		ResponseQueueBuffer: make([]byte, sizebuffer),
		ResponseQueueLimit:  queuesize,
		HashSeed:            testHashSeed,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = responder.Configure(ClientConfig{
		ResponseQueueBuffer: make([]byte, sizebuffer),
		ResponseQueueLimit:  queuesize,
		HashSeed:            testHashSeed,
	})
	if err != nil {
		t.Fatal(err)
	}
	pattern := []byte("ab12")
	size := 8
	var buf [64]byte
	key1 := testSingleExchange(t, &sender, &responder, buf[:], pattern, uint16(size))
	completed, ok := sender.PingPop(key1)
	if !completed || !ok {
		t.Fatal("ping did not complete or not exist")
	}
}

func testSingleExchange(t *testing.T, sender, responder *Client, buf []byte, pattern []byte, size uint16) (senderKey uint32) {
	var n int
	senderKey, n = testSendEcho(t, sender, buf, pattern, size)
	const frameOff = 0
	const ipOff = 0
	completed, ok := sender.PingPeek(senderKey)
	if !ok {
		t.Error("ping key not exist")
	} else if completed {
		t.Error("ping completed before response")
	}
	ifrm, _ := NewFrame(buf[frameOff : frameOff+n])
	efrm := FrameEcho{Frame: ifrm}
	id, seq := efrm.Identifier(), efrm.SequenceNumber()
	err1 := responder.Demux(buf[:frameOff+n], frameOff)
	if err1 != nil {
		t.Error("responder demux during single", err1)
	}
	n, err := responder.Encapsulate(buf, ipOff, frameOff)
	if err != nil {
		t.Error("responder encaps during single", err)
		return
	} else if n == 0 && err1 == nil {
		t.Error("responder wrote no data")
		return
	}
	ifrm, err = NewFrame(buf[frameOff : frameOff+n])
	if err != nil {
		t.Fatal(err)
	}
	if ifrm.Type() != TypeEchoReply {
		t.Fatalf("expected echo reply %d", ifrm.Type())
	}
	efrm = FrameEcho{Frame: ifrm}
	if efrm.Identifier() != id {
		t.Error("mismatched identifier want/got:", id, efrm.Identifier())
	}
	if efrm.SequenceNumber() != seq {
		t.Error("mismatched sequence number want/got:", seq, efrm.SequenceNumber())
	}
	data := efrm.Data()
	testPatternMatch(t, data, pattern, int(size))
	err = sender.Demux(buf[:frameOff+n], frameOff)
	if err != nil {
		t.Error("sender demuxed response", err)
	}
	completed, ok = sender.PingPeek(senderKey)
	if !completed {
		t.Error("expected ping to have completed")
	}
	if !ok {
		t.Error("ping key not exist after completion")
	}
	if completed2, ok2 := sender.PingPeek(senderKey); completed != completed2 || ok != ok2 {
		t.Error("change in status after peek")
	}
	return senderKey
}

func testSendEcho(t *testing.T, sender *Client, buf []byte, pattern []byte, size uint16) (key uint32, n int) {
	t.Helper()
	key, err := sender.PingStart([4]byte{1}, pattern, size)
	if err != nil {
		t.Fatal(err)
	}
	const frameOff = 0
	const ipOff = 0
	n, err = sender.Encapsulate(buf[:], ipOff, frameOff)
	if err != nil {
		t.Errorf("sender encapsulate: %v", err)
	}
	ifrm, err := NewFrame(buf[:n])
	if err != nil {
		t.Fatal(err) // only fails in short frame case.
	}
	if ifrm.Type() != TypeEcho {
		t.Errorf("not echo type on send: %d", ifrm.Type())
	}
	efrm := FrameEcho{Frame: ifrm}
	data := efrm.Data()
	testPatternMatch(t, data, pattern, int(size))
	return key, n
}

func testPatternMatch(t *testing.T, data []byte, pattern []byte, size int) {
	t.Helper()
	if len(data) != size {
		t.Errorf("pattern size mismatch, want %d, got %d", size, len(data))
	}
	for i := 0; i < size; i += len(pattern) {
		got := data[i:min(len(data), i+len(pattern))]
		want := pattern[:len(got)]
		if !internal.BytesEqual(got, want) {
			t.Errorf("pattern data mismatch at %d, got %s, want %s", i, got, want)
		}
	}
}

package dhcpv4

import (
	"testing"
)

func TestClientServer(t *testing.T) {
	svAddr := [4]byte{192, 168, 1, 1}
	clAddr := svAddr
	clAddr[3]++
	var sv Server
	var cl Client
	err := cl.BeginRequest(123, RequestConfig{
		RequestedAddr:      clAddr,
		ClientHardwareAddr: [6]byte{1, 2, 3, 4, 5, 6},
		Hostname:           "lneto",
	})
	if err != nil {
		t.Fatal(err)
	}
	assertClState := func(state ClientState) {
		t.Helper()
		if state != cl.State() {
			t.Errorf("want client state %s, got %s", state.String(), cl.State().String())
		}
	}
	sv.Reset(svAddr, DefaultServerPort)
	// CLIENT DISCOVER.
	assertClState(StateInit)
	var buf [1024]byte
	n, err := cl.Encapsulate(buf[:], 0)
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		t.Fatal("no data exchanged")
	}
	assertClState(StateSelecting)
	err = sv.Demux(buf[:n], 0)
	if err != nil {
		t.Fatal(err)
	}
	// SERVER REPLY OFFER
	n, err = sv.Encapsulate(buf[:], 0)
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		t.Fatal("no data exchanged")
	}
	err = cl.Demux(buf[:n], 0)
	if err != nil {
		t.Fatal(err)
	}
	assertClState(StateRequesting)

	// CLIENT SEND OUT ACK.
	n, err = cl.Encapsulate(buf[:], 0)
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		t.Fatal("no data exchanged")
	}
	err = sv.Demux(buf[:n], 0)
	if err != nil {
		t.Fatal(err)
	}
}

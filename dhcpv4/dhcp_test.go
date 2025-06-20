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
		t.Fatal("no client discover")
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
		t.Fatal("no server offer")
	}
	err = cl.Demux(buf[:n], 0)
	if err != nil {
		t.Fatal(err)
	}
	assertClState(StateSelecting)

	// CLIENT SEND OUT REQUEST.
	n, err = cl.Encapsulate(buf[:], 0)
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		t.Fatal("no client request")
	}
	assertClState(StateRequesting)
	err = sv.Demux(buf[:n], 0)
	if err != nil {
		t.Fatal(err)
	}

	// SERVER REPLIES WITH ACK.
	n, err = sv.Encapsulate(buf[:], 0)
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		t.Fatal("no server reply")
	}
	err = cl.Demux(buf[:n], 0)
	if err != nil {
		t.Fatal(err)
	}
	assertClState(StateBound)
}

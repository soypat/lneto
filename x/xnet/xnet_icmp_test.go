package xnet

import (
	"net/netip"
	"testing"
)

func TestStackAsync_ICMPEcho(t *testing.T) {
	tests := []struct {
		name    string
		pattern []byte
		size    uint16
	}{
		{"1 EchoRequestReply", []byte("icmp-test"), 56},
		{"2 ReplyToManualRequest", []byte("manual-echo"), 32},
	}
	sender, receiver := newICMPStacks(t, 42, 1500) // seed 42 is arbitrary, stacks get unique IPs
	if err := sender.EnableICMP(true); err != nil {
		t.Fatal(err)
	}
	if err := receiver.EnableICMP(true); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, err := sender.EgressEthernet(buf)
	if n > 0 || err != nil {
		t.Fatal("sender unexpected data sent or error", n, err)
	}
	n, err = receiver.EgressEthernet(buf)
	if n > 0 || err != nil {
		t.Fatal("receiver unexpected data sent or error", n, err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			sender.SetGateway6(receiver.HardwareAddress())
			receiver.SetGateway6(sender.HardwareAddress())

			key, err := sender.icmp.PingStart(receiver.Addr().As4(), tt.pattern, tt.size)
			if err != nil {
				t.Fatal(err)
			}
			echoSent := exchangeEthernetOnce(t, sender, receiver, buf)
			if echoSent == 0 {
				t.Error("ECHO not sent")
			}
			echoReplySent := exchangeEthernetOnce(t, receiver, sender, buf)
			if echoReplySent == 0 {
				t.Error("ECHOREPLY not sent")
			}
			n, err = sender.EgressEthernet(buf)
			if n > 0 || err != nil {
				t.Error("sender excess data sent or error", n, err)
			}
			n, err = receiver.EgressEthernet(buf)
			if n > 0 || err != nil {
				t.Error("receiver excess data sent or error", n, err)
			}

			completed, ok := sender.icmp.PingPop(key)
			if !ok {
				t.Fatal("ping key not found")
			}
			if !completed {
				t.Fatal("expected ping to complete")
			}
		})
	}
}

// exchangeEthernetOnce sends one Ethernet frame from src to dst if available.
func exchangeEthernetOnce(t *testing.T, src, dst *StackAsync, buf []byte) int {
	t.Helper()
	n, err := src.EgressEthernet(buf)
	if err != nil {
		t.Error(err)
	}
	if n == 0 {
		return 0
	}
	if err := dst.IngressEthernet(buf[:n]); err != nil {
		t.Error(err)
	}
	return n
}

// newICMPStacks creates two test stacks with distinct static addresses and hardware addresses.
func newICMPStacks(t testing.TB, randSeed int64, mtu int) (*StackAsync, *StackAsync) {
	const icmpQueue = 4
	s1, s2 := new(StackAsync), new(StackAsync)

	// Use the seed to generate two adjacent IPs (10.0.0.x) and MACs.
	base := byte(randSeed & 0x7F) // keep in safe range 0..127
	addr1 := netip.AddrFrom4([4]byte{10, 0, 0, base})
	addr2 := netip.AddrFrom4([4]byte{10, 0, 0, base + 1})
	mac1 := [6]byte{0xbe, 0xef, 0, 0, 0, base}
	mac2 := [6]byte{0xbe, 0xef, 0, 0, 0, base + 1}

	if err := s1.Reset(StackConfig{
		Hostname:        "icmp-stack-1",
		RandSeed:        randSeed,
		StaticAddress:   addr1,
		HardwareAddress: mac1,
		MTU:             uint16(mtu),
		ICMPQueueLimit:  icmpQueue,
	}); err != nil {
		t.Fatal(err)
	}

	if err := s2.Reset(StackConfig{
		Hostname:        "icmp-stack-2",
		RandSeed:        ^randSeed,
		StaticAddress:   addr2,
		HardwareAddress: mac2,
		MTU:             uint16(mtu),
		ICMPQueueLimit:  icmpQueue,
	}); err != nil {
		t.Fatal(err)
	}

	return s1, s2
}

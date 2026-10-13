package xnet

import (
	"encoding/binary"
	"testing"

	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
)

// TestSubnetTable_PatchEgressMAC_WhenGatewayMAC captures the bug where patchEgressMAC
// returns early when the Ethernet dst is a gateway MAC (not broadcast), so it never
// patches the destination to the passively-learned client MAC.
func TestSubnetTable_PatchEgressMAC_WhenGatewayMAC(t *testing.T) {
	clientIP := [4]byte{10, 0, 0, 1}
	clientMAC := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01}
	serverIP := [4]byte{10, 0, 0, 2}
	serverMAC := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02}
	gatewayMAC := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF} // separate from client

	var st subnetTable
	st.reset(4, 2)
	st.subnet4 = ipv4.PrefixFrom(clientIP, 24)

	// Learn client MAC from a simulated ingress frame (client→server SYN).
	ingressFrame := makeMinimalIPv4Frame(serverMAC, clientMAC, clientIP, serverIP)
	st.learnFromIngressEthernet(ingressFrame)

	// Simulate egress SYN-ACK: stack uses gateway MAC as Ethernet dst (the bug).
	egressFrame := makeMinimalIPv4Frame(gatewayMAC, serverMAC, serverIP, clientIP)
	st.patchEgressMAC(egressFrame)

	gotDst := [6]byte(egressFrame[0:6])
	if gotDst != clientMAC {
		t.Errorf("patchEgressMAC did not fix Ethernet dst:\n  got  %x (gateway MAC)\n  want %x (client MAC)", gotDst, clientMAC)
	}
}

// makeMinimalIPv4Frame builds a 35-byte Ethernet+IPv4 frame (no payload, 1 padding byte).
// This is the minimum size that passes both learnFromIngressEthernet (>34) and patchEgressMAC (>=34) checks.
func makeMinimalIPv4Frame(dstMAC, srcMAC [6]byte, srcIP, dstIP [4]byte) []byte {
	frame := make([]byte, 35)
	copy(frame[0:6], dstMAC[:])
	copy(frame[6:12], srcMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], uint16(ethernet.TypeIPv4))
	frame[14] = 0x45 // IPv4, IHL=5
	frame[22] = 64   // TTL
	copy(frame[26:30], srcIP[:])
	copy(frame[30:34], dstIP[:])
	return frame
}

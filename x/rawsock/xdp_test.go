//go:build !tinygo && linux && (amd64 || arm64)

package rawsock

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/x/netdev"
)

var _ netdev.DevEthernet = (*XDP)(nil)

// etherTypeTest marks test frames apart from whatever else the kernel sends
// on the veth pair. IEEE 802 local experimental EtherType.
const etherTypeTest = 0x88b5

// TestXDPOpenInvalid verifies Open rejects bad configuration and leaves the
// socket closed.
func TestXDPOpenInvalid(t *testing.T) {
	tests := []struct {
		name string
		cfg  XDPConfig
	}{
		{name: "no-interface", cfg: XDPConfig{}},
		{name: "unknown-interface", cfg: XDPConfig{Interface: "lnetonope0"}},
		{name: "frames-not-pow2", cfg: XDPConfig{Interface: "lo", NumFrames: 3}},
		{name: "bad-frame-size", cfg: XDPConfig{Interface: "lo", FrameSize: 1000}},
		{name: "bad-mode", cfg: XDPConfig{Interface: "lo", Mode: XDPModeGeneric + 1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var x XDP
			if err := x.Open(tc.cfg); err == nil {
				x.Close()
				t.Fatal("Open succeeded, want error")
			}
			if err := x.Close(); err == nil {
				t.Error("Close after failed Open = nil, want error")
			}
		})
	}
}

// TestXDPVeth verifies frames sent over a veth pair reach the XDP socket and
// not the kernel, frames the socket sends reach the peer, and Close hands the
// interface back to the kernel. Needs root with CAP_BPF.
func TestXDPVeth(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: creates a veth pair and attaches an XDP program")
	}
	const ifXDP, ifPeer = "lnxdp0", "lnxdp1"
	vethPair(t, ifXDP, ifPeer)
	peer := openBridge(t, ifPeer)
	kernel := openBridge(t, ifXDP) // Sees what the kernel stack would see on ifXDP.

	var x XDP
	err := x.Open(XDPConfig{Interface: ifXDP, Mode: XDPModeGeneric, NumFrames: 256})
	if errors.Is(err, syscall.EPERM) {
		t.Skip("needs CAP_BPF in the initial user namespace:", err)
	} else if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	if got := x.Mode(); got != XDPModeGeneric {
		t.Errorf("Mode = %v, want %v", got, XDPModeGeneric)
	}
	hw, err := x.HardwareAddr6()
	if err != nil {
		t.Fatal(err)
	}
	peerHW, err := peer.HardwareAddress6()
	if err != nil {
		t.Fatal(err)
	}
	maxFrame, off := x.MaxFrameSizeAndOffset()
	if maxFrame != 1514 || off != 0 {
		t.Fatalf("MaxFrameSizeAndOffset = %d,%d, want 1514,0", maxFrame, off)
	}

	ethPoll := func(b []byte) (int, error) {
		_, n, err := x.EthPoll(b)
		return n, err
	}
	broadcast := [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	foreign := [6]byte{0x02, 0, 0, 0, 0, 1}
	rxTests := []struct {
		name string
		dst  [6]byte
		size int
		recv func([]byte) (int, error)
	}{
		{name: "unicast/EthPoll", dst: hw, size: 64, recv: ethPoll},
		{name: "broadcast/EthPoll", dst: broadcast, size: 60, recv: ethPoll},
		{name: "foreign-dst/Read", dst: foreign, size: 100, recv: x.Read},
		{name: "max-size/Read", dst: hw, size: maxFrame, recv: x.Read},
	}
	buf := make([]byte, maxFrame)
	for i, tc := range rxTests {
		frame := testFrame(tc.dst, peerHW, tc.size, byte(i))
		if _, err := peer.Write(frame); err != nil {
			t.Fatal(err)
		}
		got := recvXDP(t, &x, tc.recv, buf)
		if !bytes.Equal(got, frame) {
			t.Errorf("%s: received %x, want %x", tc.name, got, frame)
		}
	}
	if seen := recvBridge(kernel, buf, nil); seen != nil {
		t.Errorf("kernel saw redirected frame %x", seen)
	}

	var handled []byte
	x.SetEthRecvHandler(func(rxEthframe []byte) {
		if isTestFrame(rxEthframe) {
			handled = append(handled[:0], rxEthframe...)
		}
	})
	frame := testFrame(hw, peerHW, 90, 0x30)
	if _, err := peer.Write(frame); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(time.Second); handled == nil && time.Now().Before(deadline); {
		if _, err := x.Poll(10 * time.Millisecond); err != nil {
			t.Fatal(err)
		}
		if _, _, err := x.EthPoll(nil); err != nil {
			t.Fatal(err)
		}
	}
	x.SetEthRecvHandler(nil)
	if !bytes.Equal(handled, frame) {
		t.Errorf("handler received %x, want %x", handled, frame)
	}

	txTests := []struct {
		name string
		send func([]byte) error
	}{
		{name: "SendOffsetEthFrame", send: x.SendOffsetEthFrame},
		{name: "Write", send: func(b []byte) error { _, err := x.Write(b); return err }},
	}
	for i, tc := range txTests {
		frame := testFrame(peerHW, hw, 128, byte(0x40+i))
		if err := tc.send(frame); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if recvBridge(peer, buf, frame) == nil {
			t.Errorf("%s: peer did not receive frame", tc.name)
		}
	}

	if err := x.Close(); err != nil {
		t.Fatal(err)
	}
	frame = testFrame(hw, peerHW, 70, 0x50)
	if _, err := peer.Write(frame); err != nil {
		t.Fatal(err)
	}
	if recvBridge(kernel, buf, frame) == nil {
		t.Error("kernel did not receive frame after Close")
	}
}

func vethPair(t *testing.T, a, b string) {
	t.Helper()
	ip := func(args ...string) {
		t.Helper()
		out, err := exec.Command("ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, out)
		}
	}
	exec.Command("ip", "link", "del", a).Run() // Left over from a killed run.
	ip("link", "add", a, "type", "veth", "peer", "name", b)
	t.Cleanup(func() { exec.Command("ip", "link", "del", a).Run() })
	ip("link", "set", a, "up")
	ip("link", "set", b, "up")
}

func openBridge(t *testing.T, name string) *internal.Bridge {
	t.Helper()
	br, err := internal.NewBridge(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { br.Close() })
	if err := br.SetReadTimeout(20 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	return br
}

// testFrame returns a frame of size bytes from src to dst with a payload
// derived from seq.
func testFrame(dst, src [6]byte, size int, seq byte) []byte {
	frame := make([]byte, size)
	copy(frame[0:6], dst[:])
	copy(frame[6:12], src[:])
	binary.BigEndian.PutUint16(frame[12:14], etherTypeTest)
	for i := 14; i < size; i++ {
		frame[i] = seq + byte(i)
	}
	return frame
}

func isTestFrame(frame []byte) bool {
	return len(frame) >= 14 && binary.BigEndian.Uint16(frame[12:14]) == etherTypeTest
}

// recvXDP polls x and receives with recv until a test frame arrives.
func recvXDP(t *testing.T, x *XDP, recv func([]byte) (int, error), buf []byte) []byte {
	t.Helper()
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		ready, err := x.Poll(10 * time.Millisecond)
		if err != nil {
			t.Fatal(err)
		} else if !ready {
			continue
		}
		n, err := recv(buf)
		if err != nil {
			t.Fatal(err)
		} else if isTestFrame(buf[:n]) {
			return buf[:n]
		}
	}
	t.Fatal("timed out waiting for frame on XDP socket")
	return nil
}

// recvBridge reads br until it sees want, or any test frame if want is nil.
// Returns nil if none arrives before reads time out.
func recvBridge(br *internal.Bridge, buf, want []byte) []byte {
	for deadline := time.Now().Add(500 * time.Millisecond); time.Now().Before(deadline); {
		n, err := br.Read(buf)
		if err != nil {
			continue // Read timeout.
		}
		got := buf[:n]
		if isTestFrame(got) && (want == nil || bytes.Equal(got, want)) {
			return got
		}
	}
	return nil
}

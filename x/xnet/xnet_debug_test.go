//go:build !debugheaplog

package xnet

import (
	"io"
	"os"
	"testing"

	"github.com/soypat/lneto/ethernet"
)

// R9: heap allocation logging is opt-in through the debugheaplog build tag. A default
// build must not measure the heap (stop-the-world) nor print [ALLOC] lines to stdout.
func TestStackAsyncResetIPv6NoStdout(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	var s StackAsync
	err = s.Reset(StackConfig{
		Hostname:          "stdout",
		RandSeed:          1,
		StaticAddress4:    [4]byte{10, 0, 0, 1},
		StaticAddress6:    [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1},
		IPv6Stack:         DefaultStack6(),
		HardwareAddress:   [6]byte{0xbe, 0xef, 0, 0, 0, 1},
		MTU:               ethernet.MaxMTU,
		MaxActiveTCPPorts: 1,
	})
	os.Stdout = stdout
	w.Close()
	out, _ := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(out) > 0 {
		t.Errorf("Reset printed to stdout:\n%s", out)
	}
}

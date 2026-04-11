//go:build !tinygo

// Exclude tinygo compiler from build since exec package and t.Skip() are unimplemented.
// Also: wouldn't including tinygo cause a recursive call to tinygo test?
package xnet

import (
	"os/exec"
	"testing"
)

func TestTinyGoTest(t *testing.T) {
	if exec.Command("tinygo", "version").Run() != nil {
		t.Skip("tinygo not installed")
	}
	// This takes a long time. Consider running only important
	// tests with -run=TestXxx flag: `go test ./... -run=TestXxx`
	out, err := exec.Command("tinygo", "test", ".").CombinedOutput()
	if err != nil {
		t.Fatal("tinygo failed to test:", err, "\n", string(out))
	}
}

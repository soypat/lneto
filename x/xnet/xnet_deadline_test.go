package xnet

import (
	"os"
	"testing"
	"time"

	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/tcp"
)

func TestTCPConn_SetDeadline_Established(t *testing.T) {
	const seed = 9999
	const MTU = ethernet.MaxMTU
	const svPort = 8080
	client, sv, clconn, svconn := newTCPStacks(t, seed, MTU)
	tst := testerFrom(t, MTU)

	tst.TestTCPSetupAndEstablish(sv, client, svconn, clconn, svPort, 1337)

	if clconn.State() != tcp.StateEstablished {
		t.Fatalf("expected StateEstablished, got %s", clconn.State())
	}

	// SetDeadline should succeed on established connection.
	err := clconn.SetDeadline(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("SetDeadline on established conn failed: %v", err)
	}

	// Clear deadlines.
	err = clconn.SetDeadline(time.Time{})
	if err != nil {
		t.Fatalf("SetDeadline(zero) failed: %v", err)
	}
	_ = sv
}

func TestTCPConn_ReadDeadlineExceeded(t *testing.T) {
	const seed = 10001
	const MTU = ethernet.MaxMTU
	const svPort = 8080
	client, sv, clconn, svconn := newTCPStacks(t, seed, MTU)
	tst := testerFrom(t, MTU)

	tst.TestTCPSetupAndEstablish(sv, client, svconn, clconn, svPort, 1337)

	// Set read deadline in the past.
	err := svconn.SetReadDeadline(time.Now().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}

	// Read should fail immediately with deadline exceeded.
	buf := make([]byte, 64)
	_, rerr := svconn.Read(buf)
	if rerr == nil {
		t.Fatal("Read with past deadline should fail")
	}
	if rerr != os.ErrDeadlineExceeded {
		t.Fatalf("expected os.ErrDeadlineExceeded, got %v", rerr)
	}
}

func TestTCPConn_WriteDeadlineExceeded(t *testing.T) {
	const seed = 10002
	const MTU = ethernet.MaxMTU
	const svPort = 8080
	client, sv, clconn, svconn := newTCPStacks(t, seed, MTU)
	tst := testerFrom(t, MTU)

	tst.TestTCPSetupAndEstablish(sv, client, svconn, clconn, svPort, 1337)

	// Set write deadline in the past.
	err := clconn.SetWriteDeadline(time.Now().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}

	// Write should fail immediately with deadline exceeded.
	_, werr := clconn.Write([]byte("hello"))
	if werr == nil {
		t.Fatal("Write with past deadline should fail")
	}
	if werr != os.ErrDeadlineExceeded {
		t.Fatalf("expected os.ErrDeadlineExceeded, got %v", werr)
	}
}

func TestTCPConn_FlushEmptyNoop(t *testing.T) {
	const seed = 10003
	const MTU = ethernet.MaxMTU
	const svPort = 8080
	client, sv, clconn, svconn := newTCPStacks(t, seed, MTU)
	tst := testerFrom(t, MTU)

	tst.TestTCPSetupAndEstablish(sv, client, svconn, clconn, svPort, 1337)

	// Flush with no unsent data should return nil immediately.
	err := clconn.Flush()
	if err != nil {
		t.Fatalf("Flush with no unsent data should succeed: %v", err)
	}
}

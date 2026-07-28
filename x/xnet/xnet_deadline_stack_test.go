package xnet

import (
	"testing"

	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/tcp/rto"
)

// TestStackAsyncNextDeadline verifies a connection's transmit deadline reaches the
// top of the stack. lneto drives no egress of its own, so unless the deadline is
// observable there a retransmission only leaves when the embedder happens to call
// egress again.
func TestStackAsyncNextDeadline(t *testing.T) {
	const mtu = 1280
	const svPort, clPort = 80, 12345
	tst := testerFrom(t, mtu)
	svStack, clStack, svConn, clConn := newTCPStacks(t, 8, mtu)

	if got := clStack.NextDeadline(); got != 0 {
		t.Errorf("idle stack reports deadline %d, want 0", got)
	}

	// Give the client a retransmission timer before it opens, so the node the
	// stack registers is one that answers with a real deadline.
	const nanotime = int64(1)
	clConn.InternalHandler().SetPolicy(new(rto.Timer), func() int64 { return nanotime })
	tst.TestTCPSetupAndEstablish(svStack, clStack, svConn, clConn, svPort, clPort)

	// Emit data without delivering it, so it stays unacknowledged and the
	// retransmission timer stays armed. An acknowledged connection has no
	// deadline, correctly, since there is nothing left to resend.
	if _, err := clConn.Write([]byte("data")); err != nil {
		t.Fatal("write:", err)
	}
	buf := make([]byte, mtu+ethernet.MaxOverheadSize)
	if n, err := clStack.EgressEthernet(buf); err != nil {
		t.Fatal("egress:", err)
	} else if n == 0 {
		t.Fatal("no data segment emitted")
	}

	want := clConn.NextDeadline()
	if want == 0 {
		t.Fatal("connection armed no deadline; the timer never started")
	}
	if got := clStack.NextDeadline(); got != want {
		t.Errorf("stack reports deadline %d, want the connection's %d", got, want)
	}
	// The server holds no timer, so its stack must stay silent about deadlines.
	if got := svStack.NextDeadline(); got != 0 {
		t.Errorf("stack without a policy reports deadline %d, want 0", got)
	}
}

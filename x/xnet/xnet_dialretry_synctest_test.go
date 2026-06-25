//go:build !tinygo

// synctest is unavailable under TinyGo, so this deterministic dial-retry test is
// excluded from TinyGo builds. The retry/timeout logic it exercises is platform
// independent and fully covered when run with the standard Go toolchain.
package xnet

import (
	"context"
	"errors"
	"net/netip"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/tcp"
)

// TestStackGoTCPDialRetriesPendingControl verifies that an active TCP dial fails
// after exhausting its retries when the peer never responds to the SYN.
//
// It runs inside a synctest bubble so the time package uses a fake clock: backoff
// sleeps advance logical time deterministically and the dial deadline/retries are
// reached without any real waiting or wall-clock flakiness.
//
// The test goroutine first uses synctest.Wait to let the dialing goroutine emit and
// durably block after its first SYN, drains and asserts that SYN, then blocks on the
// result channel. Blocking on the channel is what lets synctest advance the fake
// clock: only when every goroutine is durably blocked does time move forward, waking
// the dialing goroutine from backoff until the deadline and retries are exhausted.
func TestStackGoTCPDialRetriesPendingControl(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const seed = 5678
		const MTU = ethernet.MaxMTU
		const tcptimeout = time.Second
		client, sv, _, _ := newTCPStacks(t, seed, MTU)

		// Backoff sleeps a real (fake-clocked) duration so the dial deadline and
		// retry counter advance deterministically under synctest.
		dialBackoff := func(consecutiveBackoffs uint) time.Duration { return tcptimeout / 10 }
		sg := client.StackBlocking(dialBackoff).StackGo(StackGoConfig{
			ListenerPoolConfig: TCPPoolConfig{
				QueueSize:  4,
				TxBufSize:  MTU,
				RxBufSize:  MTU,
				NewBackoff: func() lneto.BackoffStrategy { return dialBackoff },
			},
			TCPDialTimeout: tcptimeout,
			TCPDialRetries: 2,
		})

		laddr := netip.AddrPortFrom(netip.AddrFrom4(client.Addr4()), 1234)
		raddr := netip.AddrPortFrom(netip.AddrFrom4(sv.Addr4()), 22)
		done := make(chan error, 1)
		go func() {
			_, err := sg.SocketNetip(context.Background(), "tcp", syscall.AF_INET, sockSTREAM, laddr, raddr)
			done <- err
		}()

		// Let the dialing goroutine run until it durably blocks in backoff, by which
		// point it has queued its first SYN. Drain and assert it without responding,
		// so the dial is forced to time out and retry.
		synctest.Wait()
		assertOutboundSYN(t, client, 1)

		// With no peer response the dial must exhaust its deadline and retries and
		// fail. Blocking here lets the fake clock advance until that happens.
		err := <-done

		// The original scheduler-based test verified the retry by checking the
		// second SYN packet too. Keep that coverage before accepting the final error.
		assertOutboundSYN(t, client, 2)

		if err == nil {
			t.Fatal("expected TCP dial to fail after retries without peer response")
		}
		if !errors.Is(err, errDeadlineExceed) && !errors.Is(err, errRetriesExceeded) {
			t.Fatalf("expected deadline/retries error, got %v", err)
		}
	})
}

func assertOutboundSYN(t testing.TB, client *StackAsync, wantPacket int) {
	t.Helper()
	var buf [ethernet.MaxMTU + ethernet.MaxOverheadSize]byte
	n, err := client.EgressEthernet(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	frm, ok := getTCPFrame(buf[:n])
	if !ok {
		t.Fatalf("expected outbound TCP SYN packet %d from dial", wantPacket)
	}
	_, flags := frm.OffsetAndFlags()
	if flags != tcp.FlagSYN {
		t.Fatalf("expected SYN packet %d, got %s", wantPacket, flags.String())
	}
}

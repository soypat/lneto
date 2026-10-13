package xnet

import (
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
)

func TestNetstackAccessors(t *testing.T) {
	var ns Netstack
	backoff := lneto.BackoffStrategy(func(uint) time.Duration { return time.Millisecond })
	err := ns.Reset(NetstackConfig{
		TCPPoolConfig: TCPPoolConfig{
			PoolSize:   1,
			QueueSize:  1,
			TxBufSize:  512,
			RxBufSize:  512,
			NewBackoff: func() lneto.BackoffStrategy { return backoff },
		},
		BackoffStack: backoff,
		StackConfig: StackConfig{
			Hostname:        "ns",
			RandSeed:        1,
			StaticAddress4:  [4]byte{192, 168, 1, 1},
			HardwareAddress: [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x00},
			MTU:             ethernet.MaxMTU,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	sa := ns.StackAsync()
	if sa.HardwareAddr() != [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x00} {
		t.Fatal("StackAsync does not return the configured stack")
	}
	if err := sa.SetAddr4([4]byte{10, 0, 0, 7}); err != nil {
		t.Fatal(err)
	}
	if ns.IPAddr4() != [4]byte{10, 0, 0, 7} {
		t.Fatal("changes through StackAsync are not seen by Netstack")
	}
	if ns.StackGo().blk.async != sa {
		t.Fatal("StackGo is not built on the Netstack StackAsync")
	}
}

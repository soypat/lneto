package netdev_test

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/x/netdev"
)

// mockDev is a DevEthernet test double. The mutex makes SetEthRecvHandler
// honor the quiescence guarantee with respect to deliver and EthPoll.
type mockDev struct {
	mu        sync.Mutex
	handler   func([]byte)
	sent      [][]byte
	rxq       [][]byte // frames pending delivery via EthPoll (poll mode or pump).
	pumped    int
	frameSize int
	frameOff  int
	pollErr   error
	sendErr   error
}

func (d *mockDev) HardwareAddr6() ([6]byte, error) {
	return [6]byte{0xde, 0xad, 0xbe, 0xef, 0, 1}, nil
}

func (d *mockDev) SendOffsetEthFrame(f []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sendErr != nil {
		return d.sendErr
	}
	d.sent = append(d.sent, append([]byte(nil), f...))
	return nil
}

func (d *mockDev) SetEthRecvHandler(h func(rxEthFrame []byte)) {
	d.mu.Lock()
	d.handler = h
	d.mu.Unlock()
}

// deliver invokes the installed receive handler as a driver goroutine would.
// Returns false if no handler is installed.
func (d *mockDev) deliver(frame []byte) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.handler == nil {
		return false
	}
	d.handler(frame)
	return true
}

func (d *mockDev) handlerInstalled() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.handler != nil
}

func (d *mockDev) numSent() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.sent)
}

func (d *mockDev) queueRx(frame []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rxq = append(d.rxq, append([]byte(nil), frame...))
}

func (d *mockDev) EthPoll(buf []byte) (int, int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.handler != nil {
		// Pump mode: frames go through the handler, buf must not be written.
		if buf != nil {
			return 0, 0, errors.New("EthPoll got non-nil buf with handler set")
		}
		d.pumped++
		for _, f := range d.rxq {
			d.handler(f)
		}
		d.rxq = nil
		return 0, 0, d.pollErr
	}
	if len(d.rxq) == 0 {
		return 0, 0, d.pollErr
	}
	f := d.rxq[0]
	d.rxq = d.rxq[1:]
	n := copy(buf[d.frameOff:], f)
	return d.frameOff, n, nil
}

func (d *mockDev) MaxFrameSizeAndOffset() (int, int) { return d.frameSize, d.frameOff }

type mockNetlink struct{}

func (mockNetlink) LinkConnect(_ struct{}) error                 { return nil }
func (mockNetlink) LinkDisconnect()                              {}
func (mockNetlink) LinkNotify(_ netdev.NotifyCallback[struct{}]) {}

// mockStack records ingressed frames and emits queued egress frames.
type mockStack struct {
	mu         sync.Mutex
	ingress    [][]byte
	egressq    [][]byte
	ingressErr error
	egressErr  error
}

func (s *mockStack) EnableICMP(bool) error { return nil }

func (s *mockStack) EnableDHCP(context.Context, bool, netip.Addr) (netip.Addr, netip.Addr, int, error) {
	return netip.Addr{}, netip.Addr{}, 0, nil
}

func (s *mockStack) Socket(context.Context, string, int, int, netip.AddrPort, netip.AddrPort) (any, error) {
	return nil, nil
}

func (s *mockStack) EgressPackets(bufs [][]byte, sizes []int, offset int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.egressErr != nil {
		return s.egressErr
	}
	for i := range bufs {
		sizes[i] = 0
		if len(s.egressq) == 0 {
			continue
		}
		sizes[i] = copy(bufs[i][offset:], s.egressq[0])
		s.egressq = s.egressq[1:]
	}
	return nil
}

func (s *mockStack) IngressPackets(bufs [][]byte, offset int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ingressErr != nil {
		return s.ingressErr
	}
	for _, b := range bufs {
		s.ingress = append(s.ingress, append([]byte(nil), b[offset:]...))
	}
	return nil
}

func (s *mockStack) queueEgress(frame []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.egressq = append(s.egressq, append([]byte(nil), frame...))
}

func (s *mockStack) numIngress() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.ingress)
}

func newIface(t *testing.T, dev *mockDev) *netdev.Interface[struct{}] {
	t.Helper()
	if dev.frameSize == 0 {
		dev.frameSize = 1514 + dev.frameOff
	}
	var iface netdev.Interface[struct{}]
	err := iface.Init(mockNetlink{}, dev, netdev.InterfaceConfig{})
	if err != nil {
		t.Fatal(err)
	}
	return &iface
}

func newRunner(t *testing.T, iface *netdev.Interface[struct{}], nbufs int, flags netdev.RunnerFlags, backoff lneto.BackoffStrategy) *netdev.Runner[struct{}] {
	t.Helper()
	if backoff == nil {
		backoff = func(uint) time.Duration { return time.Millisecond }
	}
	var r netdev.Runner[struct{}]
	err := r.Configure(netdev.RunnerConfig[struct{}]{
		Buffers: iface.RunnerBuffers(nbufs),
		Backoff: backoff,
		Flags:   flags,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &r
}

// testFrame returns a frame whose payload encodes and repeats seq for
// integrity checking with checkFrame.
func testFrame(seq uint32, size int) []byte {
	f := make([]byte, size)
	binary.LittleEndian.PutUint32(f, seq)
	for i := 4; i < size; i++ {
		f[i] = byte(seq)
	}
	return f
}

func checkFrame(t *testing.T, f []byte, size int) uint32 {
	t.Helper()
	if len(f) != size {
		t.Fatalf("frame length %d, want %d", len(f), size)
	}
	seq := binary.LittleEndian.Uint32(f)
	for i := 4; i < len(f); i++ {
		if f[i] != byte(seq) {
			t.Fatalf("frame seq %d corrupt at byte %d: got %#x want %#x", seq, i, f[i], byte(seq))
		}
	}
	return seq
}

func TestRunnerFlagsValidate(t *testing.T) {
	for _, tc := range []struct {
		flags netdev.RunnerFlags
		ok    bool
	}{
		{flags: 0, ok: false},
		{flags: netdev.RunnerInterfacePoll, ok: true},
		{flags: netdev.RunnerInterfaceAsync, ok: true},
		{flags: netdev.RunnerInterfacePoll | netdev.RunnerInterfaceAsync, ok: true},
		{flags: netdev.RunnerAsyncWakeOnRx, ok: false},
		{flags: netdev.RunnerInterfacePoll | netdev.RunnerAsyncWakeOnRx, ok: false},
		{flags: netdev.RunnerInterfaceAsync | netdev.RunnerAsyncWakeOnRx, ok: true},
		{flags: netdev.RunnerInterfaceAsync | netdev.RunnerNoBackoff, ok: false},
		{flags: netdev.RunnerInterfaceAsync | netdev.RunnerAsyncWakeOnRx | netdev.RunnerNoBackoff, ok: true},
	} {
		err := tc.flags.Validate()
		if (err == nil) != tc.ok {
			t.Errorf("flags %#b: got err=%v, want ok=%v", tc.flags, err, tc.ok)
		}
	}
}

func TestRunOncePollOnly(t *testing.T) {
	dev := &mockDev{frameOff: 4}
	iface := newIface(t, dev)
	stack := &mockStack{}
	r := newRunner(t, iface, 2, netdev.RunnerInterfacePoll, nil)

	const fsize = 64
	dev.queueRx(testFrame(1, fsize))
	stack.queueEgress(testFrame(2, fsize))

	nrx, ntx, err := r.RunOnce(iface, stack)
	if err != nil {
		t.Fatal(err)
	}
	if nrx != fsize {
		t.Errorf("nrx=%d, want %d", nrx, fsize)
	}
	if ntx != fsize {
		t.Errorf("ntx=%d, want %d", ntx, fsize)
	}
	if stack.numIngress() != 1 {
		t.Fatalf("ingress=%d, want 1", stack.numIngress())
	}
	if got := checkFrame(t, stack.ingress[0], fsize); got != 1 {
		t.Errorf("ingress seq=%d, want 1", got)
	}
	if dev.numSent() != 1 {
		t.Fatalf("sent=%d, want 1", dev.numSent())
	}
	// Sent frame includes the device frame offset prefix.
	if got := checkFrame(t, dev.sent[0][dev.frameOff:], fsize); got != 2 {
		t.Errorf("sent seq=%d, want 2", got)
	}
}

// TestRunOnceAsyncOrdering checks frames ingress in arrival order, not in
// buffer slot order (review: getRx scans slots in index order; reordering
// TCP segments triggers dup-ACK/retransmit churn).
func TestRunOnceAsyncOrdering(t *testing.T) {
	dev := &mockDev{}
	iface := newIface(t, dev)
	stack := &mockStack{}
	r := newRunner(t, iface, 4, netdev.RunnerInterfaceAsync, nil)
	err := r.EnableAsyncHandling(iface)
	if err != nil {
		t.Fatal(err)
	}
	const fsize = 64
	for seq := uint32(1); seq <= 3; seq++ {
		if !dev.deliver(testFrame(seq, fsize)) {
			t.Fatal("handler not installed")
		}
	}
	for range 3 {
		_, _, err := r.RunOnce(iface, stack)
		if err != nil {
			t.Fatal(err)
		}
	}
	if stack.numIngress() != 3 {
		t.Fatalf("ingress=%d, want 3", stack.numIngress())
	}
	for i, f := range stack.ingress {
		if got := checkFrame(t, f, fsize); got != uint32(i+1) {
			t.Errorf("ingress[%d] seq=%d, want %d: frames reordered", i, got, i+1)
		}
	}
}

// TestRunOnceAsyncPollPumpSingleBuffer exercises the async+poll pump path with
// a single buffer over several cycles. Review (MDr164, buffer.go inline): reset
// and release clear lenAcquire but not isRx, so numFree undercounts and the
// EthPoll pump is wrongly skipped.
func TestRunOnceAsyncPollPumpSingleBuffer(t *testing.T) {
	dev := &mockDev{}
	iface := newIface(t, dev)
	stack := &mockStack{}
	r := newRunner(t, iface, 1, netdev.RunnerInterfaceAsync|netdev.RunnerInterfacePoll, nil)
	err := r.EnableAsyncHandling(iface)
	if err != nil {
		t.Fatal(err)
	}
	const fsize = 64
	const cycles = 3
	for seq := uint32(1); seq <= cycles; seq++ {
		dev.queueRx(testFrame(seq, fsize))
		_, _, err := r.RunOnce(iface, stack)
		if err != nil {
			t.Fatal(err)
		}
	}
	if stack.numIngress() != cycles {
		t.Fatalf("ingress=%d, want %d: EthPoll pump skipped", stack.numIngress(), cycles)
	}
	for i, f := range stack.ingress {
		if got := checkFrame(t, f, fsize); got != uint32(i+1) {
			t.Errorf("ingress[%d] seq=%d, want %d", i, got, i+1)
		}
	}
	// Deliver a frame that stays pending in the pool, then reconfigure: reset
	// must fully clear slot state. A stale isRx mark from the abandoned frame
	// makes numFree undercount and skip the pump.
	if !dev.deliver(testFrame(cycles+1, fsize)) {
		t.Fatal("handler not installed")
	}
	err = r.Configure(netdev.RunnerConfig[struct{}]{
		Buffers: iface.RunnerBuffers(1),
		Backoff: func(uint) time.Duration { return time.Millisecond },
		Flags:   netdev.RunnerInterfaceAsync | netdev.RunnerInterfacePoll,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = r.EnableAsyncHandling(iface)
	if err != nil {
		t.Fatal(err)
	}
	dev.queueRx(testFrame(cycles+2, fsize))
	_, _, err = r.RunOnce(iface, stack)
	if err != nil {
		t.Fatal(err)
	}
	// The frame in flight at reconfigure time is legitimately dropped; the
	// queued frame must still arrive through the pump.
	if stack.numIngress() != cycles+1 {
		t.Fatalf("ingress=%d, want %d: pump skipped after reconfigure (stale isRx)", stack.numIngress(), cycles+1)
	}
}

// TestRunAfterEnableAsyncHandlingFails checks Run rejects a Runner set up via
// EnableAsyncHandling WITHOUT tearing down the installed handler. Review issue
// 4: the teardown defer is installed before the asyncH check, silently
// uninstalling the handler so subsequent RunOnce drops all async frames.
func TestRunAfterEnableAsyncHandlingFails(t *testing.T) {
	dev := &mockDev{}
	iface := newIface(t, dev)
	stack := &mockStack{}
	r := newRunner(t, iface, 2, netdev.RunnerInterfaceAsync, nil)
	err := r.EnableAsyncHandling(iface)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = r.Run(ctx, iface, stack)
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run after EnableAsyncHandling: got %v, want immediate config error", err)
	}
	// The rejected Run must not tear down the handler EnableAsyncHandling installed.
	if !dev.handlerInstalled() {
		t.Fatal("Run teardown removed handler it did not install")
	}
	if !dev.deliver(testFrame(1, 64)) {
		t.Fatal("handler not installed")
	}
	nrx, _, err := r.RunOnce(iface, stack)
	if err != nil || nrx != 64 {
		t.Fatalf("RunOnce after rejected Run: nrx=%d err=%v", nrx, err)
	}
}

// TestOversizeFrameDropped checks a frame larger than the pool buffers is
// dropped instead of panicking. Review: acquireNext slices buf[:len] without a
// bounds check — a slice-bounds panic inside the receive path.
func TestOversizeFrameDropped(t *testing.T) {
	dev := &mockDev{}
	iface := newIface(t, dev)
	stack := &mockStack{}
	r := newRunner(t, iface, 2, netdev.RunnerInterfaceAsync, nil)
	err := r.EnableAsyncHandling(iface)
	if err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("receive handler panicked on oversize frame: %v", recovered)
			}
		}()
		dev.deliver(make([]byte, dev.frameSize+1))
	}()
	nrx, _, err := r.RunOnce(iface, stack)
	if err != nil || nrx != 0 || stack.numIngress() != 0 {
		t.Fatalf("oversize frame ingressed: nrx=%d ingress=%d err=%v", nrx, stack.numIngress(), err)
	}
}

// TestRunBackoffEscalates checks the backoff counter escalates past a
// Gosched/Nop opening move. Review issue 5 (MDr164, runner.go inline): continue
// skips backoffs++, so a strategy returning Gosched at 0 busy-spins forever.
func TestRunBackoffEscalates(t *testing.T) {
	dev := &mockDev{}
	iface := newIface(t, dev)
	stack := &mockStack{}
	var mu sync.Mutex
	var recorded []uint
	backoff := func(consecutive uint) time.Duration {
		mu.Lock()
		recorded = append(recorded, consecutive)
		mu.Unlock()
		if consecutive == 0 {
			return lneto.BackoffFlagGosched
		}
		return time.Millisecond
	}
	r := newRunner(t, iface, 2, netdev.RunnerInterfaceAsync|netdev.RunnerAsyncWakeOnRx, backoff)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := r.Run(ctx, iface, stack)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(recorded) == 0 {
		t.Fatal("backoff never called")
	}
	escalated := false
	for _, c := range recorded {
		if c > 0 {
			escalated = true
			break
		}
	}
	if !escalated {
		t.Fatalf("backoff counter pinned at 0 across %d idle iterations", len(recorded))
	}
}

// TestRunAsyncStress hammers the receive handler from a producer goroutine
// while Run services the stack under Tx pressure, forcing buffer pool
// contention. Run with -race. Review issue 1: forceAcquireTx steals a slot the
// receive handler may be concurrently copying into, so partially constructed
// frames land on the wire and double release panics the runner. Checks frames
// are never corrupted (ingress AND egress) and never reordered.
func TestRunAsyncStress(t *testing.T) {
	dev := &mockDev{}
	iface := newIface(t, dev)
	stack := &mockStack{}
	r := newRunner(t, iface, 3, netdev.RunnerInterfaceAsync|netdev.RunnerAsyncWakeOnRx, nil)

	const fsize = 64
	const nframes = 2000
	const egressSeq = 0xffff
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- r.Run(ctx, iface, stack) }()

	// Egress traffic keeps the Tx path contending with Rx for buffers.
	for range 200 {
		stack.queueEgress(testFrame(egressSeq, fsize))
	}
	for seq := uint32(1); seq <= nframes; seq++ {
		for !dev.deliver(testFrame(seq, fsize)) {
			runtime.Gosched()
		}
	}
	time.Sleep(10 * time.Millisecond) // let the runner drain pending frames.
	cancel()
	err := <-runDone
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	stack.mu.Lock()
	if len(stack.ingress) == 0 {
		t.Fatal("no frames ingressed")
	}
	prev := uint32(0)
	for _, f := range stack.ingress {
		seq := checkFrame(t, f, fsize)
		if seq <= prev {
			t.Fatalf("reordered: seq %d after %d", seq, prev)
		}
		prev = seq
	}
	numIngress := len(stack.ingress)
	stack.mu.Unlock()
	dev.mu.Lock()
	for _, f := range dev.sent {
		if seq := checkFrame(t, f, fsize); seq != egressSeq {
			t.Fatalf("egress frame corrupted: seq=%#x", seq)
		}
	}
	numSent := len(dev.sent)
	dev.mu.Unlock()
	t.Logf("ingressed %d/%d frames, sent %d", numIngress, nframes, numSent)
}

// TestRunnerStatisticsCounting checks each RunnerStatistics counter increments
// per its documented trigger: device poll errors -> RxPollErrs, stack ingress
// errors -> RxStackErrs except ErrPacketDrop which -> RxPacketsDropped, stack
// egress errors -> TxStackErrs, and device send errors -> TxSendErrs.
func TestRunnerStatisticsCounting(t *testing.T) {
	const fsize = 64
	errBoom := errors.New("boom")
	for _, tc := range []struct {
		name  string
		setup func(dev *mockDev, stack *mockStack)
		want  netdev.RunnerStatistics
	}{
		{
			// Successful Rx+Tx must not bump any error counter (regression:
			// missing nil check counted every successful ingress as RxStackErrs).
			name: "no errors",
			setup: func(dev *mockDev, stack *mockStack) {
				dev.queueRx(testFrame(1, fsize))
				stack.queueEgress(testFrame(2, fsize))
			},
			want: netdev.RunnerStatistics{Rx: fsize},
		},
		{
			name:  "poll error",
			setup: func(dev *mockDev, stack *mockStack) { dev.pollErr = errBoom },
			want:  netdev.RunnerStatistics{RxPollErrs: 1},
		},
		{
			// ErrPacketDrop is counted by the stack itself, not the Runner:
			// neither RxPacketsDropped nor RxStackErrs may increment.
			name: "ingress packet drop",
			setup: func(dev *mockDev, stack *mockStack) {
				stack.ingressErr = lneto.ErrPacketDrop
				dev.queueRx(testFrame(1, fsize))
			},
			want: netdev.RunnerStatistics{Rx: fsize},
		},
		{
			name: "ingress stack error",
			setup: func(dev *mockDev, stack *mockStack) {
				stack.ingressErr = errBoom
				dev.queueRx(testFrame(1, fsize))
			},
			want: netdev.RunnerStatistics{Rx: fsize, RxStackErrs: 1},
		},
		{
			name:  "egress stack error",
			setup: func(dev *mockDev, stack *mockStack) { stack.egressErr = errBoom },
			want:  netdev.RunnerStatistics{TxStackErrs: 1},
		},
		{
			name: "send error",
			setup: func(dev *mockDev, stack *mockStack) {
				dev.sendErr = errBoom
				stack.queueEgress(testFrame(1, fsize))
			},
			want: netdev.RunnerStatistics{TxSendErrs: 1},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dev := &mockDev{}
			iface := newIface(t, dev)
			stack := &mockStack{}
			r := newRunner(t, iface, 2, netdev.RunnerInterfacePoll, nil)
			tc.setup(dev, stack)
			_, _, err := r.RunOnce(iface, stack)
			if err != nil {
				t.Fatal(err)
			}
			var stats netdev.RunnerStatistics
			r.ReadStatistics(&stats)
			if stats != tc.want {
				t.Errorf("stats=%+v, want %+v", stats, tc.want)
			}
		})
	}
}

// TestRunResetsStatistics checks Run zeroes all counters accumulated by a
// previous session, including RxPollErrs.
func TestRunResetsStatistics(t *testing.T) {
	dev := &mockDev{}
	iface := newIface(t, dev)
	stack := &mockStack{}
	r := newRunner(t, iface, 2, netdev.RunnerInterfacePoll, nil)
	dev.pollErr = errors.New("boom")
	if _, _, err := r.RunOnce(iface, stack); err != nil {
		t.Fatal(err)
	}
	var stats netdev.RunnerStatistics
	r.ReadStatistics(&stats)
	if stats == (netdev.RunnerStatistics{}) {
		t.Fatal("expected nonzero statistics before Run")
	}
	dev.mu.Lock()
	dev.pollErr = nil
	dev.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := r.Run(ctx, iface, stack); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	r.ReadStatistics(&stats)
	if stats != (netdev.RunnerStatistics{}) {
		t.Errorf("Run did not reset statistics: %+v", stats)
	}
}
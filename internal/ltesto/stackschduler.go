package ltesto

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/soypat/lneto"
)

// NewSched creates a cooperative two-goroutine scheduler modelling a
// coroutine handoff: the scheduled (stack) goroutine drives the [SchedGoro] handle
// while the controlling test thread drives the [SchedDriver] handle. Splitting the
// API across two handles makes it impossible to call a goroutine-side method
// from the test thread, or vice versa.
func NewSched(t testing.TB) *Sched {
	return &Sched{
		t:                  t,
		goroYieldSignal:    make(chan struct{}),
		goroContinueSignal: make(chan struct{}),
		finishChan:         make(chan error, 1),
		timeout:            time.Second,
	}
}

// Sched is the shared state behind a [SchedGoro]/[SchedDriver] pair. It exposes no
// handoff methods directly; obtain a handle with [Sched.Goro] (for the
// scheduled goroutine) or [Sched.Driver] (for the test thread).
type Sched struct {
	t testing.TB
	// when stack backs off it signals here and waits until channel read or timeout.
	goroYieldSignal chan struct{}
	// when main goroutine is ready for more information this channel is written to to signal waiting on stack activity.
	goroContinueSignal chan struct{}
	finishChan         chan error
	finishcalled       atomic.Bool
	coroCalls          atomic.Int32
	timeout            time.Duration
}

// AwaitGoroYield blocks until the coroutine suspends itself via [SchedGoro.Yield].
func (ss *Sched) AwaitGoroYield() {
	timeout := time.After(ss.timeout)
	select {
	case <-ss.goroYieldSignal:
	case <-timeout:
		ss.t.Fatal("timeout waiting for stack to backoff")
	}
}

// YieldToGoro wakes a coroutine parked in [SchedGoro.Yield], letting the goroutine run on.
func (ss *Sched) YieldToGoro() {
	timeout := time.After(ss.timeout)
	select {
	case ss.goroContinueSignal <- struct{}{}:
	case <-timeout:
		ss.t.Fatal("timeout while trying to yield to stack")
	}
}

// Done returns the channel that receives the coroutine's terminal error from
// [SchedGoro.FinishWithErr]. It may only be called once.
func (ss *Sched) Done() <-chan error {
	if ss.finishcalled.CompareAndSwap(false, true) {
		return ss.finishChan
	}
	panic("Done called twice")
}

// Goro returns the handle whose methods must be called from inside the
// scheduled (stack) goroutine.
func (ss *Sched) Goro() SchedGoro {
	if !ss.coroCalls.CompareAndSwap(0, 1) {
		panic("only one goroutine supported for now")
	}
	return SchedGoro{ss: ss}
}

// SchedGoro is the coroutine-side handle of a [Sched]. Every method MUST be
// called from inside the scheduled goroutine and never from the test thread.
type SchedGoro struct{ ss *Sched }

// Yield suspends the goroutine at a backoff point and parks until the driver
// calls [SchedDriver.YieldToGoro]. Its signature satisfies [lneto.BackoffStrategy] so it
// can be passed directly as the stack's backoff strategy.
func (c SchedGoro) Yield(consecutiveBackoffs uint) time.Duration {
	ss := c.ss
	timeout := time.After(ss.timeout)
	select {
	case ss.goroYieldSignal <- struct{}{}:
	case <-timeout:
		ss.t.Fatal("timeout backing off, possible race condition? Multiple stacks using same backoff is unexpected pattern")
	}
	select {
	case <-ss.goroContinueSignal:
	case <-timeout:
		ss.t.Fatal("timeout waiting for continue")
	}
	return lneto.BackoffFlagNop // backoff yield implemented on our side.
}

// FinishWithErr terminates the coroutine, handing err to the driver's [SchedDriver.Done]
// channel. It must be called at most once.
func (c SchedGoro) FinishWithErr(err error) {
	ss := c.ss
	if len(ss.finishChan) != 0 {
		ss.t.Fatal("Coro.FinishWithErr can be called once only")
	}
	ss.finishChan <- err
}

// Finish is just shorthand for c.FinishWithErr(nil).
func (c SchedGoro) Finish() {
	c.FinishWithErr(nil)
}

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
		t:       t,
		timeout: time.Second,
	}
}

// Sched is the shared state behind a [SchedGoro]/[SchedDriver] pair. It exposes no
// handoff methods directly; obtain a handle with [Sched.Goro] (for the
// scheduled goroutine) or [Sched.Driver] (for the test thread).
//
// A Sched may schedule more than one goroutine: call [Sched.Goro] once per
// goroutine and drive them as a barrier with [Sched.AwaitAllParked] and
// [Sched.YieldToAllParked]. The single-goroutine methods ([Sched.AwaitGoroYield],
// [Sched.AwaitGoroYieldOrDone], [Sched.YieldToGoro] and [Sched.Done]) address the
// first handle handed out and are the right tool when there is only one.
type Sched struct {
	t            testing.TB
	goros        []*schedGoro
	finishcalled atomic.Bool
	timeout      time.Duration
}

// schedGoro is the per-goroutine handoff state. The channels are shared with the
// scheduled goroutine; parked, finished and err are driver-side bookkeeping and
// must only ever be touched from the test thread.
type schedGoro struct {
	// when stack backs off it signals here and waits until channel read or timeout.
	yieldSignal chan struct{}
	// when main goroutine is ready for more information this channel is written to to signal waiting on stack activity.
	continueSignal chan struct{}
	finishChan     chan error

	parked   bool // goroutine is suspended inside Yield, awaiting a continue.
	finished bool // goroutine terminated via FinishWithErr.
	err      error
}

// goro0 returns the first handed-out goroutine state, which the single-goroutine
// driver methods address.
func (ss *Sched) goro0() *schedGoro {
	if len(ss.goros) == 0 {
		panic("Sched.Goro must be called before driving the scheduler")
	}
	return ss.goros[0]
}

// AwaitGoroYield blocks until the coroutine suspends itself via [SchedGoro.Yield].
func (ss *Sched) AwaitGoroYield() {
	g := ss.goro0()
	select {
	case <-g.yieldSignal:
		g.parked = true
	case <-time.After(ss.timeout):
		ss.t.Fatal("timeout waiting for stack to backoff")
	}
}

// AwaitGoroYieldOrDone blocks until the coroutine either parks itself via
// [SchedGoro.Yield] (returning done=false) or terminates via [SchedGoro.FinishWithErr]
// /[SchedGoro.Finish] (returning done=true and the terminal error). It lets a driver
// loop service an a-priori-unknown number of yields and still observe completion in
// the same select, avoiding the deadlock of guessing whether the goroutine will yield
// again. Do not mix with [Sched.Done] on the same scheduler.
func (ss *Sched) AwaitGoroYieldOrDone() (done bool, err error) {
	g := ss.goro0()
	select {
	case <-g.yieldSignal:
		g.parked = true
		return false, nil
	case err = <-g.finishChan:
		g.finished, g.err = true, err
		return true, err
	case <-time.After(ss.timeout):
		ss.t.Fatal("timeout waiting for stack to yield or finish")
		return true, nil
	}
}

// YieldToGoro wakes a coroutine parked in [SchedGoro.Yield], letting the goroutine run on.
func (ss *Sched) YieldToGoro() {
	g := ss.goro0()
	select {
	case g.continueSignal <- struct{}{}:
		g.parked = false
	case <-time.After(ss.timeout):
		ss.t.Fatal("timeout while trying to yield to stack")
	}
}

// AwaitAllParked blocks until every scheduled goroutine has either suspended
// itself in [SchedGoro.Yield] or terminated via [SchedGoro.FinishWithErr]. Once it
// returns, no scheduled goroutine is runnable, so the driver may touch state they
// share — pumping frames between stacks, advancing a simulated clock — without
// racing them. Pair it with [Sched.YieldToAllParked] to step the whole set.
//
// allFinished reports that every goroutine has terminated, which is the loop's
// exit condition; err is the first non-nil terminal error handed over so far.
func (ss *Sched) AwaitAllParked() (allFinished bool, err error) {
	ss.goro0() // Panics if the scheduler has no goroutines to drive.
	for _, g := range ss.goros {
		if g.parked || g.finished {
			continue // Already accounted for; waiting again would deadlock.
		}
		select {
		case <-g.yieldSignal:
			g.parked = true
		case gerr := <-g.finishChan:
			g.finished, g.err = true, gerr
		case <-time.After(ss.timeout):
			ss.t.Fatal("timeout waiting for scheduled goroutines to park or finish")
			return true, nil
		}
	}
	allFinished = true
	for _, g := range ss.goros {
		if !g.finished {
			allFinished = false
		}
		if err == nil {
			err = g.err
		}
	}
	return allFinished, err
}

// YieldToAllParked wakes every goroutine currently parked in [SchedGoro.Yield],
// letting them all run on until they park again. Goroutines that have already
// terminated are skipped, so it is safe to call until [Sched.AwaitAllParked]
// reports every goroutine finished.
func (ss *Sched) YieldToAllParked() {
	ss.goro0() // Panics if the scheduler has no goroutines to drive.
	for _, g := range ss.goros {
		if !g.parked {
			continue
		}
		select {
		case g.continueSignal <- struct{}{}:
			g.parked = false
		case <-time.After(ss.timeout):
			ss.t.Fatal("timeout while trying to yield to scheduled goroutine")
		}
	}
}

// Done returns the channel that receives the coroutine's terminal error from
// [SchedGoro.FinishWithErr]. It may only be called once.
func (ss *Sched) Done() <-chan error {
	g := ss.goro0()
	if ss.finishcalled.CompareAndSwap(false, true) {
		return g.finishChan
	}
	panic("Done called twice")
}

// Goro returns the handle whose methods must be called from inside the
// scheduled (stack) goroutine. Call it once per goroutine to be scheduled, from
// the test thread and before those goroutines start: the handles are handed out
// unsynchronized. The first handle is the one the single-goroutine driver methods
// address; drive two or more with [Sched.AwaitAllParked] and [Sched.YieldToAllParked].
func (ss *Sched) Goro() SchedGoro {
	g := &schedGoro{
		yieldSignal:    make(chan struct{}),
		continueSignal: make(chan struct{}),
		finishChan:     make(chan error, 1),
	}
	ss.goros = append(ss.goros, g)
	return SchedGoro{ss: ss, g: g}
}

// SchedGoro is the coroutine-side handle of a [Sched]. Every method MUST be
// called from inside the scheduled goroutine and never from the test thread.
// It holds its own handoff state directly so the goroutine never reads the
// scheduler's handle list, which the test thread may still be appending to.
type SchedGoro struct {
	ss *Sched
	g  *schedGoro
}

// Yield suspends the goroutine at a backoff point and parks until the driver
// calls [SchedDriver.YieldToGoro]. Its signature satisfies [lneto.BackoffStrategy] so it
// can be passed directly as the stack's backoff strategy.
func (c SchedGoro) Yield(consecutiveBackoffs uint) time.Duration {
	ss := c.ss
	timeout := time.After(ss.timeout)
	select {
	case c.g.yieldSignal <- struct{}{}:
	case <-timeout:
		ss.t.Fatal("timeout backing off, possible race condition? Multiple stacks using same backoff is unexpected pattern")
	}
	select {
	case <-c.g.continueSignal:
	case <-timeout:
		ss.t.Fatal("timeout waiting for continue")
	}
	return lneto.BackoffFlagNop // backoff yield implemented on our side.
}

// FinishWithErr terminates the coroutine, handing err to the driver's [SchedDriver.Done]
// channel. It must be called at most once.
func (c SchedGoro) FinishWithErr(err error) {
	ss := c.ss
	if len(c.g.finishChan) != 0 {
		ss.t.Fatal("Coro.FinishWithErr can be called once only")
	}
	c.g.finishChan <- err
}

// Finish is just shorthand for c.FinishWithErr(nil).
func (c SchedGoro) Finish() {
	c.FinishWithErr(nil)
}

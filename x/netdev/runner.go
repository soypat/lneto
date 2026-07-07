package netdev

import (
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/soypat/lneto"
)

var (
	errRunnerAcquired       = errors.New("runner currently running")
	errNotDriven            = errors.New("runner needs to be poll/async driven")
	errWakeNeedsAsync       = errors.New("runner wake needs to be async driven")
	errNoBackoffNeedsWake   = errors.New("wake mechanic not set for omitting backoff")
	errAsyncHandlingWithRun = errors.New("incompatible use of EnableAsyncHandling with Run- use with RunOnce")
	errEgressInvalidWrite   = errors.New("EgressPackets returned invalid written data given frameOffset and argument buffer size")
)

// RunnerFlags selects how a [Runner] drives its [Interface]. See [RunnerConfig.Flags].
type RunnerFlags uint32

const (
	// Signals Interface needs to be driven via [DevEthernet.EthPoll].
	// [RunnerAsync] can be set too to signal packets received via callback instead of written to EthPoll buffer.
	RunnerInterfacePoll RunnerFlags = 1 << iota
	// Interface data channel driven exclusively by callback passed to [DevEthernet.SetEthRecvHandler].
	// If set [DevEthernet.EthPoll] must not write data to argument buffer.
	RunnerInterfaceAsync
	// Runner backs off but also wakes up on receiving data asynchronously.
	// Needs [RunnerInterfaceAsync] to be set to be effective.
	RunnerAsyncWakeOnRx
	// Runner will not use the backoff to queue timer wakeups. When setting this option
	// the user is responsible for waking up the stack so that it can transmit even when not receiving data.
	// Needs [RunnerAsyncWakeOnRx] to be set to be effective.
	RunnerNoBackoff
)

// HasAll reports whether every bit in query is set.
func (rf RunnerFlags) HasAll(query RunnerFlags) bool { return rf&query == query }

// HasAny reports whether at least one bit in query is set.
func (rf RunnerFlags) HasAny(query RunnerFlags) bool { return rf&query != 0 }

// Validate reports whether the flag combination is a usable [Runner] configuration.
func (rf RunnerFlags) Validate() error {
	driven := rf.HasAny(RunnerInterfaceAsync | RunnerInterfacePoll)
	wake := rf.HasAny(RunnerAsyncWakeOnRx)
	if !driven {
		return errNotDriven
	} else if wake && !rf.HasAll(RunnerInterfaceAsync) {
		return errWakeNeedsAsync
	} else if rf.HasAny(RunnerNoBackoff) && !wake {
		return errNoBackoffNeedsWake
	}
	return nil
}

// Runner orchestrates an Interface and a Stack asynchronously.
// The complexity of Runner stems from it needing to handle three types of devices, see [RunnerConfig.Flags] documentation.
type Runner[C any] struct {
	running   atomic.Uint32
	bufs      bufferSelect
	backoff   lneto.BackoffStrategy
	reconnect *C
	// pktlost is incremented each time an incoming packet is lost due to insufficient buffer size.
	// Does not include packets dropped by the stack ([lneto.ErrPacketDrop]); the stack counts those itself.
	pktlost atomic.Uint64
	// rx includes ALL data received, even dropped data. xnet.StackAsync keeps track of actual processed data.
	rx atomic.Uint64
	// rxStackErrs/rxPollErrs/txStackErrs/txSendErrs count receive/transmit path
	// errors which are intentionally not propagated out of the run loop nor
	// printed in the datapath. See [RunnerStatistics] for per-counter semantics.
	rxStackErrs, rxPollErrs atomic.Uint64
	txStackErrs, txSendErrs atomic.Uint64
	// bufsaux is used as an argument to stack processing so that no allocations are performed
	bufsaux  [1][]byte
	sizesaux [1]int
	// flags is atomic since [Runner.Wake] reads it from arbitrary goroutines
	// concurrently with Configure. Configure stores it last so a visible
	// RunnerAsyncWakeOnRx bit guarantees a non-nil wake channel.
	flags     atomic.Uint32
	wake      chan struct{}
	waketimer *time.Timer
	asyncH    *Interface[C]
}

// RunnerConfig configures a [Runner]. Used in [Runner.Configure].
type RunnerConfig[C any] struct {
	// Buffers are the Rx/Tx packet buffers. At least one is required. Use
	// [Interface.RunnerBuffers] to get correctly sized, aligned buffers.
	Buffers [][]byte
	// ReconnectParams is stored for use during link reconnection. Optional.
	ReconnectParams *C
	// Backoff is the idle wait strategy between loop iterations. Required.
	Backoff lneto.BackoffStrategy
	// Flags must be set to be Async, Poll driven, or both.
	// This selects the kind of device operation:
	//   - [RunnerInterfacePoll]: Entirely poll driven Rx [DevEthernet] i.e: ESP32 family.
	//   - [RunnerInterfaceAsync]: Entirely async driven Rx (IRQ) [DevEthernet] i.e: LAN8720.
	//   - [RunnerInterfacePoll]|[RunnerInterfaceAsync]: Hybrid Rx [DevEthernet] that are poll driven but can receive data outside EthPoll method. i.e: CYW43439.
	Flags RunnerFlags
}

// RunnerStatistics keeps track of send/receive statistics.
// It is an incomplete view that should be combined with the likes of xnet.StackAsync.ReadStatistics.
// It also does not have a view into packets dropped by the [DevEthernet] because of insufficient/slow polling.
type RunnerStatistics struct {
	// Rx total bytes received from interface including packets dropped.
	Rx uint64
	// RxPacketsDropped incremented by 1 each time there is not enough resources to process an incoming packet.
	// This does NOT include packets dropped by the Stack with [lneto.ErrPacketDrop].
	RxPacketsDropped uint64
	// RxPollErrs increments by 1 each time polling the [Interface] returns an error.
	// Is irrelevant for callback driven [DevEthernet].
	RxPollErrs uint64
	// RxStackErrs increments by 1 each time stack returns a non [lneto.ErrPacketDrop] error.
	RxStackErrs uint64
	// TxStackErrs increments by 1 each time stack returns an error generating egress packets.
	TxStackErrs uint64
	// TxSendErrs increments by 1 each time sending a frame over [Interface] returns error.
	TxSendErrs uint64
	// BufAcquireFail increments by 1 each time a buffer is unable to be acquired for Rx/Tx.
	BufAcquireFail uint64
}

// ReadStatistics reads statistics of Runner into [RunnerStatistics].
func (r *Runner[C]) ReadStatistics(stats *RunnerStatistics) {
	*stats = RunnerStatistics{
		Rx:               r.rx.Load(),
		RxPacketsDropped: r.pktlost.Load(),
		RxPollErrs:       r.rxPollErrs.Load(),
		RxStackErrs:      r.rxStackErrs.Load(),
		TxStackErrs:      r.txStackErrs.Load(),
		TxSendErrs:       r.txSendErrs.Load(),
		BufAcquireFail:   uint64(r.bufs.missedAcquire.Load()),
	}
}

func (r *Runner[C]) getFlags() RunnerFlags { return RunnerFlags(r.flags.Load()) }

// Wake unblocks a [Runner] sleeping in [RunnerAsyncWakeOnRx] mode so it services the
// stack immediately instead of waiting out the backoff. Signals coalesce and never block.
// Safe to call from any goroutine.
// Returns an error if the Runner is not configured for wake mode.
func (r *Runner[C]) Wake() error {
	if !r.getFlags().HasAny(RunnerAsyncWakeOnRx) {
		return lneto.ErrInvalidConfig
	}
	select {
	case r.wake <- struct{}{}: // signal waiting runner
	default: // already pending — coalesce, never block
	}
	return nil
}

// Configure validates cfg and applies it to the Runner. Call before [Runner.Run].
// Returns an error on invalid flags, missing buffers/backoff, or while the Runner is running.
func (r *Runner[C]) Configure(cfg RunnerConfig[C]) error {
	if err := cfg.Flags.Validate(); err != nil {
		return err
	}
	if len(cfg.Buffers) < 1 {
		return lneto.ErrInvalidConfig
	} else if cfg.Backoff == nil {
		return lneto.ErrMissingHALConfig
	}
	if !r.acquire() {
		return errRunnerAcquired
	}
	defer r.release()
	r.flags.Store(0) // Disable Wake during reconfiguration.
	r.teardownAsync()
	r.bufs.reset(cfg.Buffers)
	r.backoff = cfg.Backoff
	r.reconnect = cfg.ReconnectParams
	if cfg.Flags.HasAny(RunnerAsyncWakeOnRx) && r.wake == nil {
		r.wake = make(chan struct{}, 1)
		r.waketimer = time.NewTimer(24 * time.Hour)
	}
	r.flags.Store(uint32(cfg.Flags)) // Publish flags last; see field comment.
	return nil
}

// RunOnce performs a single Rx-then-Tx service cycle and returns the bytes received
// and transmitted. It does no backoff, wake wait, or state reset: the caller controls
// pacing and must [Runner.Configure] (with a non-nil stack) before the first call.
// Returns an error if a [Runner.Run] or another RunOnce is already in progress.
//
// Unlike [Runner.Run], RunOnce does not install the async receive handler. For a
// poll-driven interface ([RunnerInterfacePoll]) it works as-is; for an async interface
// ([RunnerInterfaceAsync]) call [Runner.EnableAsyncHandling] once beforehand so delivered
// frames are captured.
func (r *Runner[C]) RunOnce(iface *Interface[C], stack Stack) (nrx, ntx int, err error) {
	if stack == nil {
		return 0, 0, lneto.ErrInvalidConfig
	}
	if !r.acquire() {
		return 0, 0, errRunnerAcquired
	}
	defer r.release()
	flags := r.getFlags()
	async := flags.HasAny(RunnerInterfaceAsync)
	poll := flags.HasAny(RunnerInterfacePoll)
	bufsize := iface.bufsize()
	nrx, ntx, err = r.service(iface, stack, bufsize, poll, async)
	return nrx, ntx, err
}

// EnableAsyncHandling installs the Runner's async receive handler on iface so that
// frames delivered via [DevEthernet.SetEthRecvHandler] are captured into the buffer
// pool. Use it to drive an async interface with [Runner.RunOnce], which (unlike
// [Runner.Run]) does not install the handler itself. [Runner.Run] manages the handler
// on its own and does not need this.
//
// Returns [lneto.ErrUnsupported] if the Runner is not configured async
// ([RunnerInterfaceAsync]), or an error if a Run/RunOnce is in progress.
func (r *Runner[C]) EnableAsyncHandling(iface *Interface[C]) error {
	if !r.acquire() {
		return errRunnerAcquired
	}
	defer r.release()
	if !r.getFlags().HasAny(RunnerInterfaceAsync) {
		return lneto.ErrUnsupported
	}
	r.asyncH = iface
	iface.dev.SetEthRecvHandler(r.recvEthHandler)
	return nil
}

// DisableAsyncHandling removes the receive handler installed by [Runner.EnableAsyncHandling],
// stopping async frame delivery into the buffer pool. Call before reconfiguring or tearing
// down the Runner. No-op if async handling was not enabled.
func (r *Runner[C]) DisableAsyncHandling() error {
	if !r.acquire() {
		return errRunnerAcquired
	}
	defer r.release()
	r.teardownAsync()
	return nil
}

func (r *Runner[C]) teardownAsync() {
	if r.asyncH != nil {
		r.asyncH.dev.SetEthRecvHandler(nil)
		r.asyncH = nil
	}
}

// Run drives iface and stack until ctx is cancelled, doing one Rx then Tx per iteration
// and backing off when idle. Only one Run (and not concurrent with Configure) may execute
// at a time. Returns ctx.Err().
func (r *Runner[C]) Run(ctx context.Context, iface *Interface[C], stack Stack) error {
	if stack == nil {
		return lneto.ErrInvalidConfig
	}
	if !r.acquire() {
		return errRunnerAcquired
	}
	defer r.release()
	if r.asyncH != nil {
		return errAsyncHandlingWithRun
	}
	r.bufs.releaseAll()
	r.rx.Store(0)
	r.pktlost.Store(0)
	r.rxStackErrs.Store(0)
	r.rxPollErrs.Store(0)
	r.txStackErrs.Store(0)
	r.txSendErrs.Store(0)
	bufsize := iface.bufsize()
	flags := r.getFlags()
	async := flags.HasAny(RunnerInterfaceAsync)
	poll := flags.HasAny(RunnerInterfacePoll)
	wake := flags.HasAny(RunnerAsyncWakeOnRx)
	backoffEnabled := !flags.HasAny(RunnerNoBackoff)
	if wake {
		r.waketimer.Stop()
	}
	backoff := r.backoff
	if async {
		iface.dev.SetEthRecvHandler(r.recvEthHandler)
		// Only tear down the handler Run itself installed. In poll-only mode
		// any handler on the device is not Run's to clear.
		defer iface.dev.SetEthRecvHandler(nil)
	}

	// backoffs stores number of consecutive times no data was sent/received.
	var backoffs uint
	for ctx.Err() == nil {
		nrx, ntx, err := r.service(iface, stack, bufsize, poll, async)
		if err != nil {
			return err
		}
		if nrx > 0 || ntx > 0 {
			backoffs = 0
		} else if wake {
			if backoffEnabled {
				d := backoff(backoffs)
				backoffs++
				switch d {
				case lneto.BackoffFlagGosched:
					runtime.Gosched()
					fallthrough
				case lneto.BackoffFlagNop:
					continue
				default:
					d = max(d, 100*time.Microsecond)
				}
				// Claude say:
				// Reset without draining waketimer.C assumes Go 1.23+ timer
				// semantics (stale expiries do not linger in the channel). On
				// runtimes with older semantics (e.g. TinyGo) worst case is a
				// single spurious early wakeup, which is benign here.
				r.waketimer.Reset(d)
			}
			select {
			case <-r.wake:
				backoffs = 0 // woke early on data.
			case <-ctx.Done():
			case <-r.waketimer.C:
			}
			if backoffEnabled {
				r.waketimer.Stop()
			}
		} else {
			backoff.Do(backoffs)
			backoffs++
		}
	}
	return ctx.Err()
}

func (r *Runner[C]) service(iface *Interface[C], stack Stack, bufsize int, poll, async bool) (nrx, ntx int, err error) {
	nrx, err = r.doRx(iface, stack, poll, async)

	// Now do Tx, but first acquire buffer.
	txbuf := r.bufs.acquire(bufsize)
	if txbuf == nil {
		// We got blocked by Rx. Try draining rx.
		for range len(r.bufs.bufs) {
			n, err := r.doRx(iface, stack, poll, async)
			if err != nil {

				break
			}
			nrx += n
		}
		txbuf = r.bufs.acquire(bufsize)
		if txbuf == nil {
			// Buffers still held by in-flight Rx. Skip Tx this cycle rather
			// than steal a slot the receive handler may be writing into.
			return nrx, 0, nil
		}
	}
	r.bufsaux = [1][]byte{txbuf}
	err = stack.EgressPackets(r.bufsaux[:], r.sizesaux[:], iface.frameOff)
	ntx = r.sizesaux[0]
	if err != nil {
		r.txStackErrs.Add(1)
	} else if ntx > 0 {
		if ntx+iface.frameOff > len(txbuf) {
			r.bufs.release(txbuf)
			return nrx, 0, errEgressInvalidWrite
		}
		err = iface.dev.SendOffsetEthFrame(r.bufsaux[0][:ntx+iface.frameOff])
		if err != nil {
			r.txSendErrs.Add(1)
		}
	}
	r.bufs.release(txbuf) // Release buffer.
	return nrx, ntx, nil
}

// PrintDebug
//
// Deprecated: Might be given other shape in future, but this is not how we do debugging. use freely meanwhile.
func (r *Runner[C]) PrintDebug() {
	flags := r.getFlags()
	print("RUNNER: rx:", r.rx.Load(),
		" pktlost:", r.pktlost.Load(),
		" rxErrs:", r.rxStackErrs.Load(),
		" txErrs:", r.txSendErrs.Load(),
		" devPoll:", flags.HasAny(RunnerInterfacePoll),
		" devAsync:", flags.HasAny(RunnerInterfaceAsync),
		" devWakeRx:", flags.HasAny(RunnerAsyncWakeOnRx),
		"\n")
}

// acquire takes the single-use lock, returning false if already held.
func (r *Runner[C]) acquire() bool {
	return r.running.CompareAndSwap(0, 1)
}

// release frees the lock taken by acquire. Panics if not held.
func (r *Runner[C]) release() {
	if r.running.Load()&1 == 0 {
		panic("release of unacquired resource")
	}
	r.running.Store(0)
}

// recvEthHandler is called asynchronously. Should be as fast as possible. Do not block inside.
func (r *Runner[C]) recvEthHandler(incomingEthernet []byte) {
	r.rx.Add(uint64(len(incomingEthernet))) // rx includes dropped data. xnet.StackAsync keeps track of actual received statistics.
	if !r.bufs.goroPutRx(incomingEthernet) {
		// No free buffer or frame oversize, packet dropped.
		r.pktlost.Add(1)
		return
	}
	r.Wake()
}

// doRx services one Rx cycle. In poll mode it reads a frame from the device into a buffer
// and ingresses it. In async mode it drains frames delivered by recvEthHandler, pumping a
// poll-driven device with EthPoll(nil) when buffers are free. Device errors are counted
// in rxPollErrs; the returned error is the first stack ingress error encountered.
func (r *Runner[C]) doRx(iface *Interface[C], stack Stack, poll, async bool) (n int, gerr error) {
	if !async { // poll guaranteed to be set as per RunnerFlags.Validate.
		// Poll-only doRx.
		buf := r.bufs.acquire(iface.frameSize)
		if buf == nil {
			return 0, nil
		}
		eoff, efrm, err := iface.dev.EthPoll(buf)
		if err != nil {
			r.rxPollErrs.Add(1)
		}
		if efrm > 0 {
			r.bufsaux = [1][]byte{buf[:eoff+efrm]}
			gerr = stack.IngressPackets(r.bufsaux[:], eoff)
			if gerr != nil && gerr != lneto.ErrPacketDrop {
				r.rxStackErrs.Add(1)
			}
		}
		r.bufs.release(buf)
		r.rx.Add(uint64(efrm))
		return efrm, gerr
	}

	// Async branch.
	n, gerr = r.processAsyncRx(stack)
	if poll && r.bufs.numFree() > 0 {
		// Manual polling required by device.
		// Data not transmitted via this channel as per RunnerFlags documentation.
		_, _, err := iface.dev.EthPoll(nil)
		if err != nil {
			r.rxPollErrs.Add(1)
		}
	} else {
		return n, gerr
	}
	n2, err := r.processAsyncRx(stack)
	if gerr == nil {
		gerr = err
	}
	return n + n2, gerr
}

// processAsyncRx ingresses one frame previously copied to a buffer by recvEthHandler.
// Returns the frame length, or 0 if none is pending.
func (r *Runner[C]) processAsyncRx(stack Stack) (int, error) {
	buf := r.bufs.getRx()
	if buf == nil {
		return 0, nil
	}
	r.bufsaux = [1][]byte{buf}
	err := stack.IngressPackets(r.bufsaux[:], 0)
	if err != nil && err != lneto.ErrPacketDrop {
		r.rxStackErrs.Add(1)
	}
	r.bufs.release(buf)
	return len(buf), err
}

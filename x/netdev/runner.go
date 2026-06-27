package netdev

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/soypat/lneto"
)

var (
	errRunnerAcquired = errors.New("runner currently running")
)

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
)

func (rf RunnerFlags) HasAll(query RunnerFlags) bool { return rf&query == query }
func (rf RunnerFlags) HasAny(query RunnerFlags) bool { return rf&query != 0 }

func (rf RunnerFlags) Validate() error {
	driven := rf.HasAny(RunnerInterfaceAsync | RunnerInterfacePoll)
	if !driven {
		return errors.New("runner needs to be poll/async driven")
	} else if rf.HasAny(RunnerAsyncWakeOnRx) && !rf.HasAll(RunnerInterfaceAsync) {
		return errors.New("runner wake needs to be async driven")
	}
	return nil
}

// Runner orchestrates an Interface and a Stack asynchronously.
type Runner[C any] struct {
	running   atomic.Uint32
	bufs      bufferSelect
	backoff   lneto.BackoffStrategy
	reconnect *C
	// pktlost is incremented each time an incoming packet is lost due to insufficient buffer size.
	pktlost atomic.Uint64
	// rx includes ALL data received, even dropped data. xnet.StackAsync keeps track of actual processed data.
	rx atomic.Uint64
	// bufsaux is used as ana argument to stack processing so that no allocations are performed
	bufsaux  [1][]byte
	sizesaux [1]int
	flags    RunnerFlags
}

type RunnerConfig[C any] struct {
	Buffers         [][]byte
	ReconnectParams *C
	Backoff         lneto.BackoffStrategy
	// Flags must be set to be Async, Poll driven, or both.
	Flags RunnerFlags
}

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
	r.bufs.reset(cfg.Buffers)
	r.backoff = cfg.Backoff
	r.flags = cfg.Flags
	r.reconnect = cfg.ReconnectParams
	return nil
}

func (r *Runner[C]) Run(ctx context.Context, iface Interface[C], stack Stack) error {
	if stack == nil {
		return lneto.ErrInvalidConfig
	}
	if !r.acquire() {
		return errRunnerAcquired
	}
	defer func() {
		iface.dev.SetEthRecvHandler(nil)
		r.release()
	}()
	r.bufs.releaseAll()
	r.rx.Store(0)
	r.pktlost.Store(0)
	bufsize := iface.bufsize()
	async := r.flags.HasAny(RunnerInterfaceAsync)
	poll := r.flags.HasAny(RunnerInterfacePoll)
	backoff := r.backoff
	if async {
		// TODO: RunnerAsyncWakeOnRx if set switches handler and replaces backoff with a channel driven backoff.
		iface.dev.SetEthRecvHandler(r.recvEthHandler)
	}

	// backoffs stores number of consecutive times no data was sent/received.
	var backoffs uint
	for ctx.Err() == nil {
		nrx, err := r.doRx(iface, stack, poll, async)
		if err != nil {
			println("err EthPoll:", err.Error())
		}

		// Now do Tx, but first acquire buffer.
		txbuf := r.bufs.acquireNext(bufsize, false)
		if txbuf == nil {
			// We got blocked by Rx. Try draining rx.
			for range len(r.bufs.bufs) {
				n, err := r.doRx(iface, stack, poll, async)
				if err != nil {
					println("err EthPoll:", err.Error())
					break
				}
				nrx += n
			}
			var dropped int
			txbuf, dropped = r.bufs.forceAcquireTx(bufsize)
			if dropped > 0 {
				r.pktlost.Add(1)
			}
		}
		// By now we've tried our best, force packet acquisition.
		r.bufsaux = [1][]byte{txbuf}
		err = stack.EgressPackets(r.bufsaux[:], r.sizesaux[:], iface.frameOff)
		ntx := r.sizesaux[0]
		if err != nil {
			println("err EgressPackets:", err.Error())
		} else if ntx > 0 {
			if ntx+iface.frameOff > len(txbuf) {
				return errors.New("EgressPackets returned invalid written data given frameOffset and argument buffer size")
			}
			err = iface.dev.SendOffsetEthFrame(r.bufsaux[0][:ntx+iface.frameOff])
			if err != nil {
				println("err SendOffsetEthFrame:", err.Error())
			}
		}
		r.bufs.release(txbuf) // Release buffer.
		if nrx > 0 || ntx > 0 {
			backoffs = 0
		} else {
			backoff.Do(backoffs)
			backoffs++
		}
	}
	return ctx.Err()
}

// PrintDebug
//
// Deprecated: Might be given other shape in future, but this is not how we do debugging. use freely meanwhile.
func (r *Runner[C]) PrintDebug() {
	print("RUNNER: rx:", r.rx.Load(),
		" devPoll:", r.flags.HasAny(RunnerInterfacePoll),
		" devAsync:", r.flags.HasAny(RunnerInterfaceAsync),
		" devWakeRx:", r.flags.HasAny(RunnerAsyncWakeOnRx),
		" pktlost:", r.pktlost.Load(),
		" handles:",
		"\n")
}

func (r *Runner[C]) acquire() bool {
	return r.running.CompareAndSwap(0, 1)
}

func (r *Runner[C]) release() {
	if r.running.Load()&1 == 0 {
		panic("release of unacquired resource")
	}
	r.running.Store(0)
}

// recvEthHandler is called asynchronously. Should be as fast as possible. Do not block inside.
func (r *Runner[C]) recvEthHandler(incomingEthernet []byte) {
	buf := r.bufs.acquireNext(len(incomingEthernet), true)
	r.rx.Add(uint64(len(incomingEthernet))) // rx includes dropped data. xnet.StackAsync keeps track of actual received statistics.
	if buf == nil {
		// Failed to acquire buffer, packet dropped.
		r.pktlost.Add(1)
		return
	}
	copy(buf, incomingEthernet)
}

func (r *Runner[C]) doRx(iface Interface[C], stack Stack, poll, async bool) (n int, gerr error) {
	if !async { // poll guaranteed to be set as per RunnerFlags.Validate.
		// Poll-only doRx.
		buf := r.bufs.acquireNext(iface.bufsize(), true)
		if buf == nil {
			return 0, nil
		}
		eoff, efrm, err := iface.dev.EthPoll(buf)
		if efrm > 0 {
			r.bufsaux = [1][]byte{buf[:eoff+efrm]}
			gerr = stack.IngressPackets(r.bufsaux[:], eoff)
		} else {
			gerr = err
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
		iface.dev.EthPoll(nil)
	} else {
		return n, gerr
	}
	n2, err := r.processAsyncRx(stack)
	if gerr == nil {
		gerr = err
	}
	return n + n2, gerr
}

// processRx is called after a packet is received asynchronously and compied to buffer via recvEthHandler
func (r *Runner[C]) processAsyncRx(stack Stack) (int, error) {
	buf := r.bufs.getRx()
	if buf == nil {
		return 0, nil
	}
	r.bufsaux = [1][]byte{buf}
	err := stack.IngressPackets(r.bufsaux[:], 0)
	r.bufs.release(buf)
	return len(buf), err
}

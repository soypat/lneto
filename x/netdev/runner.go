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

// Runner orchestrates an Interface and a Stack asynchronously.
type Runner[C any] struct {
	running   atomic.Uint32
	bufs      bufferSelect
	backoff   lneto.BackoffStrategy
	reconnect *C
	// pktlost is incremented each time an incoming packet is lost due to insufficient buffer size.
	pktlost atomic.Uint64
	rx      atomic.Uint64
	// bufsaux is used as ana argument to stack processing so that no allocations are performed
	bufsaux          [1][]byte
	sizesaux         [1]int
	handlerTriggered bool
}

type RunnerConfig[C any] struct {
	Buffers         [][]byte
	ReconnectParams *C
	Backoff         lneto.BackoffStrategy
	WakeOnRx        bool
}

func (r *Runner[C]) Configure(cfg RunnerConfig[C]) error {
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
	r.handlerTriggered = false
	bufsize := iface.bufsize()
	iface.dev.SetEthRecvHandler(r.recvEthHandler)

	// backoffs stores number of consecutive times no data was sent/received.
	var backoffs uint
	for ctx.Err() == nil {
		nrx, err := r.doRx(iface, stack)
		if err != nil {
			println("err EthPoll:", err.Error())
		}

		// Now do Tx, but first acquire buffer.
		txbuf := r.bufs.acquireNext(bufsize, false)
		if txbuf == nil {
			// We got blocked by Rx. Try draining rx.
			for range len(r.bufs.bufs) {
				n, err := r.doRx(iface, stack)
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
			r.backoff.Do(backoffs)
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
		" devpollonly:", !r.handlerTriggered, " pktlost:", r.pktlost.Load(),
		" handles:", r.handlerTriggered,
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
	r.handlerTriggered = true
	buf := r.bufs.acquireNext(len(incomingEthernet), true)
	if buf == nil {
		// Failed to acquire buffer, packet dropped.
		r.pktlost.Add(1)
		return
	}
	r.rx.Add(uint64(len(buf)))
	copy(buf, incomingEthernet)
}

func (r *Runner[C]) doRx(iface Interface[C], stack Stack) (int, error) {
	if r.handlerTriggered {
		// Device delivers frames asynchronously via recvEthHandler.
		return r.processAsyncRx(stack, 0)
	}
	// Poll-driven device: EthPoll writes a frame into the buffer we provide.
	buf := r.bufs.acquireNext(iface.bufsize(), true)
	if buf == nil {
		// No free buffer for the device to poll into; drain pending Rx instead.
		return r.processAsyncRx(stack, 0)
	}
	eoff, efrm, err := iface.dev.EthPoll(buf)
	if r.handlerTriggered && efrm > 0 {
		r.bufs.release(buf)
		panic("invalid use of EthPoll with async handler- EthPoll should write into argument buffer only")
	}
	if err != nil || efrm == 0 {
		r.bufs.release(buf)
		if r.handlerTriggered {
			// Device turned out to be async and filled a different buffer.
			return r.processAsyncRx(stack, 0)
		}
		return 0, err
	}
	// Device polled a frame into buf at [eoff:eoff+efrm].
	r.bufsaux = [1][]byte{buf[:eoff+efrm]}
	err = stack.IngressPackets(r.bufsaux[:], eoff)
	r.bufs.release(buf)
	r.rx.Add(uint64(efrm))
	return efrm, err
}

// processRx is called after a packet is received asynchronously and compied to buffer via recvEthHandler
func (r *Runner[C]) processAsyncRx(stack Stack, ethFrameOff int) (int, error) {
	buf := r.bufs.getRx()
	if buf == nil {
		return 0, nil
	}
	r.bufsaux = [1][]byte{buf}
	err := stack.IngressPackets(r.bufsaux[:], ethFrameOff)
	r.bufs.release(buf)
	return len(buf) - ethFrameOff, err
}

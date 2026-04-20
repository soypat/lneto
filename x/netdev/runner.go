package netdev

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/soypat/lneto"
)

// Runner orchestrates an Interface and a Stack asynchronously.
type Runner[C any] struct {
	running atomic.Uint32
	// buflen stores the length of data inside buf. It is used as a buffer acquisition synchronizing primitive.
	buflen atomic.Uint32
	// pktlost is incremented each time an incoming packet is lost due to insufficient buffer size.
	pktlost atomic.Uint64
	tx, rx  atomic.Uint64
	// buf stores actual data.
	buf []byte
	// bufsaux is used as ana argument to stack processing so that no allocations are performed
	bufsaux          [1][]byte
	sizesaux         [1]int
	handlerTriggered bool
	deviceIsPollOnly bool
}

func (r *Runner[C]) Run(ctx context.Context, iface Interface[C], stack Stack, backoff lneto.BackoffStrategy) error {
	if stack == nil || backoff == nil {
		return errors.New("nil arguments to Run")
	}
	if !r.acquire() {
		return errors.New("runner currently running.")
	}
	defer func() {
		iface.dev.SetEthRecvHandler(nil)
		r.release()
	}()
	r.rx.Store(0)
	r.tx.Store(0)
	r.buflen.Store(0)
	r.pktlost.Store(0)
	r.handlerTriggered = false
	r.deviceIsPollOnly = false
	bufsize := iface.bufsize()
	if cap(r.buf) < bufsize {
		r.buf = make([]byte, bufsize)
	}
	r.buf = r.buf[:bufsize]
	iface.dev.SetEthRecvHandler(r.recvEthHandler)

	// backoffs stores number of consecutive times no data was sent/received.
	var backoffs uint
	for ctx.Err() == nil {
		n1, _ := r.processRx(stack, 0)
		eoff, efrm, err := iface.dev.EthPoll(r.buf)
		n2, _ := r.processRx(stack, 0)
		if efrm > 0 && n2 == 0 {
			r.deviceIsPollOnly = true
			r.buflen.Store(uint32(eoff + efrm))
			r.processRx(stack, eoff)
		} else if efrm > 0 && n2 > 0 {
			return errors.New("device both returns nonzero poll read and calls, choose one")
		} else if err != nil {
			println("err EthPoll:", err.Error())
		}

		// Now do Tx, but first acquire buffer.
		if !r.buflen.CompareAndSwap(0, 1) {
			continue // Oh no, async data received, go back to Rx processing.
		}
		r.bufsaux = [1][]byte{r.buf}

		err = stack.EgressPackets(r.bufsaux[:], r.sizesaux[:], iface.frameOff)
		n := r.sizesaux[0]
		if err != nil {
			println("err EgressPackets:", err.Error())
		} else if n > 0 {
			if n+iface.frameOff > len(r.buf) {
				return errors.New("EgressPackets returned invalid written data given frameOffset and argument buffer size")
			}
			err = iface.dev.SendOffsetEthFrame(r.bufsaux[0][:n+iface.frameOff])
			r.tx.Add(uint64(n + iface.frameOff))
			if err != nil {
				println("err SendOffsetEthFrame:", err.Error())
			}
		}
		r.buflen.Store(0) // Release buffer.
		if n1 > 0 || n2 > 0 || efrm > 0 || n > 0 {
			backoffs = 0
		} else {
			backoff.Do(backoffs)
			backoffs++
		}
	}
	return ctx.Err()
}

func (r *Runner[C]) PrintDebug() {
	print("RUNNER: tx|rx:", r.tx.Load(), "|", r.rx.Load(),
		" devpollonly:", r.deviceIsPollOnly, " pktlost:", r.pktlost.Load(), " handles:", r.handlerTriggered, "\n")
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
	if !r.buflen.CompareAndSwap(0, uint32(len(incomingEthernet))) {
		// Failed to acquire buffer, packet dropped.
		r.pktlost.Add(1)
		return
	}
	copy(r.buf, incomingEthernet)
}

// processRx is called after a packet is received asynchronously and compied to buffer via recvEthHandler
func (r *Runner[C]) processRx(stack Stack, ethFrameOff int) (int, error) {
	r.handlerTriggered = true
	n := r.buflen.Load()
	if n == 0 {
		return 0, nil
	}
	r.rx.Add(uint64(n))
	defer r.buflen.Store(0)
	r.bufsaux = [1][]byte{r.buf[:n]}
	return int(n), stack.IngressPackets(r.bufsaux[:], ethFrameOff)
}

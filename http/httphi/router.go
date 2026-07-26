package httphi

import (
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

//go:generate stringer -type Method,status -linecomment -output stringers.go

// reconfigureWait bounds how long [Router.Configure] waits for the previous
// generation to stop serving before reusing its exchange buffers.
const reconfigureWait = 10 * time.Millisecond

var (
	errNoRequestProto = errors.New("httphi: request line with no HTTP version")
	errBusyExchanges  = errors.New("httphi: exchanges still serving, cannot reuse their buffers")
)

type conn = io.ReadWriteCloser

// Router hosts concurrent safe data.
type Router struct {
	mu            sync.Mutex
	gen           atomic.Uint32
	numGoro       int
	reqBuf        int
	respBuf       int
	normalizeKeys bool
	pendingConns  chan job
	mux           Mux

	globbuf  []byte
	exchs    []Exchange
	freeList *Exchange

	backoff lneto.BackoffStrategy
	log     *slog.Logger
}

type job struct {
	exch *Exchange
}

// RouterConfig configures a [Router]. See [Router.Configure].
type RouterConfig struct {
	// FixedNumGoroutines must be set to either -1 (freely allocate new goroutines) or to the number of goroutines
	// to spawn on [Router.Configure] being called.
	FixedNumGoroutines int
	// RequestBufferSize determines the buffer allocated
	// for processing requests.
	RequestBufferSize int
	// ResponseMinBufferSize determines buffer allocated for processing responses.
	// Response buffer will reuse unused request memory so this is not a strict limit.
	ResponseMinBufferSize int

	NormalizeOutgoingKeys bool
	MaxAwaitingConns      int

	Backoff lneto.BackoffStrategy
	Mux     Mux
	Logger  *slog.Logger
}

// Validate returns a non-nil error if the configuration cannot be used to
// configure a [Router].
func (cfg RouterConfig) Validate() error {
	workerMode := cfg.workerMode()
	if workerMode && cfg.MaxAwaitingConns == 0 ||
		cfg.Mux == nil ||
		!workerMode && cfg.FixedNumGoroutines != -1 {
		return lneto.ErrInvalidConfig
	} else if cfg.Backoff == nil {
		return lneto.ErrMissingHALConfig
	}
	return nil
}

func (cfg RouterConfig) workerMode() bool {
	return cfg.FixedNumGoroutines > 0
}

// Teardown stops fixed goroutines.
func (r *Router) TeardownGoroutines() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.teardownGoroutinesLocked()
}

// teardownGoroutinesLocked closes the job queue fixed goroutines feed from.
// Requires r.mu held so that a concurrent [Router.Handle] cannot be enqueueing
// on the channel being closed.
func (r *Router) teardownGoroutinesLocked() {
	r.gen.Add(1)
	if r.pendingConns != nil {
		close(r.pendingConns)
		r.pendingConns = nil
	}
}

// Configure prepares the router to serve connections, tearing down the previous
// generation of goroutines and exchanges first. In worker mode it spawns
// [RouterConfig.FixedNumGoroutines] goroutines and allocates their exchange
// buffers up front, so the router's memory use does not grow with load.
//
// Configure may be called on a serving router, but since the exchange buffers
// are reused it waits for connections in flight to finish and fails with a
// non-nil error rather than reconfigure buffers still being served from.
func (r *Router) Configure(cfg RouterConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.teardownGoroutinesLocked()
	gen := r.gen.Load()
	numgoro := cfg.FixedNumGoroutines
	workerMode := cfg.workerMode()
	r.reqBuf = cfg.RequestBufferSize
	r.respBuf = cfg.ResponseMinBufferSize
	r.mux = cfg.Mux
	r.log = cfg.Logger
	r.normalizeKeys = cfg.NormalizeOutgoingKeys
	if !workerMode {
		r.backoff = cfg.Backoff
		r.numGoro = 0
		r.pendingConns = nil
		return nil
	}
	if workerMode {
		jobqueue := make(chan job, cfg.MaxAwaitingConns)
		if gen > 1 {
			// Exchange buffers below are reused: the previous generation must be
			// done serving before they may be handed to the new one.
			err := r.awaitIdleExchangesLocked(reconfigureWait)
			if err != nil {
				return err
			}
		}
		r.freeList = nil // Freelist entries point into the buffers reused below.
		internal.SliceReuse(&r.exchs, numgoro)
		r.exchs = r.exchs[:numgoro]
		rawBuflen := cfg.RequestBufferSize + cfg.ResponseMinBufferSize
		internal.SliceReuse(&r.globbuf, numgoro*rawBuflen)
		for i := range numgoro {
			// TODO exchange buffer alloc
			goff := i * rawBuflen
			r.exchs[i].Configure(r.globbuf[goff:goff+rawBuflen], cfg.RequestBufferSize, cfg.NormalizeOutgoingKeys)
			go r.goroWorker(gen, jobqueue, cfg.Backoff, cfg.Mux)
		}
		r.pendingConns = jobqueue
		r.numGoro = numgoro
	}
	return nil
}

// awaitIdleExchangesLocked waits up to maxWait for exchanges of the previous
// generation to finish serving so their buffers may be reused. Requires r.mu
// held; the lock is released while waiting since [Router.freeExch] needs it to
// free the exchanges being waited on.
func (r *Router) awaitIdleExchangesLocked(maxWait time.Duration) error {
	const pollInterval = time.Millisecond
	for waited := time.Duration(0); ; waited += pollInterval {
		busy := false
		for i := range r.exchs {
			if r.exchs[i].used.Load() {
				busy = true
				break
			}
		}
		if !busy {
			return nil
		} else if waited >= maxWait {
			return errBusyExchanges
		}
		r.mu.Unlock()
		time.Sleep(pollInterval)
		r.mu.Lock()
	}
}

// Handle takes ownership of conn and serves one exchange on it, closing it when
// done. It does not block on the exchange: the connection is handed to a
// goroutine and Handle returns immediately.
//
// Handle returns [lneto.ErrExhausted] when no exchange is free and
// [lneto.ErrPacketDrop] when the job queue is full. Both leave conn untouched
// and unclosed for the caller to dispose of: dropping is how a router with
// fixed memory applies backpressure.
func (r *Router) Handle(conn conn) error {
	// Exchange acquisition and the configuration it is served with must be read
	// under the same lock: [Router.Configure] may run concurrently.
	r.mu.Lock()
	exch := r.getExchLocked(conn)
	numGoro, backoff, mux := r.numGoro, r.backoff, r.mux
	if exch == nil {
		r.mu.Unlock()
		return lneto.ErrExhausted
	} else if numGoro == 0 {
		r.mu.Unlock()
		go r.goroHandle(exch, backoff, mux)
		return nil
	}
	// Enqueue under the lock: [Router.Configure] closes pendingConns while
	// holding it, so an unlocked send could land on a closed channel. The send
	// never blocks, so holding the lock cannot stall a worker.
	var enqueued bool
	select {
	case r.pendingConns <- job{exch: exch}:
		enqueued = true
	default:
		// pendingConns cannot store another Conn, we drop and return error.
		exch.used.Store(false) // release.
	}
	r.mu.Unlock()
	if enqueued {
		return nil
	}
	return lneto.ErrPacketDrop
}

func (r *Router) goroWorker(gen uint32, queue chan job, backoff lneto.BackoffStrategy, mux Mux) {
	for job := range queue {
		exch := job.exch
		if gen != r.gen.Load() {
			return
		} else if exch == nil {
			panic("httplo: unreachable nil job")
		}
		r.goroHandle(exch, backoff, mux)
	}
}

func (r *Router) goroHandle(exch *Exchange, backoff lneto.BackoffStrategy, mux Mux) {
	defer r.freeExch(exch)
	err := Handle(exch, mux, backoff)
	if err != nil {
		if exch.readErr != nil {
			r.error("goroHandle:ReadFromLimited", slog.String("err", err.Error()))
		} else {
			r.error("goroHandle:TryParse?", slog.String("err", err.Error()))
		}
	}
}

func (r *Router) freeExch(exch *Exchange) {
	const freelistMaxDepth = 5
	r.mu.Lock()
	depth := 0
	for node := r.freeList; node != nil && depth < freelistMaxDepth; node = node.nextFree {
		depth++
	}
	if depth < freelistMaxDepth {
		// Push at head: appending at the tail would drop every node past the
		// depth limit instead of dropping the exchange we cannot store.
		exch.nextFree = r.freeList
		r.freeList = exch
	} else {
		exch.nextFree = nil // Freelist full, exchange is dropped.
	}
	exch.Release()
	r.mu.Unlock()
}

// getExchLocked returns an exchange acquired on conn. Requires r.mu held.
func (r *Router) getExchLocked(conn conn) (exch *Exchange) {
	if r.freeList != nil {
		// Successor must be read before Acquire: Acquire clears nextFree, so
		// popping afterwards would truncate the freelist to the popped node.
		next := r.freeList.nextFree
		if r.freeList.Acquire(conn) {
			exch = r.freeList
			r.freeList = next
			return exch
		}
	}
	for i := range r.exchs {
		if r.exchs[i].Acquire(conn) {
			return &r.exchs[i]
		}
	}

	if r.numGoro == 0 {
		exch := new(Exchange)
		exch.Configure(make([]byte, r.respBuf+r.reqBuf), r.reqBuf, r.normalizeKeys)
		exch.Acquire(conn) // Fresh exchange, CAS cannot fail.
		return exch
	}
	return nil
}

func (r *Router) error(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(r.log, slog.LevelError, msg, attrs...)
}

func (r *Router) info(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(r.log, slog.LevelInfo, msg, attrs...)
}

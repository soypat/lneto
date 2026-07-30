package httphi

import (
	"errors"
	"io"
	"log/slog"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

//go:generate stringer -type Method -linecomment -output stringers.go

// reconfigureWait bounds how long [Router.Configure] waits for the previous
// generation to stop serving before reusing its exchange buffers.
const reconfigureWait = 10 * time.Millisecond

var (
	errNoRequestProto  = errors.New("httphi: request line with no HTTP version")
	errBadRequestProto = errors.New("httphi: unsupported HTTP version in request line")
	errBusyExchanges   = errors.New("httphi: exchanges still serving, cannot reuse their buffers")
	errRouterTornDown  = errors.New("httphi: router torn down, configure it before serving")

	errNotFormEncoded            = errors.New("httphi: request body is not application/x-www-form-urlencoded")
	errNotMultipart              = errors.New("httphi: request body is not multipart/form-data")
	errUnsupportedTransferCoding = errors.New("httphi: transfer coding not decoded, read the body directly")
)

type conn = io.ReadWriteCloser

// Router serves HTTP connections handed to it with [Router.Handle], routing
// each request to a handler found through its [Mux]. It plays the part of
// http.Server minus the listening: accepting connections is the caller's job,
// which is what lets the same router run over a TCP stack, a socket or a test
// pipe.
//
// A Router owns the exchanges and goroutines that serve connections and sizes
// both at [Router.Configure] time, so serving load costs no allocation and
// bounded memory. Connections arriving with nothing left to serve them are
// refused rather than queued, see [Router.Handle].
//
// Methods are safe for concurrent use. The zero value is not usable: configure
// it first.
type Router struct {
	mu              sync.Mutex
	gen             atomic.Uint32
	numGoro         int
	reqBuf          int
	respBuf         int
	reqNumHeaderCap int
	maxPathValues   int
	normalizeKeys   bool
	pendingConns    chan job
	mux             Mux

	globbuf  []byte
	exchs    []Exchange
	freeList *Exchange

	log *slog.Logger
}

// job is a connection waiting on an exchange for a worker goroutine to serve it.
type job struct {
	exch *Exchange
}

// RouterConfig configures a [Router]. See [Router.Configure].
type RouterConfig struct {
	// FixedNumGoroutines must be set to either -1 (freely allocate new goroutines) or to the number of goroutines
	// to spawn on [Router.Configure] being called.
	FixedNumGoroutines int
	// RequestHeaderBufferSize determines the buffer allocated
	// for processing request HTTP headers including request-target (URI), protocol and key/value pairs.
	RequestHeaderBufferSize int
	// ResponseHeaderMinBufferSize determines buffer allocated for processing response headers.
	// Response buffer will reuse unused request memory so this is not a strict limit.
	// "HTTP/1.1 200 OK\r\n" does not count towards this memory, only actual Headers key/value pairs use this memory.
	// After memory is fully consumed [Exchange.StageHeader] will not append more headers.
	ResponseHeaderMinBufferSize int
	// Number of request header key/value pairs to parse before failing and returning [StatusRequestHeaderFieldsTooLarge].
	RequestNumHeaderKVCap int

	// NormalizeOutgoingKeys normalizes response header field keys as they are
	// staged, i.e: "content-type" becomes "Content-Type".
	NormalizeOutgoingKeys bool
	// MaxAwaitingConns is the depth of the queue connections wait in for a free
	// goroutine. [Router.Handle] drops connections once it is full. Required and
	// must be non-zero when running a fixed number of goroutines, unused otherwise.
	MaxAwaitingConns int

	// Mux resolves each request's method and path to the handler serving it. Required.
	Mux Mux
	// Logger receives failed exchanges. Optional, nil disables logging.
	Logger *slog.Logger
}

const (
	// minRequestHeaderBuffer is the smallest request buffer [httpraw.Header]
	// accepts with buffer growth disabled, which is how exchanges are configured.
	minRequestHeaderBuffer = 32
	// minResponseHeaderBuffer is the room [Exchange.FlushHeader] needs for the
	// CRLF closing the header block, written even when no field was staged.
	minResponseHeaderBuffer = len("\r\n")
	// maxExchangeBuffer bounds an exchange's whole buffer: [Exchange] indexes it
	// with uint16 offsets, so a larger one would be addressed truncated.
	maxExchangeBuffer = math.MaxUint16
)

// Validate returns a non-nil error if the configuration cannot be used to
// configure a [Router].
func (cfg RouterConfig) Validate() error {
	workerMode := cfg.workerMode()
	switch {
	case cfg.Mux == nil,
		!workerMode && cfg.FixedNumGoroutines != -1,
		workerMode && cfg.MaxAwaitingConns <= 0,
		cfg.RequestNumHeaderKVCap <= 0,
		cfg.RequestHeaderBufferSize < minRequestHeaderBuffer,
		cfg.ResponseHeaderMinBufferSize < minResponseHeaderBuffer,
		cfg.ResponseHeaderMinBufferSize > maxExchangeBuffer,
		cfg.RequestHeaderBufferSize > maxExchangeBuffer-cfg.ResponseHeaderMinBufferSize:
		return lneto.ErrInvalidConfig
	}
	if workerMode {
		// Buffer sizes are bounded by maxExchangeBuffer above so the sum cannot
		// overflow; the products below allocate and can.
		exchBuf := cfg.RequestHeaderBufferSize + cfg.ResponseHeaderMinBufferSize
		if cfg.FixedNumGoroutines > math.MaxInt/exchBuf ||
			cfg.FixedNumGoroutines > math.MaxInt/cfg.RequestNumHeaderKVCap {
			return lneto.ErrInvalidConfig
		}
	}
	return nil
}

func (cfg RouterConfig) workerMode() bool {
	return cfg.FixedNumGoroutines > 0
}

// Shutdown stops the router once in-flight exchanges finish; until
// [Router.Configure] is called again, connections are refused with a
// non-nil error. Configure calls it before installing a new generation.
func (r *Router) Shutdown() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.shutdownLocked()
}

// shutdownLocked is [Router.Shutdown] but without locking requirement.
func (r *Router) shutdownLocked() {
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
	r.shutdownLocked()
	gen := r.gen.Load()
	numgoro := cfg.FixedNumGoroutines
	workerMode := cfg.workerMode()

	r.reqNumHeaderCap = cfg.RequestNumHeaderKVCap
	r.reqBuf = cfg.RequestHeaderBufferSize
	r.respBuf = cfg.ResponseHeaderMinBufferSize
	r.mux = cfg.Mux
	r.log = cfg.Logger
	maxPathValues := cfg.Mux.MaxPathValues()
	r.maxPathValues = maxPathValues
	r.normalizeKeys = cfg.NormalizeOutgoingKeys
	// Freelist entries were sized by the outgoing configuration: recycling one
	// would serve a request with buffer limits cfg never asked for.
	r.freeList = nil
	if !workerMode {
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
		internal.SliceReuse(&r.exchs, numgoro)
		r.exchs = r.exchs[:numgoro]
		rawBuflen := cfg.RequestHeaderBufferSize + cfg.ResponseHeaderMinBufferSize
		internal.SliceReuse(&r.globbuf, numgoro*rawBuflen)

		for i := range numgoro {
			// TODO exchange buffer alloc
			goff := i * rawBuflen
			// r.globbuf[goff:goff+rawBuflen], cfg.RequestHeaderBufferSize, cfg.RequestNumHeaderCap, cfg.NormalizeOutgoingKeys
			r.exchs[i].Configure(ExchangeConfig{
				RawBuf:                r.globbuf[goff : goff+rawBuflen],
				RequestBufferLim:      cfg.RequestHeaderBufferSize,
				NumHeaderKVCap:        cfg.RequestNumHeaderKVCap,
				NormalizeOutgoingKeys: cfg.NormalizeOutgoingKeys,
				NoRequestBufferGrowth: true, // Hard memory limit.
				MaxPathValues:         maxPathValues,
			})
			go r.goroWorker(gen, jobqueue, cfg.Mux)
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
			if r.exchs[i].acquired.Load() {
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
// Handle returns [lneto.ErrExhausted] when no exchange is free,
// [lneto.ErrPacketDrop] when the queue of connections awaiting a goroutine is
// full, and an error when the router's goroutines have been torn down. On every
// one of them conn is left untouched and unclosed for the caller to dispose of:
// refusing connections is how a router with fixed memory applies backpressure.
func (r *Router) Handle(conn io.ReadWriteCloser) error {
	// Exchange acquisition and the configuration it is served with must be read
	// under the same lock: [Router.Configure] may run concurrently.
	r.mu.Lock()
	numGoro, mux := r.numGoro, r.mux
	gen := r.gen.Load() // Generation whose buffers the exchange below is sized by.
	if numGoro > 0 && r.pendingConns == nil {
		// Goroutines torn down: refuse before claiming an exchange.
		r.mu.Unlock()
		return errRouterTornDown
	}
	exch := r.getExchLocked(conn)
	if exch == nil {
		r.mu.Unlock()
		return lneto.ErrExhausted
	} else if numGoro == 0 {
		r.mu.Unlock()
		go r.goroHandle(gen, exch, mux)
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
		exch.acquired.Store(false) // release.
	}
	r.mu.Unlock()
	if enqueued {
		return nil
	}
	return lneto.ErrPacketDrop
}

func (r *Router) goroWorker(gen uint32, queue chan job, mux Mux) {
	for job := range queue {
		exch := job.exch
		if exch == nil {
			panic("httplo: unreachable nil job")
		} else if gen != r.gen.Load() {
			// Not released with freeExch since generation torn down,
			// new buffer may have been allocated for Exchanges.
			exch.Release()
			continue
		}
		r.goroHandle(gen, exch, mux)
	}
}

func (r *Router) goroHandle(gen uint32, exch *Exchange, mux Mux) {
	defer r.freeExch(gen, exch)
	err := Handle(exch, mux, nil)
	if err != nil {
		if exch.readErr != nil {
			r.error("goroHandle:ReadFromLimited", slog.String("err", err.Error()))
		} else {
			r.error("goroHandle:TryParse?", slog.String("err", err.Error()))
		}
	}
}

// freeExch releases exch and offers it to the freelist for reuse. gen is the
// generation exch was acquired under: an exchange outliving its generation is
// dropped, its buffers being sized by a configuration the router no longer
// serves and possibly carved out of a globbuf it no longer owns.
func (r *Router) freeExch(gen uint32, exch *Exchange) {
	const freelistMaxDepth = 5
	r.mu.Lock()
	if gen != r.gen.Load() {
		exch.Release()
		r.mu.Unlock()
		return
	}
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
	// Unbounded mode is stored as zero, see [Router.Configure].
	workerMode := r.numGoro > 0
	if workerMode {
		for i := range r.exchs {
			if r.exchs[i].Acquire(conn) {
				return &r.exchs[i]
			}
		}
	} else {
		// Unbounded growth mode when r.numGoro==0.
		exch := new(Exchange)
		exch.Configure(ExchangeConfig{
			RawBuf:                make([]byte, r.respBuf+r.reqBuf),
			RequestBufferLim:      r.reqBuf,
			NumHeaderKVCap:        r.reqNumHeaderCap,
			NormalizeOutgoingKeys: r.normalizeKeys,
			NoRequestBufferGrowth: true,
			MaxPathValues:         r.maxPathValues,
		})
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

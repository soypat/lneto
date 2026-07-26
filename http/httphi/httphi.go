package httphi

import (
	"errors"
	"io"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/http/httpraw"
	"github.com/soypat/lneto/internal"
)

//go:generate stringer -type Method,status -linecomment -output stringers.go

// defaultReconfigureWait is how long [Router.Configure] waits on a busy
// previous generation when [RouterConfig.MaxReconfigureWait] is unset.
const defaultReconfigureWait = 100 * time.Millisecond

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

type Mux interface {
	LookupHandler(get Method, uri []byte) HandlerFunc
}

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
			err := r.awaitIdleExchangesLocked(10 * time.Millisecond)
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

// Handle is a extremely low-level HTTP handling method used internally in [Router].
// Requires exchange to be acquired and configured. Will panic if any argument is nil.
// Handle does not close the connection on any outcome: the caller owns it.
func Handle(exch *Exchange, mux Mux, backoff lneto.BackoffStrategy) error {
	reqhdr := &exch.reqHdr
	reqhdr.Reset(nil)
	var consecutiveBackoffs uint
	for {
		n, err := reqhdr.ReadFromLimited(exch.rw, reqhdr.BufferFree())
		if err != nil {
			exch.readErr = err
			return err
		} else if n == 0 {
			backoff.Do(consecutiveBackoffs)
			consecutiveBackoffs++
			continue
		}
		consecutiveBackoffs = 0
		const asRequest = false
		needMore, err := reqhdr.TryParse(asRequest)
		if needMore {
			continue // Request header split across reads, accumulate the rest.
		} else if err != nil {
			return err
		}
		break // Done!
	}
	// Setup Exchange fields necessary for correct functioning.
	parsed := reqhdr.BufferParsed()
	exch.respRemains = reqhdr.BufferReceived() - parsed
	exch.respHeaderOff = uint16(parsed)
	exch.respHeaderLen = 0
	if len(reqhdr.Protocol()) == 0 {
		// Request line with no HTTP version is a HTTP/0.9 simple-request, which
		// httpraw tolerates. It is not a valid HTTP/1.1 request-line, RFC 9112 3.
		exch.WriteHeader(int(StatusBadRequest))
		return errNoRequestProto
	}
	// Mux URI.
	uri := reqhdr.RequestURI()
	meth := reqhdr.Method()
	handler := mux.LookupHandler(MethodFromBytes(meth), uri)
	if handler != nil {
		handler(exch)
		exch.FlushHeader()
	} else {
		exch.WriteHeader(404)
	}
	// TODO write response from exchange here.
	return nil
}

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

// maxStatusLine bounds the response status line: "HTTP/1.1 " + 3 digit code +
// " " + longest [StatusText] + CRLF.
const maxStatusLine = len("HTTP/1.1 ") + 3 + 1 + len("Network Authentication Required") + 2

type Exchange struct {
	used           atomic.Bool
	respTopBuf     [maxStatusLine]byte
	respTopWritten uint8

	rawbuf        []byte
	respHeaderOff uint16
	respHeaderLen uint16
	reqHdr        httpraw.Header

	hijacked bool
	rw       conn

	respRemains   int
	respErr       error // Sticky: response is unrecoverable once a write fails.
	headerWritten bool
	normalizeKeys bool
	nextFree      *Exchange
	readErr       error
}

// HijackRaw is a low-level implementation of http.Hijacker interface.
// A Hijack method is not exposed due to heap allocation implications and correctness concerns.
// Below is what an actual implementation may look like:
//
//	func (exch *Exchange) Hijack() (net.Conn, *bufio.ReadWriter, error) {
//		conn, ok := exch.rw.(net.Conn)
//		if !ok {
//			return nil, nil, errors.New("net.Conn not implemented")
//		}
//		_, data, err := exch.HijackRaw(nil)
//		if err != nil {
//			return nil, nil, err
//		}
//		var rd *bufio.ReadWriter
//		if len(data) > 0 {
//			rd = &bufio.ReadWriter{Reader: bufio.NewReader(bytes.NewReader(data))}
//		}
//		return conn, rd, nil
//	}
func (exch *Exchange) HijackRaw(dstBody []byte) (conn, []byte, error) {
	data, err := exch.remainingSurplusBody()
	if err != nil {
		return nil, nil, err
	}
	exch.hijacked = true
	dstBody = append(dstBody, data...)
	return exch.rw, dstBody, nil
}

func (exch *Exchange) Configure(rawbuf []byte, requestLim int, normalizeKeys bool) {
	respSize := len(rawbuf) - requestLim
	if respSize < 0 {
		panic("request lim larger than buffer")
	}
	exch.rawbuf = rawbuf
	exch.reqHdr.Reset(rawbuf[:0:requestLim])
	exch.normalizeKeys = normalizeKeys
}

func (exch *Exchange) Acquire(conn conn) bool {
	if !exch.used.CompareAndSwap(false, true) {
		return false
	}
	exch.readErr = nil
	exch.respErr = nil
	exch.hijacked = false
	exch.respTopWritten = 0
	exch.respHeaderOff = 0
	exch.respHeaderLen = 0
	exch.respRemains = 0
	exch.rw = conn
	exch.headerWritten = false
	exch.nextFree = nil
	exch.reqHdr.Reset(nil)
	return true
}

func (exch *Exchange) Release() {
	if !exch.hijacked {
		exch.rw.Close()
	}
	exch.rw = nil
	exch.used.Store(false)
}

func (exch *Exchange) SetHeader(key, value string) (enoughMemory bool) {
	off := int(exch.respHeaderOff) + int(exch.respHeaderLen)
	free := len(exch.rawbuf) - off
	// Field costs key+':'+value+CRLF, plus the CRLF [Exchange.FlushHeader]
	// appends past the last field to close the header block.
	if len(key)+len(value)+len(":\r\n")+len("\r\n") > free {
		return false
	}
	n := copy(exch.rawbuf[off:], key)
	if exch.normalizeKeys {
		httpraw.NormalizeHeaderKey(exch.rawbuf[off : off+n])
	}
	exch.rawbuf[off+n] = ':'
	n++
	n += copy(exch.rawbuf[off+n:], value)
	exch.rawbuf[off+n] = '\r'
	exch.rawbuf[off+n+1] = '\n'
	n += 2
	exch.respHeaderLen += uint16(n)
	return true
}

func (exch *Exchange) StageWriteStatus(code int) {
	if code >= 1000 || exch.headerWritten {
		return
	} else if code == 200 {
		// Common case.
		exch.respTopWritten = uint8(copy(exch.respTopBuf[:], "HTTP/1.1 200 OK\r\n"))
		return
	}
	n := copy(exch.respTopBuf[:], "HTTP/1.1 ")
	n += len(strconv.AppendInt(exch.respTopBuf[n:n], int64(code), 10))
	text := StatusText(code)
	exch.respTopBuf[n] = ' '
	n++
	n += copy(exch.respTopBuf[n:], text)
	exch.respTopBuf[n] = '\r'
	exch.respTopBuf[n+1] = '\n'
	exch.respTopWritten = uint8(n + 2)
}

func (exch *Exchange) WriteHeader(code int) {
	if !exch.headerWritten {
		exch.StageWriteStatus(code)
		exch.FlushHeader()
	}
}
func (exch *Exchange) FlushHeader() (int, error) {
	if exch.respErr != nil {
		return 0, exch.respErr
	} else if exch.headerWritten {
		return 0, nil
	}
	if exch.respTopWritten == 0 {
		exch.StageWriteStatus(200)
	}
	exch.headerWritten = true
	ng, err := exch.rw.Write(exch.respTopBuf[:exch.respTopWritten])
	if err != nil {
		exch.respErr = err
		return ng, err
	}
	off := int(exch.respHeaderOff)
	headers := exch.rawbuf[off : off+int(exch.respHeaderLen)+2]
	headers[len(headers)-1] = '\n'
	headers[len(headers)-2] = '\r'
	ng2, err := exch.rw.Write(headers)
	exch.respErr = err
	return ng + ng2, err
}

func (exch *Exchange) Write(buf []byte) (int, error) {
	if exch.respErr != nil {
		return 0, exch.respErr
	} else if !exch.headerWritten {
		_, err := exch.FlushHeader()
		if err != nil {
			return 0, err // Body must not reach the wire without its header.
		}
	}
	if len(buf) == 0 {
		return 0, nil
	}
	n, err := exch.rw.Write(buf)
	exch.respErr = err
	return n, err
}

func (exch *Exchange) ReadBody(dst []byte) (n int, _ error) {
	if exch.respRemains > 0 {
		toRead, err := exch.remainingSurplusBody()
		if err != nil {
			return 0, err
		}
		n = copy(dst, toRead)
		exch.respRemains -= n
		if len(dst) == n {
			return n, nil
		}
		dst = dst[n:]
	}
	nr, err := exch.rw.Read(dst)
	return nr + n, err
}

func (exch *Exchange) remainingSurplusBody() ([]byte, error) {
	_, err := exch.reqHdr.Body()
	if err != nil {
		return nil, err // Returns mangled buffer error if request header has been misused.
	}
	surplus := exch.rawbuf[exch.reqHdr.BufferParsed():exch.reqHdr.BufferReceived()]
	toRead := surplus[len(surplus)-exch.respRemains:]
	return toRead, nil
}

func (exch *Exchange) RequestHeaderRaw() *httpraw.Header {
	return &exch.reqHdr
}

func (exch *Exchange) RequestParseCookie(dst *httpraw.Cookie, key string) error {
	value := exch.RequestHeader(key)
	return dst.ParseBytes(value)
}

func (exch *Exchange) RequestHeader(key string) []byte {
	header := exch.RequestHeaderRaw()
	return header.Get(key)
}

func (exch *Exchange) RequestURI() []byte {
	return exch.RequestHeaderRaw().RequestURI()
}

func (exch *Exchange) RequestMethod() []byte {
	return exch.RequestHeaderRaw().Method()
}

func (exch *Exchange) RequestConnectionClose() bool {
	return exch.RequestHeaderRaw().ConnectionClose()
}

type HandlerFunc func(ex *Exchange)

type Method uint8

const (
	MethUndefined Method = iota // undefined
	MethGet                     // GET
	// lol.
	MethHead // HEAD
	MethPost // POST
	MethPut  // PUT
	// RFC 5789
	MethPatch   // PATCH
	MethDelete  // DELETE
	MethConnect // CONNECT
	MethOptions // OPTIONS
	MethTrace   // TRACE
	MethUnknown // unknown
)

func MethodFromBytes(meth []byte) (res Method) {
	if len(meth) == 0 {
		return MethUndefined
	}
	switch unsafe.String(&meth[0], len(meth)) {
	case "GET":
		res = MethGet
	case "HEAD":
		res = MethHead
	case "POST":
		res = MethPost
	case "PUT":
		res = MethPut
	case "PATCH":
		res = MethPatch
	case "DELETE":
		res = MethDelete
	case "CONNECT":
		res = MethConnect
	case "OPTIONS":
		res = MethOptions
	case "TRACE":
		res = MethTrace
	default:
		res = MethUnknown
	}
	return res
}

// b2s converts byte slice to a string without memory allocation.
// See https://groups.google.com/forum/#!msg/Golang-Nuts/ENgbUzYvCuU/90yGx7GUAgAJ .
func b2s(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

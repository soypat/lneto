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

var errNoRequestProto = errors.New("httphi: request line with no HTTP version")

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
	Backoff               lneto.BackoffStrategy
	Mux                   Mux
	Logger                *slog.Logger
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
	r.gen.Add(1)
	if r.pendingConns != nil {
		close(r.pendingConns)
	}
}

func (r *Router) Configure(cfg RouterConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.TeardownGoroutines()
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
			// Previously existing goroutine manager, wait a bit for it to close.
			time.Sleep(5 * time.Millisecond)
		}
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

// Handle is a extremely low-level HTTP handling method used internally in [Router].
// Requires exchange to be acquired and configured. Will panic if any argument is nil.
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
		if !needMore && err == nil {
			// Done!
			break
		} else if err != nil {
			return err
		}
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
		exch.rw.Close()
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
	exch.rw.Close()
	return nil
}

func (r *Router) Handle(conn conn) error {
	exch := r.getExch(conn)
	if exch == nil {
		return lneto.ErrExhausted
	}

	if r.numGoro == 0 {
		go r.goroHandle(exch, r.backoff, r.mux)
		return nil
	}
	select {
	case r.pendingConns <- job{exch: exch}:
		return nil
	default:
		// pendingConns cannot store another Conn, we drop and return error.
		exch.used.Store(false) // release.
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
	if r.freeList == nil {
		r.freeList = exch
	} else {
		node := r.freeList
		depth := 0
		for depth < freelistMaxDepth && node.nextFree != nil {
			node = node.nextFree
			depth++
		}
		node.nextFree = exch
	}
	exch.Release()
	r.mu.Unlock()
}

func (r *Router) getExch(conn conn) (exch *Exchange) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.freeList != nil {
		if r.freeList.Acquire(conn) {
			exch = r.freeList
		}
		r.freeList = r.freeList.nextFree
	}
	if exch != nil {
		return exch
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
	rw            conn

	respRemains   int
	headerWritten bool
	normalizeKeys bool
	nextFree      *Exchange
	readErr       error
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
	exch.rw = nil
	exch.used.Store(false)
}

func (exch *Exchange) SetHeader(key, value string) (enoughMemory bool) {
	off := int(exch.respHeaderOff) + int(exch.respHeaderLen)
	free := len(exch.rawbuf) - off
	if len(key)+len(value)+2 > free {
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
	if exch.headerWritten {
		return 0, nil
	}
	if exch.respTopWritten == 0 {
		exch.StageWriteStatus(200)
	}
	exch.headerWritten = true
	ng, err := exch.rw.Write(exch.respTopBuf[:exch.respTopWritten])
	if err != nil {
		return ng, err
	}
	off := int(exch.respHeaderOff)
	headers := exch.rawbuf[off : off+int(exch.respHeaderLen)+2]
	headers[len(headers)-1] = '\n'
	headers[len(headers)-2] = '\r'
	ng2, err := exch.rw.Write(headers)
	return ng + ng2, err
}

func (exch *Exchange) Write(buf []byte) (int, error) {
	if !exch.headerWritten {
		exch.FlushHeader()
	}
	if len(buf) == 0 {
		return 0, nil
	}
	return exch.rw.Write(buf)
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

func (exch *Exchange) ReadBody(dst []byte) (n int, _ error) {
	if exch.respRemains > 0 {
		_, err := exch.reqHdr.Body()
		if err != nil {
			return 0, err // Returns mangled buffer error if request header has been misused.
		}
		surplus := exch.rawbuf[exch.reqHdr.BufferParsed():exch.reqHdr.BufferReceived()]
		toRead := surplus[len(surplus)-exch.respRemains:]
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

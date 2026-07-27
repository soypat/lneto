package httphi

import (
	"strings"
	"unsafe"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/http/httpraw"
	"github.com/soypat/lneto/internal"
)

// Handle is a extremely low-level HTTP handling method used internally in [Router].
// Requires exchange to be acquired and configured. Will panic if any argument is nil.
// Handle does not close the connection on any outcome: the caller owns it.
func Handle(exch *Exchange, mux Mux, backoff lneto.BackoffStrategy) error {
	reqhdr := &exch.reqHdr
	reqhdr.Reset(nil, 0) // Assume exchange has been configured and reuse memory.
	var consecutiveBackoffs uint
	for {
		n, err := reqhdr.ReadFromLimited(exch.rw, reqhdr.BufferFree())
		if err != nil {
			exch.readErr = err
			exch.handleError(err)
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
			exch.handleError(err)
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
	// Mux on the request path: the query string is the handler's business.
	path := reqhdr.RequestPath()
	meth := reqhdr.Method()
	matchedPattern, handler := mux.LookupHandler(MethodFromBytes(meth), b2s(path))
	if handler != nil {
		exch.matchedPattern = matchedPattern
		handler(exch)
		exch.FlushHeader()
	} else {
		exch.WriteHeader(404)
	}
	// TODO write response from exchange here.
	return nil
}

func (exch *Exchange) handleError(err error) {
	if err == httpraw.ErrHeaderTooMany || err == httpraw.ErrSmallHeaderBuffer || exch.reqHdr.BufferFree() == 0 {
		// The peer is owed an answer: no larger buffer is coming, so
		// say so instead of dropping the connection, RFC 6585 5.
		exch.StageHeader("Content-Length", "0")
		exch.WriteHeader(int(StatusRequestHeaderFieldsTooLarge))
	}
}

// HandlerFunc serves a single request, playing the part of http.Handler.
// The exchange is only valid for the duration of the call: it is released to
// the router's pool on return, so a handler must not retain it nor any slice it
// handed out.
type HandlerFunc func(ex *Exchange)

// Mux resolves a request to the handler that serves it. [Handle] calls
// LookupHandler with the request-target's path, not the whole target, and
// replies 404 when it returns nil.
type Mux interface {
	// LookupHandler matches the requestPath and method to a handler and returns it and the
	// pattern it matched.
	LookupHandler(get Method, requestPath string) (matchedPattern string, handler HandlerFunc)
}

// MuxSlice is a [Mux] backed by a slice of registered endpoints, matched by
// exact path. Lookup is linear in the number of registrations.
type MuxSlice struct {
	// TODO: binary search worth it?
	_handlers []struct {
		method  Method
		path    string
		handler HandlerFunc
	}
}

// Reset discards all registered handlers, reusing the backing array and growing
// it to fit capacity registrations.
func (sm *MuxSlice) Reset(capacity int) {
	internal.SliceReuse(&sm._handlers, capacity)
}

// LookupHandler returns the handler registered for request path, or nil if none matches.
// The first registration matching both method and uri wins.
func (sm *MuxSlice) LookupHandler(method Method, path string) (matched string, _ HandlerFunc) {
	for _, endpoint := range sm._handlers {
		if endpoint.method != MethUndefined && endpoint.method != method {
			continue
		}
		// Method matches.
		if path == endpoint.path {
			return endpoint.path, endpoint.handler
		}
	}
	return "", nil
}

// Handle registers handler for reg, either a bare path matching any method or a
// method and path separated by a space, i.e: "/health" or "GET /health".
// Handle does not check for duplicate registrations: the first one added wins.
func (sm *MuxSlice) Handle(optMethodAndPath string, handler HandlerFunc) {
	v := internal.SliceReclaim(&sm._handlers)
	method := MethUndefined
	methodOrURL, url, methodFound := strings.Cut(optMethodAndPath, " ")
	if methodFound {
		method = MethodFrom(methodOrURL)
	} else {
		url = methodOrURL
	}
	v.method = method
	v.path = url
	v.handler = handler
}

// Method is a HTTP request method, parsed by [MethodFrom].
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

// MethodFrom returns the [Method] matching meth, [MethUndefined] if meth is
// empty and [MethUnknown] if it names a method this package does not know.
// Comparison is case sensitive: methods are uppercase, RFC 9110 9.1.
func MethodFrom(meth string) (res Method) {
	if len(meth) == 0 {
		return MethUndefined
	}
	switch meth {
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

// MethodFromBytes is a [MethodFrom] wrapper with bytes argument instead of string.
func MethodFromBytes(meth []byte) (res Method) {
	if len(meth) == 0 {
		return MethUndefined
	}
	return MethodFrom(b2s(meth))
}

// b2s converts byte slice to a string without memory allocation.
// See https://groups.google.com/forum/#!msg/Golang-Nuts/ENgbUzYvCuU/90yGx7GUAgAJ .
func b2s(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

package httphi

import (
	"bytes"
	"io"
	"strings"
	"unsafe"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/http/httpraw"
	"github.com/soypat/lneto/internal"
)

// Handle is a extremely low-level HTTP handling method used internally in [Router].
// Requires exchange to be acquired and configured. Will panic if any argument is nil.
// Handle does not close the connection on any outcome: the caller owns it.
// backoff can be set for dealing with non-blocking connections. If backoff set to nil
// then a zero-length-read will result in Handle returning [io.ErrNoProgress].
func Handle(exch *Exchange, mux Mux, backoff lneto.BackoffStrategy) error {
	if !exch.acquired.Load() {
		return lneto.ErrBadState
	}
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
			if backoff == nil {
				return io.ErrNoProgress
			}
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
	proto := b2s(reqhdr.Protocol())
	if len(proto) == 0 {
		// HTTP/0.9 not tolerated RFC 9112 3.
		exch.WriteHeader(int(StatusBadRequest))
		return errNoRequestProto
	} else if proto != "HTTP/1.1" && proto != "HTTP/1.0" {
		// RFC 9112 2.6.
		exch.WriteHeader(int(StatusHTTPVersionNotSupported))
		return errBadRequestProto
	}
	// Mux on the request path: the query string is the handler's business.
	path := reqhdr.RequestPath()
	meth := reqhdr.Method()
	clear(exch.pathValues)
	matchedPattern, handler := mux.LookupHandler(MethodFromBytes(meth), path, exch.pathValues)
	if handler != nil {
		exch.matchedPattern = matchedPattern
		handler(exch)
		if !exch.hijacked {
			exch.FlushHeader()
		}
	} else {
		exch.WriteHeader(404)
	}
	return nil
}

func (exch *Exchange) handleError(err error) {
	if err == lneto.ErrUnsupported {
		// httpraw refused a first line naming a version it does not speak, before
		// spending the field loop on it. An empty protocol is a HTTP/0.9
		// simple-request, RFC 9112 3: a malformed 1.x request-line rather than a
		// version there is any point naming back.
		if len(exch.reqHdr.Protocol()) == 0 {
			exch.WriteHeader(int(StatusBadRequest))
		} else {
			exch.WriteHeader(int(StatusHTTPVersionNotSupported))
		}
		return
	}
	if err == httpraw.ErrHeaderTooMany || err == httpraw.ErrBufferExhausted || exch.reqHdr.BufferFree() == 0 {
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
	// pattern it matched. dstPathVals are set to non-zero values by Mux and can later be accessed by [Exchange.PathValue]
	// requestPath is a buffer owned by the [Exchange] usually and should not be held after LookupHandler returns.
	LookupHandler(get Method, requestPath []byte, dstPathVals []PathValue) (matchedPattern string, handler HandlerFunc)
	// MaxPathValues specifies the required size of dstPathVals in a call to [Mux.LookupHandler].
	// MaxPathValues should return -1 if no paths have been configured to catch situation
	// where the Mux has been passed to a [Router.Configuration] before registering paths.
	MaxPathValues() int
}

// PathValue used to implement [Mux] interface. Stores http.Request.PathValue-like values.
type PathValue struct {
	Key   string // owned by mux.
	Value []byte // points to raw exchange buffer.
}

// pathSeparator is shared so [SetPathValues] never converts a literal per call.
var pathSeparator = []byte{'/'}

// SetPathValues matches requestPath against pattern and binds its wildcards
// into dstPathVals, read back with [Exchange.PathValue]. Wildcards are whole
// segments as per http.ServeMux: "{name}" takes one non-empty segment,
// "{name...}" the rest including slashes, "{$}" only the path's end, and a
// trailing slash is an anonymous "{...}". i.e: "/b/{bucket}/o/{obj...}".
//
// Unlike ServeMux, segments are compared and bound raw, so "/users/{id}" binds
// "x%2Fy" and not "x/y". Which paths match is unaffected. Bound values alias
// requestPath rather than copy it.
//
// Values are bound while walking, before the match is known, so on failure
// SetPathValues clears what it bound. A [Mux] may then try patterns in turn
// without a matching one inheriting values from one that failed.
func SetPathValues(dstPathVals []PathValue, pattern string, requestPath []byte) (matched, pathValSliceTooShort bool) {
	n, matched, pathValSliceTooShort := setPathValues(dstPathVals, pattern, requestPath)
	if !matched {
		clear(dstPathVals[:n])
	}
	return matched, pathValSliceTooShort
}

// setPathValues is [SetPathValues] reporting how many values it bound, so its
// caller can discard them when the pattern turns out not to match.
func setPathValues(dstPathVals []PathValue, pattern string, requestPath []byte) (n int, matched, pathValSliceTooShort bool) {
	if len(pattern) == 0 || pattern[0] != '/' || len(requestPath) == 0 || requestPath[0] != '/' {
		return n, false, false
	}
	pattern, requestPath = pattern[1:], requestPath[1:]
	for {
		if len(pattern) == 0 {
			// Nothing left after a slash: an anonymous "..." taking the rest,
			// which is why "/files/" matches "/files/a/b" and "/" matches all.
			return n, true, false
		}
		patSeg, patRest, patMore := strings.Cut(pattern, "/")
		reqSeg, reqRest, reqMore := bytes.Cut(requestPath, pathSeparator)
		name, isMulti, isWildcard := pathWildcard(patSeg)
		switch {
		case isWildcard && name == "$":
			// Matches the end of the path and nothing else, so it must be the
			// last segment of the pattern and leave no path behind.
			return n, !patMore && len(requestPath) == 0, false

		case isWildcard && isMulti:
			// Takes the remainder including slashes, possibly empty.
			if name != "" {
				if n >= len(dstPathVals) {
					return n, false, true
				}
				dstPathVals[n] = PathValue{Key: name, Value: requestPath}
				n++
			}
			return n, true, false

		case isWildcard:
			if len(reqSeg) == 0 {
				return n, false, false // One segment means a non-empty one.
			}
			if n >= len(dstPathVals) {
				return n, false, true
			}
			dstPathVals[n] = PathValue{Key: name, Value: reqSeg}
			n++

		default:
			if b2s(reqSeg) != patSeg {
				return n, false, false
			}
		}
		if patMore != reqMore {
			// One side has a further segment and the other does not, so
			// "/health" misses "/health/" and "/files/" misses "/files".
			return n, false, false
		} else if !patMore {
			return n, true, false // Both spent on the same segment.
		}
		pattern, requestPath = patRest, reqRest
	}
}

// pathWildcard picks apart a "{name}" or "{name...}" pattern segment. It
// reports ok false for a literal segment, so "/b_{bucket}" is literal text and
// not a wildcard, matching ServeMux's rule that wildcards be whole segments.
func pathWildcard(segment string) (name string, isMulti, ok bool) {
	if len(segment) < 2 || segment[0] != '{' || segment[len(segment)-1] != '}' {
		return "", false, false
	}
	name = segment[1 : len(segment)-1]
	if rest, found := strings.CutSuffix(name, "..."); found {
		return rest, true, true
	}
	return name, false, true
}

// MuxSlice is a [Mux] implementation backed by a slice of registered endpoints, matched by
// exact path. Lookup is linear in the number of registrations.
type MuxSlice struct {
	// TODO: binary search worth it?
	_handlers []struct {
		method   Method
		path     string
		handler  HandlerFunc
		pathVals int
		spec     int
	}
}

// Reset discards all registered handlers, reusing the backing array and growing
// it to fit capacity registrations.
func (sm *MuxSlice) Reset(capacity int) {
	internal.SliceReuse(&sm._handlers, capacity)
}

// LookupHandler returns the handler registered for request path, or nil if none
// matches. The most specific matching registration wins, not the first, so the
// catch-all "/" may be registered alongside the endpoints it backs without
// shadowing them, as in http.ServeMux, see [patternSpecificity]. Registrations
// of equal specificity are resolved in registration order.
//
// Every method this package does not name is [MethUnknown], so a request with an
// extension method matches a bare-path registration and any registration naming
// an extension method, whichever it names. Tell PROPFIND from MKCOL inside the
// handler with [Exchange.RequestMethodRaw].
func (sm *MuxSlice) LookupHandler(method Method, path []byte, dstPathVals []PathValue) (matched string, _ HandlerFunc) {
	best := -1
	bestSpec := 0
	for i, endpoint := range sm._handlers {
		if endpoint.method != MethUndefined && endpoint.method != method {
			continue
		} else if best >= 0 && endpoint.spec <= bestSpec {
			continue // Cannot beat the incumbent, so do not pay to match it.
		}
		// Method matches. A pattern ending in '/' is a wildcard despite binding no
		// values: the trailing slash is an anonymous "{...}", so it must go
		// through the matcher and not a literal compare, see [SetPathValues].
		var ok bool
		if isWildcardPattern(endpoint.path) {
			// dstPathVals is scratch during the scan: a candidate that matches and
			// is then beaten, or one that is beaten and clears on failure, would
			// leave the winner's values wrong, so the winner is bound below.
			ok, _ = SetPathValues(dstPathVals, endpoint.path, path)
		} else {
			ok = b2s(path) == endpoint.path
		}
		if ok {
			best, bestSpec = i, endpoint.spec
		}
	}
	if best < 0 {
		return "", nil
	}
	winner := sm._handlers[best]
	if isWildcardPattern(winner.path) {
		clear(dstPathVals) // The scan may have bound more values than the winner does.
		SetPathValues(dstPathVals, winner.path, path)
	}
	return winner.path, winner.handler
}

// MaxPathValues returns the maximum number of path values any endpoint could have.
func (sm *MuxSlice) MaxPathValues() (maxPathValues int) {
	if len(sm._handlers) == 0 {
		return -1 // Signal no handlers registered.
	}
	for _, endpoint := range sm._handlers {
		maxPathValues = max(maxPathValues, endpoint.pathVals)
	}
	return maxPathValues
}

// Handle registers handler for reg, either a bare path matching any method or a
// method and path separated by a space, i.e: "/health" or "GET /health".
//
// Handle panics on a registration that could never serve a request: a method
// token carrying lowercase (methods are case sensitive and uppercase, RFC 9110
// 9.1, so "Get" matches no GET request), a path not rooted at '/', or an exact
// duplicate of an earlier registration, which the first one always shadows.
// Registration is program startup, so a fault belongs there and not in a
// permanent silent 404.
func (sm *MuxSlice) Handle(optMethodAndPath string, handler HandlerFunc) {
	method := MethUndefined
	methodOrURL, url, methodFound := strings.Cut(optMethodAndPath, " ")
	if methodFound {
		if hasLowerASCII(methodOrURL) {
			panic("httphi: method must be uppercase in registration " + optMethodAndPath)
		}
		method = MethodFrom(methodOrURL)
	} else {
		url = methodOrURL
	}
	if len(url) == 0 || url[0] != '/' {
		panic("httphi: path must begin with '/' in registration " + optMethodAndPath)
	}
	for _, endpoint := range sm._handlers {
		if endpoint.method == method && endpoint.path == url {
			if method == MethUnknown {
				// Two extension methods are both MethUnknown, so the second is
				// unreachable. Register one and branch in the handler, see
				// [MuxSlice.LookupHandler].
				panic("httphi: extension method already registered on path in " + optMethodAndPath)
			}
			panic("httphi: duplicate registration " + optMethodAndPath)
		}
	}
	v := internal.SliceReclaim(&sm._handlers)
	v.pathVals = countPathValues(url)
	v.spec = patternSpecificity(url)
	v.method = method
	v.path = url
	v.handler = handler
}

// patternSpecificity scores how tightly pattern pins a path, letting
// [MuxSlice.LookupHandler] prefer the most specific match over the first one
// registered. A literal segment pins harder than a wildcard segment, and a
// pattern left open at the end ("/", "/files/", "/{p...}") pins less than one
// spent on the whole path, so "/cnt" outscores "/" and "/users/me" outscores
// "/users/{id}". Scoring at registration keeps lookup to an integer compare.
//
// The score is a total order over patterns, which the subset relation is not:
// neither of "/a/{x}/c" and "/a/b/{y}" is more specific than the other, and they
// tie here where http.ServeMux rejects the pair as conflicting. A tie is settled
// by registration order rather than by a panic.
func patternSpecificity(pattern string) (spec int) {
	if len(pattern) == 0 || pattern[0] != '/' {
		return 0
	}
	pattern = pattern[1:]
	for {
		if len(pattern) == 0 {
			return spec // Nothing after a slash: an anonymous "{...}" taking the rest.
		}
		segment, rest, more := strings.Cut(pattern, "/")
		name, isMulti, isWildcard := pathWildcard(segment)
		switch {
		case isWildcard && name == "$":
			return spec + 1 // Ends the path, so nothing is left open.
		case isWildcard && isMulti:
			return spec // Takes the remainder, pinning nothing more.
		case isWildcard:
			spec++
		default:
			spec += 2
		}
		if !more {
			return spec + 1 // Spent on the last segment: the pattern is exact.
		}
		pattern = rest
	}
}

// countPathValues is how many values pattern can bind, which is what sizes the
// slice [SetPathValues] writes into. Only a named wildcard segment binds: "{$}"
// marks the path's end, an anonymous "{...}" has no name to bind under, and a
// brace inside a literal segment is not a wildcard at all.
func countPathValues(pattern string) (n int) {
	if len(pattern) == 0 || pattern[0] != '/' {
		return 0
	}
	pattern = pattern[1:]
	for len(pattern) > 0 {
		segment, rest, more := strings.Cut(pattern, "/")
		if name, _, ok := pathWildcard(segment); ok && name != "" && name != "$" {
			n++
		}
		if !more {
			break
		}
		pattern = rest
	}
	return n
}

// isWildcardPattern reports whether pattern must go through [SetPathValues]
// rather than a literal comparison. Distinct from the value count: "{$}" and a
// trailing slash match by walking segments while binding nothing.
func isWildcardPattern(pattern string) bool {
	return strings.IndexByte(pattern, '{') >= 0 || strings.HasSuffix(pattern, "/")
}

// hasLowerASCII reports whether s carries an ASCII lowercase letter, which a
// method token registered by mistake ("Get") does and a legal extension method
// ("PROPFIND") does not.
func hasLowerASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'a' && s[i] <= 'z' {
			return true
		}
	}
	return false
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

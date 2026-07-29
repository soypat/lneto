package httphi

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/soypat/lneto/http/httpraw"
)

// Fuzz targets in this file are written so that a stored corpus keeps its
// meaning as the tests grow. Go's corpus files are positional and typed, so an
// input is only reproducible while the code that decodes it stays fixed. Five
// rules keep that true, and edits to this file must obey them:
//
//  1. A target's signature is frozen: func(t *testing.T, ctrl uint64, data []byte).
//     Adding, removing or reordering a parameter invalidates every stored entry.
//  2. Control decisions come from ctrl only, wire bytes from data only. Never
//     branch on data, never put payload in ctrl: the two axes mutate apart.
//  3. ctrl is a bit field read through absolute shifts and masks named below.
//     New knobs claim unused high bits and are only ever appended, never
//     renumbered, and the zero value of a knob must decode to the behaviour that
//     existed before it was added, so old entries keep replaying as they did.
//  4. No PRNG, no cursor. No rand, no internal.Prand64, and no helper that
//     "reads the next N bits" while advancing a position: inserting one draw
//     ahead of another shifts every later decision, which is the same corpus
//     invalidation a PRNG causes.
//  5. Nothing ambient: no wall clock, no goroutines, no map iteration order.
//     Targets drive [Handle] on the calling goroutine; [Router] is not fuzzed
//     here precisely because it serves on goroutines of its own.
const (
	// Bits 0..3 index segSizes: how the request is split across reads.
	ctlSegShift, ctlSegMask = 0, 0xf
	// Bits 4..7 and 8..11 size the request and response halves of the buffer.
	ctlReqBufShift, ctlRespBufShift, ctlBufMask = 4, 8, 0xf
	// Bits 12..13 size the request header field table.
	ctlKVCapShift, ctlKVCapMask = 12, 0x3
	// Bit 14 normalizes outgoing header keys.
	ctlNormalizeShift, ctlNormalizeMask = 14, 0x1
	// Bits 15..16 make that many leading writes to the connection fail.
	ctlFailWriteShift, ctlFailWriteMask = 15, 0x3
	// Bits 17..20 select what the handler does, see the op constants.
	ctlHandlerOpsShift, ctlHandlerOpsMask = 17, 0xf
	// Bits 21..23 count the header fields the handler stages.
	ctlStageCountShift, ctlStageCountMask = 21, 0x7
	// Bit 24 asks AppendQuery for decoded values.
	ctlDecodeShift, ctlDecodeMask = 24, 0x1
	// Bits 25..28 size the scratch buffer handed to form and multipart parsing.
	ctlScratchShift, ctlScratchMask = 25, 0xf
	// Bit 29 makes the multipart sink discard part content.
	ctlDiscardShift, ctlDiscardMask = 29, 0x1
	// Next knob starts at bit 30.
)

// Handler operations, selected by the ctlHandlerOps field. Values are frozen:
// a new operation takes the next free bit within the field.
const (
	opStageHeaders = 1 << iota
	opReadBody
	opWriteBody
	opHijack
)

// segSizes are the chunk sizes a request may be delivered in, index 0 meaning
// "all at once". Splitting a request mid-CRLF or before a colon is what drives
// [httpraw.Header.TryParse]'s resumption path. Entries may be appended, never
// changed: an existing index must keep splitting exactly as it does today.
var segSizes = [16]int{0, 1, 2, 3, 5, 7, 11, 16, 23, 37, 64, 101, 173, 256, 509, 1024}

// ctlField reads a knob out of ctrl. Absolute shift, no cursor, so knobs are
// independent of one another and of the order they are read in.
func ctlField(ctrl uint64, shift, mask uint64) uint64 {
	return (ctrl >> shift) & mask
}

// maxFuzzInput bounds the wire data a target accepts. The filter depends only
// on the input, so it classifies an entry the same way on every run.
const maxFuzzInput = 16 << 10

// fuzzExchange returns an exchange acquired on a connection preloaded with data,
// both sized and segmented by ctrl.
func fuzzExchange(t *testing.T, ctrl uint64, data []byte) (*Exchange, *rwconn) {
	t.Helper()
	reqBuf := minRequestHeaderBuffer + int(ctlField(ctrl, ctlReqBufShift, ctlBufMask))*8
	respBuf := minResponseHeaderBuffer + int(ctlField(ctrl, ctlRespBufShift, ctlBufMask))*8
	kvCap := 1 + int(ctlField(ctrl, ctlKVCapShift, ctlKVCapMask))*8

	conn := newConn("")
	seg := segSizes[ctlField(ctrl, ctlSegShift, ctlSegMask)]
	if seg <= 0 || seg >= len(data) {
		conn.AddReadable(data)
	} else {
		for off := 0; off < len(data); off += seg {
			conn.AddSegment(string(data[off:min(off+seg, len(data))]))
		}
	}
	// Always hang up: a drained connection that never reports EOF reads (0,nil)
	// forever and [Handle] would back off in an unbounded loop.
	conn.Hangup()
	if n := ctlField(ctrl, ctlFailWriteShift, ctlFailWriteMask); n > 0 {
		conn.FailWrites(int(n))
	}
	exch := newExchange(t, conn, ExchangeConfig{
		RawBuf:                make([]byte, reqBuf+respBuf),
		RequestBufferLim:      reqBuf,
		NumHeaderKVCap:        kvCap,
		NormalizeOutgoingKeys: ctlField(ctrl, ctlNormalizeShift, ctlNormalizeMask) != 0,
		NoRequestBufferGrowth: true,
	})
	return exch, conn
}

// checkRequestView asserts the request-target views agree with one another.
func checkRequestView(t *testing.T, exch *Exchange) {
	t.Helper()
	target, path, query := exch.RequestTarget(), exch.RequestPath(), exch.RequestQuery()
	if !bytes.HasPrefix(target, path) {
		t.Fatalf("path %q is not a prefix of target %q", path, target)
	}
	if len(query) > 0 && !bytes.HasSuffix(target, query) {
		t.Fatalf("query %q is not a suffix of target %q", query, target)
	}
	if len(path)+len(query) > len(target) {
		t.Fatalf("path %q and query %q exceed target %q", path, query, target)
	}
}

// checkResponse asserts that whatever reached the wire is a response a peer
// could parse: a status line this package produced, followed by a header block
// that terminates, and that [httpraw] reads back what it wrote.
func checkResponse(t *testing.T, written string) {
	t.Helper()
	if written == "" {
		return // Hijacked, or a request refused before anything was staged.
	}
	const proto = "HTTP/1.1 "
	if !strings.HasPrefix(written, proto) {
		t.Fatalf("response does not open with a status line: %q", written)
	}
	if len(written) < len(proto)+4 {
		t.Fatalf("status line truncated: %q", written)
	}
	for _, c := range []byte(written[len(proto) : len(proto)+3]) {
		if c < '0' || c > '9' {
			t.Fatalf("status code is not three digits: %q", written)
		}
	}
	if written[len(proto)+3] != ' ' {
		t.Fatalf("status code not followed by a space: %q", written)
	}
	if !strings.Contains(written, "\r\n\r\n") {
		t.Fatalf("header block never terminated: %q", written)
	}
	var resp httpraw.Header
	const asResponse = true
	if err := resp.ParseBytes(asResponse, []byte(written)); err != nil {
		t.Fatalf("response does not parse back: %s in %q", err, written)
	}
}

// handler2Path is a second registration so lookup does not always match on the
// first entry of the mux.
const handler2Path = "/fuzz"

// fuzzMux returns a mux serving handler on the paths the seed corpus requests.
func fuzzMux(handler HandlerFunc) *MuxSlice {
	var mux MuxSlice
	mux.Handle("/", handler)
	mux.Handle(handler2Path, handler)
	return &mux
}

// FuzzHandleRequest drives a whole exchange: a request off the wire through
// [Handle], a handler staging and writing a response, and back out to the peer.
func FuzzHandleRequest(f *testing.F) {
	addSeeds(f)
	f.Fuzz(func(t *testing.T, ctrl uint64, data []byte) {
		if len(data) > maxFuzzInput {
			return
		}
		exch, conn := fuzzExchange(t, ctrl, data)
		ops := ctlField(ctrl, ctlHandlerOpsShift, ctlHandlerOpsMask)
		stage := ctlField(ctrl, ctlStageCountShift, ctlStageCountMask)

		Handle(exch, fuzzMux(func(exch *Exchange) {
			checkRequestView(t, exch)
			if ops&opStageHeaders != 0 {
				// Literal fields: staging request bytes would test the caller's
				// escaping, not this package's framing.
				for i := range stage {
					exch.StageHeader("X-Fuzz", "value")
					exch.StageHeaderInt("X-Fuzz-Int", int64(i), 10)
				}
			}
			if ops&opReadBody != 0 {
				var body [64]byte
				for range 64 {
					n, err := exch.ReadBody(body[:])
					if n == 0 && err != nil {
						break
					}
				}
			}
			if ops&opWriteBody != 0 {
				exch.WriteBody([]byte("fuzz body"))
			}
			if ops&opHijack != 0 {
				exch.HijackRaw(nil)
			}
		}), nopBackoff)

		if ctlField(ctrl, ctlFailWriteShift, ctlFailWriteMask) == 0 {
			// A refused write leaves a partial response on purpose, so the
			// wire is only well formed when every write got through.
			checkResponse(t, conn.ViewWritten())
		}
	})
}

// FuzzQueryAndForm drives the request-target query and the form-encoded body,
// both of which decode percent escapes in place over caller memory.
func FuzzQueryAndForm(f *testing.F) {
	addSeeds(f)
	f.Fuzz(func(t *testing.T, ctrl uint64, data []byte) {
		if len(data) > maxFuzzInput {
			return
		}
		exch, _ := fuzzExchange(t, ctrl, data)
		decoded := ctlField(ctrl, ctlDecodeShift, ctlDecodeMask) != 0
		scratchLen := 8 + int(ctlField(ctrl, ctlScratchShift, ctlScratchMask))*16

		Handle(exch, fuzzMux(func(exch *Exchange) {
			// Every pair the iterator yields must be reachable by name, or the
			// two views of the query string disagree.
			const maxPairs = 64
			key, _, rest := httpraw.NextQueryPair(exch.RequestQuery())
			for pairs := 0; key != nil && pairs < maxPairs; pairs++ {
				dec := make([]byte, len(key))
				n, err := httpraw.CopyDecodedPercentURL(dec, key, true)
				if err == nil {
					if n > len(key) {
						t.Fatalf("decoding key %q grew it to %d bytes", key, n)
					}
					if _, present := exch.AppendQuery(nil, string(dec[:n]), decoded); !present {
						t.Fatalf("query pair %q absent from AppendQuery", key)
					}
				}
				key, _, rest = httpraw.NextQueryPair(rest)
			}

			var form httpraw.Form
			buf := make([]byte, scratchLen)
			if err := exch.RequestParseForm(&form, buf); err != nil {
				return
			}
			total := 0
			lens := make([]int, form.Len())
			for i := range form.Len() {
				k, v := form.Pair(i)
				lens[i] = len(k) + len(v)
				total += lens[i]
			}
			if total > len(buf) {
				t.Fatalf("form pairs span %d bytes of a %d byte buffer", total, len(buf))
			}
			if err := form.Decode(); err != nil {
				return
			}
			// Decoding replaces escapes in place, so no pair may grow.
			for i := range form.Len() {
				k, v := form.Pair(i)
				if len(k)+len(v) > lens[i] {
					t.Fatalf("pair %d grew from %d to %d bytes on decode", i, lens[i], len(k)+len(v))
				}
			}
		}), nopBackoff)
	})
}

// countSink counts what a multipart part streamed into it and whether the part
// was closed off.
type countSink struct {
	written int
	closed  bool
}

func (c *countSink) Write(b []byte) (int, error) {
	c.written += len(b)
	return len(b), nil
}

func (c *countSink) Close() error {
	c.closed = true
	return nil
}

// FuzzMultipart drives [Exchange.ReadMultiparts], which streams a body of
// unknown length through a buffer the caller sized.
func FuzzMultipart(f *testing.F) {
	addSeeds(f)
	f.Fuzz(func(t *testing.T, ctrl uint64, data []byte) {
		if len(data) > maxFuzzInput {
			return
		}
		exch, _ := fuzzExchange(t, ctrl, data)
		discard := ctlField(ctrl, ctlDiscardShift, ctlDiscardMask) != 0
		bufLen := 16 + int(ctlField(ctrl, ctlScratchShift, ctlScratchMask))*16

		Handle(exch, fuzzMux(func(exch *Exchange) {
			var sinks []*countSink
			_, err := exch.ReadMultiparts(nil, make([]byte, bufLen), func(hdr *httpraw.MultipartHeader) io.WriteCloser {
				if discard {
					return nil
				}
				sink := new(countSink)
				sinks = append(sinks, sink)
				return sink
			})
			if err != nil {
				return // Sinks are left for the caller to deal with on error.
			}
			total := 0
			for _, sink := range sinks {
				if !sink.closed {
					t.Fatal("ReadMultiparts returned with a part left open")
				}
				total += sink.written
			}
			if total > len(data) {
				t.Fatalf("parts streamed %d bytes out of a %d byte request", total, len(data))
			}
		}), nopBackoff)
	})
}

// addSeeds adds the shared seed corpus. Every seed pins ctrl to zero so its
// meaning never moves: knobs added later decode their zero value to the
// behaviour the seed was recorded under.
func addSeeds(f *testing.F) {
	f.Helper()
	const (
		formType = "Content-Type: application/x-www-form-urlencoded\r\n"
		mpType   = "Content-Type: multipart/form-data; boundary=b0undary\r\n"
	)
	seeds := []string{
		// Well formed traffic, so the fuzzer has somewhere to mutate from.
		"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
		"GET /fuzz?q=go&n=1 HTTP/1.1\r\nHost: h\r\n\r\n",
		"POST /fuzz HTTP/1.1\r\nHost: h\r\n" + formType + "Content-Length: 11\r\n\r\na=1&b=2&c=3",
		"POST /fuzz HTTP/1.1\r\nHost: h\r\n" + mpType + "Content-Length: 76\r\n\r\n--b0undary\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nbody\r\n--b0undary--\r\n",

		// Framing the RFC leaves room to disagree over, which is where request
		// smuggling lives: two lengths, a length plus a coding, and a coding
		// this package does not decode.
		"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd",
		"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n",

		// Field names are case insensitive, RFC 9110 5.1, so a lookup that
		// misses one of these reads the request differently than the peer wrote it.
		"POST / HTTP/1.1\r\nHost: h\r\ncontent-length: 4\r\n\r\nbody",
		"POST / HTTP/1.1\r\nHost: h\r\nCONTENT-LENGTH: 4\r\n\r\nbody",
		"POST /fuzz HTTP/1.1\r\nHost: h\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 3\r\n\r\na=1",

		// Content-Length values that are not a bare digit string, RFC 9112 6.2.
		"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: +5\r\n\r\nbody!",
		"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: -1\r\n\r\nbody",
		"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 1 2\r\n\r\nbody",
		"POST / HTTP/1.1\r\nHost: h\r\nContent-Length:\r\n\r\nbody",
		"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 9223372036854775808\r\n\r\nbody",

		// Line ending and field syntax edges.
		"GET / HTTP/1.1\nHost: h\n\n",
		"GET / HTTP/1.1\r\nHost: h\rX: y\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: h\r\n Continued: fold\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: h\r\nX: va\x00lue\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: h\r\nNoColon\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: h\r\n: novalue\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: h\r\nX:\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: h\r\n\r\n\r\n",

		// Request lines this package tolerates or must refuse.
		"GET http://h/abs HTTP/1.1\r\nHost: h\r\n\r\n",
		"GET /\r\n\r\n", // HTTP/0.9 simple request, no version.
		" GET / HTTP/1.1\r\nHost: h\r\n\r\n",
		"GET  / HTTP/1.1\r\nHost: h\r\n\r\n",
		"/ HTTP/1.1\r\nHost: h\r\n\r\n",
		"GET / HTTP/9.9\r\nHost: h\r\n\r\n",

		// Percent escapes, including the truncated and the malformed.
		"GET /a%20b?a%20b=c%20d HTTP/1.1\r\nHost: h\r\n\r\n",
		"GET /?q=%2 HTTP/1.1\r\nHost: h\r\n\r\n",
		"GET /?q=%zz HTTP/1.1\r\nHost: h\r\n\r\n",
		"GET /%00?a=%00 HTTP/1.1\r\nHost: h\r\n\r\n",
		"GET /?a=b=c&&=v&debug HTTP/1.1\r\nHost: h\r\n\r\n",
		"GET /?a%3db=1&a+b=2 HTTP/1.1\r\nHost: h\r\n\r\n",

		// Multipart bodies that end early or never open a part.
		"POST /fuzz HTTP/1.1\r\nHost: h\r\n" + mpType + "Content-Length: 12\r\n\r\n--b0undary\r\n",
		"POST /fuzz HTTP/1.1\r\nHost: h\r\n" + mpType + "Content-Length: 14\r\n\r\n--b0undary--\r\n",
		"POST /fuzz HTTP/1.1\r\nHost: h\r\nContent-Type: multipart/form-data\r\nContent-Length: 4\r\n\r\nbody",

		// Sizes that crowd the buffers: a long target, many fields, and a body
		// arriving in the same read as the header it follows.
		"GET /" + strings.Repeat("a", 512) + " HTTP/1.1\r\nHost: h\r\n\r\n",
		"GET / HTTP/1.1\r\n" + strings.Repeat("X: y\r\n", 200) + "\r\n",
		"GET / HTTP/1.1\r\n" + strings.Repeat("k", 512) + ": v\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\nbodyTRAILING",

		// Nothing, and nothing that resembles a request at all.
		"",
		"\r\n\r\n",
		"\x00\x00\x00\x00",
	}
	for _, seed := range seeds {
		f.Add(uint64(0), []byte(seed))
	}
}

package httphi

import (
	"math"
	"unsafe"

	"github.com/soypat/lneto/http/httpraw"
)

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

	// sizeofExchange is the fixed cost of an exchange, which a Router pays per
	// connection it can serve concurrently on top of the buffers it hands it.
	// It dwarfs a small request buffer, so budgets must account for it.
	sizeofExchange = int(unsafe.Sizeof(Exchange{}))
	// sizeofPathValue is the per-wildcard cost of the path value table.
	sizeofPathValue = int(unsafe.Sizeof(PathValue{}))
	// sizeofJob is an exchange's slot in the queue connections wait on for a
	// worker goroutine, sized to the goroutine count in worker mode.
	sizeofJob = int(unsafe.Sizeof(job{}))

	// bytesPerHeaderField is the request buffer [DefaultRouterConfig] budgets per
	// parseable header field. Real fields run a little longer than this
	// ("Accept-Encoding: gzip, deflate, br\r\n" is 35 bytes), so a request fills
	// the buffer before it exhausts the field table, which is the cheaper of the
	// two limits to hit: growing the table costs [httpraw.SizeKV] per field on top
	// of the bytes the field already occupies.
	bytesPerHeaderField = 32
	// defaultResponseHeaderBuffer is the response header room
	// [DefaultRouterConfig] reserves when the budget can afford it: enough for a
	// Content-Type, a Content-Length and a Connection field with room to spare.
	// It does not scale with the request buffer because what a response header
	// costs depends on the fields a handler stages, not on the request's size.
	defaultResponseHeaderBuffer = 128
)

// MemoryUsagePerConnection returns the heap bytes a [Router] configured with cfg
// reserves for each connection it can serve concurrently, maxPathValues being
// the [Mux.MaxPathValues] of the mux it is configured with. Goroutine stacks are
// not counted: those are the runtime's to size, not the router's.
//
// In worker mode this is exact and fixed, so a router's whole heap footprint is
// this times FixedNumGoroutines, plus the runtime's own header for the job
// queue. With FixedNumGoroutines -1 the router allocates one of these per
// connection in flight instead, so the total grows with peak concurrency.
//
// It is the inverse of [DefaultRouterConfig] and useful to check a hand written
// configuration against a memory budget.
func (cfg RouterConfig) MemoryUsagePerConnection(maxPathValues int) int {
	if maxPathValues < 0 {
		maxPathValues = 0 // Mux with no routes registered yet, see [Mux.MaxPathValues].
	}
	n := sizeofExchange + // Exchange itself, an element of the router's exchange store.
		cfg.RequestHeaderBufferSize + cfg.ResponseHeaderMinBufferSize + // Its window into the raw buffer.
		cfg.RequestNumHeaderKVCap*httpraw.SizeKV + // The request header's field table.
		maxPathValues*sizeofPathValue // Its window into the path value store.
	if cfg.workerMode() {
		n += sizeofJob // Slot in the queue connections wait on for a worker.
	}
	return n
}

// DefaultRouterConfig is a general purpose configuration creator
// for small, medium, large, performant or embedded projects.
//
// Generalness is achieved with parameters that let the Configuration
// determine allocation buffer sizes based on typical usage for that
// number of goroutines and heap allocation on a per-connection basis.
func DefaultRouterConfig(numGoroutines, memoryPerConnectionBytes, maxPathValues int) RouterConfig {
	// The budget is spent on the request header buffer first, since that is what
	// decides which requests are answered at all, then on a field table sized to
	// match it and a small response header reserve. A budget too small to fund the
	// minimum viable exchange yields the minimum instead, so the returned config is
	// always one [Router.Configure] accepts but may exceed a budget under roughly
	// sizeofExchange + 200 bytes. Check it with MemoryUsagePerConnection when the
	// bound has to hold.
	if numGoroutines <= 0 {
		numGoroutines = -1 // Unbounded mode, the only non-positive value Validate accepts.
	}
	// Everything the exchange costs before any buffer is sized: subtract it first
	// so the buffers below divide up what is actually left to spend.
	fixed := sizeofExchange + maxPathValues*sizeofPathValue
	if numGoroutines > 0 {
		fixed += sizeofJob
	}
	// A budget past what the buffers may grow to is only spendable up to the cap
	// below, so clamp before the products: on a 32 bit target an unclamped
	// multiply would overflow and wrap a generous budget into a tiny buffer.
	const maxSpendable = (maxExchangeBuffer + defaultResponseHeaderBuffer) *
		(bytesPerHeaderField + httpraw.SizeKV) / bytesPerHeaderField
	avail := min(memoryPerConnectionBytes-fixed, maxSpendable)

	// The response reserve is a floor rather than a share of the budget, but a
	// budget this small cannot afford the full one without starving the request.
	respBuf := min(defaultResponseHeaderBuffer, avail/4)

	// Solve avail-respBuf = reqBuf + reqBuf/bytesPerHeaderField*httpraw.SizeKV for
	// reqBuf, the field table growing with the buffer it parses.
	reqBuf := (avail - respBuf) * bytesPerHeaderField / (bytesPerHeaderField + httpraw.SizeKV)

	// Clamp to what [RouterConfig.Validate] accepts. Truncating division above
	// keeps the result under budget; these floors are what can push it over.
	respBuf = max(respBuf, minResponseHeaderBuffer)
	reqBuf = max(reqBuf, minRequestHeaderBuffer)
	reqBuf = min(reqBuf, maxExchangeBuffer-respBuf)
	return RouterConfig{
		FixedNumGoroutines:          numGoroutines,
		RequestHeaderBufferSize:     reqBuf,
		ResponseHeaderMinBufferSize: respBuf,
		RequestNumHeaderKVCap:       max(reqBuf/bytesPerHeaderField, 1),
		NormalizeOutgoingKeys:       false,
	}
}

# httφ

Heapless HTTP/1.1 router with `net/http`-shaped handlers. Benchmarked against `net/http` and friends at [**soypat/httpbench**](https://github.com/soypat/httpbench).

## Why

`net/http` allocates per request: `Request`, header map, response buffer, goroutine. Fine on a
server, fatal on a microcontroller. httφ pays that cost once, at `Router.Configure`:

- Exchanges and goroutines are fixed there. Serving allocates nothing; memory does not grow with load.
- No free exchange means `Handle` refuses the connection unclosed, rather than allocating one more of everything.
- `Handle` takes an `io.ReadWriteCloser`, so the router runs over a raw socket, an [`lneto`](https://github.com/soypat/lneto) TCP stack or a test pipe. No listener, no OS, no clock.

Parsing is [`httpraw`](../httpraw).

## Example

```go
var mux httphi.MuxSlice
mux.Handle("GET /", func(ex *httphi.Exchange) {
	ex.WriteBody([]byte("hello world"))
})

var router httphi.Router
cfg := httphi.DefaultRouterConfig(numWorkers, memoryPerConn, mux.MaxPathValues())
err := router.Configure(&mux, cfg)
if err != nil {
	log.Fatal(err)
}
for {
	conn, err := listener.Accept() // Accepting is the caller's job.
	if err != nil {
		log.Fatal(err)
	}
	if err = router.Handle(conn); err != nil {
		conn.Close() // Refused: never blocks, never queues unboundedly.
	}
}
```

`FixedNumGoroutines: -1` gives the unbounded flavor, a goroutine and an exchange per connection.

Runnable server over raw Linux sockets, plus query, form and multipart handlers:
[`example_test.go`](./example_test.go).


## Naming

Gonna be honest with y'all. I initially wanted it to be named `httplo` until I saw I could write `httphi.MethHead` with a small change.
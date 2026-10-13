# Testing lneto

This document describes how tests in lneto are written and run. Tests use
only the standard library `testing` package. Fuzzing and property-based
testing live in [lfuzzo](https://github.com/soypat/lfuzzo), which is to get
its own document for them.

## Running the checks

CI runs the following. Run them before opening a pull request:

```sh
gofmt -l -d .
go vet ./...
go vet -tags=tinygo ./...
go fix -diff ./...    # must print nothing
go build ./...
go test -shuffle=on -count=1 ./...
go test -race -shuffle=on -count=1 ./...
```

CI also tests the following environments. Reproduce a failure in one of them
with the same variables:

| Environment | How CI runs it |
|---|---|
| Go 1.24, the `go.mod` minimum | `go test ./...` |
| `GOARCH=386` (32-bit) | `go test ./...` |
| linux/arm64 | `go test ./...` on an arm64 runner |
| Build tags `onlytcp`, `noslog`, `xnetdebug`, `debugheaplog` | `go vet -tags=…` and `go test -tags=…` |
| darwin, windows, linux/arm, linux/riscv64, linux/mips, wasip1, js/wasm | `GOOS=… GOARCH=… go vet ./...` |
| TinyGo | `tinygo test` on every package with tests |

Cross-vet type-checks; it does not run tests. These jobs sample platforms and
build tags, not their full product.

## Where a test belongs

Test a behaviour at the lowest layer that shows it. A bug in a state machine
is tested against the state machine, not through a full stack.

| Layer | What is tested | Examples |
|---|---|---|
| Codec | Parsing and encoding of one frame or message | `ipv4` frame tests, `http/httpraw` |
| State machine | Protocol rules: transitions, sequence checks, expected errors | `tcp.ControlBlock` in `tcp/tcp_test.go`, `dhcpv4` client |
| Handler | Buffers, queues and policies around a state machine | `tcp/handler_test.go` |
| Stack | Several protocols exchanging packets in memory | `internet`, `x/xnet` |

Add a test to the existing test file of its package and topic, next to the
tests it relates to. Do not create a file per test or per bug.

## Shape of a test

Prefer one table-driven test per behaviour over many similar test functions.
Each row names its case and states the expected outcome, including the
expected error.

```go
tests := []struct {
	name    string
	input   []byte
	want    Frame
	wantErr error // matched with errors.Is; nil means success.
}{ ... }
for _, tt := range tests {
	t.Run(tt.name, func(t *testing.T) { ... })
}
```

Protocols with a sequence of exchanges model each step as a row, as
`tcp.ExchangeTest` does with `SegmentStep`: the segment sent, the states of
both peers afterwards, the pending segment and the expected error.
The `synSentDropsSynFin` case of `TestExchangeTest` is a typical regression
test of this kind. Before adding a test function, check whether the case is a new row of
an existing table.

## Regression tests

- A bug fix comes with a regression test that fails without the fix and
  passes with it. Check both.
- Keep fixes small: one bug, the smallest change that fixes it and one test.
  Two places with the same bug are two fixes.
- Assert what the RFC or the API documentation prescribes, not incidental
  details of the current implementation.
- Fix a bug found by a test, by lfuzzo or by a new CI environment right away.
  Do not keep failing tests around for later.

## Changing existing tests

When rewriting existing tests, for example into a table, show that the new
tests catch what the old ones caught before deleting them: introduce the bug
each old test guards against and check that a new test fails too. When a fix
changes what an existing test expects, say why in the commit message.

## Time and concurrency

Tests do not sleep and do not read the wall clock.

- Packages take their clock as configuration, for example `func() int64`
  nanoseconds (`tcp/rto`) or `func() time.Time` (`linklocal4`, `ntp`). Tests
  pass a fake clock and advance it explicitly.
- Tests with goroutines hand control back and forth with `ltesto.Sched`
  (`internal/ltesto`) instead of waiting for time to pass.
- A `select` on `time.After` may guard against a hang, but must not decide
  the result.
- A test must give the same result under `-shuffle=on`, `-race` and any
  `-count`, and with several test processes at once: write files under
  `t.TempDir()`, never into the source tree.

## TinyGo

lneto targets TinyGo. Avoid test code TinyGo cannot compile, or exclude the
file with `//go:build !tinygo` and say why. Packages and tests that do not
pass under TinyGo yet are skipped by name in the `tinygo` job of
`.github/workflows/ci.yaml`, each with its reason.

TinyGo has no `runtime.Goexit`, so `t.Skip`, `t.SkipNow` and `t.FailNow`
report but do not stop the test: the code after them still runs. Return right
after them in a test that must not continue.

## Recurring bug classes

Most bugs found so far fall in a few classes:

- **State surviving Reset.** A reset object must behave like a fresh one.
  Compare what both put on the wire for the same traffic after the reused one
  carried other traffic. Reslicing reused memory without `clear` is the usual
  cause.
- **Writes past a buffer.** Reslicing up to capacity is legal in Go, so a
  frame written past the MTU goes unnoticed when the buffer has room to spare.
  Egress into buffers of exactly one frame.
- **Allocation driven by input.** Handling a frame must not allocate. Check it
  with `testing.AllocsPerRun` on a fresh object, since its warm-up call hides
  first-use allocations. Formatting log attributes before checking the log
  level allocates too.
- **Lifecycle.** Close, EOF and errors after close follow `net.Conn` and RFC
  9293. Test them with loss and reordering, not only on the happy path.
- **32-bit targets.** 64-bit atomics need 8-byte alignment on 386, arm and
  mips. Use the `sync/atomic` types, as `StackNode.ConnectionID` does with
  `*atomic.Uint32`, and let the 32-bit CI job run the tests.

## Fuzzing and property-based testing

[lfuzzo](https://github.com/soypat/lfuzzo) fuzzes lneto from outside, through
its public API, and runs nightly. It covers mutated traffic between stacks,
synthesized frames and codec round trips; property-based testing moves there
too. It is to get its own document on how to run it and add to it.

A bug lfuzzo finds is fixed in lneto with a regression test in lneto, as
described above, so it is caught without fuzzing. The fuzz targets still in
lneto run their seed corpus as part of `go test`.

## Coverage

CI reports coverage. Patch coverage is informational; the project gate is
62%. Neither replaces the regression tests above.

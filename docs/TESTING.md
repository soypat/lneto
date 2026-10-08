# Testing lneto

This document describes how tests in lneto are written and run. It applies to
every package. Tests use only the standard library `testing` package.

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
with the same variables, using qemu user emulation for foreign architectures:

| Environment | How CI runs it |
|---|---|
| Go 1.24, the `go.mod` minimum | `go test ./...` |
| `GOARCH=386` (32-bit) | `go test ./...` |
| linux/arm64 | `go test ./...` on an arm64 runner |
| Build tags `onlytcp`, `noslog`, `xnetdebug`, `debugheaplog` | `go vet -tags=…` and `go test -tags=…` |
| darwin, windows, linux/arm, linux/riscv64, linux/mips, wasip1, js/wasm | `GOOS=… GOARCH=… go vet ./...` |
| linux/mips (big-endian), nightly | `GOARCH=mips go test -exec qemu-mips-static ./...` |

Cross-vet is a type-checking check, not a runtime test. These jobs sample
platforms and build tags; they do not cover their full Cartesian product.

## Where a test belongs

Test a behaviour at the lowest layer that exhibits it. A bug in a state
machine is tested against the state machine, not through a full stack.

| Layer | What is tested | Examples |
|---|---|---|
| Codec | Parsing and encoding of a single frame or message | `ipv4` frame tests, `http/httpraw` |
| State machine | Protocol rules: transitions, sequence checks, expected errors | `tcp.ControlBlock` in `tcp/tcp_test.go`, `dhcpv4` client |
| Handler | Buffers, queues and policies around a state machine | `tcp/handler_test.go` |
| Stack | Several protocols exchanging packets in memory | `internet`, `x/xnet` |

Fuzz targets (`func FuzzXxx`) cover parsers and state machines against
arbitrary input. Their seed corpus runs as part of `go test`. CI fuzzes each
target for a second to check the fuzzing setup, and the nightly workflow
fuzzes every target for an hour; run one locally with
`go test -run '^$' -fuzz '^FuzzXxx$' ./pkg`. When fuzzing finds a failing
input, the job uploads it from `testdata/fuzz`. Commit that file with the fix,
so it keeps running as a regression test.

## Shape of a test

Prefer one table-driven test per behaviour over many similar test functions.
Each table row names its case and states the expected outcome, including the
expected error, so a reader sees every case of a rule in one place.

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

Protocols with a sequence of exchanges model each step as a table row, as
`tcp.ExchangeTest` does with `SegmentStep`: the segment sent, the states of
both peers afterwards, the pending segment and the expected error.
`crypto/tlsraw` `TestHalfConn` is an example of a table covering limits and
error cases of one type.

Before adding a test function, check whether the case is a new row of an
existing table.

## Regression tests

- A bug fix comes with a regression test that fails without the fix and
  passes with it. Check both.
- Add only the tests the change needs. A small fix gets a small test.
- Assert the behaviour the RFC or the API documentation prescribes, not
  incidental details of the current implementation.
- A bug found by a test, fuzzing or a new CI environment is fixed right away
  with the smallest change that makes the test pass, one fix per commit. Do
  not keep failing tests around for later.

## Replacing or merging tests

When rewriting existing tests, for example into a table, show that the new
tests catch what the old ones caught before deleting the old ones: introduce
the bug each old test guards against and confirm that a new test fails too.
Keep the old tests until this is shown. Record the mutation and both failures
in the review evidence. If a separate proof branch is used to show failures in
CI, do not merge its deliberately broken commits into the implementation.

## Time and concurrency

Tests do not sleep and do not read the wall clock.

- Packages take their clock as configuration, for example
  `func() int64` nanoseconds (`rto.Timer.Configure`) or `func() time.Time`
  (`linklocal4`, `ntp`). Tests pass a fake clock and advance it explicitly.
- Tests with goroutines hand control back and forth with `ltesto.Sched`
  (`internal/ltesto`) instead of waiting for time to pass. See its users in
  `x/xnet` for examples.
- A `select` on `time.After` may guard against a hang, but must not decide
  the result.
- A test must give the same result under `-shuffle=on`, `-race` and any
  `-count`, and when several test processes run at once: write files under
  `t.TempDir()`, never into the source tree. The nightly workflow repeats the
  suite to catch tests that pass only most of the time.

## TinyGo

lneto targets TinyGo, and CI runs `tinygo test` on every package with tests.
Avoid test code that TinyGo cannot compile, or exclude the file with
`//go:build !tinygo` and say why in a comment. Packages and tests that do not
yet pass under TinyGo are skipped by name in the `tinygo` job of
`.github/workflows/ci.yaml`, each with the reason.

## Recurring bug classes

Most bugs found in review and audits fall in a few classes. Code in these
areas should be covered by checks of this kind:

- **State surviving Reset.** A reset object must behave like a fresh one.
  Compare what both put on the wire for the same traffic after the reused one
  carried other traffic, as `TestStackAsync_ResetMatchesFresh` does. Reslicing
  reused memory to its capacity without `clear` is the usual cause.
- **Writes past a buffer.** Reslicing up to capacity is legal in Go, so a
  frame written past the MTU goes unnoticed when the buffer has room to spare.
  Egress into buffers of exactly one frame with no spare capacity, as
  `FuzzStackPair` does with stacks of different MTUs.
- **Allocation driven by input.** Handling any frame must not allocate. See
  `FuzzStackIngressAllocs`. Formatting log attributes before checking the
  log level allocates too.
- **Lifecycle.** Close, EOF and errors after close follow `net.Conn` and RFC
  9293; drive them with loss and reordering, as the model in
  `examples/_import_examples/hegel` does.
- **32-bit targets.** 64-bit atomics need 8-byte alignment on 386, arm and
  mips; use `lneto.ConnID` and the `internal` helpers, and let the 32-bit CI
  jobs run the tests.

## Coverage

CI reports coverage. Patch coverage is informational, while the project gate
is 62%. Neither replaces the regression-test requirements above.

## Property-based testing with Hegel

`examples/_import_examples/hegel` evaluates
[Hegel](https://github.com/hegeldev/hegel-go) in a separate module outside go
tooling, since it requires Go 1.26 and loads a native library. It is not a
TinyGo runner and not a dependency of lneto. One model of two Handlers
on a fake clock runs under Hegel, a seeded random baseline and a Go fuzz
target. Run it with:

```sh
cd examples/_import_examples/hegel && GOWORK=off go test -v -count=1 ./...
```

Hegel shrinks a failure to a short action sequence, which made the bugs it
found quick to understand. A bug it finds gets a regression test in the main
module.

## Remaining work

Existing tests are not yet migrated to these rules. Shared Handler and link
fixtures, conversion of loose tests into tables, the remaining wall-clock
synchronization and integration tests against independent peers are still to
do. Parser fuzzing checks buffer safety and selected representations, not
complete protocol conformance.

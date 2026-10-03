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
| `GOARCH=386` (32-bit) | `go test` excluding `x/rawsock`, which does not build on this target |
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
arbitrary input. Their seed corpus runs as part of `go test`. The nightly
workflow fuzzes every target for an hour; run one locally with
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

## Known bugs

A bug found but not yet fixed is recorded as a failing test, so the list of
known problems lives in the code next to the tests that will guard the fix.

- Put the test in a file with the `//go:build knownbug` constraint, named
  `knownbug_test.go` in the package it concerns.
- Name it `TestKnownBug_Xxx` and say in its comment what is wrong, what the
  RFC or documentation prescribes, and which existing tests assert the
  current behaviour.
- Assert the correct behaviour, so the test passes once the bug is fixed.

`.github/scripts/knownbug.sh` (Bash and jq) runs each tagged-only test with a
one-minute timeout and requires an ordinary named test failure. Passing or
skipped tests, build failures, panics and timeouts are unexpected results.
The pull request fixing a bug therefore moves its test out of the `knownbug`
file, where it becomes the regression test. CI lists the known bugs in the
summary of the `knownbug` job.

Bugs that only show under TinyGo cannot fail under `go test`; they are listed
as skips of the `tinygo` job instead (see [TinyGo](#tinygo)).

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

## Coverage

CI reports coverage. Patch coverage is informational, while the project gate
is 62%. Neither replaces the regression-test requirements above.

## Optional property-testing experiment

[Hegel](https://github.com/hegeldev/hegel-go) could complement the existing
tests by generating and shrinking protocol action sequences. As reviewed at
v0.9.13, it is beta, requires Go 1.26 and uses a native Rust library loaded
through FFI. It is not a TinyGo or bare-metal test runner, and is not a
dependency of this rework.

If evaluated, keep it in a separate, pinned host-only module; build tags alone
would not isolate its dependencies or toolchain requirements from `go.mod`.
Start with sequential actions over a Handler pair and a small reference
model: write, deliver/drop/duplicate a packet, read, close and advance an
injected clock. Check safety invariants after every action using
`WithAlwaysCheckInvariants`. Liveness requires a bounded loss period followed
by eventual delivery, not an arbitrary lossy link.

Keep fake clocks and `ltesto.Sched`; Hegel's concurrent mode is not a
deterministic scheduler. Compare its counterexamples and reproducibility
against an equivalent standard-library action-sequence fuzz target before
adoption. Promote any discovered defect into a dependency-free regression
test. Ordinary parser fuzzing, race checks and table tests remain necessary.

## Remaining work

This draft adds test infrastructure and selected test corrections, not a
completed suite migration. Shared Handler/link fixtures, equivalent table
conversions, remaining wall-clock synchronization and independent-peer
integration tests still need separate work. Parser fuzzing checks buffer
safety and selected representations, not complete protocol conformance.

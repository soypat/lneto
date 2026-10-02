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

`.github/scripts/knownbug.sh` runs each of these tests and fails if one passes.
The pull request fixing a bug therefore moves its test out of the `knownbug`
file, where it becomes the regression test. CI lists the known bugs in the
summary of the `knownbug` job.

Bugs that only show under TinyGo cannot fail under `go test`; they are listed
as skips of the `tinygo` job instead (see [TinyGo](#tinygo)).

## Replacing or merging tests

When rewriting existing tests, for example into a table, show that the new
tests catch what the old ones caught before deleting the old ones: introduce
the bug each old test guards against and confirm that a new test fails too.
Keep the old tests until this is shown. A commit that breaks the code on
purpose makes the failures visible in CI.

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

CI reports coverage. A pull request does not have to cover its patch, but the
project coverage must not fall below 62%.

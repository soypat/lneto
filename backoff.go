package lneto

import (
	"runtime"
	"time"
)

// Flag return values for a BackoffStrategy.
const (
	BackoffFlagGosched = time.Duration(-1)
	BackoffFlagNop     = time.Duration(-2)
)

// BackoffStrategy is the abstraction of a backoff strategy for retrying an operation.
// It returns the amount of time to sleep for or a flag value:
//   - Returns [BackoffFlagNop]: Signal no yielding function should be called.
//     Useful for when the BackoffStrategy implements its own yield.
//   - Returns [BackoffFlagGosched]: Signal [runtime.Gosched] should be called.
//
// Despite the name(changes welcome) consecutiveBackoffs starts at 0 and
// increments by 1 every time the operation is retried.
// See internal/backoff.go for a implementation example.
type BackoffStrategy func(consecutiveBackoffs uint) (sleepOrFlag time.Duration)

// Do applies the backoff strategy by calling backoff(consecutiveBackoffs)
// and then the corresponding yield function for the returned value. See [BackoffStrategy].
func (backoff BackoffStrategy) Do(consecutiveBackoffs uint) {
	sleep := backoff(consecutiveBackoffs)
	switch sleep {
	case BackoffFlagNop:
		// No yield. Yield implemented by backoff.
	case BackoffFlagGosched:
		runtime.Gosched()
	default:
		time.Sleep(sleep)
	}
}

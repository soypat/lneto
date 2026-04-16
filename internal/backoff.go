package internal

import (
	"time"
)

// BackoffConnRW implements exponential backoff suitable for TCP connection
// read/write polling. It starts at 1us and caps at 5ms, doubling on each consecutive backoff.
func BackoffConnRW(consecutiveBackoffs uint) {
	const (
		minWait        = uint32(time.Microsecond)
		maxWait        = 5 * uint32(time.Millisecond)
		maxShift       = 22
		_overflowCheck = minWait << maxShift
	)
	shifted := minWait << min(consecutiveBackoffs, maxShift)
	wait := min(shifted, maxWait)
	time.Sleep(time.Duration(wait))
}

// BackoffStackProto implements exponential backoff suitable for stack-level
// protocol processing polling. It starts at 1us and caps at 100ms, doubling on each consecutive backoff.
func BackoffStackProto(consecutiveBackoffs uint) {
	const (
		minWait = uint32(time.Microsecond)
		maxWait = 100 * uint32(time.Millisecond)

		// Statically calculated numbers below.
		maxShift       = 22
		_overflowCheck = minWait << maxShift
	)
	shifted := minWait << min(consecutiveBackoffs, maxShift)
	wait := min(shifted, maxWait)
	time.Sleep(time.Duration(wait))
}

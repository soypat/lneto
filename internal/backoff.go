package internal

import (
	"time"
)

// ConnRWBackoff implements exponential backoff suitable for TCP connection
// read/write polling. It starts at 1us and caps at 5ms, doubling on each consecutive backoff.
func ConnRWBackoff(consecutiveBackoffs int) {
	const (
		minWait        = uint32(time.Microsecond) >> 1
		maxWait        = 5 * uint32(time.Millisecond)
		maxShift       = 23
		_overflowCheck = minWait << maxShift
	)
	wait := minWait << min(consecutiveBackoffs, maxShift)
	if wait > maxWait {
		wait = maxWait
	}
	time.Sleep(time.Duration(wait))
}

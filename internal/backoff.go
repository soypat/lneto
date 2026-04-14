package internal

import (
	"time"
)

// ConnRWBackoff implements exponential backoff suitable for TCP connection
// read/write polling. It starts at 1us and caps at 5ms, doubling on each consecutive backoff.
func ConnRWBackoff(consecutiveBackoffs int) {
	const (
		minWait = time.Microsecond >> 1
		maxWait = 5 * time.Millisecond
	)
	wait := minWait << consecutiveBackoffs
	if wait > maxWait {
		wait = maxWait
	}
	time.Sleep(wait)
}

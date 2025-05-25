package internal

import "time"

type BackoffFlags uint8

const (
	BackoffHasPriority BackoffFlags = 1 << iota
	BackoffCriticalPath
)

func NewBackoff(priority BackoffFlags) Backoff {
	if priority&BackoffCriticalPath != 0 {
		return Backoff{
			maxWait: uint32(1 * time.Millisecond),
		}
	}
	return Backoff{
		maxWait: uint32(time.Second) >> (priority & BackoffHasPriority),
	}
}

// A Backoff with a non-zero MaxWait is ready for use.
type Backoff struct {
	// wait defines the amount of time that Miss will wait on next call.
	wait uint32
	// Maximum allowable value for Wait.
	maxWait uint32
	// startWait is the value that Wait takes after a call to Hit.
	startWait uint32
	// expMinusOne is the shift performed on Wait minus one, so the zero value performs a shift of 1.
	expMinusOne uint32
}

// Hit sets eb.Wait to the StartWait value.
func (eb *Backoff) Hit() {
	if eb.maxWait == 0 {
		panic("MaxWait cannot be zero")
	}
	eb.wait = eb.startWait
}

// Miss sleeps for eb.Wait and increases eb.Wait exponentially.
func (eb *Backoff) Miss() {
	const k = 1
	wait := eb.wait
	maxWait := eb.maxWait
	exp := eb.expMinusOne + 1
	if maxWait == 0 {
		panic("MaxWait cannot be zero")
	}
	time.Sleep(time.Duration(wait))
	wait |= k
	wait <<= exp
	if wait > maxWait {
		wait = maxWait
	}
	eb.wait = wait
}

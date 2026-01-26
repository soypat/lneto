package internal

import "time"

type BackoffFlags uint8

const (
	BackoffHasPriority BackoffFlags = 1 << iota
	BackoffCriticalPath
	BackoffTCPConn
)

const backoffMinWait = time.Microsecond

func backoffMaxWait(priority BackoffFlags) time.Duration {
	switch {
	case priority&BackoffCriticalPath != 0:
		return 1 * time.Millisecond
	case priority&BackoffTCPConn != 0:
		return 5 * time.Millisecond
	default:
		return time.Second >> (priority & BackoffHasPriority)
	}
}

func NewBackoff(priority BackoffFlags) Backoff {
	return Backoff{
		wait:      uint32(backoffMinWait),
		maxWait:   uint32(backoffMaxWait(priority)),
		startWait: uint32(backoffMinWait),
	}
}

// A Backoff with a non-zero MaxWait is ready for use.
type Backoff struct {
	// wait defines the amount of time that Miss will wait on next call.
	wait uint32
	// Maximum allowable value for Wait.
	maxWait uint32
	// startWait is the intial Wait value, as well as the value that Wait takes after a call to Hit.
	startWait uint32
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
	if eb.maxWait == 0 {
		panic("MaxWait cannot be zero")
	}
	time.Sleep(time.Duration(eb.wait))
	eb.wait *= 2
	if eb.wait > eb.maxWait {
		eb.wait = eb.maxWait
	}
}

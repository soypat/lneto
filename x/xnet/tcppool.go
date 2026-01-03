package xnet

import (
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/soypat/lneto/tcp"
)

// TCPPool implements tcp.pool.
type TCPPool struct {
	mu             sync.Mutex
	naqcuired      int
	conns          []tcp.Conn
	acquiredAt     []time.Time
	closingAt      []time.Time
	abortedAt      []time.Time
	nextISS        tcp.Value
	_now           func() time.Time
	estbTimeout    time.Duration
	closingTimeout time.Duration
}

func _() {
	var l tcp.Listener
	l.Reset(0, &TCPPool{}) // compile time guarantee of interface implementation.
}

type TCPPoolConfig struct {
	PoolSize   int
	QueueSize  int
	BufferSize int
	ConnLogger *slog.Logger
	Now        func() time.Time
	// EstablishedTimeout sets the timeout for a TCP connection since it is acquired until it is established.
	// If the connection does not establish in this time it will be closed by the pool.
	EstablishedTimeout time.Duration
	// ClosingTimeout sets the timeout for a TCP connection to close and be returned to Pool.
	// If the connection is not closed in this time it will be aborted by the pool.
	ClosingTimeout time.Duration
}

func NewTCPPool(cfg TCPPoolConfig) (*TCPPool, error) {
	if cfg.EstablishedTimeout <= 0 || cfg.ClosingTimeout <= 0 {
		return nil, errors.New("invalid timeout")
	}
	n := cfg.PoolSize
	bufsize := cfg.BufferSize
	pool := &TCPPool{
		acquiredAt:     make([]time.Time, n),
		closingAt:      make([]time.Time, n),
		abortedAt:      make([]time.Time, n),
		conns:          make([]tcp.Conn, n),
		_now:           cfg.Now,
		estbTimeout:    cfg.EstablishedTimeout,
		closingTimeout: cfg.ClosingTimeout,
	}
	bufSpace := make([]byte, 2*n*bufsize)
	for i := range pool.conns {
		bufoff := 2 * i * bufsize
		err := pool.conns[i].Configure(tcp.ConnConfig{
			RxBuf:             bufSpace[bufoff : bufoff+bufsize],
			TxBuf:             bufSpace[bufoff+bufsize : bufoff+2*bufsize],
			TxPacketQueueSize: cfg.QueueSize,
			Logger:            cfg.ConnLogger,
		})
		if err != nil {
			return nil, err
		}
	}
	return pool, nil
}

func (p *TCPPool) GetTCP() (*tcp.Conn, tcp.Value) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.conns {
		if p.acquiredAt[i].IsZero() {
			p.acquiredAt[i] = p.now()
			p.nextISS += 1000
			p.naqcuired++
			return &p.conns[i], p.nextISS
		}
	}
	return nil, 0
}

func (p *TCPPool) PutTCP(conn *tcp.Conn) {
	for i := range p.conns {
		if &p.conns[i] == conn {
			p.mu.Lock()
			p.conns[i].Abort()
			p.acquiredAt[i] = time.Time{}
			p.abortedAt[i] = time.Time{}
			p.closingAt[i] = time.Time{}
			p.naqcuired--
			p.mu.Unlock()
			return
		}
	}
	panic("conn does not belong to this pool")
}

func (p *TCPPool) CheckTimeouts() {
	for i := range p.conns {
		st := p.conns[i].State()
		if st == tcp.StateEstablished {
			continue
		}
		p.mu.Lock()
		acq := p.acquiredAt[i]
		p.mu.Unlock()
		if acq.IsZero() {
			continue
		} else if st.IsPreestablished() && p.since(acq) > p.estbTimeout {
			// Was acquired and did not reach establishment state so we close.
			// This is part of a syn-flood defense mechanism.
			p.conns[i].Close()
		} else if st.IsClosed() || st.IsClosing() {
			p.mu.Lock()
			if p.closingAt[i].IsZero() {
				p.closingAt[i] = p.now()
			} else if p.abortedAt[i].IsZero() && p.since(p.closingAt[i]) > p.closingTimeout {
				p.abortedAt[i] = p.now()
				p.conns[i].Abort()
			} else if p.since(p.abortedAt[i]) > 10*time.Second {
				println("connection aborted and still not returned to TCPPool")
			}
			p.mu.Unlock()
		}
	}
}

func (p *TCPPool) since(t time.Time) time.Duration {
	if p._now == nil {
		return time.Since(t)
	}
	return p._now().Sub(t)
}

func (p *TCPPool) now() time.Time {
	if p._now == nil {
		return time.Now()
	}
	return p._now()
}

func (p *TCPPool) NumberOfAcquired() int {
	return p.naqcuired
}

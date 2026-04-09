package xnet

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/tcp"
)

// TCPPool implements tcp.pool.
type TCPPool struct {
	mu             sync.Mutex
	naqcuired      int
	conns          []tcp.Conn
	userData       []any
	acquiredAt     []int64
	closingAt      []int64
	abortedAt      []int64
	nextISS        tcp.Value
	_now           func() int64
	estbTimeout    time.Duration
	closingTimeout time.Duration
	logger         *slog.Logger
}

func _() {
	var l tcp.Listener
	l.Reset(0, &TCPPool{}) // compile time guarantee of interface implementation.
}

type TCPPoolConfig struct {
	// PoolSize determines the maximum number of active incoming TCP connections to the pool.
	PoolSize  uint16
	QueueSize int
	TxBufSize int
	RxBufSize int

	Logger     *slog.Logger
	ConnLogger *slog.Logger

	// NanoTime returns the current monotonic time in nanoseconds.
	// Used for pool timeout tracking and passed to each [tcp.Conn] for
	// retransmission timing (RFC 6298). If nil, defaults to time.Now().UnixNano().
	NanoTime func() int64
	// EstablishedTimeout sets the timeout for a TCP connection since it is acquired until it is established.
	// If the connection does not establish in this time it will be closed by the pool.
	EstablishedTimeout time.Duration
	// ClosingTimeout sets the timeout for a TCP connection to close and be returned to Pool.
	// If the connection is not closed in this time it will be aborted by the pool.
	ClosingTimeout time.Duration
	// NewUserData is used to create user data used for each individual TCP connection and returned on GetTCP.
	NewUserData func() any
}

func NewTCPPool(cfg TCPPoolConfig) (*TCPPool, error) {
	if cfg.EstablishedTimeout <= 0 || cfg.ClosingTimeout <= 0 {
		return nil, lneto.ErrInvalidConfig
	}
	n := int(cfg.PoolSize)
	pool := &TCPPool{
		acquiredAt:     make([]int64, n),
		closingAt:      make([]int64, n),
		abortedAt:      make([]int64, n),
		conns:          make([]tcp.Conn, n),
		userData:       make([]any, n),
		_now:           cfg.NanoTime,
		estbTimeout:    cfg.EstablishedTimeout,
		closingTimeout: cfg.ClosingTimeout,
		logger:         cfg.Logger,
	}
	allocPerConn := cfg.TxBufSize + cfg.RxBufSize
	bufSpace := make([]byte, n*allocPerConn)
	for i := range pool.conns {
		bufoff := i * allocPerConn
		txOff := bufoff + cfg.RxBufSize
		err := pool.conns[i].Configure(tcp.ConnConfig{
			RxBuf:             bufSpace[bufoff:txOff],
			TxBuf:             bufSpace[txOff : txOff+cfg.TxBufSize],
			TxPacketQueueSize: cfg.QueueSize,
			Logger:            cfg.ConnLogger,
		})
		if err != nil {
			return nil, err
		}
		if cfg.NewUserData != nil {
			pool.userData[i] = cfg.NewUserData()
		}
	}
	return pool, nil
}

func (p *TCPPool) NumberOfAcquired() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.naqcuired
}

func (p *TCPPool) GetTCP() (conn *tcp.Conn, userData any, SuggestedISS tcp.Value) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.debug("TCPPool:get")
	for i := range p.conns {
		if p.acquiredAt[i] == 0 {
			p.acquiredAt[i] = p.now()
			p.nextISS += 1000
			p.naqcuired++
			return &p.conns[i], p.userData[i], p.nextISS
		}
	}
	return nil, nil, 0
}

func (p *TCPPool) PutTCP(conn *tcp.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.debug("TCPPool:put", slog.Uint64("lport", uint64(conn.LocalPort())))
	for i := range p.conns {
		if &p.conns[i] == conn {
			// p.mu.Lock()
			p.conns[i].Abort()
			p.acquiredAt[i] = 0
			p.abortedAt[i] = 0
			p.closingAt[i] = 0
			p.naqcuired--
			// p.mu.Unlock()
			return
		}
	}
	panic("conn does not belong to this pool")
}

func (p *TCPPool) CheckTimeouts() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.debug("TCPPool:checktimeouts", slog.Int("acq", p.naqcuired))
	for i := range p.conns {
		conn := &p.conns[i]
		st := conn.State()
		if st == tcp.StateEstablished {
			continue
		}
		// p.mu.Lock()
		acq := p.acquiredAt[i]
		// p.mu.Unlock()
		if acq == 0 {
			continue
		} else if st.IsPreestablished() && p.since(acq) > p.estbTimeout {
			// Was acquired and did not reach establishment state so we close.
			// This is part of a syn-flood defense mechanism.
			conn.Close()
		} else if st.IsClosed() || st.IsClosing() {
			// p.mu.Lock()
			if p.closingAt[i] == 0 {
				p.closingAt[i] = p.now()
			} else if p.abortedAt[i] == 0 && p.since(p.closingAt[i]) > p.closingTimeout {
				p.abortedAt[i] = p.now()
				conn.Abort()
			} else if p.abortedAt[i] != 0 && p.since(p.abortedAt[i]) > 10*time.Second {
				println("connection aborted and still not returned to TCPPool")
				println("source", conn.LocalPort(), "remote", conn.RemotePort(), "state", conn.State().String())
			}
		}
	}
}

func (p *TCPPool) since(t int64) time.Duration {
	return time.Duration(p.now() - t)
}

func (p *TCPPool) now() int64 {
	if p._now == nil {
		return time.Now().UnixNano()
	}
	return p._now()
}

func (p *TCPPool) trace(msg string, attrs ...slog.Attr) {
	p.log(slog.LevelDebug-2, msg, attrs...)
}
func (p *TCPPool) debug(msg string, attrs ...slog.Attr) {
	p.log(slog.LevelDebug, msg, attrs...)
}
func (p *TCPPool) log(lvl slog.Level, msg string, attrs ...slog.Attr) {
	if p.logger != nil {
		p.logger.LogAttrs(context.Background(), lvl, msg, attrs...)
	}
}

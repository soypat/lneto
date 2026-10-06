package xnet

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
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
	key            [16]byte // See [tcp.ISN].
	mono           internal.Monotonic
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

	// EstablishedTimeout sets the timeout for a TCP connection since it is acquired until it is established.
	// If the connection does not establish in this time it will be closed by the pool.
	EstablishedTimeout time.Duration
	// ClosingTimeout sets the timeout for a TCP connection to close and be returned to Pool.
	// If the connection is not closed in this time it will be aborted by the pool.
	ClosingTimeout time.Duration
	// NewUserData is used to create user data used for each individual TCP connection and returned on GetTCP.
	NewUserData func() any
	// NewBackoff returns the backoff to use for every newly configured TCP connection. Must be non-nil.
	// This should always return a static(non-method) function unless you know what you are doing.
	NewBackoff func() lneto.BackoffStrategy
	// NewPolicy if non-nil creates a [tcp.Policy] for each [tcp.Conn] used by the configured Listener.
	// NewPolicy should not return reused policies unless the algorithm is stateless. See [tcp.Policy] for more information.
	NewPolicy func() tcp.Policy

	// NanoTime returns the current monotonic time in nanoseconds.
	// Nanotime is monotonic clock used for pool timeout tracking.
	// Retransmission timing is not driven by this clock: a [tcp.Policy] carries
	// its own. See [TCPPoolConfig.NewPolicy].
	nanotime func() int64
	// key used for Initial Sequence Number generation. Should be from a high-entropy source. Cannot be zero.
	key [16]byte
}

// NewTCPPool using StackAsync's internal ISN key.
func (s *StackAsync) NewTCPPool(cfg TCPPoolConfig) (*TCPPool, error) {
	s.mu.Lock()
	cfg.key = s.key
	cfg.nanotime = s.mono.HAL()
	s.mu.Unlock()
	return newTCPPool(&cfg)
}

func newTCPPool(cfg *TCPPoolConfig) (*TCPPool, error) {
	if cfg.EstablishedTimeout <= 0 || cfg.ClosingTimeout <= 0 || internal.IsZeroed(cfg.key) {
		return nil, lneto.ErrInvalidConfig
	} else if cfg.NewBackoff == nil {
		return nil, lneto.ErrMissingHALConfig
	}
	n := int(cfg.PoolSize)
	pool := &TCPPool{
		acquiredAt:     make([]int64, n),
		closingAt:      make([]int64, n),
		abortedAt:      make([]int64, n),
		conns:          make([]tcp.Conn, n),
		userData:       make([]any, n),
		estbTimeout:    cfg.EstablishedTimeout,
		closingTimeout: cfg.ClosingTimeout,
		logger:         cfg.Logger,
		key:            cfg.key,
	}
	pool.mono.Config(cfg.nanotime)
	allocPerConn := cfg.TxBufSize + cfg.RxBufSize
	bufSpace := make([]byte, n*allocPerConn)
	for i := range pool.conns {
		bufoff := i * allocPerConn
		txOff := bufoff + cfg.RxBufSize
		conncfg := tcp.ConnConfig{
			RxBuf:             bufSpace[bufoff:txOff],
			TxBuf:             bufSpace[txOff : txOff+cfg.TxBufSize],
			TxPacketQueueSize: cfg.QueueSize,
			Logger:            cfg.ConnLogger,
			RWBackoff:         cfg.NewBackoff(),
		}
		if cfg.NewPolicy != nil {
			// One Policy per connection: it shadows that connection's send
			// sequence space and so cannot be shared.
			conncfg.Policy = cfg.NewPolicy()
		}
		err := pool.conns[i].Configure(conncfg)
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

// GetTCP acquires a free connection from the pool and returns its user data and an
// Initial Sequence Number for the connection identified by laddr, raddr, lport and rport.
func (p *TCPPool) GetTCP(laddr, raddr []byte, lport, rport uint16) (conn *tcp.Conn, userData any, iss tcp.Value) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.debug("TCPPool:get")
	for i := range p.conns {
		if p.acquiredAt[i] == 0 {
			now := p.now()
			p.acquiredAt[i] = now
			p.naqcuired++
			return &p.conns[i], p.userData[i], tcp.ISN(&p.key, now, laddr, raddr, lport, rport)
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
			conn.Abort()
		} else if st.IsClosed() || st.IsClosing() {
			// p.mu.Lock()
			if p.closingAt[i] == 0 {
				p.closingAt[i] = p.now()
			} else if p.abortedAt[i] == 0 && p.since(p.closingAt[i]) > p.closingTimeout {
				p.abortedAt[i] = p.now()
				conn.Abort()
			} else if p.abortedAt[i] != 0 && p.since(p.abortedAt[i]) > 10*time.Second {
				p.debug("TCPPool:aborted-not-returned", slog.Uint64("lport", uint64(conn.LocalPort())), slog.Uint64("rport", uint64(conn.RemotePort())), slog.String("state", st.String()))
			}
		}
	}
}

func (p *TCPPool) since(t int64) time.Duration {
	return time.Duration(p.now() - t)
}

func (p *TCPPool) now() int64 {
	return p.mono.Nanotime()
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

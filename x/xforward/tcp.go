package xforward

import (
	"log/slog"
	"math"
	"math/bits"
	"net"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/tcp"
)

// minTCPCarrier fits an IPv6 header and a TCP header with maximum options.
const minTCPCarrier = sizeIPv6Header + 60

// TCPHandler terminates TCP flows addressed to any IP:port, answering as the
// original destination. A SYN is held until [TCPHandler.Accept] or [TCPHandler.Reject].
//
// Not safe for concurrent use; see [TCPForwarder].
type TCPHandler struct {
	flows  []tcpFlow // len MaxFlows, fixed at Configure.
	table  flowTable
	dirty  bitset // slots that may have a segment to send. Set by flow I/O, cleared by Encapsulate.
	cursor uint16 // round-robin start of the dirty scan.
	// locker, set only by TCPForwarder, guards a slot against FlowConn I/O running outside its lock.
	locker     slotLocker
	npending   uint16
	maxPending uint16
	txQueue    int // TxPacketQueueSize passed to SetBuffers on Accept.
	rst        rstQueue
	mono       internal.Monotonic
	key        [16]byte // ISN (RFC 6528) key.

	pendingTimeout int64
	closeTimeout   int64
	// nextScan is the earliest timer; Encapsulate runs maintenance once due.
	nextScan int64
	release  func(rx, tx []byte)
	ipID     uint16
	log      *slog.Logger
}

type flowState uint8

const (
	flowFree flowState = iota
	flowPending
	flowOpen
	flowReleased
)

// slotLocker serializes one flow slot. Lock order is the caller's lock, then the slot's.
type slotLocker interface {
	lockSlot(slot int)
	unlockSlot(slot int)
}

func (th *TCPHandler) lock(slot int) {
	if th.locker != nil {
		th.locker.lockSlot(slot)
	}
}

func (th *TCPHandler) unlock(slot int) {
	if th.locker != nil {
		th.locker.unlockSlot(slot)
	}
}

// tcpFlow is a flow slot. Under TCPForwarder its fields are guarded by the slot lock.
type tcpFlow struct {
	h      tcp.Handler
	policy tcp.Policy // one per slot from NewPolicy; NextDeadline read directly.
	rx, tx []byte     // Accept's buffers, passed to ReleaseBuffers on reap.
	syn    [60]byte   // held SYN TCP header; its data offset gives the length.
	at     int64      // pending: SYN arrival. released: release time.
	rxPkts uint32
	txPkts uint32
	gen    uint32 // bumped on reap; stale TCPFlow fails with net.ErrClosed.
	// state stores whether flow is released: caller intent not derivable from tcp.Handler's public API.
	state flowState
}

// TCPFlow is a handle to a forwarded TCP flow, pending or accepted.
// It becomes stale once its slot is reaped.
type TCPFlow struct {
	ID   FlowID
	slot uint16
	gen  uint32
}

// Slot returns the flow's slot index in [0, MaxFlows) so callers can keep per-flow data in their own slice.
func (f TCPFlow) Slot() int { return int(f.slot) }

// TCPHandlerConfig configures a [TCPHandler]. All memory is sized from it at Configure.
type TCPHandlerConfig struct {
	// MaxFlows bounds pending, open and released flows. At most 1<<15.
	MaxFlows uint16
	// MaxPending bounds SYNs held awaiting Accept or Reject. Extra SYNs are dropped so the peer retries.
	MaxPending uint16
	// TxPacketQueueSize is the per-flow retransmit queue length. See [tcp.ConnConfig].
	TxPacketQueueSize int
	// NewPolicy creates one Policy per slot at Configure (RTO, SACK, congestion control).
	// A Policy with a NextDeadline method schedules retransmits. nil disables policies:
	// no retransmission timer nor zero-window probes, so lost segments stall the flow.
	NewPolicy func() tcp.Policy
	// PendingTimeout rejects a held SYN not accepted in time, and resets an accepted flow
	// whose handshake does not complete in time. Must exceed the caller's upstream dial timeout.
	PendingTimeout time.Duration
	// CloseTimeout aborts a released flow that has not finished closing in time.
	CloseTimeout time.Duration
	// ReleaseBuffers, if set, receives Accept's buffers when a flow slot is reaped.
	// Called with handler state held: must not call back into the handler.
	// When set, Accept requires buffers since released ones are not reused.
	ReleaseBuffers func(rx, tx []byte)
	// NanoTime returns monotonic time in nanoseconds. Required.
	NanoTime func() int64
	// Entropy fills dst with secret random bytes for ISN (RFC 6528) and flow table keys,
	// read once per Configure. Required; crypto/rand.Read fits.
	Entropy func(dst []byte) (n int, err error)
	Logger  *slog.Logger
}

// Configure sizes the handler for cfg and resets it. Flows from before are reaped.
func (th *TCPHandler) Configure(cfg TCPHandlerConfig) error {
	if cfg.NanoTime == nil || cfg.Entropy == nil {
		return lneto.ErrMissingHALConfig
	} else if cfg.MaxFlows == 0 || cfg.MaxFlows > maxFlows || cfg.MaxPending == 0 || cfg.MaxPending > cfg.MaxFlows ||
		cfg.TxPacketQueueSize <= 0 || cfg.PendingTimeout <= 0 || cfg.CloseTimeout <= 0 {
		return lneto.ErrInvalidConfig
	}
	var keys [32]byte // ISN key, then table key.
	if err := readKeys(cfg.Entropy, keys[:]); err != nil {
		return err
	}
	th.Abort() // Hand buffers of previous flows to the previous ReleaseBuffers.
	// New generations start past every old one so earlier handles stay stale even if flows is reallocated.
	var gen uint32
	for i := range th.flows[:cap(th.flows)] {
		gen = max(gen, th.flows[:cap(th.flows)][i].gen)
	}
	gen = nextGen(gen)
	n := int(cfg.MaxFlows)
	internal.SliceReuse(&th.flows, n)
	th.flows = th.flows[:n]
	for i := range th.flows {
		f := &th.flows[i]
		f.policy = nil
		if cfg.NewPolicy != nil {
			f.policy = cfg.NewPolicy()
		}
		f.h.SetPolicy(f.policy)
		f.h.SetLoggers(cfg.Logger, nil)
		f.state = flowFree
		f.gen = gen
	}
	th.table.reset(n, [16]byte(keys[16:]))
	th.dirty.reset(n)
	th.cursor = 0
	th.npending = 0
	th.maxPending = cfg.MaxPending
	th.txQueue = cfg.TxPacketQueueSize
	th.mono.Config(cfg.NanoTime)
	th.key = [16]byte(keys[:16])
	th.pendingTimeout = int64(cfg.PendingTimeout)
	th.closeTimeout = int64(cfg.CloseTimeout)
	th.release = cfg.ReleaseBuffers
	th.log = cfg.Logger
	return nil
}

// Abort reaps every flow. All handles become stale.
func (th *TCPHandler) Abort() {
	for slot := range th.flows {
		f := &th.flows[slot]
		th.lock(slot)
		if f.state != flowFree {
			th.reap(slot, f)
		}
		th.unlock(slot)
	}
	th.rst.len = 0
	th.nextScan = 0
	th.cursor = 0
}

// Demux processes a TCP packet. A hit feeds the flow's [tcp.Handler].
// A SYN for an unknown flow is held and returned with isNew=true: caller must Accept or Reject it.
// Other segments for unknown flows queue a stateless RST and return [lneto.ErrPacketDrop].
func (th *TCPHandler) Demux(pkt Packet) (flow TCPFlow, isNew bool, err error) {
	flow, isNew, _, err = th.demux(pkt)
	return flow, isNew, err
}

// demux is Demux also reporting whether a segment became due to send.
func (th *TCPHandler) demux(pkt Packet) (flow TCPFlow, isNew, wake bool, err error) {
	if pkt.proto != lneto.IPProtoTCP {
		return flow, false, false, lneto.ErrMismatch
	}
	k := pkt.key()
	tfrm, _ := tcp.NewFrame(pkt.buf[pkt.toff:])
	slot := th.table.lookup(&k)
	if slot < 0 {
		return th.demuxMiss(&k, tfrm)
	}
	f := &th.flows[slot]
	th.lock(slot)
	defer th.unlock(slot)
	_, flags := tfrm.OffsetAndFlags()
	if f.state == flowPending {
		if syn, _ := tcp.NewFrame(f.syn[:]); flags.HasAny(tcp.FlagRST) && tfrm.Seq() == syn.Seq()+1 {
			th.reap(slot, f) // Peer gave up while caller dials.
			return flow, false, false, nil
		}
		return flow, false, false, lneto.ErrPacketDrop // Retransmitted SYN while caller dials.
	}
	flow = TCPFlow{ID: k.id(), slot: uint16(slot), gen: f.gen}
	f.rxPkts++
	if flags.HasAny(tcp.FlagSYN) && !flags.HasAny(tcp.FlagACK) && f.h.State() == tcp.StateSynRcvd {
		f.h.RequeueControl() // Peer retransmitted its SYN: our SYN-ACK was lost.
	} else if err = f.h.Recv(tfrm.RawData()); err == net.ErrClosed {
		err = nil // Flow ended. Slot is reaped once released.
	}
	th.lowerNextScan(f.deadline())
	return flow, false, th.dirty.set(slot), err
}

// demuxMiss holds a new SYN or queues a stateless RST for a segment of an unknown flow.
func (th *TCPHandler) demuxMiss(k *flowKey, tfrm tcp.Frame) (flow TCPFlow, isNew, wake bool, err error) {
	_, flags := tfrm.OffsetAndFlags()
	switch {
	case flags.HasAny(tcp.FlagRST):
		return flow, false, false, lneto.ErrPacketDrop
	case flags.HasAny(tcp.FlagSYN) && !flags.HasAny(tcp.FlagACK):
		if th.npending >= th.maxPending {
			return flow, false, false, lneto.ErrPacketDrop // Peer retries the SYN.
		}
		slot := th.table.insert(k)
		if slot < 0 {
			return flow, false, false, lneto.ErrPacketDrop
		}
		now := th.mono.Nanotime()
		f := &th.flows[slot]
		th.lock(slot)
		copy(f.syn[:], tfrm.RawData()[:tfrm.HeaderLength()])
		f.state = flowPending
		f.at = now
		f.rxPkts = 1
		f.txPkts = 0
		flow = TCPFlow{ID: k.id(), slot: uint16(slot), gen: f.gen}
		th.unlock(slot)
		th.npending++
		th.lowerNextScan(now + th.pendingTimeout)
		return flow, true, false, nil
	case flags.HasAny(tcp.FlagACK):
		th.rst.queue(k, tfrm.Ack(), 0, tcp.FlagRST)
	default:
		seg := tfrm.Segment(len(tfrm.Payload()))
		th.rst.queue(k, 0, seg.SEQ+tcp.Value(seg.LEN()), tcp.FlagRST|tcp.FlagACK)
	}
	return flow, false, true, lneto.ErrPacketDrop
}

// Accept opens the held SYN's flow with the given buffers and queues the SYN-ACK.
// nil buffers reuse the slot's previous ones. On failure a RST is queued and the slot freed;
// rxbuf and txbuf stay the caller's and are not passed to ReleaseBuffers.
func (th *TCPHandler) Accept(flow TCPFlow, rxbuf, txbuf []byte) error {
	f, err := th.lockFlow(flow)
	if err != nil {
		return err
	}
	defer th.unlock(int(flow.slot))
	slot := int(flow.slot)
	if f.state != flowPending {
		return lneto.ErrBadState
	}
	if rxbuf == nil {
		rxbuf = f.rx
	}
	if txbuf == nil {
		txbuf = f.tx
	}
	if err = th.open(slot, f, rxbuf, txbuf); err != nil {
		f.h.Abort()
		th.rejectLocked(slot, f)
		return err
	}
	th.npending--
	f.state = flowOpen
	f.rx, f.tx = rxbuf, txbuf
	f.at = th.mono.Nanotime()
	th.lowerNextScan(f.at + th.pendingTimeout) // Handshake timeout.
	th.dirty.set(slot)
	return nil
}

// open starts f's Handler on the buffers and replays the held SYN, readying the SYN-ACK. Must hold the slot lock.
func (th *TCPHandler) open(slot int, f *tcpFlow, rxbuf, txbuf []byte) error {
	if rxbuf == nil || txbuf == nil {
		return lneto.ErrShortBuffer
	}
	err := f.h.SetBuffers(txbuf, rxbuf, th.txQueue)
	if err != nil {
		return err
	}
	k := &th.table.keys[slot]
	laddr, raddr := k.addrs()
	err = f.h.OpenListen(k.lport, tcp.ISN(&th.key, th.mono.Nanotime(), laddr, raddr, k.lport, k.rport))
	if err != nil {
		return err
	}
	syn, _ := tcp.NewFrame(f.syn[:])
	return f.h.Recv(f.syn[:syn.HeaderLength()])
}

// Reject refuses the held SYN with RST|ACK and frees its slot.
func (th *TCPHandler) Reject(flow TCPFlow) error {
	f, err := th.lockFlow(flow)
	if err != nil {
		return err
	}
	defer th.unlock(int(flow.slot))
	if f.state != flowPending {
		return lneto.ErrBadState
	}
	th.rejectLocked(int(flow.slot), f)
	return nil
}

// rejectLocked queues RST|ACK for f's held SYN and frees slot. Must hold the slot lock.
func (th *TCPHandler) rejectLocked(slot int, f *tcpFlow) {
	syn, _ := tcp.NewFrame(f.syn[:])
	th.rst.queue(&th.table.keys[slot], 0, syn.Seq()+1, tcp.FlagRST|tcp.FlagACK)
	th.reap(slot, f)
}

// abortLocked queues RST|ACK for a synchronizing or synchronized flow and aborts its
// Handler, keeping the slot so flow calls return [net.ErrClosed] until Release. Must hold the slot lock.
func (th *TCPHandler) abortLocked(slot int, f *tcpFlow) {
	if st := f.h.State(); !st.IsClosed() && st != tcp.StateListen {
		tcb := f.h.ControlBlock()
		th.rst.queue(&th.table.keys[slot], tcb.SendNext(), tcb.RecvNext(), tcp.FlagRST|tcp.FlagACK)
	}
	f.h.Abort()
	th.dirty.clear(slot)
}

// reap frees slot and invalidates its handles. Accepted flows are aborted
// and their buffers handed to ReleaseBuffers. Must hold the slot lock.
func (th *TCPHandler) reap(slot int, f *tcpFlow) {
	if f.state == flowPending {
		th.npending--
	} else {
		f.h.Abort()
		if th.release != nil {
			th.release(f.rx, f.tx)
			f.rx, f.tx = nil, nil
		}
	}
	f.state = flowFree
	f.gen = nextGen(f.gen)
	th.table.remove(slot)
	th.dirty.clear(slot)
}

// Encapsulate writes the next IP+TCP packet to carrierData[offsetToIP:] and returns its length, 0 when idle.
// len(carrierData[offsetToIP:]) capped at 65535 is taken as the MTU; the SYN-ACK MSS derives from it.
func (th *TCPHandler) Encapsulate(carrierData []byte, offsetToIP int) (int, error) {
	if offsetToIP < 0 || len(carrierData)-offsetToIP < minTCPCarrier {
		return 0, lneto.ErrShortBuffer
	}
	pkt := carrierData[offsetToIP:min(len(carrierData), offsetToIP+math.MaxUint16)]
	if now := th.mono.Nanotime(); th.nextScan != 0 && now >= th.nextScan {
		th.maintain(now)
	}
	nflows := len(th.flows)
	start := int(th.cursor)
	for range nflows {
		slot := th.dirty.next(start)
		if slot < 0 {
			break
		}
		start = (slot + 1) % nflows
		if n := th.encapsulateFlow(slot, pkt); n > 0 {
			th.cursor = uint16(start) // One segment per flow per pass.
			return n, nil
		}
	}
	// Stateless RSTs go once flows are idle so junk segments cannot starve them; a full queue drops extras.
	if th.rst.len > 0 {
		th.ipID = internal.Prand16(th.ipID + 1)
		return th.rst.drain(pkt, th.ipID), nil
	}
	return 0, nil
}

// encapsulateFlow writes slot's next segment as an IP packet into pkt and returns its length.
// It clears the slot's dirty bit when nothing is left to send and reaps released flows that are done.
func (th *TCPHandler) encapsulateFlow(slot int, pkt []byte) int {
	f := &th.flows[slot]
	th.lock(slot)
	defer th.unlock(slot)
	if f.state == flowFree || f.state == flowPending {
		th.dirty.clear(slot)
		return 0
	}
	id := internal.Prand16(th.ipID + 1)
	hl := putIPHeader(pkt, &th.table.keys[slot], lneto.IPProtoTCP, id)
	n, _ := f.h.Send(pkt[hl:])
	if n == 0 {
		th.dirty.clear(slot)
		if f.state == flowReleased && f.h.IsTxOver() {
			th.reap(slot, f)
		}
		return 0
	}
	th.ipID = id
	finishIP(pkt, hl, n, lneto.IPProtoTCP)
	f.txPkts++
	th.lowerNextScan(f.deadline())
	return hl + n
}

// maintain expires held SYNs, reaps released flows that are done or past CloseTimeout,
// flags flows whose Policy timer is due and recomputes nextScan.
// Due timers do not feed nextScan so a timer that sends nothing cannot spin the pump.
func (th *TCPHandler) maintain(now int64) {
	th.nextScan = 0
	for slot := range th.flows {
		f := &th.flows[slot]
		th.lock(slot)
		switch {
		case f.state == flowFree:
		case f.state == flowPending:
			if expiry := f.at + th.pendingTimeout; now >= expiry {
				th.rejectLocked(slot, f)
			} else {
				th.lowerNextScan(expiry)
			}
		case f.state == flowReleased && (now >= f.at+th.closeTimeout || f.h.IsTxOver()):
			th.abortLocked(slot, f) // RST unless the close completed.
			th.reap(slot, f)
		case f.state == flowOpen && f.h.State() == tcp.StateSynRcvd && now >= f.at+th.pendingTimeout:
			th.abortLocked(slot, f) // Peer never completed the handshake.
		default:
			if f.state == flowReleased {
				th.lowerNextScan(f.at + th.closeTimeout)
			} else if f.h.State() == tcp.StateSynRcvd {
				th.lowerNextScan(f.at + th.pendingTimeout)
			}
			if d := f.deadline(); d != 0 && d <= now {
				th.dirty.set(slot)
			} else {
				th.lowerNextScan(d)
			}
		}
		th.unlock(slot)
	}
}

// lowerNextScan makes Encapsulate run maintenance at t if earlier than already due. Zero t is ignored.
func (th *TCPHandler) lowerNextScan(t int64) {
	if t != 0 && (th.nextScan == 0 || t < th.nextScan) {
		th.nextScan = t
	}
}

// NextDeadline returns the earliest pending timer in monotonic nanoseconds, or 0 if none.
// Calling Encapsulate once it passes drives retransmits and timeouts.
func (th *TCPHandler) NextDeadline() int64 {
	return th.nextScan
}

// Read reads received flow data into b. Returns 0, nil when none is buffered and io.EOF after the peer's FIN.
func (th *TCPHandler) Read(flow TCPFlow, b []byte) (int, error) {
	n, kick, err := th.read(flow, b)
	if kick {
		th.dirty.set(int(flow.slot))
	}
	return n, err
}

// Write queues b for sending on flow. Short writes happen when the tx buffer is full.
func (th *TCPHandler) Write(flow TCPFlow, b []byte) (int, error) {
	n, kick, err := th.write(flow, b)
	if kick {
		th.dirty.set(int(flow.slot))
	}
	return n, err
}

// read is Read reporting whether reading queued a window update, leaving dirty untouched.
// Touches only flow's slot, so TCPForwarder runs it under the slot lock alone.
func (th *TCPHandler) read(flow TCPFlow, b []byte) (n int, kick bool, err error) {
	f, err := th.lockFlow(flow)
	if err != nil {
		return 0, false, err
	}
	defer th.unlock(int(flow.slot))
	if f.state == flowPending {
		return 0, false, lneto.ErrBadState
	} else if f.h.State().IsPreestablished() {
		return 0, false, nil // Handshake in progress: nothing to read yet.
	}
	n, err = f.h.Read(b)
	return n, n > 0 && f.h.ControlBlock().HasPending(), err
}

// write is Write reporting whether data was queued, leaving dirty untouched.
// Touches only flow's slot, so TCPForwarder runs it under the slot lock alone.
func (th *TCPHandler) write(flow TCPFlow, b []byte) (n int, kick bool, err error) {
	f, err := th.lockFlow(flow)
	if err != nil {
		return 0, false, err
	}
	defer th.unlock(int(flow.slot))
	if f.state == flowPending {
		return 0, false, lneto.ErrBadState
	} else if f.h.State().IsPreestablished() {
		return 0, false, nil // Handshake in progress: data cannot be queued yet.
	}
	towrite := min(len(b), f.h.FreeOutput())
	if towrite == 0 {
		if !f.h.State().TxDataOpen() {
			return 0, false, net.ErrClosed
		}
		return 0, false, nil // Tx buffer full or b empty.
	}
	n, err = f.h.Write(b[:towrite])
	return n, n > 0, err
}

// CloseWrite queues a FIN once buffered data is sent. Reads keep working.
func (th *TCPHandler) CloseWrite(flow TCPFlow) error {
	f, err := th.lockFlow(flow)
	if err != nil {
		return err
	}
	defer th.unlock(int(flow.slot))
	switch f.state {
	case flowPending:
		return lneto.ErrBadState
	case flowReleased:
		return net.ErrClosed
	}
	err = f.h.Close()
	th.dirty.set(int(flow.slot))
	return err
}

// Release closes flow and discards further received data. The slot is reaped once sending ends.
func (th *TCPHandler) Release(flow TCPFlow) error {
	f, err := th.lockFlow(flow)
	if err != nil {
		return err
	}
	defer th.unlock(int(flow.slot))
	slot := int(flow.slot)
	switch f.state {
	case flowPending:
		return lneto.ErrBadState
	case flowReleased:
		return net.ErrClosed
	}
	f.h.Close() // Queues FIN unless already closing or closed.
	f.h.ShutdownRead()
	if f.h.IsTxOver() {
		th.reap(slot, f)
		return nil
	}
	f.state = flowReleased
	f.at = th.mono.Nanotime()
	th.lowerNextScan(f.at + th.closeTimeout)
	th.dirty.set(slot)
	return nil
}

// Stats returns the number of segments received and sent on flow.
func (th *TCPHandler) Stats(flow TCPFlow) (rxPkts, txPkts uint32, err error) {
	f, err := th.lockFlow(flow)
	if err != nil {
		return 0, 0, err
	}
	defer th.unlock(int(flow.slot))
	return f.rxPkts, f.txPkts, nil
}

// lockFlow returns flow's slot locked, or net.ErrClosed if the handle is stale.
// Caller unlocks with th.unlock(flow.Slot()).
func (th *TCPHandler) lockFlow(flow TCPFlow) (*tcpFlow, error) {
	slot := int(flow.slot)
	if slot >= len(th.flows) {
		return nil, net.ErrClosed
	}
	f := &th.flows[slot]
	th.lock(slot)
	if f.gen != flow.gen || f.state == flowFree {
		th.unlock(slot)
		return nil, net.ErrClosed
	}
	return f, nil
}

// deadline returns the flow Policy's next timer, or 0 if none. Must hold the slot lock.
func (f *tcpFlow) deadline() int64 {
	if dp, ok := f.policy.(interface{ NextDeadline() int64 }); ok {
		return dp.NextDeadline()
	}
	return 0
}

// bitset is a bitset over flow slots.
type bitset []uint32

// reset sizes the set for n slots and clears every bit.
func (bs *bitset) reset(n int) {
	words := (n + 31) / 32
	internal.SliceReuse((*[]uint32)(bs), words)
	*bs = (*bs)[:words]
	clear(*bs)
}

// set raises bit i and reports whether it was clear.
func (bs bitset) set(i int) (wasClear bool) {
	w, bit := &bs[i>>5], uint32(1)<<(i&31)
	wasClear = *w&bit == 0
	*w |= bit
	return wasClear
}

// clear lowers bit i.
func (bs bitset) clear(i int) { bs[i>>5] &^= uint32(1) << (i & 31) }

// next returns the first set bit at or after start, wrapping around, or -1 if none is set.
func (bs bitset) next(start int) int {
	nw := len(bs)
	first := start >> 5
	for k := 0; k <= nw && nw > 0; k++ {
		wi := (first + k) % nw
		word := bs[wi]
		switch k {
		case 0:
			word &= ^uint32(0) << (start & 31) // Bits at or after start.
		case nw:
			word &= uint32(1)<<(start&31) - 1 // Wrapped back: bits before start.
		}
		if word != 0 {
			return wi<<5 + bits.TrailingZeros32(word)
		}
	}
	return -1
}

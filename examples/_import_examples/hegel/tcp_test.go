package hegel_test

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/tcp/rto"
	"hegel.dev/go/hegel"
)

var (
	cases = flag.Int("cases", 1000, "generated cases for Hegel and the random baseline")
	steps = flag.Int("steps", 100, "maximum generated actions per case")
	seed  = flag.Int64("seed", 42, "generation seed")
)

type tcpMachine struct {
	fail        func(string, ...any)
	peers       [2]tcp.Handler
	now         int64
	want        []byte
	read        []byte
	serial      byte
	queue       []packet
	trace       []string
	rejected    [2]int
	policyAbort bool
	closed      [2]bool // Close called on the peer.
}

type packet struct {
	side int
	data []byte
}

func newTCPMachine(t testing.TB, iss tcp.Value) *tcpMachine {
	m := &tcpMachine{fail: t.Fatalf}
	for i := range m.peers {
		h := &m.peers[i]
		if err := h.SetBuffers(make([]byte, 256), make([]byte, 256), 8); err != nil {
			t.Fatal(err)
		}
		timer := new(rto.Timer)
		if err := timer.Configure(func() int64 { return m.now }); err != nil {
			t.Fatal(err)
		}
		h.SetPolicy(timer)
	}
	if err := m.peers[1].OpenListen(80, iss+1000); err != nil {
		t.Fatal(err)
	}
	if err := m.peers[0].OpenActive(81, 80, iss); err != nil {
		t.Fatal(err)
	}
	for _, side := range []int{0, 1, 0} {
		m.transfer(side)
	}
	m.check()
	return m
}

func (m *tcpMachine) write(n int) {
	if m.closed[0] {
		if written, err := m.peers[0].Write([]byte{m.serial}); err == nil || written != 0 {
			m.fail("Write after Close = %d, %v in %s; want an error; trace=%v", written, err, m.peers[0].State(), m.trace)
		}
		return
	}
	data := make([]byte, min(n, m.peers[0].FreeOutput()))
	if len(data) == 0 {
		return
	}
	for i := range data {
		data[i] = m.serial
		m.serial++
	}
	written, err := m.peers[0].Write(data)
	if err != nil || written != len(data) {
		m.fail("Write = %d, %v; want %d; trace=%v", written, err, len(data), m.trace)
	}
	m.want = append(m.want, data...)
}

func (m *tcpMachine) emit(side int) (sent bool) {
	if len(m.queue) == 16 {
		return false
	}
	var buf [128]byte
	n, err := m.peers[side].Send(buf[:])
	state := m.peers[side].State()
	if errors.Is(err, lneto.ErrBufferFull) ||
		errors.Is(err, net.ErrClosed) && m.closed[side] && (state == tcp.StateClosed || state == tcp.StateTimeWait) {
		return false // Nothing to send, or the close is complete.
	}
	if err != nil {
		m.fail("Send: %v; trace=%v", err, m.trace)
	}
	if n > 0 {
		m.queue = append(m.queue, packet{side: side, data: bytes.Clone(buf[:n])})
	}
	return n > 0
}

func (m *tcpMachine) deliver(index int, duplicate bool) {
	if len(m.queue) == 0 {
		return
	}
	index %= len(m.queue)
	p := m.queue[index]
	if !duplicate {
		m.queue = append(m.queue[:index], m.queue[index+1:]...)
	}
	receiver := 1 - p.side
	h := &m.peers[receiver]
	frm, err := tcp.NewFrame(p.data)
	if err != nil {
		m.fail("generated invalid frame: %v", err)
	}
	next := h.ControlBlock().RecvNext()
	err = h.Recv(p.data)
	var rejected *tcp.RejectError
	if errors.Is(err, net.ErrClosed) && h.State() == tcp.StateClosed && frm.Seq() != next && m.rejected[receiver] >= 8 {
		m.policyAbort = true
		return
	}
	if errors.As(err, &rejected) && frm.Seq() != next {
		m.rejected[receiver]++
	} else if err == nil && (h.ControlBlock().RecvNext() != next || frm.Seq() == next) {
		m.rejected[receiver] = 0
	}
	// net.ErrClosed reports a clean close completing, as on the final ACK in
	// LAST-ACK. The Handler also releases the connection on entering TIME-WAIT,
	// having no 2MSL timer, so a retransmitted FIN there is refused unanswered.
	cleanClose := errors.Is(err, net.ErrClosed) && m.closed[receiver] &&
		(h.State() == tcp.StateClosed || h.State() == tcp.StateTimeWait)
	// ErrPacketDrop is a silent drop, as of an old duplicate; liveness is checked by finish.
	dropped := errors.Is(err, lneto.ErrPacketDrop) || errors.Is(err, lneto.ErrBufferFull)
	if err != nil && !cleanClose && !dropped && !errors.As(err, &rejected) {
		m.fail("Recv: %v; receiver=%d in %s, closed=%v, segment %v; trace=%v", err, receiver, h.State(), m.closed, frm.Segment(len(frm.Payload())), m.trace)
	}
}

func (m *tcpMachine) transfer(side int) (sent bool) {
	sent = m.emit(side)
	m.deliver(0, false)
	return sent
}

func (m *tcpMachine) step(action, value int) {
	if m.policyAbort {
		return
	}
	m.trace = append(m.trace, fmt.Sprintf("%s(%d)", actions[action], value))
	switch action {
	case 0:
		m.write(1 + value%64)
	case 1, 2:
		m.emit(action - 1)
	case 3, 4:
		m.deliver(value, action == 4)
	case 5:
		if len(m.queue) > 0 {
			i := value % len(m.queue)
			m.queue = append(m.queue[:i], m.queue[i+1:]...)
		}
	case 6:
		m.readData(1 + value%256)
	case 7:
		m.now += int64(1+value%60) * 1e9
	case 8, 9:
		side := action - 8
		if !m.closed[side] {
			if err := m.peers[side].Close(); err != nil {
				m.fail("Close: %v; trace=%v", err, m.trace)
			}
			m.closed[side] = true
		}
	}
}

var actions = [...]string{"write", "send-data", "send-ACK", "deliver", "duplicate", "drop", "read", "advance", "close-client", "close-server"}

func (m *tcpMachine) readData(n int) {
	buf := make([]byte, min(n, m.peers[1].BufferedInput()))
	n, err := m.peers[1].Read(buf)
	if err == io.EOF && !(m.closed[0] && len(m.read)+n == len(m.want)) {
		m.fail("Read returned EOF after %d of %d bytes, client closed=%v; trace=%v", len(m.read)+n, len(m.want), m.closed[0], m.trace)
	} else if err != nil && err != io.EOF {
		m.fail("Read: %v; trace=%v", err, m.trace)
	}
	m.read = append(m.read, buf[:n]...)
}

func (m *tcpMachine) check() {
	if len(m.read) > len(m.want) || !bytes.Equal(m.read, m.want[:len(m.read)]) {
		m.fail("stream mismatch: read=%x want=%x; trace=%v", m.read, m.want, m.trace)
	}
	for i := range m.peers {
		if !m.policyAbort && !m.closed[0] && !m.closed[1] && m.peers[i].State() != tcp.StateEstablished {
			m.fail("peer %d: %s; trace=%v", i, m.peers[i].State(), m.trace)
		}
		if m.peers[i].BufferedInput() > 256 || m.peers[i].BufferedUnsent() > 256 || m.peers[i].FreeInput() < 0 || m.peers[i].FreeOutput() < 0 {
			m.fail("peer %d: buffers exceed capacity; trace=%v", i, m.trace)
		}
	}
}

func (m *tcpMachine) finish() {
	for range 200 {
		if m.policyAbort {
			m.check()
			return
		}
		for len(m.queue) > 0 {
			m.deliver(0, false)
			if m.policyAbort {
				m.check()
				return
			}
		}
		m.readData(256)
		sent := m.transfer(0)
		if m.policyAbort {
			m.check()
			return
		}
		sent = m.transfer(1) || sent
		m.readData(256)
		m.now += 60e9
		m.check()
		acked := func(i int) bool { return m.peers[i].ControlBlock().SendUNA() == m.peers[i].ControlBlock().SendNext() }
		drained := len(m.read) == len(m.want) && m.peers[1].BufferedInput() == 0
		if drained && (!sent && acked(0) && acked(1) || m.timeWaitGap()) {
			m.checkClosed()
			return
		}
	}
	m.fail("stream did not drain: client=%s server=%s read=%d want=%d UNA=%d NXT=%d RCV.NXT=%d unsent=%d buffered=%d rejections=%v; trace=%v", m.peers[0].State(), m.peers[1].State(), len(m.read), len(m.want), m.peers[0].ControlBlock().SendUNA(), m.peers[0].ControlBlock().SendNext(), m.peers[1].ControlBlock().RecvNext(), m.peers[0].BufferedUnsent(), m.peers[1].BufferedInput(), m.rejected, m.trace)
}

// timeWaitGap reports one peer in TIME-WAIT and the other still waiting for the
// ACK of its FIN. The Handler in TIME-WAIT no longer answers a retransmitted
// FIN (see deliver), so a lost final ACK leaves the other side there.
func (m *tcpMachine) timeWaitGap() bool {
	for i := range m.peers {
		other := m.peers[1-i].State()
		if m.peers[i].State() == tcp.StateTimeWait && (other == tcp.StateLastAck || other == tcp.StateClosing) {
			return true
		}
	}
	return false
}

// checkClosed checks, once traffic has settled, that a closed client's data
// ends in EOF and that the peers are in the states RFC 9293 §3.6 leads to.
func (m *tcpMachine) checkClosed() {
	if m.closed[0] {
		if n, err := m.peers[1].Read(make([]byte, 1)); n != 0 || err != io.EOF {
			m.fail("Read after the client's FIN = %d, %v; want EOF; trace=%v", n, err, m.trace)
		}
	}
	client, server := m.peers[0].State(), m.peers[1].State()
	done := func(s tcp.State) bool { return s == tcp.StateTimeWait || s == tcp.StateClosed }
	var ok bool
	switch m.closed {
	case [2]bool{}:
		ok = client == tcp.StateEstablished && server == tcp.StateEstablished
	case [2]bool{true, false}:
		ok = client == tcp.StateFinWait2 && server == tcp.StateCloseWait
	case [2]bool{false, true}:
		ok = client == tcp.StateCloseWait && server == tcp.StateFinWait2
	default:
		ok = done(client) && done(server) || m.timeWaitGap()
	}
	if !ok {
		m.fail("settled in client=%s server=%s after closes %v; trace=%v", client, server, m.closed, m.trace)
	}
}

func (m *tcpMachine) run(tc hegel.TestCase, action, value int) {
	m.fail = tc.Errorf
	m.step(action, value)
}

func (m *tcpMachine) RuleWrite(tc hegel.TestCase) {
	m.run(tc, 0, hegel.Draw(tc, hegel.Integers(0, 255)))
}
func (m *tcpMachine) RuleSendData(tc hegel.TestCase) { m.run(tc, 1, 0) }
func (m *tcpMachine) RuleSendACK(tc hegel.TestCase)  { m.run(tc, 2, 0) }
func (m *tcpMachine) RuleDeliver(tc hegel.TestCase) {
	m.run(tc, 3, hegel.Draw(tc, hegel.Integers(0, 15)))
}
func (m *tcpMachine) RuleDuplicate(tc hegel.TestCase) {
	m.run(tc, 4, hegel.Draw(tc, hegel.Integers(0, 15)))
}
func (m *tcpMachine) RuleDrop(tc hegel.TestCase) { m.run(tc, 5, hegel.Draw(tc, hegel.Integers(0, 15))) }
func (m *tcpMachine) RuleRead(tc hegel.TestCase) {
	m.run(tc, 6, hegel.Draw(tc, hegel.Integers(0, 255)))
}
func (m *tcpMachine) RuleAdvance(tc hegel.TestCase) {
	m.run(tc, 7, hegel.Draw(tc, hegel.Integers(0, 59)))
}
func (m *tcpMachine) RuleCloseClient(tc hegel.TestCase) { m.run(tc, 8, 0) }
func (m *tcpMachine) RuleCloseServer(tc hegel.TestCase) { m.run(tc, 9, 0) }
func (m *tcpMachine) InvariantStream(tc hegel.TestCase) {
	m.fail = tc.Errorf
	m.check()
}

func TestTCPStateful(t *testing.T) {
	var generated, actions, written int
	hegel.Test(t, func(ht *hegel.T) {
		m := newTCPMachine(ht, tcp.Value(hegel.Draw(ht, hegel.Integers(0, 1<<32-1))))
		hegel.RunStateful(ht, m, hegel.WithStatefulStepCount(*steps), hegel.WithAlwaysCheckInvariants("InvariantStream"))
		m.fail = ht.Errorf
		m.finish()
		generated++
		actions += len(m.trace)
		written += len(m.want)
		if m.policyAbort {
			ht.Event("challenge-ACK-policy-abort")
		} else if len(m.want) > 0 {
			ht.Event("data-transferred")
		} else {
			ht.Event("no-data")
		}
	}, hegel.WithTestCases(*cases), hegel.WithSeed(*seed), hegel.WithDatabase(""), hegel.WithStatistics(true))
	t.Logf("cases=%d actions=%d accepted-bytes=%d", generated, actions, written)
}

func TestTCPRandomBaseline(t *testing.T) {
	rng := rand.New(rand.NewPCG(uint64(*seed), 1))
	var count, written, aborted int
	for range *cases {
		m := newTCPMachine(t, tcp.Value(rng.Uint32()))
		for range *steps {
			m.step(rng.IntN(len(actions)), rng.IntN(256))
			m.check()
		}
		m.finish()
		count += len(m.trace)
		written += len(m.want)
		if m.policyAbort {
			aborted++
		}
	}
	t.Logf("cases=%d actions=%d accepted-bytes=%d policy-aborts=%d", *cases, count, written, aborted)
}

func FuzzTCPActions(f *testing.F) {
	f.Add(uint32(100), []byte{0, 63, 1, 0, 3, 0, 2, 0, 3, 0, 6, 63})
	f.Fuzz(func(t *testing.T, iss uint32, data []byte) {
		m := newTCPMachine(t, tcp.Value(iss))
		for i := 0; i+1 < min(len(data), 2**steps); i += 2 {
			m.step(int(data[i])%len(actions), int(data[i+1]))
			m.check()
		}
		m.finish()
	})
}

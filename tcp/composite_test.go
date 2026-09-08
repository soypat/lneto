package tcp

import (
	"math/rand"
	"testing"

	"github.com/soypat/lneto/ethernet"
)

// stubPolicy is a Policy whose every hook result is dictated by the test, so the
// composite's merge rules can be checked in isolation from any real algorithm.
type stubPolicy struct {
	name     string
	deadline int64
	keep     bool
	dir      TxDirective
	opts     []byte

	// Observations.
	resets  int
	preRx   int
	postRx  int
	preTx   int
	postTx  int
	written int
}

func newStub(name string) *stubPolicy { return &stubPolicy{name: name, keep: true} }

func (s *stubPolicy) Reset()                     { s.resets++ }
func (s *stubPolicy) NextDeadline() int64        { return s.deadline }
func (s *stubPolicy) PostRx(RxEvent)             { s.postRx++ }
func (s *stubPolicy) PostTx(Segment, int64)      { s.postTx++ }
func (s *stubPolicy) PreRx(RxMeta) RxDirective   { s.preRx++; return RxDirective{Keep: s.keep} }
func (s *stubPolicy) PreTx(TxIntent) TxDirective { s.preTx++; return s.dir }

func (s *stubPolicy) WriteOptions(plan TxPlan, opts []byte) uint8 {
	s.written = len(opts) // Records the space this policy was offered.
	if len(s.opts) == 0 || len(opts) < len(s.opts) {
		return 0
	}
	return uint8(copy(opts, s.opts))
}

// TestComposite_FansOutEveryHook verifies each hook reaches every composed policy.
func TestComposite_FansOutEveryHook(t *testing.T) {
	a, b := newStub("a"), newStub("b")
	var c Composite
	for _, p := range []*stubPolicy{a, b} {
		if err := c.Add(p); err != nil {
			t.Fatal(err)
		}
	}
	if c.Len() != 2 {
		t.Fatalf("Len=%d, want 2", c.Len())
	}
	c.Reset()
	c.PreRx(RxMeta{})
	c.PostRx(RxEvent{})
	c.PreTx(TxIntent{})
	c.PostTx(Segment{}, 1)
	var opts [8]byte
	c.WriteOptions(TxPlan{}, opts[:])
	for _, p := range []*stubPolicy{a, b} {
		if p.resets != 1 || p.preRx != 1 || p.postRx != 1 || p.preTx != 1 || p.postTx != 1 {
			t.Errorf("policy %s missed a hook: reset=%d preRx=%d postRx=%d preTx=%d postTx=%d",
				p.name, p.resets, p.preRx, p.postRx, p.preTx, p.postTx)
		}
	}
}

// TestComposite_AddLimit verifies the fixed storage is enforced rather than
// silently dropping a policy that would never be driven.
func TestComposite_AddLimit(t *testing.T) {
	var c Composite
	for i := range MaxComposedPolicies {
		if err := c.Add(newStub("p")); err != nil {
			t.Fatalf("Add %d: %v", i, err)
		}
	}
	if err := c.Add(newStub("overflow")); err == nil {
		t.Error("adding past the limit must fail rather than be ignored")
	}
	if err := c.Add(nil); err == nil {
		t.Error("adding nil must fail rather than panic on the datapath")
	}
	if c.Len() != MaxComposedPolicies {
		t.Errorf("Len=%d, want %d", c.Len(), MaxComposedPolicies)
	}
}

// TestComposite_EarliestDeadlineWins verifies the connection is serviced when the
// first policy needs it, and that a policy with no deadline does not suppress one.
func TestComposite_EarliestDeadlineWins(t *testing.T) {
	for _, test := range []struct {
		name      string
		deadlines []int64
		want      int64
	}{
		{"none", []int64{0, 0}, 0},
		{"one", []int64{0, 500}, 500},
		{"earliest first", []int64{300, 900}, 300},
		{"earliest last", []int64{900, 300}, 300},
		{"zero must not win", []int64{0, 900}, 900},
	} {
		t.Run(test.name, func(t *testing.T) {
			var c Composite
			for _, d := range test.deadlines {
				s := newStub("p")
				s.deadline = d
				if err := c.Add(s); err != nil {
					t.Fatal(err)
				}
			}
			if got := c.NextDeadline(); got != test.want {
				t.Errorf("NextDeadline=%d, want %d", got, test.want)
			}
		})
	}
}

// TestComposite_AnyPolicyMayDrop verifies a single rejection drops the segment and
// that every policy is still consulted, so what a policy observes does not depend
// on the order it was added in.
func TestComposite_AnyPolicyMayDrop(t *testing.T) {
	for _, test := range []struct {
		name string
		keep []bool
		want bool
	}{
		{"all keep", []bool{true, true}, true},
		{"first drops", []bool{false, true}, false},
		{"second drops", []bool{true, false}, false},
		{"both drop", []bool{false, false}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var c Composite
			var stubs []*stubPolicy
			for _, k := range test.keep {
				s := newStub("p")
				s.keep = k
				stubs = append(stubs, s)
				if err := c.Add(s); err != nil {
					t.Fatal(err)
				}
			}
			if got := c.PreRx(RxMeta{}).Keep; got != test.want {
				t.Errorf("Keep=%v, want %v", got, test.want)
			}
			for i, s := range stubs {
				if s.preRx != 1 {
					t.Errorf("policy %d saw PreRx %d times, want 1 even after a rejection", i, s.preRx)
				}
			}
		})
	}
}

// TestComposite_MergesTxDirectives verifies the transmit merge rule: retransmit and
// hold are the logical or, and the lowest requested sequence number wins so a
// policy asking to resend from further back is not narrowed by another.
func TestComposite_MergesTxDirectives(t *testing.T) {
	for _, test := range []struct {
		name string
		dirs []TxDirective
		want TxDirective
	}{
		{"nothing", []TxDirective{{}, {}}, TxDirective{}},
		{"hold propagates", []TxDirective{{}, {HoldNew: true}}, TxDirective{HoldNew: true}},
		{
			"single retransmit",
			[]TxDirective{{}, {Retransmit: true, RetransmitFrom: 500}},
			TxDirective{Retransmit: true, RetransmitFrom: 500},
		},
		{
			"lowest wins, lower first",
			[]TxDirective{{Retransmit: true, RetransmitFrom: 300}, {Retransmit: true, RetransmitFrom: 800}},
			TxDirective{Retransmit: true, RetransmitFrom: 300},
		},
		{
			"lowest wins, lower last",
			[]TxDirective{{Retransmit: true, RetransmitFrom: 800}, {Retransmit: true, RetransmitFrom: 300}},
			TxDirective{Retransmit: true, RetransmitFrom: 300},
		},
		{
			"a non-retransmitter must not contribute its zero sequence",
			[]TxDirective{{HoldNew: true}, {Retransmit: true, RetransmitFrom: 800}},
			TxDirective{Retransmit: true, RetransmitFrom: 800, HoldNew: true},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var c Composite
			for _, d := range test.dirs {
				s := newStub("p")
				s.dir = d
				if err := c.Add(s); err != nil {
					t.Fatal(err)
				}
			}
			if got := c.PreTx(TxIntent{}); got != test.want {
				t.Errorf("PreTx=%+v, want %+v", got, test.want)
			}
		})
	}
}

// TestComposite_RetransmitFromWrapsInSequenceSpace verifies the lowest-wins rule is
// a sequence comparison and not an integer one. Across the 32-bit wrap the numerically
// larger value is the earlier sequence, and picking the smaller integer would rewind
// the connection forward by nearly 4 GiB.
func TestComposite_RetransmitFromWrapsInSequenceSpace(t *testing.T) {
	const nearWrap Value = 0xFFFF_FF00 // Earlier in sequence space.
	const afterWrap Value = 0x0000_0100
	var c Composite
	for _, from := range []Value{afterWrap, nearWrap} {
		s := newStub("p")
		s.dir = TxDirective{Retransmit: true, RetransmitFrom: from}
		if err := c.Add(s); err != nil {
			t.Fatal(err)
		}
	}
	got := c.PreTx(TxIntent{})
	if got.RetransmitFrom != nearWrap {
		t.Errorf("RetransmitFrom=%#x, want %#x (the earlier sequence across the wrap)", got.RetransmitFrom, nearWrap)
	}
}

// TestComposite_WriteOptionsSharesSpace verifies each policy is offered what its
// predecessors left and the lengths are summed, which is what lets two
// option-writing extensions coexist.
func TestComposite_WriteOptionsSharesSpace(t *testing.T) {
	a, b := newStub("a"), newStub("b")
	a.opts = []byte{1, 1, 1, 1}
	b.opts = []byte{2, 2}
	var c Composite
	for _, p := range []*stubPolicy{a, b} {
		if err := c.Add(p); err != nil {
			t.Fatal(err)
		}
	}
	var opts [10]byte
	n := c.WriteOptions(TxPlan{}, opts[:])
	if n != 6 {
		t.Fatalf("wrote %d octets, want 6", n)
	}
	want := [10]byte{1, 1, 1, 1, 2, 2, 0, 0, 0, 0}
	if opts != want {
		t.Errorf("option area = %v, want %v", opts, want)
	}
	if a.written != 10 {
		t.Errorf("first policy offered %d octets, want the whole area (10)", a.written)
	}
	if b.written != 6 {
		t.Errorf("second policy offered %d octets, want what was left (6)", b.written)
	}
}

// TestComposite_WriteOptionsRespectsRemainingSpace verifies a policy that does not
// fit in what is left writes nothing, rather than the composite reporting a length
// past the end of the option area.
func TestComposite_WriteOptionsRespectsRemainingSpace(t *testing.T) {
	a, b := newStub("a"), newStub("b")
	a.opts = []byte{1, 1, 1, 1}
	b.opts = []byte{2, 2, 2, 2} // Only 2 octets will be left.
	var c Composite
	for _, p := range []*stubPolicy{a, b} {
		if err := c.Add(p); err != nil {
			t.Fatal(err)
		}
	}
	var opts [6]byte
	n := c.WriteOptions(TxPlan{}, opts[:])
	if n != 4 {
		t.Errorf("wrote %d octets, want 4: the second policy did not fit", n)
	}
	if int(n) > len(opts) {
		t.Fatalf("reported %d octets for a %d octet area", n, len(opts))
	}
}

// TestComposite_DrivesRealPoliciesOnAConnection verifies a composite works as the
// installed policy of a live connection, with two policies that both observe the
// traffic, and that data still flows.
func TestComposite_DrivesRealPoliciesOnAConnection(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(23))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)
	a, b := newStub("a"), newStub("b")
	var c Composite
	for _, p := range []*stubPolicy{a, b} {
		if err := c.Add(p); err != nil {
			t.Fatal(err)
		}
	}
	client.SetPolicy(&c, func() int64 { return 1 })
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])

	data := []byte("composed")
	if _, err := client.Write(data); err != nil {
		t.Fatal("write:", err)
	}
	clear(buf[:])
	n, err := client.Send(buf[:])
	if err != nil {
		t.Fatal("send:", err)
	}
	if err = server.Recv(buf[:n]); err != nil {
		t.Fatal("server recv:", err)
	}
	got := make([]byte, len(data))
	nr, err := server.Read(got)
	if err != nil {
		t.Fatal("read:", err)
	}
	if string(got[:nr]) != string(data) {
		t.Errorf("server read %q, want %q", got[:nr], data)
	}
	for _, p := range []*stubPolicy{a, b} {
		if p.preTx == 0 || p.postTx == 0 || p.preRx == 0 || p.postRx == 0 {
			t.Errorf("policy %s was not driven by the connection: preRx=%d postRx=%d preTx=%d postTx=%d",
				p.name, p.preRx, p.postRx, p.preTx, p.postTx)
		}
	}
}

// TestComposite_ZeroAlloc verifies driving a composite allocates nothing, which is
// what the fixed-size storage is for.
func TestComposite_ZeroAlloc(t *testing.T) {
	var c Composite
	for range MaxComposedPolicies {
		if err := c.Add(newStub("p")); err != nil {
			t.Fatal(err)
		}
	}
	var opts [16]byte
	allocs := testing.AllocsPerRun(200, func() {
		c.PreRx(RxMeta{})
		c.PostRx(RxEvent{})
		c.PreTx(TxIntent{})
		c.WriteOptions(TxPlan{}, opts[:])
		c.PostTx(Segment{}, 1)
		c.NextDeadline()
	})
	if allocs != 0 {
		t.Errorf("composite allocated %v times per iteration, want 0", allocs)
	}
}

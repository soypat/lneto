package dns

import (
	"testing"
)

// FuzzMessage checks round-trip preservation of the decoded representation.
// Opaque resource data is compared as bytes, not interpreted as names; this
// does not verify relocation of compression pointers within that data.
func FuzzMessage(f *testing.F) {
	var seed Message
	seed.AddQuestions([]Question{{Name: MustNewName("example.com"), Type: TypeA, Class: ClassINET}})
	b, err := seed.AppendTo(nil, 1, 0)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		var m Message
		m.LimitResourceDecoding(4, 8, 4, 4)
		_, incomplete, err := m.Decode(b)
		if err != nil || incomplete {
			return
		}
		enc, err := m.AppendTo(nil, 1, 0)
		if err != nil {
			return // Not every decodable message is encodable.
		}
		var got Message
		got.LimitResourceDecoding(4, 8, 4, 4)
		if _, incomplete, err := got.Decode(enc); err != nil || incomplete {
			t.Fatalf("re-encoded message does not decode: %v (incomplete=%v)", err, incomplete)
		}
		if got.String() != m.String() {
			t.Fatalf("round trip changed the message:\n%s\n%s", m.String(), got.String())
		}
	})
}

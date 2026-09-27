package sshraw_test

import (
	"strings"
	"testing"

	ssh "github.com/soypat/lneto/crypto/sshraw"
)

// StringConst must name defined values as String does and everything else
// "unknown", without allocating. A constant added without extending a
// StringConst switch fails here.
func TestStringConst(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    int // Values checked; the uint32 types only define small ones.
		str  func(int) string
		cst  func(int) string
	}{
		{"MsgType", 1 << 8,
			func(i int) string { return ssh.MsgType(i).String() },
			func(i int) string { return ssh.MsgType(i).StringConst() }},
		{"DisconnectReason", 1 << 8,
			func(i int) string { return ssh.DisconnectReason(i).String() },
			func(i int) string { return ssh.DisconnectReason(i).StringConst() }},
		{"ChannelOpenFailureReason", 1 << 8,
			func(i int) string { return ssh.ChannelOpenFailureReason(i).String() },
			func(i int) string { return ssh.ChannelOpenFailureReason(i).StringConst() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i := range tc.n {
				str, cst := tc.str(i), tc.cst(i)
				if !strings.ContainsRune(str, '(') { // stringer names undefined values "Type(9)".
					if cst != str {
						t.Fatalf("%s(%d)=%q want %q", tc.name, i, cst, str)
					}
				} else if cst != "unknown" {
					t.Fatalf("%s(%d)=%q want %q", tc.name, i, cst, "unknown")
				}
			}
			allocs := testing.AllocsPerRun(1, func() {
				for i := range tc.n {
					_ = tc.cst(i)
				}
			})
			if allocs != 0 {
				t.Errorf("%s allocated %v times", tc.name, allocs)
			}
		})
	}
}

package tls_test

import (
	"strings"
	"testing"

	"github.com/soypat/lneto/x/tls"
)

// StringConst must name defined values as String does, GREASE values "GREASE"
// and everything else "unknown", over the whole range and without allocating.
// A constant added without extending a StringConst switch fails here.
func TestStringConst(t *testing.T) {
	for _, tc := range []struct {
		name   string
		n      int
		grease bool // type carries GREASE values
		str    func(int) string
		cst    func(int) string
	}{
		{"ContentType", 1 << 8, false,
			func(i int) string { return tls.ContentType(i).String() },
			func(i int) string { return tls.ContentType(i).StringConst() }},
		{"HandshakeType", 1 << 8, false,
			func(i int) string { return tls.HandshakeType(i).String() },
			func(i int) string { return tls.HandshakeType(i).StringConst() }},
		{"AlertLevel", 1 << 8, false,
			func(i int) string { return tls.AlertLevel(i).String() },
			func(i int) string { return tls.AlertLevel(i).StringConst() }},
		{"AlertDescription", 1 << 8, false,
			func(i int) string { return tls.AlertDescription(i).String() },
			func(i int) string { return tls.AlertDescription(i).StringConst() }},
		{"ExtensionType", 1 << 16, true,
			func(i int) string { return tls.ExtensionType(i).String() },
			func(i int) string { return tls.ExtensionType(i).StringConst() }},
		{"NamedGroup", 1 << 16, true,
			func(i int) string { return tls.NamedGroup(i).String() },
			func(i int) string { return tls.NamedGroup(i).StringConst() }},
		{"SignatureScheme", 1 << 16, true,
			func(i int) string { return tls.SignatureScheme(i).String() },
			func(i int) string { return tls.SignatureScheme(i).StringConst() }},
		{"CipherSuite", 1 << 16, true,
			func(i int) string { return tls.CipherSuite(i).String() },
			func(i int) string { return tls.CipherSuite(i).StringConst() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i := range tc.n {
				str, cst := tc.str(i), tc.cst(i)
				if !strings.ContainsRune(str, '(') { // stringer names undefined values "Type(9)".
					if cst != str {
						t.Fatalf("%s(%d)=%q want %q", tc.name, i, cst, str)
					}
					continue
				}
				want := "unknown"
				if tc.grease && tls.IsGREASE(uint16(i)) {
					want = "GREASE"
				}
				if cst != want {
					t.Fatalf("%s(%d)=%q want %q", tc.name, i, cst, want)
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

//go:build !tinygo

// Exclude tinygo compiler from build since exec package and t.Skip() are unimplemented.
// Also: wouldn't including tinygo cause a recursive call to tinygo test?
package xnet

import (
	"debug/elf"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestTinyGoTest(t *testing.T) {
	if exec.Command("tinygo", "version").Run() != nil {
		t.Skip("tinygo not installed")
	}
	// This takes a long time. Consider running only important
	// tests with -run=TestXxx flag: `go test ./... -run=TestXxx`
	out, err := exec.Command("tinygo", "test", ".").CombinedOutput()
	if err != nil {
		t.Fatal("tinygo failed to test:", err, "\n", string(out))
	}
}

func TestStackAsyncNoIPv6(t *testing.T) {
	const name = "mwe.elf"
	cmd := exec.Command("go", "build", "-o="+name, "../../examples/min-working-example")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err, "\n", string(out))
	}
	defer os.Remove(name)
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	file, err := elf.NewFile(f)
	if err != nil {
		t.Fatal(err)
	}
	syms, err := file.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	// Sanity check that symbol/debug information was compiled in normally.
	// If this exported method is missing the binary was likely stripped
	// (e.g. -ldflags="-s -w") and the IPv6 absence check below would be
	// meaningless since every symbol would be gone.
	const wantSym = "(*StackAsync).AssimilateDHCPResults"
	if !elfContainsSymbol(t, syms, wantSym) {
		t.Fatalf("expected symbol %q in %s; symbol table may be stripped", wantSym, name)
	}

	// Guarantee the compiler did not aggressively include the IPv6 stack in
	// this IPv4-only example. Methods on the unexported stack6 type are the
	// IPv6 implementation; their presence means IPv6 code leaked into the
	// binary and was not dead-code eliminated.
	const ipv6Sym = "(*stack6)"
	if elfContainsSymbol(t, syms, ipv6Sym) {
		t.Errorf("unexpected IPv6 symbol %q found in %s; IPv6 functionality was not eliminated from IPv4-only build", ipv6Sym, name)
	}
}

// elfContainsSymbol reports whether the ELF binary at path defines a symbol
// whose name contains identifier. It reads the symbol table (.symtab), which a
// normal go build retains.
func elfContainsSymbol(t *testing.T, syms []elf.Symbol, identifier string) bool {
	t.Helper()
	for i := range syms {
		if strings.Contains(syms[i].Name, identifier) {
			return true
		}
	}
	return false
}

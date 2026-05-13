//go:build !tinygo && linux

package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type program struct {
	Name           string
	Link           string // relative path for README link
	Dir            string // directory to build from, relative to repo root
	ExtraProtocols string
	PacketCapture  bool
}

type buildTarget struct {
	Name  string
	ext   string // output file extension (determines format for tinygo)
	build func(dir, outFile string) error
}

type result struct {
	BinarySize  int64
	CompileTime time.Duration
	DNC         bool // Does Not Compile
	Err         error
}

func (r result) sizeString() string {
	if r.DNC {
		return "DNC"
	}
	if r.Err != nil {
		return "ERR"
	}
	return formatSize(r.BinarySize)
}

func formatSize(n int64) string {
	const mb = 1024 * 1024
	if n >= mb {
		return fmt.Sprintf("%.1fMB", float64(n)/mb)
	}
	return fmt.Sprintf("%dkB", (n+512)/1024)
}

func goBuild(goos, goarch string) func(dir, out string) error {
	return func(dir, out string) error {
		cmd := exec.Command("go", "build", "-o", out, ".")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%w: %s", err, out)
		}
		return nil
	}
}

func tinygoBuild(target string) func(dir, out string) error {
	return func(dir, out string) error {
		args := []string{"build"}
		if target != "" {
			args = append(args, "-target="+target)
		}
		args = append(args, "-o", out, ".")
		cmd := exec.Command("tinygo", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%w: %s", err, out)
		}
		return nil
	}
}

var buildTargets = []buildTarget{
	{Name: "amd64 Go", ext: ".elf", build: goBuild("linux", "amd64")},
	{Name: "WASM Go", ext: ".wasm", build: goBuild("wasip1", "wasm")},
	{Name: "amd64 TinyGo", ext: ".elf", build: tinygoBuild("")},
	{Name: "WASM TinyGo", ext: ".wasm", build: tinygoBuild("wasm")},
	{Name: "Pico TinyGo", ext: ".bin", build: tinygoBuild("pico")},
}

var programs = []program{
	{
		Name:           "Lneto MWE",
		Link:           "./examples/min-working-example/",
		Dir:            "examples/min-working-example",
		ExtraProtocols: "DNS,NTP,DHCP",
		PacketCapture:  true,
	},
	{
		Name:           "Gvisor MWE w/ go-net",
		Link:           "./examples/_import_examples/gvisor-mwe/",
		Dir:            "examples/_import_examples/gvisor-mwe",
		ExtraProtocols: "None",
		PacketCapture:  false,
	},
}

func measure(dir, outFile string, fn func(dir, out string) error) result {
	start := time.Now()
	err := fn(dir, outFile)
	elapsed := time.Since(start)
	if err != nil {
		return result{DNC: true, CompileTime: elapsed, Err: err}
	}
	fi, err := os.Stat(outFile)
	if err != nil {
		return result{Err: err, CompileTime: elapsed}
	}
	size := fi.Size()
	os.Remove(outFile)
	return result{BinarySize: size, CompileTime: elapsed}
}

func main() {
	root := flag.String("root", ".", "path to repository root")
	flag.Parse()

	repoRoot, err := filepath.Abs(*root)
	if err != nil {
		panic(err)
	}

	tmpDir, err := os.MkdirTemp("", "binbench-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmpDir)

	type row struct {
		prog    program
		results []result
	}
	rows := make([]row, len(programs))
	for i, prog := range programs {
		dir := filepath.Join(repoRoot, prog.Dir)
		results := make([]result, len(buildTargets))
		for j, bt := range buildTargets {
			outFile := filepath.Join(tmpDir, fmt.Sprintf("p%d_t%d%s", i, j, bt.ext))
			fmt.Fprintf(os.Stderr, "building %s for %s...\n", prog.Name, bt.Name)
			r := measure(dir, outFile, bt.build)
			if r.DNC {
				fmt.Fprintf(os.Stderr, "  DNC: %v\n", r.Err)
			}
			results[j] = r
		}
		rows[i] = row{prog: prog, results: results}
	}

	// Print markdown table.
	headers := []string{"Program", "Extra Protocols", "Packet capture printing"}
	for _, bt := range buildTargets {
		headers = append(headers, bt.Name)
	}
	fmt.Printf("| %s |\n", strings.Join(headers, " | "))

	aligns := make([]string, len(headers))
	aligns[0] = "---"
	aligns[1] = ":---:"
	aligns[2] = ":---:"
	for i := 3; i < len(aligns); i++ {
		aligns[i] = "---"
	}
	fmt.Printf("|%s|\n", strings.Join(aligns, "|"))

	for _, r := range rows {
		pcap := "❌"
		if r.prog.PacketCapture {
			pcap = "✅"
		}
		cols := []string{
			fmt.Sprintf("[%s](%s)", r.prog.Name, r.prog.Link),
			r.prog.ExtraProtocols,
			pcap,
		}
		for _, res := range r.results {
			cols = append(cols, res.sizeString())
		}
		fmt.Printf("| %s |\n", strings.Join(cols, " | "))
	}
}

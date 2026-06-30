// Command benchci parses `go test -bench` output and renders a Markdown
// report. It is repo-owned tooling so CI does not depend on third-party
// benchmark actions. With -count>1 it reports the median of each metric to
// reduce noise.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// commentMarker is a stable HTML marker so a PR commenter can locate and
// update an existing report comment instead of posting duplicates.
const commentMarker = "<!-- lneto-bench -->"

func main() {
	var (
		currentPath = flag.String("current", "", "path to `go test -bench` output (default stdin)")
		outPath     = flag.String("out", "", "path to write Markdown report (default stdout)")
		title       = flag.String("title", "Benchmark results", "report heading")
	)
	flag.Parse()

	in := io.Reader(os.Stdin)
	if *currentPath != "" {
		f, err := os.Open(*currentPath)
		if err != nil {
			fatal(err)
		}
		defer f.Close()
		in = f
	}

	results, err := parse(in)
	if err != nil {
		fatal(err)
	}

	out := io.Writer(os.Stdout)
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			fatal(err)
		}
		defer f.Close()
		out = f
	}

	if err := render(out, *title, results); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "benchci:", err)
	os.Exit(1)
}

// result is the aggregated metrics for a single benchmark.
type result struct {
	pkg  string
	name string // benchmark name including the GOMAXPROCS suffix, e.g. BenchmarkFoo-12

	nsPerOp     []float64
	bytesPerOp  []float64
	allocsPerOp []float64
}

// parse reads `go test -bench -benchmem` output and groups metric samples by
// package and benchmark name. Repeated lines (from -count) accumulate samples.
func parse(r io.Reader) ([]result, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	byKey := make(map[string]*result)
	var order []string
	var pkg string

	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "pkg:" && len(fields) >= 2 {
			pkg = fields[1]
			continue
		}
		if !strings.HasPrefix(fields[0], "Benchmark") || len(fields) < 4 {
			continue
		}
		// fields: name iters value unit [value unit]...
		name := fields[0]
		if _, err := strconv.Atoi(fields[1]); err != nil {
			continue // second field must be the iteration count
		}

		key := pkg + "\x00" + name
		res := byKey[key]
		if res == nil {
			res = &result{pkg: pkg, name: name}
			byKey[key] = res
			order = append(order, key)
		}
		parseMetrics(res, fields[2:])
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	out := make([]result, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].pkg != out[j].pkg {
			return out[i].pkg < out[j].pkg
		}
		return out[i].name < out[j].name
	})
	return out, nil
}

// parseMetrics consumes (value, unit) pairs and appends the metrics benchci
// reports on. Unknown metrics are ignored.
func parseMetrics(res *result, tokens []string) {
	for i := 0; i+1 < len(tokens); i += 2 {
		v, err := strconv.ParseFloat(tokens[i], 64)
		if err != nil {
			continue
		}
		switch tokens[i+1] {
		case "ns/op":
			res.nsPerOp = append(res.nsPerOp, v)
		case "B/op":
			res.bytesPerOp = append(res.bytesPerOp, v)
		case "allocs/op":
			res.allocsPerOp = append(res.allocsPerOp, v)
		}
	}
}

// median returns the median of samples. ok is false when there are no samples.
func median(samples []float64) (value float64, ok bool) {
	if len(samples) == 0 {
		return 0, false
	}
	s := append([]float64(nil), samples...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2], true
	}
	return (s[n/2-1] + s[n/2]) / 2, true
}

func render(w io.Writer, title string, results []result) error {
	bw := bufio.NewWriter(w)
	fmt.Fprintf(bw, "%s\n\n", commentMarker)
	fmt.Fprintf(bw, "### %s\n\n", title)

	if len(results) == 0 {
		fmt.Fprintln(bw, "_No benchmarks found._")
		return bw.Flush()
	}

	fmt.Fprintln(bw, "_Timing results (`ns/op`) depend on the host CPU and are only a rough guideline. Memory results (`B/op` and `allocs/op`) are not affected._")
	fmt.Fprintln(bw)
	fmt.Fprintln(bw, "| Package | Benchmark | ns/op | B/op | allocs/op |")
	fmt.Fprintln(bw, "|---|---|---:|---:|---:|")
	for _, r := range results {
		fmt.Fprintf(bw, "| %s | %s | %s | %s | %s |\n",
			shortPkg(r.pkg), r.name,
			formatNs(median(r.nsPerOp)),
			formatCount(median(r.bytesPerOp)),
			formatCount(median(r.allocsPerOp)),
		)
	}
	return bw.Flush()
}

// shortPkg trims the well-known module prefix for readability.
func shortPkg(pkg string) string {
	const prefix = "github.com/soypat/lneto/"
	if pkg == "" {
		return "-"
	}
	return strings.TrimPrefix(pkg, prefix)
}

func formatCount(v float64, ok bool) string {
	if !ok {
		return "-"
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// formatNs renders a ns/op value using a human-friendly time unit.
func formatNs(v float64, ok bool) string {
	if !ok {
		return "-"
	}
	switch {
	case v >= 1e9:
		return fmt.Sprintf("%.3f s", v/1e9)
	case v >= 1e6:
		return fmt.Sprintf("%.3f ms", v/1e6)
	case v >= 1e3:
		return fmt.Sprintf("%.3f µs", v/1e3)
	default:
		return fmt.Sprintf("%.3f ns", v)
	}
}

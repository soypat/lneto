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
		basePath    = flag.String("base", "", "path to baseline `go test -bench` output")
		currentPath = flag.String("current", "", "path to `go test -bench` output (default stdin)")
		outPath     = flag.String("out", "", "path to write Markdown report (default stdout)")
		title       = flag.String("title", "Benchmark results", "report heading")
	)
	flag.Parse()

	current, err := parseInput(*currentPath, os.Stdin)
	if err != nil {
		fatal(err)
	}
	var base []result
	if *basePath != "" {
		base, err = parseInput(*basePath, nil)
		if err != nil {
			fatal(err)
		}
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

	if *basePath != "" {
		err = renderComparison(out, *title, base, current)
	} else {
		err = render(out, *title, current)
	}
	if err != nil {
		fatal(err)
	}
}

func parseInput(path string, fallback io.Reader) ([]result, error) {
	if path == "" {
		return parse(fallback)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parse(f)
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

func renderComparison(w io.Writer, title string, base, current []result) error {
	bw := bufio.NewWriter(w)
	fmt.Fprintf(bw, "%s\n\n", commentMarker)
	fmt.Fprintf(bw, "### %s\n\n", title)

	type pair struct{ base, current *result }
	byKey := make(map[string]pair, len(base)+len(current))
	for i := range base {
		key := base[i].pkg + "\x00" + base[i].name
		p := byKey[key]
		p.base = &base[i]
		byKey[key] = p
	}
	for i := range current {
		key := current[i].pkg + "\x00" + current[i].name
		p := byKey[key]
		p.current = &current[i]
		byKey[key] = p
	}
	if len(byKey) == 0 {
		fmt.Fprintln(bw, "_No benchmarks found._")
		return bw.Flush()
	}

	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	fmt.Fprintln(bw, "_Diff is `(PR - Main) / Main`; lower values are better. Timing results depend on the host CPU and are only a rough guideline._")
	fmt.Fprintln(bw)
	fmt.Fprintln(bw, "| Package | Benchmark | Metric | Main | PR | Diff |")
	fmt.Fprintln(bw, "|---|---|---|---:|---:|---:|")
	for _, key := range keys {
		p := byKey[key]
		identity := p.base
		if identity == nil {
			identity = p.current
		}
		metrics := []struct {
			name   string
			values func(*result) []float64
			format func(float64, bool) string
		}{
			{"ns/op", func(r *result) []float64 { return r.nsPerOp }, formatNs},
			{"B/op", func(r *result) []float64 { return r.bytesPerOp }, formatCount},
			{"allocs/op", func(r *result) []float64 { return r.allocsPerOp }, formatCount},
		}
		for _, metric := range metrics {
			baseSamples := metricSamples(p.base, metric.values)
			currentSamples := metricSamples(p.current, metric.values)
			fmt.Fprintf(bw, "| %s | %s | %s | %s | %s | %s |\n",
				shortPkg(identity.pkg), identity.name, metric.name,
				metric.format(median(baseSamples)), metric.format(median(currentSamples)),
				formatDiff(baseSamples, currentSamples),
			)
		}
	}
	return bw.Flush()
}

func metricSamples(r *result, values func(*result) []float64) []float64 {
	if r == nil {
		return nil
	}
	return values(r)
}

func formatDiff(base, current []float64) string {
	baseValue, baseOK := median(base)
	currentValue, currentOK := median(current)
	if !baseOK && !currentOK {
		return "-"
	}
	if !baseOK {
		return "new"
	}
	if !currentOK {
		return "removed"
	}
	if baseValue == 0 {
		if currentValue == 0 {
			return "0.00%"
		}
		return "n/a"
	}
	return fmt.Sprintf("%+.2f%%", (currentValue-baseValue)/baseValue*100)
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

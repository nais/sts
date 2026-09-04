package main

import (
	"errors"
	"flag"
	"fmt"
	"html/template"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

type metricFiles map[string]string

func (m *metricFiles) String() string {
	return fmt.Sprint(map[string]string(*m))
}

func (m *metricFiles) Set(value string) error {
	name, path, ok := strings.Cut(value, "=")
	if !ok || name == "" || path == "" {
		return errors.New("metrics must have the form benchmark=path")
	}
	(*m)[name] = path
	return nil
}

type benchmarkResult struct {
	Name       string
	Iterations int64
	Duration   time.Duration
	Bytes      int64
	Allocs     int64
}

type histogramResult struct {
	Name      string
	Operation string
	Outcome   string
	Count     uint64
	Average   time.Duration
	P95       time.Duration
}

type reportSection struct {
	Name    string
	Queries []histogramResult
	Steps   []histogramResult
}

type reportData struct {
	Generated  string
	Benchmarks []benchmarkResult
	Sections   []reportSection
	Summary    []string
}

var benchmarkLine = regexp.MustCompile(`^BenchmarkSts/([^\s-]+)-\d+\s+(\d+)\s+([0-9.]+) ns/op\s+(\d+) B/op\s+(\d+) allocs/op`)

func main() {
	benchmarkPath := flag.String("benchmark", "", "path to Go benchmark output")
	outputPath := flag.String("output", "benchmark-report.html", "path to generated HTML")
	metrics := metricFiles{}
	flag.Var(&metrics, "metrics", "benchmark name and Prometheus file: name=path (repeatable)")
	flag.Parse()

	if *benchmarkPath == "" || len(metrics) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	benchmarks, err := parseBenchmarks(*benchmarkPath)
	if err != nil {
		fatal(err)
	}
	sections := make([]reportSection, 0, len(metrics))
	for name, path := range metrics {
		section, err := parseMetrics(name, path)
		if err != nil {
			fatal(err)
		}
		sections = append(sections, section)
	}
	sort.Slice(sections, func(i, j int) bool { return sections[i].Name < sections[j].Name })

	data := reportData{
		Generated:  time.Now().Format(time.RFC1123),
		Benchmarks: benchmarks,
		Sections:   sections,
		Summary:    summarize(benchmarks, sections),
	}
	if err := writeReport(*outputPath, data); err != nil {
		fatal(err)
	}
	fmt.Printf("HTML benchmark report: %s\n", *outputPath)
}

func fatal(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "benchmark report: %v\n", err)
	os.Exit(1)
}

func parseBenchmarks(path string) ([]benchmarkResult, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read benchmark output: %w", err)
	}
	var results []benchmarkResult
	for _, line := range strings.Split(string(contents), "\n") {
		match := benchmarkLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		iterations, _ := strconv.ParseInt(match[2], 10, 64)
		ns, _ := strconv.ParseFloat(match[3], 64)
		bytes, _ := strconv.ParseInt(match[4], 10, 64)
		allocs, _ := strconv.ParseInt(match[5], 10, 64)
		results = append(results, benchmarkResult{
			Name:       match[1],
			Iterations: iterations,
			Duration:   time.Duration(ns),
			Bytes:      bytes,
			Allocs:     allocs,
		})
	}
	if len(results) == 0 {
		return nil, errors.New("no BenchmarkSts results found")
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })
	return results, nil
}

func parseMetrics(name, path string) (reportSection, error) {
	input, err := os.Open(path)
	if err != nil {
		return reportSection{}, fmt.Errorf("open metrics for %s: %w", name, err)
	}
	defer func() { _ = input.Close() }()

	parser := expfmt.NewTextParser(model.LegacyValidation)
	families, err := parser.TextToMetricFamilies(input)
	if err != nil {
		return reportSection{}, fmt.Errorf("parse metrics for %s: %w", name, err)
	}
	section := reportSection{Name: name}
	queries := histogramRows(families["db_client_operation_duration_seconds"], "db_query_summary", true)
	for _, query := range queries {
		// A sqlc query name differs from its SQL operation. Generic SELECT,
		// INSERT, and OTHER summaries are startup or migration statements.
		if query.Name != query.Operation {
			section.Queries = append(section.Queries, query)
		}
	}
	section.Steps = histogramRows(families["sts_token_step_duration_seconds"], "step", false)
	return section, nil
}

func histogramRows(family *dto.MetricFamily, nameLabel string, includeOperation bool) []histogramResult {
	if family == nil {
		return nil
	}
	var rows []histogramResult
	for _, metric := range family.Metric {
		histogram := metric.GetHistogram()
		if histogram == nil {
			continue
		}
		labels := labels(metric)
		name := labels[nameLabel]
		if name == "" {
			name = "unknown"
		}
		count := histogram.GetSampleCount()
		average := time.Duration(0)
		if count > 0 {
			average = seconds(histogram.GetSampleSum() / float64(count))
		}
		operation := ""
		if includeOperation {
			operation = labels["db_operation_name"]
		}
		rows = append(rows, histogramResult{
			Name:      name,
			Operation: operation,
			Outcome:   labels["outcome"],
			Count:     count,
			Average:   average,
			P95:       percentile(histogram, 0.95),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].P95 == rows[j].P95 {
			return rows[i].Name < rows[j].Name
		}
		return rows[i].P95 > rows[j].P95
	})
	return rows
}

func labels(metric *dto.Metric) map[string]string {
	result := make(map[string]string, len(metric.Label))
	for _, pair := range metric.Label {
		result[pair.GetName()] = pair.GetValue()
	}
	return result
}

func percentile(histogram *dto.Histogram, quantile float64) time.Duration {
	count := histogram.GetSampleCount()
	if count == 0 {
		return 0
	}
	target := uint64(float64(count)*quantile + 0.999999)
	for _, bucket := range histogram.Bucket {
		if bucket.GetCumulativeCount() >= target {
			return seconds(bucket.GetUpperBound())
		}
	}
	return 0
}

func seconds(value float64) time.Duration {
	return time.Duration(value * float64(time.Second))
}

func summarize(benchmarks []benchmarkResult, sections []reportSection) []string {
	var summary []string
	if len(benchmarks) == 2 {
		fast, slow := benchmarks[0], benchmarks[1]
		if fast.Duration > slow.Duration {
			fast, slow = slow, fast
		}
		difference := float64(slow.Duration-fast.Duration) / float64(fast.Duration) * 100
		summary = append(summary, fmt.Sprintf("%s is %.0f%% slower per request than %s in this run.", displayName(slow.Name), difference, displayName(fast.Name)))
	}
	for _, section := range sections {
		for _, query := range section.Queries {
			if query.Outcome == "success" && query.P95 > 0 {
				summary = append(summary, fmt.Sprintf("The slowest observed database p95 for %s was %s at approximately %s.", displayName(section.Name), query.Name, formatDuration(query.P95)))
				break
			}
		}
	}
	if len(summary) == 0 {
		summary = append(summary, "Not enough samples were recorded to generate comparisons.")
	}
	return summary
}

func displayName(value string) string {
	return strings.ReplaceAll(value, "_", " ")
}

func formatDuration(value time.Duration) string {
	if value >= time.Second {
		return fmt.Sprintf("%.2f s", value.Seconds())
	}
	if value >= time.Millisecond {
		return fmt.Sprintf("%.2f ms", float64(value)/float64(time.Millisecond))
	}
	return fmt.Sprintf("%.2f µs", float64(value)/float64(time.Microsecond))
}

func writeReport(path string, data reportData) error {
	output, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create report: %w", err)
	}
	defer func() { _ = output.Close() }()
	if err := reportTemplate.Execute(output, data); err != nil {
		return fmt.Errorf("render report: %w", err)
	}
	return nil
}

var reportTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"duration": formatDuration,
	"name":     displayName,
	"bytes": func(value int64) string {
		return fmt.Sprintf("%.1f KiB", float64(value)/1024)
	},
	"throughput": func(value time.Duration) string {
		if value <= 0 {
			return "–"
		}
		return fmt.Sprintf("%.0f requests/s", float64(time.Second)/float64(value))
	},
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>STS performance report</title>
<style>
:root { color-scheme: light dark; --bg:#f5f7fb; --card:#fff; --text:#172033; --muted:#657089; --line:#dce2ec; --accent:#2855d9; --good:#18794e; }
@media (prefers-color-scheme: dark) { :root { --bg:#10131a; --card:#191e28; --text:#edf1f7; --muted:#a8b0c0; --line:#343c4b; --accent:#8eabff; --good:#6dd6a0; } }
* { box-sizing:border-box } body { margin:0; background:var(--bg); color:var(--text); font:15px/1.5 system-ui,sans-serif }
main { max-width:1100px; margin:auto; padding:36px 20px 70px } h1 { margin-bottom:4px } h2 { margin-top:38px } h3 { margin-top:28px }
.muted,.hint { color:var(--muted) }.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:16px }
.card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:18px; box-shadow:0 2px 10px #0000000a }
.value { font-size:28px; font-weight:700; color:var(--accent) }.label { color:var(--muted); font-size:13px }
table { width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line) } th,td { text-align:left; padding:10px 12px; border-bottom:1px solid var(--line) } th { color:var(--muted); font-size:12px; text-transform:uppercase } td.num { font-variant-numeric:tabular-nums }
.pill { display:inline-block; border-radius:999px; padding:2px 8px; background:color-mix(in srgb,var(--good) 15%,transparent); color:var(--good); font-size:12px }
.note { border-left:4px solid var(--accent); padding:10px 14px; background:var(--card) } code { font-size:13px }
</style>
</head>
<body><main>
<h1>STS performance report</h1><div class="muted">Generated {{.Generated}}</div>
<h2>Plain-language summary</h2><div class="card"><ul>{{range .Summary}}<li>{{.}}</li>{{end}}</ul></div>
<h2>Token endpoint benchmarks</h2>
<p class="hint">Latency is the complete steady-state HTTP <code>/token</code> request. Lower latency and fewer allocations are better.</p>
<div class="grid">{{range .Benchmarks}}<div class="card"><div class="label">{{name .Name}}</div><div class="value">{{duration .Duration}}</div><div>{{throughput .Duration}}</div><hr><div>{{bytes .Bytes}} allocated/request</div><div>{{.Allocs}} allocations/request</div><div class="muted">{{.Iterations}} measured iterations</div></div>{{end}}</div>
{{range .Sections}}
<h2>Metrics: {{name .Name}}</h2>
<p class="hint">These are OpenTelemetry metrics captured from the benchmark process. Sample counts include benchmark calibration and the untimed warm-up request.</p>
<h3>Database queries</h3>
<table><thead><tr><th>Query</th><th>Operation</th><th>Outcome</th><th>Samples</th><th>Average</th><th>Approx. p95</th></tr></thead><tbody>
{{range .Queries}}<tr><td><code>{{.Name}}</code></td><td>{{.Operation}}</td><td><span class="pill">{{.Outcome}}</span></td><td class="num">{{.Count}}</td><td class="num">{{duration .Average}}</td><td class="num">{{duration .P95}}</td></tr>{{else}}<tr><td colspan="6">No database samples recorded.</td></tr>{{end}}
</tbody></table>
<h3>Token processing steps</h3>
<table><thead><tr><th>Step</th><th>Outcome</th><th>Samples</th><th>Average</th><th>Approx. p95</th></tr></thead><tbody>
{{range .Steps}}<tr><td><code>{{.Name}}</code></td><td><span class="pill">{{.Outcome}}</span></td><td class="num">{{.Count}}</td><td class="num">{{duration .Average}}</td><td class="num">{{duration .P95}}</td></tr>{{else}}<tr><td colspan="5">No token-step samples recorded.</td></tr>{{end}}
</tbody></table>
{{end}}
<h2>How to read this report</h2>
<div class="note"><strong>Average</strong> shows typical recorded work. <strong>p95</strong> means roughly 95% of samples completed at or below that histogram boundary. It is an approximation, not an exact percentile. Compare reports produced on the same machine and look for trends; this is not a production load test.</div>
</main></body></html>`))

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

type namedMetricFile struct {
	name string
	path string
}

type metricFileList []namedMetricFile

func (m *metricFileList) String() string { return fmt.Sprint([]namedMetricFile(*m)) }

func (m *metricFileList) Set(value string) error {
	name, path, ok := strings.Cut(value, "=")
	if !ok || name == "" || path == "" {
		return errors.New("metrics must have the form benchmark=path")
	}
	*m = append(*m, namedMetricFile{name: name, path: path})
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
	Generated      string
	Benchmarks     []benchmarkResult
	Sections       []reportSection
	Summary        []string
	Remote         bool
	RequestPath    string
	MetricsWarning string
}

var benchmarkLine = regexp.MustCompile(`^BenchmarkSts/([^\s-]+)-\d+\s+(\d+)\s+([0-9.]+) ns/op\s+(\d+) B/op\s+(\d+) allocs/op`)

func main() {
	benchmarkPath := flag.String("benchmark", "", "path to Go benchmark output")
	outputPath := flag.String("output", "benchmark-report.html", "path to generated HTML")
	remote := flag.Bool("remote", false, "report benchmark-client timings with remote server metrics")
	requestPath := flag.String("request-path", "ingress", "remote request path: ingress or cluster")
	metrics := metricFiles{}
	flag.Var(&metrics, "metrics", "benchmark name and Prometheus file: name=path (repeatable)")
	var metricsBefore, metricsAfter metricFileList
	flag.Var(&metricsBefore, "metrics-before", "benchmark name and pre-run Prometheus file: name=path (repeatable)")
	flag.Var(&metricsAfter, "metrics-after", "benchmark name and post-run Prometheus file: name=path (repeatable)")
	metricsIncomplete := flag.String("metrics-incomplete", "", "reason server metrics are unreliable")
	flag.Parse()

	if err := validateRequestPath(*requestPath); err != nil {
		fatal(err)
	}
	if *remote && len(metrics) > 0 {
		fatal(errors.New("-metrics cannot be used with -remote"))
	}
	if !*remote && (len(metricsBefore) > 0 || len(metricsAfter) > 0 || *metricsIncomplete != "") {
		fatal(errors.New("-metrics-before, -metrics-after, and -metrics-incomplete require -remote"))
	}
	if *benchmarkPath == "" || (!*remote && len(metrics) == 0) {
		flag.Usage()
		os.Exit(2)
	}
	if *remote {
		if err := validateMetricPairs(metricsBefore, metricsAfter); err != nil {
			fatal(err)
		}
		if *metricsIncomplete == "" && len(metricsBefore) == 0 {
			fatal(errors.New("remote metrics require at least one -metrics-before and -metrics-after pair"))
		}
	}

	benchmarks, err := parseBenchmarks(*benchmarkPath)
	if err != nil {
		fatal(err)
	}
	var sections []reportSection
	if *metricsIncomplete == "" {
		sections = make([]reportSection, 0, len(metrics)+len(metricsBefore))
		for name, path := range metrics {
			section, err := parseMetrics(name, path)
			if err != nil {
				fatal(err)
			}
			sections = append(sections, section)
		}
		if *remote {
			remoteSections, warning := remoteMetrics(metricsBefore, metricsAfter)
			if warning != "" {
				*metricsIncomplete = warning
			} else {
				sections = append(sections, remoteSections...)
			}
		}
	}
	if *metricsIncomplete != "" {
		sections = nil
	}
	sort.Slice(sections, func(i, j int) bool { return sections[i].Name < sections[j].Name })

	data := reportData{
		Generated:      time.Now().Format(time.RFC1123),
		Benchmarks:     benchmarks,
		Sections:       sections,
		Summary:        summarize(benchmarks, sections),
		Remote:         *remote,
		RequestPath:    *requestPath,
		MetricsWarning: *metricsIncomplete,
	}
	if err := writeReport(*outputPath, data); err != nil {
		fatal(err)
	}
	fmt.Printf("HTML benchmark report: %s\n", *outputPath)
}

func validateRequestPath(requestPath string) error {
	switch requestPath {
	case "ingress", "cluster":
		return nil
	default:
		return errors.New("-request-path must be ingress or cluster")
	}
}

func fatal(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "benchmark report: %v\n", err)
	os.Exit(1)
}

func parseBenchmarks(path string) ([]benchmarkResult, error) {
	contents, err := os.ReadFile(path) // #nosec G304 -- This CLI intentionally accepts a benchmark output path.
	if err != nil {
		return nil, fmt.Errorf("read benchmark output: %w", err)
	}
	var results []benchmarkResult
	for line := range strings.SplitSeq(string(contents), "\n") {
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
	families, err := readMetricFamilies(name, path)
	if err != nil {
		return reportSection{}, err
	}
	return sectionFromFamilies(name, families), nil
}

func readMetricFamilies(name, path string) (map[string]*dto.MetricFamily, error) {
	input, err := os.Open(path) // #nosec G304 -- This CLI intentionally accepts a metrics input path.
	if err != nil {
		return nil, fmt.Errorf("open metrics for %s: %w", name, err)
	}
	defer func() { _ = input.Close() }()

	parser := expfmt.NewTextParser(model.LegacyValidation)
	families, err := parser.TextToMetricFamilies(input)
	if err != nil {
		return nil, fmt.Errorf("parse metrics for %s: %w", name, err)
	}
	return families, nil
}

func sectionFromFamilies(name string, families map[string]*dto.MetricFamily) reportSection {
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
	return section
}

func validateMetricPairs(before, after metricFileList) error {
	counts := make(map[string]int)
	for _, file := range before {
		counts[file.name]++
	}
	for _, file := range after {
		counts[file.name]--
	}
	for name, count := range counts {
		if count != 0 {
			return fmt.Errorf("metrics-before and metrics-after must have matching pod counts for %s", name)
		}
	}
	if len(before) != len(after) {
		return errors.New("metrics-before and metrics-after must have matching pod counts")
	}
	return nil
}

func remoteMetrics(before, after metricFileList) ([]reportSection, string) {
	sections, err := parseMetricDeltas(before, after)
	if err != nil {
		return nil, err.Error()
	}
	return sections, ""
}

func parseMetricDeltas(before, after metricFileList) ([]reportSection, error) {
	afterByName := make(map[string][]namedMetricFile)
	for _, file := range after {
		afterByName[file.name] = append(afterByName[file.name], file)
	}
	paired := make(map[string]int)
	byName := make(map[string]map[string]*dto.Metric)
	for _, beforeFile := range before {
		i := paired[beforeFile.name]
		paired[beforeFile.name]++
		afterFile := afterByName[beforeFile.name][i]
		beforeFamilies, err := readMetricFamilies(beforeFile.name, beforeFile.path)
		if err != nil {
			return nil, err
		}
		afterFamilies, err := readMetricFamilies(afterFile.name, afterFile.path)
		if err != nil {
			return nil, err
		}
		for _, familyName := range []string{"db_client_operation_duration_seconds", "sts_token_step_duration_seconds"} {
			delta, err := histogramDelta(beforeFamilies[familyName], afterFamilies[familyName])
			if err != nil {
				return nil, fmt.Errorf("metrics delta for %s: %w", beforeFile.name, err)
			}
			if byName[beforeFile.name] == nil {
				byName[beforeFile.name] = make(map[string]*dto.Metric)
			}
			for key, metric := range delta {
				merged := byName[beforeFile.name][familyName+key]
				if merged == nil {
					byName[beforeFile.name][familyName+key] = metric
					continue
				}
				if err := mergeHistogram(merged.Histogram, metric.Histogram); err != nil {
					return nil, fmt.Errorf("metrics delta for %s: %w", beforeFile.name, err)
				}
			}
		}
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	sections := make([]reportSection, 0, len(names))
	for _, name := range names {
		families := map[string]*dto.MetricFamily{}
		for _, familyName := range []string{"db_client_operation_duration_seconds", "sts_token_step_duration_seconds"} {
			family := &dto.MetricFamily{}
			for key, metric := range byName[name] {
				if strings.HasPrefix(key, familyName) {
					family.Metric = append(family.Metric, metric)
				}
			}
			families[familyName] = family
		}
		sections = append(sections, sectionFromFamilies(name, families))
	}
	return sections, nil
}

func histogramDelta(before, after *dto.MetricFamily) (map[string]*dto.Metric, error) {
	old := metricsByLabels(before)
	current := metricsByLabels(after)
	result := make(map[string]*dto.Metric)
	for key, metric := range current {
		base := old[key]
		var baseline *dto.Histogram
		if base != nil {
			baseline = base.GetHistogram()
		}
		delta, err := subtractHistogram(baseline, metric.GetHistogram())
		if err != nil {
			return nil, err
		}
		copyMetric := &dto.Metric{Label: metric.Label, Histogram: delta}
		result[key] = copyMetric
	}
	for key, metric := range old {
		if _, exists := current[key]; !exists && metric.GetHistogram().GetSampleCount() > 0 {
			return nil, errors.New("histogram count reset")
		}
	}
	return result, nil
}

func metricsByLabels(family *dto.MetricFamily) map[string]*dto.Metric {
	result := make(map[string]*dto.Metric)
	if family == nil {
		return result
	}
	for _, metric := range family.Metric {
		result[metricLabelKey(metric)] = metric
	}
	return result
}

func metricLabelKey(metric *dto.Metric) string {
	values := labels(metric)
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		fmt.Fprintf(&b, "%s=%q;", key, values[key])
	}
	return b.String()
}

func subtractHistogram(before *dto.Histogram, after *dto.Histogram) (*dto.Histogram, error) {
	if after == nil {
		after = &dto.Histogram{}
	}
	if before == nil {
		before = &dto.Histogram{}
	}
	if after.GetSampleCount() < before.GetSampleCount() {
		return nil, errors.New("histogram count reset")
	}
	if after.GetSampleSum()+1e-12 < before.GetSampleSum() {
		return nil, errors.New("histogram sum reset")
	}
	if before.GetSampleCount() > 0 && len(before.Bucket) != len(after.Bucket) {
		return nil, errors.New("histogram bucket layout changed")
	}
	sumDelta := after.GetSampleSum() - before.GetSampleSum()
	if sumDelta < 0 {
		sumDelta = 0
	}
	result := &dto.Histogram{SampleCount: uint64Pointer(after.GetSampleCount() - before.GetSampleCount()), SampleSum: float64Pointer(sumDelta)}
	for i, bucket := range after.Bucket {
		oldCount := uint64(0)
		if before.GetSampleCount() > 0 && i < len(before.Bucket) {
			if bucket.GetUpperBound() != before.Bucket[i].GetUpperBound() {
				return nil, errors.New("histogram bucket layout changed")
			}
			oldCount = before.Bucket[i].GetCumulativeCount()
		}
		if bucket.GetCumulativeCount() < oldCount {
			return nil, errors.New("histogram bucket reset")
		}
		result.Bucket = append(result.Bucket, &dto.Bucket{UpperBound: float64Pointer(bucket.GetUpperBound()), CumulativeCount: uint64Pointer(bucket.GetCumulativeCount() - oldCount)})
	}
	return result, nil
}

func mergeHistogram(target, source *dto.Histogram) error {
	if len(target.Bucket) != len(source.Bucket) {
		return errors.New("histogram bucket layout changed")
	}
	for i := range target.Bucket {
		if target.Bucket[i].GetUpperBound() != source.Bucket[i].GetUpperBound() {
			return errors.New("histogram bucket layout changed")
		}
	}
	target.SampleCount = uint64Pointer(target.GetSampleCount() + source.GetSampleCount())
	target.SampleSum = float64Pointer(target.GetSampleSum() + source.GetSampleSum())
	for i := range target.Bucket {
		target.Bucket[i].CumulativeCount = uint64Pointer(target.Bucket[i].GetCumulativeCount() + source.Bucket[i].GetCumulativeCount())
	}
	return nil
}

func uint64Pointer(value uint64) *uint64 { return &value }

func float64Pointer(value float64) *float64 { return &value }

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
	output, err := os.Create(path) // #nosec G304 -- This CLI intentionally accepts a report output path.
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
{{if .MetricsWarning}}<div class="note"><strong>Server metrics are incomplete:</strong> {{.MetricsWarning}} Server metrics are omitted because comparisons could be misleading.</div>{{end}}
<h2>Token endpoint benchmarks</h2>
<p class="hint">{{if .Remote}}{{if eq .RequestPath "cluster"}}Latency is the complete steady-state HTTP <code>/token</code> request. It includes in-cluster service network and STS work, but excludes external network and ingress. Lower latency and fewer benchmark-client allocations are better.{{else}}Latency is ingress time for the complete steady-state HTTP <code>/token</code> request. It includes network and proxy delay. Lower latency and fewer benchmark-client allocations are better.{{end}}{{else}}Latency is the complete steady-state HTTP <code>/token</code> request. Lower latency and fewer allocations are better.{{end}}</p>
{{if .Remote}}<p class="hint">Server process metrics use before/after deltas. They include calibration, warm-up, and concurrent traffic, and can include unrelated server activity.</p>{{end}}
<div class="grid">{{range .Benchmarks}}<div class="card"><div class="label">{{name .Name}}</div><div class="value">{{duration .Duration}}</div><div>{{throughput .Duration}}</div><hr><div>{{bytes .Bytes}} {{if $.Remote}}benchmark-client {{end}}allocated/request</div><div>{{.Allocs}} {{if $.Remote}}benchmark-client {{end}}allocations/request</div><div class="muted">{{.Iterations}} measured iterations</div></div>{{end}}</div>
{{range .Sections}}
<h2>Metrics: {{name .Name}}</h2>
<p class="hint">{{if $.Remote}}These are server process metrics. Before/after deltas include calibration, warm-up, and concurrent traffic. The process metrics can include unrelated server activity.{{else}}These are OpenTelemetry metrics captured from the benchmark process. Sample counts include benchmark calibration and the untimed warm-up request.{{end}}</p>
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

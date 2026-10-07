package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseBenchmarks(t *testing.T) {
	path := writeTestFile(t, "benchmark.txt", `goos: darwin
BenchmarkSts/client_credentials-14    400    2990000 ns/op    61250 B/op    616 allocs/op
BenchmarkSts/token_exchange-14        300    3450000 ns/op    86837 B/op    891 allocs/op
`)

	results, err := parseBenchmarks(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("result count = %d, want 2", len(results))
	}
	if results[0].Name != "client_credentials" || results[0].Duration != 2990*time.Microsecond {
		t.Errorf("first result = %+v", results[0])
	}
}

func TestParseMetricDeltasMergesPodsBeforeStatistics(t *testing.T) {
	before := metricFileList{
		{name: "remote", path: writeHistogramFile(t, "before1.prom", "query", 10, 0.010, 8, 10)},
		{name: "remote", path: writeHistogramFile(t, "before2.prom", "query", 5, 0.005, 4, 5)},
	}
	after := metricFileList{
		{name: "remote", path: writeHistogramFile(t, "after1.prom", "query", 12, 0.014, 9, 12)},
		{name: "remote", path: writeHistogramFile(t, "after2.prom", "query", 8, 0.026, 6, 8)},
	}
	sections, err := parseMetricDeltas(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if len(sections) != 1 || len(sections[0].Queries) != 1 {
		t.Fatalf("sections = %+v", sections)
	}
	query := sections[0].Queries[0]
	if query.Count != 5 || query.Average < 5*time.Millisecond-time.Nanosecond || query.Average > 5*time.Millisecond+time.Nanosecond || query.P95 != 20*time.Millisecond {
		t.Errorf("merged query = %+v, want count 5, average 5ms, p95 20ms", query)
	}
}

func TestMissingBaselineHistogramSeriesUsesZero(t *testing.T) {
	before := writeTestFile(t, "empty.prom", "# unrelated family\nother_metric 12\n")
	after := writeHistogramFile(t, "after.prom", "query", 4, 0.012, 3, 4)
	sections, err := parseMetricDeltas(metricFileList{{name: "remote", path: before}}, metricFileList{{name: "remote", path: after}})
	if err != nil {
		t.Fatal(err)
	}
	if got := sections[0].Queries[0]; got.Count != 4 || got.Average != 3*time.Millisecond {
		t.Errorf("query = %+v, want full after histogram", got)
	}
}

func TestHistogramCounterResetAndBucketLayoutMismatch(t *testing.T) {
	for _, test := range []struct {
		name          string
		before, after string
		wantErr       string
	}{
		{name: "counter reset", before: "query", after: "query", wantErr: "reset"},
		{name: "bucket mismatch", before: "query", after: "query", wantErr: "layout changed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := writeHistogramFile(t, "before.prom", test.before, 5, 0.005, 3, 5)
			count, sum, firstBound := uint64(6), 0.006, 0.01
			if test.name == "counter reset" {
				count, sum = 4, 0.004
			}
			if test.name == "bucket mismatch" {
				firstBound = 0.015
			}
			after := writeHistogramFileWithBound(t, "after.prom", "query", count, sum, 4, count, firstBound)
			_, err := parseMetricDeltas(metricFileList{{name: "remote", path: before}}, metricFileList{{name: "remote", path: after}})
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestRemoteAndIncompleteReportLabels(t *testing.T) {
	for _, test := range []struct {
		name     string
		data     reportData
		contains []string
		omits    []string
	}{
		{name: "remote ingress", data: reportData{Remote: true, RequestPath: "ingress"}, contains: []string{"benchmark-client allocations", "ingress time", "concurrent traffic", "Server process metrics"}},
		{name: "remote cluster", data: reportData{Remote: true, RequestPath: "cluster"}, contains: []string{"in-cluster service network and STS work", "excludes external network and ingress"}, omits: []string{"ingress time"}},
		{name: "incomplete", data: reportData{Remote: true, RequestPath: "ingress", MetricsWarning: "one pod was unreachable"}, contains: []string{"one pod was unreachable", "Server metrics are incomplete"}, omits: []string{"Metrics: remote", "Database queries"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "report.html")
			if err := writeReport(path, test.data); err != nil {
				t.Fatal(err)
			}
			contents, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range test.contains {
				if !strings.Contains(string(contents), value) {
					t.Errorf("report missing %q", value)
				}
			}
			for _, value := range test.omits {
				if strings.Contains(string(contents), value) {
					t.Errorf("report contains %q", value)
				}
			}
		})
	}
}

func TestValidateRequestPath(t *testing.T) {
	for _, requestPath := range []string{"ingress", "cluster"} {
		if err := validateRequestPath(requestPath); err != nil {
			t.Errorf("validateRequestPath(%q) = %v", requestPath, err)
		}
	}
	if err := validateRequestPath("external"); err == nil {
		t.Error("validateRequestPath(\"external\") = nil, want error")
	}
}

func TestRemoteMetricResetWritesTimingReport(t *testing.T) {
	benchmarkPath := writeTestFile(t, "benchmark.txt", "BenchmarkSts/client_credentials-14 10 2500000 ns/op 100 B/op 2 allocs/op\n")
	before := writeHistogramFile(t, "before.prom", "query", 5, 0.005, 3, 5)
	after := writeHistogramFile(t, "after.prom", "query", 4, 0.004, 2, 4)
	benchmarks, err := parseBenchmarks(benchmarkPath)
	if err != nil {
		t.Fatal(err)
	}
	sections, warning := remoteMetrics(metricFileList{{name: "remote", path: before}}, metricFileList{{name: "remote", path: after}})
	if warning == "" || len(sections) != 0 {
		t.Fatalf("remote metrics = (%+v, %q), want warning and no sections", sections, warning)
	}
	path := filepath.Join(t.TempDir(), "report.html")
	if err := writeReport(path, reportData{Benchmarks: benchmarks, Remote: true, MetricsWarning: warning}); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"2.50 ms", "histogram count reset", "Server metrics are incomplete"} {
		if !strings.Contains(string(contents), value) {
			t.Errorf("report missing %q", value)
		}
	}
	if strings.Contains(string(contents), "Database queries") {
		t.Error("report includes server metrics after a reset")
	}
}

func writeHistogramFile(t *testing.T, file, name string, count uint64, sum float64, firstBucket, infBucket uint64) string {
	return writeHistogramFileWithBound(t, file, name, count, sum, firstBucket, infBucket, 0.01)
}

func writeHistogramFileWithBound(t *testing.T, file, name string, count uint64, sum float64, firstBucket, infBucket uint64, firstBound float64) string {
	contents := fmt.Sprintf(`# TYPE db_client_operation_duration_seconds histogram
db_client_operation_duration_seconds_bucket{db_operation_name="SELECT",db_query_summary=%q,outcome="success",le=%q} %d
db_client_operation_duration_seconds_bucket{db_operation_name="SELECT",db_query_summary=%q,outcome="success",le="0.02"} %d
db_client_operation_duration_seconds_bucket{db_operation_name="SELECT",db_query_summary=%q,outcome="success",le="+Inf"} %d
db_client_operation_duration_seconds_sum{db_operation_name="SELECT",db_query_summary=%q,outcome="success"} %g
db_client_operation_duration_seconds_count{db_operation_name="SELECT",db_query_summary=%q,outcome="success"} %d
`, name, fmt.Sprint(firstBound), firstBucket, name, infBucket-1, name, infBucket, name, sum, name, count)
	return writeTestFile(t, file, contents)
}

func TestParseMetricsAndWriteReport(t *testing.T) {
	path := writeTestFile(t, "metrics.prom", `# TYPE db_client_operation_duration_seconds histogram
db_client_operation_duration_seconds_bucket{db_operation_name="SELECT",db_query_summary="GetKubernetesClient",outcome="success",le="0.001"} 9
db_client_operation_duration_seconds_bucket{db_operation_name="SELECT",db_query_summary="GetKubernetesClient",outcome="success",le="0.0025"} 10
db_client_operation_duration_seconds_bucket{db_operation_name="SELECT",db_query_summary="GetKubernetesClient",outcome="success",le="+Inf"} 10
db_client_operation_duration_seconds_sum{db_operation_name="SELECT",db_query_summary="GetKubernetesClient",outcome="success"} 0.008
db_client_operation_duration_seconds_count{db_operation_name="SELECT",db_query_summary="GetKubernetesClient",outcome="success"} 10
# TYPE sts_token_step_duration_seconds histogram
sts_token_step_duration_seconds_bucket{step="get_client",outcome="success",le="0.001"} 10
sts_token_step_duration_seconds_bucket{step="get_client",outcome="success",le="+Inf"} 10
sts_token_step_duration_seconds_sum{step="get_client",outcome="success"} 0.005
sts_token_step_duration_seconds_count{step="get_client",outcome="success"} 10
`)

	section, err := parseMetrics("client_credentials", path)
	if err != nil {
		t.Fatal(err)
	}
	if len(section.Queries) != 1 || section.Queries[0].Name != "GetKubernetesClient" {
		t.Fatalf("queries = %+v", section.Queries)
	}
	if section.Queries[0].Average != 800*time.Microsecond || section.Queries[0].P95 != 2500*time.Microsecond {
		t.Errorf("query timing = %+v", section.Queries[0])
	}

	output := filepath.Join(t.TempDir(), "report.html")
	data := reportData{Generated: "now", Sections: []reportSection{section}, Summary: []string{"Readable summary."}}
	if err := writeReport(output, data); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), "GetKubernetesClient") || !strings.Contains(string(contents), "Readable summary") {
		t.Error("report does not contain parsed results")
	}
}

func writeTestFile(t *testing.T, name, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

package main

import (
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

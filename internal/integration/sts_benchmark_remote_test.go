//go:build integration_test

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRemoteBenchmarkConfigRequiresValues(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
	}{
		{name: "client assertion", env: map[string]string{"STS_BENCHMARK_URL": "https://sts.example"}},
		{name: "subject token", env: map[string]string{
			"STS_BENCHMARK_URL": "https://sts.example", "STS_BENCHMARK_CLIENT_ASSERTION": "assertion",
		}},
		{name: "target", env: map[string]string{
			"STS_BENCHMARK_URL": "https://sts.example", "STS_BENCHMARK_CLIENT_ASSERTION": "assertion",
			"STS_BENCHMARK_SUBJECT_TOKEN": "subject",
		}},
		{name: "URL scheme", env: map[string]string{
			"STS_BENCHMARK_URL": "ftp://sts.example", "STS_BENCHMARK_CLIENT_ASSERTION": "assertion",
			"STS_BENCHMARK_SUBJECT_TOKEN": "subject", "STS_BENCHMARK_TARGET": "target",
		}},
		{name: "URL host", env: map[string]string{
			"STS_BENCHMARK_URL": "https:///token", "STS_BENCHMARK_CLIENT_ASSERTION": "assertion",
			"STS_BENCHMARK_SUBJECT_TOKEN": "subject", "STS_BENCHMARK_TARGET": "target",
		}},
		{name: "malformed URL", env: map[string]string{
			"STS_BENCHMARK_URL": "http://[::1", "STS_BENCHMARK_CLIENT_ASSERTION": "assertion",
			"STS_BENCHMARK_SUBJECT_TOKEN": "subject", "STS_BENCHMARK_TARGET": "target",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, remote, err := remoteBenchmarkConfigFromEnv(func(key string) string { return tt.env[key] })
			if !remote || err == nil {
				t.Fatalf("remote config = (remote %v, err %v), want remote with an error", remote, err)
			}
		})
	}
}

func TestRemoteBenchmarkForms(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sts/token" {
			t.Errorf("path = %q, want /sts/token", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
			return
		}
		want := map[string]string{
			"client_assertion": "assertion", "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		}
		switch r.Form.Get("grant_type") {
		case "client_credentials":
			want["scope"] = "target"
		case "urn:ietf:params:oauth:grant-type:token-exchange":
			want["subject_token"] = "subject"
			want["subject_token_type"] = "urn:ietf:params:oauth:token-type:jwt"
			want["requested_token_type"] = "urn:ietf:params:oauth:token-type:access_token"
			want["audience"] = "target"
		default:
			t.Errorf("unexpected grant type %q", r.Form.Get("grant_type"))
		}
		for key, value := range want {
			if got := r.Form.Get(key); got != value {
				t.Errorf("form[%q] = %q, want %q", key, got, value)
			}
		}
		if err := json.NewEncoder(w).Encode(map[string]string{"access_token": "access-token", "token_type": "Bearer"}); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	defer server.Close()

	config, remote, err := remoteBenchmarkConfigFromEnv(func(key string) string {
		return map[string]string{
			"STS_BENCHMARK_URL":              server.URL + "/sts/",
			"STS_BENCHMARK_CLIENT_ASSERTION": "assertion",
			"STS_BENCHMARK_SUBJECT_TOKEN":    "subject",
			"STS_BENCHMARK_TARGET":           "target",
		}[key]
	})
	if err != nil || !remote {
		t.Fatalf("remote config = (remote %v, err %v), want remote without error", remote, err)
	}
	if config.endpoint != server.URL+"/sts/token" {
		t.Fatalf("endpoint = %q, want %q", config.endpoint, server.URL+"/sts/token")
	}
	for _, benchmark := range config.benchmarks {
		if _, err := benchmarkTokenRequest(t, config.endpoint, benchmark.form); err != nil {
			t.Errorf("%s request: %v", benchmark.name, err)
		}
	}
}

func TestNoRemoteBenchmarkConfigWithoutURL(t *testing.T) {
	config, remote, err := remoteBenchmarkConfigFromEnv(func(string) string { return "" })
	if err != nil || remote || config.endpoint != "" {
		t.Fatalf("config = (%+v, remote %v, err %v), want empty local config", config, remote, err)
	}
}

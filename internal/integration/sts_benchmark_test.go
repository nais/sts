//go:build integration_test

package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/nais/sts/internal/oauth"
)

// BenchmarkSts measures steady-state token issuance over HTTP, including JWT
// verification, database lookups, and token signing. Container and token setup
// are excluded from the measurements.
func BenchmarkSts(b *testing.B) {
	oauthServer := startMockOAuthServer(b)
	stsConfig := startSts(b, oauthServer)
	internalSts := stsConfig.InternalAddress
	stsAddress := stsConfig.Address

	clientAssertion := getClientToken(b, oauthServer, fixtures.Client1)
	subjectToken, _ := getSubjectTokenFromIssuer(b, oauthServer, "subject1")

	benchmarks := []struct {
		name string
		form url.Values
	}{
		{
			name: "client_credentials",
			form: clientCredentialsForm(clientAssertion, fixtures.Client2.ID),
		},
		{
			name: "token_exchange",
			form: tokenExchangeForm(clientAssertion, subjectToken, fixtures.Client2.ID),
		},
	}

	for _, benchmark := range benchmarks {
		b.Run(benchmark.name, func(b *testing.B) {
			// Warm remote JWKS and signing-key caches. This keeps the benchmark
			// focused on steady-state request cost rather than one-time fetches.
			if _, err := benchmarkTokenRequest(b, stsAddress.Endpoint("/token"), benchmark.form); err != nil {
				b.Fatal(err)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				response, err := benchmarkTokenRequest(b, stsAddress.Endpoint("/token"), benchmark.form)
				if err != nil {
					b.Fatal(err)
				}
				if response.AccessToken == "" {
					b.Fatal("STS returned an empty access token")
				}
			}
		})
	}

	if output := os.Getenv("STS_BENCHMARK_METRICS_FILE"); output != "" {
		writeBenchmarkMetrics(b, internalSts.Endpoint("/metrics"), output)
	}
}

func writeBenchmarkMetrics(b *testing.B, endpoint, output string) {
	b.Helper()

	response, err := http.Get(endpoint) //nolint:noctx // Test server request is bounded by benchmark cleanup.
	if err != nil {
		b.Fatalf("get benchmark metrics: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		b.Fatalf("get benchmark metrics: server returned %s", response.Status)
	}
	contents, err := io.ReadAll(response.Body)
	if err != nil {
		b.Fatalf("read benchmark metrics: %v", err)
	}
	if err := os.WriteFile(output, contents, 0o600); err != nil {
		b.Fatalf("write benchmark metrics: %v", err)
	}
}

func benchmarkTokenRequest(b *testing.B, endpoint string, form url.Values) (*oauth.AccessTokenResponse, error) {
	b.Helper()

	req, err := http.NewRequestWithContext(b.Context(), http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request returned %s", resp.Status)
	}

	response := new(oauth.AccessTokenResponse)
	if err := json.NewDecoder(resp.Body).Decode(response); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	return response, nil
}

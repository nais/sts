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
	var endpoint, internalMetricsEndpoint string
	var benchmarks []benchmarkCase
	remoteConfig, remote, err := remoteBenchmarkConfigFromEnv(os.Getenv)
	if err != nil {
		b.Fatal(err)
	}
	if remote {
		endpoint = remoteConfig.endpoint
		benchmarks = remoteConfig.benchmarks
	} else {
		oauthServer := startMockOAuthServer(b)
		stsConfig := startSts(b, oauthServer)
		internalMetricsEndpoint = stsConfig.InternalAddress.Endpoint("/metrics")

		clientAssertion := getClientToken(b, oauthServer, fixtures.Client1)
		subjectToken, _ := getSubjectTokenFromIssuer(b, oauthServer, "subject1")
		endpoint = stsConfig.Address.Endpoint("/token")
		benchmarks = []benchmarkCase{
			{name: "client_credentials", form: clientCredentialsForm(clientAssertion, fixtures.Client2.ID)},
			{name: "token_exchange", form: tokenExchangeForm(clientAssertion, subjectToken, fixtures.Client2.ID)},
		}
	}

	for _, benchmark := range benchmarks {
		b.Run(benchmark.name, func(b *testing.B) {
			// Warm remote JWKS and signing-key caches. This keeps the benchmark
			// focused on steady-state request cost rather than one-time fetches.
			if _, err := benchmarkTokenRequest(b, endpoint, benchmark.form); err != nil {
				b.Fatal(err)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				response, err := benchmarkTokenRequest(b, endpoint, benchmark.form)
				if err != nil {
					b.Fatal(err)
				}
				if response.AccessToken == "" {
					b.Fatal("STS returned an empty access token")
				}
			}
		})
	}

	if !remote {
		if output := os.Getenv("STS_BENCHMARK_METRICS_FILE"); output != "" {
			writeBenchmarkMetrics(b, internalMetricsEndpoint, output)
		}
	}
}

type remoteBenchmarkConfig struct {
	endpoint   string
	benchmarks []benchmarkCase
}

type benchmarkCase struct {
	name string
	form url.Values
}

func remoteBenchmarkConfigFromEnv(getenv func(string) string) (remoteBenchmarkConfig, bool, error) {
	baseURL := getenv("STS_BENCHMARK_URL")
	if baseURL == "" {
		return remoteBenchmarkConfig{}, false, nil
	}

	parsedURL, err := url.Parse(baseURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Hostname() == "" {
		return remoteBenchmarkConfig{}, true, fmt.Errorf("STS_BENCHMARK_URL must be a usable http or https URL")
	}
	clientAssertion := getenv("STS_BENCHMARK_CLIENT_ASSERTION")
	subjectToken := getenv("STS_BENCHMARK_SUBJECT_TOKEN")
	target := getenv("STS_BENCHMARK_TARGET")
	if tokenFile := getenv("STS_BENCHMARK_TOKEN_FILE"); tokenFile != "" {
		token, err := os.ReadFile(tokenFile)
		if err != nil {
			return remoteBenchmarkConfig{}, true, fmt.Errorf("read STS_BENCHMARK_TOKEN_FILE %q: %w", tokenFile, err)
		}
		clientAssertion = strings.TrimSpace(string(token))
		subjectToken = clientAssertion
	}
	if clientAssertion == "" || subjectToken == "" || target == "" {
		return remoteBenchmarkConfig{}, true, fmt.Errorf("STS_BENCHMARK_CLIENT_ASSERTION, STS_BENCHMARK_SUBJECT_TOKEN, and STS_BENCHMARK_TARGET are required with STS_BENCHMARK_URL")
	}

	parsedURL.Path = strings.TrimRight(parsedURL.Path, "/") + "/token"
	parsedURL.RawPath = ""
	return remoteBenchmarkConfig{
		endpoint: parsedURL.String(),
		benchmarks: []benchmarkCase{
			{name: "client_credentials", form: clientCredentialsForm(clientAssertion, target)},
			{name: "token_exchange", form: tokenExchangeForm(clientAssertion, subjectToken, target)},
		},
	}, true, nil
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

func benchmarkTokenRequest(t testing.TB, endpoint string, form url.Values) (*oauth.AccessTokenResponse, error) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint, strings.NewReader(form.Encode()))
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

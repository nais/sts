package server

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nais/sts/internal/config"
)

func TestRouteSeparation(t *testing.T) {
	const issuer = "http://localhost:8080"
	publicHandler, err := publicRouter(issuer)
	if err != nil {
		t.Fatal(err)
	}
	internalHandler := internalRouter(newRegistry())

	for _, path := range []string{"/readyz", "/metrics"} {
		resp := serveRequest(publicHandler, path)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("public %s status = %d, want %d", path, resp.StatusCode, http.StatusNotFound)
		}
		_ = resp.Body.Close()
	}

	resp := serveRequest(publicHandler, "/.well-known/openid-configuration")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var discovery struct {
		Issuer string `json:"issuer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if discovery.Issuer != issuer {
		t.Errorf("discovery issuer = %q, want %q", discovery.Issuer, issuer)
	}

	for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
		resp := serveRequest(internalHandler, path)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("internal %s status = %d, want %d", path, resp.StatusCode, http.StatusOK)
		}
		_ = resp.Body.Close()
	}
}

func TestMetricsIncludeGoAndProcessCollectors(t *testing.T) {
	server := httptest.NewServer(internalRouter(newRegistry()))
	defer server.Close()

	resp := get(t, server.URL+"/metrics")
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, metric := range []string{"go_gc_duration_seconds", "process_cpu_seconds_total"} {
		if !strings.Contains(text, metric) {
			t.Errorf("metrics body does not contain %s", metric)
		}
	}
}

func TestRunCancellation(t *testing.T) {
	publicAddress := freeAddress(t)
	internalAddress := freeAddress(t)
	cfg := config.Config{
		BindAddress:         publicAddress,
		InternalBindAddress: internalAddress,
		Issuer:              "http://" + publicAddress,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg) }()
	waitForHTTP(t, "http://"+publicAddress+"/oauth/token")
	waitForHTTP(t, "http://"+internalAddress+"/healthz")
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after context cancellation")
	}
}

func TestRunClosesPublicListenerWhenInternalListenFails(t *testing.T) {
	publicAddress := freeAddress(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	err = Run(context.Background(), config.Config{BindAddress: publicAddress, InternalBindAddress: listener.Addr().String()})
	if err == nil {
		t.Fatal("Run returned nil error")
	}
	if _, err := net.Dial("tcp", publicAddress); err == nil {
		t.Fatal("public listener remained open")
	}
}

func serveRequest(handler http.Handler, path string) *http.Response {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	return recorder.Result()
}

func get(t *testing.T, url string) *http.Response {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

func waitForHTTP(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server did not become ready: %s", url)
}

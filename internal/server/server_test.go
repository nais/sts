package server

import (
	"context"
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
	public := httptest.NewServer(publicRouter())
	defer public.Close()
	internal := httptest.NewServer(internalRouter(newRegistry()))
	defer internal.Close()

	for _, path := range []string{"/healthz", "/readyz", "/metrics", "/.well-known/openid-configuration"} {
		resp := get(t, public.URL+path)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("public %s status = %d, want %d", path, resp.StatusCode, http.StatusNotFound)
		}
		_ = resp.Body.Close()
	}
	for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
		resp := get(t, internal.URL+path)
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
	cfg := config.Config{BindAddress: publicAddress, InternalBindAddress: internalAddress}

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

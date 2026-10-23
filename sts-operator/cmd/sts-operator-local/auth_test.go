package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nais/sts-operator/internal/config"
	"k8s.io/client-go/rest"
)

type tokenRequest struct {
	method string
	path   string
	body   struct {
		Spec struct {
			Audiences         []string `json:"audiences"`
			ExpirationSeconds *int64   `json:"expirationSeconds"`
		} `json:"spec"`
	}
}

// fakeKubeAPI serves the TokenRequest subresource and records each request.
func fakeKubeAPI(t *testing.T, status int, token string) (*httptest.Server, *[]tokenRequest) {
	t.Helper()
	var requests []tokenRequest
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req tokenRequest
		req.method = r.Method
		req.path = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&req.body); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		requests = append(requests, req)
		if status != http.StatusCreated {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","code":` + fmt.Sprint(status) + `}`))
			return
		}
		tok := token
		if tok != "" {
			tok = fmt.Sprintf("%s-%d", token, n.Add(1))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"kind":       "TokenRequest",
			"apiVersion": "authentication.k8s.io/v1",
			"status":     map[string]any{"token": tok},
		})
	}))
	t.Cleanup(srv.Close)
	return srv, &requests
}

func localConfig(sa string) *config.Config {
	return &config.Config{LocalServiceAccount: sa}
}

func TestFetchAPIServerToken_LocalServiceAccount(t *testing.T) {
	srv, requests := fakeKubeAPI(t, http.StatusCreated, "genuine")
	kubeConfig := &rest.Config{Host: srv.URL, Timeout: 0}

	cb, err := fetchAPIServerToken(localConfig("ns/sa"), kubeConfig)
	if err != nil {
		t.Fatalf("fetchAPIServerToken: %v", err)
	}

	first, err := cb(context.Background())
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	second, err := cb(context.Background())
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if first == second {
		t.Errorf("expected a fresh token per invocation, got %q twice", first)
	}
	if kubeConfig.Timeout != 0 {
		t.Errorf("caller rest.Config mutated: timeout = %v", kubeConfig.Timeout)
	}

	if len(*requests) != 2 {
		t.Fatalf("expected 2 apiserver requests, got %d", len(*requests))
	}
	for _, req := range *requests {
		if req.method != http.MethodPost {
			t.Errorf("method = %s, want POST", req.method)
		}
		if req.path != "/api/v1/namespaces/ns/serviceaccounts/sa/token" {
			t.Errorf("path = %s", req.path)
		}
		if len(req.body.Spec.Audiences) != 1 || req.body.Spec.Audiences[0] != "nais" {
			t.Errorf("audiences = %v, want [nais]", req.body.Spec.Audiences)
		}
		if req.body.Spec.ExpirationSeconds == nil || *req.body.Spec.ExpirationSeconds != 3600 {
			t.Errorf("expirationSeconds = %v, want 3600", req.body.Spec.ExpirationSeconds)
		}
	}
}

func TestFetchAPIServerToken_APIFailure(t *testing.T) {
	srv, _ := fakeKubeAPI(t, http.StatusForbidden, "")
	cb, err := fetchAPIServerToken(localConfig("ns/sa"), &rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatalf("fetchAPIServerToken: %v", err)
	}
	if _, err := cb(context.Background()); err == nil || !strings.Contains(err.Error(), "ns/sa") {
		t.Fatalf("expected wrapped API error naming the service account, got %v", err)
	}
}

func TestFetchAPIServerToken_EmptyToken(t *testing.T) {
	srv, _ := fakeKubeAPI(t, http.StatusCreated, "")
	cb, err := fetchAPIServerToken(localConfig("ns/sa"), &rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatalf("fetchAPIServerToken: %v", err)
	}
	if tok, err := cb(context.Background()); err == nil || tok != "" {
		t.Fatalf("expected error for empty token, got token=%q err=%v", tok, err)
	}
}

func TestFetchAPIServerToken_CallerCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)

	cb, err := fetchAPIServerToken(localConfig("ns/sa"), &rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatalf("fetchAPIServerToken: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cb(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestFetchAPIServerToken_RequiresServiceAccount(t *testing.T) {
	if _, err := fetchAPIServerToken(localConfig(""), nil); err == nil {
		t.Fatal("expected error when local service account is missing")
	}
}

func TestFetchAPIServerToken_MalformedServiceAccount(t *testing.T) {
	for _, sa := range []string{"ns", "/name", "ns/", "/", "a/b/c", "ns/name/", "ns//name"} {
		t.Run(sa, func(t *testing.T) {
			if _, err := fetchAPIServerToken(localConfig(sa), &rest.Config{Host: "http://127.0.0.1:1"}); err == nil {
				t.Fatalf("expected error for %q", sa)
			}
		})
	}
}

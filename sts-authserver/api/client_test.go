package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestTokenFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	callback := TokenFromFile(path)

	if _, err := callback(t.Context()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected missing-file error, got %v", err)
	}
	for _, test := range []struct {
		content string
		want    string
	}{
		{"  first-token\n", "first-token"},
		{"second-token\n", "second-token"},
		{" \n\t", ""},
		{"", ""},
	} {
		if err := os.WriteFile(path, []byte(test.content), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := callback(t.Context())
		if test.want == "" {
			if err == nil || !strings.Contains(err.Error(), "is empty") {
				t.Fatalf("expected empty-token error, got %v", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
		if got != test.want {
			t.Fatalf("got token %q, want %q", got, test.want)
		}
	}
}

func TestRegistrationClientRegister(t *testing.T) {
	for _, issuer := range []string{"https://sts.example", "https://sts.example/"} {
		t.Run(issuer, func(t *testing.T) {
			const clientID = "dev:team:app"
			transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodPost || req.URL.String() != "https://sts.example/v1/registration/client" {
					t.Fatalf("unexpected request: %s %s", req.Method, req.URL)
				}
				if got := req.Header.Get("Authorization"); got != "Bearer token" {
					t.Fatalf("unexpected Authorization: %q", got)
				}
				if got := req.Header.Get("Content-Type"); got != "application/json" {
					t.Fatalf("unexpected Content-Type: %q", got)
				}
				var registration ClientRegistration
				if err := json.NewDecoder(req.Body).Decode(&registration); err != nil {
					t.Fatalf("decode request: %v", err)
				}
				if registration.SoftwareStatement == "" {
					t.Fatal("missing signed software statement")
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"client_id":"dev:team:app","software_statement":"signed"}`)),
				}, nil
			})
			client, err := NewRegistrationClient(STSIssuer(issuer), func(context.Context) (string, error) {
				return "token", nil
			}, WithHTTPClient(&http.Client{Transport: transport}))
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Register(t.Context(), SoftwareStatement{Client: Client{Namespace: "team", Name: "app"}})
			if err != nil {
				t.Fatal(err)
			}
			if response.ClientID != clientID || response.SoftwareStatement != "signed" {
				t.Fatalf("unexpected response: %+v", response)
			}
		})
	}
}

func TestRegistrationClientUnexpectedStatus(t *testing.T) {
	for _, test := range []struct {
		name   string
		method string
		status int
		body   string
	}{
		{"register created", http.MethodPost, http.StatusCreated, `{}`},
		{"register accepted", http.MethodPost, http.StatusAccepted, ""},
		{"register no content", http.MethodPost, http.StatusNoContent, ""},
		{"register redirect", http.MethodPost, http.StatusFound, "redirect"},
		{"register unauthorized", http.MethodPost, http.StatusUnauthorized, "unauthorized"},
		{"delete OK", http.MethodDelete, http.StatusOK, `{}`},
		{"delete empty OK", http.MethodDelete, http.StatusOK, ""},
		{"delete accepted", http.MethodDelete, http.StatusAccepted, ""},
		{"delete redirect", http.MethodDelete, http.StatusFound, "redirect"},
		{"delete server error", http.MethodDelete, http.StatusInternalServerError, "server error"},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: test.status,
					Body:       io.NopCloser(strings.NewReader(test.body)),
				}, nil
			})
			client, err := NewRegistrationClient("https://sts.example", func(context.Context) (string, error) {
				return "token", nil
			}, WithHTTPClient(&http.Client{Transport: transport}))
			if err != nil {
				t.Fatal(err)
			}
			if test.method == http.MethodPost {
				var response *ClientRegistrationResponse
				response, err = client.Register(t.Context(), SoftwareStatement{Client: Client{Namespace: "team", Name: "app"}})
				if response != nil {
					t.Fatalf("expected no registration response, got %+v", response)
				}
			} else {
				err = client.Delete(t.Context(), "dev:team:app")
			}
			var httpErr HTTPError
			if !errors.As(err, &httpErr) {
				t.Fatalf("expected HTTPError, got %v", err)
			}
			if httpErr.StatusCode != test.status || httpErr.Body != test.body {
				t.Fatalf("unexpected HTTPError: %+v", httpErr)
			}
		})
	}
}

func TestRegistrationClientDelete(t *testing.T) {
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodDelete || req.URL.String() != "https://sts.example/v1/registration/client/dev:team:app" {
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL)
		}
		if got := req.Header.Get("Authorization"); got != "Bearer token" {
			t.Fatalf("unexpected Authorization: %q", got)
		}
		if req.Body != nil {
			t.Fatal("DELETE should not have a request body")
		}
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	})
	client, err := NewRegistrationClient("https://sts.example", func(context.Context) (string, error) {
		return "token", nil
	}, WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Delete(t.Context(), "dev:team:app"); err != nil {
		t.Fatal(err)
	}
}

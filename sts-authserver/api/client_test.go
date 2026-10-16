package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
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
			response, err := client.Register(context.Background(), SoftwareStatement{ClientID: clientID})
			if err != nil {
				t.Fatal(err)
			}
			if response.ClientID != clientID || response.SoftwareStatement != "signed" {
				t.Fatalf("unexpected response: %+v", response)
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
	if err := client.Delete(context.Background(), "dev:team:app"); err != nil {
		t.Fatal(err)
	}
}

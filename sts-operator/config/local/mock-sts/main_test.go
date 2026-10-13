package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMockProtocol(t *testing.T) {
	const issuer = "http://mock-sts.sts-operator-dev.svc.cluster.local:8080"
	h := handler(issuer)
	request := func(method, path, body string, want int) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
		if w.Code != want {
			t.Fatalf("%s %s: status %d, want %d: %s", method, path, w.Code, want, w.Body.String())
		}
		return w
	}

	request(http.MethodGet, "/healthz", "", http.StatusOK)
	metadata := request(http.MethodGet, "/.well-known/oauth-authorization-server", "", http.StatusOK)
	if metadata.Header().Get("Content-Type") != "application/json" {
		t.Fatal("discovery must return application/json")
	}
	var document map[string]string
	if err := json.Unmarshal(metadata.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document["issuer"] != issuer || document["jwks_uri"] != issuer+"/jwks" || document["token_endpoint"] != issuer+"/token" {
		t.Fatalf("invalid discovery: %v", document)
	}
	request(http.MethodGet, "/jwks", "", http.StatusOK)
	request(http.MethodPost, "/token", "", http.StatusNotImplemented)
	request(http.MethodPost, "/registration/client", "invalid", http.StatusBadRequest)
	request(http.MethodPost, "/registration/client", `{}`, http.StatusBadRequest)

	const body = `{"client_name":"dev:team:app","software_statement":"signed-statement"}`
	request(http.MethodPost, "/registration/client", body, http.StatusCreated)
	// Repeated registrations replace, rather than duplicate, a client.
	request(http.MethodPost, "/registration/client", body, http.StatusCreated)
	registered := request(http.MethodGet, "/registrations", "", http.StatusOK)
	var clients map[string]registration
	if err := json.Unmarshal(registered.Body.Bytes(), &clients); err != nil {
		t.Fatal(err)
	}
	if len(clients) != 1 || clients["dev:team:app"].SoftwareStatement != "signed-statement" {
		t.Fatalf("unexpected registrations: %v", clients)
	}
	request(http.MethodDelete, "/registration/client/dev:team:app", "", http.StatusNoContent)
	request(http.MethodDelete, "/registration/client/dev:team:app", "", http.StatusNoContent)
	deleted := request(http.MethodGet, "/registrations", "", http.StatusOK)
	if strings.TrimSpace(deleted.Body.String()) != "{}" {
		t.Fatalf("client not removed: %s", deleted.Body.String())
	}
}

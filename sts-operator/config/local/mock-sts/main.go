// Development-only stub for the operator's current registration protocol.
// No authentication, signature verification, policy enforcement, or token issuance.
package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type registration struct {
	ClientName        string `json:"client_name"`
	SoftwareStatement string `json:"software_statement"`
}

func handler(issuer string) http.Handler {
	var mu sync.Mutex
	clients := make(map[string]registration)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"issuer": issuer, "jwks_uri": issuer + "/jwks", "token_endpoint": issuer + "/token",
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"keys": []any{}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "mock_does_not_issue_tokens"})
	})
	mux.HandleFunc("POST /registration/client", func(w http.ResponseWriter, r *http.Request) {
		var payload registration
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&payload); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if payload.ClientName == "" || payload.SoftwareStatement == "" {
			http.Error(w, "client_name and software_statement required", http.StatusBadRequest)
			return
		}
		mu.Lock()
		clients[payload.ClientName] = payload
		mu.Unlock()
		slog.Info("mock registered client", "clientID", payload.ClientName)
		writeJSON(w, http.StatusCreated, payload)
	})
	mux.HandleFunc("DELETE /registration/client/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		mu.Lock()
		delete(clients, id)
		mu.Unlock()
		slog.Info("mock deleted client", "clientID", id)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /registrations", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		writeJSON(w, http.StatusOK, clients)
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		slog.Error("encoding response", "error", err)
	}
}

func main() {
	issuer := strings.TrimRight(os.Getenv("MOCK_STS_ISSUER"), "/")
	if issuer == "" {
		slog.Error("MOCK_STS_ISSUER is required")
		os.Exit(1)
	}
	server := &http.Server{
		Addr: ":8080", Handler: handler(issuer),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	slog.Warn("development mock STS: authentication and JWT verification are disabled")
	if err := server.ListenAndServe(); err != nil {
		slog.Error("serving mock STS", "error", err)
		os.Exit(1)
	}
}

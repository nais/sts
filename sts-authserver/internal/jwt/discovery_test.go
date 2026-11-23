package jwt_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nais/sts/internal/jwk"
	"github.com/nais/sts/internal/jwt"
	"github.com/stretchr/testify/require"
)

func TestTokenVerifierFallsBackToOAuthMetadata(t *testing.T) {
	signer, err := jwk.GenerateSigner()
	require.NoError(t, err)

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	issuer := server.URL + "/"
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "jwks_uri": server.URL + "/jwk"})
	})
	mux.HandleFunc("GET /jwk", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(signer.PublicKeySet())
	})

	verifier, err := jwt.NewTokenVerifier(t.Context(), jwt.WithHttpClient(server.Client()), jwt.WithIssuer(jwt.Issuer(issuer)))
	require.NoError(t, err)

	now := time.Now()
	token, err := signer.SignJWT(map[string]any{"iss": issuer, "sub": "subject", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()})
	require.NoError(t, err)
	_, err = verifier.Verify(t.Context(), token)
	require.NoError(t, err)
}

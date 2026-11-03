package sts

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHTTPClientAdditionalCAFile(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	require.NoError(t, os.WriteFile(caPath, caPEM, 0o600))

	t.Run("empty setting rejects untrusted certificate", func(t *testing.T) {
		client, err := newHTTPClient("")
		require.NoError(t, err)
		resp, err := client.Get(srv.URL)
		if resp != nil {
			_ = resp.Body.Close()
		}
		require.Error(t, err)
	})

	t.Run("additional CA file trusts certificate", func(t *testing.T) {
		client, err := newHTTPClient(caPath)
		require.NoError(t, err)
		resp, err := client.Get(srv.URL)
		require.NoError(t, err)
		assert.NoError(t, resp.Body.Close())
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := newHTTPClient(filepath.Join(t.TempDir(), "missing.pem"))
		require.ErrorContains(t, err, "read additional CA file")
	})

	t.Run("invalid PEM", func(t *testing.T) {
		badPath := filepath.Join(t.TempDir(), "bad.pem")
		require.NoError(t, os.WriteFile(badPath, []byte("not a certificate"), 0o600))
		_, err := newHTTPClient(badPath)
		require.ErrorContains(t, err, "no valid PEM certificates")
	})

	t.Run("preserves timeout and redirect rejection", func(t *testing.T) {
		client, err := newHTTPClient(caPath)
		require.NoError(t, err)
		assert.Equal(t, 10*time.Second, client.Timeout)
		require.NotNil(t, client.CheckRedirect)
		redirectURL, err := url.Parse("https://example.com/other")
		require.NoError(t, err)
		require.ErrorContains(t, client.CheckRedirect(&http.Request{URL: redirectURL}, nil), "redirect")
	})
}

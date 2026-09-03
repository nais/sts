//go:build integration_test

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4/testutils/assert"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestSts(t *testing.T) {
	oauthServer := startMockOAuthServer(t)
	sts := startSts(t, oauthServer)

	t.Run("discovery", func(t *testing.T) {
		resp := get[oidc.DiscoveryConfiguration](t, fmt.Sprintf("%s/.well-known/oauth-authorization-server", sts))
		assert.Equal(t, resp.Issuer, sts)
	})

	t.Run("client credentials", func(t *testing.T) {

	})

	t.Run("token exchange", func(t *testing.T) {

	})
}

func getKubernetesToken(t *testing.T, oauthServer string, environment, namespace, workload string) string {
	t.Helper()
	resp := post[oidc.AccessTokenResponse](t, fmt.Sprintf("%s/%s/token", oauthServer, environment), url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"client1"},
		"client_secret": {"secret1"},
		"ns":            {namespace},
		"workload":      {workload},
	})
	return resp.AccessToken
}

func post[T any](t *testing.T, endpoint string, form url.Values) *T {
	t.Helper()

	body := strings.NewReader(form.Encode())
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint, body)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	ret := new(T)
	err = httphelper.HttpRequest(http.DefaultClient, req, ret)
	if err != nil {
		t.Fatalf("http request failed: %v", err)
	}
	return ret
}

func get[T any](t *testing.T, url string) *T {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	ret := new(T)
	err = httphelper.HttpRequest(http.DefaultClient, req, ret)
	if err != nil {
		t.Fatalf("http request failed: %v", err)
	}
	return ret
}

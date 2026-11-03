package oauth

import (
	"encoding/json"
	nethttp "net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nais/sts/api"
	"github.com/nais/sts/internal/errs"
	"github.com/nais/sts/internal/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestDiscoveryOmitsTokenExchangeWhenDisabled(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(nethttp.MethodGet, "/.well-known/oauth-authorization-server", nil)

	server := &AuthorizationServer{AuthorizationServerConfig: AuthorizationServerConfig{Issuer: "https://sts.example"}}
	server.DiscoveryEndpoint()(recorder, request)

	require.Equal(t, nethttp.StatusOK, recorder.Code)
	var discovery api.DiscoveryMetadata
	require.NoError(t, json.NewDecoder(recorder.Body).Decode(&discovery))
	assert.Equal(t, []api.GrantType{api.GrantTypeClientCredentials}, discovery.GrantTypesSupported)
}

func TestTokenEndpointRejectsTokenExchangeWhenDisabled(t *testing.T) {
	form := url.Values{"grant_type": {string(oidc.GrantTypeTokenExchange)}}
	request := httptest.NewRequest(nethttp.MethodPost, "/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()

	new(AuthorizationServer).TokenEndpoint()(recorder, request)

	require.Equal(t, nethttp.StatusBadRequest, recorder.Code)
	var response errs.ErrorResponse
	require.NoError(t, json.NewDecoder(recorder.Body).Decode(&response))
	assert.Equal(t, "unsupported_grant_type", response.Code)
}

func TestTokenEndpointRejectsInvalidRequests(t *testing.T) {
	for name, test := range map[string]struct {
		query       string
		contentType string
		form        url.Values
		status      int
		description string
	}{
		"json content type": {
			contentType: "application/json",
			status:      nethttp.StatusUnsupportedMediaType,
			description: "content type must be application/x-www-form-urlencoded",
		},
		"body too large": {
			form:        url.Values{"grant_type": {strings.Repeat("a", http.MaxRequestBodySize)}},
			status:      nethttp.StatusBadRequest,
			description: "invalid request body",
		},
		"grant type in query": {
			query:       "?grant_type=" + string(oidc.GrantTypeClientCredentials),
			description: "grant_type missing",
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(nethttp.MethodPost, "/token"+test.query, strings.NewReader(test.form.Encode()))
			contentType := test.contentType
			if contentType == "" {
				contentType = "application/x-www-form-urlencoded"
			}
			request.Header.Set("Content-Type", contentType)
			recorder := httptest.NewRecorder()

			new(AuthorizationServer).TokenEndpoint()(recorder, request)

			status := test.status
			if status == 0 {
				status = nethttp.StatusBadRequest
			}
			require.Equal(t, status, recorder.Code)
			var response errs.ErrorResponse
			require.NoError(t, json.NewDecoder(recorder.Body).Decode(&response))
			assert.Equal(t, "invalid_request", response.Code)
			assert.Equal(t, test.description, response.Description)
		})
	}
}

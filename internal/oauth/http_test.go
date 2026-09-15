package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func TestDiscoveryOmitsTokenExchangeWhenDisabled(t *testing.T) {
	endpoints := &op.Endpoints{
		Token:   op.NewEndpoint("/token"),
		JwksURI: op.NewEndpoint("/jwks"),
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)

	DiscoveryEndpoint(endpoints, AuthorizationServerConfig{Issuer: "https://sts.example"})(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Code)
	var discovery oidc.DiscoveryConfiguration
	require.NoError(t, json.NewDecoder(recorder.Body).Decode(&discovery))
	assert.Equal(t, []oidc.GrantType{oidc.GrantTypeClientCredentials}, discovery.GrantTypesSupported)
}

func TestTokenEndpointRejectsTokenExchangeWhenDisabled(t *testing.T) {
	form := url.Values{"grant_type": {string(oidc.GrantTypeTokenExchange)}}
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()

	new(AuthorizationServer).TokenEndpoint()(recorder, request)

	require.Equal(t, http.StatusBadRequest, recorder.Code)
	var response oidc.Error
	require.NoError(t, json.NewDecoder(recorder.Body).Decode(&response))
	assert.Equal(t, oidc.UnsupportedGrantType, response.ErrorType)
}

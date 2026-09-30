package oauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
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

func TestWriteError(t *testing.T) {
	for name, test := range map[string]struct {
		err         error
		status      int
		errorType   string
		description string
		level       string
	}{
		"plain error": {
			err:         errors.New("private detail"),
			status:      http.StatusInternalServerError,
			errorType:   "server_error",
			description: "internal error",
			level:       "ERROR",
		},
		"server error": {
			err:         oidc.ErrServerError().WithDescription("private detail"),
			status:      http.StatusInternalServerError,
			errorType:   "server_error",
			description: "internal error",
			level:       "ERROR",
		},
		"client error with status": {
			err:         op.NewStatusError(WrapError(oidc.ErrInvalidClient(), "authentication failed", errors.New("private detail")), http.StatusUnauthorized),
			status:      http.StatusUnauthorized,
			errorType:   "invalid_client",
			description: "authentication failed",
			level:       "WARN",
		},
	} {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			t.Cleanup(func() { slog.SetDefault(previous) })

			recorder := httptest.NewRecorder()
			WriteError(recorder, httptest.NewRequest(http.MethodPost, "/token", nil), test.err)

			assert.Equal(t, test.status, recorder.Code)
			assert.NotContains(t, recorder.Body.String(), "private detail")
			var body struct {
				Error       string `json:"error"`
				Description string `json:"error_description"`
			}
			require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
			assert.Equal(t, test.errorType, body.Error)
			assert.Equal(t, test.description, body.Description)
			assert.Equal(t, 1, strings.Count(logs.String(), "private detail"))
			assert.Contains(t, logs.String(), "level="+test.level)
		})
	}
}

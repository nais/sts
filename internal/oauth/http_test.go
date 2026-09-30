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
	var response ErrorResponse
	require.NoError(t, json.NewDecoder(recorder.Body).Decode(&response))
	assert.Equal(t, CodeUnsupportedGrantType, response.Code)
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
			status:      http.StatusUnsupportedMediaType,
			description: "content type must be application/x-www-form-urlencoded",
		},
		"body too large": {
			form:        url.Values{"grant_type": {strings.Repeat("a", maxTokenRequestBodySize)}},
			status:      http.StatusRequestEntityTooLarge,
			description: "request body exceeds 65536 bytes",
		},
		"grant type in query": {
			query:       "?grant_type=" + string(oidc.GrantTypeClientCredentials),
			description: "grant_type missing",
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/token"+test.query, strings.NewReader(test.form.Encode()))
			contentType := test.contentType
			if contentType == "" {
				contentType = "application/x-www-form-urlencoded"
			}
			request.Header.Set("Content-Type", contentType)
			recorder := httptest.NewRecorder()

			new(AuthorizationServer).TokenEndpoint()(recorder, request)

			status := test.status
			if status == 0 {
				status = http.StatusBadRequest
			}
			require.Equal(t, status, recorder.Code)
			var response ErrorResponse
			require.NoError(t, json.NewDecoder(recorder.Body).Decode(&response))
			assert.Equal(t, CodeInvalidRequest, response.Code)
			assert.Equal(t, test.description, response.Description)
		})
	}
}

func TestRequireContentType(t *testing.T) {
	tests := map[string]struct {
		contentType string
		wantErr     bool
	}{
		"json":              {contentType: "application/json"},
		"json with charset": {contentType: "application/json; charset=utf-8"},
		"missing":           {wantErr: true},
		"wrong type":        {contentType: "text/plain", wantErr: true},
		"malformed":         {contentType: "application/json; charset", wantErr: true},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/", nil)
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}

			err := RequireContentType(request, "application/json")
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
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
		"unwrapped public error": {
			err:         NewPublicError("private detail"),
			status:      http.StatusInternalServerError,
			errorType:   "server_error",
			description: "internal error",
			level:       "ERROR",
		},
		"server error": {
			err:         NewErrorResponse(CodeServerError, "private detail"),
			status:      http.StatusInternalServerError,
			errorType:   "server_error",
			description: "internal error",
			level:       "ERROR",
		},
		"client error with status": {
			err:         NewErrorResponse(CodeInvalidClient, "authentication failed").Wrap(errors.New("private detail")).WithStatus(http.StatusUnauthorized),
			status:      http.StatusUnauthorized,
			errorType:   "invalid_client",
			description: "authentication failed",
			level:       "WARN",
		},
		"invalid token": {
			err:         NewErrorResponse(CodeInvalidToken, "authentication failed").Wrap(errors.New("private detail")),
			status:      http.StatusUnauthorized,
			errorType:   "invalid_token",
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

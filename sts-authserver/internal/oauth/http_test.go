package oauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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
			request := httptest.NewRequest(nethttp.MethodPost, "/", nil)
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}

			err := http.RequireContentType(request, "application/json")
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestHandlerFuncHidesPlainError(t *testing.T) {
	recorder := httptest.NewRecorder()
	http.HandlerFunc(func(nethttp.ResponseWriter, *nethttp.Request) error { return errors.New("private detail") })(recorder, httptest.NewRequest(nethttp.MethodPost, "/", nil))

	assert.Equal(t, nethttp.StatusInternalServerError, recorder.Code)
	var body errs.ErrorResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, "internal error", body.Description)
}

func TestHandlerFuncLogsWrappingContext(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	recorder := httptest.NewRecorder()
	http.HandlerFunc(func(nethttp.ResponseWriter, *nethttp.Request) error {
		return fmt.Errorf("context: %w", errs.InvalidTarget(errors.New("reason"), "described"))
	})(recorder, httptest.NewRequest(nethttp.MethodPost, "/", nil))

	var body errs.ErrorResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, "described", body.Description)
	assert.Contains(t, logs.String(), "context: described: reason")
}

func TestWriteError(t *testing.T) {
	for name, test := range map[string]struct {
		err         errs.Error
		status      int
		errorType   string
		description string
		level       string
	}{
		"server error": {
			err:         errs.ServerError(errors.New("private detail")),
			status:      nethttp.StatusInternalServerError,
			errorType:   "server_error",
			description: "internal error",
			level:       "ERROR",
		},
		"sentinel status": {
			err:         errs.UnsupportedMediaType(errors.New("private detail"), "authentication failed"),
			status:      nethttp.StatusUnsupportedMediaType,
			errorType:   "invalid_request",
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
			http.WriteError(recorder, httptest.NewRequest(nethttp.MethodPost, "/token", nil), test.err)

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

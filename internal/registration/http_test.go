package registration

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func TestWithLoggedHTTPStatus(t *testing.T) {
	for _, test := range []struct {
		message string
		status  int
		level   string
	}{
		{message: "unauthorized", status: http.StatusUnauthorized, level: "WARN"},
		{message: "invalid software statement", status: http.StatusBadRequest, level: "WARN"},
		{message: "failed to save registration", status: http.StatusInternalServerError, level: "ERROR"},
		{message: "failed to delete registration", status: http.StatusInternalServerError, level: "ERROR"},
	} {
		t.Run(test.message, func(t *testing.T) {
			var logs bytes.Buffer
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			t.Cleanup(func() { slog.SetDefault(previous) })

			request := httptest.NewRequest(http.MethodPost, "/v1/registration/client", nil)
			response := httptest.NewRecorder()
			op.WriteError(response, request, withLoggedHTTPStatus(request.Context(), test.message, errors.New("private detail"), test.status), slog.Default())

			assert.Equal(t, test.status, response.Code)
			var body oidc.Error
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
			assert.Equal(t, test.message, body.Description)
			assert.NotContains(t, response.Body.String(), "private detail")
			assert.Contains(t, logs.String(), "private detail")
			assert.Contains(t, logs.String(), "level="+test.level)
		})
	}
}

func TestValidateJSONContentType(t *testing.T) {
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
			request := httptest.NewRequest(http.MethodPost, "/v1/registration/client", nil)
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}

			err := validateContentType(request)
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestDecodeClientRegistration(t *testing.T) {
	tests := map[string]struct {
		body    string
		want    ClientRegistration
		wantErr bool
	}{
		"valid": {
			body: `{"software_statement":"statement"}`,
			want: ClientRegistration{SoftwareStatement: "statement"},
		},
		"unknown field": {
			body:    `{"software_statement":"statement","unknown":true}`,
			wantErr: true,
		},
		"removed client name": {
			body:    `{"client_name":"client","software_statement":"statement"}`,
			wantErr: true,
		},
		"second JSON value": {
			body:    `{"software_statement":"statement"} {}`,
			wantErr: true,
		},
		"trailing malformed data": {
			body:    `{"software_statement":"statement"} trailing`,
			wantErr: true,
		},
		"null": {
			body:    `null`,
			wantErr: true,
		},
		"missing software statement": {
			body:    `{}`,
			wantErr: true,
		},
		"blank software statement": {
			body:    `{"software_statement":"  "}`,
			wantErr: true,
		},
		"software statement too long": {
			body:    `{"software_statement":"` + strings.Repeat("a", maxSoftwareStatementLength+1) + `"}`,
			wantErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/registration/client", strings.NewReader(test.body))
			response := httptest.NewRecorder()

			got, err := decodeClientRegistration(response, request)
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestDecodeClientRegistrationRejectsOversizedBody(t *testing.T) {
	body, err := json.Marshal(ClientRegistration{
		SoftwareStatement: strings.Repeat("a", maxRegistrationBodySize),
	})
	require.NoError(t, err)

	request := httptest.NewRequest(http.MethodPost, "/v1/registration/client", strings.NewReader(string(body)))
	response := httptest.NewRecorder()

	_, err = decodeClientRegistration(response, request)
	var maxBytesError *http.MaxBytesError
	require.ErrorAs(t, err, &maxBytesError)
	require.EqualValues(t, maxRegistrationBodySize, maxBytesError.Limit)
}

func TestUnsupportedMediaTypeError(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/v1/registration/client", nil)
	require.Error(t, validateContentType(request))
}

package registration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
			request := httptest.NewRequest(http.MethodPost, "/registration/client", nil)
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
			body: `{"client_name":"client","software_statement":"statement"}`,
			want: ClientRegistration{ClientName: "client", SoftwareStatement: "statement"},
		},
		"unknown field": {
			body:    `{"client_name":"client","software_statement":"statement","unknown":true}`,
			wantErr: true,
		},
		"second JSON value": {
			body:    `{"client_name":"client","software_statement":"statement"} {}`,
			wantErr: true,
		},
		"trailing malformed data": {
			body:    `{"client_name":"client","software_statement":"statement"} trailing`,
			wantErr: true,
		},
		"null": {
			body:    `null`,
			wantErr: true,
		},
		"missing client name": {
			body:    `{"software_statement":"statement"}`,
			wantErr: true,
		},
		"blank client name": {
			body:    `{"client_name":"  ","software_statement":"statement"}`,
			wantErr: true,
		},
		"client name too long": {
			body:    `{"client_name":"` + strings.Repeat("a", maxClientNameLength+1) + `","software_statement":"statement"}`,
			wantErr: true,
		},
		"missing software statement": {
			body:    `{"client_name":"client"}`,
			wantErr: true,
		},
		"blank software statement": {
			body:    `{"client_name":"client","software_statement":"  "}`,
			wantErr: true,
		},
		"software statement too long": {
			body:    `{"client_name":"client","software_statement":"` + strings.Repeat("a", maxSoftwareStatementLength+1) + `"}`,
			wantErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/registration/client", strings.NewReader(test.body))
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
		ClientName:        strings.Repeat("a", maxRegistrationBodySize),
		SoftwareStatement: "statement",
	})
	require.NoError(t, err)

	request := httptest.NewRequest(http.MethodPost, "/registration/client", strings.NewReader(string(body)))
	response := httptest.NewRecorder()

	_, err = decodeClientRegistration(response, request)
	var maxBytesError *http.MaxBytesError
	require.ErrorAs(t, err, &maxBytesError)
	require.EqualValues(t, maxRegistrationBodySize, maxBytesError.Limit)
}

func TestUnsupportedMediaTypeError(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/registration/client", nil)
	require.Error(t, validateContentType(request))
}

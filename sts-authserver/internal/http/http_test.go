package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nais/sts/internal/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

			err := RequireContentType(request, "application/json")
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
	HandlerFunc(func(nethttp.ResponseWriter, *nethttp.Request) error { return errors.New("private detail") })(recorder, httptest.NewRequest(nethttp.MethodPost, "/", nil))

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
	HandlerFunc(func(nethttp.ResponseWriter, *nethttp.Request) error {
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
			WriteError(recorder, httptest.NewRequest(nethttp.MethodPost, "/token", nil), test.err)

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

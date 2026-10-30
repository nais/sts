package http

import (
	"bytes"
	"encoding/json"
	"log/slog"
	nethttp "net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/nais/sts/internal/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestErrorLogRoute(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	router := chi.NewRouter()
	router.Delete("/v1/registration/client/{id}", HandlerFunc(func(nethttp.ResponseWriter, *nethttp.Request) error {
		return errs.InvalidRequest(nil, "invalid client")
	}))
	request := httptest.NewRequest(nethttp.MethodDelete, "/v1/registration/client/private-client?secret=hidden", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	var record map[string]any
	require.NoError(t, json.Unmarshal(output.Bytes(), &record))
	assert.Equal(t, "request error", record["msg"])
	assert.Equal(t, "WARN", record["level"])
	assert.Equal(t, "DELETE", record["method"])
	assert.Equal(t, "/v1/registration/client/{id}", record["route"])
	assert.Equal(t, "invalid_request", record["code"])
	assert.Equal(t, float64(400), record["status_code"])
	assert.NotContains(t, output.String(), "private-client")
	assert.NotContains(t, output.String(), "hidden")
	assert.Equal(t, nethttp.StatusBadRequest, response.Code)
}

func TestRequestErrorLogWithoutRoute(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	WriteError(httptest.NewRecorder(), httptest.NewRequest(nethttp.MethodPost, "/token", nil), errs.ServerError(nil))
	var record map[string]any
	require.NoError(t, json.Unmarshal(output.Bytes(), &record))
	assert.Equal(t, "ERROR", record["level"])
	assert.Equal(t, "POST", record["method"])
	assert.NotContains(t, record, "route")
}

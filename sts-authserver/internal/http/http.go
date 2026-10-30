package http

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	nethttp "net/http"
	"net/url"
	"reflect"

	"github.com/nais/sts/internal/errs"
)

const (
	MediaTypeJSON      = "application/json"
	MediaTypeForm      = "application/x-www-form-urlencoded"
	MaxRequestBodySize = 64 << 10
)

func WriteError(w nethttp.ResponseWriter, r *nethttp.Request, e errs.Error) {
	resp := e.HTTPError()
	level := slog.LevelWarn
	if e.Internal() {
		level = slog.LevelError
	}

	slog.LogAttrs(r.Context(), level, "request error", e.LogAttrs()...)

	w.Header().Set("Content-Type", MediaTypeJSON)
	w.WriteHeader(resp.Status)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.ErrorContext(r.Context(), "encode error response", "error", err)
	}
}

func WriteJSON(w nethttp.ResponseWriter, r *nethttp.Request, v any) {
	if v == nil || (reflect.ValueOf(v).Kind() == reflect.Pointer && reflect.ValueOf(v).IsNil()) {
		w.WriteHeader(nethttp.StatusInternalServerError)
		return
	}

	if h := w.Header().Get("content-type"); h == "" {
		w.Header().Set("content-type", MediaTypeJSON)
	}

	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.ErrorContext(r.Context(), "encode response", "error", err)
	}
}

func RequireContentType(r *nethttp.Request, mediaType string) error {
	header := r.Header.Get("Content-Type")
	got, _, err := mime.ParseMediaType(header)
	if err != nil || got != mediaType {
		return errs.UnsupportedMediaType(fmt.Errorf("got content type %q", header), "content type must be %s", mediaType)
	}
	return nil
}

func HandlerFunc(f func(nethttp.ResponseWriter, *nethttp.Request) error) nethttp.HandlerFunc {
	return func(w nethttp.ResponseWriter, r *nethttp.Request) {
		err := f(w, r)
		if err == nil {
			return
		}
		WriteError(w, r, errs.ToError(err))
	}
}

func ReadForm(w nethttp.ResponseWriter, r *nethttp.Request) (url.Values, error) {
	if err := RequireContentType(r, MediaTypeForm); err != nil {
		return nil, err
	}

	r.Body = nethttp.MaxBytesReader(w, r.Body, MaxRequestBodySize)
	if err := r.ParseForm(); err != nil {
		if _, ok := errors.AsType[*nethttp.MaxBytesError](err); ok {
			return nil, errs.InvalidRequest(err, "invalid request body")
		}
		return nil, errs.InvalidRequest(err, "error parsing form")
	}
	return r.PostForm, nil
}

func ReadJSON[T any](w nethttp.ResponseWriter, r *nethttp.Request) (T, error) {
	var obj T
	r.Body = nethttp.MaxBytesReader(w, r.Body, MaxRequestBodySize)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&obj); err != nil {
		return obj, err
	}

	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return obj, errors.New("request body must contain exactly one JSON value")
		}
		return obj, err
	}
	return obj, nil
}

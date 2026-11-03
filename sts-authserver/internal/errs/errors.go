package errs

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
)

// Error is an OAuth error response. The rules for errors are:
//
//  1. A check returns a plain error and does not know the OAuth code.
//  2. A handler returns a constructor such as [InvalidClient], which sets the code and the status.
//     The format sets error_description. The cause is only logged; pass nil if there is none.
//  3. Any other error is an internal failure. [HandlerFunc] responds with [ServerError].
type Error struct {
	code        string
	description string
	status      int
	cause       error
}

// ErrorResponse is the body of an error response (RFC 6749 section 5.2).
type ErrorResponse struct {
	Status      int    `json:"-"`
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// RFC 6749 section 5.2

func InvalidRequest(cause error, format string, args ...any) Error {
	return newError("invalid_request", http.StatusBadRequest, cause, format, args...)
}

func UnsupportedMediaType(cause error, format string, args ...any) Error {
	return newError("invalid_request", http.StatusUnsupportedMediaType, cause, format, args...)
}

func InvalidClient(cause error, format string, args ...any) Error {
	return newError("invalid_client", http.StatusBadRequest, cause, format, args...)
}

func UnauthorizedClient(cause error, format string, args ...any) Error {
	return newError("unauthorized_client", http.StatusBadRequest, cause, format, args...)
}

func UnsupportedGrantType(cause error, format string, args ...any) Error {
	return newError("unsupported_grant_type", http.StatusBadRequest, cause, format, args...)
}

// RFC 6749 section 4.1.2.1

func ServerError(cause error) Error {
	return Error{code: "server_error", status: http.StatusInternalServerError, description: "internal error", cause: cause}
}

// RFC 8693 section 2.2.2

func InvalidTarget(cause error, format string, args ...any) Error {
	return newError("invalid_target", http.StatusBadRequest, cause, format, args...)
}

// RFC 6750 section 3.1

func InvalidToken(cause error, format string, args ...any) Error {
	return newError("invalid_token", http.StatusUnauthorized, cause, format, args...)
}

// RFC 7591 section 3.2.2

func InvalidClientMetadata(cause error, format string, args ...any) Error {
	return newError("invalid_client_metadata", http.StatusBadRequest, cause, format, args...)
}

func InvalidSoftwareStatement(cause error, format string, args ...any) Error {
	return newError("invalid_software_statement", http.StatusBadRequest, cause, format, args...)
}

func (e Error) Error() string {
	if e.cause == nil {
		return e.description
	}
	return e.description + ": " + e.cause.Error()
}

func (e Error) Unwrap() error {
	return e.cause
}

func (e Error) HTTPError() ErrorResponse {
	if e.Internal() {
		s := ServerError(nil)
		return ErrorResponse{Status: s.status, Code: s.code, Description: s.description}
	}
	return ErrorResponse{
		Status:      e.status,
		Code:        e.code,
		Description: e.description,
	}
}

func newError(code string, status int, cause error, format string, args ...any) Error {
	return Error{code: code, status: status, cause: cause, description: fmt.Sprintf(format, args...)}
}

// Internal reports whether e is a server failure, whose details must not reach the HTTP client.
func (e Error) Internal() bool {
	return e.status >= http.StatusInternalServerError
}

func (e Error) LogAttrs() []slog.Attr {
	resp := e.HTTPError()
	attrs := []slog.Attr{
		slog.String("code", resp.Code),
		slog.String("description", resp.Description),
		slog.Int("status_code", resp.Status),
	}
	if e.cause != nil {
		attrs = append(attrs, slog.Any("error", e.cause))
	}
	return attrs
}

// ToError converts any handler error into the Error that WriteError writes as the HTTP response.
func ToError(err error) Error {
	inner, ok := errors.AsType[Error](err)
	if !ok {
		return ServerError(err)
	}
	// Preserve the full error chain for logs without exposing it in the response.
	return Error{code: inner.code, description: inner.description, status: inner.status, cause: err}
}

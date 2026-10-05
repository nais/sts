package errs

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

// Error is an OAuth error response. The rules for errors are:
//
//  1. A check returns [NewErrorDescription] when its text may be displayed in error_description.
//     A check does not know the OAuth code.
//     [WrapErrorDescription] also attaches a cause, which is only logged.
//  2. A handler returns a constructor such as [InvalidClient], which sets the code and the status.
//     The format sets error_description. The cause is only logged; pass nil if there is none.
//     Every [ErrorDescription] and [Error] description in the cause is appended, in the order that Error() prints them.
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

func RequestTooLarge(cause error, format string, args ...any) Error {
	return newError("invalid_request", http.StatusRequestEntityTooLarge, cause, format, args...)
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

func UnapprovedSoftwareStatement(cause error, format string, args ...any) Error {
	return newError("unapproved_software_statement", http.StatusBadRequest, cause, format, args...)
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
		Description: strings.Join(appendErrorDescriptions(nil, e), ": "),
	}
}

type ErrorDescription string

func NewErrorDescription(format string, args ...any) error {
	return ErrorDescription(fmt.Sprintf(format, args...))
}

func WrapErrorDescription(cause error, format string, args ...any) error {
	return fmt.Errorf("%w: %w", NewErrorDescription(format, args...), cause)
}

func (r ErrorDescription) Error() string {
	return string(r)
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
	// The cause is err, not inner.cause, so that logAttrs also includes any text that the handler wrapped around inner.
	return Error{code: inner.code, status: inner.status, cause: err}
}

// multiWrapper is the interface of errors from errors.Join and fmt.Errorf with several %w verbs.
type multiWrapper interface{ Unwrap() []error }

// appendErrorDescriptions appends the text in err that goes into error_description, in the order of err.Error().
// It skips plain errors, and an internal Error together with its cause.
func appendErrorDescriptions(parts []string, err error) []string {
	switch e := err.(type) {
	case nil:
		return parts
	case ErrorDescription:
		return append(parts, string(e))
	case Error:
		if e.Internal() {
			return parts
		}
		if e.description != "" {
			parts = append(parts, e.description)
		}
		return appendErrorDescriptions(parts, e.cause)
	case multiWrapper:
		for _, inner := range e.Unwrap() {
			parts = appendErrorDescriptions(parts, inner)
		}
		return parts
	default:
		return appendErrorDescriptions(parts, errors.Unwrap(err))
	}
}

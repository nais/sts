package oauth

import (
	"errors"
	"fmt"
	"net/http"
)

// Error is an OAuth error response. The rules for errors are:
//
//  1. A check returns [NewErrorDescription] when its text may be displayed in error_description.
//     A check does not know the OAuth code.
//     [WrapErrorDescription] also attaches a cause, which is only logged.
//  2. A handler returns a constructor such as [InvalidClient], which sets the code and the status.
//     The format sets error_description. The cause is only logged; pass nil if there is none.
//     If the cause contains an [ErrorDescription], its text is appended to the description.
//  3. Any other error is an internal failure. [HandlerFunc] responds with [ServerError].
type Error struct {
	code        string
	description string
	status      int
	cause       error
}

func newError(code string, status int, cause error, format string, args ...any) error {
	return &Error{code: code, status: status, cause: cause, description: fmt.Sprintf(format, args...)}
}

// RFC 6749 section 5.2

func InvalidRequest(cause error, format string, args ...any) error {
	return newError("invalid_request", http.StatusBadRequest, cause, format, args...)
}

func RequestTooLarge(cause error, format string, args ...any) error {
	return newError("invalid_request", http.StatusRequestEntityTooLarge, cause, format, args...)
}

func UnsupportedMediaType(cause error, format string, args ...any) error {
	return newError("invalid_request", http.StatusUnsupportedMediaType, cause, format, args...)
}

func InvalidClient(cause error, format string, args ...any) error {
	return newError("invalid_client", http.StatusBadRequest, cause, format, args...)
}

func UnauthorizedClient(cause error, format string, args ...any) error {
	return newError("unauthorized_client", http.StatusBadRequest, cause, format, args...)
}

func UnsupportedGrantType(cause error, format string, args ...any) error {
	return newError("unsupported_grant_type", http.StatusBadRequest, cause, format, args...)
}

// RFC 6749 section 4.1.2.1

func ServerError(cause error) error {
	return serverError(cause)
}

func serverError(cause error) *Error {
	return &Error{code: "server_error", status: http.StatusInternalServerError, description: "internal error", cause: cause}
}

// RFC 8693 section 2.2.2

func InvalidTarget(cause error, format string, args ...any) error {
	return newError("invalid_target", http.StatusBadRequest, cause, format, args...)
}

// RFC 6750 section 3.1

func InvalidToken(cause error, format string, args ...any) error {
	return newError("invalid_token", http.StatusUnauthorized, cause, format, args...)
}

// RFC 7591 section 3.2.2

func InvalidClientMetadata(cause error, format string, args ...any) error {
	return newError("invalid_client_metadata", http.StatusBadRequest, cause, format, args...)
}

func InvalidSoftwareStatement(cause error, format string, args ...any) error {
	return newError("invalid_software_statement", http.StatusBadRequest, cause, format, args...)
}

func UnapprovedSoftwareStatement(cause error, format string, args ...any) error {
	return newError("unapproved_software_statement", http.StatusBadRequest, cause, format, args...)
}

func (e *Error) Error() string {
	if e.cause == nil {
		return e.description
	}
	return e.description + ": " + e.cause.Error()
}

func (e *Error) Unwrap() error {
	return e.cause
}

func (e *Error) HTTPError() ErrorResponse {
	if e.status >= http.StatusInternalServerError {
		return ErrorResponse{Status: e.status, Code: e.code, Description: serverError(nil).description}
	}
	description := e.description
	if reason, ok := errors.AsType[ErrorDescription](e.cause); ok {
		description += ": " + string(reason)
	}
	return ErrorResponse{Status: e.status, Code: e.code, Description: description}
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

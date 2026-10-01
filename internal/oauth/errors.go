package oauth

import (
	"errors"
	"fmt"
	"net/http"
)

// Error is an OAuth error response. The rules for errors are:
//
//  1. A check returns [NewPublicReason] when its text may be displayed in error_description.
//     A check does not know the OAuth code.
//     To keep a cause private, return fmt.Errorf("%w: %w", reason, cause).
//  2. A handler returns a sentinel such as [ErrInvalidClient], which sets the code and the status.
//     [Error.Describe] sets error_description.
//     [Error.Wrap] attaches the cause, which is only logged.
//     If the cause contains a [PublicReason], its text is appended to the description.
//  3. Any other error is an internal failure. [HandlerFunc] responds with [ErrServerError].
type Error struct {
	code        string
	description string
	status      int
	cause       error
}

var (
	// RFC 6749 section 5.2
	ErrInvalidRequest       = &Error{code: "invalid_request", status: http.StatusBadRequest}
	ErrRequestTooLarge      = &Error{code: "invalid_request", status: http.StatusRequestEntityTooLarge}
	ErrUnsupportedMediaType = &Error{code: "invalid_request", status: http.StatusUnsupportedMediaType}
	ErrInvalidClient        = &Error{code: "invalid_client", status: http.StatusBadRequest}
	ErrUnauthorizedClient   = &Error{code: "unauthorized_client", status: http.StatusBadRequest}
	ErrUnsupportedGrantType = &Error{code: "unsupported_grant_type", status: http.StatusBadRequest}

	// RFC 6749 section 4.1.2.1
	ErrServerError = &Error{code: "server_error", status: http.StatusInternalServerError, description: "internal error"}

	// RFC 8693 section 2.2.2
	ErrInvalidTarget = &Error{code: "invalid_target", status: http.StatusBadRequest}

	// RFC 6750 section 3.1
	ErrInvalidToken = &Error{code: "invalid_token", status: http.StatusUnauthorized}

	// RFC 7591 section 3.2.2
	ErrInvalidClientMetadata       = &Error{code: "invalid_client_metadata", status: http.StatusBadRequest}
	ErrInvalidSoftwareStatement    = &Error{code: "invalid_software_statement", status: http.StatusBadRequest}
	ErrUnapprovedSoftwareStatement = &Error{code: "unapproved_software_statement", status: http.StatusBadRequest}
)

func (e *Error) Describe(format string, args ...any) *Error {
	c := *e
	c.description = fmt.Sprintf(format, args...)
	return &c
}

func (e *Error) Wrap(cause error) *Error {
	c := *e
	c.cause = cause
	return &c
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
		return ErrorResponse{Status: e.status, Code: e.code, Description: ErrServerError.description}
	}
	description := e.description
	if reason, ok := errors.AsType[PublicReason](e.cause); ok {
		description += ": " + string(reason)
	}
	return ErrorResponse{Status: e.status, Code: e.code, Description: description}
}

type PublicReason string

func NewPublicReason(format string, args ...any) error {
	return PublicReason(fmt.Sprintf(format, args...))
}

func (r PublicReason) Error() string {
	return string(r)
}

package oauth

import (
	"errors"
	"fmt"
	"net/http"
)

const (
	// RFC 6749 section 5.2
	CodeInvalidRequest       = "invalid_request"
	CodeInvalidClient        = "invalid_client"
	CodeUnauthorizedClient   = "unauthorized_client"
	CodeUnsupportedGrantType = "unsupported_grant_type"
	CodeServerError          = "server_error"

	// RFC 8693 section 2.2.2
	CodeInvalidTarget = "invalid_target"

	// RFC 6750 section 3.1
	CodeInvalidToken = "invalid_token"

	// RFC 7591 section 3.2.2
	CodeInvalidClientMetadata       = "invalid_client_metadata"
	CodeInvalidSoftwareStatement    = "invalid_software_statement"
	CodeUnapprovedSoftwareStatement = "unapproved_software_statement"
)

// ErrorResponse is the OAuth error response that [WriteError] sends to the HTTP client.
// [WriteError] logs Cause.
type ErrorResponse struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	// Status is the HTTP status. If it is zero, [ErrorResponse.status] derives it from Code.
	Status int   `json:"-"`
	Cause  error `json:"-"`
}

func NewErrorResponse(code, format string, args ...any) *ErrorResponse {
	return &ErrorResponse{Code: code, Description: fmt.Sprintf(format, args...)}
}

// Wrap returns a copy of e with err as its cause.
// If err contains a [PublicError] and Code is not server_error,
// the Description of the copy is "[ErrorResponse.Description]: [PublicError.Message]".
func (e *ErrorResponse) Wrap(err error) *ErrorResponse {
	c := *e
	c.Cause = err
	if public, ok := errors.AsType[*PublicError](err); ok && c.Code != CodeServerError {
		c.Description += ": " + public.Message
	}
	return &c
}

func (e *ErrorResponse) WithStatus(status int) *ErrorResponse {
	c := *e
	c.Status = status
	return &c
}

func (e *ErrorResponse) Error() string {
	return e.Code + ": " + e.Description
}

func (e *ErrorResponse) Unwrap() error {
	return e.Cause
}

func (e *ErrorResponse) status() int {
	switch {
	case e.Status != 0:
		return e.Status
	case e.Code == CodeServerError:
		return http.StatusInternalServerError
	case e.Code == CodeInvalidToken:
		return http.StatusUnauthorized
	default:
		return http.StatusBadRequest
	}
}

// clientErrorResponse returns the ErrorResponse in err, unless it is a server_error.
func clientErrorResponse(err error) (*ErrorResponse, bool) {
	e, ok := errors.AsType[*ErrorResponse](err)
	return e, ok && e.Code != CodeServerError
}

// PublicError is an error whose Message is safe to show to the HTTP client.
// [ErrorResponse.Wrap] adds Message to [ErrorResponse.Description].
// [WriteError] responds with 500 to a PublicError that is not wrapped in an [ErrorResponse].
type PublicError struct {
	Message string
	Cause   error
}

func NewPublicError(format string, args ...any) *PublicError {
	return &PublicError{Message: fmt.Sprintf(format, args...)}
}

// Wrap returns a copy of p with cause attached.
// [ErrorResponse.Wrap] copies only [PublicError.Message] into [ErrorResponse.Description]. [WriteError] logs the cause.
func (p *PublicError) Wrap(cause error) *PublicError {
	c := *p
	c.Cause = cause
	return &c
}

// Error includes the cause. Do not use it in a response description.
func (p *PublicError) Error() string {
	if p.Cause == nil {
		return p.Message
	}
	return p.Message + ": " + p.Cause.Error()
}

func (p *PublicError) Unwrap() error {
	return p.Cause
}

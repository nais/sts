package oauth

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorWrap(t *testing.T) {
	cause := errors.New("private detail")
	for name, test := range map[string]struct {
		err  error
		want string
	}{
		"public reason": {err: fmt.Errorf("wrap: %w", fmt.Errorf("%w: %w", NewPublicReason("issuer %q is not trusted", "https://x"), cause)), want: `prefix: issuer "https://x" is not trusted`},
		"error":         {err: ErrInvalidRequest.Describe("private detail").Wrap(cause), want: "prefix"},
		"plain error":   {err: cause, want: "prefix"},
	} {
		t.Run(name, func(t *testing.T) {
			e := ErrInvalidClient.Describe("prefix").Wrap(test.err)
			assert.Equal(t, ErrorResponse{Status: http.StatusBadRequest, Code: "invalid_client", Description: test.want}, e.HTTPError())
			assert.ErrorIs(t, e, cause)
		})
	}
}

func TestErrorDescribeAfterWrapKeepsReason(t *testing.T) {
	e := ErrInvalidClient.Wrap(NewPublicReason("reason")).Describe("described")
	assert.Equal(t, "described: reason", e.HTTPError().Description)
}

func TestErrorServerErrorHidesDescription(t *testing.T) {
	for name, e := range map[string]*Error{
		"described":     ErrServerError.Describe("private detail"),
		"public reason": ErrServerError.Wrap(NewPublicReason("private detail")),
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, "internal error", e.HTTPError().Description)
		})
	}
}

func TestErrorCopies(t *testing.T) {
	e := ErrInvalidClient.Describe("described").Wrap(errors.New("private detail"))

	assert.Equal(t, ErrorResponse{Status: http.StatusBadRequest, Code: "invalid_client", Description: "described"}, e.HTTPError())
	assert.Equal(t, "described: private detail", e.Error())
	assert.Equal(t, ErrorResponse{Status: http.StatusBadRequest, Code: "invalid_client"}, ErrInvalidClient.HTTPError())
}

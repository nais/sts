package oauth

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorResponseWrap(t *testing.T) {
	for name, test := range map[string]struct {
		code string
		err  error
		want string
	}{
		"public error":         {err: fmt.Errorf("wrap: %w", NewPublicError("issuer %q is not trusted", "https://x").Wrap(errors.New("cause"))), want: `prefix: issuer "https://x" is not trusted`},
		"inner error response": {err: NewErrorResponse(CodeInvalidRequest, "private detail"), want: "prefix"},
		"internal error":       {err: errors.New("private detail"), want: "prefix"},
		"server error code":    {code: CodeServerError, err: NewPublicError("private detail"), want: "prefix"},
	} {
		t.Run(name, func(t *testing.T) {
			code := test.code
			if code == "" {
				code = CodeInvalidClient
			}
			wrapped := NewErrorResponse(code, "prefix").Wrap(test.err)
			assert.Equal(t, test.want, wrapped.Description)
			assert.Equal(t, code, wrapped.Code)
			assert.Equal(t, test.err, wrapped.Cause)
		})
	}
}

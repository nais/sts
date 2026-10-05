package errs

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorHTTPError(t *testing.T) {
	cause := errors.New("private detail")
	for name, test := range map[string]struct {
		cause error
		want  string
	}{
		"error description": {cause: fmt.Errorf("wrap: %w", WrapErrorDescription(cause, "issuer %q is not trusted", "https://x")), want: `prefix: issuer "https://x" is not trusted`},
		"error":             {cause: InvalidRequest(cause, "inner"), want: "prefix: inner"},
		"plain error":       {cause: cause, want: "prefix"},
		"nested chain": {
			cause: WrapErrorDescription(InvalidRequest(WrapErrorDescription(cause, "d2"), "e2"), "d1"),
			want:  "prefix: d1: e2: d2",
		},
		"nested server error": {cause: ServerError(WrapErrorDescription(cause, "hidden")), want: "prefix"},
		"joined":              {cause: errors.Join(NewErrorDescription("a"), cause, NewErrorDescription("b")), want: "prefix: a: b"},
	} {
		t.Run(name, func(t *testing.T) {
			err := InvalidClient(test.cause, "prefix")
			assert.Equal(t, ErrorResponse{Status: http.StatusBadRequest, Code: "invalid_client", Description: test.want}, err.HTTPError())
			assert.ErrorIs(t, err, cause)
		})
	}
}

func TestServerErrorHidesErrorDescription(t *testing.T) {
	err := ServerError(NewErrorDescription("private reason"))
	assert.Equal(t, "internal error", err.HTTPError().Description)
}

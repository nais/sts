package oauth

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
		"error":             {cause: InvalidRequest(cause, "private detail"), want: "prefix"},
		"plain error":       {cause: cause, want: "prefix"},
	} {
		t.Run(name, func(t *testing.T) {
			err := InvalidClient(test.cause, "prefix")
			assert.Equal(t, ErrorResponse{Status: http.StatusBadRequest, Code: "invalid_client", Description: test.want}, err.(*Error).HTTPError())
			assert.ErrorIs(t, err, cause)
		})
	}
}

func TestServerErrorHidesErrorDescription(t *testing.T) {
	err := ServerError(NewErrorDescription("private reason"))
	assert.Equal(t, "internal error", err.(*Error).HTTPError().Description)
}

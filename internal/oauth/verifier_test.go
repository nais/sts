package oauth

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestPublicTokenError(t *testing.T) {
	for name, test := range map[string]struct {
		err  error
		want string
	}{
		"listed error":   {err: fmt.Errorf("%w: detail", oidc.ErrExpired), want: "token has expired"},
		"parse error":    {err: fmt.Errorf("%w: detail", oidc.ErrParse), want: "token is not a valid JWT"},
		"unlisted error": {err: fmt.Errorf("%w: private detail", oidc.ErrDiscoveryFailed)},
	} {
		t.Run(name, func(t *testing.T) {
			err := PublicTokenError(test.err)
			public, ok := errors.AsType[*PublicError](err)
			if test.want == "" {
				assert.False(t, ok)
				assert.Equal(t, test.err, err)
				return
			}
			require.True(t, ok)
			assert.Equal(t, test.want, public.Message)
			assert.Equal(t, test.err, public.Cause)
		})
	}
}

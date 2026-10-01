package oauth

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestFromZitadelTokenError(t *testing.T) {
	for name, test := range map[string]struct {
		err  error
		want string
	}{
		"listed error":   {err: fmt.Errorf("%w: detail", oidc.ErrExpired), want: "token has expired"},
		"parse error":    {err: fmt.Errorf("%w: detail", oidc.ErrParse), want: "token is not a valid JWT"},
		"unlisted error": {err: fmt.Errorf("%w: private detail", oidc.ErrDiscoveryFailed)},
	} {
		t.Run(name, func(t *testing.T) {
			err := FromZitadelTokenError(test.err)
			reason, ok := errors.AsType[ErrorDescription](err)
			if test.want == "" {
				assert.False(t, ok)
				assert.Equal(t, test.err, err)
				return
			}
			require.True(t, ok)
			assert.Equal(t, ErrorDescription(test.want), reason)
			assert.ErrorIs(t, err, test.err)
		})
	}
}

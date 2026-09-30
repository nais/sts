package oauth

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestWrapError(t *testing.T) {
	errCause := errors.New("cause")
	for name, test := range map[string]struct {
		base       *oidc.Error
		err        error
		want       string
		wantParent error
	}{
		"wrapped oidc error":     {err: fmt.Errorf("wrap: %w", oidc.ErrInvalidRequest().WithDescription("issuer %q is not trusted", "https://x").WithParent(errCause)), want: `prefix: issuer "https://x" is not trusted`, wantParent: errCause},
		"zitadel token error":    {err: fmt.Errorf("%w: detail", oidc.ErrExpired), want: "prefix: token has expired"},
		"server oidc error":      {err: oidc.ErrServerError().WithDescription("private detail"), want: "prefix"},
		"internal error":         {err: errors.New("private detail"), want: "prefix"},
		"unlisted zitadel error": {err: fmt.Errorf("%w: private detail", oidc.ErrDiscoveryFailed), want: "prefix"},
		"server error base":      {base: oidc.ErrServerError(), err: fmt.Errorf("%w: detail", oidc.ErrExpired), want: "prefix"},
	} {
		t.Run(name, func(t *testing.T) {
			base := test.base
			if base == nil {
				base = oidc.ErrInvalidClient()
			}
			wantType := base.ErrorType
			wrapped := WrapError(base, "prefix", test.err)
			assert.Equal(t, test.want, wrapped.Description)
			assert.Equal(t, wantType, wrapped.ErrorType)
			wantParent := test.wantParent
			if wantParent == nil {
				wantParent = test.err
			}
			assert.Equal(t, wantParent, wrapped.Parent)
		})
	}
}

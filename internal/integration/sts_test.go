//go:build integration_test

package integration

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/go-jose/go-jose/v4/testutils/assert"
	"github.com/stretchr/testify/require"
)

func TestSts(t *testing.T) {
	oauthServer := startMockOAuthServer(t)
	sts := startSts(t, oauthServer)

	t.Run("discovery", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("%s/jwks", sts))
		require.NoError(t, err)
		assert.Equal(t, resp.StatusCode, http.StatusOK)
	})

	t.Run("client credentials", func(t *testing.T) {

	})

	t.Run("token exchange", func(t *testing.T) {

	})
}

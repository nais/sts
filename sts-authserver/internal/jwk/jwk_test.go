package jwk

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignerPublicKeySetIsPublic(t *testing.T) {
	signer, err := GenerateSigner()
	require.NoError(t, err)

	for _, key := range signer.PublicKeySet().Keys {
		assert.True(t, key.IsPublic())
	}
}

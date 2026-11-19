package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyDefaultsPreservesExistingValues(t *testing.T) {
	var cfg struct {
		BindAddress string `default:":8080"`
		Nested      struct {
			Audience string        `default:"nais"`
			Expiry   time.Duration `default:"15m"`
		}
	}
	cfg.BindAddress = ":9090"

	require.NoError(t, Apply(&cfg))
	assert.Equal(t, ":9090", cfg.BindAddress)
	assert.Equal(t, "nais", cfg.Nested.Audience)
	assert.Equal(t, 15*time.Minute, cfg.Nested.Expiry)
}

func TestApplyDefaultsRejectsInvalidTag(t *testing.T) {
	var cfg struct {
		Nested struct {
			Count int `default:"invalid"`
		}
	}
	err := Apply(&cfg)
	require.ErrorContains(t, err, "field Nested: field Count:")
}

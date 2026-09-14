package oauth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAuthorizationServerConfigRejectsInvalidClientAuthSigningAlgorithms(t *testing.T) {
	for name, algorithms := range map[string][]string{
		"duplicate":   {"RS256", "RS256"},
		"unsupported": {"EdDSA"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := AuthorizationServerConfig{
				Issuer:                      "https://sts.example",
				ExpectedAudience:            "nais",
				ClientAuthIssuers:           []Issuer{"https://client.example"},
				ClientAuthSigningAlgorithms: algorithms,
				SubjectTokenIssuers:         []Issuer{"https://subject.example"},
				MaxClientAuthTokenLifetime:  time.Hour,
				TokenExpiry:                 time.Hour,
			}

			require.Error(t, cfg.Validate())
		})
	}
}

package api

import "testing"

func TestSTSIssuerEndpoints(t *testing.T) {
	for _, raw := range []string{"https://sts.example", "https://sts.example/"} {
		t.Run(raw, func(t *testing.T) {
			issuer := STSIssuer(raw)
			if issuer.String() != raw {
				t.Fatalf("issuer changed: got %q, want %q", issuer.String(), raw)
			}
			for name, test := range map[string]struct {
				got  string
				want string
			}{
				"token":        {issuer.TokenEndpoint(), "https://sts.example/token"},
				"JWKS":         {issuer.JWKSEndpoint(), "https://sts.example/jwks"},
				"registration": {issuer.RegistrationEndpoint(), "https://sts.example/v1/registration/client"},
				"discovery":    {issuer.OAuthDiscoveryEndpoint(), "https://sts.example/.well-known/oauth-authorization-server"},
			} {
				t.Run(name, func(t *testing.T) {
					if test.got != test.want {
						t.Fatalf("got %q, want %q", test.got, test.want)
					}
				})
			}
		})
	}
}

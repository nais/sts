package jwt

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestAccessTokenClaimsUnmarshal(t *testing.T) {
	data := []byte(`{"iss":"issuer","sub":"subject","aud":["audience"],"custom":{"number":9007199254740993,"items":[1,true]}}`)
	claims := new(AccessTokenClaims)

	require.NoError(t, json.Unmarshal(data, claims))
	assert.Equal(t, "issuer", claims.Issuer)
	assert.Equal(t, "subject", claims.Subject)
	assert.Equal(t, oidc.Audience{"audience"}, claims.Audience)
	assert.JSONEq(t, `{"number":9007199254740993,"items":[1,true]}`, string(claims.Claims["custom"]))
}

func TestAccessTokenClaimsKubernetes(t *testing.T) {
	for name, test := range map[string]struct {
		claims map[string]json.RawMessage
		want   string
	}{
		"missing":      {claims: map[string]json.RawMessage{}, want: "kubernetes.io claim is missing"},
		"malformed":    {claims: map[string]json.RawMessage{"kubernetes.io": json.RawMessage(`"text"`)}, want: "kubernetes.io claim is malformed"},
		"empty fields": {claims: map[string]json.RawMessage{"kubernetes.io": json.RawMessage(`{"namespace":"ns"}`)}, want: "kubernetes.io claim has no namespace or service account name"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := (&AccessTokenClaims{Claims: test.claims}).Kubernetes()
			assert.ErrorContains(t, err, test.want)
			if name == "malformed" {
				assert.ErrorContains(t, err, "cannot unmarshal string")
			}
		})
	}
}

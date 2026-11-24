package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// Issuer identifies an issuer for token verification, including STS itself.
type Issuer string

var _ json.Unmarshaler = (*AccessTokenClaims)(nil)

type AccessTokenClaims struct {
	oidc.TokenClaims
	Claims map[string]json.RawMessage `json:"-"`
}

func (a *AccessTokenClaims) UnmarshalJSON(data []byte) error {
	// Use a distinct type without UnmarshalJSON to avoid recursive unmarshalling.
	type tokenClaims oidc.TokenClaims
	if err := json.Unmarshal(data, (*tokenClaims)(&a.TokenClaims)); err != nil {
		return err
	}
	return json.Unmarshal(data, &a.Claims)
}

type KubernetesClaims struct {
	Namespace      string `json:"namespace"`
	ServiceAccount struct {
		Name string `json:"name"`
	} `json:"serviceaccount"`
}

func (a *AccessTokenClaims) Kubernetes() (*KubernetesClaims, error) {
	raw, ok := a.Claims["kubernetes.io"]
	if !ok {
		return nil, errors.New("kubernetes.io claim is missing")
	}

	var kubernetes KubernetesClaims
	if err := json.Unmarshal(raw, &kubernetes); err != nil {
		return nil, fmt.Errorf("kubernetes.io claim is malformed: %w", err)
	}

	if kubernetes.Namespace == "" || kubernetes.ServiceAccount.Name == "" {
		return nil, errors.New("kubernetes.io claim has no namespace or service account name")
	}
	return &kubernetes, nil
}

// StringClaim supports dotted object paths, not full JSONPath. Longest matching
// keys take precedence so keys containing dots (such as kubernetes.io) work.
func StringClaim(claims map[string]json.RawMessage, path string) (string, error) {
	if path == "" {
		return "", errors.New("claim path is required")
	}
	for key := path; key != ""; {
		if raw, ok := claims[key]; ok {
			if key == path {
				var value string
				if err := json.Unmarshal(raw, &value); err != nil {
					return "", fmt.Errorf("claim %q must be a string: %w", path, err)
				}
				if value == "" {
					return "", fmt.Errorf("claim %q must not be empty", path)
				}
				return value, nil
			}
			var nested map[string]json.RawMessage
			if err := json.Unmarshal(raw, &nested); err != nil {
				return "", fmt.Errorf("claim %q must be an object: %w", key, err)
			}
			return StringClaim(nested, path[len(key)+1:])
		}
		index := strings.LastIndexByte(key, '.')
		if index < 0 {
			break
		}
		key = key[:index]
	}
	return "", fmt.Errorf("claim %q is missing", path)
}

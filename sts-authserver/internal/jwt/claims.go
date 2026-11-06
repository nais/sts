package jwt

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

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

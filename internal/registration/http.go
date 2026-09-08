package registration

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/nais/sts/internal/oauth"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type ClientRegistration struct {
	ClientName        string `json:"client_name"`
	SoftwareStatement string `json:"software_statement"`
}

type ClientRegistrationResponse struct {
	ClientRegistration
	GrantTypes              []string `json:"grant_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

type SoftwareStatement struct {
	ClientId              string                `json:"client_id"`
	Workload              Workload              `json:"workload"`
	AuthorizationPolicies []AuthorizationPolicy `json:"authorization_policies"`
}

func (s SoftwareStatement) SetSignatureAlgorithm(algorithm jose.SignatureAlgorithm) {

}

type Workload struct {
	Environment string `json:"environment"`
	Issuer      string `json:"issuer"`
	Namespace   string `json:"namespace"`
	Name        string `json:"workload"`
}

type AuthorizationPolicy struct {
	Owner    oauth.ClientID `json:"owner"`
	Consumer oauth.ClientID `json:"consumer"`
	Roles    oauth.Roles    `json:"roles"`
}

type ClientRegistrator struct {
	Issuer        string   `json:"issuer"`
	Subject       string   `json:"subject"`
	ClientJwksUri string   `json:"client_jwks_uri"`
	RequiredAlgs  []string `json:"required_algs"`
}

type AuthorizedClientRegistrators = []*ClientRegistrator

func NewClientHandler(registrators AuthorizedClientRegistrators, verifier oauth.MultiIssuerTokenVerifier) http.Handler {
	// TODO: auth
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		claims, err := bearerAuth(r, verifier)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		var registrator *ClientRegistrator
		for _, client := range registrators {
			if claims.Issuer == client.Issuer && claims.Subject == client.Subject {
				registrator = client
				break
			}
		}
		if registrator == nil {
			// TODO: better error message
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var registration *ClientRegistration
		if err := json.NewDecoder(r.Body).Decode(&registration); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		ss, err := verifySoftwareStatement(r.Context(), registrator, registration.SoftwareStatement)
		if err != nil {
			http.Error(w, "Invalid software statement: "+err.Error(), http.StatusBadRequest)
			return
		}
		_ = ss // TODO: use software statement to create client

		respond(w, r, &ClientRegistrationResponse{
			ClientRegistration: *registration,
		}, nil)
	})
}

// TODO: save remote keyset to avoid fetching it for every request
func verifySoftwareStatement(ctx context.Context, registrator *ClientRegistrator, softwareStatementString string) (*SoftwareStatement, error) {
	ss := new(SoftwareStatement)
	payload, err := oidc.ParseToken(softwareStatementString, ss)
	if err != nil {
		return nil, err
	}
	keyset := rp.NewRemoteKeySet(http.DefaultClient, registrator.ClientJwksUri)

	if err := oidc.CheckSignature(ctx, softwareStatementString, payload, ss, registrator.RequiredAlgs, keyset); err != nil {
		return nil, err
	}
	return ss, nil
}

func bearerAuth(r *http.Request, verifier oauth.MultiIssuerTokenVerifier) (*oauth.AccessTokenClaims, error) {
	token := strings.TrimPrefix(strings.ToLower(r.Header.Get("Authorization")), "bearer ")
	if token == "" {
		return nil, oidc.ErrUnauthorizedClient().WithDescription("missing bearer token")
	}
	// TODO: verify claims for authorized client registrators
	return verifier.Verify(r.Context(), token)
}

func respond(w http.ResponseWriter, r *http.Request, resp any, err error) {
	if err != nil {
		op.WriteError(w, r, err, nil)
		return
	}

	if resp == nil || (reflect.ValueOf(resp).Kind() == reflect.Pointer && reflect.ValueOf(resp).IsNil()) {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if h := w.Header().Get("content-type"); h == "" {
		w.Header().Set("content-type", "application/json")
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

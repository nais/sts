package sts

import (
	"context"

	stsv1 "github.com/nais/sts-operator/api/nais.io/v1"
	"github.com/nais/sts-operator/internal/config"
	stsapi "github.com/nais/sts/api"
)

type Registrator struct {
	*stsapi.RegistrationClient
	Metadata     *stsapi.DiscoveryMetadata
	ClusterName  string
	WellKnownURL string
}

func NewRegistrator(ctx context.Context, cfg *config.Config) (*Registrator, error) {
	issuer := stsapi.STSIssuer(cfg.STSBaseURL)
	client, err := stsapi.NewRegistrationClient(issuer, stsapi.TokenFromFile(cfg.AuthTokenPath))
	if err != nil {
		return nil, err
	}

	metadata, err := client.FetchSTSMetadata(ctx)
	if err != nil {
		return nil, err
	}

	r := &Registrator{
		RegistrationClient: client,
		Metadata:           metadata,
		ClusterName:        cfg.ClusterName,
		// TODO: go over this and the fetching, a bit weird as is
		WellKnownURL: issuer.OAuthDiscoveryEndpoint(),
	}

	return r, nil
}

// MakeSoftwareStatement describes the client for the STSClient's service
// account. STS derives the client's environment from the registrator, and
// expands each consumer to every configured environment.
func (r *Registrator) MakeSoftwareStatement(oauthClient stsv1.STSClient) stsapi.SoftwareStatement {
	var policies []stsapi.AuthorizationPolicy
	for _, acl := range oauthClient.Spec.AccessControlList {
		for _, workload := range acl.Workloads {
			policies = append(policies, stsapi.AuthorizationPolicy{
				Consumer: stsapi.Client{Namespace: acl.Team, Name: workload.Name},
				Roles:    workload.Roles,
			})
		}
	}

	return stsapi.SoftwareStatement{
		Client:                stsapi.Client{Namespace: oauthClient.Namespace, Name: oauthClient.Name},
		AuthorizationPolicies: policies,
	}
}

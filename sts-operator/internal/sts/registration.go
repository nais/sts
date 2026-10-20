package sts

import (
	"context"
	"fmt"

	stsv1 "github.com/nais/sts-operator/api/nais.io/v1"
	"github.com/nais/sts-operator/internal/config"
	stsapi "github.com/nais/sts/api"
)

type Registrator struct {
	*stsapi.RegistrationClient
	Metadata         *stsapi.DiscoveryMetadata
	ClusterName      string
	kubernetesIssuer string
	WellKnownURL     string
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
		kubernetesIssuer:   cfg.KubernetesIssuer,
		// TODO: go over this and the fetching, a bit weird as is
		WellKnownURL: issuer.OAuthDiscoveryEndpoint(),
	}

	return r, nil
}

func (r *Registrator) MakeSoftwareStatement(oauthClient stsv1.STSClient) stsapi.SoftwareStatement {
	workload := stsapi.Workload{
		Name:        oauthClient.Name,
		Namespace:   oauthClient.Namespace,
		Environment: r.ClusterName,
		Issuer:      r.kubernetesIssuer,
	}

	policies := make([]stsapi.AuthorizationPolicy, 0)
	for _, acl := range oauthClient.Spec.AccessControlList {
		team := acl.Team
		for _, w := range acl.Workloads {
			wName := w.Name
			// TODO: make a function in stsapi to generate the client ID, since this is also used in the STS service itself
			clientID := fmt.Sprintf("%s:%s:%s", r.ClusterName, team, wName)
			policy := stsapi.AuthorizationPolicy{
				Consumer: clientID,
				Roles:    w.Roles,
			}
			policies = append(policies, policy)
		}
	}

	return stsapi.SoftwareStatement{
		ClientID:              workload.ClientID(),
		Workload:              workload,
		AuthorizationPolicies: policies,
	}
}

package configmap

import (
	"fmt"

	"github.com/nais/sts-operator/internal/sts"
	corev1 "k8s.io/api/core/v1"
)

const (
	STSClientIDKey      = "STS_CLIENT_ID"
	STSIssuerKey        = "STS_ISSUER"
	STSJwksURIKey       = "STS_JWKS_URI"
	STSTokenEndpointKey = "STS_TOKEN_ENDPOINT"
	STSWellKnownURLKey  = "STS_WELL_KNOWN_URL"

	StakaterReloaderAnnotationKey = "reloader.stakater.com/match"
)

type Data struct {
	ClientID sts.ClientID
	STS      sts.Instance
}

func CreateConfigMapSpec(name string, data Data) (*corev1.ConfigMap, error) {
	wellKnownURL, err := data.STS.Metadata.WellKnownURL()
	if err != nil {
		return nil, fmt.Errorf("constructing well-known URL: %w", err)
	}

	return &corev1.ConfigMap{
		Kind:       "ConfigMap",
		APIVersion: "v1",
		Name:       name,
		Namespace:  data.ClientID.Namespace,
		Labels:     Labels(data.ClientID.Name),
		Annotations: map[string]string{
			StakaterReloaderAnnotationKey: "true",
		},
		Data: map[string]string{
			STSClientIDKey:      data.ClientID.String(),
			STSWellKnownURLKey:  wellKnownURL,
			STSIssuerKey:        data.STS.Metadata.Issuer,
			STSJwksURIKey:       data.STS.Metadata.JwksURI,
			STSTokenEndpointKey: data.STS.Metadata.TokenEndpoint,
		},
	}, nil
}

func Labels(appName string) map[string]string {
	return map[string]string{
		"app": appName,
	}
}

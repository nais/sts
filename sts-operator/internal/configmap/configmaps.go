package configmap

import (
	stsapi "github.com/nais/sts/api"
	corev1 "k8s.io/api/core/v1"
)

const (
	STSClientIDKey      = "STS_CLIENT_ID"
	STSIssuerKey        = "STS_ISSUER"
	STSJwksURIKey       = "STS_JWKS_URI"
	STSTokenEndpointKey = "STS_TOKEN_ENDPOINT" // #nosec G101 -- Environment variable name, not a credential.
	STSWellKnownURLKey  = "STS_WELL_KNOWN_URL"

	StakaterReloaderAnnotationKey = "reloader.stakater.com/match"
)

func CreateConfigMapSpec(name, namespace string, wellKnownURL string, metadata *stsapi.DiscoveryMetadata, appName, clientID string) (*corev1.ConfigMap, error) {
	return &corev1.ConfigMap{
		Kind:       "ConfigMap",
		APIVersion: "v1",
		Name:       name,
		Namespace:  namespace,
		Labels:     Labels(appName),
		Annotations: map[string]string{
			StakaterReloaderAnnotationKey: "true",
		},
		Data: map[string]string{
			STSClientIDKey:      clientID,
			STSWellKnownURLKey:  wellKnownURL,
			STSIssuerKey:        metadata.Issuer,
			STSJwksURIKey:       metadata.JwksURI,
			STSTokenEndpointKey: metadata.TokenEndpoint,
		},
	}, nil
}

func Labels(appName string) map[string]string {
	return map[string]string{
		"app": appName,
	}
}

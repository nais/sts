package configmap

import (
	stsapi "github.com/nais/sts/api"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const (
	STSClientIDKey      = "STS_CLIENT_ID"
	STSIssuerKey        = "STS_ISSUER"
	STSJwksURIKey       = "STS_JWKS_URI"
	STSTokenEndpointKey = "STS_TOKEN_ENDPOINT" // #nosec G101 -- Environment variable name, not a credential.
	STSWellKnownURLKey  = "STS_WELL_KNOWN_URL"

	StakaterReloaderAnnotationKey = "reloader.stakater.com/match"

	// ManagedByLabelKey marks ConfigMaps written by the operator. The operator
	// only caches ConfigMaps with this label.
	ManagedByLabelKey   = "app.kubernetes.io/managed-by"
	ManagedByLabelValue = "sts-operator"
)

type ConfigMapData struct {
	AppName  string
	ClientID string
	Issuer   stsapi.STSIssuer
}

func Spec(name, namespace string, data ConfigMapData) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		Kind:       "ConfigMap",
		APIVersion: "v1",
		Name:       name,
		Namespace:  namespace,
		Labels:     Labels(data.AppName),
		Annotations: map[string]string{
			StakaterReloaderAnnotationKey: "true",
		},
		Data: map[string]string{
			STSClientIDKey:      data.ClientID,
			STSWellKnownURLKey:  data.Issuer.OAuthDiscoveryEndpoint(),
			STSIssuerKey:        data.Issuer.String(),
			STSJwksURIKey:       data.Issuer.JWKSEndpoint(),
			STSTokenEndpointKey: data.Issuer.TokenEndpoint(),
		},
	}
}

func Labels(appName string) map[string]string {
	return map[string]string{
		"app":             appName,
		ManagedByLabelKey: ManagedByLabelValue,
	}
}

func ManagedBySelector() labels.Selector {
	return labels.SelectorFromSet(labels.Set{ManagedByLabelKey: ManagedByLabelValue})
}

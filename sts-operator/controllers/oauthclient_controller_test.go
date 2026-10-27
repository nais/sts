package controllers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	stsv1 "github.com/nais/sts-operator/api/nais.io/v1"
	"github.com/nais/sts-operator/internal/configmap"
	stsapi "github.com/nais/sts/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func TestSynchronizeDoesNotOverwriteAnotherController(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case stsapi.OAuthDiscoveryPath:
			_ = json.NewEncoder(w).Encode(stsapi.DiscoveryMetadata{})
		case stsapi.RegistrationPath:
			_ = json.NewEncoder(w).Encode(stsapi.ClientRegistrationResponse{ClientID: "registered-client"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	registrator, err := stsapi.NewRegistrationClient(stsapi.STSIssuer(server.URL), func(context.Context) (string, error) {
		return "token", nil
	})
	require.NoError(t, err)

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, stsv1.AddToScheme(scheme))
	owner := &stsv1.OAuthClient{Name: "other-client", Namespace: "default", UID: "other-uid"}
	cm := &corev1.ConfigMap{
		Name: "shared-config", Namespace: "default",
		Labels: configmap.Labels(owner.Name), Data: map[string]string{"keep": "original"},
	}
	require.NoError(t, controllerutil.SetControllerReference(owner, cm, scheme))
	original := cm.DeepCopy()
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cm).Build()
	r := &OAuthClientReconciler{Client: k8sClient, Scheme: scheme, RegistrationClient: registrator}
	oauthClient := stsv1.OAuthClient{
		Name: "new-client", Namespace: "default", UID: "new-uid",
		Spec: stsv1.OAuthClientSpec{ConfigMapName: cm.Name},
	}
	_, err = r.synchronize(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&oauthClient)}, oauthClient)
	var ownedErr *controllerutil.AlreadyOwnedError
	require.ErrorAs(t, err, &ownedErr)
	var after corev1.ConfigMap
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(cm), &after))
	assert.Equal(t, original.Data, after.Data)
	assert.Equal(t, original.Labels, after.Labels)
	assert.Equal(t, original.OwnerReferences, after.OwnerReferences)
	assert.True(t, metav1.IsControlledBy(&after, owner))
}

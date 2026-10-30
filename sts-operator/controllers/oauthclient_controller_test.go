package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	stsv1 "github.com/nais/sts-operator/api/nais.io/v1"
	"github.com/nais/sts-operator/internal/config"
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
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// testSyncInterval is deliberately not the 1m default, so tests prove the reconciler reads config.
const testSyncInterval = 7 * time.Minute

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

func TestReconcileRegistersAndRefreshesConfigMapEverySyncInterval(t *testing.T) {
	ctx := context.Background()
	registrator, registrations := newRegistrationTestServer(t)
	oauthClient := newReconcileTestOAuthClient()
	k8sClient, r := newReconcileTestReconciler(t, registrator, oauthClient, interceptor.Funcs{})
	stale := &corev1.ConfigMap{
		Name: oauthClient.Spec.ConfigMapName, Namespace: oauthClient.Namespace,
		Labels: configmap.Labels(oauthClient.Name),
		Data:   map[string]string{configmap.STSClientIDKey: "stale-client"},
	}
	require.NoError(t, k8sClient.Create(ctx, stale))

	res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(oauthClient)})
	require.NoError(t, err)
	assert.Equal(t, testSyncInterval, res.RequeueAfter)
	require.Equal(t, int32(1), registrations.Load())

	var cm corev1.ConfigMap
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKey{Namespace: oauthClient.Namespace, Name: oauthClient.Spec.ConfigMapName}, &cm))
	assert.Equal(t, registeredClientID, cm.Data[configmap.STSClientIDKey])
	assert.True(t, metav1.IsControlledBy(&cm, oauthClient))

	var after stsv1.OAuthClient
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(oauthClient), &after))
	assert.Equal(t, registeredClientID, after.Status.ClientID)
	assert.Equal(t, int64(1), after.Status.ObservedGeneration)
	assert.True(t, after.Status.SynchronizationTimestamp.After(time.Now().Add(-testSyncInterval)))

	res, err = r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(oauthClient)})
	require.NoError(t, err)
	assert.Greater(t, res.RequeueAfter, time.Duration(0))
	assert.LessOrEqual(t, res.RequeueAfter, testSyncInterval)
	assert.Equal(t, int32(1), registrations.Load(), "a fresh sync must not register again")
}

func TestReconcileReturnsErrorWhenStatusUpdateFails(t *testing.T) {
	ctx := context.Background()
	registrator, _ := newRegistrationTestServer(t)
	oauthClient := newReconcileTestOAuthClient()
	funcs := interceptor.Funcs{
		SubResourceUpdate: func(context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption) error {
			return errors.New("status conflict")
		},
	}
	k8sClient, r := newReconcileTestReconciler(t, registrator, oauthClient, funcs)
	var before stsv1.OAuthClient
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(oauthClient), &before))

	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(oauthClient)})
	require.ErrorContains(t, err, "updating status")
	require.ErrorContains(t, err, "status conflict")

	var after stsv1.OAuthClient
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(oauthClient), &after))
	assert.Equal(t, before.Status, after.Status, "status must not be persisted")
}

const registeredClientID = "registered-client"

func newReconcileTestOAuthClient() *stsv1.OAuthClient {
	return &stsv1.OAuthClient{
		ObjectMeta: metav1.ObjectMeta{
			Name: "new-client", Namespace: "default", UID: "new-uid",
			Generation: 1, Finalizers: []string{finalizer},
		},
		Spec: stsv1.OAuthClientSpec{ConfigMapName: "new-config"},
		Status: stsv1.OAuthClientStatus{
			ObservedGeneration:       1,
			ClientID:                 "existing-client",
			SynchronizationTimestamp: metav1.NewTime(time.Now().Add(-2 * testSyncInterval)),
		},
	}
}

func newReconcileTestReconciler(t *testing.T, registrator *stsapi.RegistrationClient, oauthClient *stsv1.OAuthClient, funcs interceptor.Funcs) (client.Client, *OAuthClientReconciler) {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, stsv1.AddToScheme(scheme))
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(oauthClient).
		WithStatusSubresource(&stsv1.OAuthClient{}).
		WithInterceptorFuncs(funcs).
		Build()
	cfg := &config.Config{SyncInterval: testSyncInterval}
	return k8sClient, &OAuthClientReconciler{Client: k8sClient, Scheme: scheme, Config: cfg, RegistrationClient: registrator}
}

// newRegistrationTestServer serves STS discovery and registration. The returned
// counter reports how many registrations the server has accepted.
func newRegistrationTestServer(t *testing.T) (*stsapi.RegistrationClient, *atomic.Int32) {
	t.Helper()
	var registrations atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == stsapi.OAuthDiscoveryPath:
			writeJSON(w, stsapi.DiscoveryMetadata{})
		case r.Method == http.MethodPost && r.URL.Path == stsapi.RegistrationPath:
			var reg stsapi.ClientRegistration
			if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			registrations.Add(1)
			writeJSON(w, stsapi.ClientRegistrationResponse{ClientRegistration: reg, ClientID: registeredClientID})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	registrator, err := stsapi.NewRegistrationClient(stsapi.STSIssuer(server.URL), func(context.Context) (string, error) {
		return "token", nil
	})
	require.NoError(t, err)
	return registrator, &registrations
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

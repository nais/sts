package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

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
	registrator, registered := newRegistrationTestServer(t)
	oauthClient := newReconcileTestOAuthClient(1, 1, "existing-client", time.Now().Add(-2*testSyncInterval))
	k8sClient, r := newReconcileTestReconciler(t, registrator, oauthClient, interceptor.Funcs{})
	stale := &corev1.ConfigMap{
		Name: oauthClient.Spec.ConfigMapName, Namespace: oauthClient.Namespace,
		Labels: configmap.Labels(oauthClient.Name),
		Data:   map[string]string{configmap.STSClientIDKey: "stale-client"},
	}
	require.NoError(t, k8sClient.Create(ctx, stale))

	res, err := r.Reconcile(ctx, reconcileRequest(oauthClient))
	require.NoError(t, err)
	assert.Equal(t, testSyncInterval, res.RequeueAfter)
	require.Len(t, registered(), 1)

	var cm corev1.ConfigMap
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKey{Namespace: oauthClient.Namespace, Name: oauthClient.Spec.ConfigMapName}, &cm))
	assert.Equal(t, registeredClientID, cm.Data[configmap.STSClientIDKey])
	assert.True(t, metav1.IsControlledBy(&cm, oauthClient))

	var after stsv1.OAuthClient
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(oauthClient), &after))
	assert.Equal(t, registeredClientID, after.Status.ClientID)
	assert.Equal(t, int64(1), after.Status.ObservedGeneration)
	assert.True(t, after.Status.SynchronizationTimestamp.After(time.Now().Add(-testSyncInterval)))

	res, err = r.Reconcile(ctx, reconcileRequest(oauthClient))
	require.NoError(t, err)
	assert.Greater(t, res.RequeueAfter, time.Duration(0))
	assert.LessOrEqual(t, res.RequeueAfter, testSyncInterval)
	assert.Len(t, registered(), 1, "a fresh sync must not register again")
}

func TestReconcileRegistersChangedSpecAndPersistsStatus(t *testing.T) {
	ctx := context.Background()
	registrator, registered := newRegistrationTestServer(t)
	oauthClient := newReconcileTestOAuthClient(2, 1, "old-client", time.Now())
	oauthClient.Spec.AccessControlList = []stsv1.AccessControlList{
		{Team: "team1", Workloads: []stsv1.Workload{{Name: "consumer1", Roles: []string{"reader"}}}},
	}
	k8sClient, r := newReconcileTestReconciler(t, registrator, oauthClient, interceptor.Funcs{})

	res, err := r.Reconcile(ctx, reconcileRequest(oauthClient))
	require.NoError(t, err)
	assert.Equal(t, testSyncInterval, res.RequeueAfter)

	statements := registered()
	require.Len(t, statements, 1)
	assert.Equal(t, stsapi.SoftwareStatement{
		Client: stsapi.Client{Namespace: oauthClient.Namespace, Name: oauthClient.Name},
		AuthorizationPolicies: []stsapi.AuthorizationPolicy{
			{Consumer: stsapi.Client{Namespace: "team1", Name: "consumer1"}, Roles: []string{"reader"}},
		},
	}, unverifiedSoftwareStatement(t, statements[0]))

	var cm corev1.ConfigMap
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKey{Namespace: oauthClient.Namespace, Name: oauthClient.Spec.ConfigMapName}, &cm))
	assert.Equal(t, registeredClientID, cm.Data[configmap.STSClientIDKey])

	var after stsv1.OAuthClient
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(oauthClient), &after))
	assert.Equal(t, registeredClientID, after.Status.ClientID)
	assert.Equal(t, int64(2), after.Status.ObservedGeneration)
}

func TestReconcileReturnsErrorWhenStatusUpdateFails(t *testing.T) {
	ctx := context.Background()
	registrator, _ := newRegistrationTestServer(t)
	oauthClient := newReconcileTestOAuthClient(1, 1, "existing-client", time.Now().Add(-2*testSyncInterval))
	funcs := interceptor.Funcs{
		SubResourceUpdate: func(context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption) error {
			return errors.New("status conflict")
		},
	}
	k8sClient, r := newReconcileTestReconciler(t, registrator, oauthClient, funcs)
	var before stsv1.OAuthClient
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(oauthClient), &before))

	_, err := r.Reconcile(ctx, reconcileRequest(oauthClient))
	require.ErrorContains(t, err, "updating status")
	require.ErrorContains(t, err, "status conflict")

	var after stsv1.OAuthClient
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(oauthClient), &after))
	assert.Equal(t, before.Status, after.Status, "status must not be persisted")
}

const registeredClientID = "registered-client"

func newReconcileTestOAuthClient(generation, observedGeneration int64, clientID string, syncedAt time.Time) *stsv1.OAuthClient {
	return &stsv1.OAuthClient{
		ObjectMeta: metav1.ObjectMeta{
			Name: "new-client", Namespace: "default", UID: "new-uid",
			Generation: generation, Finalizers: []string{finalizer},
		},
		Spec: stsv1.OAuthClientSpec{ConfigMapName: "new-config"},
		Status: stsv1.OAuthClientStatus{
			ObservedGeneration:       observedGeneration,
			ClientID:                 clientID,
			SynchronizationTimestamp: metav1.NewTime(syncedAt),
		},
	}
}

func reconcileRequest(oauthClient *stsv1.OAuthClient) ctrl.Request {
	return ctrl.Request{NamespacedName: client.ObjectKeyFromObject(oauthClient)}
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
// function reports the software statements received so far.
func newRegistrationTestServer(t *testing.T) (*stsapi.RegistrationClient, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var statements []string
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
			mu.Lock()
			statements = append(statements, reg.SoftwareStatement)
			mu.Unlock()
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
	return registrator, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), statements...)
	}
}

func unverifiedSoftwareStatement(t *testing.T, raw string) stsapi.SoftwareStatement {
	t.Helper()
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	var statement stsapi.SoftwareStatement
	require.NoError(t, json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &statement))
	return statement
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

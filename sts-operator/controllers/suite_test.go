package controllers_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	stsv1 "github.com/nais/sts-operator/api/nais.io/v1"
	"github.com/nais/sts-operator/controllers"
	"github.com/nais/sts-operator/internal/config"
	"github.com/nais/sts-operator/internal/configmap"
	"github.com/nais/sts-operator/internal/sts"
	stsapi "github.com/nais/sts/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	controllerconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	ctrlmetricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

const (
	namespace = "default"
	appName   = "app1"
	// The mock STS returns an ID unlike the operator's fallback derivation, so
	// tests prove the operator stores the registration response.
	clientID         = "sts-env:default:app1"
	finalizerName    = "sts-operator.nais.io/finalizer"
	configMapName    = "sts-" + appName
	reconcileTimeout = 10 * time.Second
	pollInterval     = 100 * time.Millisecond
)

func TestSTSClientReconciler(t *testing.T) {
	ctrl.SetLogger(zap.New())

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, stsv1.AddToScheme(scheme))

	// Cleanup runs in LIFO order: manager stops first, then the HTTP server, then envtest.
	testEnv := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}

	if getFirstFoundEnvTestBinaryDir() != "" {
		testEnv.BinaryAssetsDirectory = getFirstFoundEnvTestBinaryDir()
	}

	restCfg, err := testEnv.Start()
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, testEnv.Stop())
	})

	registrations := make(chan string, 10)
	deletedIDs := make(chan string, 10)
	var stsURL string
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+stsapi.OAuthDiscoveryPath, func(w http.ResponseWriter, _ *http.Request) {
		issuer := stsapi.STSIssuer(stsURL)
		writeJSON(w, stsapi.DiscoveryMetadata{
			Issuer:        stsURL,
			TokenEndpoint: issuer.TokenEndpoint(),
			JwksURI:       issuer.JWKSEndpoint(),
		})
	})
	mux.HandleFunc("POST "+stsapi.RegistrationPath, func(w http.ResponseWriter, r *http.Request) {
		var reg stsapi.ClientRegistration
		if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// Drop overflow so retry loops cannot block test cleanup.
		select {
		case registrations <- reg.SoftwareStatement:
		default:
		}
		writeJSON(w, stsapi.ClientRegistrationResponse{ClientRegistration: reg, ClientID: clientID})
	})
	mux.HandleFunc("DELETE "+stsapi.RegistrationPath+"/{id}", func(w http.ResponseWriter, r *http.Request) {
		select {
		case deletedIDs <- r.PathValue("id"):
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	})
	stsServer := httptest.NewServer(mux)
	t.Cleanup(stsServer.Close)

	// Controller-runtime retains controller names across repeated test runs.
	skipNameValidation := true
	mgr, err := ctrl.NewManager(restCfg, ctrl.Options{
		Scheme:     scheme,
		Metrics:    ctrlmetricsserver.Options{BindAddress: "0"},
		Controller: controllerconfig.Controller{SkipNameValidation: &skipNameValidation},
	})
	require.NoError(t, err)

	stsURL = stsServer.URL
	authTokenPath := filepath.Join(t.TempDir(), "auth-token")
	require.NoError(t, os.WriteFile(authTokenPath, []byte("a very secure token"), 0o600))
	cfg := &config.Config{
		AuthTokenPath:           authTokenPath,
		ClusterName:             "local",
		MaxConcurrentReconciles: 1,
		STSBaseURL:              stsURL,
	}
	ctx, cancel := context.WithCancel(context.Background())
	registrator, err := sts.NewRegistrator(ctx, cfg)
	require.NoError(t, err)
	keySet, err := registrator.PublicKeySet()
	require.NoError(t, err)

	require.NoError(t, (&controllers.STSClientReconciler{
		Client:      mgr.GetClient(),
		Scheme:      mgr.GetScheme(),
		Recorder:    mgr.GetEventRecorder("sts-operator"),
		Config:      cfg,
		Registrator: registrator,
	}).SetupWithManager(mgr))

	mgrDone := make(chan error, 1)
	go func() {
		mgrDone <- mgr.Start(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-mgrDone:
			assert.NoError(t, err)
		case <-time.After(reconcileTimeout):
			t.Error("manager did not stop in time")
		}
	})

	k8sClient, err := client.New(restCfg, client.Options{Scheme: scheme})
	require.NoError(t, err)

	stsClient := &stsv1.STSClient{
		Name: appName, Namespace: namespace,
	}
	require.NoError(t, k8sClient.Create(ctx, stsClient))
	key := client.ObjectKeyFromObject(stsClient)

	if !t.Run("creation registers client and creates config map", func(t *testing.T) {
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			var obj stsv1.STSClient
			if !assert.NoError(c, k8sClient.Get(ctx, key, &obj)) {
				return
			}
			assert.Equal(c, clientID, obj.Status.ClientID)
			assert.Equal(c, obj.Generation, obj.Status.ObservedGeneration)
			assert.False(c, obj.Status.SynchronizationTimestamp.IsZero())
			assert.Contains(c, obj.Finalizers, finalizerName)
		}, reconcileTimeout, pollInterval)
		require.NoError(t, k8sClient.Get(ctx, key, stsClient))

		require.Len(t, registrations, 1)
		assert.Equal(t, stsapi.SoftwareStatement{
			Client: stsapi.Client{Namespace: namespace, Name: appName},
		}, verifySoftwareStatement(t, <-registrations, keySet))

		var cm corev1.ConfigMap
		require.NoError(t, k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: configMapName}, &cm))
		assert.Equal(t, map[string]string{"app": appName}, cm.Labels)
		assert.Equal(t, map[string]string{configmap.StakaterReloaderAnnotationKey: "true"}, cm.Annotations)
		assert.Equal(t, map[string]string{
			configmap.STSClientIDKey:      clientID,
			configmap.STSWellKnownURLKey:  stsURL + stsapi.OAuthDiscoveryPath,
			configmap.STSIssuerKey:        stsURL,
			configmap.STSJwksURIKey:       stsURL + "/jwks",
			configmap.STSTokenEndpointKey: stsURL + "/token",
		}, cm.Data)
		assert.True(t, metav1.IsControlledBy(&cm, stsClient), "config map should be controlled by STSClient")
	}) {
		t.FailNow()
	}

	if !t.Run("spec change re-registers client and keeps config map", func(t *testing.T) {
		var before corev1.ConfigMap
		require.NoError(t, k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: configMapName}, &before))
		previousGeneration := stsClient.Generation

		stsClient.Spec.AccessControlList = []stsv1.AccessControlList{
			{
				Team: "team1",
				Workloads: []stsv1.Workload{
					{Name: "consumer1", Roles: []string{"reader"}},
					// Roles are optional.
					{Name: "consumer2"},
				},
			},
			{Team: "team2", Workloads: []stsv1.Workload{{Name: "consumer1"}}},
		}
		require.NoError(t, k8sClient.Update(ctx, stsClient))
		require.Greater(t, stsClient.Generation, previousGeneration)

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			var obj stsv1.STSClient
			if !assert.NoError(c, k8sClient.Get(ctx, key, &obj)) {
				return
			}
			assert.Equal(c, stsClient.Generation, obj.Status.ObservedGeneration)
		}, reconcileTimeout, pollInterval)

		require.Len(t, registrations, 1)
		assert.Equal(t, stsapi.SoftwareStatement{
			Client: stsapi.Client{Namespace: namespace, Name: appName},
			AuthorizationPolicies: []stsapi.AuthorizationPolicy{
				{Consumer: stsapi.Client{Namespace: "team1", Name: "consumer1"}, Roles: []string{"reader"}},
				{Consumer: stsapi.Client{Namespace: "team1", Name: "consumer2"}},
				{Consumer: stsapi.Client{Namespace: "team2", Name: "consumer1"}},
			},
		}, verifySoftwareStatement(t, <-registrations, keySet))

		var after corev1.ConfigMap
		require.NoError(t, k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: configMapName}, &after))
		assert.Equal(t, before.UID, after.UID, "config map should be updated in place")
	}) {
		t.FailNow()
	}

	t.Run("deletion deregisters client and removes STSClient", func(t *testing.T) {
		require.NoError(t, k8sClient.Delete(ctx, stsClient))

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			var obj stsv1.STSClient
			err := k8sClient.Get(ctx, key, &obj)
			assert.True(c, apierrors.IsNotFound(err), "STSClient should be removed, got: %v", err)
		}, reconcileTimeout, pollInterval)

		require.Len(t, deletedIDs, 1)
		assert.Equal(t, clientID, <-deletedIDs)
	})
}

func verifySoftwareStatement(t *testing.T, raw string, keySet jose.JSONWebKeySet) stsapi.SoftwareStatement {
	t.Helper()

	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)

	require.Len(t, keySet.Keys, 1)
	payload, err := jws.Verify(keySet.Keys[0])
	require.NoError(t, err, "software statement must verify with operator public key")

	var statement stsapi.SoftwareStatement
	require.NoError(t, json.Unmarshal(payload, &statement))
	return statement
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// getFirstFoundEnvTestBinaryDir locates the first binary in the specified path.
// ENVTEST-based tests depend on specific binaries, usually located in paths set by
// controller-runtime. When running tests directly (e.g., via an IDE) without using
// Makefile targets, the 'BinaryAssetsDirectory' must be explicitly configured.
//
// This function streamlines the process by finding the required binaries, similar to
// setting the 'KUBEBUILDER_ASSETS' environment variable. To ensure the binaries are
// properly set up, run 'make setup-envtest' beforehand.
func getFirstFoundEnvTestBinaryDir() string {
	basePath := filepath.Join("..", "bin", "k8s")
	entries, err := os.ReadDir(basePath)
	if err != nil {
		slog.Error("failed to read envtest binary directory; have you run 'make setup-envtest'?", "path", basePath, "error", err)
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return filepath.Join(basePath, entry.Name())
		}
	}
	return ""
}

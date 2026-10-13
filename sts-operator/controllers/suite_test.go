package controllers_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	liberatorv1 "github.com/nais/liberator/pkg/apis/nais.io/v1"
	"github.com/nais/liberator/pkg/events"
	"github.com/nais/liberator/pkg/oauth"
	stsv1 "github.com/nais/sts-operator/api/nais.io/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // for side effects only
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	ctrlmetricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/nais/sts-operator/controllers"
	"github.com/nais/sts-operator/internal/config"
	"github.com/nais/sts-operator/internal/configmap"
	"github.com/nais/sts-operator/internal/jwk"
	"github.com/nais/sts-operator/internal/sts"
	// +kubebuilder:scaffold:imports
)

var (
	cli     client.Client
	testEnv *envtest.Environment
	ctx     context.Context
	cancel  context.CancelFunc
)

const (
	appName            = "app1"
	secretName         = "app1-secret-foobar"
	alreadyInUseSecret = "already-in-use"
	expiredSecret      = "expired-secret"
	namespace          = "default"
)

type stsHandler struct{}

func (h *stsHandler) serveRegistration(w http.ResponseWriter, r *http.Request) {
	statement := &sts.ClientRegistration{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(statement)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *stsHandler) serveDelete(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (h *stsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		h.serveRegistration(w, r)
	} else if r.Method == http.MethodDelete {
		h.serveDelete(w, r)
	}
}

func fixtures(cli client.Client, stsURL string) error {
	var err error

	ctx := context.Background()

	err = cli.Create(
		ctx,
		&stsv1.STSClient{
			Kind:       "STSClient",
			APIVersion: "nais.io/v1",
			Name:       appName,
			Namespace:  namespace,
			Spec: stsv1.STSClientSpec{
				SecretName:   secretName,
				AccessPolicy: &liberatorv1.AccessPolicy{},
			},
		},
	)
	if err != nil {
		return err
	}

	err = cli.Create(
		ctx,
		&corev1.Pod{
			Kind:       "Pod",
			APIVersion: "v1",
			Name:       appName,
			Namespace:  namespace,
			Labels: map[string]string{
				"app": appName,
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "main",
						Image: "foo",
					},
				},
				Volumes: []corev1.Volume{
					{
						Name: "secret-previous-in-use",
						Secret: &corev1.SecretVolumeSource{
							SecretName: alreadyInUseSecret,
						},
					},
					{
						Name: "secret-to-create",
						Secret: &corev1.SecretVolumeSource{
							SecretName: secretName,
						},
					},
				},
			},
		},
	)
	if err != nil {
		return err
	}

	key, err := jwk.Generate()
	if err != nil {
		return err
	}

	keyBytes, err := key.MarshalJSON()
	if err != nil {
		return err
	}

	err = cli.Create(
		ctx,
		&corev1.Secret{
			Kind:       "Secret",
			APIVersion: "v1",
			Name:       alreadyInUseSecret,
			Namespace:  namespace,
			Labels: map[string]string{
				"app":                       appName,
				configmap.STSSecretLabelKey: configmap.STSSecretLabelType,
			},
			Annotations: map[string]string{
				configmap.StakaterReloaderAnnotationKey: "true",
			},
			Data: map[string][]byte{
				configmap.STSPrivateJWKKey:    keyBytes,
				configmap.STSClientIDKey:      []byte("local:default:app1"),
				configmap.STSWellKnownURLKey:  fmt.Appendf(nil, "%s/.well-known/oauth-authorization-server", stsURL),
				configmap.STSIssuerKey:        []byte(stsURL),
				configmap.STSJwksURIKey:       fmt.Appendf(nil, "%s/jwks", stsURL),
				configmap.STSTokenEndpointKey: fmt.Appendf(nil, "%s/token", stsURL),
			},
		},
	)
	if err != nil {
		return err
	}

	err = cli.Create(
		ctx,
		&corev1.Secret{
			Kind:       "Secret",
			APIVersion: "v1",
			Name:       expiredSecret,
			Namespace:  namespace,
			Labels: map[string]string{
				"app":                       appName,
				configmap.STSSecretLabelKey: configmap.STSSecretLabelType,
			},
		},
	)

	return err
}

func TestReconciler(t *testing.T) {
	ctrl.SetLogger(zap.New())

	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	// Retrieve the first found binary directory to allow running tests from IDEs
	if getFirstFoundEnvTestBinaryDir() != "" {
		testEnv.BinaryAssetsDirectory = getFirstFoundEnvTestBinaryDir()
	}

	k8scfg, err := testEnv.Start()
	require.NoError(t, err)
	require.NotNil(t, k8scfg)

	err = stsv1.AddToScheme(scheme.Scheme)
	require.NoError(t, err)

	// +kubebuilder:scaffold:scheme

	mgr, err := ctrl.NewManager(testEnv.Config, ctrl.Options{
		Scheme: scheme.Scheme,
		Metrics: ctrlmetricsserver.Options{
			BindAddress: "0",
		},
	})
	require.NoError(t, err)

	cli = mgr.GetClient()
	require.NoError(t, err)

	stsServer := httptest.NewServer(&stsHandler{})
	cfg, err := makeConfig(stsServer.URL)
	if err != nil {
		log.Fatalf("unable to create STS instances: %+v", err)
	}

	err = (&controllers.STSClientReconciler{
		Client:   cli,
		Recorder: mgr.GetEventRecorder("sts-operator"),
		Scheme:   mgr.GetScheme(),
		Config:   cfg,
	}).SetupWithManager(mgr)
	require.NoError(t, err)

	// insert data into the cluster
	err = fixtures(cli, stsServer.URL)
	if err != nil {
		t.Error(err)
		t.Fail()
		return
	}

	ctx, cancel = context.WithCancel(context.Background())

	go func() {
		err = mgr.Start(ctx)
		if err != nil {
			panic(err)
		}
	}()

	// wait for synced secret until timeout
	currentSecret, err := getSecretWithTimeout(ctx, cli, namespace, secretName)
	require.NoError(t, err)
	require.NotNil(t, currentSecret)
	ensureSecretIsValid(t, currentSecret, stsServer.URL)

	// existing, in-use secret should be preserved
	previousSecret, err := getSecret(ctx, cli, namespace, alreadyInUseSecret)
	require.NoError(t, err)
	require.NotNil(t, previousSecret)
	ensureSecretIsValid(t, previousSecret, stsServer.URL)

	// expired secret should be deleted
	_, err = getSecret(ctx, cli, namespace, expiredSecret)
	assert.True(t, errors.IsNotFound(err), "expired secret should be deleted")

	// retrieve the STSClient resource and check that hash and status is set
	stsClient := &stsv1.STSClient{}
	key := client.ObjectKey{
		Namespace: namespace,
		Name:      appName,
	}
	err = cli.Get(ctx, key, stsClient)
	require.NoError(t, err)

	assert.True(t, containsOwnerRef(currentSecret.GetOwnerReferences(), stsClient), "secret should contain ownerReference")

	assert.Equal(t, stsClient.GetGeneration(), stsClient.Status.ObservedGeneration)
	assert.Equal(t, events.RolloutComplete, stsClient.Status.SynchronizationState)
	assert.Equal(t, []string{
		"sts-operator.nais.io/finalizer",
	}, stsClient.GetFinalizers())

	// update secret name in STSClient spec and verify that a new secret is created
	err = cli.Get(ctx, key, stsClient)
	require.NoError(t, err)
	stsClient.Spec.SecretName = "new-secret-name"
	err = cli.Update(ctx, stsClient)
	require.NoError(t, err)

	newSecret, err := getSecretWithTimeout(ctx, cli, namespace, "new-secret-name")
	require.NoError(t, err)
	require.NotNil(t, newSecret)
	ensureSecretIsValid(t, newSecret, stsServer.URL)

	// verify that the previous secret still exists
	previousSecret, err = getSecret(ctx, cli, namespace, secretName)
	require.NoError(t, err)
	require.NotNil(t, previousSecret)
	ensureSecretIsValid(t, previousSecret, stsServer.URL)

	// remove the STSClient resource; usually done when naiserator syncs
	err = cli.Delete(ctx, stsClient)
	require.NoError(t, err)
	require.NoError(t, waitForDeletedSTSClient(ctx, cli, namespace, stsClient.Name))

	cancel()
	err = testEnv.Stop()
	require.NoError(t, err)
}

func ensureSecretIsValid(t *testing.T, sec *corev1.Secret, stsURL string) {
	assert.Equal(t, map[string]string{
		configmap.StakaterReloaderAnnotationKey: "true",
	}, sec.GetAnnotations())
	assert.Equal(t, map[string]string{
		"app":                       appName,
		configmap.STSSecretLabelKey: configmap.STSSecretLabelType,
	}, sec.GetLabels())
	assert.NotEmpty(t, sec.Data[configmap.STSPrivateJWKKey])
	assert.Equal(t, "local:default:app1", string(sec.Data[configmap.STSClientIDKey]))
	assert.Equal(t, fmt.Sprintf("%s/.well-known/oauth-authorization-server", stsURL), string(sec.Data[configmap.STSWellKnownURLKey]))
	assert.Equal(t, stsURL, string(sec.Data[configmap.STSIssuerKey]))
	assert.Equal(t, fmt.Sprintf("%s/jwks", stsURL), string(sec.Data[configmap.STSJwksURIKey]))
	assert.Equal(t, fmt.Sprintf("%s/token", stsURL), string(sec.Data[configmap.STSTokenEndpointKey]))
}

func getSecret(ctx context.Context, cli client.Client, namespace, name string) (*corev1.Secret, error) {
	key := client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}
	sec := &corev1.Secret{}
	err := cli.Get(ctx, key, sec)
	return sec, err
}

func getSecretWithTimeout(ctx context.Context, cli client.Client, namespace, name string) (*corev1.Secret, error) {
	key := client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}
	sec := &corev1.Secret{}
	timeout := time.NewTimer(5 * time.Second)
	ticker := time.NewTicker(250 * time.Millisecond)

	for {
		select {
		case <-timeout.C:
			return nil, fmt.Errorf("timeout while waiting for secret synchronization")
		case <-ticker.C:
			err := cli.Get(ctx, key, sec)
			if err == nil {
				return sec, nil
			}
			if !errors.IsNotFound(err) {
				return nil, err
			}
		}
	}
}

func waitForDeletedSTSClient(ctx context.Context, cli client.Client, namespace, name string) error {
	key := client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}
	stsClient := &stsv1.STSClient{}
	timeout := time.NewTimer(5 * time.Second)
	ticker := time.NewTicker(250 * time.Millisecond)

	for {
		select {
		case <-timeout.C:
			return fmt.Errorf("STSClient still exists")
		case <-ticker.C:
			err := cli.Get(ctx, key, stsClient)
			if errors.IsNotFound(err) {
				return nil
			} else if err != nil {
				return err
			}
		}
	}
}

func makeConfig(stsURL string) (*config.Config, error) {
	jwk, err := jwk.Generate()
	if err != nil {
		return nil, err
	}

	raw, err := sts.ClientAssertion(&jwk, "client1", "http://endpoint/registration/client")
	if err != nil {
		return nil, err
	}

	authTokenPath := os.TempDir() + "/auth-token"
	err = os.WriteFile(authTokenPath, []byte(raw), 0o600)
	if err != nil {
		return nil, fmt.Errorf("unable to write token for invoking STS: %w", err)
	}

	return &config.Config{
		ClientID:      "sts-operator",
		ClientJwk:     &jwk,
		ClusterName:   "local",
		AuthTokenPath: authTokenPath,
		STSInstances: []sts.Instance{
			sts.NewInstance(stsURL, "sts-operator", &jwk, &oauth.MetadataOAuth{
				Issuer:        stsURL,
				JwksURI:       stsURL + "/jwks",
				TokenEndpoint: stsURL + "/token",
			}, authTokenPath),
		},
	}, nil
}

func containsOwnerRef(refs []metav1.OwnerReference, owner *stsv1.STSClient) bool {
	expected := metav1.OwnerReference{
		APIVersion: owner.APIVersion,
		Kind:       owner.Kind,
		Name:       owner.Name,
		UID:        owner.UID,
	}
	for _, ref := range refs {
		sameApiVersion := ref.APIVersion == expected.APIVersion
		sameKind := ref.Kind == expected.Kind
		sameName := ref.Name == expected.Name
		sameUID := ref.UID == expected.UID
		isBlockOwnerDeletion := ref.BlockOwnerDeletion != nil && *ref.BlockOwnerDeletion == true
		isController := ref.Controller != nil && *ref.Controller == true
		if sameApiVersion && sameKind && sameName && sameUID && isBlockOwnerDeletion && isController {
			return true
		}
	}
	return false
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

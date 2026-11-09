package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// testSyncInterval is deliberately not the 1m default, so tests prove the reconciler reads config.
const testSyncInterval = 7 * time.Minute

const (
	registeredClientID = "registered-client"

	messageSucceeded          = "Registration and ConfigMap reconciled"
	messageRegistrationFailed = "Registration with STS failed"
	messageConfigMapFailed    = `ConfigMap "new-config" could not be reconciled`
)

func TestReconcileRegistersAndRefreshesConfigMapEverySyncInterval(t *testing.T) {
	rt := newReconcileTest(t, newSyncedOAuthClient())
	stale := &corev1.ConfigMap{
		Name: "new-config", Namespace: "default",
		Labels: configmap.Labels("new-client"),
		Data:   map[string]string{configmap.STSClientIDKey: "stale-client"},
	}
	require.NoError(t, rt.client.Create(rt.ctx, stale))

	// An expired sync registers and refreshes the ConfigMap.
	res, err := rt.reconcile()
	require.NoError(t, err)
	assert.Equal(t, testSyncInterval, res.RequeueAfter)
	assert.Equal(t, int32(1), rt.stub.registrations.Load())

	var cm corev1.ConfigMap
	require.NoError(t, rt.client.Get(rt.ctx, client.ObjectKeyFromObject(stale), &cm))
	assert.Equal(t, registeredClientID, cm.Data[configmap.STSClientIDKey])

	synced := rt.get()
	assert.True(t, metav1.IsControlledBy(&cm, synced))
	assert.Equal(t, registeredClientID, synced.Status.ClientID)
	assertReady(t, synced, metav1.ConditionTrue, stsv1.ReasonSucceeded, messageSucceeded)

	// A fresh sync is skipped until the interval expires.
	res, err = rt.reconcile()
	require.NoError(t, err)
	assert.Positive(t, res.RequeueAfter)
	assert.LessOrEqual(t, res.RequeueAfter, testSyncInterval)
	assert.Equal(t, int32(1), rt.stub.registrations.Load())
}

func TestReconcileReturnsErrorWhenStatusUpdateFails(t *testing.T) {
	rt := newReconcileTest(t, newSyncedOAuthClient())
	before := rt.get()
	rt.failStatusUpdate = true

	_, err := rt.reconcile()
	require.ErrorContains(t, err, "updating status")

	assert.Equal(t, before.Status, rt.get().Status)
}

func TestReconcileSyncsWithinIntervalUnlessCurrentSpecIsReady(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*stsv1.OAuthClient)
	}{
		{"spec changed", func(o *stsv1.OAuthClient) {
			o.Generation = 2
		}},
		{"not ready", func(o *stsv1.OAuthClient) {
			_ = failed(o, messageRegistrationFailed, nil)
		}},
		{"no Ready condition", func(o *stsv1.OAuthClient) {
			o.Status.Conditions = nil
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oauthClient := newSyncedOAuthClient()
			now := metav1.Now()
			oauthClient.Status.SynchronizationTimestamp = &now
			tt.mutate(oauthClient)
			rt := newReconcileTest(t, oauthClient)

			_, err := rt.reconcile()
			require.NoError(t, err)

			assert.Equal(t, int32(1), rt.stub.registrations.Load())
		})
	}
}

func TestReconcileReadyTransitions(t *testing.T) {
	oauthClient := newSyncedOAuthClient()
	other := metav1.Condition{Type: "Other", Status: metav1.ConditionTrue, Reason: "Other", LastTransitionTime: metav1.Now()}
	oauthClient.Status.Conditions = append(oauthClient.Status.Conditions, other)
	rt := newReconcileTest(t, oauthClient)
	initial := rt.get()

	// A registration failure sets Ready False and keeps the last successful sync.
	rt.stub.failRegister.Store(true)
	_, err := rt.reconcile()
	require.ErrorContains(t, err, "registering client with STS")

	failed := rt.get()
	assertReady(t, failed, metav1.ConditionFalse, stsv1.ReasonFailed, messageRegistrationFailed)
	assert.Equal(t, initial.Status.ClientID, failed.Status.ClientID)
	assert.Equal(t, initial.Status.SynchronizationTimestamp, failed.Status.SynchronizationTimestamp)

	// A ConfigMap failure keeps the new registration's client ID.
	rt.stub.failRegister.Store(false)
	rt.failConfigMap = true
	_, err = rt.reconcile()
	require.ErrorContains(t, err, "creating or updating config map")

	partial := rt.get()
	assertReady(t, partial, metav1.ConditionFalse, stsv1.ReasonFailed, messageConfigMapFailed)
	assert.Equal(t, registeredClientID, partial.Status.ClientID)

	// Recovery sets Ready True.
	rt.failConfigMap = false
	_, err = rt.reconcile()
	require.NoError(t, err)

	recovered := rt.get()
	assertReady(t, recovered, metav1.ConditionTrue, stsv1.ReasonSucceeded, messageSucceeded)

	// A periodic success keeps Ready's transition time and moves the sync timestamp.
	expired := metav1.NewTime(time.Now().Add(-2 * testSyncInterval))
	recovered.Status.SynchronizationTimestamp = &expired
	require.NoError(t, rt.client.Status().Update(rt.ctx, recovered))
	_, err = rt.reconcile()
	require.NoError(t, err)

	periodic := rt.get()
	assert.Equal(t, readyCondition(t, recovered).LastTransitionTime, readyCondition(t, periodic).LastTransitionTime)
	assert.True(t, periodic.Status.SynchronizationTimestamp.After(expired.Time))

	assert.NotNil(t, meta.FindStatusCondition(periodic.Status.Conditions, other.Type))
}

func TestReconcileDeletionWithoutClientID(t *testing.T) {
	oauthClient := newSyncedOAuthClient()
	oauthClient.Status = stsv1.OAuthClientStatus{}
	now := metav1.Now()
	oauthClient.DeletionTimestamp = &now
	rt := newReconcileTest(t, oauthClient)

	_, err := rt.reconcile()
	require.NoError(t, err)

	assert.Zero(t, rt.stub.deletes.Load())
	err = rt.client.Get(rt.ctx, rt.req.NamespacedName, &stsv1.OAuthClient{})
	assert.True(t, apierrors.IsNotFound(err))
}

// newSyncedOAuthClient returns a Ready client with a finalizer whose last sync has expired.
func newSyncedOAuthClient() *stsv1.OAuthClient {
	expired := metav1.NewTime(time.Now().Add(-2 * testSyncInterval))
	oauthClient := &stsv1.OAuthClient{
		Name: "new-client", Namespace: "default", UID: "new-uid",
		Generation: 1,
		Finalizers: []string{finalizer},
		Spec:       stsv1.OAuthClientSpec{ConfigMapName: "new-config"},
		Status: stsv1.OAuthClientStatus{
			ClientID:                 "existing-client",
			SynchronizationTimestamp: &expired,
		},
	}
	ready(oauthClient)
	return oauthClient
}

func readyCondition(t *testing.T, obj *stsv1.OAuthClient) metav1.Condition {
	t.Helper()
	condition := meta.FindStatusCondition(obj.Status.Conditions, stsv1.ConditionReady)
	require.NotNil(t, condition, "Ready condition missing")
	return *condition
}

func assertReady(t *testing.T, obj *stsv1.OAuthClient, status metav1.ConditionStatus, reason, message string) {
	t.Helper()
	condition := readyCondition(t, obj)
	assert.Equal(t, status, condition.Status)
	assert.Equal(t, reason, condition.Reason)
	assert.Equal(t, message, condition.Message)
	assert.Equal(t, obj.Generation, condition.ObservedGeneration)
}

type reconcileTest struct {
	t          *testing.T
	ctx        context.Context
	stub       *stsStub
	client     client.Client
	reconciler *OAuthClientReconciler
	req        ctrl.Request

	failConfigMap    bool
	failStatusUpdate bool
}

func newReconcileTest(t *testing.T, oauthClient *stsv1.OAuthClient) *reconcileTest {
	t.Helper()
	rt := &reconcileTest{
		t:    t,
		ctx:  context.Background(),
		stub: newSTSStub(t),
		req:  ctrl.Request{NamespacedName: client.ObjectKeyFromObject(oauthClient)},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, stsv1.AddToScheme(scheme))

	rt.client = fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(oauthClient).
		WithStatusSubresource(&stsv1.OAuthClient{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.ConfigMap); ok && rt.failConfigMap {
					return errors.New("configmap get failed")
				}
				return c.Get(ctx, key, obj, opts...)
			},
			SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
				if rt.failStatusUpdate {
					return errors.New("status update rejected")
				}
				return c.SubResource(sub).Update(ctx, obj, opts...)
			},
		}).
		Build()

	rt.reconciler = &OAuthClientReconciler{
		Client:             rt.client,
		Scheme:             scheme,
		Config:             &config.Config{SyncInterval: testSyncInterval},
		RegistrationClient: rt.stub.RegistrationClient,
	}
	return rt
}

func (rt *reconcileTest) reconcile() (ctrl.Result, error) {
	return rt.reconciler.Reconcile(rt.ctx, rt.req)
}

func (rt *reconcileTest) get() *stsv1.OAuthClient {
	rt.t.Helper()
	var obj stsv1.OAuthClient
	require.NoError(rt.t, rt.client.Get(rt.ctx, rt.req.NamespacedName, &obj))
	return &obj
}

type stsStub struct {
	*stsapi.RegistrationClient
	registrations atomic.Int32
	deletes       atomic.Int32
	failRegister  atomic.Bool
}

func newSTSStub(t *testing.T) *stsStub {
	t.Helper()
	stub := &stsStub{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == stsapi.OAuthDiscoveryPath:
			writeJSON(w, stsapi.DiscoveryMetadata{})

		case r.Method == http.MethodPost && r.URL.Path == stsapi.RegistrationPath:
			if stub.failRegister.Load() {
				http.Error(w, "registration rejected", http.StatusInternalServerError)
				return
			}
			var reg stsapi.ClientRegistration
			if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			stub.registrations.Add(1)
			writeJSON(w, stsapi.ClientRegistrationResponse{ClientRegistration: reg, ClientID: registeredClientID})

		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, stsapi.RegistrationPath+"/"):
			stub.deletes.Add(1)
			w.WriteHeader(http.StatusNoContent)

		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	registrator, err := stsapi.NewRegistrationClient(stsapi.STSIssuer(server.URL), func(context.Context) (string, error) {
		return "token", nil
	})
	require.NoError(t, err)
	stub.RegistrationClient = registrator
	return stub
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

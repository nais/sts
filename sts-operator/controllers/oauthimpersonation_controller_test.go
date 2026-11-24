package controllers

import (
	"context"
	"testing"

	stsv1 "github.com/nais/sts-operator/api/nais.io/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestOAuthImpersonationReconcile(t *testing.T) {
	newImpersonation := func() *stsv1.OAuthImpersonation {
		return &stsv1.OAuthImpersonation{
			Name: "app", Namespace: "default", UID: "impersonation-uid", Generation: 2,
			Spec: stsv1.OAuthImpersonationSpec{AllowedSubjects: []string{"alice"}},
		}
	}
	newClient := func(observed *stsv1.ObservedImpersonation, readyStatus metav1.ConditionStatus) *stsv1.OAuthClient {
		c := &stsv1.OAuthClient{
			Name: "app", Namespace: "default", UID: "client-uid",
			Status: stsv1.OAuthClientStatus{
				ObservedImpersonation:    observed,
				SynchronizationTimestamp: new(metav1.Now()),
			},
		}
		meta.SetStatusCondition(&c.Status.Conditions, metav1.Condition{Type: stsv1.ConditionReady, Status: readyStatus, Reason: "Test"})
		return c
	}

	tests := []struct {
		name       string
		client     *stsv1.OAuthClient
		wantStatus metav1.ConditionStatus
		wantReason string
	}{
		{"client not found", nil, metav1.ConditionFalse, stsv1.ReasonClientNotFound},
		{"registered", newClient(&stsv1.ObservedImpersonation{UID: "impersonation-uid", Generation: 2}, metav1.ConditionTrue), metav1.ConditionTrue, stsv1.ReasonSucceeded},
		{"old generation registered", newClient(&stsv1.ObservedImpersonation{UID: "impersonation-uid", Generation: 1}, metav1.ConditionTrue), metav1.ConditionFalse, stsv1.ReasonPending},
		{"client failed", newClient(nil, metav1.ConditionFalse), metav1.ConditionFalse, stsv1.ReasonFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			require.NoError(t, stsv1.AddToScheme(scheme))
			objs := []client.Object{newImpersonation()}
			if tt.client != nil {
				objs = append(objs, tt.client)
			}
			c := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(objs...).
				WithStatusSubresource(&stsv1.OAuthImpersonation{}).
				Build()
			r := &OAuthImpersonationReconciler{Client: c, Scheme: scheme}
			key := client.ObjectKey{Namespace: "default", Name: "app"}

			_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
			require.NoError(t, err)

			var got stsv1.OAuthImpersonation
			require.NoError(t, c.Get(context.Background(), key, &got))
			condition := meta.FindStatusCondition(got.Status.Conditions, stsv1.ConditionReady)
			require.NotNil(t, condition)
			assert.Equal(t, tt.wantStatus, condition.Status)
			assert.Equal(t, tt.wantReason, condition.Reason)
			assert.Equal(t, got.Generation, condition.ObservedGeneration)
			if tt.client != nil {
				assert.Len(t, got.OwnerReferences, 1)
				assert.Equal(t, tt.client.UID, got.OwnerReferences[0].UID)
			}
		})
	}
}

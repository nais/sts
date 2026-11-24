package controllers

import (
	"context"
	"fmt"

	stsv1 "github.com/nais/sts-operator/api/nais.io/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
)

// OAuthImpersonationReconciler links an OAuthImpersonation to the OAuthClient
// with the same name and reports whether that client has registered it.
// The OAuthClientReconciler sends the impersonators to STS.
type OAuthImpersonationReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func NewOAuthImpersonationReconciler(mgr ctrl.Manager) error {
	r := &OAuthImpersonationReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}
	return r.SetupWithManager(mgr)
}

func (r *OAuthImpersonationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&stsv1.OAuthImpersonation{}).
		// Status changes on the OAuthClient with the same name update this status.
		Watches(&stsv1.OAuthClient{}, &handler.EnqueueRequestForObject{}).
		Complete(r)
}

// +kubebuilder:rbac:groups=nais.io,resources=oauthimpersonations,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=nais.io,resources=oauthimpersonations/status,verbs=get;update;patch

func (r *OAuthImpersonationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var impersonation stsv1.OAuthImpersonation
	if err := r.Get(ctx, req.NamespacedName, &impersonation); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !impersonation.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	before := impersonation.Status.DeepCopy()

	var oauthClient stsv1.OAuthClient
	err := r.Get(ctx, req.NamespacedName, &oauthClient)
	switch {
	case apierrors.IsNotFound(err):
		r.setReady(&impersonation, metav1.ConditionFalse, stsv1.ReasonClientNotFound,
			fmt.Sprintf("OAuthClient %q not found", req.Name))
	case err != nil:
		return ctrl.Result{}, fmt.Errorf("getting OAuthClient: %w", err)
	default:
		// Garbage-collect the impersonation with its OAuthClient.
		owned, err := controllerutil.HasOwnerReference(impersonation.OwnerReferences, &oauthClient, r.Scheme)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("checking owner reference: %w", err)
		}
		if !owned {
			if err := controllerutil.SetOwnerReference(&oauthClient, &impersonation, r.Scheme); err != nil {
				return ctrl.Result{}, fmt.Errorf("setting owner reference: %w", err)
			}
			if err := r.Update(ctx, &impersonation); err != nil {
				return ctrl.Result{}, fmt.Errorf("updating owner reference: %w", err)
			}
		}
		r.setReadyFromClient(&impersonation, &oauthClient)
	}

	if equality.Semantic.DeepEqual(before, &impersonation.Status) {
		return ctrl.Result{}, nil
	}
	if err := r.Status().Update(ctx, &impersonation); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
	}
	return ctrl.Result{}, nil
}

// setReadyFromClient sets Ready from the OAuthClient's last successful registration.
func (r *OAuthImpersonationReconciler) setReadyFromClient(impersonation *stsv1.OAuthImpersonation, oauthClient *stsv1.OAuthClient) {
	registered := oauthClient.Status.ObservedImpersonation
	isCurrent := registered != nil && registered.UID == impersonation.UID &&
		registered.Generation == impersonation.Generation
	clientFailed := meta.IsStatusConditionFalse(oauthClient.Status.Conditions, stsv1.ConditionReady)

	switch {
	case isCurrent:
		impersonation.Status.SynchronizationTimestamp = oauthClient.Status.SynchronizationTimestamp
		r.setReady(impersonation, metav1.ConditionTrue, stsv1.ReasonSucceeded, "Registered with OAuthClient")
	case clientFailed:
		r.setReady(impersonation, metav1.ConditionFalse, stsv1.ReasonFailed, "OAuthClient is not ready")
	default:
		r.setReady(impersonation, metav1.ConditionFalse, stsv1.ReasonPending, "Waiting for OAuthClient registration")
	}
}

func (r *OAuthImpersonationReconciler) setReady(impersonation *stsv1.OAuthImpersonation, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&impersonation.Status.Conditions, metav1.Condition{
		Type:               stsv1.ConditionReady,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: impersonation.GetGeneration(),
	})
}

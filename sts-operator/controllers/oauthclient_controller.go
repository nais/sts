package controllers

import (
	"context"
	"errors"
	"fmt"
	"time"

	stsv1 "github.com/nais/sts-operator/api/nais.io/v1"
	"github.com/nais/sts-operator/internal/config"
	"github.com/nais/sts-operator/internal/configmap"
	stsmetrics "github.com/nais/sts-operator/internal/metric"
	stsapi "github.com/nais/sts/api"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kevents "k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const (
	finalizer = "sts-operator.nais.io/finalizer"
)

// OAuthClientReconciler reconciles an OAuthClient object.
type OAuthClientReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder kevents.EventRecorder
	Config   *config.Config
	*stsapi.RegistrationClient
}

func NewOAuthClientReconciler(mgr ctrl.Manager, cfg *config.Config, registrator *stsapi.RegistrationClient) error {
	r := &OAuthClientReconciler{
		Client:             mgr.GetClient(),
		Config:             cfg,
		Recorder:           mgr.GetEventRecorder("sts-operator"),
		Scheme:             mgr.GetScheme(),
		RegistrationClient: registrator,
	}
	return r.SetupWithManager(mgr)
}

func (r *OAuthClientReconciler) SetupWithManager(mgr ctrl.Manager) error {
	opts := controller.Options{
		MaxConcurrentReconciles: r.Config.MaxConcurrentReconciles,
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&stsv1.OAuthClient{}).
		// An OAuthImpersonation adds impersonators to the OAuthClient with the same name.
		Watches(&stsv1.OAuthImpersonation{}, &handler.EnqueueRequestForObject{},
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		WithOptions(opts).
		Complete(r)
}

// +kubebuilder:rbac:groups=nais.io,resources=oauthclients,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=nais.io,resources=oauthclients/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=nais.io,resources=oauthclients/finalizers,verbs=update
// +kubebuilder:rbac:groups=nais.io,resources=oauthimpersonations,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=nais.io,resources=oauthimpersonations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="";events.k8s.io,resources=events,verbs=create;update;patch

func (r *OAuthClientReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx).WithName("reconciler")
	ctx = ctrl.LoggerInto(ctx, log)
	defer stsmetrics.OAuthClientsProcessedCount.Inc()

	var oauthClient stsv1.OAuthClient
	err := r.Get(ctx, req.NamespacedName, &oauthClient)
	if err != nil {
		// we ignore not found errors as cleanup should already be handled by the finalizer
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// object is marked for deletion
	if !oauthClient.DeletionTimestamp.IsZero() {
		if err := r.finalize(ctx, &oauthClient); err != nil {
			stsmetrics.OAuthClientsProcessingFailedCount.Inc()
			return ctrl.Result{}, fmt.Errorf("finalize: %w", err)
		}
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(&oauthClient, finalizer) {
		controllerutil.AddFinalizer(&oauthClient, finalizer)
		if err := r.Update(ctx, &oauthClient); err != nil {
			stsmetrics.OAuthClientsProcessingFailedCount.Inc()
			return ctrl.Result{}, fmt.Errorf("registering finalizer: %w", err)
		}
		return ctrl.Result{}, nil
	}

	impersonation, err := r.getImpersonation(ctx, req)
	if err != nil {
		stsmetrics.OAuthClientsProcessingFailedCount.Inc()
		return ctrl.Result{}, fmt.Errorf("getting impersonation: %w", err)
	}
	ref := impersonationRef(impersonation)

	condition := meta.FindStatusCondition(oauthClient.Status.Conditions, stsv1.ConditionReady)
	readyForGeneration := condition != nil && condition.Status == metav1.ConditionTrue &&
		condition.ObservedGeneration == oauthClient.GetGeneration()
	impersonationSynced := equality.Semantic.DeepEqual(ref, oauthClient.Status.ObservedImpersonation)
	lastSync := oauthClient.Status.SynchronizationTimestamp

	if readyForGeneration && impersonationSynced && lastSync != nil {
		if remaining := time.Until(lastSync.Add(r.Config.SyncInterval)); remaining > 0 {
			log.V(4).WithValues(
				".metadata.generation", oauthClient.GetGeneration(),
				"remaining", remaining,
			).Info("skipping reconciliation")
			return ctrl.Result{RequeueAfter: remaining}, nil
		}
	}

	if err := r.synchronize(ctx, req, &oauthClient, impersonation); err != nil {
		stsmetrics.OAuthClientsProcessingFailedCount.Inc()
		err = fmt.Errorf("synchronize: %w", err)
		if impersonationErr := r.updateImpersonation(ctx, &oauthClient, impersonation); impersonationErr != nil {
			err = errors.Join(err, fmt.Errorf("updating impersonation: %w", impersonationErr))
		}
		if statusErr := r.Status().Update(ctx, &oauthClient); statusErr != nil {
			err = errors.Join(err, fmt.Errorf("updating status: %w", statusErr))
		}
		return ctrl.Result{}, err
	}

	oauthClient.Status.SynchronizationTimestamp = new(metav1.Now())
	oauthClient.Status.ObservedImpersonation = ref
	ready(&oauthClient)

	// Update the impersonation first: a failure leaves the client status stale,
	// so the next reconcile retries instead of skipping.
	if err := r.updateImpersonation(ctx, &oauthClient, impersonation); err != nil {
		stsmetrics.OAuthClientsProcessingFailedCount.Inc()
		return ctrl.Result{}, fmt.Errorf("updating impersonation: %w", err)
	}

	if err := r.Status().Update(ctx, &oauthClient); err != nil {
		stsmetrics.OAuthClientsProcessingFailedCount.Inc()
		return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
	}

	log.Info("successfully reconciled")
	return ctrl.Result{RequeueAfter: r.Config.SyncInterval}, nil
}

// getImpersonation returns the OAuthImpersonation with the client's name, or nil
// if it does not exist or is being deleted.
func (r *OAuthClientReconciler) getImpersonation(ctx context.Context, req ctrl.Request) (*stsv1.OAuthImpersonation, error) {
	var impersonation stsv1.OAuthImpersonation
	if err := r.Get(ctx, req.NamespacedName, &impersonation); err != nil {
		return nil, client.IgnoreNotFound(err)
	}
	if !impersonation.DeletionTimestamp.IsZero() {
		return nil, nil
	}
	return &impersonation, nil
}

// impersonationRef identifies the impersonation's current version, or returns nil.
func impersonationRef(impersonation *stsv1.OAuthImpersonation) *stsv1.ObservedImpersonation {
	if impersonation == nil {
		return nil
	}
	return &stsv1.ObservedImpersonation{UID: impersonation.UID, Generation: impersonation.Generation}
}

// updateImpersonation makes the OAuthClient own the impersonation, so they are
// deleted together, and copies the client's Ready condition to it.
func (r *OAuthClientReconciler) updateImpersonation(ctx context.Context, oauthClient *stsv1.OAuthClient, impersonation *stsv1.OAuthImpersonation) error {
	if impersonation == nil {
		return nil
	}

	owned, err := controllerutil.HasOwnerReference(impersonation.OwnerReferences, oauthClient, r.Scheme)
	if err != nil {
		return fmt.Errorf("checking owner reference: %w", err)
	}
	if !owned {
		if err := controllerutil.SetOwnerReference(oauthClient, impersonation, r.Scheme); err != nil {
			return fmt.Errorf("setting owner reference: %w", err)
		}
		if err := r.Update(ctx, impersonation); err != nil {
			return fmt.Errorf("updating owner reference: %w", err)
		}
	}

	condition := *meta.FindStatusCondition(oauthClient.Status.Conditions, stsv1.ConditionReady)
	condition.ObservedGeneration = impersonation.GetGeneration()
	meta.SetStatusCondition(&impersonation.Status.Conditions, condition)
	if condition.Status == metav1.ConditionTrue {
		impersonation.Status.SynchronizationTimestamp = oauthClient.Status.SynchronizationTimestamp
	}
	if err := r.Status().Update(ctx, impersonation); err != nil {
		return fmt.Errorf("updating status: %w", err)
	}
	return nil
}

func (r *OAuthClientReconciler) synchronize(ctx context.Context, req ctrl.Request, oauthClient *stsv1.OAuthClient, impersonation *stsv1.OAuthImpersonation) error {
	log := ctrl.LoggerFrom(ctx).WithValues("subsystem", "synchronize")

	registration, err := r.Register(ctx, makeSoftwareStatement(oauthClient, impersonation))
	if err != nil {
		return failed(oauthClient, "Registration with STS failed", fmt.Errorf("registering client with STS: %w", err))
	}
	// Retain the registration ID even if ConfigMap reconciliation fails, so finalization can clean it up.
	oauthClient.Status.ClientID = registration.ClientID

	log.Info(fmt.Sprintf("registered %q with STS", registration.ClientID))

	cmName := oauthClient.Spec.ConfigMapName
	configMap := configmap.Spec(cmName, req.Namespace, configmap.ConfigMapData{
		AppName:  req.Name,
		ClientID: registration.ClientID,
		Issuer:   r.STSIssuer,
	})

	target := &corev1.ConfigMap{
		Name:      cmName,
		Namespace: req.Namespace,
	}
	res, err := controllerutil.CreateOrUpdate(ctx, r.Client, target, func() error {
		target.SetAnnotations(configMap.GetAnnotations())
		target.SetLabels(configMap.GetLabels())
		target.Data = configMap.Data

		return ctrl.SetControllerReference(oauthClient, target, r.Scheme)
	})
	if err != nil {
		return failed(oauthClient, fmt.Sprintf("ConfigMap %q could not be reconciled", cmName), fmt.Errorf("creating or updating config map %q: %w", cmName, err))
	}

	if res != controllerutil.OperationResultNone {
		log.Info(fmt.Sprintf("config map %q %s", cmName, res))
	}
	return nil
}

// finalize purges relevant resources from external systems (i.e. the STS instances)
func (r *OAuthClientReconciler) finalize(ctx context.Context, oauthClient *stsv1.OAuthClient) error {
	if !controllerutil.ContainsFinalizer(oauthClient, finalizer) {
		return nil
	}

	log := ctrl.LoggerFrom(ctx).WithValues("subsystem", "finalize")

	if clientID := oauthClient.Status.ClientID; clientID != "" {
		if err := r.RegistrationClient.Delete(ctx, clientID); err != nil {
			return fmt.Errorf("deleting %q from STS: %w", clientID, err)
		}
		log.Info(fmt.Sprintf("deleted %q from STS", clientID))
	}

	controllerutil.RemoveFinalizer(oauthClient, finalizer)
	if err := r.Update(ctx, oauthClient); err != nil {
		return fmt.Errorf("removing finalizer: %w", err)
	}

	stsmetrics.OAuthClientsFinalizedCount.Inc()
	return nil
}

func ready(oauthClient *stsv1.OAuthClient) {
	meta.SetStatusCondition(&oauthClient.Status.Conditions, metav1.Condition{
		Type:               stsv1.ConditionReady,
		Status:             metav1.ConditionTrue,
		Reason:             stsv1.ReasonSucceeded,
		Message:            "Registration and ConfigMap reconciled",
		ObservedGeneration: oauthClient.GetGeneration(),
	})
}

func failed(oauthClient *stsv1.OAuthClient, message string, err error) error {
	meta.SetStatusCondition(&oauthClient.Status.Conditions, metav1.Condition{
		Type:               stsv1.ConditionReady,
		Status:             metav1.ConditionFalse,
		Reason:             stsv1.ReasonFailed,
		Message:            message,
		ObservedGeneration: oauthClient.GetGeneration(),
	})
	return err
}

func makeSoftwareStatement(oauthClient *stsv1.OAuthClient, impersonation *stsv1.OAuthImpersonation) stsapi.SoftwareStatement {
	var clients []stsapi.AuthorizedClient
	var namespaces []string
	for _, acl := range oauthClient.Spec.AccessControlList {
		if acl.AllowAll {
			namespaces = append(namespaces, acl.Team)
		}
		for _, workload := range acl.Workloads {
			clients = append(clients, stsapi.AuthorizedClient{
				Client: stsapi.Client{Namespace: acl.Team, Name: workload.Name},
				Roles:  workload.Roles,
			})
		}
	}

	var impersonators []stsapi.ImpersonatorSubject
	if impersonation != nil {
		impersonators = impersonation.Spec.AllowedSubjects
	}

	return stsapi.SoftwareStatement{
		Client: stsapi.Client{Namespace: oauthClient.Namespace, Name: oauthClient.Name},
		AuthorizationPolicy: stsapi.AuthorizationPolicy{
			AllowAll:             oauthClient.Spec.AllowAll,
			AllowedNamespaces:    namespaces,
			Clients:              clients,
			AllowedImpersonators: impersonators,
		},
	}
}

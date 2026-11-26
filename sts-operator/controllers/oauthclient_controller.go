package controllers

import (
	"context"
	"errors"
	"fmt"
	"slices"

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
	"sigs.k8s.io/controller-runtime/pkg/event"
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
	// Ignore status-only updates so status writes don't trigger re-registration.
	// Finalizer changes pass because Reconcile relies on that event to start the
	// first sync; setting deletionTimestamp bumps generation.
	finalizersChanged := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			return !slices.Equal(e.ObjectOld.GetFinalizers(), e.ObjectNew.GetFinalizers())
		},
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&stsv1.OAuthClient{}, builder.WithPredicates(predicate.Or(predicate.GenerationChangedPredicate{}, finalizersChanged))).
		WithOptions(opts).
		Complete(r)
}

// +kubebuilder:rbac:groups=nais.io,resources=oauthclients,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=nais.io,resources=oauthclients/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=nais.io,resources=oauthclients/finalizers,verbs=update
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

	previousStatus := oauthClient.Status.DeepCopy()
	changed, err := r.synchronize(ctx, req, &oauthClient)
	if err != nil {
		stsmetrics.OAuthClientsProcessingFailedCount.Inc()
		err = fmt.Errorf("synchronize: %w", err)
		if statusErr := r.Status().Update(ctx, &oauthClient); statusErr != nil {
			err = errors.Join(err, fmt.Errorf("updating status: %w", statusErr))
		}
		return ctrl.Result{}, err
	}

	ready(&oauthClient)

	// Periodic syncs usually leave status unchanged; skipping the write avoids
	// API server churn for every client on each interval.
	statusChanged := !equality.Semantic.DeepEqual(previousStatus, &oauthClient.Status)
	if statusChanged {
		if err := r.Status().Update(ctx, &oauthClient); err != nil {
			stsmetrics.OAuthClientsProcessingFailedCount.Inc()
			return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
		}
	}

	if changed || statusChanged {
		log.Info("successfully reconciled")
	} else {
		log.V(1).Info("successfully reconciled without changes")
	}
	return ctrl.Result{RequeueAfter: r.Config.SyncInterval}, nil
}

// synchronize registers the client with STS and reconciles its ConfigMap. It
// reports whether either the registration or the ConfigMap changed.
func (r *OAuthClientReconciler) synchronize(ctx context.Context, req ctrl.Request, oauthClient *stsv1.OAuthClient) (bool, error) {
	log := ctrl.LoggerFrom(ctx).WithValues("subsystem", "synchronize")

	registration, err := r.Register(ctx, makeSoftwareStatement(oauthClient))
	if err != nil {
		return false, failed(oauthClient, "Registration with STS failed", fmt.Errorf("registering client with STS: %w", err))
	}
	// Retain the registration ID even if ConfigMap reconciliation fails, so finalization can clean it up.
	oauthClient.Status.ClientID = registration.ClientID

	if registration.Changed {
		log.Info(fmt.Sprintf("registered %q with STS", registration.ClientID))
	} else {
		log.V(1).Info(fmt.Sprintf("registration %q unchanged in STS", registration.ClientID))
	}

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
		return registration.Changed, failed(oauthClient, fmt.Sprintf("ConfigMap %q could not be reconciled", cmName), fmt.Errorf("creating or updating config map %q: %w", cmName, err))
	}

	configMapChanged := res != controllerutil.OperationResultNone
	if configMapChanged {
		log.Info(fmt.Sprintf("config map %q %s", cmName, res))
	}
	return registration.Changed || configMapChanged, nil
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

func makeSoftwareStatement(oauthClient *stsv1.OAuthClient) stsapi.SoftwareStatement {
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

	return stsapi.SoftwareStatement{
		Client: stsapi.Client{Namespace: oauthClient.Namespace, Name: oauthClient.Name},
		AuthorizationPolicy: stsapi.AuthorizationPolicy{
			AllowAll:          oauthClient.Spec.AllowAll,
			AllowedNamespaces: namespaces,
			Clients:           clients,
		},
	}
}

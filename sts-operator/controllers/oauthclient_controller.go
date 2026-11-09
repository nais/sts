package controllers

import (
	"context"
	"fmt"
	"time"

	stsv1 "github.com/nais/sts-operator/api/nais.io/v1"
	"github.com/nais/sts-operator/internal/config"
	"github.com/nais/sts-operator/internal/configmap"
	stsmetrics "github.com/nais/sts-operator/internal/metric"
	stsapi "github.com/nais/sts/api"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kevents "k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
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
		clientID := oauthClient.Status.ClientID
		// Registration may have succeeded before its status update failed. It is ok if the client is not removed from STS
		// in this edge case, as the OAuthClient will be re-registered on the next reconciliation.
		if clientID != "" {
			if err := r.finalize(ctx, clientID, &oauthClient); err != nil {
				stsmetrics.OAuthClientsProcessingFailedCount.Inc()
				return ctrl.Result{}, fmt.Errorf("finalize: %w", err)
			}
		}
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(&oauthClient, finalizer) {
		if err := r.updateOAuthClient(ctx, oauthClient, func(existing *stsv1.OAuthClient) error {
			controllerutil.AddFinalizer(existing, finalizer)
			return r.Update(ctx, existing)
		}); err != nil {
			return ctrl.Result{}, fmt.Errorf("registering finalizer: %w", err)
		}
		return ctrl.Result{}, nil
	}

	specUnchanged := oauthClient.GetGeneration() == oauthClient.Status.ObservedGeneration
	remaining := time.Until(oauthClient.Status.SynchronizationTimestamp.Add(r.Config.SyncInterval))

	if specUnchanged && remaining > 0 {
		log.V(4).WithValues(
			".metadata.generation", oauthClient.GetGeneration(),
			".status.observedGeneration", oauthClient.Status.ObservedGeneration,
			"remaining", remaining,
		).Info("skipping reconciliation")
		return ctrl.Result{RequeueAfter: remaining}, nil
	}

	clientID, err := r.synchronize(ctx, req, oauthClient)
	if err != nil {
		stsmetrics.OAuthClientsProcessingFailedCount.Inc()
		return ctrl.Result{}, fmt.Errorf("synchronize: %w", err)
	}

	oauthClient.Status.SynchronizationTimestamp = metav1.Now()
	oauthClient.Status.ObservedGeneration = oauthClient.GetGeneration()
	oauthClient.Status.ClientID = clientID

	if err := r.updateOAuthClient(ctx, oauthClient, func(existing *stsv1.OAuthClient) error {
		existing.Status = oauthClient.Status
		return r.Status().Update(ctx, existing)
	}); err != nil {
		stsmetrics.OAuthClientsProcessingFailedCount.Inc()
		return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
	}

	log.Info("successfully reconciled")
	return ctrl.Result{RequeueAfter: r.Config.SyncInterval}, nil
}

func (r *OAuthClientReconciler) synchronize(ctx context.Context, req ctrl.Request, oauthClient stsv1.OAuthClient) (string, error) {
	log := ctrl.LoggerFrom(ctx).WithValues("subsystem", "synchronize")

	registration, err := r.Register(ctx, makeSoftwareStatement(oauthClient))
	if err != nil {
		return "", fmt.Errorf("registering client with STS: %w", err)
	}
	clientID := registration.ClientID

	log.Info(fmt.Sprintf("registered %q with STS", clientID))

	cmName := oauthClient.Spec.ConfigMapName
	configMap := configmap.CreateConfigMapSpec(cmName, req.Namespace, configmap.ConfigMapData{
		AppName:  req.Name,
		ClientID: clientID,
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

		return ctrl.SetControllerReference(&oauthClient, target, r.Scheme)
	})
	if err != nil {
		return "", fmt.Errorf("creating or updating config map %s: %w", cmName, err)
	}

	if res != controllerutil.OperationResultNone {
		log.Info(fmt.Sprintf("config map %q %s", cmName, res))
	}
	return clientID, nil
}

// finalize purges relevant resources from external systems (i.e. the STS instances)
func (r *OAuthClientReconciler) finalize(ctx context.Context, clientId string, oauthClient *stsv1.OAuthClient) error {
	if !controllerutil.ContainsFinalizer(oauthClient, finalizer) {
		return nil
	}

	log := ctrl.LoggerFrom(ctx).WithValues("subsystem", "finalize")

	if err := r.RegistrationClient.Delete(ctx, clientId); err != nil {
		return err
	}
	log.Info(fmt.Sprintf("deleted %q from STS", clientId))

	controllerutil.RemoveFinalizer(oauthClient, finalizer)
	if err := r.Update(ctx, oauthClient); err != nil {
		return fmt.Errorf("removing finalizer: %w", err)
	}

	stsmetrics.OAuthClientsFinalizedCount.Inc()
	return nil
}

func (r *OAuthClientReconciler) updateOAuthClient(ctx context.Context, oauthClient stsv1.OAuthClient, updateFunc func(existing *stsv1.OAuthClient) error) error {
	existing := &stsv1.OAuthClient{}
	err := r.Get(ctx, client.ObjectKey{Namespace: oauthClient.GetNamespace(), Name: oauthClient.GetName()}, existing)
	if err != nil {
		return fmt.Errorf("get newest version of OAuthClient: %s", err)
	}

	return updateFunc(existing)
}

func makeSoftwareStatement(oauthClient stsv1.OAuthClient) stsapi.SoftwareStatement {
	var policies []stsapi.AuthorizationPolicy
	for _, acl := range oauthClient.Spec.AccessControlList {
		for _, workload := range acl.Workloads {
			policies = append(policies, stsapi.AuthorizationPolicy{
				Consumer: stsapi.Client{Namespace: acl.Team, Name: workload.Name},
				Roles:    workload.Roles,
			})
		}
	}

	return stsapi.SoftwareStatement{
		Client:                stsapi.Client{Namespace: oauthClient.Namespace, Name: oauthClient.Name},
		AuthorizationPolicies: policies,
	}
}

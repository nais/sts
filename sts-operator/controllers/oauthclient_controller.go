package controllers

import (
	"context"
	"fmt"

	stsv1 "github.com/nais/sts-operator/api/nais.io/v1"
	"github.com/nais/sts-operator/internal/config"
	"github.com/nais/sts-operator/internal/configmap"
	stsmetrics "github.com/nais/sts-operator/internal/metric"
	stsapi "github.com/nais/sts/api"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	kevents "k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	finalizer = "sts-operator.nais.io/finalizer"
)

// CacheOptions limits the ConfigMap informer to ConfigMaps managed by this
// operator, instead of caching every ConfigMap in the cluster.
func CacheOptions() cache.Options {
	return cache.Options{
		ByObject: map[client.Object]cache.ByObject{
			&corev1.ConfigMap{}: {
				Label: labels.SelectorFromSet(labels.Set{configmap.ManagedByLabelKey: configmap.ManagedByLabelValue}),
			},
		},
	}
}

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

	var stsClient stsv1.OAuthClient
	err := r.Get(ctx, req.NamespacedName, &stsClient)
	if err != nil {
		// we ignore not found errors as cleanup should already be handled by the finalizer
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// object is marked for deletion
	if !stsClient.DeletionTimestamp.IsZero() {
		clientID := stsClient.Status.ClientID
		// Registration may have succeeded before its status update failed. It is ok if the client is not removed from STS
		// in this edge case, as the OAuthClient will be re-registered on the next reconciliation.
		if clientID != "" {
			if err := r.finalize(ctx, clientID, &stsClient); err != nil {
				stsmetrics.OAuthClientsProcessingFailedCount.Inc()
				return ctrl.Result{}, fmt.Errorf("finalize: %w", err)
			}
		}
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(&stsClient, finalizer) {
		if err := r.updateOAuthClient(ctx, stsClient, func(existing *stsv1.OAuthClient) error {
			controllerutil.AddFinalizer(existing, finalizer)
			return r.Update(ctx, existing)
		}); err != nil {
			return ctrl.Result{}, fmt.Errorf("registering finalizer: %w", err)
		}
		return ctrl.Result{}, nil
	}

	if stsClient.GetGeneration() == stsClient.Status.ObservedGeneration {
		log.V(4).WithValues(
			".metadata.generation", stsClient.GetGeneration(),
			".status.observedGeneration", stsClient.Status.ObservedGeneration,
		).Info("generation is unchanged; skipping reconciliation")
		return ctrl.Result{}, nil
	}

	// update status subresource at the end of reconciliation, regardless of success or failure
	defer func() {
		stsClient.Status.SynchronizationTimestamp = metav1.Now()

		if err := r.updateOAuthClient(ctx, stsClient, func(existing *stsv1.OAuthClient) error {
			existing.Status = stsClient.Status
			return r.Status().Update(ctx, existing)
		}); err != nil {
			log.Error(err, "failed to update status subresource")
			return
		}
	}()

	err = r.prepare(ctx, req, stsClient)
	if err != nil {
		stsmetrics.OAuthClientsProcessingFailedCount.Inc()
		return ctrl.Result{}, fmt.Errorf("prepare: %w", err)
	}

	clientID, err := r.synchronize(ctx, req, stsClient)
	if err != nil {
		stsmetrics.OAuthClientsProcessingFailedCount.Inc()
		return ctrl.Result{}, fmt.Errorf("synchronize: %w", err)
	}

	stsClient.Status.ObservedGeneration = stsClient.GetGeneration()
	stsClient.Status.ClientID = clientID

	log.Info("successfully reconciled")
	return ctrl.Result{}, nil
}

// TODO: determine if need to resync config map etc
func (r *OAuthClientReconciler) prepare(ctx context.Context, _ ctrl.Request, _ stsv1.OAuthClient) error {
	_ = ctrl.LoggerFrom(ctx).WithValues("subsystem", "prepare")
	return nil
}

func (r *OAuthClientReconciler) synchronize(ctx context.Context, req ctrl.Request, stsClient stsv1.OAuthClient) (string, error) {
	log := ctrl.LoggerFrom(ctx).WithValues("subsystem", "synchronize")

	registration, err := r.Register(ctx, makeSoftwareStatement(stsClient))
	if err != nil {
		return "", fmt.Errorf("registering client with STS: %w", err)
	}
	clientID := registration.ClientID

	log.Info(fmt.Sprintf("registered %q with STS", clientID))

	cmName := stsClient.Spec.ConfigMapName
	configMap, err := configmap.CreateConfigMapSpec(cmName, req.Namespace, configmap.ConfigMapData{
		AppName:  req.Name,
		ClientID: clientID,
		Issuer:   r.STSIssuer,
	})
	if err != nil {
		return "", fmt.Errorf("creating config map spec: %w", err)
	}

	target := &corev1.ConfigMap{
		Name:      cmName,
		Namespace: req.Namespace,
	}
	res, err := controllerutil.CreateOrUpdate(ctx, r.Client, target, func() error {
		target.SetAnnotations(configMap.GetAnnotations())
		target.SetLabels(configMap.GetLabels())
		target.Data = configMap.Data

		return ctrl.SetControllerReference(&stsClient, target, r.Scheme)
	})
	if err != nil {
		return "", fmt.Errorf("creating or updating config map %s: %w", cmName, err)
	}

	log.Info(fmt.Sprintf("config map %q %s", cmName, res))
	return clientID, nil
}

// finalize purges relevant resources from external systems (i.e. the STS instances)
func (r *OAuthClientReconciler) finalize(ctx context.Context, clientId string, stsClient *stsv1.OAuthClient) error {
	if !controllerutil.ContainsFinalizer(stsClient, finalizer) {
		return nil
	}

	log := ctrl.LoggerFrom(ctx).WithValues("subsystem", "finalize")

	if err := r.RegistrationClient.Delete(ctx, clientId); err != nil {
		return err
	}
	log.Info(fmt.Sprintf("deleted %q from STS", clientId))

	controllerutil.RemoveFinalizer(stsClient, finalizer)
	if err := r.Update(ctx, stsClient); err != nil {
		return fmt.Errorf("removing finalizer: %w", err)
	}

	stsmetrics.OAuthClientsFinalizedCount.Inc()
	return nil
}

func (r *OAuthClientReconciler) updateOAuthClient(ctx context.Context, stsClient stsv1.OAuthClient, updateFunc func(existing *stsv1.OAuthClient) error) error {
	existing := &stsv1.OAuthClient{}
	err := r.Get(ctx, client.ObjectKey{Namespace: stsClient.GetNamespace(), Name: stsClient.GetName()}, existing)
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

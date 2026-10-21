package controllers

import (
	"context"
	"fmt"

	stsv1 "github.com/nais/sts-operator/api/nais.io/v1"
	"github.com/nais/sts-operator/internal/config"
	"github.com/nais/sts-operator/internal/configmap"
	stsmetrics "github.com/nais/sts-operator/internal/metric"
	"github.com/nais/sts-operator/internal/sts"
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

// STSClientReconciler reconciles an STSClient object.
type STSClientReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder kevents.EventRecorder
	Config   *config.Config
	*sts.Registrator
}

func NewSTSClientReconciler(ctx context.Context, mgr ctrl.Manager, cfg *config.Config) error {
	registrator, err := sts.NewRegistrator(ctx, cfg)
	if err != nil {
		return fmt.Errorf("create STS registrator: %w", err)
	}
	r := &STSClientReconciler{
		Client:      mgr.GetClient(),
		Config:      cfg,
		Recorder:    mgr.GetEventRecorder("sts-operator"),
		Scheme:      mgr.GetScheme(),
		Registrator: registrator,
	}
	if err := r.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("create controller: %w", err)
	}
	return nil
}

func (r *STSClientReconciler) SetupWithManager(mgr ctrl.Manager) error {
	opts := controller.Options{
		MaxConcurrentReconciles: r.Config.MaxConcurrentReconciles,
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&stsv1.STSClient{}).
		WithOptions(opts).
		Complete(r)
}

// +kubebuilder:rbac:groups=nais.io,resources=stsclients,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=nais.io,resources=stsclients/status,verbs=get;update;patch

func (r *STSClientReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx).WithName("reconciler")
	ctx = ctrl.LoggerInto(ctx, log)
	defer stsmetrics.STSClientsProcessedCount.Inc()

	var stsClient stsv1.STSClient
	err := r.Get(ctx, req.NamespacedName, &stsClient)
	if err != nil {
		// we ignore not found errors as cleanup should already be handled by the finalizer
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// object is marked for deletion
	if !stsClient.DeletionTimestamp.IsZero() {
		clientID := stsClient.Status.ClientID
		if clientID == "" {
			// Registration may have succeeded before its status update failed.
			clientID = r.clientID(req)
		}
		if err := r.finalize(ctx, clientID, &stsClient); err != nil {
			stsmetrics.STSClientsProcessingFailedCount.Inc()
			return ctrl.Result{}, fmt.Errorf("finalize: %w", err)
		}
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(&stsClient, finalizer) {
		if err := r.updateSTSClient(ctx, stsClient, func(existing *stsv1.STSClient) error {
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

		if err := r.updateSTSClient(ctx, stsClient, func(existing *stsv1.STSClient) error {
			existing.Status = stsClient.Status
			return r.Status().Update(ctx, existing)
		}); err != nil {
			log.Error(err, "failed to update status subresource")
			return
		}
	}()

	err = r.prepare(ctx, req, stsClient)
	if err != nil {
		stsmetrics.STSClientsProcessingFailedCount.Inc()
		return ctrl.Result{}, fmt.Errorf("prepare: %w", err)
	}

	clientID, err := r.synchronize(ctx, req, stsClient)
	if err != nil {
		stsmetrics.STSClientsProcessingFailedCount.Inc()
		return ctrl.Result{}, fmt.Errorf("synchronize: %w", err)
	}

	stsClient.Status.ObservedGeneration = stsClient.GetGeneration()
	stsClient.Status.ClientID = clientID

	log.Info("successfully reconciled")
	return ctrl.Result{}, nil
}

// TODO: determine if need to resync config map etc
func (r *STSClientReconciler) prepare(ctx context.Context, _ ctrl.Request, _ stsv1.STSClient) error {
	_ = ctrl.LoggerFrom(ctx).WithValues("subsystem", "prepare")
	return nil
}

func (r *STSClientReconciler) synchronize(ctx context.Context, req ctrl.Request, stsClient stsv1.STSClient) (string, error) {
	log := ctrl.LoggerFrom(ctx).WithValues("subsystem", "synchronize")

	statement := r.MakeSoftwareStatement(stsClient)
	registration, err := r.Register(ctx, statement)
	if err != nil {
		return "", fmt.Errorf("registering client with STS: %w", err)
	}
	clientID := registration.ClientID

	log.Info(fmt.Sprintf("registered %q with STS", clientID))

	// TODO: set name properly, get from CRD
	cmName := "sts-" + req.Name
	// TODO: go over params here
	configMap, err := configmap.CreateConfigMapSpec(cmName, req.Namespace, r.WellKnownURL, r.Metadata, req.Name, clientID)
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
func (r *STSClientReconciler) finalize(ctx context.Context, clientId string, stsClient *stsv1.STSClient) error {
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

	stsmetrics.STSClientsFinalizedCount.Inc()
	return nil
}

func (r *STSClientReconciler) updateSTSClient(ctx context.Context, stsClient stsv1.STSClient, updateFunc func(existing *stsv1.STSClient) error) error {
	existing := &stsv1.STSClient{}
	err := r.Get(ctx, client.ObjectKey{Namespace: stsClient.GetNamespace(), Name: stsClient.GetName()}, existing)
	if err != nil {
		return fmt.Errorf("get newest version of STSClient: %s", err)
	}

	return updateFunc(existing)
}

// TODO: move this and consolidate client id generation/usage
func (r *STSClientReconciler) clientID(req ctrl.Request) string {
	return fmt.Sprintf("%s:%s:%s", r.ClusterName, req.Namespace, req.Name)
}

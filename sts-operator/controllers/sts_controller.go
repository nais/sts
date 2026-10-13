package controllers

import (
	"context"
	"fmt"

	libernetes "github.com/nais/liberator/pkg/kubernetes"
	stsv1 "github.com/nais/sts-operator/api/nais.io/v1"
	"github.com/nais/sts-operator/internal/config"
	"github.com/nais/sts-operator/internal/configmap"
	"github.com/nais/sts-operator/internal/jwk"
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
	Reader   client.Reader
	Recorder kevents.EventRecorder
	Config   *config.Config
}

type transaction struct {
	ctx         context.Context
	req         ctrl.Request
	jwks        jwk.KeySet
	secretLists libernetes.SecretLists
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
	if !stsClient.ObjectMeta.DeletionTimestamp.IsZero() {
		if err := r.finalize(ctx, r.clientID(req), &stsClient); err != nil {
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

	err = r.synchronize(ctx, req, stsClient)
	if err != nil {
		stsmetrics.STSClientsProcessingFailedCount.Inc()
		return ctrl.Result{}, fmt.Errorf("synchronize: %w", err)
	}

	stsClient.Status.ObservedGeneration = stsClient.GetGeneration()
	stsClient.Status.ClientID = r.clientID(req).String()

	log.Info("successfully reconciled")
	return ctrl.Result{}, nil
}

// TODO: determine if need to resync config map etc
func (r *STSClientReconciler) prepare(ctx context.Context, req ctrl.Request, stsClient stsv1.STSClient) error {
	_ = ctrl.LoggerFrom(ctx).WithValues("subsystem", "prepare")
	return nil
}

func (r *STSClientReconciler) synchronize(ctx context.Context, req ctrl.Request, stsClient stsv1.STSClient) error {
	clientID := r.clientID(req)
	log := ctrl.LoggerFrom(ctx).WithValues("subsystem", "synchronize")

	registration, err := sts.MakeClientRegistration(r.Config.ClientJwk, clientID, stsClient)
	if err != nil {
		return fmt.Errorf("create client registration payload: %s", err)
	}

	instances := r.Config.STSInstances
	for _, instance := range instances {
		if err := instance.RegisterClient(registration); err != nil {
			return fmt.Errorf("registering client with STS %q: %w", instance.BaseURL, err)
		}
		log.Info(fmt.Sprintf("registered %q with STS at %q", clientID.String(), instance.BaseURL))
	}

	// TODO: set name properly
	cmName := "sts-" + req.Name
	cmData := configmap.Data{ClientID: clientID, STS: instances[0]}
	configMap, err := configmap.CreateConfigMapSpec(cmName, cmData)
	if err != nil {
		return fmt.Errorf("creating config map spec: %w", err)
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
		return fmt.Errorf("creating or updating config map %s: %w", cmName, err)
	}

	log.Info(fmt.Sprintf("config map %q %s", cmName, res))
	return nil
}

// finalize purges relevant resources from external systems (i.e. the STS instances)
func (r *STSClientReconciler) finalize(ctx context.Context, clientId sts.ClientID, stsClient *stsv1.STSClient) error {
	if !controllerutil.ContainsFinalizer(stsClient, finalizer) {
		return nil
	}

	log := ctrl.LoggerFrom(ctx).WithValues("subsystem", "finalize")

	for _, instance := range r.Config.STSInstances {
		if err := instance.DeleteClient(ctx, clientId); err != nil {
			return fmt.Errorf("deleting client from STS at %q: %w", instance.BaseURL, err)
		}
		log.Info(fmt.Sprintf("deleted %q from STS at %q", clientId.String(), instance.BaseURL))
	}

	controllerutil.RemoveFinalizer(stsClient, finalizer)
	if err := r.Client.Update(ctx, stsClient); err != nil {
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

func (r *STSClientReconciler) clientID(req ctrl.Request) sts.ClientID {
	return sts.ClientID{
		Name:      req.Name,
		Namespace: req.Namespace,
		Cluster:   r.Config.ClusterName,
	}
}

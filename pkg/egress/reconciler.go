package egress

import (
	"context"

	v1alpha1 "github.com/moolen/skouter/api"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type Reconciler struct {
	client.Client
	log          *logrus.Logger
	scheme       *runtime.Scheme
	recorder     record.EventRecorder
	updateTicker chan struct{}
}

func NewReconciler(cl client.Client, log *logrus.Logger, scheme *runtime.Scheme, updateTicker chan struct{}) *Reconciler {
	return &Reconciler{
		Client:       cl,
		log:          log,
		scheme:       scheme,
		updateTicker: updateTicker,
	}
}

func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	var egress v1alpha1.Egress
	r.log.Infof("reconciling %s", req.NamespacedName.String())
	err := r.Get(ctx, req.NamespacedName, &egress)
	if apierrors.IsNotFound(err) {
		r.updateTicker <- struct{}{}
		r.log.Debugf("egress resource removal reconciled")
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, nil
	}

	r.log.Debugf("egress resource reconciled")

	r.updateTicker <- struct{}{}
	// TODO: update status

	return reconcile.Result{}, nil
}

// SetupWithManager returns a new controller builder that will be started by the provided Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	r.recorder = mgr.GetEventRecorderFor("external-secrets")

	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(opts).
		For(&v1alpha1.Egress{}).
		Complete(r)
}

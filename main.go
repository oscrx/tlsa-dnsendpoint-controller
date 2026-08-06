// Command tlsa-dnsendpoint-controller publishes TLSA (DANE) records for
// cert-manager Certificates by writing external-dns DNSEndpoint resources.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	edv1alpha1 "github.com/oscrx/tlsa-dnsendpoint-controller/internal/apis/externaldns/v1alpha1"
	"github.com/oscrx/tlsa-dnsendpoint-controller/internal/controller"
	"github.com/oscrx/tlsa-dnsendpoint-controller/internal/tlsa"
)

var scheme = runtime.NewScheme()

func init() {
	must(clientgoscheme.AddToScheme(scheme))
	must(cmapi.AddToScheme(scheme))
	must(edv1alpha1.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddr      string
		probeAddr        string
		leaderElection   bool
		leaderElectionNS string
		annotationPrefix string
		rolloverGrace    time.Duration
		resyncPeriod     time.Duration
		watchNamespaces  string
	)

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080",
		"Address the metrics endpoint binds to; set to 0 to disable.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081",
		"Address the health probe endpoint binds to.")
	flag.BoolVar(&leaderElection, "leader-elect", false,
		"Enable leader election, for running more than one replica.")
	flag.StringVar(&leaderElectionNS, "leader-election-namespace", "",
		"Namespace holding the leader election lease. Defaults to the pod's namespace.")
	flag.StringVar(&annotationPrefix, "annotation-prefix", tlsa.DefaultAnnotationPrefix,
		"Domain prefix for the annotations read from Certificates.")
	flag.DurationVar(&rolloverGrace, "rollover-grace", 168*time.Hour,
		"How long a superseded TLSA record stays published after it stops matching the current certificate. "+
			"Extra TLSA records do not break DANE validation, but removing one while a server still presents the old "+
			"certificate does, so this errs long. Shorten it only if your workloads reload certificates promptly.")
	flag.DurationVar(&resyncPeriod, "resync-period", time.Hour,
		"Interval at which all Certificates are reconciled even without a watch event.")
	flag.StringVar(&watchNamespaces, "namespace", "",
		"Restrict the controller to a single namespace. Empty means all namespaces.")

	var providerSpecific keyValueFlag
	flag.Var(&providerSpecific, "provider-specific",
		"key=value passed through to the external-dns provider on every emitted record. Repeatable. "+
			"On Cloudflare, set external-dns.kubernetes.io/cloudflare-proxied=false if external-dns runs with "+
			"--cloudflare-proxied, since TLSA records cannot be proxied.")

	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	log := ctrl.Log.WithName("setup")

	cacheOpts := cache.Options{SyncPeriod: &resyncPeriod}
	if watchNamespaces != "" {
		cacheOpts.DefaultNamespaces = map[string]cache.Config{watchNamespaces: {}}
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                        scheme,
		Metrics:                       metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress:        probeAddr,
		LeaderElection:                leaderElection,
		LeaderElectionID:              "tlsa-dnsendpoint-controller.oscarr.nl",
		LeaderElectionNamespace:       leaderElectionNS,
		LeaderElectionReleaseOnCancel: true,
		Cache:                         cacheOpts,
		Client: client.Options{
			Cache: &client.CacheOptions{
				// Read Secrets straight from the API server. The alternative is
				// an informer holding every Secret in the cluster in memory.
				DisableFor: []client.Object{&corev1.Secret{}},
			},
		},
	})
	if err != nil {
		fatal(log, err, "unable to create manager")
	}

	reconciler := &controller.CertificateReconciler{
		Client:           mgr.GetClient(),
		SecretReader:     mgr.GetAPIReader(),
		Scheme:           mgr.GetScheme(),
		Recorder:         mgr.GetEventRecorder("tlsa-dnsendpoint-controller"),
		AnnotationPrefix: annotationPrefix,
		RolloverGrace:    rolloverGrace,
		ProviderSpecific: providerSpecific.properties(),
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		fatal(log, err, "unable to set up certificate controller")
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		fatal(log, err, "unable to set up health check")
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		fatal(log, err, "unable to set up ready check")
	}

	log.Info("starting controller",
		"annotationPrefix", annotationPrefix,
		"rolloverGrace", rolloverGrace.String(),
		"resyncPeriod", resyncPeriod.String())
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		fatal(log, err, "manager exited with error")
	}
}

// keyValueFlag collects repeated key=value flag values in order.
type keyValueFlag []edv1alpha1.ProviderSpecificProperty

func (f *keyValueFlag) String() string {
	parts := make([]string, 0, len(*f))
	for _, p := range *f {
		parts = append(parts, p.Name+"="+p.Value)
	}
	return strings.Join(parts, ",")
}

func (f *keyValueFlag) Set(v string) error {
	name, value, found := strings.Cut(v, "=")
	if !found || name == "" {
		return fmt.Errorf("want key=value, got %q", v)
	}
	*f = append(*f, edv1alpha1.ProviderSpecificProperty{Name: name, Value: value})
	return nil
}

func (f *keyValueFlag) properties() []edv1alpha1.ProviderSpecificProperty {
	return []edv1alpha1.ProviderSpecificProperty(*f)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func fatal(log logr.Logger, err error, msg string) {
	log.Error(err, msg)
	os.Exit(1)
}

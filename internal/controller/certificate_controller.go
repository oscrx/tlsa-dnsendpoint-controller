// Package controller reconciles cert-manager Certificates into external-dns
// DNSEndpoint resources carrying TLSA records.
package controller

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	edv1alpha1 "github.com/oscrx/tlsa-dnsendpoint-controller/internal/apis/externaldns/v1alpha1"
	"github.com/oscrx/tlsa-dnsendpoint-controller/internal/tlsa"
)

const (
	// dnsEndpointSuffix is appended to the Certificate name to form the
	// DNSEndpoint name.
	dnsEndpointSuffix = "-tlsa"

	// recordType is the DNS record type we manage.
	recordType = "TLSA"

	// retiredAnnotation (suffixed onto the configured prefix) records the rdata
	// we are keeping published past its useful life, and when each entry may be
	// dropped. Stored on the DNSEndpoint rather than the Certificate so that we
	// never write to a resource cert-manager owns.
	retiredAnnotation = "retired"
)

// CertificateReconciler publishes TLSA records for opted-in Certificates.
type CertificateReconciler struct {
	client.Client

	// SecretReader reads Secrets directly from the API server. Secrets are
	// deliberately excluded from the manager cache: caching every Secret in the
	// cluster to read one key out of a handful of them is a poor trade, and it
	// would mean holding all of the cluster's secret material in memory.
	SecretReader client.Reader

	Scheme   *runtime.Scheme
	Recorder events.EventRecorder

	// AnnotationPrefix is the domain prefix for the annotations we read.
	AnnotationPrefix string

	// RolloverGrace is how long a superseded rdata value stays published after
	// it stops matching the current certificate. See the package README for the
	// reasoning; the short version is that we cannot observe when the serving
	// process actually stops presenting the old certificate, so we keep the old
	// record for a while. Extra TLSA records are harmless to DANE validation
	// (any matching record authenticates), whereas removing one too early
	// breaks it.
	RolloverGrace time.Duration

	// ProviderSpecific is copied onto every endpoint we emit. external-dns
	// passes these through to the provider, which is how per-provider quirks are
	// configured. The Cloudflare provider in particular does not know that TLSA
	// records cannot be proxied, so when external-dns runs with
	// --cloudflare-proxied it will try to create them with proxied=true and
	// Cloudflare will reject the change; setting cloudflare-proxied=false here
	// avoids that. Kept generic rather than Cloudflare-specific because the
	// annotation key depends on external-dns's own --annotation-prefix.
	ProviderSpecific []edv1alpha1.ProviderSpecificProperty

	// Clock is overridable in tests.
	Clock func() time.Time
}

func (r *CertificateReconciler) now() time.Time {
	if r.Clock != nil {
		return r.Clock()
	}
	return time.Now()
}

// +kubebuilder:rbac:groups=cert-manager.io,resources=certificates,verbs=get;list;watch
// +kubebuilder:rbac:groups=externaldns.k8s.io,resources=dnsendpoints,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get
// +kubebuilder:rbac:groups="";events.k8s.io,resources=events,verbs=create;patch

// Reconcile brings the DNSEndpoint for a Certificate in line with the
// Certificate's current (and imminent) key material.
func (r *CertificateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var cert cmapi.Certificate
	if err := r.Get(ctx, req.NamespacedName, &cert); err != nil {
		if apierrors.IsNotFound(err) {
			// The DNSEndpoint carries an owner reference to the Certificate, so
			// Kubernetes garbage collection removes it for us. That is the whole
			// reason this controller does not need a finalizer, and why deleting
			// a Certificate can never block on DNS being reachable.
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	cfg, err := tlsa.ParseConfig(cert.Annotations, r.AnnotationPrefix)
	switch {
	case errors.Is(err, tlsa.ErrNotEnabled):
		if tlsa.HasAnyAnnotation(cert.Annotations, r.AnnotationPrefix) {
			r.Recorder.Eventf(&cert, nil, corev1.EventTypeWarning, "TLSAConfigIgnored", "Validate",
				"TLSA annotations are present but %s/%s is not true; no records will be published",
				r.AnnotationPrefix, tlsa.AnnotationEnabled)
		}
		// Opting out should withdraw the records, not orphan them.
		return ctrl.Result{}, r.deleteDNSEndpoint(ctx, &cert)
	case err != nil:
		// A malformed annotation is a user error; retrying cannot fix it, and the
		// next annotation edit triggers a fresh reconcile.
		log.Error(err, "invalid TLSA configuration")
		r.Recorder.Eventf(&cert, nil, corev1.EventTypeWarning, "TLSAConfigInvalid", "Validate", "%s", err.Error())
		return ctrl.Result{}, nil
	}

	names, skipped := recordBaseNames(&cert, cfg)
	if len(skipped) > 0 {
		r.Recorder.Eventf(&cert, nil, corev1.EventTypeWarning, "TLSANameSkipped", "Publish",
			"Skipping wildcard DNS name(s) %s: DANE clients look up TLSA records under the concrete name they connected to, so a wildcard owner name would never be queried",
			strings.Join(skipped, ", "))
	}
	if len(names) == 0 {
		r.Recorder.Eventf(&cert, nil, corev1.EventTypeWarning, "TLSANoNames", "Publish",
			"No usable DNS names for TLSA records")
		return ctrl.Result{}, r.deleteDNSEndpoint(ctx, &cert)
	}

	live, prepublish, err := r.rdataFor(ctx, &cert, cfg)
	if err != nil {
		log.V(1).Info("cannot compute TLSA record data yet", "reason", err.Error())
		r.Recorder.Eventf(&cert, nil, corev1.EventTypeWarning, "TLSADataUnavailable", "Compute", "%s", err.Error())
		// Nothing to publish yet, but do not tear down records that are already
		// out there: a transient read failure must not withdraw a valid record.
		return ctrl.Result{}, nil
	}

	desired := []string{}
	if live != "" {
		desired = append(desired, live)
	}
	if prepublish != "" && prepublish != live {
		desired = append(desired, prepublish)
	}
	if len(desired) == 0 {
		return ctrl.Result{}, nil
	}

	requeue, err := r.applyDNSEndpoint(ctx, &cert, cfg, names, desired)
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: requeue}, nil
}

// rdataFor computes the record data for the certificate currently in the Secret
// ("live") and, where possible, for the certificate that is about to be issued
// ("prepublish").
//
// prepublish is the mechanism that makes renewal safe. cert-manager writes the
// next private key to its own Secret and sets status.nextPrivateKeySecretName
// before it requests a new certificate, and with selector SPKI the record data
// depends only on the public key. So we can publish the record for the next
// certificate before that certificate exists, satisfying RFC 7671 section 8.1's
// requirement to publish before switching. This is not possible with selector
// FullCert, where the rdata covers fields that are not known until the CA signs.
func (r *CertificateReconciler) rdataFor(ctx context.Context, cert *cmapi.Certificate, cfg *tlsa.Config) (live, prepublish string, err error) {
	live, liveErr := r.liveRData(ctx, cert, cfg)

	prepublish, preErr := r.prepublishRData(ctx, cert, cfg)
	if preErr != nil {
		logf.FromContext(ctx).V(1).Info("not pre-publishing next key", "reason", preErr.Error())
	}

	if liveErr != nil {
		if prepublish == "" {
			return "", "", liveErr
		}
		// First issuance: no certificate yet, but the key exists. Publishing
		// ahead of issuance is exactly what we want.
		return "", prepublish, nil
	}
	return live, prepublish, nil
}

func (r *CertificateReconciler) liveRData(ctx context.Context, cert *cmapi.Certificate, cfg *tlsa.Config) (string, error) {
	if cert.Spec.SecretName == "" {
		return "", errors.New("certificate has no spec.secretName")
	}

	var secret corev1.Secret
	key := types.NamespacedName{Namespace: cert.Namespace, Name: cert.Spec.SecretName}
	if err := r.SecretReader.Get(ctx, key, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			return "", fmt.Errorf("secret %s does not exist yet", key.Name)
		}
		return "", fmt.Errorf("reading secret %s: %w", key.Name, err)
	}

	chainPEM := secret.Data[corev1.TLSCertKey]
	if len(chainPEM) == 0 {
		return "", fmt.Errorf("secret %s has no %s", key.Name, corev1.TLSCertKey)
	}
	chain, err := tlsa.ParseCertificateChain(chainPEM)
	if err != nil {
		return "", fmt.Errorf("parsing %s from secret %s: %w", corev1.TLSCertKey, key.Name, err)
	}

	target, err := selectCertificate(chain, secret.Data[cmmeta.TLSCAKey], cfg.Params.Usage)
	if err != nil {
		return "", err
	}
	return tlsa.RData(target, cfg.Params)
}

// selectCertificate picks the certificate the TLSA record should describe.
//
// For the end-entity usages that is the leaf. For the trust-anchor usages it is
// the issuing CA: the intermediate from the served chain when there is one
// (which is what RFC 7671 section 5.2.2 wants, since that is the certificate the
// peer actually presents), falling back to ca.crt for issuers that do not ship
// an intermediate.
func selectCertificate(chain []*x509.Certificate, caPEM []byte, usage tlsa.Usage) (*x509.Certificate, error) {
	if !usage.TargetsTrustAnchor() {
		return chain[0], nil
	}
	if len(chain) > 1 {
		return chain[1], nil
	}
	if len(caPEM) > 0 {
		caChain, err := tlsa.ParseCertificateChain(caPEM)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", cmmeta.TLSCAKey, err)
		}
		return caChain[0], nil
	}
	return nil, fmt.Errorf("usage %s needs an issuer certificate, but tls.crt has no intermediate and the secret has no %s", usage, cmmeta.TLSCAKey)
}

func (r *CertificateReconciler) prepublishRData(ctx context.Context, cert *cmapi.Certificate, cfg *tlsa.Config) (string, error) {
	if cfg.Params.Selector != tlsa.SelectorSPKI {
		return "", fmt.Errorf("selector %s depends on fields that only exist once the certificate is signed", cfg.Params.Selector)
	}
	if cfg.Params.Usage.TargetsTrustAnchor() {
		// A trust-anchor record describes the CA, which does not change when the
		// leaf is renewed. There is nothing to pre-publish.
		return "", fmt.Errorf("usage %s describes the issuer, not the renewed key", cfg.Params.Usage)
	}
	if !hasCondition(cert, cmapi.CertificateConditionIssuing, cmmeta.ConditionTrue) {
		return "", errors.New("certificate is not currently issuing")
	}
	if cert.Status.NextPrivateKeySecretName == nil || *cert.Status.NextPrivateKeySecretName == "" {
		return "", errors.New("status.nextPrivateKeySecretName is not set yet")
	}

	var secret corev1.Secret
	key := types.NamespacedName{Namespace: cert.Namespace, Name: *cert.Status.NextPrivateKeySecretName}
	if err := r.SecretReader.Get(ctx, key, &secret); err != nil {
		return "", fmt.Errorf("reading next private key secret %s: %w", key.Name, err)
	}
	keyPEM := secret.Data[corev1.TLSPrivateKeyKey]
	if len(keyPEM) == 0 {
		return "", fmt.Errorf("secret %s has no %s", key.Name, corev1.TLSPrivateKeyKey)
	}

	pub, err := tlsa.PublicKeyFromPEM(keyPEM)
	if err != nil {
		return "", fmt.Errorf("reading public key from secret %s: %w", key.Name, err)
	}
	return tlsa.RDataForPublicKey(pub, cfg.Params)
}

// applyDNSEndpoint creates or updates the DNSEndpoint, merging in any rdata that
// is being retired. It returns how long until the next retirement expires, or
// zero if nothing is pending.
func (r *CertificateReconciler) applyDNSEndpoint(
	ctx context.Context,
	cert *cmapi.Certificate,
	cfg *tlsa.Config,
	names []string,
	desired []string,
) (time.Duration, error) {
	log := logf.FromContext(ctx)
	now := r.now()

	de := &edv1alpha1.DNSEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: cert.Namespace,
			Name:      cert.Name + dnsEndpointSuffix,
		},
	}

	var nextExpiry time.Time
	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, de, func() error {
		retired := r.reconcileRetired(de, desired, now)

		targets := slices.Clone(desired)
		for rdata := range retired {
			if !slices.Contains(targets, rdata) {
				targets = append(targets, rdata)
			}
		}
		// Stable ordering keeps us from writing an update on every reconcile
		// just because map iteration reordered the slice.
		sort.Strings(targets)

		for _, expiry := range retired {
			if nextExpiry.IsZero() || expiry.Before(nextExpiry) {
				nextExpiry = expiry
			}
		}

		if err := setRetiredAnnotation(de, r.AnnotationPrefix, retired); err != nil {
			return err
		}

		providerSpecific := slices.Clone(r.ProviderSpecific)
		sort.Slice(providerSpecific, func(i, j int) bool {
			return providerSpecific[i].Name < providerSpecific[j].Name
		})

		endpoints := make([]*edv1alpha1.Endpoint, 0, len(names)*len(cfg.Ports))
		for _, name := range names {
			for _, port := range cfg.Ports {
				endpoints = append(endpoints, &edv1alpha1.Endpoint{
					DNSName:          tlsa.RecordName(port, cfg.Protocol, name),
					RecordType:       recordType,
					RecordTTL:        cfg.TTL,
					Targets:          slices.Clone(targets),
					ProviderSpecific: slices.Clone(providerSpecific),
				})
			}
		}
		de.Spec.Endpoints = endpoints

		return controllerutil.SetControllerReference(cert, de, r.Scheme)
	})
	if err != nil {
		return 0, fmt.Errorf("applying DNSEndpoint %s/%s: %w", de.Namespace, de.Name, err)
	}

	if op != controllerutil.OperationResultNone {
		log.Info("reconciled TLSA records", "operation", op,
			"dnsEndpoint", de.Name, "records", len(de.Spec.Endpoints), "targets", len(desired))
		r.Recorder.Eventf(cert, nil, corev1.EventTypeNormal, "TLSARecordsPublished", "Publish",
			"Published %d TLSA record(s) via DNSEndpoint %s", len(de.Spec.Endpoints), de.Name)
	}

	if nextExpiry.IsZero() {
		return 0, nil
	}
	// Add a second of slack so the requeue lands after the expiry, not exactly on it.
	if d := nextExpiry.Sub(now) + time.Second; d > 0 {
		return d, nil
	}
	return time.Second, nil
}

// reconcileRetired returns the set of superseded rdata values that should stay
// published, keyed by the time each may be dropped. Values that are desired
// again (for instance because a renewal was rolled back) leave the retired set.
func (r *CertificateReconciler) reconcileRetired(de *edv1alpha1.DNSEndpoint, desired []string, now time.Time) map[string]time.Time {
	retired := readRetiredAnnotation(de, r.AnnotationPrefix)

	// Anything currently published but no longer desired starts its grace period.
	for _, ep := range de.Spec.Endpoints {
		if ep == nil || ep.RecordType != recordType {
			continue
		}
		for _, rdata := range ep.Targets {
			if slices.Contains(desired, rdata) {
				continue
			}
			if _, alreadyRetiring := retired[rdata]; !alreadyRetiring {
				retired[rdata] = now.Add(r.RolloverGrace)
			}
		}
	}

	for rdata, expiry := range retired {
		if slices.Contains(desired, rdata) || !expiry.After(now) {
			delete(retired, rdata)
		}
	}
	return retired
}

func readRetiredAnnotation(de *edv1alpha1.DNSEndpoint, prefix string) map[string]time.Time {
	out := map[string]time.Time{}
	raw, ok := de.Annotations[prefix+"/"+retiredAnnotation]
	if !ok || raw == "" {
		return out
	}
	var stored map[string]string
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		// Unreadable bookkeeping must not wedge the controller. Dropping it means
		// the grace period restarts for anything still published, which is the
		// safe direction to fail in.
		return out
	}
	for rdata, ts := range stored {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			out[rdata] = t
		}
	}
	return out
}

func setRetiredAnnotation(de *edv1alpha1.DNSEndpoint, prefix string, retired map[string]time.Time) error {
	key := prefix + "/" + retiredAnnotation
	if len(retired) == 0 {
		delete(de.Annotations, key)
		return nil
	}
	stored := make(map[string]string, len(retired))
	for rdata, expiry := range retired {
		stored[rdata] = expiry.UTC().Format(time.RFC3339)
	}
	raw, err := json.Marshal(stored)
	if err != nil {
		return fmt.Errorf("encoding retired record bookkeeping: %w", err)
	}
	if de.Annotations == nil {
		de.Annotations = map[string]string{}
	}
	de.Annotations[key] = string(raw)
	return nil
}

func (r *CertificateReconciler) deleteDNSEndpoint(ctx context.Context, cert *cmapi.Certificate) error {
	de := &edv1alpha1.DNSEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: cert.Namespace,
			Name:      cert.Name + dnsEndpointSuffix,
		},
	}
	err := r.Delete(ctx, de)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("deleting DNSEndpoint %s/%s: %w", de.Namespace, de.Name, err)
	}
	return nil
}

// recordBaseNames returns the DNS names to publish records under, plus any
// wildcard names that were skipped.
func recordBaseNames(cert *cmapi.Certificate, cfg *tlsa.Config) (names, skipped []string) {
	candidates := cfg.DNSNames
	if len(candidates) == 0 {
		candidates = cert.Spec.DNSNames
	}

	seen := make(map[string]struct{}, len(candidates))
	for _, name := range candidates {
		name = strings.TrimSuffix(strings.TrimSpace(name), ".")
		if name == "" {
			continue
		}
		if strings.HasPrefix(name, "*.") {
			skipped = append(skipped, name)
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, skipped
}

func hasCondition(cert *cmapi.Certificate, t cmapi.CertificateConditionType, status cmmeta.ConditionStatus) bool {
	for _, c := range cert.Status.Conditions {
		if c.Type == t {
			return c.Status == status
		}
	}
	return false
}

// SetupWithManager wires the reconciler into the manager.
//
// Only Certificates and the DNSEndpoints we own are watched. Secret changes are
// not watched: cert-manager updates the Certificate's status (revision,
// notAfter, renewalTime, conditions) whenever key material changes, so every
// event we care about reaches us through the Certificate anyway — without
// caching the cluster's Secrets.
func (r *CertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.AnnotationPrefix == "" {
		r.AnnotationPrefix = tlsa.DefaultAnnotationPrefix
	}
	if r.SecretReader == nil {
		r.SecretReader = mgr.GetAPIReader()
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&cmapi.Certificate{}).
		Owns(&edv1alpha1.DNSEndpoint{}).
		Named("certificate-tlsa").
		Complete(r)
}

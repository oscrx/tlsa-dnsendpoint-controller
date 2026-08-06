package controller

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	edv1alpha1 "github.com/oscrx/tlsa-dnsendpoint-controller/internal/apis/externaldns/v1alpha1"
	"github.com/oscrx/tlsa-dnsendpoint-controller/internal/tlsa"
)

const (
	testPrefix = "tlsa.example.com"
	testNS     = "apps"
	testCert   = "mail"
)

var testScheme = func() *runtime.Scheme {
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		panic(err)
	}
	if err := cmapi.AddToScheme(s); err != nil {
		panic(err)
	}
	if err := edv1alpha1.AddToScheme(s); err != nil {
		panic(err)
	}
	return s
}()

// keyPair is a generated key plus a self-signed certificate carrying it.
type keyPair struct {
	keyPEM  []byte
	certPEM []byte
	cert    *x509.Certificate
}

func newKeyPair(t *testing.T, cn string) keyPair {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}

	return keyPair{
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		cert:    cert,
	}
}

// newCAKeyPair returns a CA and a leaf signed by it, plus the served chain.
func newCAKeyPair(t *testing.T, cn string) (chainPEM []byte, leaf, ca *x509.Certificate) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	chainPEM = append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...,
	)
	return chainPEM, leaf, ca
}

type fixtureOpt func(*fixture)

type fixture struct {
	cert    *cmapi.Certificate
	objects []client.Object
	now     time.Time
	grace   time.Duration
}

func withAnnotations(kv ...string) fixtureOpt {
	return func(f *fixture) {
		if f.cert.Annotations == nil {
			f.cert.Annotations = map[string]string{}
		}
		for i := 0; i+1 < len(kv); i += 2 {
			f.cert.Annotations[testPrefix+"/"+kv[i]] = kv[i+1]
		}
	}
}

func withDNSNames(names ...string) fixtureOpt {
	return func(f *fixture) { f.cert.Spec.DNSNames = names }
}

func withIssuing(nextKeySecret string) fixtureOpt {
	return func(f *fixture) {
		f.cert.Status.Conditions = append(f.cert.Status.Conditions, cmapi.CertificateCondition{
			Type:   cmapi.CertificateConditionIssuing,
			Status: cmmeta.ConditionTrue,
		})
		f.cert.Status.NextPrivateKeySecretName = &nextKeySecret
	}
}

func withSecret(name string, data map[string][]byte) fixtureOpt {
	return func(f *fixture) {
		f.objects = append(f.objects, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: name},
			Data:       data,
		})
	}
}

func withObjects(objs ...client.Object) fixtureOpt {
	return func(f *fixture) { f.objects = append(f.objects, objs...) }
}

func withNow(now time.Time) fixtureOpt {
	return func(f *fixture) { f.now = now }
}

func withGrace(d time.Duration) fixtureOpt {
	return func(f *fixture) { f.grace = d }
}

func reconcile(t *testing.T, opts ...fixtureOpt) (*edv1alpha1.DNSEndpoint, ctrl.Result, []string) {
	t.Helper()

	f := &fixture{
		cert: &cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: testNS,
				Name:      testCert,
				UID:       types.UID("cert-uid"),
			},
			Spec: cmapi.CertificateSpec{
				SecretName: "mail-tls",
				DNSNames:   []string{"mail.example.com"},
			},
		},
		now:   time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC),
		grace: 168 * time.Hour,
	}
	for _, opt := range opts {
		opt(f)
	}

	objs := append([]client.Object{f.cert}, f.objects...)
	c := fake.NewClientBuilder().WithScheme(testScheme).WithObjects(objs...).Build()
	recorder := events.NewFakeRecorder(50)

	r := &CertificateReconciler{
		Client:           c,
		SecretReader:     c,
		Scheme:           testScheme,
		Recorder:         recorder,
		AnnotationPrefix: testPrefix,
		RolloverGrace:    f.grace,
		Clock:            func() time.Time { return f.now },
	}

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: testNS, Name: testCert},
	})
	if err != nil {
		t.Fatalf("Reconcile returned an error: %v", err)
	}

	var recorded []string
	for {
		select {
		case e := <-recorder.Events:
			recorded = append(recorded, e)
			continue
		default:
		}
		break
	}

	var de edv1alpha1.DNSEndpoint
	getErr := c.Get(context.Background(), types.NamespacedName{Namespace: testNS, Name: testCert + dnsEndpointSuffix}, &de)
	if apierrors.IsNotFound(getErr) {
		return nil, res, recorded
	}
	if getErr != nil {
		t.Fatalf("getting DNSEndpoint: %v", getErr)
	}
	return &de, res, recorded
}

func targetsFor(t *testing.T, de *edv1alpha1.DNSEndpoint, name string) []string {
	t.Helper()
	for _, ep := range de.Spec.Endpoints {
		if ep.DNSName == name {
			out := slices.Clone(ep.Targets)
			sort.Strings(out)
			return out
		}
	}
	t.Fatalf("no endpoint named %q in %v", name, endpointNames(de))
	return nil
}

func endpointNames(de *edv1alpha1.DNSEndpoint) []string {
	var names []string
	for _, ep := range de.Spec.Endpoints {
		names = append(names, ep.DNSName)
	}
	sort.Strings(names)
	return names
}

func rdata(t *testing.T, cert *x509.Certificate, usage tlsa.Usage) string {
	t.Helper()
	s, err := tlsa.RData(cert, tlsa.Params{Usage: usage, Selector: tlsa.SelectorSPKI, MatchingType: tlsa.MatchingTypeSHA256})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNotEnabledPublishesNothing(t *testing.T) {
	kp := newKeyPair(t, "mail.example.com")
	de, _, _ := reconcile(t, withSecret("mail-tls", map[string][]byte{corev1.TLSCertKey: kp.certPEM}))
	if de != nil {
		t.Fatalf("expected no DNSEndpoint, got %v", endpointNames(de))
	}
}

func TestStrayAnnotationsWarn(t *testing.T) {
	_, _, events := reconcile(t, withAnnotations("ports", "25"))
	if !hasEvent(events, "TLSAConfigIgnored") {
		t.Errorf("expected a TLSAConfigIgnored warning, got %v", events)
	}
}

func TestInvalidConfigWarnsAndDoesNotRetry(t *testing.T) {
	de, res, events := reconcile(t, withAnnotations("enabled", "true", "usage", "DANE-XX"))
	if de != nil {
		t.Error("expected no DNSEndpoint for an invalid config")
	}
	if res.RequeueAfter != 0 {
		t.Errorf("RequeueAfter = %v, want 0: retrying cannot fix a typo", res.RequeueAfter)
	}
	if !hasEvent(events, "TLSAConfigInvalid") {
		t.Errorf("expected a TLSAConfigInvalid warning, got %v", events)
	}
}

func TestPublishesRecordForIssuedCertificate(t *testing.T) {
	kp := newKeyPair(t, "mail.example.com")
	de, _, _ := reconcile(t,
		withAnnotations("enabled", "true", "ports", "25"),
		withSecret("mail-tls", map[string][]byte{corev1.TLSCertKey: kp.certPEM}),
	)
	if de == nil {
		t.Fatal("expected a DNSEndpoint")
	}

	want := []string{"_25._tcp.mail.example.com"}
	if got := endpointNames(de); !slices.Equal(got, want) {
		t.Fatalf("endpoint names = %v, want %v", got, want)
	}

	ep := de.Spec.Endpoints[0]
	if ep.RecordType != "TLSA" {
		t.Errorf("recordType = %q, want TLSA", ep.RecordType)
	}
	if ep.RecordTTL != 300 {
		t.Errorf("recordTTL = %d, want 300", ep.RecordTTL)
	}

	got := targetsFor(t, de, "_25._tcp.mail.example.com")
	if wantTargets := []string{rdata(t, kp.cert, tlsa.UsageDANEEE)}; !slices.Equal(got, wantTargets) {
		t.Errorf("targets = %v, want %v", got, wantTargets)
	}
}

func TestOwnerReferenceEnablesGarbageCollection(t *testing.T) {
	kp := newKeyPair(t, "mail.example.com")
	de, _, _ := reconcile(t,
		withAnnotations("enabled", "true"),
		withSecret("mail-tls", map[string][]byte{corev1.TLSCertKey: kp.certPEM}),
	)
	if de == nil {
		t.Fatal("expected a DNSEndpoint")
	}

	refs := de.OwnerReferences
	if len(refs) != 1 {
		t.Fatalf("got %d owner references, want 1", len(refs))
	}
	if refs[0].Kind != "Certificate" || refs[0].Name != testCert {
		t.Errorf("owner = %s/%s, want Certificate/%s", refs[0].Kind, refs[0].Name, testCert)
	}
	if refs[0].Controller == nil || !*refs[0].Controller {
		t.Error("owner reference should be a controller reference")
	}
	// The absence of a finalizer is the point: deleting the Certificate must not
	// be able to block on DNS reachability.
	if len(de.Finalizers) != 0 {
		t.Errorf("DNSEndpoint should carry no finalizers, got %v", de.Finalizers)
	}
}

func TestCartesianProductOfNamesAndPorts(t *testing.T) {
	kp := newKeyPair(t, "mail.example.com")
	de, _, _ := reconcile(t,
		withAnnotations("enabled", "true", "ports", "25,465,587"),
		withDNSNames("mail.example.com", "smtp.example.com"),
		withSecret("mail-tls", map[string][]byte{corev1.TLSCertKey: kp.certPEM}),
	)
	if de == nil {
		t.Fatal("expected a DNSEndpoint")
	}

	want := []string{
		"_25._tcp.mail.example.com", "_25._tcp.smtp.example.com",
		"_465._tcp.mail.example.com", "_465._tcp.smtp.example.com",
		"_587._tcp.mail.example.com", "_587._tcp.smtp.example.com",
	}
	sort.Strings(want)
	if got := endpointNames(de); !slices.Equal(got, want) {
		t.Errorf("endpoint names = %v\nwant %v", got, want)
	}
}

func TestWildcardNamesAreSkipped(t *testing.T) {
	kp := newKeyPair(t, "mail.example.com")
	de, _, events := reconcile(t,
		withAnnotations("enabled", "true"),
		withDNSNames("*.example.com", "mail.example.com"),
		withSecret("mail-tls", map[string][]byte{corev1.TLSCertKey: kp.certPEM}),
	)
	if de == nil {
		t.Fatal("expected a DNSEndpoint")
	}
	if got, want := endpointNames(de), []string{"_443._tcp.mail.example.com"}; !slices.Equal(got, want) {
		t.Errorf("endpoint names = %v, want %v", got, want)
	}
	if !hasEvent(events, "TLSANameSkipped") {
		t.Errorf("expected a TLSANameSkipped warning, got %v", events)
	}
}

// This is the behaviour that makes renewal safe: cert-manager has generated the
// next private key but the new certificate does not exist yet, and we already
// publish the record that will match it.
func TestPrePublishesNextKeyBeforeIssuance(t *testing.T) {
	current := newKeyPair(t, "mail.example.com")
	next := newKeyPair(t, "mail.example.com")

	de, _, _ := reconcile(t,
		withAnnotations("enabled", "true", "ports", "25"),
		withIssuing("mail-next-key"),
		withSecret("mail-tls", map[string][]byte{corev1.TLSCertKey: current.certPEM}),
		withSecret("mail-next-key", map[string][]byte{corev1.TLSPrivateKeyKey: next.keyPEM}),
	)
	if de == nil {
		t.Fatal("expected a DNSEndpoint")
	}

	want := []string{
		rdata(t, current.cert, tlsa.UsageDANEEE),
		rdata(t, next.cert, tlsa.UsageDANEEE),
	}
	sort.Strings(want)
	if got := targetsFor(t, de, "_25._tcp.mail.example.com"); !slices.Equal(got, want) {
		t.Errorf("targets = %v\nwant both the current and the upcoming digest %v", got, want)
	}
}

func TestFirstIssuancePublishesBeforeCertificateExists(t *testing.T) {
	next := newKeyPair(t, "mail.example.com")

	de, _, _ := reconcile(t,
		withAnnotations("enabled", "true"),
		withIssuing("mail-next-key"),
		withSecret("mail-next-key", map[string][]byte{corev1.TLSPrivateKeyKey: next.keyPEM}),
	)
	if de == nil {
		t.Fatal("expected a DNSEndpoint even though no certificate has been issued yet")
	}
	want := []string{rdata(t, next.cert, tlsa.UsageDANEEE)}
	if got := targetsFor(t, de, "_443._tcp.mail.example.com"); !slices.Equal(got, want) {
		t.Errorf("targets = %v, want %v", got, want)
	}
}

func TestNoPrePublishForFullCertSelector(t *testing.T) {
	current := newKeyPair(t, "mail.example.com")
	next := newKeyPair(t, "mail.example.com")

	de, _, _ := reconcile(t,
		withAnnotations("enabled", "true", "selector", "FullCert", "matching-type", "SHA256"),
		withIssuing("mail-next-key"),
		withSecret("mail-tls", map[string][]byte{corev1.TLSCertKey: current.certPEM}),
		withSecret("mail-next-key", map[string][]byte{corev1.TLSPrivateKeyKey: next.keyPEM}),
	)
	if de == nil {
		t.Fatal("expected a DNSEndpoint")
	}
	// Only the current certificate's rdata: a FullCert digest cannot be known
	// before the CA signs.
	if got := targetsFor(t, de, "_443._tcp.mail.example.com"); len(got) != 1 {
		t.Errorf("targets = %v, want exactly the current certificate's rdata", got)
	}
}

func TestRenewalRetainsOldDigestThenDropsIt(t *testing.T) {
	oldKP := newKeyPair(t, "mail.example.com")
	newKP := newKeyPair(t, "mail.example.com")
	oldRData := rdata(t, oldKP.cert, tlsa.UsageDANEEE)
	newRData := rdata(t, newKP.cert, tlsa.UsageDANEEE)

	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	grace := 48 * time.Hour

	existing := &edv1alpha1.DNSEndpoint{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: testCert + dnsEndpointSuffix},
		Spec: edv1alpha1.DNSEndpointSpec{
			Endpoints: []*edv1alpha1.Endpoint{{
				DNSName:    "_443._tcp.mail.example.com",
				RecordType: "TLSA",
				RecordTTL:  300,
				Targets:    []string{oldRData},
			}},
		},
	}

	// Renewal has completed: the Secret now holds the new certificate.
	de, res, _ := reconcile(t,
		withAnnotations("enabled", "true"),
		withSecret("mail-tls", map[string][]byte{corev1.TLSCertKey: newKP.certPEM}),
		withObjects(existing),
		withNow(now),
		withGrace(grace),
	)
	if de == nil {
		t.Fatal("expected a DNSEndpoint")
	}

	want := []string{newRData, oldRData}
	sort.Strings(want)
	if got := targetsFor(t, de, "_443._tcp.mail.example.com"); !slices.Equal(got, want) {
		t.Fatalf("targets = %v\nwant the old digest kept alongside the new one %v", got, want)
	}

	retired := readRetired(t, de)
	expiry, ok := retired[oldRData]
	if !ok {
		t.Fatalf("old digest is not recorded as retired: %v", retired)
	}
	if want := now.Add(grace); !expiry.Equal(want) {
		t.Errorf("retirement expiry = %v, want %v", expiry, want)
	}
	if res.RequeueAfter <= 0 {
		t.Error("expected a requeue so the retired record can be dropped later")
	}

	// Now run again past the grace period: the old digest should be gone.
	de2, res2, _ := reconcile(t,
		withAnnotations("enabled", "true"),
		withSecret("mail-tls", map[string][]byte{corev1.TLSCertKey: newKP.certPEM}),
		withObjects(de),
		withNow(now.Add(grace).Add(time.Minute)),
		withGrace(grace),
	)
	if de2 == nil {
		t.Fatal("expected a DNSEndpoint")
	}
	if got, want := targetsFor(t, de2, "_443._tcp.mail.example.com"), []string{newRData}; !slices.Equal(got, want) {
		t.Errorf("targets = %v, want only the current digest %v", got, want)
	}
	if len(readRetired(t, de2)) != 0 {
		t.Errorf("retired bookkeeping should be cleared, got %v", readRetired(t, de2))
	}
	if res2.RequeueAfter != 0 {
		t.Errorf("RequeueAfter = %v, want 0 once nothing is retired", res2.RequeueAfter)
	}
}

func TestRetiredDigestReturningToServiceIsUnretired(t *testing.T) {
	kp := newKeyPair(t, "mail.example.com")
	rd := rdata(t, kp.cert, tlsa.UsageDANEEE)
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)

	existing := &edv1alpha1.DNSEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   testNS,
			Name:        testCert + dnsEndpointSuffix,
			Annotations: map[string]string{testPrefix + "/" + retiredAnnotation: `{"` + rd + `":"2026-08-13T12:00:00Z"}`},
		},
		Spec: edv1alpha1.DNSEndpointSpec{
			Endpoints: []*edv1alpha1.Endpoint{{
				DNSName:    "_443._tcp.mail.example.com",
				RecordType: "TLSA",
				Targets:    []string{rd},
			}},
		},
	}

	de, _, _ := reconcile(t,
		withAnnotations("enabled", "true"),
		withSecret("mail-tls", map[string][]byte{corev1.TLSCertKey: kp.certPEM}),
		withObjects(existing),
		withNow(now),
	)
	if de == nil {
		t.Fatal("expected a DNSEndpoint")
	}
	if got, want := targetsFor(t, de, "_443._tcp.mail.example.com"), []string{rd}; !slices.Equal(got, want) {
		t.Errorf("targets = %v, want %v", got, want)
	}
	if r := readRetired(t, de); len(r) != 0 {
		t.Errorf("digest is current again, so it should not be retired: %v", r)
	}
}

func TestDANETAUsesIntermediateFromChain(t *testing.T) {
	chainPEM, leaf, ca := newCAKeyPair(t, "mail.example.com")

	de, _, _ := reconcile(t,
		withAnnotations("enabled", "true", "usage", "DANE-TA"),
		withSecret("mail-tls", map[string][]byte{corev1.TLSCertKey: chainPEM}),
	)
	if de == nil {
		t.Fatal("expected a DNSEndpoint")
	}

	got := targetsFor(t, de, "_443._tcp.mail.example.com")
	if want := []string{rdata(t, ca, tlsa.UsageDANETA)}; !slices.Equal(got, want) {
		t.Errorf("targets = %v, want the CA digest %v", got, want)
	}
	if leafRData := rdata(t, leaf, tlsa.UsageDANETA); slices.Contains(got, leafRData) {
		t.Error("DANE-TA record must not contain the leaf digest")
	}
}

func TestDANETAFallsBackToCACrt(t *testing.T) {
	kp := newKeyPair(t, "mail.example.com")
	_, _, ca := newCAKeyPair(t, "other.example.com")
	caOnlyPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})

	de, _, _ := reconcile(t,
		withAnnotations("enabled", "true", "usage", "DANE-TA"),
		withSecret("mail-tls", map[string][]byte{
			corev1.TLSCertKey: kp.certPEM,
			cmmeta.TLSCAKey:   caOnlyPEM,
		}),
	)
	if de == nil {
		t.Fatal("expected a DNSEndpoint")
	}
	if got, want := targetsFor(t, de, "_443._tcp.mail.example.com"), []string{rdata(t, ca, tlsa.UsageDANETA)}; !slices.Equal(got, want) {
		t.Errorf("targets = %v, want the ca.crt digest %v", got, want)
	}
}

func TestDANETAWithoutIssuerCertificateWarns(t *testing.T) {
	kp := newKeyPair(t, "mail.example.com")
	de, _, events := reconcile(t,
		withAnnotations("enabled", "true", "usage", "DANE-TA"),
		withSecret("mail-tls", map[string][]byte{corev1.TLSCertKey: kp.certPEM}),
	)
	if de != nil {
		t.Errorf("expected no DNSEndpoint, got targets %v", de.Spec.Endpoints)
	}
	if !hasEvent(events, "TLSADataUnavailable") {
		t.Errorf("expected a TLSADataUnavailable warning, got %v", events)
	}
}

func TestOptingOutWithdrawsRecords(t *testing.T) {
	kp := newKeyPair(t, "mail.example.com")
	existing := &edv1alpha1.DNSEndpoint{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: testCert + dnsEndpointSuffix},
		Spec: edv1alpha1.DNSEndpointSpec{
			Endpoints: []*edv1alpha1.Endpoint{{
				DNSName:    "_443._tcp.mail.example.com",
				RecordType: "TLSA",
				Targets:    []string{rdata(t, kp.cert, tlsa.UsageDANEEE)},
			}},
		},
	}

	de, _, _ := reconcile(t,
		withAnnotations("enabled", "false"),
		withSecret("mail-tls", map[string][]byte{corev1.TLSCertKey: kp.certPEM}),
		withObjects(existing),
	)
	if de != nil {
		t.Errorf("DNSEndpoint should have been deleted, still has %v", endpointNames(de))
	}
}

// A Secret that has gone missing must not withdraw records that are already
// published: DANE breaks the moment a matching record disappears.
func TestMissingSecretDoesNotWithdrawRecords(t *testing.T) {
	kp := newKeyPair(t, "mail.example.com")
	rd := rdata(t, kp.cert, tlsa.UsageDANEEE)
	existing := &edv1alpha1.DNSEndpoint{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: testCert + dnsEndpointSuffix},
		Spec: edv1alpha1.DNSEndpointSpec{
			Endpoints: []*edv1alpha1.Endpoint{{
				DNSName:    "_443._tcp.mail.example.com",
				RecordType: "TLSA",
				Targets:    []string{rd},
			}},
		},
	}

	de, _, events := reconcile(t,
		withAnnotations("enabled", "true"),
		withObjects(existing),
	)
	if de == nil {
		t.Fatal("existing records must be left in place")
	}
	if got := targetsFor(t, de, "_443._tcp.mail.example.com"); !slices.Equal(got, []string{rd}) {
		t.Errorf("targets = %v, want the previously published %v", got, []string{rd})
	}
	if !hasEvent(events, "TLSADataUnavailable") {
		t.Errorf("expected a TLSADataUnavailable warning, got %v", events)
	}
}

func TestDeletedCertificateIsANoOp(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme).Build()
	r := &CertificateReconciler{
		Client:           c,
		SecretReader:     c,
		Scheme:           testScheme,
		Recorder:         events.NewFakeRecorder(10),
		AnnotationPrefix: testPrefix,
		RolloverGrace:    time.Hour,
	}
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: testNS, Name: "gone"},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Errorf("RequeueAfter = %v, want 0", res.RequeueAfter)
	}
}

func TestReconcileIsIdempotent(t *testing.T) {
	kp := newKeyPair(t, "mail.example.com")
	secretData := map[string][]byte{corev1.TLSCertKey: kp.certPEM}

	first, _, _ := reconcile(t,
		withAnnotations("enabled", "true", "ports", "25,443"),
		withSecret("mail-tls", secretData),
	)
	if first == nil {
		t.Fatal("expected a DNSEndpoint")
	}

	second, _, _ := reconcile(t,
		withAnnotations("enabled", "true", "ports", "25,443"),
		withSecret("mail-tls", secretData),
		withObjects(first),
	)
	if second == nil {
		t.Fatal("expected a DNSEndpoint")
	}
	if first.ResourceVersion != second.ResourceVersion {
		t.Errorf("a second identical reconcile rewrote the object (%s -> %s); it should be a no-op",
			first.ResourceVersion, second.ResourceVersion)
	}
}

// The Cloudflare provider does not know TLSA records cannot be proxied, so when
// external-dns runs with --cloudflare-proxied it would try to create them with
// proxied=true and Cloudflare would reject the change. Passing the property
// through on every record is the workaround.
func TestProviderSpecificIsCopiedToEveryEndpoint(t *testing.T) {
	kp := newKeyPair(t, "mail.example.com")

	c := fake.NewClientBuilder().WithScheme(testScheme).WithObjects(
		&cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:   testNS,
				Name:        testCert,
				UID:         types.UID("cert-uid"),
				Annotations: map[string]string{testPrefix + "/enabled": "true", testPrefix + "/ports": "25,443"},
			},
			Spec: cmapi.CertificateSpec{SecretName: "mail-tls", DNSNames: []string{"mail.example.com"}},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: "mail-tls"},
			Data:       map[string][]byte{corev1.TLSCertKey: kp.certPEM},
		},
	).Build()

	r := &CertificateReconciler{
		Client:           c,
		SecretReader:     c,
		Scheme:           testScheme,
		Recorder:         events.NewFakeRecorder(10),
		AnnotationPrefix: testPrefix,
		RolloverGrace:    time.Hour,
		ProviderSpecific: []edv1alpha1.ProviderSpecificProperty{
			{Name: "external-dns.kubernetes.io/cloudflare-proxied", Value: "false"},
		},
	}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: testNS, Name: testCert},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var de edv1alpha1.DNSEndpoint
	if err := c.Get(context.Background(), types.NamespacedName{
		Namespace: testNS, Name: testCert + dnsEndpointSuffix,
	}, &de); err != nil {
		t.Fatalf("getting DNSEndpoint: %v", err)
	}

	if len(de.Spec.Endpoints) != 2 {
		t.Fatalf("got %d endpoints, want 2", len(de.Spec.Endpoints))
	}
	for _, ep := range de.Spec.Endpoints {
		if len(ep.ProviderSpecific) != 1 {
			t.Fatalf("%s: got %d providerSpecific entries, want 1", ep.DNSName, len(ep.ProviderSpecific))
		}
		got := ep.ProviderSpecific[0]
		if got.Name != "external-dns.kubernetes.io/cloudflare-proxied" || got.Value != "false" {
			t.Errorf("%s: providerSpecific = %+v", ep.DNSName, got)
		}
	}
}

func TestCorruptRetiredAnnotationIsIgnored(t *testing.T) {
	kp := newKeyPair(t, "mail.example.com")
	existing := &edv1alpha1.DNSEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   testNS,
			Name:        testCert + dnsEndpointSuffix,
			Annotations: map[string]string{testPrefix + "/" + retiredAnnotation: "{not json"},
		},
	}
	de, _, _ := reconcile(t,
		withAnnotations("enabled", "true"),
		withSecret("mail-tls", map[string][]byte{corev1.TLSCertKey: kp.certPEM}),
		withObjects(existing),
	)
	if de == nil {
		t.Fatal("a corrupt annotation should not stop reconciliation")
	}
	if got, want := targetsFor(t, de, "_443._tcp.mail.example.com"), []string{rdata(t, kp.cert, tlsa.UsageDANEEE)}; !slices.Equal(got, want) {
		t.Errorf("targets = %v, want %v", got, want)
	}
}

func readRetired(t *testing.T, de *edv1alpha1.DNSEndpoint) map[string]time.Time {
	t.Helper()
	raw, ok := de.Annotations[testPrefix+"/"+retiredAnnotation]
	if !ok || raw == "" {
		return map[string]time.Time{}
	}
	var stored map[string]string
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		t.Fatalf("retired annotation is not valid JSON: %v (%q)", err, raw)
	}
	out := make(map[string]time.Time, len(stored))
	for k, v := range stored {
		ts, err := time.Parse(time.RFC3339, v)
		if err != nil {
			t.Fatalf("retired annotation has a bad timestamp %q: %v", v, err)
		}
		out[k] = ts
	}
	return out
}

func hasEvent(events []string, reason string) bool {
	for _, e := range events {
		if strings.Contains(e, reason) {
			return true
		}
	}
	return false
}

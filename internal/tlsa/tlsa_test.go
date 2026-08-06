package tlsa

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// The expected digests below were computed independently with OpenSSL, not with
// this package, so they are a real cross-check of RFC 6698 conformance:
//
//	openssl x509 -in leaf.crt -noout -pubkey | openssl pkey -pubin -outform DER | shasum -a 256
//	openssl x509 -in leaf.crt -outform DER | shasum -a 256
const (
	leafSPKISHA256     = "d42f4f160f3bfde5f01e68bb20757537d302167f61a2f4923f424d2ee57cb8bf"
	leafSPKISHA512     = "f758ae635ec9b464b46d89e05274b791b72ac4245f8eb18ccad836ef59238706fa201cf1616169813a8d0743f3e0275eb69bad17bcf1032217830d0aacbbc843"
	leafFullCertSHA256 = "462ec92ca033885c904dbbece52c89bc47ed52e8bce2bb1fdd28be0019ae1ba5"
	caSPKISHA256       = "f633b15734fbec0d8beef0ac7927b5a15022574a4ce2014e6d6bdb13da406f01"
	signedLeafSPKI256  = "2768434ab9681e29a79ff3c55a98ef2d3fe294424a8268ad6794ce1b48689fb3"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return b
}

func TestRData(t *testing.T) {
	chain, err := ParseCertificateChain(readFixture(t, "leaf.crt"))
	if err != nil {
		t.Fatalf("ParseCertificateChain: %v", err)
	}
	leaf := chain[0]

	tests := []struct {
		name   string
		params Params
		want   string
	}{
		{
			name:   "DANE-EE SPKI SHA256",
			params: Params{UsageDANEEE, SelectorSPKI, MatchingTypeSHA256},
			want:   "3 1 1 " + leafSPKISHA256,
		},
		{
			name:   "DANE-EE SPKI SHA512",
			params: Params{UsageDANEEE, SelectorSPKI, MatchingTypeSHA512},
			want:   "3 1 2 " + leafSPKISHA512,
		},
		{
			name:   "DANE-EE FullCert SHA256",
			params: Params{UsageDANEEE, SelectorFullCert, MatchingTypeSHA256},
			want:   "3 0 1 " + leafFullCertSHA256,
		},
		{
			name:   "PKIX-EE SPKI SHA256 differs only in the usage octet",
			params: Params{UsagePKIXEE, SelectorSPKI, MatchingTypeSHA256},
			want:   "1 1 1 " + leafSPKISHA256,
		},
		{
			name:   "PKIX-TA SPKI SHA256",
			params: Params{UsagePKIXTA, SelectorSPKI, MatchingTypeSHA256},
			want:   "0 1 1 " + leafSPKISHA256,
		},
		{
			name:   "DANE-TA SPKI SHA256",
			params: Params{UsageDANETA, SelectorSPKI, MatchingTypeSHA256},
			want:   "2 1 1 " + leafSPKISHA256,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RData(leaf, tc.params)
			if err != nil {
				t.Fatalf("RData: %v", err)
			}
			if got != tc.want {
				t.Errorf("RData()\n got %q\nwant %q", got, tc.want)
			}
		})
	}
}

// TestRDataIsParseableAsTLSA feeds our output through miekg/dns, the library
// external-dns providers use to build resource records. If this passes, the
// rdata we put in a DNSEndpoint target is syntactically acceptable to the write
// path in external-dns's rfc2136 provider, which formats presentation syntax and
// calls dns.NewRR exactly like this.
func TestRDataIsParseableAsTLSA(t *testing.T) {
	chain, err := ParseCertificateChain(readFixture(t, "leaf.crt"))
	if err != nil {
		t.Fatalf("ParseCertificateChain: %v", err)
	}

	params := Params{UsageDANEEE, SelectorSPKI, MatchingTypeSHA256}
	rdata, err := RData(chain[0], params)
	if err != nil {
		t.Fatalf("RData: %v", err)
	}

	name := RecordName(25, "tcp", "mail.example.com")
	rr, err := dns.NewRR(name + ". 300 IN TLSA " + rdata)
	if err != nil {
		t.Fatalf("dns.NewRR rejected our rdata %q: %v", rdata, err)
	}

	tlsaRR, ok := rr.(*dns.TLSA)
	if !ok {
		t.Fatalf("parsed record is %T, want *dns.TLSA", rr)
	}
	if tlsaRR.Usage != uint8(UsageDANEEE) {
		t.Errorf("Usage = %d, want %d", tlsaRR.Usage, UsageDANEEE)
	}
	if tlsaRR.Selector != uint8(SelectorSPKI) {
		t.Errorf("Selector = %d, want %d", tlsaRR.Selector, SelectorSPKI)
	}
	if tlsaRR.MatchingType != uint8(MatchingTypeSHA256) {
		t.Errorf("MatchingType = %d, want %d", tlsaRR.MatchingType, MatchingTypeSHA256)
	}
	if tlsaRR.Certificate != leafSPKISHA256 {
		t.Errorf("Certificate = %q, want %q", tlsaRR.Certificate, leafSPKISHA256)
	}
	if got, want := tlsaRR.Hdr.Name, "_25._tcp.mail.example.com."; got != want {
		t.Errorf("owner name = %q, want %q", got, want)
	}
}

// TestPrepublishMatchesIssuedCertificate is the load-bearing test for renewal
// safety: the record data derived from a private key alone must equal the record
// data derived from a certificate carrying that key. If this ever stops holding,
// pre-publishing would announce a digest that never matches and DANE validation
// would fail on every renewal.
func TestPrepublishMatchesIssuedCertificate(t *testing.T) {
	chain, err := ParseCertificateChain(readFixture(t, "leaf.crt"))
	if err != nil {
		t.Fatalf("ParseCertificateChain: %v", err)
	}
	pub, err := PublicKeyFromPEM(readFixture(t, "leaf.key"))
	if err != nil {
		t.Fatalf("PublicKeyFromPEM: %v", err)
	}

	for _, mt := range []MatchingType{MatchingTypeSHA256, MatchingTypeSHA512} {
		params := Params{UsageDANEEE, SelectorSPKI, mt}

		fromCert, err := RData(chain[0], params)
		if err != nil {
			t.Fatalf("RData: %v", err)
		}
		fromKey, err := RDataForPublicKey(pub, params)
		if err != nil {
			t.Fatalf("RDataForPublicKey: %v", err)
		}
		if fromCert != fromKey {
			t.Errorf("matching type %s: key-derived rdata %q != cert-derived rdata %q", mt, fromKey, fromCert)
		}
	}
}

func TestRDataForPublicKeyRejectsFullCert(t *testing.T) {
	pub, err := PublicKeyFromPEM(readFixture(t, "leaf.key"))
	if err != nil {
		t.Fatalf("PublicKeyFromPEM: %v", err)
	}
	_, err = RDataForPublicKey(pub, Params{UsageDANEEE, SelectorFullCert, MatchingTypeSHA256})
	if err == nil {
		t.Fatal("expected an error: FullCert rdata cannot be derived from a key alone")
	}
}

func TestParseCertificateChain(t *testing.T) {
	chain, err := ParseCertificateChain(readFixture(t, "chain.crt"))
	if err != nil {
		t.Fatalf("ParseCertificateChain: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("got %d certificates, want 2", len(chain))
	}
	if got, want := chain[0].Subject.CommonName, "smtp.example.com"; got != want {
		t.Errorf("chain[0] CN = %q, want %q", got, want)
	}
	if got, want := chain[1].Subject.CommonName, "Test CA"; got != want {
		t.Errorf("chain[1] CN = %q, want %q", got, want)
	}

	leafRData, err := RData(chain[0], Params{UsageDANEEE, SelectorSPKI, MatchingTypeSHA256})
	if err != nil {
		t.Fatalf("RData(leaf): %v", err)
	}
	if want := "3 1 1 " + signedLeafSPKI256; leafRData != want {
		t.Errorf("leaf rdata = %q, want %q", leafRData, want)
	}

	caRData, err := RData(chain[1], Params{UsageDANETA, SelectorSPKI, MatchingTypeSHA256})
	if err != nil {
		t.Fatalf("RData(ca): %v", err)
	}
	if want := "2 1 1 " + caSPKISHA256; caRData != want {
		t.Errorf("CA rdata = %q, want %q", caRData, want)
	}
}

func TestParseCertificateChainRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "not pem at all", "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n"} {
		if _, err := ParseCertificateChain([]byte(in)); err == nil {
			t.Errorf("ParseCertificateChain(%q) succeeded, want error", in)
		}
	}
}

func TestRecordName(t *testing.T) {
	tests := []struct {
		port     int
		protocol string
		dnsName  string
		want     string
	}{
		{443, "tcp", "example.com", "_443._tcp.example.com"},
		{25, "tcp", "mail.example.com", "_25._tcp.mail.example.com"},
		{853, "udp", "dns.example.com", "_853._udp.dns.example.com"},
		{443, "TCP", "example.com", "_443._tcp.example.com"},
		{443, "tcp", "example.com.", "_443._tcp.example.com"},
	}
	for _, tc := range tests {
		if got := RecordName(tc.port, tc.protocol, tc.dnsName); got != tc.want {
			t.Errorf("RecordName(%d, %q, %q) = %q, want %q", tc.port, tc.protocol, tc.dnsName, got, tc.want)
		}
	}
}

func TestPublicKeyFromPEMFormats(t *testing.T) {
	// cert-manager writes PKCS#8 or PKCS#1 depending on privateKey.encoding, so
	// both must round-trip to the same SPKI digest.
	pkcs1 := readFixture(t, "leaf.key")
	pkcs8Out, err := convertToPKCS8(t, pkcs1)
	if err != nil {
		t.Skipf("cannot produce a PKCS#8 fixture: %v", err)
	}

	params := Params{UsageDANEEE, SelectorSPKI, MatchingTypeSHA256}

	a, err := PublicKeyFromPEM(pkcs1)
	if err != nil {
		t.Fatalf("PublicKeyFromPEM(original): %v", err)
	}
	b, err := PublicKeyFromPEM(pkcs8Out)
	if err != nil {
		t.Fatalf("PublicKeyFromPEM(pkcs8): %v", err)
	}

	ra, err := RDataForPublicKey(a, params)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := RDataForPublicKey(b, params)
	if err != nil {
		t.Fatal(err)
	}
	if ra != rb {
		t.Errorf("encoding changed the rdata: %q != %q", ra, rb)
	}
	if want := "3 1 1 " + leafSPKISHA256; ra != want {
		t.Errorf("rdata = %q, want %q", ra, want)
	}
}

func TestPublicKeyFromPEMRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "nope", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"} {
		if _, err := PublicKeyFromPEM([]byte(in)); err == nil {
			t.Errorf("PublicKeyFromPEM(%q) succeeded, want error", in)
		}
	}
}

func TestParseUsageSelectorMatchingType(t *testing.T) {
	if u, err := ParseUsage("dane-ee"); err != nil || u != UsageDANEEE {
		t.Errorf("ParseUsage(dane-ee) = %v, %v", u, err)
	}
	if u, err := ParseUsage("3"); err != nil || u != UsageDANEEE {
		t.Errorf("ParseUsage(3) = %v, %v", u, err)
	}
	if _, err := ParseUsage("DANE-XX"); err == nil {
		t.Error("ParseUsage(DANE-XX) should fail")
	}
	if s, err := ParseSelector("SPKI"); err != nil || s != SelectorSPKI {
		t.Errorf("ParseSelector(SPKI) = %v, %v", s, err)
	}
	if m, err := ParseMatchingType("sha-512"); err != nil || m != MatchingTypeSHA512 {
		t.Errorf("ParseMatchingType(sha-512) = %v, %v", m, err)
	}
	if _, err := ParseMatchingType("md5"); err == nil {
		t.Error("ParseMatchingType(md5) should fail")
	}
}

func TestStringers(t *testing.T) {
	if got := UsageDANEEE.String(); got != "DANE-EE" {
		t.Errorf("UsageDANEEE = %q", got)
	}
	if got := SelectorSPKI.String(); got != "SPKI" {
		t.Errorf("SelectorSPKI = %q", got)
	}
	if got := MatchingTypeSHA256.String(); got != "SHA256" {
		t.Errorf("MatchingTypeSHA256 = %q", got)
	}
	if !UsageDANETA.TargetsTrustAnchor() || !UsagePKIXTA.TargetsTrustAnchor() {
		t.Error("TA usages should report TargetsTrustAnchor")
	}
	if UsageDANEEE.TargetsTrustAnchor() || UsagePKIXEE.TargetsTrustAnchor() {
		t.Error("EE usages should not report TargetsTrustAnchor")
	}
}

func TestRDataRejectsNilCertificate(t *testing.T) {
	if _, err := RData(nil, Params{UsageDANEEE, SelectorSPKI, MatchingTypeSHA256}); err == nil {
		t.Error("RData(nil) should fail")
	}
}

func TestRDataHasNoWhitespaceInHex(t *testing.T) {
	chain, err := ParseCertificateChain(readFixture(t, "leaf.crt"))
	if err != nil {
		t.Fatal(err)
	}
	// FullCert produces the longest rdata; several providers reject wrapped or
	// colon-separated hex, so make sure the digest field is one contiguous token.
	got, err := RData(chain[0], Params{UsageDANEEE, SelectorFullCert, MatchingTypeSHA512})
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(got)
	if len(fields) != 4 {
		t.Fatalf("rdata has %d fields, want 4: %q", len(fields), got)
	}
	if strings.ContainsAny(fields[3], ": \t\n") {
		t.Errorf("digest field contains separators: %q", fields[3])
	}
}

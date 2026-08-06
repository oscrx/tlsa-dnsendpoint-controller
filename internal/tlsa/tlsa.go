// Package tlsa implements TLSA record data computation per RFC 6698.
package tlsa

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// Usage is the TLSA certificate usage field (RFC 6698 section 2.1.1).
type Usage uint8

// TLSA certificate usage values.
const (
	UsagePKIXTA Usage = 0
	UsagePKIXEE Usage = 1
	UsageDANETA Usage = 2
	UsageDANEEE Usage = 3
)

// Selector is the TLSA selector field (RFC 6698 section 2.1.2).
type Selector uint8

// TLSA selector values.
const (
	SelectorFullCert Selector = 0
	SelectorSPKI     Selector = 1
)

// MatchingType is the TLSA matching type field (RFC 6698 section 2.1.3).
type MatchingType uint8

// TLSA matching type values.
const (
	MatchingTypeFull   MatchingType = 0
	MatchingTypeSHA256 MatchingType = 1
	MatchingTypeSHA512 MatchingType = 2
)

// ParseUsage parses a TLSA usage from its RFC 6698 mnemonic or numeric value.
func ParseUsage(s string) (Usage, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "PKIX-TA", "PKIX_TA", "0":
		return UsagePKIXTA, nil
	case "PKIX-EE", "PKIX_EE", "1":
		return UsagePKIXEE, nil
	case "DANE-TA", "DANE_TA", "2":
		return UsageDANETA, nil
	case "DANE-EE", "DANE_EE", "3":
		return UsageDANEEE, nil
	}
	return 0, fmt.Errorf("invalid TLSA usage %q: want one of PKIX-TA, PKIX-EE, DANE-TA, DANE-EE (or 0-3)", s)
}

// ParseSelector parses a TLSA selector from its mnemonic or numeric value.
func ParseSelector(s string) (Selector, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "FULLCERT", "FULL-CERT", "CERT", "0":
		return SelectorFullCert, nil
	case "SPKI", "1":
		return SelectorSPKI, nil
	}
	return 0, fmt.Errorf("invalid TLSA selector %q: want FullCert or SPKI (or 0-1)", s)
}

// ParseMatchingType parses a TLSA matching type from its mnemonic or numeric value.
func ParseMatchingType(s string) (MatchingType, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "FULL", "0":
		return MatchingTypeFull, nil
	case "SHA256", "SHA-256", "SHA2-256", "1":
		return MatchingTypeSHA256, nil
	case "SHA512", "SHA-512", "SHA2-512", "2":
		return MatchingTypeSHA512, nil
	}
	return 0, fmt.Errorf("invalid TLSA matching type %q: want Full, SHA256 or SHA512 (or 0-2)", s)
}

func (u Usage) String() string {
	switch u {
	case UsagePKIXTA:
		return "PKIX-TA"
	case UsagePKIXEE:
		return "PKIX-EE"
	case UsageDANETA:
		return "DANE-TA"
	case UsageDANEEE:
		return "DANE-EE"
	}
	return fmt.Sprintf("Usage(%d)", uint8(u))
}

func (s Selector) String() string {
	switch s {
	case SelectorFullCert:
		return "FullCert"
	case SelectorSPKI:
		return "SPKI"
	}
	return fmt.Sprintf("Selector(%d)", uint8(s))
}

func (m MatchingType) String() string {
	switch m {
	case MatchingTypeFull:
		return "Full"
	case MatchingTypeSHA256:
		return "SHA256"
	case MatchingTypeSHA512:
		return "SHA512"
	}
	return fmt.Sprintf("MatchingType(%d)", uint8(m))
}

// TargetsTrustAnchor reports whether the usage refers to a trust anchor (the
// issuing CA) rather than the end-entity certificate.
func (u Usage) TargetsTrustAnchor() bool {
	return u == UsagePKIXTA || u == UsageDANETA
}

// Params is a validated TLSA parameter triple.
type Params struct {
	Usage        Usage
	Selector     Selector
	MatchingType MatchingType
}

// RecordName returns the TLSA owner name for a port, protocol and base name,
// e.g. RecordName(25, "tcp", "mail.example.com") == "_25._tcp.mail.example.com".
//
// The returned name is not fully qualified; external-dns and its providers
// handle zone qualification.
func RecordName(port int, protocol, dnsName string) string {
	return fmt.Sprintf("_%d._%s.%s", port, strings.ToLower(protocol), strings.TrimSuffix(dnsName, "."))
}

// RData computes the presentation-format TLSA record data for cert under the
// given parameters, e.g. "3 1 1 0b9fa5a5...".
//
// RFC 6698 section 2.2 specifies the certificate association data as a
// contiguous lowercase hex string; whitespace is permitted only as a line-break
// convenience and is rejected by several DNS providers, so we never emit it.
func RData(cert *x509.Certificate, p Params) (string, error) {
	if cert == nil {
		return "", errors.New("nil certificate")
	}

	var input []byte
	switch p.Selector {
	case SelectorFullCert:
		input = cert.Raw
	case SelectorSPKI:
		input = cert.RawSubjectPublicKeyInfo
	default:
		return "", fmt.Errorf("unsupported selector %d", p.Selector)
	}
	if len(input) == 0 {
		return "", fmt.Errorf("certificate has no data for selector %s", p.Selector)
	}

	digest, err := digest(input, p.MatchingType)
	if err != nil {
		return "", err
	}
	return format(p, digest), nil
}

// RDataForPublicKey computes TLSA record data directly from a public key.
//
// This only works for Selector SPKI, where the record data depends solely on
// the SubjectPublicKeyInfo and not on any other certificate field. It is what
// lets us publish the record for a certificate that has not been issued yet:
// cert-manager creates the next private key before requesting the certificate,
// so the future SPKI digest is already knowable. See RFC 7671 section 8.1 for
// why publishing ahead of the switchover matters.
func RDataForPublicKey(pub any, p Params) (string, error) {
	if p.Selector != SelectorSPKI {
		return "", fmt.Errorf("cannot derive record data from a public key with selector %s: only SPKI is key-only", p.Selector)
	}
	if pub == nil {
		return "", errors.New("nil public key")
	}

	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshalling SubjectPublicKeyInfo: %w", err)
	}
	d, err := digest(spki, p.MatchingType)
	if err != nil {
		return "", err
	}
	return format(p, d), nil
}

func digest(input []byte, mt MatchingType) ([]byte, error) {
	switch mt {
	case MatchingTypeFull:
		return input, nil
	case MatchingTypeSHA256:
		sum := sha256.Sum256(input)
		return sum[:], nil
	case MatchingTypeSHA512:
		sum := sha512.Sum512(input)
		return sum[:], nil
	}
	return nil, fmt.Errorf("unsupported matching type %d", mt)
}

func format(p Params, digest []byte) string {
	return fmt.Sprintf("%d %d %d %s", p.Usage, p.Selector, p.MatchingType, hex.EncodeToString(digest))
}

// ParseCertificateChain parses a PEM bundle into its certificates, in the order
// they appear. Non-certificate PEM blocks are ignored.
func ParseCertificateChain(pemBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("no CERTIFICATE block found in PEM data")
	}
	return certs, nil
}

// PublicKeyFromPEM extracts the public key from a PEM-encoded private key.
// cert-manager writes PKCS#8, PKCS#1 or SEC 1 depending on the Certificate's
// privateKey.encoding and algorithm, so all three are accepted.
func PublicKeyFromPEM(pemBytes []byte) (any, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found in private key data")
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return publicKeyOf(key)
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key.Public(), nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key.Public(), nil
	}
	return nil, fmt.Errorf("private key is not in PKCS#8, PKCS#1 or SEC 1 format (PEM type %q)", block.Type)
}

func publicKeyOf(key any) (any, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k.Public(), nil
	case *ecdsa.PrivateKey:
		return k.Public(), nil
	case ed25519.PrivateKey:
		return k.Public(), nil
	}
	return nil, fmt.Errorf("unsupported private key type %T", key)
}

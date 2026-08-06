package tlsa

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
)

// convertToPKCS8 re-encodes a PKCS#1 private key PEM as PKCS#8, so we can check
// that both encodings cert-manager may write yield the same TLSA record data.
func convertToPKCS8(t *testing.T, pkcs1PEM []byte) ([]byte, error) {
	t.Helper()

	block, _ := pem.Decode(pkcs1PEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in fixture")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("fixture is not PKCS#1: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshalling PKCS#8: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

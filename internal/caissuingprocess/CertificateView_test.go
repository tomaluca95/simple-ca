package caissuingprocess_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/tomaluca95/simple-ca/internal/caissuingprocess"
)

func selfSignedCert(t *testing.T, isCA bool) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "leaf", Organization: []string{"ACME"}},
		NotBefore:             time.Now().Add(-time.Minute).UTC().Truncate(time.Second),
		NotAfter:              time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		DNSNames:              []string{"www.example.com"},
		EmailAddresses:        []string{"admin@example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestCertificateViewIsReasonable(t *testing.T) {
	view := caissuingprocess.NewCertificateView(selfSignedCert(t, false))
	encoded, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	jsonText := string(encoded)

	for _, forbidden := range []string{`"Raw"`, `"RawTBSCertificate"`, `"RawSubject"`, `"Signature"`, `"SignatureValue"`, `"N":`, `"X":`} {
		if strings.Contains(jsonText, forbidden) {
			t.Fatalf("certificate view leaks %s: %s", forbidden, jsonText)
		}
	}
	if strings.Contains(jsonText, ":null") {
		t.Fatalf("certificate view must not contain null values: %s", jsonText)
	}
	if !strings.Contains(jsonText, `"is_ca":false`) {
		t.Fatalf("expected is_ca:false, got %s", jsonText)
	}
	if !strings.Contains(jsonText, `"algorithm":"RSA"`) {
		t.Fatalf("expected readable public key algorithm, got %s", jsonText)
	}
	if !strings.Contains(jsonText, `"digitalSignature"`) {
		t.Fatalf("expected readable key usage, got %s", jsonText)
	}
	if !strings.Contains(jsonText, `"serverAuth"`) {
		t.Fatalf("expected readable extended key usage, got %s", jsonText)
	}
}

func TestCertificateViewExtensionsAreComplete(t *testing.T) {
	cert := selfSignedCert(t, true)
	view := caissuingprocess.NewCertificateView(cert)

	viewOIDs := map[string]bool{}
	for _, extension := range view.Extensions {
		viewOIDs[extension.OID] = true
	}
	for _, extension := range cert.Extensions {
		if !viewOIDs[extension.Id.String()] {
			t.Fatalf("extension %s missing from certificate view", extension.Id.String())
		}
	}
	if !view.IsCA {
		t.Fatal("expected is_ca:true for a CA certificate")
	}
}

func TestCertificateViewMaxPathLen(t *testing.T) {
	leaf := caissuingprocess.NewCertificateView(selfSignedCert(t, false))
	if leaf.MaxPathLen != nil {
		t.Fatalf("unconstrained leaf max_path_len = %d, want absent", *leaf.MaxPathLen)
	}

	ca := caissuingprocess.NewCertificateView(selfSignedCert(t, true))
	if ca.MaxPathLen != nil {
		t.Fatalf("unconstrained ca max_path_len = %d, want absent", *ca.MaxPathLen)
	}

	pathLenZero := certWithPathLen(t, 0, true)
	if view := caissuingprocess.NewCertificateView(pathLenZero); view.MaxPathLen == nil || *view.MaxPathLen != 0 {
		t.Fatalf("pathlen-zero ca max_path_len = %v, want 0", view.MaxPathLen)
	}

	pathLenTwo := certWithPathLen(t, 2, false)
	if view := caissuingprocess.NewCertificateView(pathLenTwo); view.MaxPathLen == nil || *view.MaxPathLen != 2 {
		t.Fatalf("pathlen-2 ca max_path_len = %v, want 2", view.MaxPathLen)
	}
}

func certWithPathLen(t *testing.T, maxPathLen int, zero bool) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            maxPathLen,
		MaxPathLenZero:        zero,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestCertificateViewEcdsa(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "ec"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	view := caissuingprocess.NewCertificateView(cert)
	if view.PublicKey.Algorithm != "ECDSA" || view.PublicKey.Bits != 256 {
		t.Fatalf("unexpected public key view %#v", view.PublicKey)
	}
}

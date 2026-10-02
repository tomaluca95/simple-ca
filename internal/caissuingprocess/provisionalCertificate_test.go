package caissuingprocess

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestProvisionalCertificateAppliesBasicConstraints(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "sub-ca.example.com"},
		SerialNumber: big.NewInt(42),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff}},
		},
	}
	provisional, err := provisionalCertificateForAuthorization(template, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !provisional.IsCA {
		t.Fatal("provisional cert must set IsCA from basicConstraints ExtraExtensions")
	}
	if !provisional.BasicConstraintsValid {
		t.Fatal("provisional cert must set BasicConstraintsValid")
	}
	view := NewCertificateView(provisional)
	if !view.IsCA {
		t.Fatal("CertificateView must report is_ca for the provisional CA")
	}
}

func TestProvisionalCertificateRefusesTrailingBasicConstraintsBytes(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// CA:TRUE SEQUENCE plus a trailing 0x00 that CreateCertificate may still
	// accept while a strict Unmarshal leaves rest non-empty.
	template := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "sub-ca.example.com"},
		SerialNumber: big.NewInt(42),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff, 0x00}},
		},
	}
	_, err = provisionalCertificateForAuthorization(template, &key.PublicKey)
	if !errors.Is(err, ErrInvalidCsr) {
		t.Fatalf("trailing ASN.1 on basicConstraints must be ErrInvalidCsr, got %v", err)
	}
}
